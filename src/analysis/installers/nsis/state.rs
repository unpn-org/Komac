use std::{
    collections::{HashMap, VecDeque},
    io::{self, Cursor},
};

use itertools::Either;
use tracing::{debug, debug_span};
use zerocopy::{FromBytes, I32, LE, U16};

use super::{
    Variables,
    entry::{Entry, EntryError, ExecFlags, system::MockCaller},
};
use crate::analysis::installers::nsis::{
    NsisError,
    file_io::Files,
    file_system::FileSystem,
    header::Header,
    language::table::LanguageTable,
    registry::Registry,
    strings::{NsisChar, NsisCow, NsisStr, NsisString, code::NsCode, shell::Shell, var::NsVar},
    variables::{MAX_STRING_LENGTH, NsisStringExt, bound_string},
    version::NsisVersion,
};

pub struct NsisState<'data> {
    pub read_file: &'data mut dyn FnMut(u64) -> io::Result<Cursor<Vec<u8>>>,
    pub str_block: &'data [u8],
    entries: Cow<'data, [Entry]>,
    pub language_table: &'data LanguageTable,
    pub stack: Vec<NsisCow<'data>>,
    pub variables: Variables<'data>,
    pub registry: Registry,
    pub file_system: FileSystem,
    pub files: Files,
    pub ini_files: HashMap<indextree::NodeId, super::ini::IniFile>,
    pub find_handles: HashMap<i32, VecDeque<String>>,
    pub exec_flags: ExecFlags,
    pub last_used_exec_flags: ExecFlags,
    pub status_up_hack: I32<LE>,
    pub mock_caller: MockCaller,
    version: NsisVersion,
    string_version: NsisVersion,
    pub section_flags: Vec<i32>,
    file_positions: Vec<Option<u64>>,
    entry_index: usize,
}

impl<'data> NsisState<'data> {
    pub fn new(
        data: &'data [u8],
        header: &Header,
        manifest: Option<&str>,
        read_file: &'data mut dyn FnMut(u64) -> io::Result<Cursor<Vec<u8>>>,
        is_bi: bool,
    ) -> Result<Self, NsisError> {
        let mut state = Self {
            read_file,
            str_block: header.blocks().strings_block(data),
            entries: Cow::Borrowed(&[]),
            language_table: LanguageTable::primary_language(data, header.blocks())?,
            stack: Vec::new(),
            variables: Variables::new(),
            registry: Registry::new(),
            file_system: FileSystem::new(),
            files: Files::default(),
            ini_files: HashMap::new(),
            find_handles: HashMap::new(),
            exec_flags: ExecFlags::new(),
            last_used_exec_flags: ExecFlags::new(),
            status_up_hack: I32::ZERO,
            mock_caller: MockCaller::new(),
            version: NsisVersion::default(),
            string_version: NsisVersion::default(),
            file_positions: Vec::new(),
            entry_index: 0,
            section_flags: header
                .blocks()
                .sections(data)
                .map(|section| section.flags())
                .collect(),
        };

        state.variables.insert(
            Variables::NUM_REGISTERS + super::strings::PredefinedVar::Language as usize,
            state.language_table.id().to_string(),
        );
        state.version = NsisVersion::detect(state.str_block);
        state.string_version = state.version;
        state.entries = if header.indexed_files().is_some() {
            Cow::Owned(header.blocks().indexed_entries(data)?)
        } else if is_bi {
            let (entries, positions) = header.blocks().bi_entries(data)?;
            state.file_positions = positions;
            Cow::Owned(entries)
        } else if state.version.is_park() {
            header
                .blocks()
                .park_entries(data, state.str_block.starts_with(b"\0\0"))?
        } else {
            Cow::Borrowed(header.blocks().entries(data)?)
        };
        state.version = manifest
            .and_then(NsisVersion::from_manifest)
            .or_else(|| NsisVersion::from_branding_text(&state))
            .filter(|_| !state.version.is_park())
            .unwrap_or(state.version);

        debug!(version = %state.version);

        // The install directory must be read after the version is determined; `get_string` depends on it
        if let Some(install_directory_ptr) = header.install_directory() {
            let install_dir = state.get_string(install_directory_ptr);
            debug!(%install_dir);
            state.variables.insert_install_dir(install_dir);
        }

        Ok(state)
    }

    /// Returns the version of the NSIS executable.
    #[must_use]
    #[inline]
    pub const fn version(&self) -> NsisVersion {
        self.version
    }

    /// Returns `true` if the NSIS executable is Unicode, `false` otherwise.
    #[must_use]
    #[inline]
    pub fn is_unicode(&self) -> bool {
        // The strings block starts with a UTF-16 null byte if it is Unicode
        self.str_block.starts_with(b"\0\0")
    }

    /// Encodes a UTF-8 string in this executable's native string encoding.
    #[must_use]
    pub fn encode(&self, string: &str) -> NsisString {
        NsisString::from_str(string, self.is_unicode())
    }

    #[inline]
    pub const fn is_park(&self) -> bool {
        self.version.is_park()
    }

    /// Returns `true` if the NSIS executable is portable.
    ///
    /// <https://www.electron.build/nsis.html#portable>
    pub fn is_portable(&self) -> bool {
        const PORTABLE_EXECUTABLE_DIR: &str = "PORTABLE_EXECUTABLE_DIR";
        const PORTABLE_EXECUTABLE_FILE: &str = "PORTABLE_EXECUTABLE_FILE";
        const PORTABLE_EXECUTABLE_APP_FILENAME: &str = "PORTABLE_EXECUTABLE_APP_FILENAME";
        const PORTABLE_ENVIRONMENT_VARIABLES: [&str; 3] = [
            PORTABLE_EXECUTABLE_DIR,
            PORTABLE_EXECUTABLE_FILE,
            PORTABLE_EXECUTABLE_APP_FILENAME,
        ];

        self.mock_caller
            .kernel32()
            .environment_variables()
            .keys()
            .any(|key| PORTABLE_ENVIRONMENT_VARIABLES.contains(&&**key))
    }

    /// Resolves the string at `relative_offset` in the strings block, substituting any variables,
    /// shell folders, and language strings it references. A negative offset refers to a string in
    /// the language table. The string is borrowed from the strings block when it needs no
    /// substitution, and is `$ERROR` if the offset is invalid.
    pub fn get_string(&self, relative_offset: i32) -> NsisCow<'data> {
        self.get_string_inner(relative_offset, 0)
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "Truncating u16 as u8 is intentional"
    )]
    fn get_string_inner(&self, relative_offset: i32, depth: usize) -> NsisCow<'data> {
        if depth >= 64 {
            return NsisCow::Borrowed(NsisStr::error());
        }
        // The strings block starts with a UTF-16 null byte if it is Unicode
        let unicode = self.is_unicode();

        // Double the offset if the string is Unicode as each character will be 2 bytes
        let offset = if relative_offset.is_negative() {
            // A negative offset means it's a language string from the language table
            let Some(offset) = self
                .language_table
                .string_offset((relative_offset + 1).unsigned_abs() as usize)
            else {
                return NsisCow::Borrowed(NsisStr::error());
            };

            offset.unsigned_abs() as usize
        } else {
            relative_offset.unsigned_abs() as usize
        } * (usize::from(unicode) + 1);

        let Some(offset_slice) = self.str_block.get(offset..) else {
            return NsisCow::Borrowed(NsisStr::error());
        };

        // Get the index of the null byte at the end of the string
        let string_end_index = if unicode {
            let (chunks, _remainder) = offset_slice.as_chunks();
            chunks
                .iter()
                .position(|chunk| chunk == b"\0\0")
                .map(|index| index * size_of::<u16>())
        } else {
            memchr::memchr(0, offset_slice)
        }
        .unwrap_or(offset_slice.len());

        let string_bytes = &offset_slice[..string_end_index];
        if unicode && string_bytes.len() % size_of::<u16>() != 0 {
            return Cow::Borrowed("$ERROR");
        }

        let string_chars = if unicode {
            assert_eq!(string_bytes.len() % size_of::<u16>(), 0);
            Either::Left(<[U16<LE>]>::ref_from_bytes(string_bytes).unwrap())
        } else {
            Either::Right(string_bytes)
        };

        // Park's Unicode fork uses U+E000..U+E003 and 15-bit parameters.
        let normalize_code = |unit: u16| {
            if unicode && self.is_park() && (0xE000..=0xE003).contains(&unit) {
                unit - 0xE000 + 252
            } else {
                unit
            }
        };

        // Check whether the string contains any special characters that need to be decoded
        let contains_code = match string_chars {
            Either::Left(chars) => chars
                .iter()
                .any(|char| NsCode::is_code(normalize_code(char.get()), self.string_version)),
            Either::Right(bytes) => bytes
                .iter()
                .any(|&char| NsCode::is_code(char, self.string_version)),
        };

        // If the string doesn't have any special characters, we can just decode it normally
        if !contains_code {
            return bound_string(NsisCow::Borrowed(NsisStr::from_bytes(string_bytes, unicode)));
        }

        // Create an iterator of characters represented as an unsigned 16-bit integer
        let mut characters = string_chars
            .map_left(|chars| chars.iter().copied().map(U16::get))
            .map_right(|bytes| bytes.iter().copied().map(u16::from));

        let mut buf = NsisString::new(unicode);

        while let Some(mut current) = characters.next() {
            if buf.len() >= MAX_STRING_LENGTH {
                break;
            }
            if let Some(code) =
                NsCode::try_new_with_version(normalize_code(current), self.string_version)
            {
                let Some(next) = characters.next() else {
                    break;
                };
                if !code.is_skip() {
                    let special_char = if unicode {
                        next
                    } else {
                        let Some(next_next) = characters.next() else {
                            break;
                        };
                        u16::from_le_bytes([next as u8, next_next as u8])
                    };
                    if code.is_shell() {
                        Shell::resolve(&mut buf, self, special_char);
                    } else {
                        let index = usize::from(if unicode && self.is_park() {
                            special_char & 0x7FFF
                        } else {
                            decode_number_from_char(special_char)
                        });
                        if code.is_var() {
                            NsVar::resolve(&mut buf, index, &self.variables, self.version);
                        } else if code.is_lang()
                            && let Some(offset) = self.language_table.string_offset(index)
                        {
                            buf.push_bounded_nsis(
                                self.get_string_inner(offset, depth + 1).as_nsis_str(),
                            );
                        }
                    }
                    continue;
                }
                current = next;
            }
            buf.push(if unicode {
                NsisChar::Wide(U16::new(current))
            } else {
                NsisChar::Ansi(current as u8)
            });
        }

        bound_string(NsisCow::Owned(buf))
    }

    pub fn file_position(&self, encoded: i32) -> u64 {
        self.file_positions
            .get(self.entry_index)
            .copied()
            .flatten()
            .unwrap_or(u64::from(encoded as u32))
    }

    pub fn registry_root(&self, root: super::registry::RegRoot) -> super::registry::RegRoot {
        root.resolve(
            self.exec_flags[super::entry::ExecFlag::ShellVarContext].get() != 0,
            self.exec_flags[super::entry::ExecFlag::RegView].get(),
        )
    }

    /// Resolves the string at `relative_offset` and parses it as a decimal integer, or as
    /// hexadecimal if it starts with `0x`. Returns `0` if the string is not a valid integer.
    pub fn get_int(&self, relative_offset: i32) -> i32 {
        parse_int(&self.get_string(relative_offset).to_string_lossy())
    }

    pub fn get_int64(&self, relative_offset: i32) -> i64 {
        parse_int64(&self.get_string(relative_offset).to_string_lossy())
    }

    pub fn ini_file(&mut self, path: &str, create: bool) -> io::Result<&mut super::ini::IniFile> {
        use super::file_system::RelativeLocation;
        let id = if let Some(id) = self.file_system.get_id(path, RelativeLocation::Current) {
            id
        } else if create {
            let id = self
                .file_system
                .create_file(path, None, 0u64, RelativeLocation::Current)
                .ok_or_else(|| io::Error::other("Invalid INI filename"))?;
            self.ini_files.insert(id, super::ini::IniFile::default());
            id
        } else {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        };
        if !self.ini_files.contains_key(&id) {
            let bytes = self
                .files
                .bytes(id, self.read_file)
                .ok_or_else(|| io::Error::other("INI file contents are unavailable"))?;
            if bytes.len() > 8 * 1024 * 1024 {
                return Err(io::Error::other("INI file exceeds simulation limit"));
            }
            self.ini_files
                .insert(id, super::ini::IniFile::parse(&bytes));
        }
        Ok(self.ini_files.get_mut(&id).expect("INI file was inserted"))
    }

    /// Execute a NSIS code section.
    ///
    /// <https://github.com/NSIS-Dev/nsis/blob/v311/Source/exehead/exec.c#L79>
    pub fn execute_code_segment(&mut self, position: i32) -> Result<Entry, EntryError> {
        let mut position = position;
        let mut calls = Vec::new();
        let mut total_steps = 0usize;
        // File callbacks can run string-processing loops for thousands of payload
        // files. Bound the whole simulation without treating each script-sized
        // batch of instructions as an infinite loop.
        let instruction_budget = self
            .entries
            .len()
            .saturating_mul(1024)
            .clamp(128, 64 * 1024 * 1024);
        while let Ok(index) = usize::try_from(position) {
            total_steps += 1;
            if total_steps > instruction_budget {
                return Err(EntryError::InfiniteLoop);
            }
            let span = debug_span!("", "{}", index + 1);
            let _enter = span.enter();

            self.entry_index = index;
            let entry = *self.entries.get(index).ok_or(EntryError::Invalid)?;
            // Interpret calls using an explicit stack: recursive Rust calls can overflow
            // before the loop watchdog has an opportunity to run.
            if let Entry::Call { address } = entry {
                let address = self.resolve_address(address.get())?;
                // ExecuteCodeSegment(-1) is a no-op in NSIS, including Call $var
                // when the variable is empty or zero.
                if address == 0 {
                    position += 1;
                    continue;
                }
                if calls.len() >= 128 {
                    return Err(EntryError::InfiniteLoop);
                }
                calls.push(position + 1);
                position = address - 1;
                continue;
            }
            let address = entry.execute(self)?;

            if entry == Entry::Quit {
                return Ok(entry);
            }
            if entry == Entry::Return {
                if let Some(return_position) = calls.pop() {
                    position = return_position;
                    continue;
                }
                return Ok(entry);
            }

            let resolved_address = self.resolve_address(address)?;
            if resolved_address == 0 {
                position += 1;
            } else {
                position = resolved_address - 1; // -1 because addresses are encoded as +1
            }
        }

        Ok(Entry::Return)
    }

    pub fn resolve_address(&self, address: i32) -> Result<i32, EntryError> {
        if address.is_negative() {
            let address = self
                .variables
                .get(&((address.unsigned_abs() - 1) as usize))
                .map(|address| parse_int(&address.to_string_lossy()))
                .unwrap_or_default();
            (address >= 0).then_some(address).ok_or(EntryError::Invalid)
        } else {
            Ok(address)
        }
    }
}

/// NSIS strtoiptr/myatoi accepts hexadecimal and octal, stops at the first
/// non-digit, and wraps arithmetic. Script integer operations use the low 32 bits.
pub(super) fn parse_int(value: &str) -> i32 {
    parse_int64(value) as i32
}

pub(super) fn parse_int64(value: &str) -> i64 {
    let (negative, mut value) = value
        .strip_prefix('-')
        .map_or((false, value), |s| (true, s));
    let mut radix = 10u32;
    if let Some(rest) = value.strip_prefix('0') {
        value = rest;
        if matches!(value.as_bytes().first(), Some(b'0'..=b'7')) {
            radix = 8;
        } else if value.starts_with(['x', 'X']) {
            radix = 16;
            value = &value[1..];
        }
    }
    let mut result = 0u64;
    for digit in value.chars() {
        let Some(digit) = digit.to_digit(radix) else {
            break;
        };
        result = result
            .wrapping_mul(u64::from(radix))
            .wrapping_add(u64::from(digit));
    }
    if negative {
        result.wrapping_neg() as i64
    } else {
        result as i64
    }
}

const fn decode_number_from_char(mut char: u16) -> u16 {
    const ASCII_MASK: u16 = u16::from_le_bytes([u8::MAX >> 1; size_of::<u16>()]);

    // Convert each byte into ASCII value range (0x00 - 0x7F)
    char &= ASCII_MASK;
    let le_bytes = char.to_le_bytes();
    le_bytes[0] as u16 | ((le_bytes[1] as u16) << 7)
}

#[cfg(test)]
mod tests {
    use zerocopy::TryFromBytes;

    use super::*;
    use crate::analysis::installers::nsis::{entry::ExecFlag, registry::RegRoot};

    #[test]
    fn integer_literals_follow_nsis_conversion() {
        for (input, expected) in [
            ("0xFFFFFFFF", -1),
            ("4294967295", -1),
            ("4294967296", 0),
            ("010", 8),
            ("08", 8),
            ("-0x10", -16),
            ("12suffix", 12),
            ("+7", 0),
            (" 7", 0),
            ("", 0),
        ] {
            assert_eq!(parse_int(input), expected, "{input}");
        }
        assert_eq!(parse_int64("4294967296"), 4294967296);
        assert_eq!(parse_int64("0xffffffffffffffff"), -1);
    }

    #[test]
    fn copying_past_the_start_of_a_symbolic_path_terminates_a_backwards_scan() {
        let mut read = |_| Ok(Cursor::new(Vec::new()));
        let mut state = state(b"\0$EXEDIR\0-7\0-8\0-2147483648\x001\0", &[], &mut read);
        for (offset, expected) in [(9, "$"), (12, ""), (15, "")] {
            Entry::AssignVar {
                variable: I32::ZERO,
                string_offset: I32::new(1),
                max_length: I32::new(27),
                start_position: I32::new(offset),
            }
            .execute(&mut state)
            .unwrap();
            assert_eq!(
                state
                    .variables
                    .get(&0)
                    .map(|value| value.to_string_lossy().into_owned())
                    .as_deref()
                    .unwrap_or_default(),
                expected
            );
        }
    }

    #[test]
    fn integer_comparison_uses_its_encoded_width_and_signedness() {
        let mut read = |_| Ok(Cursor::new(Vec::new()));
        let mut state = state(b"\0-4294967296\0-1\0", &[], &mut read);
        let entry = |flags| Entry::IntCmp {
            val_1: I32::new(1),
            val_2: I32::new(13),
            equal: I32::new(1),
            val1_lt_val2: I32::new(2),
            val1_gt_val2: I32::new(3),
            flags: I32::new(flags),
        };
        assert_eq!(entry(0x8000).execute(&mut state), Ok(2));
        assert_eq!(entry(0).execute(&mut state), Ok(3));
    }

    fn state<'a>(
        strings: &'a [u8],
        entries: &'a [Entry],
        read_file: &'a mut dyn FnMut(u64) -> io::Result<Cursor<Vec<u8>>>,
    ) -> NsisState<'a> {
        // One language string referring to offset 1.
        let language_table =
            LanguageTable::ref_from_bytes(&[9, 4, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]).unwrap();
        NsisState {
            read_file,
            str_block: strings,
            entries: Cow::Borrowed(entries),
            language_table,
            stack: Vec::new(),
            variables: Variables::new(),
            registry: Registry::new(),
            file_system: FileSystem::new(),
            files: Files::default(),
            ini_files: HashMap::new(),
            find_handles: HashMap::new(),
            exec_flags: ExecFlags::new(),
            last_used_exec_flags: ExecFlags::new(),
            status_up_hack: I32::ZERO,
            mock_caller: MockCaller::new(),
            version: NsisVersion::v3(),
            string_version: NsisVersion::v3(),
            file_positions: Vec::new(),
            entry_index: 0,
            section_flags: Vec::new(),
        }
    }

    #[test]
    fn window_queries_replace_stale_values_and_message_boxes_take_the_default_branch() {
        let mut read = |_| Ok(Cursor::new(Vec::new()));
        let mut state = state(b"\0AppWindow\0Continue?\0", &[], &mut read);
        state.variables.insert(0, "1");
        state.exec_flags[ExecFlag::Errors] = I32::new(7);
        Entry::FindWindow {
            output: I32::ZERO,
            window_class: I32::new(1),
            window_name: I32::ZERO,
            window_parent: I32::ZERO,
            window_after: I32::ZERO,
        }
        .execute(&mut state)
        .unwrap();
        assert_eq!(
            state
                .variables
                .get(&0)
                .map(|value| value.to_string_lossy().into_owned())
                .as_deref(),
            Some("0")
        );
        assert_eq!(state.exec_flags[ExecFlag::Errors].get(), 7);
        assert_eq!(
            Entry::IsWindow {
                window_handle: I32::ZERO,
                jump_if_window: I32::new(100),
                jump_if_not_window: I32::new(200),
            }
            .execute(&mut state),
            Ok(200)
        );
        let raw: Vec<_> = [22i32, 4, 11, 7, 100, 6, 200]
            .into_iter()
            .flat_map(i32::to_le_bytes)
            .collect();
        let message = Entry::try_read_from_bytes(&raw).unwrap();
        assert_eq!(message.execute(&mut state), Ok(200));
    }

    #[test]
    fn missing_file_reads_clear_stale_metadata_and_signal_errors() {
        let mut read = |_| Err(io::ErrorKind::NotFound.into());
        let mut state = state(b"\0missing.txt\08191\0", &[], &mut read);
        state.variables.insert(0, "1610612752");
        state.variables.insert(1, "1610612752");
        let bytes: Vec<_> = [55i32, 0, i32::MIN, 3, 1, 0, 0]
            .into_iter()
            .flat_map(i32::to_le_bytes)
            .collect();
        Entry::try_read_from_bytes(&bytes)
            .unwrap()
            .execute(&mut state)
            .unwrap();
        assert_eq!(
            state
                .variables
                .get(&0)
                .map(|value| value.to_string_lossy().into_owned())
                .as_deref(),
            Some("")
        );
        assert_eq!(state.exec_flags[ExecFlag::Errors].get(), 1);
        state.exec_flags[ExecFlag::Errors] = I32::ZERO;
        Entry::FileReadUTF16LE {
            handle: I32::ZERO,
            output: I32::new(1),
            max_length: I32::new(13),
            get_char_gets: I32::ZERO,
        }
        .execute(&mut state)
        .unwrap();
        assert_eq!(
            state
                .variables
                .get(&1)
                .map(|value| value.to_string_lossy().into_owned())
                .as_deref(),
            Some("")
        );
        assert_eq!(state.exec_flags[ExecFlag::Errors].get(), 1);
    }

    #[test]
    fn registry_reads_replace_or_clear_the_output_register() {
        let mut read = |_| Ok(Cursor::new(Vec::new()));
        let mut state = state(b"\0Key\0Version\0", &[], &mut read);
        state
            .registry
            .insert_value(RegRoot::HKEY_CURRENT_USER, "Key", "Version", "1.2.3");
        let entry = Entry::ReadReg {
            output: I32::new(0),
            root: RegRoot::HKEY_CURRENT_USER,
            key_name: I32::new(1),
            value_name: I32::new(5),
            r#type: I32::ZERO,
        };
        state.variables.insert(0, "stale");
        entry.execute(&mut state).unwrap();
        assert_eq!(
            state
                .variables
                .get(&0)
                .map(|value| value.to_string_lossy().into_owned())
                .as_deref(),
            Some("1.2.3")
        );
        state.registry.remove_key(RegRoot::HKEY_CURRENT_USER, "Key");
        entry.execute(&mut state).unwrap();
        assert_eq!(
            state
                .variables
                .get(&0)
                .map(|value| value.to_string_lossy().into_owned())
                .as_deref(),
            Some("")
        );
        assert_eq!(state.exec_flags[ExecFlag::Errors].get(), 1);
    }

    #[test]
    fn account_type_plugins_preserve_saved_registers_on_the_stack() {
        let mut read = |_| Ok(Cursor::new(Vec::new()));
        let strings = b"\0Plugins\\userinfo.DLL\0GetAccountType\0GetOriginalAccountType\0";
        let mut state = state(strings, &[], &mut read);
        for function in [22, 37] {
            state.stack = vec!["0".into(), "".into()];
            state.exec_flags[ExecFlag::Errors] = I32::new(1);
            Entry::RegisterDLL {
                dll_file_name: I32::new(1),
                function: I32::new(function),
                display_text: I32::ZERO,
                no_unload: I32::ZERO,
            }
            .execute(&mut state)
            .unwrap();
            assert_eq!(
                state
                    .stack
                    .pop()
                    .map(|value| value.into_string_lossy())
                    .as_deref(),
                Some("Admin")
            );
            assert_eq!(
                state
                    .stack
                    .pop()
                    .map(|value| value.into_string_lossy())
                    .as_deref(),
                Some("")
            );
            assert_eq!(
                state
                    .stack
                    .pop()
                    .map(|value| value.into_string_lossy())
                    .as_deref(),
                Some("0")
            );
            assert_eq!(state.exec_flags[ExecFlag::Errors].get(), 1);
        }
    }

    #[test]
    fn account_type_plugin_preserves_the_arp_display_name_suffix() {
        let mut strings = vec![0];
        let mut add_string = |value: &[u8]| {
            let offset = strings.len() as i32;
            strings.extend(value);
            strings.push(0);
            offset
        };
        let dll = add_string(b"Plugins\\UserInfo.dll");
        let function = add_string(b"GetAccountType");
        let key = add_string(b"Firefox Developer Edition");
        let registers = [0x80, 0x81, 0x82, 0x83].map(|index| add_string(&[3, index, 0x80]));
        let name = add_string(b"Firefox Developer Edition\x03\x83\x80 (x64 gu-IN)");
        let [r0, r1, r2, r3] = registers;
        // The stack/register convention used by Firefox's getUninstallKey and
        // its nested UserInfo call. The empty $3 is the non-ESR name suffix.
        let entries = [
            [31, r3, 0, 0, 0, 0, 0], // Push $3
            [31, 0, 0, 1, 0, 0, 0],  // Exch
            [31, 3, 1, 0, 0, 0, 0],  // Pop $3
            [31, r0, 0, 0, 0, 0, 0],
            [31, r1, 0, 0, 0, 0, 0],
            [31, r2, 0, 0, 0, 0, 0],
            [5, 16, 0, 0, 0, 0, 0], // Call the account helper
            [25, 3, key, 0, 0, 0, 0],
            [31, 2, 1, 0, 0, 0, 0],
            [31, 1, 1, 0, 0, 0, 0],
            [31, 0, 1, 0, 0, 0, 0],
            [31, r3, 0, 0, 0, 0, 0],
            [31, 0, 0, 1, 0, 0, 0],
            [31, 3, 1, 0, 0, 0, 0],
            [1, 0, 0, 0, 0, 0, 0],
            [31, r0, 0, 0, 0, 0, 0], // Save $0 across UserInfo
            [44, dll, function, 0, 0, 0, 0],
            [31, 0, 1, 0, 0, 0, 0], // Pop the account type
            [31, 0, 1, 0, 0, 0, 0], // Restore $0
            [1, 0, 0, 0, 0, 0, 0],
        ]
        .map(|values| {
            let bytes: Vec<_> = values.into_iter().flat_map(i32::to_le_bytes).collect();
            Entry::try_read_from_bytes(&bytes).unwrap()
        });
        let mut read = |_| Ok(Cursor::new(Vec::new()));
        let mut state = state(&strings, &entries, &mut read);
        state.variables.insert(0, "0");
        state.variables.insert(3, "");
        state.stack = vec!["sentinel".into(), "26300".into()];
        assert_eq!(state.execute_code_segment(0), Ok(Entry::Return));
        assert_eq!(state.stack, ["sentinel", "Firefox Developer Edition"]);
        assert_eq!(
            state
                .variables
                .get(&3)
                .map(|value| value.to_string_lossy().into_owned())
                .as_deref(),
            Some("")
        );
        assert_eq!(
            state.get_string(name),
            "Firefox Developer Edition (x64 gu-IN)"
        );
    }

    #[test]
    fn decodes_park_variable_parameters() {
        let mut read = |_| Ok(Cursor::new(Vec::new()));
        let mut state = state(b"\0\0\x01\xe0\x00\x80\0\0", &[], &mut read);
        state.version = NsisVersion::detect(state.str_block);
        // Two Park code points are needed for automatic detection.
        state.version = NsisVersion::from_manifest("<assembly><description>Nullsoft Install System v2.46.5-Unicode</description></assembly>").unwrap();
        state.string_version = state.version;
        state.variables.insert(0, "App");
        assert_eq!(state.get_string(1), "App");
    }

    #[test]
    fn advertised_version_does_not_replace_observed_string_encoding() {
        let mut read = |_| Ok(Cursor::new(Vec::new()));
        let mut state = state(b"\0\0\x03\0\x80\x80\0\0", &[], &mut read);
        state.version = NsisVersion::new(2, 46);
        state.variables.insert(0, "App");
        assert_eq!(state.get_string(1), "App");
    }

    #[test]
    fn handles_truncated_and_unterminated_strings() {
        let mut read = |_| Ok(Cursor::new(Vec::new()));
        assert_eq!(state(b"", &[], &mut read).get_string(0), "");
        assert_eq!(state(b"\0tail", &[], &mut read).get_string(1), "tail");
        assert_eq!(state(b"\0\0t\0", &[], &mut read).get_string(1), "t");
        assert_eq!(state(b"\0\0t", &[], &mut read).get_string(1), "$ERROR");
        assert_eq!(state(b"\0", &[], &mut read).get_string(i32::MAX), "$ERROR");
    }

    #[test]
    fn bounds_recursive_language_strings() {
        let mut read = |_| Ok(Cursor::new(Vec::new()));
        let state = state(b"\0\0\x01\0\x80\x80\0\0", &[], &mut read);
        assert_eq!(state.get_string(1), "$ERROR");
    }

    #[test]
    fn rejects_out_of_bounds_instructions() {
        let mut read = |_| Ok(Cursor::new(Vec::new()));
        let entries = [Entry::Jump {
            address: I32::new(100),
        }];
        assert_eq!(
            state(b"\0", &entries, &mut read).execute_code_segment(0),
            Err(EntryError::Invalid)
        );
    }

    #[test]
    fn file_enumeration_can_repeat_more_times_than_the_script_has_instructions() {
        let mut read = |_| Ok(Cursor::new(Vec::new()));
        let entries = [
            Entry::FindNext {
                output: I32::ZERO,
                handle: I32::new(1),
            },
            Entry::IfFlag {
                on: I32::new(3),
                off: I32::new(1),
                r#type: ExecFlag::Errors,
                new_value_mask: I32::ZERO,
            },
            Entry::Return,
        ];
        let mut state = state(b"\0", &entries, &mut read);
        state.variables.insert(1, "0");
        state
            .find_handles
            .insert(0, (0..100).map(|i| format!("file{i}.dll")).collect());
        assert_eq!(state.execute_code_segment(0), Ok(Entry::Return));
        assert_eq!(state.find_handles[&0].len(), 0);
    }

    #[test]
    fn unconditional_loops_still_exhaust_the_total_instruction_budget() {
        let mut read = |_| Ok(Cursor::new(Vec::new()));
        let entries = [Entry::Jump {
            address: I32::new(1),
        }];
        assert_eq!(
            state(b"\0", &entries, &mut read).execute_code_segment(0),
            Err(EntryError::InfiniteLoop)
        );
    }

    #[test]
    fn bounds_recursive_calls() {
        let mut read = |_| Ok(Cursor::new(Vec::new()));
        let entries = [Entry::Call {
            address: I32::new(1),
        }];
        assert_eq!(
            state(b"\0", &entries, &mut read).execute_code_segment(0),
            Err(EntryError::InfiniteLoop)
        );
    }

    #[test]
    fn empty_and_zero_indirect_branches_fall_through() {
        let mut read = |_| Ok(Cursor::new(Vec::new()));
        let entries = [
            Entry::Call {
                address: I32::new(-1),
            },
            Entry::Jump {
                address: I32::new(-1),
            },
            Entry::Return,
        ];
        let mut state = state(b"\0", &entries, &mut read);
        for value in ["", "0"] {
            state.variables.insert(0, value);
            assert_eq!(state.resolve_address(-1), Ok(0));
            assert_eq!(state.execute_code_segment(0), Ok(Entry::Return));
            assert_eq!(state.entry_index, 2);
        }
    }
}
