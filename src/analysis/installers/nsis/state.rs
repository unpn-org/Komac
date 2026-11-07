use std::{
    borrow::Cow,
    collections::{HashMap, VecDeque},
    io::{self, Cursor},
};

use encoding_rs::{UTF_16LE, WINDOWS_1252};
use itertools::Either;
use tracing::{debug, debug_span};
use zerocopy::{FromBytes, I32, LE, U16};

use super::{
    Variables,
    entry::{Entry, EntryError, ExecFlags, system::MockCaller},
};
use crate::analysis::installers::nsis::{
    NsisError,
    file_system::FileSystem,
    header::Header,
    language::table::LanguageTable,
    registry::Registry,
    strings::{code::NsCode, shell::Shell, var::NsVar},
    variables::{MAX_STRING_LENGTH, NsisStringExt, bound_string},
    version::NsisVersion,
};

pub struct NsisState<'data> {
    pub read_file: &'data mut dyn FnMut(u64) -> io::Result<Cursor<Vec<u8>>>,
    pub str_block: &'data [u8],
    entries: Cow<'data, [Entry]>,
    pub language_table: &'data LanguageTable,
    pub stack: Vec<Cow<'data, str>>,
    pub variables: Variables<'data>,
    pub registry: Registry,
    pub file_system: FileSystem,
    pub find_handles: HashMap<i32, VecDeque<String>>,
    pub exec_flags: ExecFlags,
    pub last_used_exec_flags: ExecFlags,
    pub status_up_hack: I32<LE>,
    pub mock_caller: MockCaller,
    version: NsisVersion,
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
            find_handles: HashMap::new(),
            exec_flags: ExecFlags::new(),
            last_used_exec_flags: ExecFlags::new(),
            status_up_hack: I32::ZERO,
            mock_caller: MockCaller::new(),
            version: NsisVersion::default(),
            file_positions: Vec::new(),
            entry_index: 0,
        };

        state.variables.insert(
            Variables::NUM_REGISTERS + super::strings::PredefinedVar::Language as usize,
            state.language_table.id().to_string(),
        );
        state.version = NsisVersion::detect(state.str_block);
        state.entries = if header.indexed_files().is_some() {
            Cow::Owned(header.blocks().indexed_entries(data)?)
        } else if is_bi {
            let (entries, positions) = header.blocks().bi_entries(data)?;
            state.file_positions = positions;
            Cow::Owned(entries)
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

    #[expect(
        clippy::cast_possible_truncation,
        reason = "Truncating u16 as u8 is intentional"
    )]
    pub fn get_string(&self, relative_offset: i32) -> Cow<'data, str> {
        // The strings block starts with a UTF-16 null byte if it is Unicode
        let unicode = &self.str_block[..size_of::<u16>()] == b"\0\0";

        // Double the offset if the string is Unicode as each character will be 2 bytes
        let offset = if relative_offset.is_negative() {
            // A negative offset means it's a language string from the language table
            let Some(offset) = self
                .language_table
                .string_offset((relative_offset + 1).unsigned_abs() as usize)
            else {
                return Cow::Borrowed("$ERROR");
            };

            offset.unsigned_abs() as usize
        } else {
            relative_offset.unsigned_abs() as usize
        } * (usize::from(unicode) + 1);

        let Some(offset_slice) = self.str_block.get(offset..) else {
            return Cow::Borrowed("$ERROR");
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
        .unwrap_or(self.str_block.len());

        let string_bytes = &self.str_block[offset..offset + string_end_index];

        let string_chars = if unicode {
            assert_eq!(string_bytes.len() % size_of::<u16>(), 0);
            Either::Left(<[U16<LE>]>::ref_from_bytes(string_bytes).unwrap())
        } else {
            Either::Right(string_bytes)
        };

        if self.is_park() {
            todo!("NSIS Park support");
        }

        // Check whether the string contains any special characters that need to be decoded
        let contains_code = match string_chars {
            Either::Left(chars) => chars
                .iter()
                .any(|char| NsCode::is_code(char.get(), self.version)),
            Either::Right(bytes) => bytes
                .iter()
                .any(|&char| NsCode::is_code(char, self.version)),
        };

        // If the string doesn't have any special characters, we can just decode it normally
        if !contains_code {
            let encoding = if unicode { UTF_16LE } else { WINDOWS_1252 };
            return bound_string(encoding.decode_without_bom_handling(string_bytes).0);
        }

        // Create an iterator of characters represented as an unsigned 16-bit integer
        let mut characters = string_chars
            .map_left(|chars| chars.iter().copied().map(U16::get))
            .map_right(|bytes| bytes.iter().copied().map(u16::from));

        let mut buf = String::new();

        while let Some(mut current) = characters.next() {
            if buf.len() >= MAX_STRING_LENGTH {
                break;
            }
            if let Some(code) = NsCode::try_new_with_version(current, self.version) {
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
                        let index = usize::from(decode_number_from_char(special_char));
                        if code.is_var() {
                            NsVar::resolve(&mut buf, index, &self.variables, self.version);
                        } else if code.is_lang()
                            && let Some(offset) = self.language_table.string_offset(index)
                        {
                            buf.push_bounded(&self.get_string(offset));
                        }
                    }
                    continue;
                }
                current = next;
            }
            if let Some(character) = char::from_u32(u32::from(current))
                && buf.len() + character.len_utf8() <= MAX_STRING_LENGTH
            {
                buf.push(character);
            }
        }

        bound_string(Cow::Owned(buf))
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

    pub fn get_int(&self, relative_offset: i32) -> i32 {
        parse_int(&self.get_string(relative_offset))
    }

    pub fn get_int64(&self, relative_offset: i32) -> i64 {
        parse_int64(&self.get_string(relative_offset))
    }

    /// Execute a NSIS code section.
    ///
    /// <https://github.com/NSIS-Dev/nsis/blob/v311/Source/exehead/exec.c#L79>
    pub fn execute_code_segment(&mut self, position: i32) -> Result<Entry, EntryError> {
        let mut position = position;
        let mut calls = Vec::new();
        let mut total_steps = 0usize;
        // Create a watchdog counter to detect infinite loops
        let mut watchdog_counter = 0;

        // Set an infinite loop threshold to the number of total entries, as we're only simulating
        // execution of a segment, not all code
        let infinite_loop_threshold = self.entries.len();

        while let Ok(index) = usize::try_from(position) {
            total_steps += 1;
            if total_steps > self.entries.len().saturating_mul(128).max(128) {
                return Err(EntryError::InfiniteLoop);
            }
            let span = debug_span!("", "{}", index + 1);
            let _enter = span.enter();

            self.entry_index = index;
            let entry = *self.entries.get(index).ok_or(EntryError::Invalid)?;
            // Interpret calls using an explicit stack: recursive Rust calls can overflow
            // before the loop watchdog has an opportunity to run.
            if let Entry::Call { address } = entry {
                if calls.len() >= 128 {
                    return Err(EntryError::InfiniteLoop);
                }
                calls.push((position + 1, watchdog_counter));
                position = self
                    .resolve_address(address.get())?
                    .checked_sub(1)
                    .ok_or(EntryError::Invalid)?;
                watchdog_counter = 0;
                continue;
            }
            let address = entry.execute(self)?;

            if entry == Entry::Quit {
                return Ok(entry);
            }
            if entry == Entry::Return {
                if let Some((return_position, counter)) = calls.pop() {
                    position = return_position;
                    watchdog_counter = counter + 1;
                    continue;
                }
                return Ok(entry);
            }

            if watchdog_counter >= infinite_loop_threshold {
                return Err(EntryError::InfiniteLoop);
            }

            let resolved_address = self.resolve_address(address)?;
            if resolved_address == 0 {
                position += 1;
            } else {
                position = resolved_address - 1; // -1 because addresses are encoded as +1
            }

            watchdog_counter += 1;
        }

        Ok(Entry::Return)
    }

    pub fn resolve_address(&self, address: i32) -> Result<i32, EntryError> {
        if address.is_negative() {
            self.variables
                .get(&((address.unsigned_abs() - 1) as usize))
                .map(parse_int)
                .filter(|&address| address > 0)
                .ok_or(EntryError::Invalid)
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
            find_handles: HashMap::new(),
            exec_flags: ExecFlags::new(),
            last_used_exec_flags: ExecFlags::new(),
            status_up_hack: I32::ZERO,
            mock_caller: MockCaller::new(),
            version: NsisVersion::v3(),
            file_positions: Vec::new(),
            entry_index: 0,
        }
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
        assert_eq!(state.variables.get(&0), Some("1.2.3"));
        state.registry.remove_key(RegRoot::HKEY_CURRENT_USER, "Key");
        entry.execute(&mut state).unwrap();
        assert_eq!(state.variables.get(&0), Some(""));
        assert_eq!(state.exec_flags[ExecFlag::Errors].get(), 1);
    }

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
    fn handles_unset_indirect_address() {
        let mut read = |_| Ok(Cursor::new(Vec::new()));
        assert_eq!(
            state(b"\0", &[], &mut read).resolve_address(-1),
            Err(EntryError::Invalid)
        );
    }
}
