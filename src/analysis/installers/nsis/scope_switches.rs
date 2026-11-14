//! Conservative recognition of the standard electron-builder and Tauri switch
//! handlers. String-table markers alone do not establish scope-switch support.
use std::collections::HashSet;

use super::{
    entry::{Entry, ExecFlag},
    strings::PredefinedVar,
    variables::Variables,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeSwitches {
    ElectronBuilder,
    Tauri,
}

impl ScopeSwitches {
    pub fn switches(self) -> [(&'static str, winget_types::installer::Scope); 2] {
        use winget_types::installer::Scope;
        match self {
            Self::ElectronBuilder => [("/currentuser", Scope::User), ("/allusers", Scope::Machine)],
            Self::Tauri => [("/CurrentUser", Scope::User), ("/AllUsers", Scope::Machine)],
        }
    }
}

pub fn detect(
    entries: &[Entry],
    text: impl Fn(i32) -> String,
    variable: impl Fn(i32) -> Option<usize>,
    strings: &[u8],
) -> Option<ScopeSwitches> {
    let decoded;
    let strings = if strings.starts_with(b"\0\0") {
        decoded = String::from_utf16_lossy(
            &strings
                .chunks_exact(2)
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .collect::<Vec<_>>(),
        );
        decoded.as_bytes()
    } else {
        strings
    };
    let literals = strings.split(|&b| b == 0).collect::<Vec<_>>();
    let electron = literals.iter().any(|s| {
        let name = s
            .rsplit(|&b| b == b'\\' || b == b'/')
            .next()
            .unwrap_or_default();
        [
            b"app-32.7z".as_slice(),
            b"app-64.7z",
            b"app-arm64.7z",
            b"app-32.zip",
            b"app-64.zip",
            b"app-arm64.zip",
            b"app-32",
            b"app-64",
            b"app-arm64",
        ]
        .contains(&name)
    });
    let tauri = [
        b"nsis_tauri_utils.dll".as_slice(),
        b"MainBinaryName",
        b"placeholder\\",
    ]
    .iter()
    .all(|marker| {
        literals.iter().any(|s| {
            if *marker == b"placeholder\\" {
                s.starts_with(marker)
            } else {
                s.ends_with(marker)
            }
        })
    });
    if !electron && !tauri {
        return None;
    }

    let supported = [false, true].into_iter().all(|machine| {
        entries.iter().enumerate().any(|(index, entry)| {
            let Entry::PushPop { variable_or_string, push_pop, exchange } = *entry else { return false; };
            if !push_pop.is_push() || exchange.get() != 0 { return false; }
            let parameter = text(variable_or_string.get());
            let is_electron = electron && parameter == if machine { "allusers" } else { "currentuser" };
            let is_tauri = !electron && tauri && parameter == if machine { "/AllUsers" } else { "/CurrentUser" };
            let mut parser = index + 1;
            if is_electron {
                // makensis inserts InitPluginsDir, extraction and detail-output
                // restoration before a plug-in call, even after its arguments.
                if let Some(Entry::Call { address }) = entries.get(parser) {
                    let Some(target) = destination(address.get(), entries.len()) else { return false; };
                    let Some([Entry::SetFlag { r#type: ExecFlag::DetailsPrint, mode, .. }, Entry::StrCmp { str_1, str_2, .. }]) = entries.get(target..target.saturating_add(2)) else { return false; };
                    if !matches!(mode.get(), -1 | 0) || variable(str_1.get()) != Some(Variables::NUM_REGISTERS + PredefinedVar::PluginsDir as usize) || !text(str_2.get()).is_empty() { return false; }
                    parser += 1;
                }
                if matches!(entries.get(parser), Some(Entry::ExtractFile { .. })) { parser += 1; }
                if matches!(entries.get(parser), Some(Entry::SetFlag { r#type: ExecFlag::DetailsPrint, .. })) { parser += 1; }
            }
            let Some(window) = entries.get(parser..parser.saturating_add(3)) else { return false; };
            match window[0] {
                Entry::RegisterDLL { dll_file_name, function, display_text, .. } if is_electron => {
                    if display_text.get() != 0 || !text(dll_file_name.get()).ends_with("StdUtils.dll")
                        || text(function.get()) != "TestParameter" { return false; }
                }
                Entry::Call { address } if is_tauri => {
                    // StrStr's generated wrapper pushes the command line before
                    // the search term. Require its compiled string-search body.
                    if index == 0 || !matches!(entries[index - 1], Entry::PushPop { push_pop, exchange, .. } if push_pop.is_push() && exchange.get() == 0)
                        || !is_string_search(entries, address.get(), &text, &variable) { return false; }
                }
                _ => return false,
            }
            let Entry::PushPop { variable_or_string: output, push_pop, exchange } = window[1] else { return false; };
            if !push_pop.is_pop() || exchange.get() != 0 { return false; }
            let Entry::StrCmp { str_1, str_2, jump_if_equal, jump_if_not_equal, .. } = window[2] else { return false; };
            let Ok(output) = usize::try_from(output.get()) else { return false; };
            let literal = if variable(str_1.get()) == Some(output) {
                text(str_2.get())
            } else if variable(str_2.get()) == Some(output) {
                text(str_1.get())
            } else { return false; };
            let equal = if is_electron {
                match literal.as_str() { "true" => true, "false" => false, _ => return false }
            } else {
                if !literal.is_empty() { return false; }
                false // StrStr returns a nonempty suffix when the switch exists.
            };
            let jump = if equal { jump_if_equal } else { jump_if_not_equal }.get();
            let Some(start) = destination(jump, parser + 3) else { return false; };
            reaches_scope(entries, &text, start, machine)
        })
    });
    supported.then_some(if electron {
        ScopeSwitches::ElectronBuilder
    } else {
        ScopeSwitches::Tauri
    })
}

fn destination(address: i32, fallthrough: usize) -> Option<usize> {
    if address == 0 {
        Some(fallthrough)
    } else {
        usize::try_from(address.checked_sub(1)?).ok()
    }
}

// Recognize StrFunc.nsh's StrStr data flow: measure needle and haystack,
// compare a sliding window with the needle, and return the matching suffix.
fn is_string_search(
    entries: &[Entry],
    address: i32,
    text: &impl Fn(i32) -> String,
    variable: &impl Fn(i32) -> Option<usize>,
) -> bool {
    let Some(start) = destination(address, entries.len()) else {
        return false;
    };
    let body = entries.get(start..).unwrap_or_default();
    let end = body
        .iter()
        .take(96)
        .position(|entry| matches!(entry, Entry::Return))
        .unwrap_or(0);
    let body = &body[..end];
    body.windows(5).enumerate().any(|(index, window)| {
        let [Entry::StrLen { output: needle_len, input: needle },
             Entry::StrLen { input: haystack, .. },
             Entry::AssignVar { variable: counter, string_offset: zero, .. },
             Entry::AssignVar { variable: part, string_offset: source, max_length, start_position },
             Entry::StrCmp { str_1, str_2, .. }] = window else { return false; };
        let register = |operand: i32, output: i32| usize::try_from(output).is_ok_and(|output| variable(operand) == Some(output));
        if text(zero.get()) != "0" || variable(needle.get()).is_none()
            || variable(haystack.get()).is_none() || source != haystack
            || !register(max_length.get(), needle_len.get())
            || !register(start_position.get(), counter.get())
            || !register(str_1.get(), part.get()) || str_2 != needle { return false; }
        let suffix = body.iter().any(|entry| matches!(entry,
            Entry::AssignVar { string_offset, max_length, start_position, .. }
                if string_offset == haystack && max_length.get() == 0
                    && register(start_position.get(), counter.get())));
        let increment = body.iter().any(|entry| matches!(entry,
            Entry::IntOp { output, input1, input2, operation }
                if output == counter && register(input1.get(), counter.get())
                    && text(input2.get()) == "1" && operation.get() == 0));
        let loop_back = body.iter().any(|entry| matches!(entry,
            Entry::Jump { address } if destination(address.get(), entries.len()) == Some(start + index + 3)));
        suffix && increment && loop_back
    })
}

// Follow direct calls and jumps from the switch's successful comparison. Stop
// at the first shell context on each path; never scan across Return or Quit.
// Other conditions (e.g. administrative privileges) are possible paths, not
// claims that installation will succeed on the machine running Komac.
fn reaches_scope(
    entries: &[Entry],
    text: &impl Fn(i32) -> String,
    start: usize,
    machine: bool,
) -> bool {
    let mut pending = vec![(start, Vec::<usize>::new())];
    let mut visited = HashSet::new();
    for _ in 0..512 {
        let Some((index, mut calls)) = pending.pop() else {
            break;
        };
        if !visited.insert((index, calls.clone())) {
            continue;
        }
        let Some(entry) = entries.get(index) else {
            continue;
        };
        let mut next = |address| {
            if let Some(target) = destination(address, index + 1) {
                pending.push((target, calls.clone()));
            }
        };
        match entry {
            Entry::Return => {
                if let Some(target) = calls.pop() {
                    pending.push((target, calls));
                }
            }
            Entry::Quit | Entry::Abort { .. } | Entry::Invalid => {}
            Entry::Jump { address } => next(address.get()),
            Entry::Call { address } => {
                if address.get() > 0 && calls.len() < 16 {
                    calls.push(index + 1);
                    pending.push(((address.get() - 1) as usize, calls));
                }
            }
            Entry::StrCmp {
                jump_if_equal,
                jump_if_not_equal,
                ..
            } => {
                next(jump_if_equal.get());
                next(jump_if_not_equal.get());
            }
            Entry::IfFlag { on, off, .. } => {
                next(on.get());
                next(off.get());
            }
            Entry::IfFileExists {
                jump_amount_if_exists,
                jump_amount_if_not_exists,
                ..
            } => {
                next(jump_amount_if_exists.get());
                next(jump_amount_if_not_exists.get());
            }
            Entry::IsWindow {
                jump_if_window,
                jump_if_not_window,
                ..
            } => {
                next(jump_if_window.get());
                next(jump_if_not_window.get());
            }
            Entry::MessageBox { jump_1, jump_2, .. } => {
                next(0);
                next(jump_1.get());
                next(jump_2.get());
            }
            Entry::IntCmp {
                equal,
                val1_lt_val2,
                val1_gt_val2,
                ..
            } => {
                next(equal.get());
                next(val1_lt_val2.get());
                next(val1_gt_val2.get());
            }
            Entry::SetFlag {
                r#type: ExecFlag::ShellVarContext,
                data,
                mode,
                ..
            } => {
                if mode.get() != 0 || text(data.get()) != if machine { "1" } else { "0" } {
                    continue;
                }
                // Standard setters assign their mode immediately before setting
                // context. This excludes unrelated context changes in payload code.
                if let Some(Entry::AssignVar { string_offset, .. }) =
                    index.checked_sub(1).and_then(|i| entries.get(i))
                {
                    let value = text(string_offset.get());
                    if if machine {
                        value == "AllUsers" || value == "all"
                    } else {
                        value == "CurrentUser"
                    } {
                        return true;
                    }
                }
            }
            _ => next(0),
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use zerocopy::TryFromBytes;

    use super::*;

    fn entry(opcode: i32, args: &[i32]) -> Entry {
        let mut raw = [0i32; 7];
        raw[0] = opcode;
        raw[1..=args.len()].copy_from_slice(args);
        Entry::try_read_from_bytes(
            &raw.into_iter()
                .flat_map(i32::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn fixture(tauri: bool) -> (Vec<Entry>, Vec<String>) {
        // Offsets are symbolic here; the resolver maps them to the literal or
        // direct-variable reference that an actual decoded header provides.
        let text = [
            "",
            "1",
            "0",
            "allusers",
            "currentuser",
            "$PLUGINSDIR\\StdUtils.dll",
            "TestParameter",
            "true",
            "all",
            "CurrentUser",
            "/AllUsers",
            "/CurrentUser",
            "AllUsers",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let mut entries = Vec::new();
        for machine in [false, true] {
            if tauri {
                entries.push(entry(31, &[101, 0, 0]));
            }
            entries.push(entry(
                31,
                &[
                    if tauri {
                        if machine { 10 } else { 11 }
                    } else if machine {
                        3
                    } else {
                        4
                    },
                    0,
                    0,
                ],
            ));
            entries.push(if tauri {
                entry(5, &[40])
            } else {
                entry(44, &[5, 6, 0])
            });
            entries.push(entry(31, &[9, 1, 0]));
            // A present parameter enters the setter, an absent one returns.
            let setter = entries.len() + 2;
            let end = entries.len() + 4;
            entries.push(if tauri {
                entry(26, &[100, 0, end as i32 + 1, 0])
            } else {
                entry(26, &[100, 7, 0, end as i32 + 1])
            });
            entries.push(entry(
                25,
                &[
                    30,
                    if machine {
                        if tauri { 12 } else { 8 }
                    } else {
                        9
                    },
                    0,
                    0,
                ],
            ));
            entries.push(entry(13, &[1, if machine { 1 } else { 2 }, 0, 0]));
            entries.push(entry(1, &[]));
            assert!(matches!(entries[setter - 1], Entry::AssignVar { .. }));
        }
        if tauri {
            entries.resize(39, entry(1, &[]));
            entries.extend([
                entry(24, &[2, 101]),
                entry(24, &[3, 102]),
                entry(25, &[4, 2]),
                entry(25, &[5, 102, 103, 105]),
                entry(26, &[106, 101, 48, 0]),
                entry(28, &[105, 104, 48, 0, 48]),
                entry(29, &[4, 105, 1, 0]),
                entry(2, &[43]),
                entry(25, &[0, 102, 0, 105]),
                entry(1, &[]),
            ]);
        }
        (entries, text)
    }

    fn check(entries: &[Entry], text: &[String], markers: &[u8]) -> Option<ScopeSwitches> {
        detect(
            entries,
            |offset| text.get(offset as usize).cloned().unwrap_or_default(),
            |offset| match offset {
                100 => Some(9),
                101..=106 => Some((offset - 101) as usize),
                107 => Some(26),
                _ => None,
            },
            markers,
        )
    }

    const ELECTRON: &[u8] = b"\0app-64.7z\0allusers\0currentuser\0TestParameter\0StdUtils.dll\0";
    const TAURI: &[u8] = b"\0nsis_tauri_utils.dll\0MainBinaryName\0placeholder\\\0";

    #[test]
    fn electron_accepts_makensis_plugin_setup_wrapper() {
        use zerocopy::I32;
        let (mut entries, text) = fixture(false);
        for position in [8, 1] {
            for entry in &mut entries {
                let relocate = |address: &mut I32<zerocopy::LE>| {
                    if address.get() > position as i32 {
                        address.set(address.get() + 3);
                    }
                };
                match entry {
                    Entry::StrCmp {
                        jump_if_equal,
                        jump_if_not_equal,
                        ..
                    } => {
                        relocate(jump_if_equal);
                        relocate(jump_if_not_equal);
                    }
                    _ => {}
                }
            }
            entries.splice(
                position..position,
                [
                    entry(5, &[-100]),
                    entry(20, &[0, 5]),
                    entry(13, &[13, 0, 1, -1]),
                ],
            );
        }
        let init = entries.len() as i32 + 1;
        for instruction in &mut entries {
            if let Entry::Call { address } = instruction {
                address.set(init);
            }
        }
        entries.extend([entry(13, &[13, 0, -1]), entry(26, &[107, 0]), entry(1, &[])]);
        assert_eq!(
            check(&entries, &text, ELECTRON),
            Some(ScopeSwitches::ElectronBuilder)
        );
        // Older makensis saves DetailsPrint with mode 0; newer builds use -1.
        entries[init as usize - 1] = entry(13, &[13, 0, 0]);
        assert_eq!(
            check(&entries, &text, ELECTRON),
            Some(ScopeSwitches::ElectronBuilder)
        );
    }

    #[test]
    fn electron_requires_compiled_handlers_and_both_contexts() {
        let (mut entries, text) = fixture(false);
        assert_eq!(
            check(&entries, &text, ELECTRON),
            Some(ScopeSwitches::ElectronBuilder)
        );
        assert_eq!(check(&[], &text, ELECTRON), None);
        assert_eq!(check(&entries, &text, b"\0app.exe\0"), None);
        entries[12] = entry(13, &[1, 2]); // machine handler sets user context
        assert_eq!(check(&entries, &text, ELECTRON), None);
    }

    #[test]
    fn tauri_rejects_helpers_without_string_search_data_flow() {
        let (mut entries, text) = fixture(true);
        entries[45] = entry(29, &[4, 105, 2, 0]); // decrements instead of scanning forward
        assert_eq!(check(&entries, &text, TAURI), None);
        let (mut entries, text) = fixture(true);
        entries[46] = entry(2, &[47]); // no search loop
        assert_eq!(check(&entries, &text, TAURI), None);
    }

    #[test]
    fn tauri_requires_search_calls_and_both_scope_setters() {
        let (mut entries, text) = fixture(true);
        assert_eq!(check(&entries, &text, TAURI), Some(ScopeSwitches::Tauri));
        assert_eq!(check(&[], &text, TAURI), None);
        entries[39] = entry(1, &[]); // switch passed to an unrelated helper
        assert_eq!(check(&entries, &text, TAURI), None);
    }

    #[test]
    fn unreachable_setters_and_unrelated_comparisons_are_rejected() {
        let (mut entries, text) = fixture(false);
        entries[3] = entry(26, &[100, 7, 7, 7]); // both outcomes skip setter
        assert_eq!(check(&entries, &text, ELECTRON), None);
        let (mut entries, text) = fixture(false);
        entries[3] = entry(26, &[101, 7, 0, 7]); // compares another variable
        assert_eq!(check(&entries, &text, ELECTRON), None);
        let (mut entries, text) = fixture(false);
        entries[3] = entry(26, &[100, 7, 4, 4]); // cyclic branch
        assert_eq!(check(&entries, &text, ELECTRON), None);
    }

    #[test]
    fn invalid_addresses_are_rejected() {
        assert_eq!(destination(i32::MIN, 1), None);
        let (mut entries, text) = fixture(true);
        entries[2] = entry(5, &[i32::MIN]);
        assert_eq!(check(&entries, &text, TAURI), None);
    }

    #[test]
    fn family_markers_support_unicode_headers() {
        let (entries, text) = fixture(false);
        let wide = String::from_utf8_lossy(ELECTRON)
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            check(&entries, &text, &wide),
            Some(ScopeSwitches::ElectronBuilder)
        );
    }
}
