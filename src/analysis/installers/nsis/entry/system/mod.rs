mod api;
mod engine;
mod folders;
#[cfg(test)]
mod installer_tests;
mod kernel32;
mod memory;
mod registry_api;
mod syntax;
#[cfg(test)]
mod tests;

use std::borrow::Cow;

pub use engine::Context;
pub use folders::known_folder_path;
pub use kernel32::Kernel32;
use tracing::warn;

use crate::analysis::installers::nsis::{Variables, entry::ExecFlags, registry::RegType};

#[derive(Clone, Debug)]
pub struct MockCaller {
    kernel32: Kernel32,
    saved_registers: Vec<[Option<String>; Variables::NUM_REGISTERS]>,
    engine: engine::Engine,
}

impl MockCaller {
    /// Creates a new [`MockCaller`].
    #[inline]
    pub fn new() -> Self {
        Self {
            kernel32: Kernel32::new(),
            saved_registers: Vec::new(),
            engine: engine::Engine::default(),
        }
    }

    /// Returns the mock [`Kernel32`].
    #[inline]
    pub const fn kernel32(&self) -> &Kernel32 {
        &self.kernel32
    }

    /// Saves or restores the general NSIS registers for `System::Store`.
    ///
    /// The private register stack contains `$0` through `$9` and `$R0` through `$R9`.
    /// Internal variables such as `$INSTDIR` and the NSIS data stack remain separate.
    pub fn store(&mut self, command: &str, variables: &mut Variables<'_>) -> bool {
        let mut depth = self.saved_registers.len();
        for character in command.chars() {
            match character {
                'S' | 's' => {
                    depth += 1;
                    if depth > 64 {
                        return false;
                    }
                }
                'L' | 'l' => depth = depth.saturating_sub(1),
                _ => return false,
            }
        }
        for character in command.chars() {
            match character {
                'S' | 's' => self.saved_registers.push(std::array::from_fn(|index| {
                    variables.get(&index).map(str::to_owned)
                })),
                'L' | 'l' => {
                    if let Some(saved) = self.saved_registers.pop() {
                        for (index, value) in saved.into_iter().enumerate() {
                            if let Some(value) = value {
                                variables.insert(index, value);
                            } else {
                                variables.remove(&index);
                            }
                        }
                    }
                }
                _ => unreachable!("Store commands were validated above"),
            }
        }
        true
    }

    pub fn configure(
        &mut self,
        architecture: winget_types::installer::Architecture,
        unicode: bool,
        manifest: Option<&str>,
    ) {
        let environment = &mut self.engine.environment;
        environment.pointer = if architecture.is_64_bit() { 8 } else { 4 };
        environment.process_machine = match architecture {
            winget_types::installer::Architecture::Arm64 => 0xaa64,
            _ if architecture.is_64_bit() => 0x8664,
            _ => 0x14c,
        };
        if environment.process_machine == 0xaa64
            && std::env::var_os("KOMAC_NSIS_NATIVE_ARCH").is_none()
        {
            environment.native_machine = 0xaa64;
        }
        environment.unicode = unicode;
        let manifest = manifest.unwrap_or_default().to_ascii_lowercase();
        environment.version_manifest = manifest.contains("8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a");
        environment.version_81_manifest = manifest.contains("1f676c76-80e1-4239-95bb-83d0f6d0da78");
        let mut shared = vec![0; 4096];
        shared[0x2c..0x2e].copy_from_slice(&0x14cu16.to_le_bytes());
        shared[0x2e..0x30].copy_from_slice(&environment.native_machine.to_le_bytes());
        self.engine.memory.map_shared(0x7ffe0000, shared);
    }

    pub fn advance_time(&mut self, milliseconds: u64) {
        self.engine.environment.ticks = self.engine.environment.ticks.saturating_add(milliseconds);
    }

    /// Returns an OS registry value from the configured Windows profile.
    pub fn windows_registry_value(&mut self, key: &str, name: &str) -> Option<(String, RegType)> {
        if !key
            .trim_end_matches('\\')
            .eq_ignore_ascii_case(r"Software\Microsoft\Windows NT\CurrentVersion")
        {
            return None;
        }
        let version = self.engine.environment.version;
        let (value, kind) = match name.to_ascii_lowercase().as_str() {
            "currentversion" => (
                if version >= (6, 3, 0) {
                    "6.3".to_owned()
                } else {
                    format!("{}.{}", version.0, version.1)
                },
                RegType::String,
            ),
            "currentbuild" | "currentbuildnumber" => (version.2.to_string(), RegType::String),
            "currentmajorversionnumber" if version.0 >= 10 => {
                (version.0.to_string(), RegType::DWord)
            }
            "currentminorversionnumber" if version.0 >= 10 => {
                (version.1.to_string(), RegType::DWord)
            }
            "ubr" if version.0 >= 10 => (
                self.engine.environment.version_revision.to_string(),
                RegType::DWord,
            ),
            _ => return None,
        };
        self.engine.assume("os-version-registry");
        Some((value, kind))
    }

    /// Reads the NSIS execution flags, cached OS information, or simulated memory.
    pub fn read_memory(&mut self, address: u64, spec: u32, flags: &ExecFlags) -> Option<i64> {
        let size = (spec & 0xff) as usize;
        let offset = u64::from(spec >> 24);
        let environment = &self.engine.environment;
        let pointer = environment.pointer;
        if size > pointer {
            return None;
        }
        let value = if address == 0 {
            let version = environment.version;
            let wow64 =
                environment.process_machine == 0x14c && environment.native_machine == 0x8664;
            let mut bytes: Vec<_> = flags
                .snapshot()
                .into_iter()
                .flat_map(i32::to_le_bytes)
                .collect();
            bytes.extend(version.2.to_le_bytes());
            bytes.extend([
                1 | if wow64 { 0x80 } else { 0 },
                0,
                version.1 as u8,
                version.0 as u8,
            ]);
            let start = offset as usize;
            let mut value = [0; 8];
            value[..size].copy_from_slice(bytes.get(start..start.checked_add(size)?)?);
            self.engine.assume("nsis-os-information");
            u64::from_le_bytes(value)
        } else {
            self.engine
                .memory
                .number(address.checked_add(offset)?, size)?
        };
        Some(if pointer == 4 {
            i64::from(value as i32)
        } else {
            value as i64
        })
    }

    fn store_context(&mut self, command: &str, context: &mut Context<'_, '_>) -> bool {
        let mut chars = command.chars().peekable();
        while let Some(character) = chars.next() {
            match character {
                'S' | 's' | 'L' | 'l' | 'F' | 'f' => {}
                'P' | 'p' | 'R' | 'r' if chars.next().is_some_and(|c| c.is_ascii_digit()) => {}
                _ => return false,
            }
        }
        let mut chars = command.chars();
        while let Some(character) = chars.next() {
            match character {
                'S' | 's' | 'L' | 'l' => {
                    if !self.store(&character.to_string(), context.variables) {
                        return false;
                    }
                }
                'P' | 'p' | 'R' | 'r' => {
                    let Some(digit) = chars.next().and_then(|c| c.to_digit(10)) else {
                        return false;
                    };
                    let index = digit as usize
                        + if character.is_ascii_uppercase() {
                            10
                        } else {
                            0
                        };
                    if matches!(character, 'p' | 'P') {
                        context.stack.push(Cow::Owned(
                            context.variables.get(&index).unwrap_or_default().to_owned(),
                        ));
                    } else {
                        context
                            .variables
                            .insert(index, context.stack.pop().unwrap_or(Cow::Borrowed("")));
                    }
                }
                'F' => context.stack.push(Cow::Owned(format!(
                    "{}\0{}",
                    if self.engine.environment.unicode {
                        '\u{2691}'
                    } else {
                        '\u{1e}'
                    },
                    context
                        .flags
                        .snapshot()
                        .iter()
                        .map(i32::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                ))),
                'f' => {
                    if let Some(frame) = context.stack.pop().and_then(|v| {
                        v.strip_prefix(if self.engine.environment.unicode {
                            "\u{2691}\0"
                        } else {
                            "\u{1e}\0"
                        })
                        .map(str::to_owned)
                    }) && let Ok(values) = frame
                        .split(',')
                        .map(str::parse::<i32>)
                        .collect::<Result<Vec<_>, _>>()
                    {
                        context.flags.restore(&values);
                    }
                }
                _ => unreachable!(),
            }
        }
        true
    }

    /// Interprets a System plugin export using the simulated installer state.
    pub fn invoke(&mut self, function: &str, context: &mut Context<'_, '_>) -> bool {
        let handled = match function {
            "Call" | "Get" => {
                let Some(source) = context.stack.pop() else {
                    return false;
                };
                let handled = if function == "Call" {
                    self.engine.call(&source, context, &mut self.kernel32)
                } else {
                    self.engine.get(&source, context)
                };
                if !handled {
                    warn!(call = %source, "Unmodeled System plugin call; subsequent state requires independent validation");
                }
                return handled;
            }
            "Store" => context
                .stack
                .pop()
                .is_some_and(|command| self.store_context(&command, context)),
            "Int64Op" => engine::Engine::int64(context.stack),
            "Alloc" | "StrAlloc" => {
                let size = context.stack.pop().map(|s| engine::integer(&s));
                let bytes = size
                    .and_then(|size| usize::try_from(size).ok())
                    .and_then(|size| {
                        size.checked_mul(
                            if function == "StrAlloc" && self.engine.environment.unicode {
                                2
                            } else {
                                1
                            },
                        )
                    });
                let address = bytes.and_then(|size| self.engine.memory.alloc(size));
                context
                    .stack
                    .push(Cow::Owned(address.unwrap_or_default().to_string()));
                address.is_some()
            }
            "Free" => context.stack.pop().is_some_and(|address| {
                let address = engine::integer(&address);
                self.engine.procedures.remove(&address).is_some()
                    || self.engine.memory.free(address)
            }),
            "Copy" => {
                let operation = (|| {
                    let first = context.stack.pop()?;
                    let (size, destination) = if let Some(size) = first.strip_prefix('/') {
                        (
                            Some(usize::try_from(engine::integer(size)).ok()?),
                            engine::integer(&context.stack.pop()?),
                        )
                    } else {
                        (None, engine::integer(&first))
                    };
                    let source = engine::integer(&context.stack.pop()?);
                    let size = size
                        .filter(|&s| s != 0)
                        .or_else(|| self.engine.memory.size(source))?;
                    let output = if destination == 0 {
                        self.engine.memory.alloc(size)?
                    } else {
                        destination
                    };
                    self.engine.memory.copy(output, source, size)?;
                    if destination == 0 {
                        context.stack.push(Cow::Owned(output.to_string()));
                    }
                    Some(())
                })();
                operation.is_some()
            }
            _ => false,
        };
        if !handled {
            warn!(%function, "Unmodeled System plugin export or invalid arguments; subsequent state requires independent validation");
        }
        handled
    }
}

#[cfg(test)]
mod register_tests {
    use super::*;

    #[test]
    fn store_restores_all_registers_but_keeps_internal_variables() {
        let mut caller = MockCaller::new();
        let mut variables = Variables::new();
        for index in 0..Variables::NUM_REGISTERS {
            variables.insert(index, format!("saved {index}"));
        }
        assert!(caller.store("S", &mut variables));
        for index in 0..Variables::NUM_REGISTERS {
            variables.insert(index, "0");
        }
        variables.insert_install_dir(r"%LocalAppData%\Programs\app");
        assert!(caller.store("L", &mut variables));
        for index in 0..Variables::NUM_REGISTERS {
            assert_eq!(
                variables.get(&index),
                Some(format!("saved {index}").as_str())
            );
        }
        assert_eq!(
            variables.install_dir().unwrap().as_str(),
            r"%LocalAppData%\Programs\app"
        );
    }

    #[test]
    fn nested_stores_restore_and_clear_registers() {
        let mut caller = MockCaller::new();
        let mut variables = Variables::new();
        assert!(caller.store("s", &mut variables));
        variables.insert(0, "outer");
        assert!(caller.store("S", &mut variables));
        variables.insert(0, "inner");
        assert!(caller.store("l", &mut variables));
        assert_eq!(variables.get(&0), Some("outer"));
        assert!(caller.store("L", &mut variables));
        assert_eq!(variables.get(&0), None);
        assert!(caller.store("L", &mut variables));
    }

    #[test]
    fn store_is_bounded_and_rejects_unmodeled_commands_without_side_effects() {
        let mut caller = MockCaller::new();
        let mut variables = Variables::new();
        assert!(!caller.store("SF", &mut variables));
        assert!(caller.saved_registers.is_empty());
        assert!(!caller.store(&"S".repeat(65), &mut variables));
        assert!(caller.saved_registers.is_empty());
        assert!(caller.store("SLsl", &mut variables));
        assert!(caller.saved_registers.is_empty());
    }
}
