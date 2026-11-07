use super::{
    engine::{Context, Engine, Handle},
    memory::Memory,
};
use crate::analysis::installers::nsis::{
    codepage,
    registry::{RegRoot, RegType},
};

impl Engine {
    fn registry_bytes(
        context: &Context<'_, '_>,
        root: RegRoot,
        key: &str,
        name: &str,
        wide: bool,
    ) -> Option<(u64, Vec<u8>)> {
        let value = context.registry.get_value(root, key, name)?;
        let kind = context.registry.value_type(root, key, name)?;
        let bytes = match kind {
            RegType::String | RegType::ExpandedString => Memory::encoded(value, wide),
            RegType::DWord => (super::engine::integer(value) as u32)
                .to_le_bytes()
                .to_vec(),
            RegType::MultiString => Memory::encoded(&(value.clone() + "\0"), wide),
            RegType::Binary => value
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
                .collect::<Option<Vec<_>>>()?,
            _ => return None,
        };
        Some((u32::from_le(kind as u32) as u64, bytes))
    }

    fn key(&self, handle: u64, access: u32) -> Option<(RegRoot, String)> {
        if let Some(root) = RegRoot::from_native(handle as u32) {
            let view = if access & 0x100 != 0 {
                0x100
            } else if access & 0x200 != 0 {
                0x200
            } else if self.environment.pointer == 8 {
                0x100
            } else {
                0x200
            };
            Some((root.resolve(false, view), String::new()))
        } else if let Some(Handle::Registry(root, key)) = self.handles.get(&handle) {
            Some((*root, key.clone()))
        } else {
            None
        }
    }

    pub fn registry_api(
        &mut self,
        function: &str,
        wide: bool,
        args: &[u64],
        context: &mut Context<'_, '_>,
    ) -> Option<u64> {
        let a = |n: usize| args.get(n).copied();
        if function == "RegCloseKey" {
            return Some(
                if RegRoot::from_native(a(0)? as u32).is_some()
                    || (matches!(self.handles.get(&a(0)?), Some(Handle::Registry(..)))
                        && self.handles.remove(&a(0)?).is_some())
                {
                    0
                } else {
                    6
                },
            );
        }
        let access = match function {
            "RegCreateKeyEx" => a(5)? as u32,
            "RegOpenKeyEx" => a(3)? as u32,
            _ => 0,
        };
        let Some((root, mut key)) = self.key(a(0)?, access) else {
            return Some(6);
        };
        if matches!(
            function,
            "RegCreateKeyEx"
                | "RegOpenKeyEx"
                | "RegCreateKey"
                | "RegOpenKey"
                | "RegDeleteKey"
                | "RegDeleteTree"
        ) {
            let child = self.memory.string(a(1)?, wide)?;
            if !key.is_empty() && !child.is_empty() {
                key.push('\\');
            }
            key.push_str(&child);
        }
        match function {
            "RegCreateKeyEx" | "RegCreateKey" | "RegOpenKeyEx" | "RegOpenKey" => {
                let exists = context.registry.key_exists(root, &key);
                if !exists && function.starts_with("RegOpen") {
                    return Some(2);
                }
                if function.starts_with("RegCreate") {
                    context.registry.create_key(root, &key);
                }
                let output = match function {
                    "RegCreateKeyEx" => a(7)?,
                    "RegOpenKeyEx" => a(4)?,
                    _ => a(2)?,
                };
                let handle = self.handle(Handle::Registry(root, key))?;
                self.memory
                    .put_number(output, handle, self.environment.pointer)?;
                if function == "RegCreateKeyEx" && a(8)? != 0 {
                    self.memory
                        .put_number(a(8)?, if exists { 2 } else { 1 }, 4)?;
                }
                Some(0)
            }
            "RegSetValueEx" => {
                let name = self.memory.string(a(1)?, wide)?;
                let kind = a(3)? as u32;
                let length = usize::try_from(a(5)?).ok()?;
                let bytes = self.memory.read(a(4)?, length)?;
                let (kind, value) = match kind {
                    1 | 2 | 7 => {
                        let value = if wide {
                            if length % 2 != 0 {
                                return Some(87);
                            }
                            String::from_utf16_lossy(
                                &bytes
                                    .chunks_exact(2)
                                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                                    .collect::<Vec<_>>(),
                            )
                        } else {
                            codepage::decode(bytes).into_owned()
                        };
                        (
                            match kind {
                                1 => RegType::String,
                                2 => RegType::ExpandedString,
                                _ => RegType::MultiString,
                            },
                            value.trim_end_matches('\0').to_owned(),
                        )
                    }
                    4 if length == 4 => (
                        RegType::DWord,
                        u32::from_le_bytes(bytes.try_into().ok()?).to_string(),
                    ),
                    3 => (
                        RegType::Binary,
                        bytes.iter().map(|b| format!("{b:02X}")).collect::<String>(),
                    ),
                    _ => return None,
                };
                context.registry.insert_typed(root, key, name, value, kind);
                Some(0)
            }
            "RegQueryValueEx" => {
                let name = self.memory.string(a(1)?, wide)?;
                if context.registry.get_value(root, &key, &name).is_none() {
                    return Some(2);
                }
                let (kind, bytes) = Self::registry_bytes(context, root, &key, &name, wide)?;
                if a(3)? != 0 {
                    self.memory.put_number(a(3)?, kind, 4)?;
                }
                let capacity = if a(5)? != 0 {
                    self.memory.number(a(5)?, 4)? as usize
                } else {
                    0
                };
                if a(5)? != 0 {
                    self.memory.put_number(a(5)?, bytes.len() as u64, 4)?;
                }
                if a(4)? == 0 {
                    return Some(0);
                }
                if capacity < bytes.len() {
                    return Some(234);
                }
                self.memory.write(a(4)?, &bytes)?;
                Some(0)
            }
            "RegDeleteValue" => {
                let name = self.memory.string(a(1)?, wide)?;
                Some(
                    if context
                        .registry
                        .remove_value_name(root, &key, &name)
                        .is_some()
                    {
                        0
                    } else {
                        2
                    },
                )
            }
            "RegDeleteKey" | "RegDeleteTree" => {
                if function == "RegDeleteKey"
                    && context.registry.enum_subkey(root, &key, 0).is_some()
                {
                    return Some(5);
                }
                Some(if context.registry.delete_key(root, &key, false) {
                    0
                } else {
                    2
                })
            }
            "RegEnumKeyEx" | "RegEnumValue" => {
                let index = usize::try_from(a(1)?).ok()?;
                let name = if function == "RegEnumKeyEx" {
                    context.registry.enum_subkey(root, &key, index)
                } else {
                    context.registry.enum_value_name(root, &key, index)
                };
                let Some(name) = name else {
                    return Some(259);
                };
                let capacity = self.memory.number(a(3)?, 4)? as usize;
                let required = if wide {
                    name.encode_utf16().count()
                } else {
                    Memory::encoded(&name, false).len() - 1
                };
                if capacity <= required {
                    return Some(234);
                }
                self.memory.put_string(a(2)?, &name, wide, capacity)?;
                self.memory.put_number(a(3)?, required as u64, 4)?;
                if function == "RegEnumValue" {
                    let (kind, bytes) = Self::registry_bytes(context, root, &key, &name, wide)?;
                    if a(5)? != 0 {
                        self.memory.put_number(a(5)?, kind, 4)?;
                    }
                    let capacity = if a(7)? != 0 {
                        self.memory.number(a(7)?, 4)? as usize
                    } else {
                        0
                    };
                    if a(7)? != 0 {
                        self.memory.put_number(a(7)?, bytes.len() as u64, 4)?;
                    }
                    if a(6)? != 0 {
                        if capacity < bytes.len() {
                            return Some(234);
                        }
                        self.memory.write(a(6)?, &bytes)?;
                    }
                } else {
                    if a(5)? != 0 {
                        self.memory.put_number(a(5)?, 0, 4)?;
                    }
                    if a(4)? != 0 {
                        self.memory.put_string(a(4)?, "", wide, 1)?;
                    }
                    if a(7)? != 0 {
                        self.memory.put_number(a(7)?, 0, 8)?;
                    }
                }
                Some(0)
            }
            _ => None,
        }
    }
}
