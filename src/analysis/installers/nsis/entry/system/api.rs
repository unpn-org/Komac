//! Windows API calls supported by the NSIS interpreter.
//!
//! All effects are applied to the simulated installer state.

use typed_path::{Utf8Component, Utf8WindowsPath};
use uuid::Uuid;

use super::{
    Kernel32,
    engine::{Context, Engine, Handle, ShellInterface},
    folders::known_folder_path,
    memory::Memory,
    syntax::Parameter,
};
use crate::analysis::installers::nsis::{
    Variables, codepage, file_system::RelativeLocation, strings::PredefinedVar,
};

const KERNEL: &[&str] = &[
    "GetCurrentProcess",
    "GetCurrentProcessId",
    "GetProcessId",
    "IsWow64Process",
    "IsWow64Process2",
    "GetVersion",
    "GetVersionEx",
    "GetNativeSystemInfo",
    "GetSystemInfo",
    "GetSystemDefaultLangID",
    "GetUserDefaultLangID",
    "GetUserDefaultUILanguage",
    "IsProcessorFeaturePresent",
    "GetLastError",
    "SetLastError",
    "CreateMutex",
    "OpenMutex",
    "ReleaseMutex",
    "CloseHandle",
    "WaitForSingleObject",
    "CreateToolhelp32Snapshot",
    "CloseToolhelp32Snapshot",
    "Process32First",
    "Process32Next",
    "OpenProcess",
    "SetEnvironmentVariable",
    "GetEnvironmentVariable",
    "ExpandEnvironmentStrings",
    "GetCommandLine",
    "GetWindowsDirectory",
    "GetSystemWindowsDirectory",
    "GetSystemDirectory",
    "GetSystemWow64Directory",
    "GetTempPath",
    "GetModuleFileName",
    "GetFullPathName",
    "GetLongPathName",
    "lstrlen",
    "lstrcpy",
    "lstrcpyn",
    "lstrcmp",
    "lstrcmpi",
    "MultiByteToWideChar",
    "WideCharToMultiByte",
    "GetTickCount",
    "GetTickCount64",
    "GetLocalTime",
    "GetSystemTime",
    "GetSystemTimeAsFileTime",
    "Sleep",
    "SetDllDirectory",
    "Wow64EnableWow64FsRedirection",
    "Wow64DisableWow64FsRedirection",
    "Wow64RevertWow64FsRedirection",
    "GetModuleHandle",
    "LoadLibrary",
    "LoadLibraryEx",
    "GetProcAddress",
    "FreeLibrary",
    "GetFileAttributes",
    "GetProductInfo",
];

fn name(target: &str) -> Option<(String, &str, Option<bool>)> {
    let (module, function) = target.split_once("::")?;
    let module = module
        .trim_matches(['\'', '"', '`'])
        .rsplit(['\\', '/'])
        .next()?
        .to_ascii_lowercase();
    let module = module.strip_suffix(".dll").unwrap_or(&module).to_owned();
    let (function, wide) = if let Some(base) = function.strip_suffix('W') {
        (base, Some(true))
    } else if let Some(base) = function.strip_suffix('A') {
        (base, Some(false))
    } else {
        (function, None)
    };
    Some((module, function, wide))
}

impl Engine {
    pub fn supports(&self, target: &str) -> bool {
        if target.starts_with('*') {
            return true;
        }
        if target.contains("->") {
            return true;
        }
        let Some((module, function, _)) = name(target) else {
            return false;
        };
        match module.as_str() {
            "kernel32" | "kernelbase" => KERNEL.contains(&function),
            "ntdll" => matches!(
                function,
                "RtlGetVersion"
                    | "RtlGetNtVersionNumbers"
                    | "RtlMoveMemory"
                    | "RtlZeroMemory"
                    | "memcpy"
                    | "memmove"
                    | "memset"
            ),
            "shell32" => matches!(
                function,
                "SHGetKnownFolderPath"
                    | "SHGetFolderPath"
                    | "SHGetSpecialFolderPath"
                    | "SHGetSpecialFolderLocation"
                    | "SHGetPathFromIDList"
                    | "SHChangeNotify"
            ),
            "ole32" => matches!(
                function,
                "CoTaskMemFree"
                    | "CoTaskMemAlloc"
                    | "CoTaskMemRealloc"
                    | "CoCreateInstance"
                    | "CoCreateGuid"
                    | "StringFromGUID2"
                    | "CLSIDFromString"
                    | "CoInitialize"
                    | "CoInitializeEx"
                    | "CoUninitialize"
                    | "CoFreeUnusedLibraries"
            ),
            "advapi32" => matches!(
                function,
                "RegCreateKeyEx"
                    | "RegCreateKey"
                    | "RegOpenKeyEx"
                    | "RegOpenKey"
                    | "RegSetValueEx"
                    | "RegQueryValueEx"
                    | "RegDeleteValue"
                    | "RegDeleteKey"
                    | "RegDeleteTree"
                    | "RegEnumKeyEx"
                    | "RegEnumValue"
                    | "RegCloseKey"
                    | "AllocateAndInitializeSid"
                    | "CheckTokenMembership"
                    | "FreeSid"
            ),
            "shlwapi" => matches!(
                function,
                "PathRemoveFileSpec"
                    | "PathFileExists"
                    | "PathIsDirectory"
                    | "PathCombine"
                    | "PathAppend"
                    | "PathIsRelative"
                    | "PathAddBackslash"
                    | "StrCmpI"
                    | "StrCmp"
            ),
            "user32" => matches!(
                function,
                "ShutdownBlockReasonCreate"
                    | "ShutdownBlockReasonDestroy"
                    | "IsWindow"
                    | "GetSystemMetrics"
                    | "CharUpper"
                    | "CharLower"
                    | "CharUpperBuff"
                    | "CharLowerBuff"
            ),
            _ => false,
        }
    }

    fn failure(&mut self, error: u32) -> Option<u64> {
        self.last_error = error;
        Some(0)
    }

    fn native_folder(&self, csidl: u32) -> Option<&'static str> {
        match csidl & 0xff {
            0 | 0x10 => Some("Desktop"),
            2 | 0x17 => Some("SMPrograms"),
            5 => Some("Documents"),
            0x1a => Some("%AppData%"),
            0x1c => Some("%LocalAppData%"),
            0x23 => Some("%ProgramData%"),
            0x24 => Some("%WinDir%"),
            0x25 | 0x29 => Some(r"%SystemRoot%\System32"),
            0x28 => Some("%UserProfile%"),
            0x26 => Some(
                if self.environment.pointer == 4 && self.environment.native_machine != 0x14c {
                    "%ProgramFiles(x86)%"
                } else {
                    "%ProgramFiles%"
                },
            ),
            0x2a => Some("%ProgramFiles(x86)%"),
            0x2b => Some(
                if self.environment.pointer == 4 && self.environment.native_machine != 0x14c {
                    "%CommonProgramFiles(x86)%"
                } else {
                    "%CommonProgramFiles%"
                },
            ),
            0x2c => Some("%CommonProgramFiles(x86)%"),
            _ => None,
        }
    }

    fn folder_guid(&self, guid: &str) -> Option<&'static str> {
        known_folder_path(guid)
    }

    fn env_value(&self, key: &str, kernel: &Kernel32) -> Option<String> {
        if let Some((_, value)) = kernel
            .environment_variables()
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
        {
            return Some(value.clone());
        }
        let value = match key.to_ascii_lowercase().as_str() {
            "localappdata" => "%LocalAppData%",
            "appdata" => "%AppData%",
            "temp" | "tmp" => "%Temp%",
            "programdata" | "allusersprofile" => "%ProgramData%",
            "systemroot" | "windir" => "%SystemRoot%",
            "userprofile" => "%UserProfile%",
            "username" => "%UserName%",
            "programfiles" => self.native_folder(0x26)?,
            "programfiles(x86)" => "%ProgramFiles(x86)%",
            "programw6432" => "%ProgramFiles%",
            "commonprogramfiles" => self.native_folder(0x2b)?,
            "commonprogramfiles(x86)" => "%CommonProgramFiles(x86)%",
            "commonprogramw6432" => "%CommonProgramFiles%",
            "processor_architecture" => {
                if self.environment.process_machine == 0xaa64 {
                    "ARM64"
                } else if self.environment.pointer == 8 {
                    "AMD64"
                } else {
                    "x86"
                }
            }
            "processor_architew6432" => {
                if self.environment.native_machine == 0xaa64 {
                    "ARM64"
                } else {
                    "AMD64"
                }
            }
            _ => return None,
        };
        Some(value.to_owned())
    }

    fn expand(&self, value: &str, kernel: &Kernel32) -> String {
        let mut out = String::new();
        let mut rest = value;
        while let Some(start) = rest.find('%') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            let Some(end) = after.find('%') else {
                out.push_str(&rest[start..]);
                return out;
            };
            out.push_str(
                &self
                    .env_value(&after[..end], kernel)
                    .unwrap_or_else(|| format!("%{}%", &after[..end])),
            );
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        out
    }

    fn path(value: &str, context: &Context<'_, '_>) -> Option<String> {
        let path = Utf8WindowsPath::new(value);
        let symbolic = path
            .components()
            .next()
            .is_some_and(|c| c.as_str().starts_with(['%', '$']));
        if path.is_absolute() || symbolic {
            return Some(path.normalize().into_string());
        }
        if path.has_root() || value.as_bytes().get(1) == Some(&b':') {
            return None;
        }
        let base = context
            .variables
            .get(&(Variables::NUM_REGISTERS + PredefinedVar::OutDir as usize))
            .unwrap_or("%Temp%");
        Some(
            Utf8WindowsPath::new(base)
                .join(path)
                .normalize()
                .into_string(),
        )
    }

    fn reported_version(&self) -> (u32, u32, u32) {
        let version = self.environment.version;
        if !self.environment.version_manifest && version >= (6, 3, 0) {
            if self.environment.version_81_manifest {
                (6, 3, 9600)
            } else {
                (6, 2, 9200)
            }
        } else {
            version
        }
    }

    fn version(&mut self, pointer: u64, wide: bool, rtl: bool) -> Option<u64> {
        self.assume("os-version");
        let size = self.memory.number(pointer, 4)? as usize;
        let base = if wide { 276 } else { 148 };
        if size != base && size != base + 8 {
            return self.failure(87);
        }
        self.memory.read(pointer, size)?;
        let version = if rtl {
            self.environment.version
        } else {
            self.reported_version()
        };
        self.memory.write(pointer, &vec![0; size])?;
        self.memory.put_number(pointer, size as u64, 4)?;
        for (offset, value) in [(4, version.0), (8, version.1), (12, version.2), (16, 2)] {
            self.memory.put_number(pointer + offset, value as u64, 4)?;
        }
        if size > base {
            self.memory.put_number(pointer + base as u64 + 6, 1, 1)?;
        }
        Some(if rtl { 0 } else { 1 })
    }

    pub fn dispatch(
        &mut self,
        target: &str,
        args: &[u64],
        _types: &[Parameter],
        context: &mut Context<'_, '_>,
        kernel: &mut Kernel32,
    ) -> Option<u64> {
        if let Some((object, index)) = target.split_once("->") {
            return self.com(
                super::engine::integer(object),
                index.parse().ok()?,
                args,
                context,
            );
        }
        let (module, function, explicit_wide) = name(target)?;
        let wide = explicit_wide.unwrap_or(self.environment.unicode);
        if module == "advapi32" && function.starts_with("Reg") {
            return self.registry_api(function, wide, args, context);
        }
        let a = |n: usize| args.get(n).copied();
        match (module.as_str(), function) {
            ("advapi32", "AllocateAndInitializeSid") => {
                let authority = self.memory.read(a(0)?, 6)?.to_vec();
                let count = a(1)? as u8;
                if count > 8 {
                    return self.failure(87);
                }
                let mut sid = vec![1, count];
                sid.extend_from_slice(&authority);
                for index in 0..usize::from(count) {
                    sid.extend_from_slice(&(a(index + 2)? as u32).to_le_bytes());
                }
                let output = a(10)?;
                self.memory.read(output, self.environment.pointer)?;
                let pointer = self.memory.alloc(sid.len())?;
                self.memory.write(pointer, &sid)?;
                self.memory
                    .put_number(output, pointer, self.environment.pointer)?;
                Some(1)
            }
            ("advapi32", "CheckTokenMembership") => {
                if a(0)? != 0 {
                    return self.failure(6);
                }
                // Match the administrative account used by UserInfo and UAC queries.
                // Other group memberships require a token model we do not have.
                const ADMINISTRATORS: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
                if self.memory.read(a(1)?, ADMINISTRATORS.len())? != ADMINISTRATORS {
                    return None;
                }
                self.assume("administrator-account");
                self.memory.put_number(a(2)?, 1, 4)?;
                Some(1)
            }
            ("advapi32", "FreeSid") => self.memory.free(a(0)?).then_some(0),
            ("kernel32" | "kernelbase", "GetCurrentProcess") => Some(u64::MAX),
            ("kernel32" | "kernelbase", "GetCurrentProcessId") => {
                self.assume("process-state");
                Some(4242)
            }
            ("kernel32" | "kernelbase", "GetProcessId") => {
                self.assume("process-state");
                if a(0)? as u32 == u32::MAX
                    || matches!(self.handles.get(&a(0)?), Some(Handle::Process))
                {
                    Some(4242)
                } else {
                    self.failure(6)
                }
            }
            ("kernel32" | "kernelbase", "IsWow64Process" | "IsWow64Process2") => {
                self.assume("architecture");
                let wow = self.environment.process_machine != self.environment.native_machine;
                if function == "IsWow64Process2" {
                    self.memory.put_number(
                        a(1)?,
                        if wow {
                            self.environment.process_machine as u64
                        } else {
                            0
                        },
                        2,
                    )?;
                    self.memory
                        .put_number(a(2)?, self.environment.native_machine as u64, 2)?;
                } else {
                    // The older API does not report x86 emulation on ARM64.
                    self.memory.put_number(
                        a(1)?,
                        u64::from(
                            self.environment.process_machine == 0x14c
                                && self.environment.native_machine == 0x8664,
                        ),
                        4,
                    )?;
                }
                Some(1)
            }
            ("kernel32" | "kernelbase", "GetVersionEx") => self.version(a(0)?, wide, false),
            ("ntdll", "RtlGetVersion") => self.version(a(0)?, true, true),
            ("ntdll", "RtlGetNtVersionNumbers") => {
                self.assume("os-version");
                for (p, v) in args.iter().zip([
                    self.environment.version.0,
                    self.environment.version.1,
                    self.environment.version.2 | 0xf0000000,
                ]) {
                    if *p != 0 {
                        self.memory.put_number(*p, v as u64, 4)?;
                    }
                }
                Some(0)
            }
            ("kernel32" | "kernelbase", "GetVersion") => {
                self.assume("os-version");
                let (major, minor, build) = self.reported_version();
                Some(((build as u64) << 16) | ((minor as u64) << 8) | major as u64)
            }
            ("kernel32" | "kernelbase", "GetSystemInfo" | "GetNativeSystemInfo") => {
                self.assume("architecture");
                let arch = if function == "GetNativeSystemInfo" {
                    self.environment.native_machine
                } else {
                    self.environment.process_machine
                };
                let pointer = a(0)?;
                let size = if self.environment.pointer == 8 {
                    48
                } else {
                    36
                };
                self.memory.write(pointer, &vec![0; size])?;
                self.memory.put_number(
                    pointer,
                    match arch {
                        0x8664 => 9,
                        0xaa64 => 12,
                        _ => 0,
                    },
                    2,
                )?;
                self.memory.put_number(pointer + 4, 4096, 4)?;
                self.memory
                    .put_number(pointer + if size == 48 { 32 } else { 20 }, 8, 4)?;
                Some(0)
            }
            (
                "kernel32" | "kernelbase",
                "GetUserDefaultUILanguage" | "GetUserDefaultLangID" | "GetSystemDefaultLangID",
            ) => {
                self.assume("locale");
                Some(1033)
            }
            ("kernel32" | "kernelbase", "IsProcessorFeaturePresent") => {
                self.assume("processor-features");
                Some(u64::from(matches!(a(0)?, 6 | 10 | 13 | 17 | 23 | 36 | 39)))
            }
            ("kernel32" | "kernelbase", "GetLastError") => Some(self.last_error as u64),
            ("kernel32" | "kernelbase", "SetLastError") => {
                self.last_error = a(0)? as u32;
                Some(0)
            }
            ("kernel32" | "kernelbase", "CreateMutex") => {
                self.assume("process-state");
                let name = self.memory.string(a(2)?, wide)?;
                let exists = self
                    .handles
                    .values()
                    .any(|h| matches!(h,Handle::Mutex(other) if !name.is_empty()&&other==&name));
                let handle = self.handle(Handle::Mutex(name))?;
                self.last_error = if exists { 183 } else { 0 };
                Some(handle)
            }
            ("kernel32" | "kernelbase", "OpenMutex") => {
                self.assume("process-state");
                let name = self.memory.string(a(2)?, wide)?;
                if self
                    .handles
                    .values()
                    .any(|h| matches!(h,Handle::Mutex(other) if other==&name))
                {
                    self.handle(Handle::Mutex(name))
                } else {
                    self.failure(2)
                }
            }
            ("kernel32" | "kernelbase", "ReleaseMutex" | "WaitForSingleObject") => {
                if self.handles.contains_key(&a(0)?) {
                    Some(if function == "ReleaseMutex" { 1 } else { 0 })
                } else {
                    self.failure(6)
                }
            }
            ("kernel32" | "kernelbase", "CloseHandle" | "CloseToolhelp32Snapshot") => {
                if self.handles.remove(&a(0)?).is_some() {
                    Some(1)
                } else {
                    self.failure(6)
                }
            }
            ("kernel32" | "kernelbase", "CreateToolhelp32Snapshot") => {
                self.assume("empty-application-process-list");
                self.handle(Handle::Snapshot)
            }
            ("kernel32" | "kernelbase", "Process32First" | "Process32Next") => {
                self.assume("empty-application-process-list");
                self.failure(
                    if matches!(self.handles.get(&a(0)?), Some(Handle::Snapshot)) {
                        18
                    } else {
                        6
                    },
                )
            }
            ("kernel32" | "kernelbase", "OpenProcess") => {
                self.assume("process-state");
                if a(2)? == 4242 {
                    self.handle(Handle::Process)
                } else {
                    self.failure(87)
                }
            }
            ("kernel32" | "kernelbase", "SetEnvironmentVariable") => {
                let key = self.memory.string(a(0)?, wide)?;
                if key.is_empty() || key.contains('=') {
                    return self.failure(87);
                }
                let value = if a(1)? == 0 {
                    None
                } else {
                    Some(self.memory.string(a(1)?, wide)?)
                };
                kernel.set_environment_variable(key, value);
                Some(1)
            }
            ("kernel32" | "kernelbase", "GetEnvironmentVariable") => {
                let key = self.memory.string(a(0)?, wide)?;
                let Some(value) = self.env_value(&key, kernel) else {
                    return self.failure(203);
                };
                let length = if wide {
                    value.encode_utf16().count()
                } else {
                    Memory::encoded(&value, false).len() - 1
                };
                if a(2)? <= length as u64 {
                    Some(length as u64 + 1)
                } else {
                    self.memory
                        .put_string(a(1)?, &value, wide, a(2)? as usize)?;
                    Some(length as u64)
                }
            }
            ("kernel32" | "kernelbase", "ExpandEnvironmentStrings") => {
                let value = self.expand(&self.memory.string(a(0)?, wide)?, kernel);
                let length = if wide {
                    value.encode_utf16().count() + 1
                } else {
                    Memory::encoded(&value, false).len()
                };
                if a(2)? >= length as u64 {
                    self.memory
                        .put_string(a(1)?, &value, wide, a(2)? as usize)?;
                }
                Some(length as u64)
            }
            ("kernel32" | "kernelbase", "GetCommandLine") => {
                self.assume("default-command-line");
                let command = context
                    .variables
                    .get(&(Variables::NUM_REGISTERS + PredefinedVar::CmdLine as usize))
                    .unwrap_or("\"%Temp%\\installer.exe\"");
                self.memory.alloc_string(command, wide, 8192)
            }
            (
                "kernel32" | "kernelbase",
                "GetWindowsDirectory"
                | "GetSystemWindowsDirectory"
                | "GetSystemDirectory"
                | "GetSystemWow64Directory"
                | "GetTempPath",
            ) => {
                if function == "GetSystemWow64Directory" && self.environment.native_machine == 0x14c
                {
                    return self.failure(120);
                }
                let value = match function {
                    "GetSystemDirectory" => r"%SystemRoot%\System32",
                    "GetSystemWow64Directory" => r"%SystemRoot%\SysWOW64",
                    "GetTempPath" => r"%Temp%\",
                    _ => "%WinDir%",
                };
                let (buffer, capacity) = if function == "GetTempPath" {
                    (a(1)?, a(0)?)
                } else {
                    (a(0)?, a(1)?)
                };
                if capacity <= value.len() as u64 {
                    Some(value.len() as u64 + 1)
                } else {
                    self.memory
                        .put_string(buffer, value, wide, capacity as usize)?;
                    Some(value.len() as u64)
                }
            }
            ("kernel32" | "kernelbase", "GetModuleFileName") => {
                self.assume("installer-module-path");
                let value = if a(0)? == 0 {
                    r"%Temp%\installer.exe".to_owned()
                } else if let Some(Handle::Module(name)) = self.handles.get(&a(0)?) {
                    format!(r"%SystemRoot%\System32\{name}")
                } else {
                    return self.failure(6);
                };
                let length = self
                    .memory
                    .put_string(a(1)?, &value, wide, a(2)? as usize)?;
                if length < value.encode_utf16().count() {
                    self.last_error = 122;
                    Some(a(2)?)
                } else {
                    Some(length as u64)
                }
            }
            ("kernel32" | "kernelbase", "GetFullPathName" | "GetLongPathName") => {
                let input = self.memory.string(a(0)?, wide)?;
                let value = Self::path(&input, context)?;
                let length = if wide {
                    value.encode_utf16().count()
                } else {
                    Memory::encoded(&value, false).len() - 1
                };
                let (buffer, capacity) = if function == "GetFullPathName" {
                    (a(2)?, a(1)?)
                } else {
                    (a(1)?, a(2)?)
                };
                if capacity <= length as u64 {
                    return Some(length as u64 + 1);
                }
                self.memory
                    .put_string(buffer, &value, wide, capacity as usize)?;
                if function == "GetFullPathName" && a(3)? != 0 {
                    let part = value
                        .rfind('\\')
                        .map_or(0, |p| value[..p + 1].encode_utf16().count());
                    self.memory.put_number(
                        a(3)?,
                        buffer + (part * if wide { 2 } else { 1 }) as u64,
                        self.environment.pointer,
                    )?;
                }
                Some(length as u64)
            }
            ("kernel32" | "kernelbase", "lstrlen") => {
                let value = self.memory.string(a(0)?, wide)?;
                Some(if wide {
                    value.encode_utf16().count()
                } else {
                    Memory::encoded(&value, false).len() - 1
                } as u64)
            }
            ("kernel32" | "kernelbase", "lstrcpy" | "lstrcpyn") => {
                let value = self.memory.string(a(1)?, wide)?;
                let capacity = if function == "lstrcpyn" {
                    a(2)? as usize
                } else {
                    if wide {
                        value.encode_utf16().count() + 1
                    } else {
                        Memory::encoded(&value, false).len()
                    }
                };
                self.memory.put_string(a(0)?, &value, wide, capacity)?;
                Some(a(0)?)
            }
            ("kernel32" | "kernelbase", "lstrcmp" | "lstrcmpi")
            | ("shlwapi", "StrCmp" | "StrCmpI") => {
                let mut left = self.memory.string(a(0)?, wide)?;
                let mut right = self.memory.string(a(1)?, wide)?;
                if function.ends_with(['i', 'I']) {
                    left = left.to_lowercase();
                    right = right.to_lowercase();
                }
                Some(match left.encode_utf16().cmp(right.encode_utf16()) {
                    std::cmp::Ordering::Less => u64::MAX,
                    std::cmp::Ordering::Equal => 0,
                    _ => 1,
                })
            }
            ("kernel32" | "kernelbase", "MultiByteToWideChar" | "WideCharToMultiByte") => {
                self.encoding(function, args)
            }
            ("kernel32" | "kernelbase", "GetTickCount" | "GetTickCount64") => {
                self.assume("virtual-clock");
                self.environment.ticks = self.environment.ticks.saturating_add(1);
                Some(if function == "GetTickCount" {
                    self.environment.ticks as u32 as u64
                } else {
                    self.environment.ticks
                })
            }
            ("kernel32" | "kernelbase", "Sleep") => {
                self.environment.ticks = self.environment.ticks.saturating_add(a(0)?);
                Some(0)
            }
            (
                "kernel32" | "kernelbase",
                "GetLocalTime" | "GetSystemTime" | "GetSystemTimeAsFileTime",
            ) => {
                self.assume("utc-clock");
                let time = jiff::Timestamp::now().to_zoned(jiff::tz::TimeZone::UTC);
                if function == "GetSystemTimeAsFileTime" {
                    let ticks = (time.timestamp().as_second() as u64)
                        .checked_add(11_644_473_600)?
                        .checked_mul(10_000_000)?;
                    self.memory.put_number(a(0)?, ticks, 8)?;
                } else {
                    for (index, value) in [
                        time.year() as u64,
                        time.month() as u64,
                        time.weekday().to_sunday_zero_offset() as u64,
                        time.day() as u64,
                        time.hour() as u64,
                        time.minute() as u64,
                        time.second() as u64,
                        time.millisecond() as u64,
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        self.memory
                            .put_number(a(0)? + (index * 2) as u64, value, 2)?;
                    }
                }
                Some(0)
            }
            (
                "kernel32" | "kernelbase",
                "SetDllDirectory"
                | "FreeLibrary"
                | "Wow64EnableWow64FsRedirection"
                | "Wow64RevertWow64FsRedirection",
            ) => Some(1),
            ("kernel32" | "kernelbase", "Wow64DisableWow64FsRedirection") => {
                self.memory.put_number(a(0)?, 0, self.environment.pointer)?;
                Some(1)
            }
            ("kernel32" | "kernelbase", "GetModuleHandle" | "LoadLibrary" | "LoadLibraryEx") => {
                let library = self.memory.string(a(0)?, wide)?;
                let library = library.rsplit(['\\', '/']).next()?.to_ascii_lowercase();
                if ![
                    "kernel32",
                    "kernelbase",
                    "ntdll",
                    "shell32",
                    "shlwapi",
                    "advapi32",
                    "ole32",
                    "user32",
                    "msvcrt",
                ]
                .iter()
                .any(|&name| library.trim_end_matches(".dll") == name)
                {
                    return None;
                }
                self.handle(Handle::Module(library))
            }
            ("kernel32" | "kernelbase", "GetProcAddress") => {
                let Handle::Module(library) = self.handles.get(&a(0)?)? else {
                    return self.failure(6);
                };
                let target = format!("{library}::{}", self.memory.string(a(1)?, false)?);
                if !self.supports(&target) {
                    return None;
                }
                let declaration = super::syntax::Declaration::parse(&target)?;
                let handle = self.handle(Handle::Module("procedure".to_owned()))?;
                self.handles.remove(&handle);
                self.procedures.insert(handle, declaration);
                Some(handle)
            }
            ("kernel32" | "kernelbase", "GetFileAttributes") => {
                let path = self.memory.string(a(0)?, wide)?;
                if let Some(attributes) = context.files.attributes(&path) {
                    Some(attributes as u64)
                } else {
                    self.last_error = 2;
                    Some(u32::MAX as u64)
                }
            }
            ("kernel32" | "kernelbase", "GetProductInfo") => {
                self.assume("os-edition");
                self.memory.put_number(a(4)?, 48, 4)?;
                Some(1)
            }
            ("shell32", "SHGetKnownFolderPath") => {
                if a(2)? != 0 {
                    return None;
                }
                let guid = format!(
                    "{}",
                    Uuid::from_bytes_le(self.memory.read(a(0)?, 16)?.try_into().ok()?)
                );
                let path = self.folder_guid(&guid)?;
                self.assume("default-known-folders");
                let pointer =
                    self.memory
                        .alloc_string(path, true, path.encode_utf16().count() + 1)?;
                self.memory
                    .put_number(a(3)?, pointer, self.environment.pointer)?;
                Some(0)
            }
            ("shell32", "SHGetFolderPath" | "SHGetSpecialFolderPath") => {
                let (folder, buffer) = if function == "SHGetFolderPath" {
                    (a(1)?, a(4)?)
                } else {
                    (a(2)?, a(1)?)
                };
                let path = self.native_folder(folder as u32)?;
                self.assume("default-known-folders");
                self.memory.put_string(buffer, path, wide, 260)?;
                Some(if function == "SHGetFolderPath" { 0 } else { 1 })
            }
            ("shell32", "SHGetSpecialFolderLocation") => {
                let path = self.native_folder(a(1)? as u32)?;
                let pointer = self.memory.alloc_string(path, true, 260)?;
                self.memory
                    .put_number(a(2)?, pointer, self.environment.pointer)?;
                Some(0)
            }
            ("shell32", "SHGetPathFromIDList") => {
                let value = self.memory.string(a(0)?, true)?;
                self.memory.put_string(a(1)?, &value, wide, 260)?;
                Some(1)
            }
            ("shell32", "SHChangeNotify")
            | ("ole32", "CoUninitialize" | "CoFreeUnusedLibraries") => Some(0),
            ("ole32", "CoInitialize" | "CoInitializeEx") => Some(0),
            ("ole32", "CoTaskMemFree") => {
                if self.memory.free(a(0)?) {
                    Some(0)
                } else {
                    None
                }
            }
            ("ole32", "CoTaskMemAlloc") => self.memory.alloc(usize::try_from(a(0)?).ok()?),
            ("ole32", "CoTaskMemRealloc") => {
                let old = a(0)?;
                let size = usize::try_from(a(1)?).ok()?;
                if size == 0 {
                    self.memory.free(old);
                    return Some(0);
                }
                let pointer = self.memory.alloc(size)?;
                if old != 0 {
                    let count = self.memory.size(old)?.min(size);
                    self.memory.copy(pointer, old, count)?;
                    self.memory.free(old);
                }
                Some(pointer)
            }
            ("ole32", "CoCreateGuid") => {
                self.memory.invalidate(a(0)?);
                self.assume("runtime-generated-guid");
                Some(0)
            }
            ("ole32", "StringFromGUID2") => {
                let value = format!(
                    "{{{}}}",
                    Uuid::from_bytes_le(self.memory.read(a(0)?, 16)?.try_into().ok()?)
                        .hyphenated()
                        .to_string()
                        .to_uppercase()
                );
                if a(2)? < (value.len() + 1) as u64 {
                    Some(0)
                } else {
                    self.memory
                        .put_string(a(1)?, &value, true, a(2)? as usize)?;
                    Some((value.len() + 1) as u64)
                }
            }
            ("ole32", "CLSIDFromString") => {
                let value = self.memory.string(a(0)?, true)?;
                let uuid = Uuid::parse_str(value.trim_matches(['{', '}'])).ok()?;
                self.memory.write(a(1)?, &uuid.to_bytes_le())?;
                Some(0)
            }
            ("ole32", "CoCreateInstance") => {
                let clsid = Uuid::from_bytes_le(self.memory.read(a(0)?, 16)?.try_into().ok()?);
                if clsid.to_string() != "00021401-0000-0000-c000-000000000046" {
                    return None;
                }
                let iid =
                    Uuid::from_bytes_le(self.memory.read(a(3)?, 16)?.try_into().ok()?).to_string();
                let interface = Self::shell_interface(&iid)?;
                let object = self.handle(Handle::ShellLink {
                    object: 0,
                    interface: interface.clone(),
                    references: 1,
                })?;
                self.handles.insert(
                    object,
                    Handle::ShellLink {
                        object,
                        interface,
                        references: 1,
                    },
                );
                self.memory
                    .put_number(a(4)?, object, self.environment.pointer)?;
                Some(0)
            }
            ("ntdll", "RtlMoveMemory" | "memcpy" | "memmove") => {
                self.memory
                    .copy(a(0)?, a(1)?, usize::try_from(a(2)?).ok()?)?;
                Some(a(0)?)
            }
            ("ntdll", "RtlZeroMemory") => {
                let size = usize::try_from(a(1)?).ok()?;
                if size > 8 * 1024 * 1024 {
                    return None;
                }
                self.memory.write(a(0)?, &vec![0; size])?;
                Some(0)
            }
            ("ntdll", "memset") => {
                let size = usize::try_from(a(2)?).ok()?;
                if size > 8 * 1024 * 1024 {
                    return None;
                }
                self.memory.write(a(0)?, &vec![a(1)? as u8; size])?;
                Some(a(0)?)
            }
            ("shlwapi", "PathFileExists" | "PathIsDirectory") => {
                let path = self.memory.string(a(0)?, wide)?;
                Some(u64::from(if function == "PathIsDirectory" {
                    context.files.attributes(&path).is_some_and(|a| a & 16 != 0)
                } else {
                    context.files.exists(path, RelativeLocation::Current)
                }))
            }
            ("shlwapi", "PathIsRelative") => {
                let path = self.memory.string(a(0)?, wide)?;
                Some(u64::from(!Utf8WindowsPath::new(&path).is_absolute()))
            }
            (
                "shlwapi",
                "PathRemoveFileSpec" | "PathAddBackslash" | "PathAppend" | "PathCombine",
            ) => {
                let pointer = a(0)?;
                let input = self.memory.string(
                    if function == "PathCombine" {
                        a(1)?
                    } else {
                        pointer
                    },
                    wide,
                )?;
                let value = match function {
                    "PathRemoveFileSpec" => Utf8WindowsPath::new(&input)
                        .parent()
                        .map(|p| p.as_str().to_owned())
                        .unwrap_or_default(),
                    "PathAddBackslash" => {
                        if input.ends_with(['\\', '/']) {
                            input
                        } else {
                            format!("{input}\\")
                        }
                    }
                    _ => Utf8WindowsPath::new(&input)
                        .join(
                            self.memory
                                .string(a(if function == "PathCombine" { 2 } else { 1 })?, wide)?,
                        )
                        .normalize()
                        .into_string(),
                };
                self.memory.put_string(pointer, &value, wide, 260)?;
                Some(
                    if function == "PathCombine" || function == "PathAddBackslash" {
                        pointer
                    } else {
                        1
                    },
                )
            }
            ("user32", "ShutdownBlockReasonCreate" | "ShutdownBlockReasonDestroy" | "IsWindow") => {
                Some(1)
            }
            ("user32", "GetSystemMetrics") => {
                self.assume("os-edition");
                if matches!(a(0)?, 86..=89) {
                    Some(0)
                } else {
                    None
                }
            }
            ("user32", "CharUpper" | "CharLower" | "CharUpperBuff" | "CharLowerBuff") => {
                let pointer = a(0)?;
                let upper = function.starts_with("CharUpper");
                let buffer = function.ends_with("Buff");
                if pointer <= 0xffff && !buffer {
                    let character = u8::try_from(pointer).ok()?;
                    if !character.is_ascii() {
                        return None;
                    }
                    return Some(if upper {
                        character.to_ascii_uppercase()
                    } else {
                        character.to_ascii_lowercase()
                    } as u64);
                }
                if buffer {
                    let count = usize::try_from(a(1)?).ok()?;
                    let width = if wide { 2 } else { 1 };
                    let mut bytes = self
                        .memory
                        .read(pointer, count.checked_mul(width)?)?
                        .to_vec();
                    for unit in bytes.chunks_exact_mut(width) {
                        if !unit[0].is_ascii() || (wide && unit[1] != 0) {
                            return None;
                        }
                        unit[0] = if upper {
                            unit[0].to_ascii_uppercase()
                        } else {
                            unit[0].to_ascii_lowercase()
                        };
                    }
                    self.memory.write(pointer, &bytes)?;
                    Some(count as u64)
                } else {
                    let value = self.memory.string(pointer, wide)?;
                    // Non-ASCII casing depends on the target Windows NLS tables.
                    if !value.is_ascii() {
                        return None;
                    }
                    let value = if upper {
                        value.to_ascii_uppercase()
                    } else {
                        value.to_ascii_lowercase()
                    };
                    self.memory.write(pointer, &Memory::encoded(&value, wide))?;
                    Some(pointer)
                }
            }
            _ => None,
        }
    }

    fn shell_interface(iid: &str) -> Option<ShellInterface> {
        Some(match iid {
            "000214f9-0000-0000-c000-000000000046" => ShellInterface::Link { wide: true },
            "000214ee-0000-0000-c000-000000000046" => ShellInterface::Link { wide: false },
            "00000000-0000-0000-c000-000000000046" => ShellInterface::Unknown,
            "0000010b-0000-0000-c000-000000000046" => ShellInterface::Persist,
            _ => return None,
        })
    }

    fn com(
        &mut self,
        handle: u64,
        index: u32,
        args: &[u64],
        context: &mut Context<'_, '_>,
    ) -> Option<u64> {
        let Handle::ShellLink {
            object,
            interface,
            references,
        } = self.handles.get(&handle)?.clone()
        else {
            return None;
        };
        match index {
            0 => {
                let iid =
                    Uuid::from_bytes_le(self.memory.read(*args.first()?, 16)?.try_into().ok()?)
                        .to_string();
                let interface = Self::shell_interface(&iid)?;
                let next = self.handle(Handle::ShellLink {
                    object,
                    interface,
                    references: 1,
                })?;
                self.memory
                    .put_number(*args.get(1)?, next, self.environment.pointer)?;
                Some(0)
            }
            1 => {
                let references = references.checked_add(1)?;
                self.handles.insert(
                    handle,
                    Handle::ShellLink {
                        object,
                        interface,
                        references,
                    },
                );
                Some(references as u64)
            }
            2 => {
                let references = references.checked_sub(1)?;
                if references == 0 {
                    self.handles.remove(&handle);
                } else {
                    self.handles.insert(
                        handle,
                        Handle::ShellLink {
                            object,
                            interface,
                            references,
                        },
                    );
                }
                Some(references as u64)
            }
            20 if matches!(interface, ShellInterface::Link { .. }) => {
                let ShellInterface::Link { wide } = interface else {
                    return None;
                };
                let path = self.memory.string(*args.first()?, wide)?;
                self.links.insert(object, path);
                Some(0)
            }
            6 if matches!(interface, ShellInterface::Persist) => {
                let path = self.memory.string(*args.first()?, true)?;
                let target = self.links.get(&object).cloned().unwrap_or_default();
                context.files.create_link(path, target);
                Some(0)
            }
            7 | 9 | 11 | 13 | 15 | 17 | 18 | 19
                if matches!(interface, ShellInterface::Link { .. }) =>
            {
                Some(0)
            }
            _ => None,
        }
    }

    fn encoding(&mut self, function: &str, args: &[u64]) -> Option<u64> {
        let codepage = *args.first()?;
        let flags = *args.get(1)?;
        let pointer = *args.get(2)?;
        let count = *args.get(3)? as u32 as i32;
        let output = *args.get(4)?;
        let capacity = usize::try_from(*args.get(5)?).ok()?;
        let encoding = if codepage == 0 {
            Some(codepage::ansi())
        } else {
            u16::try_from(codepage).ok().and_then(codepage::for_id)
        };
        let Some(encoding) = encoding else {
            return self.failure(87);
        };
        if count == 0 || count < -1 {
            return self.failure(87);
        }
        if function == "MultiByteToWideChar" {
            let bytes = if count == -1 {
                let mut bytes = Vec::new();
                for i in 0..8192 {
                    let b = self.memory.number(pointer + i, 1)? as u8;
                    bytes.push(b);
                    if b == 0 {
                        break;
                    }
                }
                bytes
            } else {
                self.memory.read(pointer, count as usize)?.to_vec()
            };
            let (value, invalid) = encoding.decode_without_bom_handling(&bytes);
            if invalid && flags & 8 != 0 {
                return self.failure(1113);
            }
            let units: Vec<_> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let required = units.len() / 2;
            if capacity == 0 {
                return Some(required as u64);
            }
            if capacity < required {
                return self.failure(122);
            }
            self.memory.write(output, &units)?;
            Some(required as u64)
        } else {
            let units = if count == -1 {
                let mut units = Vec::new();
                for i in 0..8192 {
                    let c = self.memory.number(pointer + i * 2, 2)? as u16;
                    units.push(c);
                    if c == 0 {
                        break;
                    }
                }
                units
            } else {
                self.memory
                    .read(pointer, (count as usize).checked_mul(2)?)?
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect()
            };
            let value = String::from_utf16(&units).ok()?;
            let bytes = codepage::encode_with(&value, encoding);
            if capacity == 0 {
                return Some(bytes.len() as u64);
            }
            if capacity < bytes.len() {
                return self.failure(122);
            }
            self.memory.write(output, &bytes)?;
            if args.get(7).copied().unwrap_or(0) != 0 {
                self.memory.put_number(args[7], 0, 4)?;
            }
            Some(bytes.len() as u64)
        }
    }
}
