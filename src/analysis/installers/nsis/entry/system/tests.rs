use std::borrow::Cow;

use zerocopy::I32;

use super::{Context, MockCaller, engine};
use crate::analysis::installers::nsis::{
    Variables,
    entry::{ExecFlag, ExecFlags},
    file_system::{FileSystem, RelativeLocation},
    registry::{RegType, Registry},
};

struct Harness {
    system: MockCaller,
    variables: Variables<'static>,
    stack: Vec<Cow<'static, str>>,
    flags: ExecFlags,
    registry: Registry,
    files: FileSystem,
}

impl Harness {
    fn new() -> Self {
        let mut system = MockCaller::new();
        system.engine.environment.version = (10, 0, 26300);
        system.engine.environment.version_revision = 9818;
        system.engine.environment.native_machine = 0x8664;
        Self {
            system,
            variables: Variables::new(),
            stack: Vec::new(),
            flags: ExecFlags::new(),
            registry: Registry::new(),
            files: FileSystem::new(),
        }
    }

    fn export(&mut self, name: &str) -> bool {
        self.system.invoke(
            name,
            &mut Context {
                variables: &mut self.variables,
                stack: &mut self.stack,
                flags: &mut self.flags,
                registry: &mut self.registry,
                files: &mut self.files,
            },
        )
    }

    fn call(&mut self, source: impl Into<String>) {
        let source = source.into();
        self.stack.push(Cow::Owned(source.clone()));
        assert!(self.export("Call"), "{source}");
    }

    fn reg(&self, index: usize) -> String {
        self.variables
            .get(&index)
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    fn pop(&mut self) -> String {
        self.stack.pop().unwrap().into_owned()
    }
}

#[test]
fn administrator_membership_uses_an_allocated_sid_and_separate_result() {
    let mut h = Harness::new();
    h.call("*(&i1 0,&i4 0,&i1 5)p.r0");
    h.call("advapi32::AllocateAndInitializeSid(pr0,i2,i32,i544,i0,i0,i0,i0,i0,i0,*p.r1)i.r2");
    assert_eq!(h.reg(2), "1");
    let sid = engine::integer(&h.reg(1));
    h.call("advapi32::CheckTokenMembership(p0,pr1,*i.r3)i.r2");
    assert_eq!(h.reg(2), "1");
    assert_eq!(h.reg(3), "1");
    h.variables.insert(10, sid.to_string());
    h.call("advapi32::CheckTokenMembership(i n,i R0,*i .R1)i.r5");
    assert_eq!(h.reg(5), "1");
    assert_eq!(h.reg(11), "1");
    h.call("advapi32::CheckTokenMembership(p123,pr1,*i.r3)i.r2");
    assert_eq!(h.reg(2), "0");
    h.call("kernel32::GetLastError()i.r2");
    assert_eq!(h.reg(2), "6");
    h.call("advapi32::FreeSid(pr1)p.r2");
    assert_eq!(h.reg(2), "0");
    assert!(h.system.engine.memory.read(sid, 16).is_none());
}

#[test]
fn explicit_ansi_conversion_preserves_multibyte_characters() {
    let mut h = Harness::new();
    h.call("*(&i8 0xa5b2b1d6e3d3b7b6)p.r0");
    h.call("kernel32::MultiByteToWideChar(i936,i0,pr0,i8,w.r1,i8192)i.r2");
    assert_eq!(h.reg(1), "斗鱼直播");
    assert_eq!(h.reg(2), "4");
    let pointer = engine::integer(&h.reg(0));
    h.call("kernel32::WideCharToMultiByte(i936,i0,w '斗鱼直播',i4,pr0,i8,p0,p0)i.r2");
    assert_eq!(h.reg(2), "8");
    assert_eq!(
        h.system.engine.memory.read(pointer, 8),
        Some(b"\xb6\xb7\xd3\xe3\xd6\xb1\xb2\xa5".as_slice())
    );
}

#[test]
fn os_registry_values_use_profile_versions_and_windows_compatibility_strings() {
    let mut h = Harness::new();
    let key = r"Software\Microsoft\Windows NT\CurrentVersion";
    assert_eq!(
        h.system.windows_registry_value(key, "CurrentVersion"),
        Some(("6.3".to_owned(), RegType::String))
    );
    assert_eq!(
        h.system
            .windows_registry_value(key, "CurrentBuild")
            .unwrap()
            .0,
        "26300"
    );
    assert_eq!(
        h.system.windows_registry_value(key, "UBR").unwrap().0,
        "9818"
    );
    assert_eq!(
        h.system
            .windows_registry_value("Software\\Example", "CurrentVersion"),
        None
    );
    h.system.engine.environment.version = (6, 1, 7601);
    assert_eq!(
        h.system
            .windows_registry_value(key, "CurrentVersion")
            .unwrap()
            .0,
        "6.1"
    );
    assert_eq!(
        h.system
            .windows_registry_value(key, "CurrentMajorVersionNumber"),
        None
    );
}

#[test]
fn nsis_reads_cached_windows_version_and_execution_flags() {
    let mut h = Harness::new();
    h.flags[ExecFlag::Errors] = I32::new(7);
    for (offset, size, expected) in [
        (56, 4, 26300),
        (60, 1, 129),
        (61, 1, 0),
        (62, 1, 0),
        (63, 1, 10),
        (62, 2, 2560),
        (8, 4, 7),
    ] {
        assert_eq!(
            h.system.read_memory(0, (offset << 24) | size, &h.flags),
            Some(expected)
        );
    }
    assert_eq!(h.flags[ExecFlag::Errors].get(), 7);
    assert_eq!(h.system.read_memory(0, (63 << 24) | 4, &h.flags), None);
    assert_eq!(h.system.read_memory(0, 8, &h.flags), None);
    h.system
        .configure(winget_types::installer::Architecture::X64, true, None, None);
    assert_eq!(h.system.read_memory(0, (60 << 24) | 1, &h.flags), Some(1));
}

#[test]
fn nsis_read_memory_uses_only_known_simulated_allocations() {
    let mut h = Harness::new();
    h.call("*(&i8 0x1122334455667788)p.r0");
    let address = engine::integer(&h.reg(0));
    assert_eq!(
        h.system.read_memory(address, (2 << 24) | 2, &h.flags),
        Some(0x5566)
    );
    assert_eq!(h.system.read_memory(address, (7 << 24) | 2, &h.flags), None);
    assert_eq!(
        h.system.read_memory(u64::MAX, (1 << 24) | 1, &h.flags),
        None
    );
    assert_eq!(h.system.read_memory(0x1234, 4, &h.flags), None);
}

#[test]
fn pointer_structures_roundtrip_packed_scalars_and_strings() {
    let mut h = Harness::new();
    h.call("*(&i32)p.r0");
    let pointer = h.reg(0);
    h.call(format!("*{pointer}(i42,&i2 65535,&w6 'hello')"));
    h.call(format!("*{pointer}(i.r1,&i2.r2,&w6.r3,&l.s)"));
    assert_eq!(
        (h.reg(1), h.reg(2), h.reg(3)),
        ("42".to_owned(), "65535".to_owned(), "hello".to_owned())
    );
    assert_eq!(h.pop(), "18");
    h.call("*(t '€🚀',p0,l-1)p.r0");
    let pointer = h.reg(0);
    h.call(format!("*{pointer}(t.r1,p.r2,l.r3)"));
    assert_eq!(h.reg(1), "€🚀");
    assert_eq!(h.reg(2), "0");
    assert_eq!(h.reg(3), "-1");
    h.call("*(&l4,&i24)p.r0");
    let pointer = h.reg(0);
    h.call(format!("*{pointer}(i.r1,&l.r2)"));
    assert_eq!(h.reg(1), "28");
    // &l with no stored fields reports the size of an existing allocation.
    h.call(format!("*{pointer}(&l.s)"));
    assert_eq!(h.pop(), "28");
}

#[test]
fn aligned_structures_use_the_target_pointer_width() {
    let mut h = Harness::new();
    h.system.engine.environment.pointer = 8;
    h.call("*(b1,P2,&l.s)p.r0?2");
    assert_eq!(h.pop(), "16");
    let pointer = engine::integer(&h.reg(0));
    assert_eq!(h.system.engine.memory.number(pointer + 8, 8), Some(2));
}

#[test]
fn reference_initializers_and_stack_outputs_follow_native_order() {
    let mut h = Harness::new();
    h.stack.push(Cow::Borrowed("-1"));
    h.call("kernel32::IsWow64Process2(ps,*i0s,*i0s)i.s");
    assert_eq!(h.pop(), "1");
    assert_eq!(h.pop(), "332");
    assert_eq!(h.pop(), "34404");
    assert!(h.stack.is_empty());
}

#[test]
fn allocation_copy_free_and_stale_pointers_are_bounded() {
    let mut h = Harness::new();
    h.stack.push(Cow::Borrowed("16"));
    assert!(h.export("Alloc"));
    let source = h.pop();
    h.call(format!("*{source}(i1234)"));
    h.stack.extend([
        Cow::Owned(source.clone()),
        Cow::Borrowed("0"),
        Cow::Borrowed("/4"),
    ]);
    assert!(h.export("Copy"));
    let destination = h.pop();
    h.call(format!("*{destination}(i.s)"));
    assert_eq!(h.pop(), "1234");
    h.stack.push(Cow::Owned(source.clone()));
    assert!(h.export("Free"));
    h.stack.push(Cow::Owned(format!("*{source}(i.s)")));
    assert!(!h.export("Call"));
    assert_eq!(h.pop(), "$ERROR");
    h.stack.push(Cow::Borrowed("999999999999999"));
    assert!(!h.export("Alloc"));
    assert_eq!(h.pop(), "0");
}

#[test]
fn integer_exports_cover_overflow_division_and_unsigned_shifts() {
    let mut h = Harness::new();
    for (a, op, b, expected) in [
        ("9223372036854775807", "+", "1", "-9223372036854775808"),
        ("-1", ">>>", "1", "9223372036854775807"),
        ("7", "/", "0", "0"),
        ("7", "%", "0", "7"),
        ("0x100000000", "|", "3", "4294967299"),
        ("-2", ">>", "1", "-1"),
    ] {
        h.stack
            .extend([Cow::Borrowed(b), Cow::Borrowed(op), Cow::Borrowed(a)]);
        assert!(h.export("Int64Op"));
        assert_eq!(h.pop(), expected);
    }
}

#[test]
fn get_and_call_reuse_declarations_and_last_error_options() {
    let mut h = Harness::new();
    h.stack.push(Cow::Borrowed("kernel32::GetLastError()i.s?r"));
    assert!(h.export("Get"));
    assert_eq!(h.pop(), "ok");
    let procedure = h.pop();
    h.call("kernel32::SetLastError(i87)");
    h.call(&procedure);
    assert_eq!(h.pop(), "ok");
    assert_eq!(h.pop(), "87");
    h.call("kernel32::GetCurrentProcess()p.r0?e");
    assert_eq!(h.reg(0), "-1");
    assert_eq!(h.pop(), "87");
    h.stack.push(Cow::Owned(procedure));
    assert!(h.export("Free"));
}

#[test]
fn store_register_and_execflag_commands_keep_abort_state() {
    let mut h = Harness::new();
    h.variables.insert(19, "saved");
    h.stack.push(Cow::Borrowed("P9"));
    assert!(h.export("Store"));
    assert_eq!(h.pop(), "saved");
    h.stack.extend([Cow::Borrowed("new"), Cow::Borrowed("R9")]);
    assert!(h.export("Store"));
    assert_eq!(h.reg(19), "new");
    h.flags[ExecFlag::Errors] = I32::new(1);
    h.flags[ExecFlag::Abort] = I32::new(1);
    h.stack.push(Cow::Borrowed("F"));
    assert!(h.export("Store"));
    h.flags[ExecFlag::Errors] = I32::ZERO;
    h.flags[ExecFlag::Abort] = I32::ZERO;
    h.stack.push(Cow::Borrowed("f"));
    assert!(h.export("Store"));
    assert_eq!(h.flags[ExecFlag::Errors].get(), 1);
    assert_eq!(h.flags[ExecFlag::Abort].get(), 0);
}

#[test]
fn inline_and_legacy_environment_calls_share_state() {
    let mut h = Harness::new();
    h.call("kernel32::SetEnvironmentVariable(t,t)i ('name,1','value(2)').r0");
    h.call("kernel32::GetEnvironmentVariable(t 'name,1',t.r1,i8192)i.r2");
    assert_eq!(h.reg(1), "value(2)");
    assert_eq!(h.reg(2), "8");
    h.call("kernel32::SetEnvironmentVariable(t 'name,1',p0)i.r0");
    h.call("kernel32::GetEnvironmentVariable(t 'name,1',t.r1,i8192)i.r2?e");
    assert_eq!(h.reg(2), "0");
    assert_eq!(h.pop(), "203");
}

#[test]
fn osversion_structures_support_unicode_ansi_and_legacy_reporting() {
    let mut h = Harness::new();
    h.call("*(&i284)p.r0");
    let p = h.reg(0);
    h.call(format!("*{p}(i284)"));
    h.call("kernel32::GetVersionEx(pr0)i.r3");
    assert_eq!(h.reg(3), "1");
    h.call(format!(
        "*{p}(i,i.r1,i.r2,i.r3,i.r4,&t128,&i2,&i2,&i2,&i1.r5)"
    ));
    assert_eq!(
        (h.reg(1), h.reg(2), h.reg(3), h.reg(4), h.reg(5)),
        (
            "10".to_owned(),
            "0".to_owned(),
            "26300".to_owned(),
            "2".to_owned(),
            "1".to_owned()
        )
    );
    h.system.engine.environment.version_manifest = false;
    h.call("kernel32::GetVersionEx(pr0)i.r4");
    h.call(format!("*{p}(i,i.r1,i.r2)"));
    assert_eq!((h.reg(1), h.reg(2)), ("6".to_owned(), "2".to_owned()));
    h.system.engine.environment.unicode = false;
    h.call("*(&i156)p.r0");
    let p = h.reg(0);
    h.call(format!("*{p}(i156)"));
    h.call("kernel32::GetVersionExA(pr0)i.r1");
    assert_eq!(h.reg(1), "1");
}

#[test]
fn shell_known_folders_allocate_strings_and_release_them() {
    let mut h = Harness::new();
    h.call("SHELL32::SHGetKnownFolderPath(g '{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}',i0x8000,p0,*p.r2)i.r1");
    assert_eq!(h.reg(1), "0");
    let pointer = h.reg(2);
    h.call(format!("*{pointer}(&w8192.s)"));
    assert_eq!(h.pop(), r"%LocalAppData%\Programs");
    h.call("kernel32::lstrcpynW(w.r0,pr2,i8192)p");
    assert_eq!(h.reg(0), r"%LocalAppData%\Programs");
    h.call("ole32::CoTaskMemFree(pr2)");
    assert!(
        h.system
            .engine
            .memory
            .read(engine::integer(&pointer), 1)
            .is_none()
    );
}

#[test]
fn unknown_api_results_are_explicit_and_do_not_become_zero() {
    let mut h = Harness::new();
    h.variables.insert(0, "old");
    h.stack.push(Cow::Borrowed("unknown::Missing(*i.r1)i.r0?e"));
    assert!(!h.export("Call"));
    assert_eq!(h.reg(0), "$ERROR");
    assert_eq!(h.reg(1), "$ERROR");
    assert_eq!(h.pop(), "$ERROR");
    h.stack.extend([
        Cow::Borrowed("sentinel"),
        Cow::Borrowed("42"),
        Cow::Borrowed("not a GUID"),
        Cow::Borrowed("unknown::Missing(gs,ps)i.s?re"),
    ]);
    assert!(!h.export("Call"));
    assert_eq!(h.pop(), "$ERROR");
    assert_eq!(h.pop(), "$ERROR");
    assert_eq!(h.pop(), "$ERROR");
    assert_eq!(h.pop(), "sentinel");
}

#[test]
fn registry_api_writes_are_visible_to_arp_extraction() {
    let mut h = Harness::new();
    h.call("advapi32::RegCreateKeyExW(p0x80000001,w'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SystemPlugin',i0,p0,i0,i0xF003F,p0,*p.r0,*i.r1)i.r2");
    assert_eq!(h.reg(2), "0");
    h.call("advapi32::RegSetValueExW(pr0,w'DisplayName',i0,i1,w'From System',i24)i.r1");
    assert_eq!(h.reg(1), "0");
    h.call("advapi32::RegQueryValueExW(pr0,w'DisplayName',p0,*i.r2,w.r3,*i256r4)i.r5");
    assert_eq!(h.reg(3), "From System");
    assert_eq!(h.reg(2), "1");
    assert_eq!(h.reg(4), "24");
    assert_eq!(h.reg(5), "0");
    h.call("advapi32::RegEnumValueW(pr0,i0,w.r3,*i256r4,p0,*i.r2,w.r6,*i256r7)i.r5");
    assert_eq!(h.reg(3), "DisplayName");
    assert_eq!(h.reg(6), "From System");
    assert_eq!(h.reg(7), "24");
    assert_eq!(h.reg(5), "0");
    let (_, code, values) = h.registry.uninstall_entries().next().unwrap();
    assert_eq!(code, "SystemPlugin");
    assert_eq!(
        Registry::uninstall_value(values, "DisplayName").map(String::as_str),
        Some("From System")
    );
}

#[test]
fn shell_link_com_objects_can_create_simulated_shortcuts() {
    let mut h = Harness::new();
    h.call("ole32::CoCreateInstance(g'{00021401-0000-0000-c000-000000000046}',p0,i1,g'{000214f9-0000-0000-c000-000000000046}',*p.r0)i.r1");
    assert_eq!(h.reg(1), "0");
    let link = h.reg(0);
    h.call(format!("{link}->20(w'%ProgramFiles%\\App\\app.exe')i.r1"));
    h.call(format!(
        "{link}->0(g'{{0000010b-0000-0000-c000-000000000046}}',*p.r2)i.r1"
    ));
    let persist = h.reg(2);
    h.call(format!("{persist}->1()i.r3"));
    assert_eq!(h.reg(3), "2");
    h.call(format!("{persist}->2()i.r3"));
    assert_eq!(h.reg(3), "1");
    h.call(format!("{persist}->6(w'Desktop\\App.lnk',i1)i.r1"));
    assert!(h.files.exists(r"Desktop\App.lnk", RelativeLocation::Root));
}

#[test]
fn virtual_time_and_module_resolution_do_not_use_host_processes() {
    let mut h = Harness::new();
    h.call("kernel32::GetTickCount64()l.s");
    let before = h.pop().parse::<u64>().unwrap();
    h.system.advance_time(25);
    h.call("kernel32::GetTickCount64()l.s");
    assert_eq!(h.pop().parse::<u64>().unwrap() - before, 26);
    h.call("kernel32::LoadLibrary(w'kernel32.dll')p.r0");
    h.call("kernel32::GetProcAddress(pr0,m'GetCurrentProcess')p.r1");
    let proc = h.reg(1);
    h.call(format!("{proc}()p.s"));
    assert_eq!(h.pop(), "-1");
}

#[test]
fn saved_procedure_redefinitions_and_temporary_overrides_follow_native_rules() {
    let mut h = Harness::new();
    h.stack.push(Cow::Borrowed("kernel32::SetLastError(i13)"));
    assert!(h.export("Get"));
    let procedure = h.pop();
    h.call(format!("{procedure}(i42)"));
    h.call("kernel32::SetLastError(i0)");
    h.call(&procedure);
    assert_eq!(h.system.engine.last_error, 42);
    h.call(format!("{procedure}?n"));
    h.call(format!("{procedure}(i87)"));
    assert_eq!(h.system.engine.last_error, 87);
    h.call(&procedure);
    assert_eq!(h.system.engine.last_error, 42);
    h.stack.push(Cow::Borrowed("kernel32::GetLastError()i.r0"));
    assert!(h.export("Get"));
    let getter = h.pop();
    h.call(format!("{getter}().r1"));
    assert_eq!(h.reg(1), "42");
}

#[test]
fn target_architecture_configures_windows_without_changing_the_setup_abi() {
    use winget_types::installer::Architecture;
    let mut h = Harness::new();
    h.system
        .configure(Architecture::X86, true, None, Some(Architecture::Arm64));
    h.call("kernel32::IsWow64Process2(p-1,*i0s,*i0s)i.r0");
    assert_eq!(h.pop(), "332");
    assert_eq!(h.pop(), "43620");
    h.call("*0x7FFE002E(&i2.s)");
    assert_eq!(h.pop(), "43620");
    assert_eq!(h.system.engine.environment.pointer, 4);
}

#[test]
fn arm_emulation_shared_architecture_and_win81_compatibility_are_distinct() {
    use winget_types::installer::Architecture;
    let mut h = Harness::new();
    h.system.engine.environment.native_machine = 0xaa64;
    h.system.configure(
        Architecture::X86,
        true,
        Some("1f676c76-80e1-4239-95bb-83d0f6d0da78"),
        None,
    );
    h.call("kernel32::IsWow64Process(p-1,*i0s)i.r0");
    assert_eq!(h.pop(), "0");
    h.call("kernel32::IsWow64Process2(p-1,*i0s,*i0s)i.r0");
    assert_eq!(h.pop(), "332");
    assert_eq!(h.pop(), "43620");
    h.call("*0x7FFE002E(&i2.s)");
    assert_eq!(h.pop(), "43620");
    assert!(!h.system.engine.memory.free(0x7ffe0000));
    assert!(h.system.engine.memory.write(0x7ffe002e, &[0, 0]).is_none());
    h.call("kernel32::GetVersion()i.r0");
    assert_eq!(engine::integer(&h.reg(0)) & 0xffff, 0x0306);
    h.call("*(b1,&I2 42,&l.s)p.r0?2");
    assert_eq!(h.pop(), "4");
}

#[test]
fn character_case_updates_strings_and_exact_length_buffers() {
    let mut h = Harness::new();
    h.call("User32::CharUpper(w '%ProgramFiles%\\Mozilla Firefox' r0)p.r1");
    assert_eq!(h.reg(0), r"%PROGRAMFILES%\MOZILLA FIREFOX");
    assert_ne!(h.reg(1), "0");
    h.call("user32::CharLowerW(p65)i.s");
    assert_eq!(h.pop(), "97");
    h.call("*(&w8 'AbCd')p.r0");
    h.call("user32::CharLowerBuffW(pr0,i2)i.s");
    assert_eq!(h.pop(), "2");
    let pointer = h.reg(0);
    h.call(format!("*{pointer}(&w8.r1)"));
    assert_eq!(h.reg(1), "abCd");
    h.stack
        .push(Cow::Borrowed("user32::CharUpper(w 'ä' r0)p.r1"));
    assert!(!h.export("Call"));
    assert_eq!(h.reg(0), "$ERROR");
}
