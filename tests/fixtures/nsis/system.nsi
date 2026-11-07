; Expected ARP is derived from these calls and writes, never a winget manifest.
!ifdef TARGET
Target ${TARGET}
!else
Unicode ${UNICODE}
!endif
; Select the stock macro's System::GetVersionEx implementation.
!define WinVer_v3_7
!include WinVer.nsh
!include x64.nsh
Name "System plugin regression"
OutFile "${OUTPUT}"
InstallDir "$LOCALAPPDATA\Programs\System regression"
RequestExecutionLevel user
!define KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\SystemRegression"

!macro Check value expected
  StrCmp "${value}" "${expected}" +2
  Abort "System regression: ${value} != ${expected}"
!macroend

Section
  ; Exercise the real WinVer/x64 macros, including their private Store stack.
  ${IfNot} ${AtLeastWin10}
    Abort "Wrong OS version"
  ${EndIf}
  ; Windows 11 retains NT version 10.0; the build identifies the release.
  System::Call '*(&l4,&i280)p.r0'
  System::Call 'kernel32::GetVersionEx(pr0)i.r1'
  !insertmacro Check $1 1
  System::Call '*$0(i,i.r1,i.r2,i.r3)'
  !insertmacro Check $1 10
  !insertmacro Check $2 0
  !insertmacro Check $3 26300
  System::Free $0
  ${IfNot} ${IsNativeAMD64}
    Abort "Wrong native architecture"
  ${EndIf}
  System::Store S
  System::Call '*(&i32)p.r0'
  System::Call '*$0(i1234,&i2 65535,&t8 "fixture")'
  System::Call '*$0(i.r1,&i2.r2,&t8.r3)'
  !insertmacro Check $1 1234
  !insertmacro Check $2 65535
  !insertmacro Check $3 fixture
  System::Copy /4 0 $0
  Pop $4
  System::Call '*$4(i.r5)'
  !insertmacro Check $5 1234
  System::Free $0
  System::Free $4
  System::Int64Op 0x100000000 | 3
  Pop $0
  !insertmacro Check $0 4294967299
  System::Store L
  System::Get 'kernel32::GetLastError()i.s'
  Pop $9
  System::Call 'kernel32::SetLastError(i87)'
  System::Call '$9'
  Pop $0
  !insertmacro Check $0 87
  System::Free $9
  System::Call 'SHELL32::SHGetKnownFolderPath(g "{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}",i0,p0,*p.r0)i.r1'
  !insertmacro Check $1 0
  System::Call '*$0(&w8192.r2)'
  StrCpy $INSTDIR "$2\System regression"
  System::Call 'ole32::CoTaskMemFree(pr0)'
  System::Call 'kernel32::SetEnvironmentVariable(t "KomacSystemTest",t "From System")i.r1'
  System::Call 'kernel32::GetEnvironmentVariable(t "KomacSystemTest",t.r2,i1024)i.r1'
  !insertmacro Check $2 "From System"
  ; Native Reg* calls must share the same registry as NSIS WriteRegStr.
  System::Call 'advapi32::RegCreateKeyEx(p0x80000001,t "${KEY}",i0,p0,i0,i0xF003F,p0,*p.r0,*i.r1)i.r2'
  !insertmacro Check $2 0
  ; Pass a literal byte count: the System grammar does not evaluate arithmetic.
  !if ${NSIS_CHAR_SIZE} == 2
    System::Call 'advapi32::RegSetValueEx(pr0,t "DisplayName",i0,i1,t "System fixture",i30)i.r2'
  !else
    System::Call 'advapi32::RegSetValueEx(pr0,t "DisplayName",i0,i1,t "System fixture",i15)i.r2'
  !endif
  !insertmacro Check $2 0
  System::Call 'advapi32::RegCloseKey(pr0)i.r2'
  WriteRegStr HKCU "${KEY}" "DisplayVersion" "1.2.3"
  WriteRegStr HKCU "${KEY}" "Publisher" "From System"
  WriteRegStr HKCU "${KEY}" "InstallLocation" "$INSTDIR"
SectionEnd
