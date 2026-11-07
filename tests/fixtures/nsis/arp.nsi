; Independent ARP oracle: these are the actual registry writes, not manifest data.
Unicode true
Name "ARP regression"
OutFile "${OUTPUT}"
SetCompressor ${COMPRESSION}
InstallDir "$PROGRAMFILES\ARP regression"
RequestExecutionLevel admin
!define ARP "Software\Microsoft\Windows\CurrentVersion\Uninstall"
Section "Main"
  WriteRegStr HKCR "${ARP}\WrongHive" "DisplayName" "Not an ARP registration"
  IntOp $0 0xFFFFFFFF & 0xFFFF
  IntOp $1 010 + 2
  WriteRegStr HKCU "${ARP}\Numbers" "DisplayName" "Numeric app"
  WriteRegStr HKCU "${ARP}\Numbers" "Publisher" "$0:$1"
  IntOp $0 0 !
  IntOp $1 9 !
  WriteRegStr HKCU "${ARP}\LogicalNot" "DisplayName" "Logical not"
  WriteRegStr HKCU "${ARP}\LogicalNot" "Publisher" "$0:$1"
  ClearErrors
  IntOp $0 1 / 0
  IfErrors divide_error_set
  WriteRegStr HKCU "${ARP}\BadMath" "DisplayName" "Missing division error"
  divide_error_set:
  ClearErrors
  IntOp $0 1 % 0
  IfErrors remainder_error_set
  WriteRegStr HKCU "${ARP}\BadMath" "DisplayName" "Missing remainder error"
  remainder_error_set:
  IntFmt $0 "v%02u" 7
  IntFmt $1 "0x%08X" 255
  WriteRegStr HKCU "${ARP}\Formatted" "DisplayName" "Formatted integers"
  WriteRegStr HKCU "${ARP}\Formatted" "Publisher" "$0:$1"
  StrLen $0 "🚀"
  StrCpy $1 "🚀tail" 2
  StrCpy $2 "abcdef" 2 -99
  WriteRegStr HKCU "${ARP}\UnicodeSlice" "DisplayName" "Unicode slicing"
  WriteRegStr HKCU "${ARP}\UnicodeSlice" "Publisher" "$0:$1:$2"
  SetOutPath "$INSTDIR\Payload"
  WriteRegStr HKCU "${ARP}\OutputDirectory" "DisplayName" "$OUTDIR"
  WriteRegStr HKCU "${ARP}\OutputDirectory" "Publisher" "$LANGUAGE"
  GetFullPathName $0 "$OUTDIR\..\Payload\."
  WriteRegStr HKCU "${ARP}\FullPath" "DisplayName" "Full path app"
  WriteRegStr HKCU "${ARP}\FullPath" "Publisher" "$0"
  File "${__FILEDIR__}/arp.ini"
  ReadINIStr $0 "$OUTDIR\arp.ini" "application" "version"
  WriteRegStr HKCU "${ARP}\Ini" "DisplayName" "INI app"
  WriteRegStr HKCU "${ARP}\Ini" "DisplayVersion" "$0"
  WriteINIStr "$OUTDIR\arp.ini" "Application" "Publisher" "From INI"
  ReadINIStr $0 "$OUTDIR\arp.ini" "APPLICATION" "PUBLISHER"
  WriteRegStr HKCU "${ARP}\Ini" "Publisher" "$0"
  DeleteINIStr "$OUTDIR\arp.ini" "Application" "Publisher"
  StrCpy $0 "stale"
  ClearErrors
  ReadINIStr $0 "$OUTDIR\arp.ini" "Application" "Publisher"
  IfErrors ini_expected_error
  WriteRegStr HKCU "${ARP}\BadIni" "DisplayName" "Missing INI error flag"
  ini_expected_error:
  StrCmp $0 "" ini_done
  WriteRegStr HKCU "${ARP}\BadIni" "DisplayName" "Stale INI output"
  ini_done:
  FindFirst $0 $1 "$OUTDIR\*.ini"
  WriteRegStr HKCU "${ARP}\Find" "DisplayName" "Find app"
  WriteRegStr HKCU "${ARP}\Find" "Publisher" "$1"
  ClearErrors
  FindNext $0 $1
  IfErrors find_exhausted
  WriteRegStr HKCU "${ARP}\BadFind" "DisplayName" "Missing end-of-search error"
  find_exhausted:
  StrCmp $1 "" find_done
  WriteRegStr HKCU "${ARP}\BadFind" "DisplayName" "Stale search output"
  find_done:
  FindClose $0
  StrCpy $0 "stale handle"
  StrCpy $1 "stale name"
  ClearErrors
  FindFirst $0 $1 "$OUTDIR\Missing\*.ini"
  IfErrors find_missing_error
  WriteRegStr HKCU "${ARP}\BadFind" "DisplayName" "Missing search error"
  find_missing_error:
  StrCmp $1 "" find_missing_name_cleared
  WriteRegStr HKCU "${ARP}\BadFind" "DisplayName" "Stale missing-search name"
  find_missing_name_cleared:
  StrCmp $0 "" find_missing_done
  WriteRegStr HKCU "${ARP}\BadFind" "DisplayName" "Stale missing-search handle"
  find_missing_done:
  WriteRegStr HKCU "Software\A" "DisplayName" "Not an ARP entry"
  WriteRegStr HKCU "Software\A" "Publisher" "Wrong publisher"
  WriteRegStr HKCU "${ARP}\Main" "DisplayName" "Old name"
  WriteRegStr HKCU "${ARP}\Main" "displayname" "Main app"
  WriteRegStr HKCU "Software\VersionSource" "Version" "1.2.3"
  StrCpy $0 "Stale value"
  ReadRegStr $0 HKCU "Software\VersionSource" "Version"
  WriteRegStr HKCU "${ARP}\Main" "DisplayVersion" "$0"
  WriteRegStr HKCU "${ARP}\Main" "Publisher" "Publisher € 🚀 $0"
  WriteRegStr HKCU "${ARP}\Keep" "DisplayName" "Keep app"
  DeleteRegKey /ifempty HKCU "${ARP}\Keep"
  SetShellVarContext all
  WriteRegStr SHCTX "${ARP}\SharedAppData" "DisplayName" "Shared app data"
  WriteRegStr SHCTX "${ARP}\SharedAppData" "Publisher" "$APPDATA"
  WriteRegStr SHCTX "${ARP}\MachineContext" "DisplayName" "Machine context"
  ReadRegStr $0 HKLM "${ARP}\MachineContext" "DisplayName"
  WriteRegStr SHCTX "${ARP}\MachineContext" "Publisher" "$0"
  SetShellVarContext current
  WriteRegStr SHCTX "${ARP}\UserContext" "DisplayName" "User context"
  ReadRegStr $0 HKCU "${ARP}\UserContext" "DisplayName"
  WriteRegStr SHCTX "${ARP}\UserContext" "Publisher" "$0"
  WriteRegDWORD HKCU "Software\VersionSource" "Number" 42
  ClearErrors
  ReadRegDWORD $0 HKCU "Software\VersionSource" "Number"
  IfErrors incorrect_dword
  WriteRegStr HKCU "${ARP}\Typed" "DisplayName" "Typed app"
  WriteRegStr HKCU "${ARP}\Typed" "Publisher" "$0"
  Goto typed_done
  incorrect_dword:
    WriteRegStr HKCU "${ARP}\Typed" "DisplayName" "Wrong DWORD read"
  typed_done:
  ClearErrors
  ReadRegDWORD $0 HKCU "Software\VersionSource" "Version"
  IfErrors expected_type_error
  WriteRegStr HKCU "${ARP}\UnexpectedType" "DisplayName" "Wrong string type"
  expected_type_error:
  SetRegView 64
  WriteRegStr HKCU "${ARP}\View" "DisplayName" "64-bit entry"
  SetRegView 32
  WriteRegStr HKCU "${ARP}\View" "DisplayName" "32-bit entry"
  SetRegView 64
  ReadRegStr $0 HKCU "${ARP}\View" "DisplayName"
  SetRegView 32
  WriteRegStr HKCU "${ARP}\View" "Publisher" "$0"
  SetRegView 64
  DeleteRegKey HKCU "${ARP}\View"
  SetRegView 32
  StrCpy $0 "stale"
  EnumRegKey $0 HKCU "Software\KomacAuditFixtureMissing" 0
  StrCmp $0 "" enum_missing_cleared
  WriteRegStr HKCU "${ARP}\BadEnum" "DisplayName" "Stale enumeration output"
  enum_missing_cleared:
  WriteRegStr HKCU "Software\KomacAuditFixture\First\Leaf" "Value" "data"
  EnumRegKey $0 HKCU "Software\KomacAuditFixture" 0
  EnumRegValue $1 HKCU "Software\KomacAuditFixture\First\Leaf" 0
  WriteRegStr HKCU "${ARP}\Enumeration" "DisplayName" "Enumeration app"
  WriteRegStr HKCU "${ARP}\Enumeration" "Publisher" "$0:$1"
  SetOutPath "$INSTDIR\Payload\Keep"
  File "${__FILEDIR__}/arp.ini"
  SetOutPath "$INSTDIR\Payload"
  ClearErrors
  RMDir "$OUTDIR\Keep"
  IfErrors nonempty_directory_preserved
  WriteRegStr HKCU "${ARP}\BadRemoval" "DisplayName" "Removed a nonempty directory without /r"
  nonempty_directory_preserved:
  IfFileExists "$OUTDIR\Keep\arp.ini" nonempty_contents_preserved
  WriteRegStr HKCU "${ARP}\BadRemoval" "DisplayName" "Lost contents of nonempty directory"
  nonempty_contents_preserved:
  Delete "$OUTDIR\Keep\*.ini"
  IfFileExists "$OUTDIR\Keep\arp.ini" file_was_not_deleted file_was_deleted
  file_was_not_deleted:
  WriteRegStr HKCU "${ARP}\BadRemoval" "DisplayName" "Wildcard Delete did not remove the file"
  file_was_deleted:
  RMDir "$OUTDIR\Keep"
  ClearErrors
  RMDir "$OUTDIR"
  IfErrors working_directory_preserved
  WriteRegStr HKCU "${ARP}\BadRemoval" "DisplayName" "Removed the working directory"
  working_directory_preserved:
  StrCpy $LANGUAGE ""
  WriteRegStr HKCU "${ARP}\EmptyInternal" "DisplayName" "Empty internal app"
  WriteRegStr HKCU "${ARP}\EmptyInternal" "Publisher" "$LANGUAGE:end"
SectionEnd
Section /o "Unselected"
  WriteRegStr HKCU "${ARP}\Unselected" "DisplayName" "Must not be installed"
SectionEnd

Section /o "Enabled by callback" Selected
  WriteRegStr HKCU "${ARP}\Callback" "DisplayName" "Callback app"
SectionEnd
Function .onInit
  GetKnownFolderPath $INSTDIR {5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}
  StrCpy $0 $INSTDIR
  StrCpy $R9 "preserved upper register"
  Push "preserved data stack"
  System::Store S
  StrCpy $0 "0"
  StrCpy $R9 "temporary upper register"
  StrCpy $INSTDIR "$INSTDIR\ARP regression"
  System::Store L
  StrCmp $R9 "preserved upper register" store_register_restored
  WriteRegStr HKCU "${ARP}\BadStore" "DisplayName" "System Store did not restore registers"
  store_register_restored:
  Pop $1
  StrCmp $1 "preserved data stack" store_stack_preserved
  WriteRegStr HKCU "${ARP}\BadStore" "DisplayName" "System Store corrupted the data stack"
  store_stack_preserved:
  StrCmp $INSTDIR "$0\ARP regression" store_internal_preserved
  WriteRegStr HKCU "${ARP}\BadStore" "DisplayName" "System Store restored internal variables"
  store_internal_preserved:
  System::Call 'SHELL32::SHGetKnownFolderPath(g "{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}", i 0x8000, p 0, *p .r2)i.r1'
  StrCmp $1 "0" known_folder_status_ok
  WriteRegStr HKCU "${ARP}\BadKnownFolder" "DisplayName" "Wrong known folder status"
  known_folder_status_ok:
  System::Call '*$2(&w${NSIS_MAX_STRLEN} .s)'
  Pop $3
  StrCmp $3 $0 known_folder_string_ok
  WriteRegStr HKCU "${ARP}\BadKnownFolder" "DisplayName" "Wrong known folder string"
  known_folder_string_ok:
  System::Call 'KERNEL32::lstrcpynW(w .r4, p r2, i ${NSIS_MAX_STRLEN})p'
  StrCmp $4 $0 known_folder_copy_ok
  WriteRegStr HKCU "${ARP}\BadKnownFolder" "DisplayName" "Wrong known folder copy"
  known_folder_copy_ok:
  System::Call 'OLE32::CoTaskMemFree(p r2)'
  SectionSetFlags ${Selected} 1
FunctionEnd
