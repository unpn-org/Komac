Unicode true
Name "Termination oracle"
OutFile "${OUTPUT}"
SetCompressor zlib
RequestExecutionLevel user
!define ARP "Software\Microsoft\Windows\CurrentVersion\Uninstall"
Function .onInit
!ifdef ABORT_INIT
  Abort
!endif
!ifdef QUIT_INIT
  Quit
!endif
FunctionEnd
Section "First"
!ifdef ABORT_SECTION
  Abort
!endif
!ifdef QUIT_SECTION
  Quit
!endif
  WriteRegStr HKCU "${ARP}\Unreachable" "DisplayName" "Unreachable first section"
SectionEnd
Section "Later"
  WriteRegStr HKCU "${ARP}\Unreachable" "DisplayName" "Unreachable later section"
SectionEnd
Function .onInstSuccess
  WriteRegStr HKCU "${ARP}\Unreachable" "DisplayName" "Unreachable success callback"
FunctionEnd
Function .onInstFailed
  WriteRegStr HKCU "${ARP}\Failure" "DisplayName" "Failure callback"
FunctionEnd
