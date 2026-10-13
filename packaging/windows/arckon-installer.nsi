; Arckon Agent — per-customer Windows installer (NSIS)
;
; This template is compiled with makensis on the admin server. The SERVER,
; TOKEN, and CUSTOMER_NAME defines are baked in per-customer so the end user
; just double-clicks the resulting .exe and clicks through the wizard — no
; command prompt, no copy-pasting tokens.
;
; Build: makensis /DSERVER="https://..." /DTOKEN="..." /DCUSTOMER_NAME="..." arckon-installer.nsi
;   (the admin app generates the .nsi with these values inlined)

!ifndef SERVER
  !error "SERVER must be defined (e.g. /DSERVER=https://arckon.riskraven.ai)"
!endif
!ifndef TOKEN
  !error "TOKEN must be defined"
!endif
!ifndef CUSTOMER_NAME
  !define CUSTOMER_NAME "Customer"
!endif

Name "Arckon Agent — ${CUSTOMER_NAME}"
OutFile "ArckonAgentSetup.exe"
Unicode true
RequestExecutionLevel admin
ShowInstDetails show
SetCompressor /SOLID lzma
IconFile "arckon.ico"

Page instfiles
UninstPage instfiles

Section "Install Arckon Agent"
  SetOutPath "$TEMP\arckon-install"
  File "install.ps1"

  DetailPrint "Installing Arckon Agent for ${CUSTOMER_NAME}"
  DetailPrint "Server: ${SERVER}"
  DetailPrint ""

  nsExec::ExecToLog 'powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File "$TEMP\arckon-install\install.ps1" -Server "${SERVER}" -Token "${TOKEN}"'
  Pop $0

  DetailPrint ""
  DetailPrint "Installer exited with code: $0"

  ; Clean up the extracted script
  Delete "$TEMP\arckon-install\install.ps1"
  RMDir "$TEMP\arckon-install"

  ${If} $0 == 0
    MessageBox MB_OK "Arckon Agent installed successfully.$\r$\n$\r$\nThe service is running in the background."
  ${Else}
    MessageBox MB_OK|MB_ICONSTOP "Installation failed (exit code $0).$\r$\n$\r$\nPlease contact your IT administrator or RiskRaven support."
    SetErrorLevel $0
  ${EndIf}
SectionEnd