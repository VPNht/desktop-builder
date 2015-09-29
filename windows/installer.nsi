!define REG_KEY "HKLM SOFTWARE\OpenVPN"
var loggedInUser

;Include Modern UI
!include "MUI2.nsh"
!include "x64.nsh"

!searchparse /file "../../package.json" '"name": "' APP_NAME '",'
!searchparse /file "../../package.json" '"version": "' APP_VERSION '",'
!searchreplace APP_VERSION_CLEAN "${APP_VERSION}" "-" ".0"

!addplugindir .
!include "nsProcess.nsh"

!define APP_DIR "${APP_NAME}"

Name "${APP_NAME}"
Caption "${APP_NAME} ${APP_VERSION}"
!include "MUI2.nsh"
!define MUI_ICON "../setup.ico"

SetCompressor /SOLID lzma

# define the resulting installer's name
OutFile "../../dist/${APP_NAME}-${APP_VERSION}-Setup.exe"

# set the installation directory
InstallDir "$PROGRAMFILES\${APP_NAME}/"

# app dialogs
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_RUN_TEXT "Start ${APP_NAME}"
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APP_NAME}.exe"

!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

Function .onInit
    ; Check if we're running on 64-bit Windows
    ${If} ${RunningX64}
        SetRegView 32
    ${EndIf}
FunctionEnd

Function un.onInit
    ${If} ${RunningX64}
        SetRegView 32
    ${EndIf}
FunctionEnd

# default section start
Section
  SetShellVarContext all
  RMDir /r $INSTDIR
  SetOutPath $INSTDIR

  File /r "../../dist\VPN.ht-win32-ia32\*"

  WriteUninstaller "$INSTDIR\Uninstall ${APP_NAME}.exe"

  CreateDirectory "$SMPROGRAMS\${APP_DIR}"
  CreateShortCut "$SMPROGRAMS\${APP_DIR}\${APP_NAME}.lnk" "$INSTDIR\${APP_NAME}.exe"
  CreateShortCut "$SMPROGRAMS\${APP_DIR}\Uninstall ${APP_NAME}.lnk" "$INSTDIR\Uninstall ${APP_NAME}.exe"
  CreateShortCut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\${APP_NAME}.exe"

  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
                   "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
                   "UninstallString" "$INSTDIR\Uninstall ${APP_NAME}.exe"
  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
                   "DisplayIcon" "$INSTDIR\icon.ico"

  ${nsProcess::FindProcess} "openvpn.exe" $R0
  ${If} $R0 == 0
    MessageBox MB_OK|MB_ICONEXCLAMATION "The installation cannot continue as OpenVPN is currently running. Please close all OpenVPN instances and re-run the installer."
	Quit
  ${EndIf}

  DetailPrint "Removing any previous OpenVPN service..."
  nsExec::ExecToLog '"$INSTDIR\resources\bin\openvpnserv.exe" -remove'

  Sleep 3000

  DetailPrint "Installing TAP (may need confirmation)..."
  nsExec::ExecToLog '"$INSTDIR\resources\bin\tap.exe" /S /SELECT_UTILITIES=1'

  Sleep 3000

  DetailPrint "Installing OpenVPN Service..."
  nsExec::ExecToLog '"$INSTDIR\resources\bin\openvpnserv.exe" -install'

  Sleep 3000

  DetailPrint "Settings OpenVPN Service permissions..."
  UserMgr::GetCurrentUserName
  Pop $0
  StrCpy $loggedInUser  "$0"
  nsExec::Exec '"$INSTDIR\resources\bin\subinacl.exe" /service openvpnservice /grant=$loggedInUser=QSTOP'

  Sleep 3000

  DeleteRegValue ${REG_KEY} "config_dir"
  DeleteRegValue ${REG_KEY} "config_ext"
  DeleteRegValue ${REG_KEY} "exe_path"
  DeleteRegValue ${REG_KEY} "log_dir"
  DeleteRegValue ${REG_KEY} "log_append"
  DeleteRegValue ${REG_KEY} "priority"
  WriteRegStr ${REG_KEY} "config_dir" "$INSTDIR\resources\config"
  WriteRegStr ${REG_KEY} "config_ext" "ovpn"
  WriteRegStr ${REG_KEY} "exe_path" "$INSTDIR\resources\bin\openvpn.exe"
  WriteRegStr ${REG_KEY} "log_dir" "$INSTDIR\resources\log"
  WriteRegStr ${REG_KEY} "log_append" "0"
  WriteRegStr ${REG_KEY} "priority" "NORMAL_PRIORITY_CLASS"

  Sleep 3000

  AccessControl::GrantOnFile "$INSTDIR\resources\config" "(S-1-5-32-545)" "FullAccess"
  AccessControl::GrantOnFile "$INSTDIR\resources\log" "(S-1-5-32-545)" "FullAccess"

  Sleep 3000
  DetailPrint "Make sure firewall allow VPN.ht"
  nsisFirewall::AddAuthorizedApplication "$INSTDIR\VPN.ht.exe" "VPN.ht"

SectionEnd

# create a section to define what the uninstaller does
Section "Uninstall"

  SetShellVarContext all

  # delete the installed files
  RMDir /r $INSTDIR

  # delete the shortcuts
  delete "$SMPROGRAMS\${APP_DIR}\${APP_NAME}.lnk"
  delete "$SMPROGRAMS\${APP_DIR}\Uninstall ${APP_NAME}.lnk"
  rmDir  "$SMPROGRAMS\${APP_DIR}"
  delete "$DESKTOP\${APP_NAME}.lnk"

  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"

  nsisFirewall::RemoveAuthorizedApplication "$INSTDIR\VPN.ht.exe"

SectionEnd
