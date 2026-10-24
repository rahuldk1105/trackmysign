; Explorer integration, run by the NSIS installer (bundle > windows > nsis >
; installerHooks). Per-user (HKCU) like the install itself. PDFs keep their
; default app: TrackMy Sign is only added to the right-click menu and to
; "Open with".

!define TMS_VERB "Software\Classes\SystemFileAssociations\.pdf\shell\TrackMySign"
!define TMS_PROGID "TrackMySign.pdf"
; The name users see. productName stays TrackMySign: it names the install
; folder, the uninstall key and the shortcuts.
!define TMS_DISPLAYNAME "TrackMy Sign"
; MAINBINARYNAME and PRODUCTNAME are defined after this file is included, so
; they are only used inside the macros.

; Tauri remembers the install folder in HKCU\Software\<publisher>\<productName>
; (MANUPRODUCTKEY). Up to 0.5.0 the publisher was "DK Rahul"; without this an
; update would not find a folder chosen back then, install into the default
; one instead, and run the old uninstaller without a folder. The new key is
; checked against MANUPRODUCTKEY in NSIS_HOOK_PREINSTALL.
!define TMS_OLD_PRODUCTKEY "Software\DK Rahul\TrackMySign"
!define TMS_PRODUCTKEY "Software\TrackMy Tech Private Limited\TrackMySign"

!macro TMS_ADOPT_OLD_INSTALL_FOLDER
  Push $0
  ReadRegStr $0 SHCTX "${TMS_PRODUCTKEY}" ""
  ${If} $0 == ""
    ReadRegStr $0 SHCTX "${TMS_OLD_PRODUCTKEY}" ""
    ${If} $0 != ""
      WriteRegStr SHCTX "${TMS_PRODUCTKEY}" "" $0
      DeleteRegKey SHCTX "${TMS_OLD_PRODUCTKEY}"
      DeleteRegKey /ifempty SHCTX "Software\DK Rahul"
      ; Unless a folder was given with /D=
      ${If} $INSTDIR == "$LOCALAPPDATA\TrackMySign"
        StrCpy $INSTDIR $0
      ${EndIf}
    ${EndIf}
  ${EndIf}
  Pop $0
!macroend

; Runs before the pages, so the "already installed" page already finds the
; folder. Silent installs (/S) skip it; NSIS_HOOK_PREINSTALL covers those.
!define MUI_CUSTOMFUNCTION_GUIINIT TmsGuiInit
Function TmsGuiInit
  !insertmacro TMS_ADOPT_OLD_INSTALL_FOLDER
FunctionEnd

!macro NSIS_HOOK_PREINSTALL
  !if "${TMS_PRODUCTKEY}" != "${MANUPRODUCTKEY}"
    !error "TMS_PRODUCTKEY in hooks.nsh does not match bundle.publisher"
  !endif
  !insertmacro TMS_ADOPT_OLD_INSTALL_FOLDER
  SetOutPath $INSTDIR
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Apps & Features
  WriteRegStr SHCTX "${UNINSTKEY}" "DisplayName" "${TMS_DISPLAYNAME}"

  ; Right-click a PDF -> "Sign with TrackMy Sign"
  WriteRegStr HKCU "${TMS_VERB}" "" "Sign with ${TMS_DISPLAYNAME}"
  WriteRegStr HKCU "${TMS_VERB}" "Icon" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\",0"
  WriteRegStr HKCU "${TMS_VERB}\command" "" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\" $\"%1$\""
  ; Without this the verb is hidden when more than 15 PDFs are selected
  ; (Player: up to 100). Explorer still starts one process per file for a
  ; command verb; the app collects them into one batch.
  WriteRegStr HKCU "${TMS_VERB}" "MultiSelectModel" "Player"

  ; "Open with" list, without touching the .pdf default
  WriteRegStr HKCU "Software\Classes\${TMS_PROGID}" "" "PDF document"
  WriteRegStr HKCU "Software\Classes\${TMS_PROGID}\DefaultIcon" "" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\",0"
  WriteRegStr HKCU "Software\Classes\${TMS_PROGID}\shell\open\command" "" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\" $\"%1$\""
  WriteRegStr HKCU "Software\Classes\${TMS_PROGID}\shell\open" "MultiSelectModel" "Player"
  WriteRegStr HKCU "Software\Classes\.pdf\OpenWithProgids" "${TMS_PROGID}" ""
  WriteRegStr HKCU "Software\Classes\Applications\${MAINBINARYNAME}.exe" "FriendlyAppName" "${TMS_DISPLAYNAME}"
  WriteRegStr HKCU "Software\Classes\Applications\${MAINBINARYNAME}.exe\SupportedTypes" ".pdf" ""
  WriteRegStr HKCU "Software\Classes\Applications\${MAINBINARYNAME}.exe\shell\open\command" "" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\" $\"%1$\""

  ; SHCNE_ASSOCCHANGED: refresh Explorer's menus
  System::Call "shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; An update reinstalls straight away; keep the entries in place.
  ${If} $UpdateMode <> 1
    DeleteRegKey HKCU "${TMS_VERB}"
    DeleteRegValue HKCU "Software\Classes\.pdf\OpenWithProgids" "${TMS_PROGID}"
    DeleteRegKey HKCU "Software\Classes\${TMS_PROGID}"
    DeleteRegKey HKCU "Software\Classes\Applications\${MAINBINARYNAME}.exe"
    ; "Start TrackMy Sign when I sign in" (Settings -> Background)
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCTNAME}"
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "${PRODUCTNAME}"
    System::Call "shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)"
  ${EndIf}
!macroend
