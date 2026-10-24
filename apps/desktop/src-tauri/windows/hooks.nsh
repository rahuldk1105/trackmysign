; Explorer integration, run by the NSIS installer (bundle > windows > nsis >
; installerHooks). Per-user (HKCU) like the install itself. PDFs keep their
; default app: TrackMySign is only added to the right-click menu and to
; "Open with".

!define TMS_VERB "Software\Classes\SystemFileAssociations\.pdf\shell\TrackMySign"
!define TMS_PROGID "TrackMySign.pdf"
; MAINBINARYNAME and PRODUCTNAME are defined after this file is included, so
; they are only used inside the macros.

!macro NSIS_HOOK_POSTINSTALL
  ; Right-click a PDF -> "Sign with TrackMySign"
  WriteRegStr HKCU "${TMS_VERB}" "" "Sign with TrackMySign"
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
  WriteRegStr HKCU "Software\Classes\Applications\${MAINBINARYNAME}.exe" "FriendlyAppName" "${PRODUCTNAME}"
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
    ; "Start TrackMySign when I sign in" (Settings -> Background)
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCTNAME}"
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "${PRODUCTNAME}"
    System::Call "shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)"
  ${EndIf}
!macroend
