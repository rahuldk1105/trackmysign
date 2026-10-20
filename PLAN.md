# SignDesk — Plan

A lightweight desktop app for signing PDFs with a USB DSC token (Hypersecu HyperPKI HYP2003),
without Adobe.

## Decisions (locked)

| Topic | Decision |
|---|---|
| Platform | Desktop app first (Windows primary, macOS second). Hosted website + helper possibly later. |
| Shell / UI | Tauri (Rust) + React/TypeScript, PDF.js for rendering & placement |
| Token access | PKCS#11 directly (token does **not** appear in Windows cert store) via Hypersecu middleware; OpenSC as fallback |
| Signature appearance | Visible, text only ("Digitally signed by NAME / Date / Reason"), click to place; last position remembered |
| Existing signatures | Must be preserved — incremental-update signing only, top test priority |
| Timestamp / LTV | None; PC clock |
| Batch signing | Not needed |
| Output | Same folder, `<name>_signed.pdf`; original untouched |
| Code signing | macOS: Apple Developer ID + notarization. Windows: unsigned for now (one-time SmartScreen warning) |
| Test PDFs | Generated in-repo, incl. PDFs pre-signed with a dummy cert |

## Architecture

```
┌──────────── SignDesk (Tauri) ────────────┐
│ React UI: open PDF → click to place box  │
│           → choose cert → enter PIN      │
├──────────────────────────────────────────┤
│ Rust core                                │
│  • token: PKCS#11 (cryptoki) — list      │
│    certs, sign hash with private key     │
│  • pdf: incremental-update signer        │
│    (PAdES-B / adbe.pkcs7.detached,       │
│    SHA-256, visible widget appearance)   │
└──────────────────────────────────────────┘
```

PIN is never stored. Remaining PIN attempts shown where the token reports them.

## Phases

1. **Spike** — detect PKCS#11 library on Windows, list certificate from token, sign a test PDF;
   validate in Adobe Reader; confirm a pre-signed PDF's signature stays valid.
   Compare PDF engine: pyHanko sidecar vs native Rust/Go signer; pick the one that passes.
2. **MVP (Windows)** — open/drag-drop PDF, page viewer, click-to-place box, cert picker,
   PIN dialog, save `_signed.pdf`, success/failure messages.
3. **macOS** — build, Developer ID signing, notarization, test with Mac middleware.
4. **Polish** — "Open with SignDesk" file association, remembered settings, signature verification view.
5. **Later (optional)** — website + local helper mode, Windows code signing, open-source release.

## Testing

- CI/dev: SoftHSM2 virtual token with a test certificate; generated PDFs (plain, AcroForm,
  already-signed, xref-stream/compressed).
- Real-world: user runs each build on Windows with the real token and reports results.

## Token environment (confirmed on user's Windows PC)

- Installed: `HyperPKI_HYP2003` 1.1.25.1118 (Feitian ePass2003 rebrand)
- PKCS#11 library (64-bit): `C:\Windows\System32\eps2003csp11v2.dll` — **use this**
- 32-bit copy: `C:\Windows\SysWOW64\eps2003csp11v2.dll` (not used; app is 64-bit)
- Card types registered: `HYP2003v2`, `HYP2003v2_22` (CSP "HyperPKI HYP2003 CSP India v3.0")
- Auto-detect order: System32 `eps2003csp11v2.dll` → OpenSC `opensc-pkcs11.dll` → user-picked path
