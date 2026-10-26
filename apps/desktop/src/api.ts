// Typed wrappers over the Rust commands. Outside Tauri (plain browser, for UI
// development) a mock backend is used so the screens can be exercised.

import { Channel, invoke } from "@tauri-apps/api/core";
import { t } from "./i18n";
import type { PresetPlacement } from "./presets";
import type { Drawing, StampContent, StampStyle } from "./stamp";

export interface Cert {
  /** SHA-256 fingerprint of the certificate. */
  id: string;
  name: string;
  organization: string | null;
  issuer: string;
  validFrom: string;
  validUntil: string;
  expired: boolean;
  /** Whole days until it expires; negative once expired. */
  daysLeft: number;
  /** Whole days until it becomes valid, when it is not yet (or the PC clock is wrong). */
  startsIn: number | null;
  canSign: boolean;
  tokenLabel: string;
  /** Product name of the PKCS#11 driver the certificate was read through. */
  driver: string;
  driverPath: string;
}

/** A certificate seen on a token before, remembered for the expiry reminder. */
export interface KnownCert {
  id: string;
  name: string;
  issuer: string;
  validUntil: string;
  daysLeft: number;
}

export interface Driver {
  name: string;
  path: string;
}

export interface PdfInfo {
  path: string;
  name: string;
  pages: { width: number; height: number }[];
  signatures: number;
  /** Password-protected (possibly with an empty open password). */
  encrypted: boolean;
  /** The PDF's security settings, or the password given, allow signing. */
  signingAllowed: boolean;
  /** DocMDP level when the document is certified. */
  certified: CertifyLevel | null;
  emptyFields: EmptyField[];
}

/** What a certification allows afterwards: 1 no changes, 2 form filling and signing, 3 also comments. */
export type CertifyLevel = 1 | 2 | 3;

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** A signature field in the PDF that has not been signed yet. */
export interface EmptyField {
  /** Fully qualified name, e.g. `approvals.director`. */
  name: string;
  /** Zero-based page, or null when no page shows it. */
  page: number | null;
  /** Points from the top-left of the displayed page; null when invisible. */
  rect: Rect | null;
  /** Tooltip, often who is to sign it. */
  tooltip: string | null;
  /** Place in the intended signing order, from 1. */
  order: number | null;
}

/** What signing a new field locks: every field, or the ones named. */
export type FieldLockArg = { kind: "all" } | { kind: "fields"; fields: string[] };

/** An empty signature field to add for someone else to sign. */
export interface NewFieldArg {
  name: string;
  page: number;
  /** Points from the top-left of the displayed page. */
  rect: Rect;
  tooltip: string | null;
  /** Place in the signing order, from 1; null when the order does not matter. */
  order: number | null;
  lock: FieldLockArg | null;
  /** Ask for adbe.pkcs7.detached with SHA-256 (seed values). */
  seed: boolean;
}

/** Whether the handwritten signature image is shown, and where. */
export type ImageChoice = "off" | "left" | "above";

export interface SignArgs {
  path: string;
  page: number;
  rect: Rect | null;
  /** Zero-based pages that get the box; empty for just `page`. */
  pages: number[];
  reason: string;
  location: string;
  certId: string;
  driverPath: string;
  pin: string;
  /** RFC 3161 server, or null for no timestamp. */
  timestamp: string | null;
  ltv: boolean;
  image?: Exclude<ImageChoice, "off"> | null;
  /** How the box looks; null for the standard box. Shows the saved seal when it has `seal`. */
  style?: StampStyle | null;
  /** Sign into this empty signature field; `page`, `rect` and `pages` are then unused. */
  field?: string | null;
  /** Password the PDF was opened with; kept in memory only. */
  password?: string | null;
  /** Certify instead of approving. */
  certify?: CertifyLevel | null;
  /** Folder for the signed copy; next to the original when null. */
  outDir?: string | null;
  /** Empty signature fields to add first; `field` is one of them. */
  newFields?: NewFieldArg[];
}

/** Several PDFs, one PIN entry. The box goes on the same page and spot of each. */
export interface BatchArgs extends Omit<SignArgs, "path" | "page" | "field"> {
  paths: string[];
  /** "first", "last" or a page number (1 = first). */
  page: "first" | "last" | number;
  /** Box on every page of each file (otherwise on `pages` that a file has). */
  allPages: boolean;
}

export type BatchProgress =
  | { state: "signing"; index: number }
  | { state: "done"; index: number; output: string; name: string }
  | { state: "failed"; index: number; message: string };

/** A recently opened PDF; kept in the app's data folder, without any content. */
export interface RecentFile {
  path: string;
  name: string;
  /** Unix seconds. */
  opened: number;
  pages: number | null;
  /** Where the signed copy went, when it was signed here. */
  signed: string | null;
}

export interface Signed {
  output: string;
  name: string;
}

/** PIN attempts as the token reports them (not every token does). */
export interface PinStatus {
  countLow: boolean;
  finalTry: boolean;
  locked: boolean;
}

export interface ApiError {
  kind: "wrongPin" | "pinLocked" | "token" | "pdf" | "password" | "permission" | "io" | "timestamp" | "ltv" | "expired" | "other";
  message: string;
}

export const inTauri = "__TAURI_INTERNALS__" in window;

export function errorOf(e: unknown): ApiError {
  if (e && typeof e === "object" && "message" in e) return e as ApiError;
  return { kind: "other", message: String(e) };
}

const mock = {
  pin: "1234",
  async listCertificates(): Promise<Cert[]> {
    return [
      {
        id: "mock",
        name: "DK RAHUL",
        organization: "Personal",
        issuer: "Verasys Sub CA 2022",
        validFrom: "12 Dec 2024",
        validUntil: "11 Dec 2026",
        expired: false,
        daysLeft: 49,
        startsIn: null,
        canSign: true,
        tokenLabel: "HYP2003",
        driver: "Hypersecu HyperPKI",
        driverPath: "C:\\Windows\\System32\\eps2003csp11v2.dll",
      },
    ];
  },
  async readPdf(): Promise<ArrayBuffer> {
    return (await fetch("/sample.pdf")).arrayBuffer();
  },
  async sign(a: SignArgs): Promise<Signed> {
    await new Promise((r) => setTimeout(r, 900));
    if (a.pin !== mock.pin) throw { kind: "wrongPin", message: "Wrong PIN. Careful: few attempts left before the token locks." };
    return { output: a.path.replace(/\.pdf$/i, "_signed.pdf"), name: "sample_signed.pdf" };
  },
  async signBatch(a: BatchArgs, progress: (p: BatchProgress) => void): Promise<void> {
    await new Promise((r) => setTimeout(r, 600));
    if (a.pin !== mock.pin) throw { kind: "wrongPin", message: "Wrong PIN. Careful: few attempts left before the token locks." };
    for (const [index, path] of a.paths.entries()) {
      progress({ state: "signing", index });
      await new Promise((r) => setTimeout(r, 500));
      const name = (path.split(/[\\/]/).pop() ?? path).replace(/\.pdf$/i, "_signed.pdf");
      progress({ state: "done", index, output: path.replace(/\.pdf$/i, "_signed.pdf"), name });
    }
  },
};

export async function listCertificates(): Promise<Cert[]> {
  return inTauri ? invoke("list_certificates") : mock.listCertificates();
}

export async function knownCertificates(): Promise<KnownCert[]> {
  return inTauri ? invoke("known_certificates") : [];
}

/** `password` unlocks a protected PDF (open or owner password). */
export async function pdfInfo(path: string, password?: string): Promise<PdfInfo> {
  if (inTauri) return invoke("pdf_info", { path, password: password ?? null });
  return {
    path,
    name: path.split(/[\\/]/).pop() ?? path,
    pages: [],
    signatures: 1,
    certified: 2,
    encrypted: false,
    signingAllowed: true,
    emptyFields: [
      { name: "Director", page: 0, rect: { x: 340, y: 700, w: 200, h: 60 }, tooltip: "Director — Rahul Dhileep Kumar", order: 2 },
      { name: "approvals.cfo", page: 0, rect: { x: 60, y: 700, w: 200, h: 60 }, tooltip: null, order: 1 },
    ],
  };
}

export async function readPdf(path: string): Promise<ArrayBuffer> {
  return inTauri ? invoke("read_pdf", { path }) : mock.readPdf();
}

export async function sign(args: SignArgs): Promise<Signed> {
  return inTauri ? invoke("sign", { args }) : mock.sign(args);
}

export async function pinStatus(certId: string, driverPath: string): Promise<PinStatus> {
  if (inTauri) return invoke("pin_status", { certId, driverPath });
  return { countLow: false, finalTry: false, locked: false };
}

/** An OID, with its meaning when known. */
export interface NamedOid {
  oid: string;
  name: string | null;
}

/** Everything about a certificate on the token (public data only). */
export interface CertDetails {
  name: string;
  organization: string | null;
  /** Subject serialNumber attribute; Indian DSCs put a hash of the PAN here. */
  subjectSerial: string | null;
  email: string | null;
  /** Full distinguished names. */
  subject: string;
  issuer: string;
  issuerName: string;
  /** Hex. */
  serial: string;
  validFrom: string;
  validUntil: string;
  daysLeft: number;
  /** "RSA 2048", "EC P-256". */
  key: string;
  /** Null when the certificate does not restrict its key's use. */
  keyUsage: string[] | null;
  extendedKeyUsage: NamedOid[];
  policies: NamedOid[];
  sha1: string;
  sha256: string;
  /** Issuers, nearest first. */
  chain: { name: string; issuer: string; validUntil: string; builtIn: boolean }[];
}

/** DER `.cer`, PEM `.pem`, or the certificate with its issuers as a `.p7b`. */
export type ExportFormat = "der" | "pem" | "chain";

export async function certificateDetails(certId: string, driverPath: string): Promise<CertDetails> {
  if (inTauri) return invoke("certificate_details", { certId, driverPath });
  return {
    name: "DK RAHUL",
    organization: "Personal",
    subjectSerial: "6442fd73a940c1186d6268bd27f89233e12429902c7805037e8aab6e717be6d9",
    email: "rahul@example.com",
    subject: "CN=DK RAHUL,O=Personal,C=IN",
    issuer: "CN=Verasys Sub CA 2022,C=IN",
    issuerName: "Verasys Sub CA 2022",
    serial: "1B30D7FA4A072C4F",
    validFrom: "12 Dec 2024 10:15 UTC",
    validUntil: "11 Dec 2026 10:15 UTC",
    daysLeft: 49,
    key: "RSA 2048",
    keyUsage: ["Digital signature", "Non-repudiation"],
    extendedKeyUsage: [{ oid: "1.3.6.1.4.1.311.10.3.12", name: "Document signing (Microsoft)" }],
    policies: [{ oid: "2.16.356.100.2.3", name: "Class 3" }],
    sha1: "6B:68:01:6C:01:12:98:3B:8B:8D:62:5A:DE:EE:D3:F6:DD:18:79:C9",
    sha256: "5A:CA:DF:19:C4:04:D1:38:06:B6:C2:8E:6A:0C:AF:4B:74:65:89:59:0C:21:E6:01:4A:6C:65:08:7E:30:DF:FB",
    chain: [
      { name: "Verasys Sub CA 2022", issuer: "Verasys CA 2022", validUntil: "01 Feb 2032", builtIn: false },
      { name: "Verasys CA 2022", issuer: "CCA India 2022", validUntil: "01 Feb 2032", builtIn: false },
      { name: "CCA India 2022", issuer: "CCA India 2022", validUntil: "02 Feb 2042", builtIn: true },
    ],
  };
}

/** Asks where to save the public certificate and saves it there; null when cancelled. */
export async function exportCertificate(certId: string, driverPath: string, format: ExportFormat): Promise<string | null> {
  if (inTauri) return invoke("export_certificate", { certId, driverPath, format });
  return `C:\\Users\\rahul\\Downloads\\DK_RAHUL_DSC.${{ der: "cer", pem: "pem", chain: "p7b" }[format]}`;
}

/** PDFs the app was started with (command line, Finder, "Sign with TrackMy Sign"). */
/** Signs every file in one token session; per-file results arrive through `progress`. */
export async function signBatch(args: BatchArgs, progress: (p: BatchProgress) => void): Promise<void> {
  if (!inTauri) return mock.signBatch(args, progress);
  const channel = new Channel<BatchProgress>();
  channel.onmessage = progress;
  await invoke("sign_batch", { args, progress: channel });
}

/** Files handed over by the system together: PDFs, and others to sign as `.p7s` / `.p7m`. */
export interface Handed {
  files: string[];
  others: string[];
}

export async function startupFiles(): Promise<Handed> {
  return inTauri ? invoke("startup_files") : { files: [], others: [] };
}

/** Files handed over while the app is running (Finder, a second launch); a
 * selection opened in one go arrives as one call. */
export async function onOpenFiles(cb: (handed: Handed) => void): Promise<() => void> {
  if (!inTauri) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  return listen<Handed>("open-files", (e) => cb(e.payload));
}

/** Object URL of the saved signature image, or null when none is set. */
export async function signatureImage(): Promise<string | null> {
  if (!inTauri) return null;
  const bytes: ArrayBuffer = await invoke("signature_image");
  return bytes.byteLength ? URL.createObjectURL(new Blob([bytes])) : null;
}

/** Copies a PNG or JPEG into the app's data folder (after checking it). */
export async function setSignatureImage(path: string): Promise<void> {
  if (inTauri) await invoke("set_signature_image", { path });
}

export async function clearSignatureImage(): Promise<void> {
  if (inTauri) await invoke("clear_signature_image");
}

/** A picture kept in the app's data folder. */
export type Picture = "signature" | "seal";

/** Object URL of a saved picture, or null when there is none. */
export async function picture(which: Picture): Promise<string | null> {
  if (!inTauri) return null;
  const bytes: ArrayBuffer = await invoke("picture", { which });
  return bytes.byteLength ? URL.createObjectURL(new Blob([bytes])) : null;
}

/** Copies a PNG or JPEG into the app's data folder (after checking it). */
export async function setPicture(which: Picture, path: string): Promise<void> {
  if (inTauri) await invoke("set_picture", { which, path });
}

export async function clearPicture(which: Picture): Promise<void> {
  if (inTauri) await invoke("clear_picture", { which });
}

/** The box laid out by the signing engine; null outside the app. */
export async function stampPreview(args: StampContent & { w: number; h: number }): Promise<Drawing | null> {
  return inTauri ? invoke("stamp_preview", { args }) : null;
}

/** Typed text as the box prints it (Indian scripts transliterated). */
export async function stampText(text: string): Promise<string> {
  return inTauri ? invoke("stamp_text", { text }) : text;
}

export async function pickImage(): Promise<string | null> {
  if (!inTauri) return null;
  const { open } = await import("@tauri-apps/plugin-dialog");
  const r = await open({ multiple: false, filters: [{ name: t("dialog.images"), extensions: ["png", "jpg", "jpeg"] }] });
  return typeof r === "string" ? r : null;
}

export async function openFile(path: string): Promise<void> {
  if (inTauri) await invoke("open_file", { path });
}

export async function revealFile(path: string): Promise<void> {
  if (inTauri) await invoke("reveal_file", { path });
}

/** PKCS#11 drivers installed on this computer, preferred first. */
export async function tokenDrivers(): Promise<Driver[]> {
  if (inTauri) return invoke("token_drivers");
  return [
    { name: "Hypersecu HyperPKI", path: "C:\\Windows\\System32\\eps2003csp11v2.dll" },
    { name: "OpenSC", path: "C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll" },
  ];
}

export async function openWebsite(): Promise<void> {
  if (inTauri) await invoke("open_website");
  else window.open("https://sign.rahuldk.in", "_blank");
}

/** One or more PDFs; several are signed as a batch. The dialog starts in `folder`. */
export async function pickPdfs(folder?: string | null): Promise<string[]> {
  if (!inTauri) return ["C:\\Users\\rahul\\Downloads\\sample.pdf"];
  const { open } = await import("@tauri-apps/plugin-dialog");
  const r = await open({ multiple: true, defaultPath: folder ?? undefined, filters: [{ name: t("dialog.pdfs"), extensions: ["pdf"] }] });
  return r ?? [];
}

export async function pickFolder(folder?: string | null): Promise<string | null> {
  if (!inTauri) return "C:\\Users\\rahul\\Documents\\Signed";
  const { open } = await import("@tauri-apps/plugin-dialog");
  const r = await open({ directory: true, multiple: false, defaultPath: folder ?? undefined });
  return typeof r === "string" ? r : null;
}

const mockRecent: RecentFile[] = [
  {
    path: "C:\\Users\\rahul\\Downloads\\sample.pdf",
    name: "sample.pdf",
    opened: Date.now() / 1000 - 3600,
    pages: 2,
    signed: "C:\\Users\\rahul\\Downloads\\sample_signed.pdf",
  },
  { path: "C:\\Users\\rahul\\Documents\\Invoices\\INV-2026-0142.pdf", name: "INV-2026-0142.pdf", opened: Date.now() / 1000 - 3 * 86400, pages: 1, signed: null },
];

/** Recently opened PDFs that still exist, most recent first. */
export async function recentFiles(): Promise<RecentFile[]> {
  return inTauri ? invoke("recent_files") : mockRecent;
}

export async function recentAdd(path: string, pages: number): Promise<RecentFile[]> {
  return inTauri ? invoke("recent_add", { path, pages }) : mockRecent;
}

/** `path` was signed into `output`. */
export async function recentSigned(path: string, output: string): Promise<RecentFile[]> {
  return inTauri ? invoke("recent_signed", { path, output }) : mockRecent;
}

export async function recentClear(): Promise<void> {
  if (inTauri) await invoke("recent_clear");
}

export async function onFileDrop(cb: (paths: string[]) => void, hover: (on: boolean) => void): Promise<() => void> {
  if (!inTauri) return () => {};
  const { getCurrentWebview } = await import("@tauri-apps/api/webview");
  return getCurrentWebview().onDragDropEvent((e) => {
    const p = e.payload;
    if (p.type === "enter" || p.type === "over") hover(true);
    else if (p.type === "leave") hover(false);
    else if (p.type === "drop") {
      hover(false);
      if (p.paths.length) cb(p.paths);
    }
  });
}

export interface SignatureCheck {
  field: string;
  status: "valid" | "invalid" | "unknown";
  /** Why the status is not valid comes first; then other warnings. */
  notes: string[];
  signer: string | null;
  organization: string | null;
  issuer: string | null;
  certValidFrom: string | null;
  certValidUntil: string | null;
  signingTime: string | null;
  timeInValidity: boolean | null;
  timestamped: boolean;
  reason: string | null;
  location: string | null;
  subFilter: string | null;
  digest: string | null;
  /** What later incremental updates changed. */
  changes: "none" | "signatures" | "form" | "content" | "unknown";
  laterRevisions: number;
  bytesAfter: number;
  chain: string[];
  trust: "cca" | "notChecked";
  /** Set for a certification signature. */
  certification: CertifyLevel | null;
}

export async function verifyPdf(path: string, password?: string): Promise<SignatureCheck[]> {
  if (inTauri) return invoke("verify_pdf", { path, password: password ?? null });
  return [
    {
      field: "AuditorSignature",
      status: "valid",
      notes: [],
      signer: "CA AUDITOR PARTNER",
      organization: null,
      issuer: "Verasys Sub CA 2022",
      certValidFrom: "01 Apr 2025",
      certValidUntil: "31 Mar 2027",
      signingTime: "2026.10.20 14:32:10 +05:30",
      timeInValidity: true,
      timestamped: false,
      reason: "Audited",
      location: "Chennai",
      subFilter: "adbe.pkcs7.detached",
      digest: "SHA-256",
      changes: "signatures",
      laterRevisions: 1,
      bytesAfter: 11785,
      chain: ["CA AUDITOR PARTNER", "Verasys Sub CA 2022", "Verasys CA 2022", "CCA India 2022"],
      trust: "cca",
      certification: 2,
    },
  ];
}

// ------------------------------------------------------- other files

/** A signature over a file that is not a PDF (`.p7s` / `.p7m`), checked. */
export interface FileSignatureCheck extends SignatureCheck {
  /** The file is inside the signature (`.p7m`). */
  attached: boolean;
}

export interface FileInfo {
  path: string;
  name: string;
  size: number;
  /** "file": to sign; "signature": a `.p7s` / `.p7m` to check. */
  kind: "file" | "signature";
  /** Of the file; for a signature, of the content it signs, when known. */
  sha256: string | null;
  /** The signature that was checked: next to the file, or the file itself. */
  signaturePath: string | null;
  check: FileSignatureCheck | null;
  /** Why the signature could not be read. */
  error: string | null;
  /** For a signature: the signed file found next to it. */
  signedPath: string | null;
  hasP7s: boolean;
  hasP7m: boolean;
}

export interface FileSignArgs {
  paths: string[];
  attached: boolean;
  certId: string;
  driverPath: string;
  pin: string;
  timestamp: string | null;
}

export function isSignatureFile(path: string): boolean {
  return /\.p7[sm]$/i.test(path);
}

export async function fileInfo(path: string): Promise<FileInfo> {
  if (inTauri) return invoke("file_info", { path });
  const name = path.split(/[\\/]/).pop() ?? path;
  return {
    path,
    name,
    size: 48213,
    kind: isSignatureFile(path) ? "signature" : "file",
    sha256: "4C317A2D079D518858F1B3B72EE16EB88A7D82898B7CC3DE7F144098BA0A4EF4",
    signaturePath: null,
    check: null,
    error: null,
    signedPath: null,
    hasP7s: false,
    hasP7m: false,
  };
}

/** Signs every file in one token session, writing `<file>.p7s` (or `.p7m`) next to it. */
export async function signFiles(args: FileSignArgs, progress: (p: BatchProgress) => void): Promise<void> {
  if (!inTauri) {
    args.paths.forEach((path, index) => progress({ state: "done", index, output: `${path}.${args.attached ? "p7m" : "p7s"}`, name: "" }));
    return;
  }
  const channel = new Channel<BatchProgress>();
  channel.onmessage = progress;
  await invoke("sign_files", { args, progress: channel });
}

/** Any files, for signing or checking. */
export async function pickAnyFiles(folder?: string | null): Promise<string[]> {
  if (!inTauri) return ["C:\\Users\\rahul\\Downloads\\tender-bid.docx"];
  const { open } = await import("@tauri-apps/plugin-dialog");
  const r = await open({ multiple: true, defaultPath: folder ?? undefined });
  return r ?? [];
}

/** Asks where to save the file inside a `.p7m`; null when cancelled. */
export async function pickOriginalPath(p7m: string): Promise<string | null> {
  const suggested = inTauri ? await invoke<string>("original_path", { path: p7m }) : p7m.replace(/\.p7m$/i, "");
  if (!inTauri) return suggested;
  const { save } = await import("@tauri-apps/plugin-dialog");
  return save({ defaultPath: suggested });
}

/** Writes the file inside the `.p7m` at `path` to `output`. */
export async function extractSigned(path: string, output: string): Promise<void> {
  if (inTauri) await invoke("extract_signed", { path, output });
}

// ------------------------------------------------------- GST portal signing

/** `invoice.pdf` → `invoice_verification.pdf`, next to it. */
export function reportPath(path: string): string {
  return path.replace(/\.pdf$/i, "") + "_verification.pdf";
}

/** Asks where to save the verification report; null when cancelled. */
export async function pickReportPath(path: string): Promise<string | null> {
  if (!inTauri) return reportPath(path);
  const { save } = await import("@tauri-apps/plugin-dialog");
  return save({ defaultPath: reportPath(path), filters: [{ name: t("dialog.pdfs"), extensions: ["pdf"] }] });
}

/** Checks the signatures again and writes the report (PDF) to `output`. */
export async function exportReport(path: string, output: string, password?: string): Promise<void> {
  if (inTauri) await invoke("export_report", { path, password: password ?? null, output });
}

// ------------------------------------------------------------ page tools

/** What a source PDF loses in a new file made from its pages. */
export type PageNotice =
  | { kind: "signaturesRemoved"; source: number; count: number }
  | { kind: "passwordRemoved"; source: number }
  | { kind: "bookmarksDropped"; source: number }
  | { kind: "fieldRenamed"; from: string; to: string };

/** One page of the new file: a page of a source, turned clockwise by `rotate`, or an empty one. */
export type PageItem = { kind: "page"; source: number; page: number; rotate: number } | { kind: "blank"; width: number; height: number };

/** Checks that a PDF can give its pages (password, permissions) and what it would lose. */
export async function pagesSource(path: string, password?: string): Promise<PageNotice[]> {
  if (inTauri) return invoke("pages_source", { path, password: password ?? null });
  return [{ kind: "signaturesRemoved", source: 0, count: 1 }];
}

/** `contract.pdf` → `contract_prepared.pdf`, next to it. */
export function preparedPath(path: string): string {
  return path.replace(/\.pdf$/i, "") + "_prepared.pdf";
}

/** Asks where to save the new PDF; null when cancelled. */
export async function pickPreparedPath(path: string): Promise<string | null> {
  if (!inTauri) return preparedPath(path);
  const { save } = await import("@tauri-apps/plugin-dialog");
  return save({ defaultPath: preparedPath(path), filters: [{ name: t("dialog.pdfs"), extensions: ["pdf"] }] });
}

/** Writes a new PDF made of `items` to `output`; the sources are only read. */
export async function assemblePages(sources: { path: string; password: string | null }[], items: PageItem[], output: string): Promise<PageNotice[]> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 400));
    return [];
  }
  const r: { output: string; notices: PageNotice[] } = await invoke("assemble_pages", { args: { sources, items, output } });
  return r.notices;
}

// ------------------------------------------------------ signature fields

/** `contract.pdf` → `contract_fields.pdf`, next to it. */
export function fieldsPath(path: string): string {
  return path.replace(/\.pdf$/i, "") + "_fields.pdf";
}

/** Asks where to save the PDF with the new fields; null when cancelled. */
export async function pickFieldsPath(path: string): Promise<string | null> {
  if (!inTauri) return fieldsPath(path);
  const { save } = await import("@tauri-apps/plugin-dialog");
  return save({ defaultPath: fieldsPath(path), filters: [{ name: t("dialog.pdfs"), extensions: ["pdf"] }] });
}

/** Writes the PDF with `fields` added to `output`; the original is only read. */
export async function addSignatureFields(path: string, password: string | null, fields: NewFieldArg[], output: string): Promise<string> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 400));
    return output;
  }
  return invoke("add_fields", { args: { path, password, fields, output } });
}

// ---------------------------------------------------------- folder check

export type FolderStatus = "allValid" | "invalid" | "changed" | "unsigned" | "unreadable" | "password";

/** One PDF of a folder check. */
export interface FolderFile {
  path: string;
  /** Relative to the folder, with `/` between folder names. */
  relative: string;
  size: number | null;
  status: FolderStatus;
  signatures: number;
  signers: string[];
  /** Why the file could not be checked. */
  error: string | null;
  summary: string | null;
  /** Opened only with the password given for the folder. */
  usedPassword: boolean;
}

export type FolderProgress = { state: "found"; files: string[] } | { state: "checked"; index: number; file: FolderFile };

const mockFolder: [string, FolderStatus, string[]][] = [
  ["INV-2026-0142.pdf", "allValid", ["DK RAHUL"]],
  ["INV-2026-0143.pdf", "allValid", ["DK RAHUL", "CA AUDITOR PARTNER"]],
  ["INV-2026-0144.pdf", "changed", ["DK RAHUL"]],
  ["Board/minutes-oct.pdf", "invalid", ["DIRECTOR TWO"]],
  ["Board/agenda.pdf", "unsigned", []],
  ["Board/salary.pdf", "password", []],
  ["scan.pdf", "unreadable", []],
];

/** Checks every PDF in `folder` (results through `progress`); true when stopped early. */
export async function verifyFolder(folder: string, recursive: boolean, password: string, progress: (p: FolderProgress) => void): Promise<boolean> {
  if (inTauri) {
    const channel = new Channel<FolderProgress>();
    channel.onmessage = progress;
    return invoke("verify_folder", { folder, recursive, password: password || null, progress: channel });
  }
  const files = mockFolder.filter(([p]) => recursive || !p.includes("/"));
  progress({ state: "found", files: files.map(([p]) => p) });
  for (const [index, [relative, status, signers]] of files.entries()) {
    await new Promise((r) => setTimeout(r, 300));
    const error = status === "password" ? "this PDF is password-protected; enter its password to open it" : status === "unreadable" ? "not a PDF file" : null;
    progress({
      state: "checked",
      index,
      file: { path: `${folder}\\${relative}`, relative, size: 48213, status, signatures: signers.length, signers, error, summary: null, usedPassword: false },
    });
  }
  return false;
}

export async function stopFolderVerify(): Promise<void> {
  if (inTauri) await invoke("stop_folder_verify");
}

/** `C:\Invoices` → `C:\Invoices_verification.pdf` (next to the folder, not inside it). */
export function folderReportPath(folder: string, ext: "pdf" | "csv"): string {
  return folder.replace(/[\\/]+$/, "") + `_verification.${ext}`;
}

/** Asks where to save the folder report or CSV; null when cancelled. */
export async function pickFolderExport(folder: string, ext: "pdf" | "csv"): Promise<string | null> {
  if (!inTauri) return folderReportPath(folder, ext);
  const { save } = await import("@tauri-apps/plugin-dialog");
  const filter = ext === "pdf" ? { name: t("dialog.pdfs"), extensions: ["pdf"] } : { name: t("dialog.csv"), extensions: ["csv"] };
  return save({ defaultPath: folderReportPath(folder, ext), filters: [filter] });
}

/** Writes the last folder check to `output`: the PDF report or the CSV. */
export async function exportFolder(output: string, ext: "pdf" | "csv"): Promise<void> {
  if (inTauri) await invoke(ext === "pdf" ? "export_folder_report" : "export_folder_csv", { output });
}

export interface PortalStatus {
  /** Turned on in Settings (the listener runs while the app is open). */
  enabled: boolean;
  /** Port the listener answers on, when running. */
  port: number | null;
  /** Ports before `port` that another program (emSigner) uses. */
  taken: number[];
  /** emSigner version reported to the portal. */
  version: string;
  defaultVersion: string;
  /** Why it is not running although turned on. */
  error: string | null;
  /** Turned off, but the certificate is still in the trust store. */
  certificateLeft: boolean;
  validUntil: string | null;
  /** Recent activity, oldest first. */
  log: string[];
}

/** A signature the GST portal asked for, waiting for the user. */
export interface PortalRequest {
  id: number;
  /** Site that asked, e.g. `https://services.gst.gov.in`. */
  origin: string;
  pan: string;
  /** Exactly what will be signed. */
  toBeSigned: string;
  /** "registration": the PAN itself; "digest": a hash of a return or form. */
  kind: "registration" | "digest" | "text";
  expiryCheck: boolean;
}

export interface PortalCert extends Cert {
  /** The certificate names the requested PAN. */
  matchesPan: boolean;
}

const portalOff: PortalStatus = {
  enabled: false,
  port: null,
  taken: [],
  version: "2.8",
  defaultVersion: "2.8",
  error: null,
  certificateLeft: false,
  validUntil: null,
  log: [],
};

export async function portalStatus(): Promise<PortalStatus> {
  return inTauri ? invoke("portal_status") : portalOff;
}

/** Makes the certificate and adds it to the trust store; the system asks the user. */
export async function portalEnable(): Promise<PortalStatus> {
  if (inTauri) return invoke("portal_enable");
  return { ...portalOff, enabled: true, port: 1585, validUntil: "22 Jan 2029", log: ["10:00:00 listening on 127.0.0.1:1585"] };
}

/** Stops listening and removes the certificate from the trust store. */
export async function portalDisable(): Promise<PortalStatus> {
  return inTauri ? invoke("portal_disable") : portalOff;
}

export async function portalSetVersion(version: string): Promise<PortalStatus> {
  return inTauri ? invoke("portal_set_version", { version }) : { ...portalOff, enabled: true, port: 1585, version };
}

export async function portalPending(): Promise<PortalRequest | null> {
  return inTauri ? invoke("portal_pending") : null;
}

export async function portalCertificates(pan: string): Promise<PortalCert[]> {
  if (inTauri) return invoke("portal_certificates", { pan });
  return (await mock.listCertificates()).map((c) => ({ ...c, matchesPan: true }));
}

export async function portalSign(id: number, certId: string, driverPath: string, pin: string): Promise<void> {
  if (inTauri) return invoke("portal_sign", { args: { id, certId, driverPath, pin } });
  await new Promise((r) => setTimeout(r, 700));
  if (pin !== mock.pin) throw { kind: "wrongPin", message: "Wrong PIN. Careful: few attempts left before the token locks." };
}

export async function portalCancel(id: number): Promise<void> {
  if (inTauri) await invoke("portal_cancel", { id });
}

/** A new request from the portal page. */
export async function onPortalRequest(cb: (r: PortalRequest) => void): Promise<() => void> {
  if (!inTauri) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  return listen<PortalRequest>("portal-request", (e) => cb(e.payload));
}

/** The request was answered, or the page stopped waiting (closed, timed out). */
export async function onPortalClosed(cb: (id: number) => void): Promise<() => void> {
  if (!inTauri) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  return listen<number>("portal-closed", (e) => cb(e.payload));
}

// ------------------------------------------------------- Background

export interface BackgroundStatus {
  /** Closing the window keeps the app in the tray (menu bar). */
  enabled: boolean;
  /** Starts at sign-in, in the tray. */
  autostart: boolean;
}

let mockBackground: BackgroundStatus = { enabled: false, autostart: false };

export async function backgroundStatus(): Promise<BackgroundStatus> {
  return inTauri ? invoke("background_status") : mockBackground;
}

/** Turning it off also removes the start at sign-in. */
export async function backgroundSet(enabled: boolean): Promise<BackgroundStatus> {
  if (inTauri) return invoke("background_set", { enabled });
  mockBackground = { enabled, autostart: enabled && mockBackground.autostart };
  return mockBackground;
}

export async function backgroundSetAutostart(enabled: boolean): Promise<BackgroundStatus> {
  if (inTauri) return invoke("background_set_autostart", { enabled });
  mockBackground = { ...mockBackground, autostart: enabled };
  return mockBackground;
}

// ------------------------------------------------------- Watch folder

/** How each file of a watch folder is signed: a copy of a saved preset (src-tauri/src/watch.rs). */
export interface WatchPreset {
  name: string;
  reason: string;
  location: string;
  /** Millimetres from the top-left; bottom-right of the last page when null. */
  placement: PresetPlacement | null;
  /** More pages with the box: "all" or e.g. "1-3,5"; empty for one page. */
  pages: string;
  image: ImageChoice;
  invisible: boolean;
  /** Null for the standard box. */
  style: StampStyle | null;
  /** RFC 3161 server, or null for none. */
  timestamp: string | null;
  ltv: boolean;
}

export interface WatchConfig {
  input: string;
  /** Empty for `<input>/signed`. */
  output: string;
  /** Move originals to `<input>/done` once signed. */
  moveDone: boolean;
  /** 0 for no limit. */
  dailyLimit: number;
  /** Session length; 0 until stopped. */
  minutes: number;
  stopOnSleep: boolean;
  preset: WatchPreset;
}

export interface WatchLogEntry {
  /** Unix seconds. */
  time: number;
  kind: "started" | "stopped" | "signed" | "failed" | "skipped";
  file: string | null;
  output: string | null;
  message: string | null;
}

export interface WatchStatus {
  config: WatchConfig;
  /** Set while a session is open. */
  active: { folder: string; output: string; signed: number; started: number; until: number | null } | null;
  /** Why the last session ended, unless it was stopped. */
  ended: { kind: "timeUp" | "slept" | "dailyLimit" | "token" | "folder" | "other"; message: string } | null;
  signedToday: number;
  /** Most recent first. */
  log: WatchLogEntry[];
}

let mockWatch: WatchStatus = {
  config: {
    input: "",
    output: "",
    moveDone: true,
    dailyLimit: 200,
    minutes: 60,
    stopOnSleep: true,
    preset: { name: "", reason: "Approved", location: "", placement: null, pages: "", image: "off", invisible: false, style: null, timestamp: null, ltv: false },
  },
  active: null,
  ended: null,
  signedToday: 0,
  log: [],
};

export async function watchStatus(): Promise<WatchStatus> {
  return inTauri ? invoke("watch_status") : mockWatch;
}

/** Checks the folders and saves; refused while watching. */
export async function watchSave(config: WatchConfig): Promise<WatchStatus> {
  if (inTauri) return invoke("watch_save", { config });
  mockWatch = { ...mockWatch, config };
  return mockWatch;
}

/** Logs in once with `pin` and starts watching. */
export async function watchStart(certId: string, driverPath: string, pin: string): Promise<WatchStatus> {
  if (inTauri) return invoke("watch_start", { args: { certId, driverPath, pin } });
  await new Promise((r) => setTimeout(r, 500));
  if (pin !== mock.pin) throw { kind: "wrongPin", message: "Wrong PIN. Careful: few attempts left before the token locks." };
  const now = Date.now() / 1000;
  const c = mockWatch.config;
  mockWatch = {
    ...mockWatch,
    ended: null,
    active: { folder: c.input, output: c.output || `${c.input}\\signed`, signed: 0, started: now, until: c.minutes ? now + c.minutes * 60 : null },
  };
  return mockWatch;
}

export async function watchStop(): Promise<WatchStatus> {
  if (inTauri) return invoke("watch_stop");
  mockWatch = { ...mockWatch, active: null };
  return mockWatch;
}

/** A file was signed or failed, or the session started or ended. */
export async function onWatchChanged(cb: () => void): Promise<() => void> {
  if (!inTauri) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  return listen("watch-changed", () => cb());
}

// ------------------------------------------------------- Signing history

export type HistoryAction = "sign" | "sign_pages" | "sign_field" | "certify" | "portal_sign" | "sign_file" | "cleared" | "pruned" | "paused" | "resumed";
export type HistorySource = "manual" | "batch" | "watch" | "portal";
export type HistoryOutcome = "signed" | "failed";

export interface HistoryFile {
  path: string;
  /** Lower-case hex; missing when the file could not be read. */
  sha256?: string;
}

/** One line of the log, as stored (`trackmysign_core::history::Entry`). */
export interface HistoryEntry {
  seq: number;
  /** RFC 3339, UTC. */
  time: string;
  action: HistoryAction;
  source?: HistorySource;
  /** "desktop 0.6.0" or "cli 0.6.0". */
  program: string;
  /** The page that asked (GST portal). */
  origin?: string;
  input?: HistoryFile;
  output?: HistoryFile;
  portal?: { pan: string; kind: string; data?: string; sha256: string };
  cert?: { subject: string; organization?: string; issuer: string; serial: string; fingerprint: string };
  /** Numbered from 1. */
  pages?: number[];
  field?: string;
  reason?: string;
  location?: string;
  certify?: CertifyLevel;
  timestamp?: string;
  ltv?: boolean;
  outcome?: HistoryOutcome;
  error?: string;
  /** Entries deleted (cleared, pruned). */
  removed?: number;
}

export type Retention = "forever" | "year" | "days90";

export interface HistorySettings {
  enabled: boolean;
  retention: Retention;
  /** Where the log is kept. */
  folder: string;
}

export interface HistoryIntegrity {
  entries: number;
  files: number;
  problems: { file: string; line: number; seq: number | null; message: string }[];
}

let mockHistorySettings: HistorySettings = { enabled: true, retention: "forever", folder: "C:\\Users\\you\\AppData\\Roaming\\in.trackmytech.trackmysign\\history" };
const mockCert = { subject: "DK RAHUL", organization: "Personal", issuer: "Verasys Sub CA 2022", serial: "4f2a91c03b", fingerprint: "9c1e5b7d" };
let mockHistory: HistoryEntry[] = [
  {
    seq: 1,
    time: "2026-10-20T05:12:40Z",
    action: "sign",
    source: "manual",
    program: "desktop 0.5.0",
    input: { path: "C:\\Users\\you\\Documents\\invoice-1042.pdf", sha256: "3b7d1f0e5a3c9d8e2f6b1a4c7e9d0f2a3b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e" },
    output: { path: "C:\\Users\\you\\Documents\\invoice-1042_signed.pdf", sha256: "a1c4e6f8b0d2e4f6a8c0e2f4b6d8f0a2c4e6f8b0d2e4f6a8c0e2f4b6d8f0a2c4" },
    cert: mockCert,
    pages: [2],
    reason: "Approved",
    location: "Chennai",
    outcome: "signed",
  },
  {
    seq: 2,
    time: "2026-10-22T09:40:02Z",
    action: "sign",
    source: "watch",
    program: "desktop 0.5.0",
    input: { path: "D:\\Inbox\\scan.pdf" },
    outcome: "failed",
    error: "Not a valid PDF (it does not end like one; it may be incomplete).",
  },
  {
    seq: 3,
    time: "2026-10-23T11:02:15Z",
    action: "portal_sign",
    source: "portal",
    program: "desktop 0.5.0",
    origin: "https://services.gst.gov.in",
    portal: { pan: "ABCDE1234F", kind: "registration", data: "ABCDE1234F", sha256: "77ac0d1e" },
    cert: mockCert,
    outcome: "signed",
  },
];

/** Every entry, oldest first. */
export async function historyEntries(): Promise<HistoryEntry[]> {
  return inTauri ? invoke("history_entries") : mockHistory;
}

export async function historySettings(): Promise<HistorySettings> {
  return inTauri ? invoke("history_settings") : mockHistorySettings;
}

export async function historySetSettings(enabled: boolean, retention: Retention): Promise<HistorySettings> {
  if (inTauri) return invoke("history_set_settings", { settings: { enabled, retention } });
  mockHistorySettings = { ...mockHistorySettings, enabled, retention };
  return mockHistorySettings;
}

/** Follows the log's hash chain. */
export async function historyCheck(): Promise<HistoryIntegrity> {
  if (inTauri) return invoke("history_check");
  await new Promise((r) => setTimeout(r, 400));
  return { entries: mockHistory.length, files: 1, problems: [] };
}

/** Deletes every entry; one saying so is left. */
export async function historyClear(): Promise<void> {
  if (inTauri) return invoke("history_clear");
  const seq = (mockHistory[mockHistory.length - 1]?.seq ?? 0) + 1;
  mockHistory = [{ seq, time: new Date().toISOString(), action: "cleared", program: "desktop 0.5.0", removed: mockHistory.length }];
}

/** Asks where to save the history; null when cancelled. */
export async function pickHistoryExport(ext: "pdf" | "csv"): Promise<string | null> {
  const name = `signing-history-${new Date().toISOString().slice(0, 10)}.${ext}`;
  if (!inTauri) return name;
  const { save } = await import("@tauri-apps/plugin-dialog");
  const filter = ext === "pdf" ? { name: t("dialog.pdfs"), extensions: ["pdf"] } : { name: t("dialog.csv"), extensions: ["csv"] };
  return save({ defaultPath: name, filters: [filter] });
}

/** Writes the entries numbered `seqs` to `output`. */
export async function historyExport(output: string, ext: "pdf" | "csv", seqs: number[]): Promise<void> {
  if (inTauri) await invoke("history_export", { output, format: ext, seqs });
}

/** A signature was recorded, or the history was cleared or its settings changed. */
export async function onHistoryChanged(cb: () => void): Promise<() => void> {
  if (!inTauri) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  return listen("history-changed", () => cb());
}
