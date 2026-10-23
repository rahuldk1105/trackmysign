// Typed wrappers over the Rust commands. Outside Tauri (plain browser, for UI
// development) a mock backend is used so the screens can be exercised.

import { invoke } from "@tauri-apps/api/core";

export interface Cert {
  /** SHA-256 fingerprint of the certificate. */
  id: string;
  name: string;
  organization: string | null;
  issuer: string;
  validUntil: string;
  expired: boolean;
  canSign: boolean;
  tokenLabel: string;
  /** Product name of the PKCS#11 driver the certificate was read through. */
  driver: string;
  driverPath: string;
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
}

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface SignArgs {
  path: string;
  page: number;
  rect: Rect | null;
  reason: string;
  location: string;
  certId: string;
  driverPath: string;
  pin: string;
}

export interface Signed {
  output: string;
  name: string;
}

export interface ApiError {
  kind: "wrongPin" | "pinLocked" | "token" | "pdf" | "io" | "other";
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
        validUntil: "11 Dec 2026",
        expired: false,
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
};

export async function listCertificates(): Promise<Cert[]> {
  return inTauri ? invoke("list_certificates") : mock.listCertificates();
}

export async function pdfInfo(path: string): Promise<PdfInfo> {
  if (inTauri) return invoke("pdf_info", { path });
  return { path, name: path.split(/[\\/]/).pop() ?? path, pages: [], signatures: 1 };
}

export async function readPdf(path: string): Promise<ArrayBuffer> {
  return inTauri ? invoke("read_pdf", { path }) : mock.readPdf();
}

export async function sign(args: SignArgs): Promise<Signed> {
  return inTauri ? invoke("sign", { args }) : mock.sign(args);
}

export async function startupFile(): Promise<string | null> {
  return inTauri ? invoke("startup_file") : null;
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

export async function pickPdf(): Promise<string | null> {
  if (!inTauri) return "C:\\Users\\rahul\\Downloads\\sample.pdf";
  const { open } = await import("@tauri-apps/plugin-dialog");
  const r = await open({ multiple: false, filters: [{ name: "PDF documents", extensions: ["pdf"] }] });
  return typeof r === "string" ? r : null;
}

export async function onFileDrop(cb: (path: string) => void, hover: (on: boolean) => void): Promise<() => void> {
  if (!inTauri) return () => {};
  const { getCurrentWebview } = await import("@tauri-apps/api/webview");
  return getCurrentWebview().onDragDropEvent((e) => {
    const p = e.payload;
    if (p.type === "enter" || p.type === "over") hover(true);
    else if (p.type === "leave") hover(false);
    else if (p.type === "drop") {
      hover(false);
      const pdf = p.paths.find((x) => x.toLowerCase().endsWith(".pdf"));
      if (pdf) cb(pdf);
    }
  });
}
