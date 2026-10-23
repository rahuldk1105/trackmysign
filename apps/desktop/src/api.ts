// Typed wrappers over the Rust commands. Outside Tauri (plain browser, for UI
// development) a mock backend is used so the screens can be exercised.

import { Channel, invoke } from "@tauri-apps/api/core";

export interface Cert {
  index: number;
  name: string;
  organization: string | null;
  issuer: string;
  validUntil: string;
  expired: boolean;
  canSign: boolean;
  tokenLabel: string;
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

/** Whether the handwritten signature image is shown, and where. */
export type ImageChoice = "off" | "left" | "above";

export interface SignArgs {
  path: string;
  page: number;
  rect: Rect | null;
  reason: string;
  location: string;
  certIndex: number;
  pin: string;
  image?: Exclude<ImageChoice, "off"> | null;
}

/** Several PDFs, one PIN entry. The box goes on the same page and spot of each. */
export interface BatchArgs extends Omit<SignArgs, "path" | "page"> {
  paths: string[];
  /** "first", "last" or a page number (1 = first). */
  page: "first" | "last" | number;
}

export type BatchProgress =
  | { state: "signing"; index: number }
  | { state: "done"; index: number; output: string; name: string }
  | { state: "failed"; index: number; message: string };

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
        index: 0,
        name: "DK RAHUL",
        organization: "Personal",
        issuer: "Verasys Sub CA 2022",
        validUntil: "11 Dec 2026",
        expired: false,
        canSign: true,
        tokenLabel: "HYP2003",
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

/** PDFs the app was started with (command line, Finder, "Sign with TrackMySign"). */
/** Signs every file in one token session; per-file results arrive through `progress`. */
export async function signBatch(args: BatchArgs, progress: (p: BatchProgress) => void): Promise<void> {
  if (!inTauri) return mock.signBatch(args, progress);
  const channel = new Channel<BatchProgress>();
  channel.onmessage = progress;
  await invoke("sign_batch", { args, progress: channel });
}

export async function startupFiles(): Promise<string[]> {
  return inTauri ? invoke("startup_files") : [];
}

/** PDFs handed over while the app is running (Finder, a second launch). */
export async function onOpenFiles(cb: (paths: string[]) => void): Promise<() => void> {
  if (!inTauri) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  return listen<string[]>("open-files", (e) => cb(e.payload));
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

export async function pickImage(): Promise<string | null> {
  if (!inTauri) return null;
  const { open } = await import("@tauri-apps/plugin-dialog");
  const r = await open({ multiple: false, filters: [{ name: "Images", extensions: ["png", "jpg", "jpeg"] }] });
  return typeof r === "string" ? r : null;
}

export async function openFile(path: string): Promise<void> {
  if (inTauri) await invoke("open_file", { path });
}

export async function revealFile(path: string): Promise<void> {
  if (inTauri) await invoke("reveal_file", { path });
}

/** Path of the PKCS#11 driver used for the token, or null when none is installed. */
export async function tokenDriver(): Promise<string | null> {
  return inTauri ? invoke("token_driver") : "C:\\Windows\\System32\\eps2003csp11v2.dll";
}

export async function openWebsite(): Promise<void> {
  if (inTauri) await invoke("open_website");
  else window.open("https://sign.rahuldk.in", "_blank");
}

/** One or more PDFs; several are signed as a batch. */
export async function pickPdfs(): Promise<string[]> {
  if (!inTauri) return ["C:\\Users\\rahul\\Downloads\\sample.pdf"];
  const { open } = await import("@tauri-apps/plugin-dialog");
  const r = await open({ multiple: true, filters: [{ name: "PDF documents", extensions: ["pdf"] }] });
  return r ?? [];
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
      const pdfs = p.paths.filter((x) => x.toLowerCase().endsWith(".pdf"));
      if (pdfs.length) cb(pdfs);
    }
  });
}
