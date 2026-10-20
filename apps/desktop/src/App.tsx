import { useCallback, useEffect, useRef, useState } from "react";
import type { PDFDocumentProxy } from "pdfjs-dist";
import * as api from "./api";
import type { ApiError, Cert, PdfInfo, Signed } from "./api";
import { loadPdf, PdfView, type PageSize, type Placement } from "./PdfView";
import { useTheme, type ThemePref } from "./theme";
import {
  CheckIcon,
  CloseIcon,
  FileIcon,
  FitIcon,
  FolderIcon,
  GearIcon,
  KeyIcon,
  LockIcon,
  MinusIcon,
  MonitorIcon,
  MoonIcon,
  PenIcon,
  PlusIcon,
  RefreshIcon,
  ShieldIcon,
  SunIcon,
} from "./icons";

// ---------------------------------------------------------------- settings

interface Saved {
  reason: string;
  location: string;
  certName: string;
  /** Last box, as fractions of the page, and which page counted from the end. */
  box: { fx: number; fy: number; fw: number; fh: number; fromEnd: number } | null;
}

const KEY = "signdesk.settings.v1";
const defaults: Saved = { reason: "Approved", location: "", certName: "", box: null };

function loadSaved(): Saved {
  try {
    return { ...defaults, ...JSON.parse(localStorage.getItem(KEY) ?? "{}") };
  } catch {
    return defaults;
  }
}

function save(s: Saved) {
  try {
    localStorage.setItem(KEY, JSON.stringify(s));
  } catch {
    /* settings are a convenience only */
  }
}

function initialPlacement(sizes: PageSize[], saved: Saved): Placement {
  const page = saved.box ? Math.max(0, sizes.length - 1 - saved.box.fromEnd) : sizes.length - 1;
  const s = sizes[page];
  if (saved.box) {
    const { fx, fy, fw, fh } = saved.box;
    return { page, x: fx * s.width, y: fy * s.height, w: fw * s.width, h: fh * s.height };
  }
  const w = 170,
    h = 55,
    m = 36;
  return { page, x: s.width - w - m, y: s.height - h - m, w, h };
}

function now() {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? "+" : "-";
  return `${d.getFullYear()}.${p(d.getMonth() + 1)}.${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())} ${sign}${p(Math.floor(Math.abs(off) / 60))}:${p(Math.abs(off) % 60)}`;
}

// --------------------------------------------------------------------- app

interface Doc {
  info: PdfInfo;
  pdf: PDFDocumentProxy;
  sizes: PageSize[];
}

type Step = { kind: "idle" } | { kind: "pin"; error?: ApiError } | { kind: "signing" } | { kind: "done"; result: Signed };

export default function App() {
  const [saved, setSaved] = useState<Saved>(loadSaved);
  const [certs, setCerts] = useState<Cert[] | null>(null);
  const [certError, setCertError] = useState<string | null>(null);
  const [certIndex, setCertIndex] = useState(0);
  const [doc, setDoc] = useState<Doc | null>(null);
  const [loading, setLoading] = useState(false);
  const [docError, setDocError] = useState<string | null>(null);
  const [placement, setPlacement] = useState<Placement | null>(null);
  const [step, setStep] = useState<Step>({ kind: "idle" });
  const [hover, setHover] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [theme, setTheme] = useTheme();

  const update = (patch: Partial<Saved>) =>
    setSaved((s) => {
      const n = { ...s, ...patch };
      save(n);
      return n;
    });

  // ---- token
  const refreshCerts = useCallback(async () => {
    try {
      const list = (await api.listCertificates()).filter((c) => c.canSign);
      setCerts(list);
      setCertError(list.length ? null : "No signing certificate found on the token.");
      setCertIndex((i) => {
        const byName = list.findIndex((c) => c.name === loadSaved().certName);
        return byName >= 0 ? byName : Math.min(i, Math.max(0, list.length - 1));
      });
    } catch (e) {
      setCerts([]);
      setCertError(api.errorOf(e).message);
    }
  }, []);

  useEffect(() => {
    refreshCerts();
  }, [refreshCerts]);

  // Keep looking for the token while it is missing.
  const busy = step.kind === "signing";
  useEffect(() => {
    if (certs && certs.length > 0) return;
    if (busy) return;
    const t = setInterval(refreshCerts, 4000);
    return () => clearInterval(t);
  }, [certs, busy, refreshCerts]);

  // ---- documents
  const openPath = useCallback(async (path: string) => {
    setLoading(true);
    setDocError(null);
    setStep({ kind: "idle" });
    try {
      const [info, bytes] = await Promise.all([api.pdfInfo(path), api.readPdf(path)]);
      const { doc: pdf, sizes } = await loadPdf(bytes);
      if (!info.pages.length) info.pages = sizes;
      setDoc({ info, pdf, sizes });
      setZoom(1);
      setPlacement(initialPlacement(sizes, loadSaved()));
    } catch (e) {
      setDoc(null);
      setDocError(api.errorOf(e).message);
    } finally {
      setLoading(false);
    }
  }, []);

  const pick = async () => {
    const p = await api.pickPdf();
    if (p) openPath(p);
  };

  useEffect(() => {
    api.startupFile().then((p) => {
      if (p) openPath(p);
    });
    let off: (() => void) | undefined;
    api.onFileDrop(openPath, setHover).then((f) => (off = f));
    return () => off?.();
  }, [openPath]);

  const place = (p: Placement) => {
    setPlacement(p);
    if (!doc) return;
    const s = doc.sizes[p.page];
    update({
      box: { fx: p.x / s.width, fy: p.y / s.height, fw: p.w / s.width, fh: p.h / s.height, fromEnd: doc.sizes.length - 1 - p.page },
    });
  };

  // ---- signing
  const cert = certs?.[certIndex];
  const canSign = !!doc && !!placement && !!cert && !loading;

  const doSign = async (pin: string) => {
    if (!doc || !placement || !cert) return;
    setStep({ kind: "signing" });
    try {
      const result = await api.sign({
        path: doc.info.path,
        page: placement.page,
        rect: { x: placement.x, y: placement.y, w: placement.w, h: placement.h },
        reason: saved.reason,
        location: saved.location,
        certIndex: cert.index,
        pin,
      });
      update({ certName: cert.name });
      setStep({ kind: "done", result });
    } catch (e) {
      const err = api.errorOf(e);
      setStep({ kind: "pin", error: err });
      if (err.kind === "token") refreshCerts();
    }
  };

  const preview = [
    "Digitally signed by",
    cert?.name ?? "YOUR NAME",
    `Date: ${now()}`,
    ...(saved.reason.trim() ? [`Reason: ${saved.reason.trim()}`] : []),
    ...(saved.location.trim() ? [`Location: ${saved.location.trim()}`] : []),
  ];

  return (
    <div className={`app ${hover ? "drop-hover" : ""}`}>
      <header>
        <div className="brand">
          <Logo /> <span>SignDesk</span>
        </div>
        {doc && (
          <div className="doc-pill" title={doc.info.path}>
            <FileIcon size={15} />
            <span className="doc-name">{doc.info.name}</span>
            <span className="muted">
              {doc.sizes.length} page{doc.sizes.length > 1 ? "s" : ""}
            </span>
          </div>
        )}
        <div className="spacer" />
        <TokenChip certs={certs} error={certError} onRetry={refreshCerts} />
        {doc && (
          <button className="icon-btn" onClick={pick} title="Open another PDF">
            <FolderIcon />
          </button>
        )}
        <button className="icon-btn" onClick={() => setSettingsOpen(true)} title="Settings">
          <GearIcon />
        </button>
      </header>

      <main>
        {doc ? (
          <div className="viewer">
            <PdfView doc={doc.pdf} sizes={doc.sizes} placement={placement} preview={preview} zoom={zoom} onPlace={place} />
            <div className="zoom-bar">
              <button onClick={() => setZoom((z) => Math.max(0.4, +(z - 0.15).toFixed(2)))} title="Zoom out">
                <MinusIcon size={16} />
              </button>
              <span>{Math.round(zoom * 100)}%</span>
              <button onClick={() => setZoom((z) => Math.min(3, +(z + 0.15).toFixed(2)))} title="Zoom in">
                <PlusIcon size={16} />
              </button>
              <i />
              <button onClick={() => setZoom(1)} title="Fit to width">
                <FitIcon size={16} />
              </button>
            </div>
          </div>
        ) : (
          <div className="empty">
            <div className="hero">
              <div className="hero-icon">
                <PenIcon size={30} />
              </div>
              <h1>Sign a PDF with your DSC</h1>
              <p className="muted">Drop a PDF anywhere in this window, or choose one.</p>
              <button className="primary big" onClick={pick} disabled={loading}>
                <FolderIcon /> {loading ? "Opening…" : "Open PDF"}
              </button>
              {docError && <p className="error">{docError}</p>}
              <ul className="promises">
                <li>
                  <ShieldIcon size={16} /> Original file is never changed
                </li>
                <li>
                  <CheckIcon size={16} /> Earlier signatures stay valid
                </li>
                <li>
                  <LockIcon size={16} /> PIN is never stored
                </li>
              </ul>
            </div>
          </div>
        )}

        {doc && (
          <aside>
            <div className="card">
              <div className="card-title">
                <PenIcon size={16} /> Placement
              </div>
              <p className="hint">Click anywhere on a page to place the signature. Drag to move, drag the corner to resize.</p>
              {placement && (
                <div className="badge">
                  Page {placement.page + 1} of {doc.sizes.length}
                </div>
              )}
            </div>

            <div className="card">
              <div className="card-title">
                <KeyIcon size={16} /> Sign as
              </div>
              {cert ? (
                certs!.length > 1 ? (
                  <select value={certIndex} onChange={(e) => setCertIndex(Number(e.target.value))}>
                    {certs!.map((c, i) => (
                      <option key={i} value={i}>
                        {c.name} — {c.issuer}
                      </option>
                    ))}
                  </select>
                ) : (
                  <div className="cert">
                    <div className="avatar">{initials(cert.name)}</div>
                    <div>
                      <strong>{cert.name}</strong>
                      <span className="muted small">{cert.issuer}</span>
                      <span className="muted small">Valid until {cert.validUntil}</span>
                    </div>
                  </div>
                )
              ) : (
                <div className="cert warn">Plug in your DSC token…</div>
              )}
              {cert?.expired && <p className="error small">This certificate has expired.</p>}
            </div>

            <div className="card">
              <label htmlFor="reason">Reason</label>
              <input id="reason" value={saved.reason} onChange={(e) => update({ reason: e.target.value })} placeholder="e.g. Approved" />
              <label htmlFor="location">Location</label>
              <input id="location" value={saved.location} onChange={(e) => update({ location: e.target.value })} placeholder="e.g. Chennai" />
            </div>

            {doc.info.signatures > 0 && (
              <div className="note">
                <ShieldIcon size={16} />
                <span>
                  Already signed {doc.info.signatures} time{doc.info.signatures > 1 ? "s" : ""}. Existing signatures stay valid.
                </span>
              </div>
            )}

            <div className="spacer" />
            <button className="primary big" disabled={!canSign} onClick={() => setStep({ kind: "pin" })}>
              <PenIcon /> Sign document
            </button>
            <p className="muted small center">Saved as a new file next to the original.</p>
          </aside>
        )}
      </main>

      {settingsOpen && (
        <Settings
          theme={theme}
          setTheme={setTheme}
          saved={saved}
          update={update}
          certs={certs}
          onRefresh={refreshCerts}
          onClose={() => setSettingsOpen(false)}
        />
      )}

      {(step.kind === "pin" || step.kind === "signing") && cert && (
        <PinDialog
          cert={cert}
          busy={step.kind === "signing"}
          error={step.kind === "pin" ? step.error : undefined}
          onCancel={() => setStep({ kind: "idle" })}
          onSubmit={doSign}
        />
      )}

      {step.kind === "done" && (
        <Modal>
          <div className="done-icon">
            <CheckIcon size={28} />
          </div>
          <h2>Document signed</h2>
          <p className="muted">
            Saved as <strong>{step.result.name}</strong>
          </p>
          <div className="row">
            <button className="primary" onClick={() => api.openFile(step.result.output)}>
              Open signed PDF
            </button>
            <button onClick={() => api.revealFile(step.result.output)}>Show in folder</button>
          </div>
          <button
            className="ghost"
            onClick={() => {
              setStep({ kind: "idle" });
              setDoc(null);
            }}
          >
            Sign another document
          </button>
        </Modal>
      )}
    </div>
  );
}

function initials(name: string) {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0])
    .join("")
    .toUpperCase();
}

// -------------------------------------------------------------- components

function TokenChip({ certs, error, onRetry }: { certs: Cert[] | null; error: string | null; onRetry: () => void }) {
  if (certs === null)
    return (
      <div className="chip">
        <span className="dot" /> Looking for token…
      </div>
    );
  if (certs.length === 0)
    return (
      <button className="chip bad" onClick={onRetry} title={error ?? ""}>
        <span className="dot" /> Token not found <RefreshIcon size={14} />
      </button>
    );
  return (
    <div className="chip ok" title={`${certs[0].tokenLabel} · ${certs[0].issuer}`}>
      <span className="dot" /> {certs[0].name}
    </div>
  );
}

function PinDialog(props: { cert: Cert; busy: boolean; error?: ApiError; onCancel: () => void; onSubmit: (pin: string) => void }) {
  const [pin, setPin] = useState("");
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (props.error) setPin("");
    input.current?.focus();
  }, [props.error]);
  const locked = props.error?.kind === "pinLocked";
  return (
    <Modal onClose={props.busy ? undefined : props.onCancel}>
      <div className="modal-icon">
        <LockIcon size={24} />
      </div>
      <h2>Enter token PIN</h2>
      <p className="muted">
        Signing as <strong>{props.cert.name}</strong>
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (pin && !props.busy) props.onSubmit(pin);
        }}
      >
        <input
          ref={input}
          type="password"
          className="pin"
          value={pin}
          onChange={(e) => setPin(e.target.value)}
          disabled={props.busy || locked}
          autoComplete="off"
          placeholder="PIN"
        />
        {props.error && <p className="error">{props.error.message}</p>}
        {!props.error && <p className="muted small">The token locks after several wrong attempts. The PIN is never saved.</p>}
        <div className="row">
          <button type="button" onClick={props.onCancel} disabled={props.busy}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={!pin || props.busy || locked}>
            {props.busy ? "Signing…" : "Sign"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

const THEMES: { value: ThemePref; label: string; icon: React.ReactNode }[] = [
  { value: "light", label: "Light", icon: <SunIcon size={16} /> },
  { value: "dark", label: "Dark", icon: <MoonIcon size={16} /> },
  { value: "system", label: "System", icon: <MonitorIcon size={16} /> },
];

function Settings(props: {
  theme: ThemePref;
  setTheme: (t: ThemePref) => void;
  saved: Saved;
  update: (p: Partial<Saved>) => void;
  certs: Cert[] | null;
  onRefresh: () => void;
  onClose: () => void;
}) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && props.onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [props]);
  const cert = props.certs?.[0];
  return (
    <div className="drawer-backdrop" onPointerDown={(e) => e.target === e.currentTarget && props.onClose()}>
      <div className="drawer" role="dialog" aria-label="Settings">
        <div className="drawer-head">
          <h2>Settings</h2>
          <button className="icon-btn" onClick={props.onClose} title="Close">
            <CloseIcon />
          </button>
        </div>

        <section>
          <h3>Appearance</h3>
          <div className="segmented">
            {THEMES.map((t) => (
              <button key={t.value} className={props.theme === t.value ? "on" : ""} onClick={() => props.setTheme(t.value)}>
                {t.icon} {t.label}
              </button>
            ))}
          </div>
        </section>

        <section>
          <h3>Signature defaults</h3>
          <label htmlFor="s-reason">Reason</label>
          <input id="s-reason" value={props.saved.reason} onChange={(e) => props.update({ reason: e.target.value })} placeholder="e.g. Approved" />
          <label htmlFor="s-location">Location</label>
          <input
            id="s-location"
            value={props.saved.location}
            onChange={(e) => props.update({ location: e.target.value })}
            placeholder="e.g. Chennai"
          />
          <div className="setting-row">
            <div>
              <strong>Remembered position</strong>
              <span className="muted small">{props.saved.box ? "New PDFs open with the box where you last put it." : "Bottom-right of the last page."}</span>
            </div>
            <button onClick={() => props.update({ box: null })} disabled={!props.saved.box}>
              Reset
            </button>
          </div>
        </section>

        <section>
          <h3>DSC token</h3>
          <div className="setting-row">
            <div>
              <strong>{cert ? cert.name : "Not connected"}</strong>
              <span className="muted small">{cert ? `${cert.issuer} · ${cert.tokenLabel}` : "Plug in the token and check again."}</span>
            </div>
            <button onClick={props.onRefresh}>
              <RefreshIcon size={15} /> Check
            </button>
          </div>
        </section>

        <section className="about">
          <Logo />
          <div>
            <strong>SignDesk {__APP_VERSION__}</strong>
            <span className="muted small">Signs PDFs with your DSC. Nothing leaves this computer.</span>
          </div>
        </section>
      </div>
    </div>
  );
}

function Modal({ children, onClose }: { children: React.ReactNode; onClose?: () => void }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose?.();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  return (
    <div className="backdrop" onPointerDown={(e) => e.target === e.currentTarget && onClose?.()}>
      <div className="modal">{children}</div>
    </div>
  );
}

function Logo() {
  return (
    <svg width="26" height="26" viewBox="0 0 64 64" aria-hidden>
      <defs>
        <linearGradient id="lg" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#3b82f6" />
          <stop offset="1" stopColor="#1d4ed8" />
        </linearGradient>
      </defs>
      <rect width="64" height="64" rx="15" fill="url(#lg)" />
      <path d="M14 40c6-10 10-14 13-14 4 0-2 12 2 12s6-8 9-8 1 6 4 6 5-3 8-5" stroke="#fff" strokeWidth="4.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M14 49h36" stroke="#fff" strokeOpacity=".6" strokeWidth="3.5" strokeLinecap="round" />
    </svg>
  );
}
