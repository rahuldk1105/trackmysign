import { useCallback, useEffect, useRef, useState } from "react";
import type { PDFDocumentProxy } from "pdfjs-dist";
import * as api from "./api";
import type { ApiError, Cert, PdfInfo, Signed } from "./api";
import { loadPdf, PdfView, type PageSize, type Placement } from "./PdfView";

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
          <Logo /> SignDesk
        </div>
        {doc && (
          <div className="doc-title" title={doc.info.path}>
            {doc.info.name}
            <span className="muted"> · {doc.sizes.length} page{doc.sizes.length > 1 ? "s" : ""}</span>
          </div>
        )}
        <div className="spacer" />
        <TokenChip certs={certs} error={certError} onRetry={refreshCerts} />
        {doc && (
          <button className="ghost" onClick={pick}>
            Open another…
          </button>
        )}
      </header>

      <main>
        {doc ? (
          <PdfView doc={doc.pdf} sizes={doc.sizes} placement={placement} preview={preview} onPlace={place} />
        ) : (
          <div className="empty">
            <div className="drop">
              <DocIcon />
              <h1>Sign a PDF with your DSC</h1>
              <p>Drag a PDF here, or</p>
              <button className="primary big" onClick={pick} disabled={loading}>
                {loading ? "Opening…" : "Open PDF…"}
              </button>
              {docError && <p className="error">{docError}</p>}
            </div>
          </div>
        )}

        {doc && (
          <aside>
            <section>
              <h2>Signature</h2>
              <p className="hint">Click on any page to place the box. Drag it to move, drag the corner to resize.</p>
              {placement && <p className="muted small">Placed on page {placement.page + 1} of {doc.sizes.length}</p>}
            </section>

            <section>
              <label>Sign as</label>
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
                    <strong>{cert.name}</strong>
                    <span className="muted small">
                      {cert.issuer} · valid until {cert.validUntil}
                    </span>
                  </div>
                )
              ) : (
                <div className="cert warn">Plug in your DSC token…</div>
              )}
              {cert?.expired && <p className="error small">This certificate has expired.</p>}
            </section>

            <section>
              <label htmlFor="reason">Reason</label>
              <input id="reason" value={saved.reason} onChange={(e) => update({ reason: e.target.value })} placeholder="e.g. Approved" />
              <label htmlFor="location">Location</label>
              <input id="location" value={saved.location} onChange={(e) => update({ location: e.target.value })} placeholder="e.g. Chennai" />
            </section>

            {doc.info.signatures > 0 && (
              <section className="note">
                Already signed {doc.info.signatures} time{doc.info.signatures > 1 ? "s" : ""}. Existing signatures stay valid.
              </section>
            )}

            <div className="spacer" />
            <button className="primary big" disabled={!canSign} onClick={() => setStep({ kind: "pin" })}>
              Sign document
            </button>
            <p className="muted small center">Saved as a new file next to the original.</p>
          </aside>
        )}
      </main>

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
          <div className="done-icon">✓</div>
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

// -------------------------------------------------------------- components

function TokenChip({ certs, error, onRetry }: { certs: Cert[] | null; error: string | null; onRetry: () => void }) {
  if (certs === null) return <div className="chip">Looking for token…</div>;
  if (certs.length === 0)
    return (
      <button className="chip bad" onClick={onRetry} title={error ?? ""}>
        <span className="dot" /> Token not found — retry
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
    <svg width="22" height="22" viewBox="0 0 64 64" aria-hidden>
      <rect width="64" height="64" rx="14" fill="var(--accent)" />
      <path d="M14 42c6-10 10-14 13-14 4 0-2 12 2 12s6-8 9-8 1 6 4 6 5-3 8-5" stroke="#fff" strokeWidth="4" fill="none" strokeLinecap="round" />
      <path d="M14 50h36" stroke="#fff" strokeOpacity=".6" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

function DocIcon() {
  return (
    <svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden>
      <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
      <path d="M14 3v5h5M8 16c1.5-2 2.5-3 3-3 1 0-.5 3 .5 3s1.5-2 2.5-2 .5 1.5 1.5 1.5" />
    </svg>
  );
}
