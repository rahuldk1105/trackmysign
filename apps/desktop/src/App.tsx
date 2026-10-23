import { useCallback, useEffect, useRef, useState } from "react";
import type { PDFDocumentProxy } from "pdfjs-dist";
import * as api from "./api";
import type { ApiError, Cert, PdfInfo, Signed } from "./api";
import { loadPdf, PdfView, type PageSize, type Placement } from "./PdfView";
import { SignaturesPanel } from "./SignaturesPanel";
import { useTheme, type ThemePref } from "./theme";
import {
  AlertIcon,
  CheckIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  CloseIcon,
  FileIcon,
  FitWidthIcon,
  FolderIcon,
  GearIcon,
  MinusIcon,
  PlusIcon,
  RefreshIcon,
} from "./icons";

// ---------------------------------------------------------------- settings

interface Saved {
  reason: string;
  location: string;
  certName: string;
  /** Last box, as fractions of the page, and which page counted from the end. */
  box: { fx: number; fy: number; fw: number; fh: number; fromEnd: number } | null;
}

const KEY = "trackmysign.settings.v1";
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

const BOX_W = 170;
const BOX_H = 55;
const BOX_MARGIN = 36;

function bottomRight(page: number, s: PageSize): Placement {
  return { page, x: s.width - BOX_W - BOX_MARGIN, y: s.height - BOX_H - BOX_MARGIN, w: BOX_W, h: BOX_H };
}

function initialPlacement(sizes: PageSize[], saved: Saved): Placement {
  const page = saved.box ? Math.max(0, sizes.length - 1 - saved.box.fromEnd) : sizes.length - 1;
  const s = sizes[page];
  if (saved.box) {
    const { fx, fy, fw, fh } = saved.box;
    return { page, x: fx * s.width, y: fy * s.height, w: fw * s.width, h: fh * s.height };
  }
  return bottomRight(page, s);
}

function now() {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? "+" : "-";
  return `${d.getFullYear()}.${p(d.getMonth() + 1)}.${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())} ${sign}${p(Math.floor(Math.abs(off) / 60))}:${p(Math.abs(off) % 60)}`;
}

/** Points to millimetres, one decimal. */
const mm = (pt: number) => (pt * 0.3528).toFixed(1);

const isMac = /mac/i.test(navigator.platform);
const MOD = isMac ? "⌘" : "Ctrl+";

const ZOOM_STEPS = [0.25, 0.33, 0.5, 0.67, 0.75, 0.8, 0.9, 1, 1.1, 1.25, 1.5, 1.75, 2, 2.5, 3, 4];

function baseName(path: string) {
  return path.split(/[\\/]/).pop() ?? path;
}

function signedName(name: string) {
  return `${name.replace(/\.pdf$/i, "")}_signed.pdf`;
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
  const [driver, setDriver] = useState<string | null | undefined>(undefined);
  const [doc, setDoc] = useState<Doc | null>(null);
  const [loading, setLoading] = useState(false);
  const [docError, setDocError] = useState<string | null>(null);
  const [placement, setPlacement] = useState<Placement | null>(null);
  const [step, setStep] = useState<Step>({ kind: "idle" });
  const [hover, setHover] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [view, setView] = useState({ scale: 1, fit: 1 });
  const [page, setPage] = useState(0);
  const [goto, setGoto] = useState<{ page: number; n: number } | null>(null);
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
    api
      .tokenDriver()
      .then(setDriver)
      .catch(() => setDriver(null));
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
      setPage(0);
      setPlacement(initialPlacement(sizes, loadSaved()));
    } catch (e) {
      setDoc(null);
      setDocError(api.errorOf(e).message);
    } finally {
      setLoading(false);
    }
  }, []);

  const pick = useCallback(async () => {
    const p = await api.pickPdf();
    if (p) openPath(p);
  }, [openPath]);

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

  // ---- view
  const onScale = useCallback((scale: number, fit: number) => setView({ scale, fit }), []);
  const pages = doc?.sizes.length ?? 0;
  const goPage = (p: number) => {
    const t = Math.min(Math.max(p, 0), pages - 1);
    setGoto((g) => ({ page: t, n: (g?.n ?? 0) + 1 }));
  };
  const zoomBy = (dir: 1 | -1) => {
    const cur = view.scale;
    const next = dir > 0 ? ZOOM_STEPS.find((z) => z > cur + 0.001) : [...ZOOM_STEPS].reverse().find((z) => z < cur - 0.001);
    if (next) setZoom(next / view.fit);
  };

  // ---- signing
  const cert = certs?.[certIndex];
  const canSign = !!doc && !!placement && !!cert && !cert.expired && !loading;
  const dialogOpen = step.kind !== "idle" || settingsOpen;

  // ---- keyboard
  const keys = useRef({ pick, zoomBy, dialogOpen, hasDoc: !!doc });
  keys.current = { pick, zoomBy, dialogOpen, hasDoc: !!doc };
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey) || e.altKey) return;
      const c = keys.current;
      const key = e.key.toLowerCase();
      if (key === "o" && !c.dialogOpen) {
        e.preventDefault();
        c.pick();
      } else if (c.hasDoc && !c.dialogOpen && (key === "=" || key === "+")) {
        e.preventDefault();
        c.zoomBy(1);
      } else if (c.hasDoc && !c.dialogOpen && key === "-") {
        e.preventDefault();
        c.zoomBy(-1);
      } else if (c.hasDoc && !c.dialogOpen && key === "0") {
        e.preventDefault();
        setZoom(1);
      }
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, []);

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

  const zoomPct = `${Math.round(view.scale * 100)}%`;

  return (
    <div className={`app ${hover ? "drop-hover" : ""}`}>
      <header className="toolbar">
        <div className="brand">
          <Logo size={20} />
          <span>TrackMySign</span>
        </div>
        <i className="tb-sep" />
        {doc ? (
          <>
            <div className="doc-name" title={doc.info.path}>
              <FileIcon />
              <span>{doc.info.name}</span>
            </div>
            <i className="tb-sep" />
            <div className="tb-group" role="group" aria-label="Pages">
              <button className="tb-btn" onClick={() => goPage(page - 1)} disabled={page <= 0} title="Previous page">
                <ChevronUpIcon />
              </button>
              <span className="tb-value mono" aria-live="polite">
                {page + 1} / {pages}
              </span>
              <button className="tb-btn" onClick={() => goPage(page + 1)} disabled={page >= pages - 1} title="Next page">
                <ChevronDownIcon />
              </button>
            </div>
            <i className="tb-sep" />
            <div className="tb-group" role="group" aria-label="Zoom">
              <button className="tb-btn" onClick={() => zoomBy(-1)} disabled={view.scale <= ZOOM_STEPS[0]} title={`Zoom out (${MOD}−)`}>
                <MinusIcon />
              </button>
              <span className="tb-value mono zoom-val">{zoomPct}</span>
              <button className="tb-btn" onClick={() => zoomBy(1)} disabled={view.scale >= ZOOM_STEPS[ZOOM_STEPS.length - 1]} title={`Zoom in (${MOD}+)`}>
                <PlusIcon />
              </button>
              <button className={`tb-btn text ${zoom === 1 ? "on" : ""}`} onClick={() => setZoom(1)} title={`Fit width (${MOD}0)`}>
                <FitWidthIcon />
                <span>Fit width</span>
              </button>
            </div>
          </>
        ) : (
          <span className="muted doc-none">No document</span>
        )}
        <div className="spacer" />
        <button className="btn" onClick={pick} disabled={loading} title={`Open a PDF (${MOD}O)`}>
          <FolderIcon />
          Open…
          <kbd>{MOD}O</kbd>
        </button>
        <button className="tb-btn" onClick={() => setSettingsOpen(true)} title="Settings" aria-label="Settings">
          <GearIcon />
        </button>
      </header>

      <div className="workspace">
        <main className="viewer">
          {doc ? (
            <>
              <PdfView
                doc={doc.pdf}
                sizes={doc.sizes}
                placement={placement}
                preview={preview}
                zoom={zoom}
                onPlace={place}
                onScale={onScale}
                onPageChange={setPage}
                goto={goto}
              />
              {hover && <div className="drop-overlay">Drop to open this PDF</div>}
            </>
          ) : (
            <div className="empty">
              <div className="drop-region">
                <div className="empty-block">
                  <h1>Open a PDF to sign</h1>
                  <p className="muted">Drop a file here or press {isMac ? "⌘O" : "Ctrl+O"}</p>
                  <button className="btn primary" onClick={pick} disabled={loading}>
                    <FolderIcon />
                    {loading ? "Opening…" : "Open PDF…"}
                  </button>
                  {docError && (
                    <p className="inline-error">
                      <AlertIcon size={14} /> {docError}
                    </p>
                  )}
                  <ul className="facts">
                    <li>
                      <CheckIcon size={13} /> Original file is never modified
                    </li>
                    <li>
                      <CheckIcon size={13} /> Existing signatures stay valid
                    </li>
                    <li>
                      <CheckIcon size={13} /> Your PIN is never stored
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          )}
        </main>

        {doc && (
          <aside className="inspector">
            <div className="insp-scroll">
              <section>
                <h3>Signer</h3>
                {certs === null ? (
                  <p className="muted small">Looking for the DSC token…</p>
                ) : !cert ? (
                  <div className="warn-row">
                    <AlertIcon size={14} />
                    <div>
                      <strong>No signing certificate</strong>
                      <span>Plug in your DSC token.</span>
                      <button className="link" onClick={refreshCerts}>
                        Check again
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    {certs.length > 1 && (
                      <select value={certIndex} onChange={(e) => setCertIndex(Number(e.target.value))} aria-label="Certificate">
                        {certs.map((c, i) => (
                          <option key={i} value={i}>
                            {c.name} — {c.issuer}
                          </option>
                        ))}
                      </select>
                    )}
                    <dl className="kv">
                      <dt>Name</dt>
                      <dd className="strong">{cert.name}</dd>
                      <dt>Issuer</dt>
                      <dd>{cert.issuer}</dd>
                      <dt>Valid until</dt>
                      <dd className={cert.expired ? "bad" : undefined}>{cert.validUntil}</dd>
                    </dl>
                    {cert.expired && (
                      <div className="warn-row">
                        <AlertIcon size={14} />
                        <div>
                          <strong>Certificate expired</strong>
                          <span>Renew your DSC to sign documents.</span>
                        </div>
                      </div>
                    )}
                  </>
                )}
              </section>

              <section>
                <h3>Appearance</h3>
                <label htmlFor="reason">Reason</label>
                <input id="reason" value={saved.reason} onChange={(e) => update({ reason: e.target.value })} placeholder="e.g. Approved" />
                <label htmlFor="location">Location</label>
                <input id="location" value={saved.location} onChange={(e) => update({ location: e.target.value })} placeholder="e.g. Chennai" />
                <div className="stamp-preview" aria-label="Signature preview">
                  {preview.map((l, i) => (
                    <div key={i} className={i === 1 ? "sig-name" : undefined}>
                      {l}
                    </div>
                  ))}
                </div>
              </section>

              <section>
                <h3>Placement</h3>
                {placement && (
                  <>
                    <div className="place-row">
                      <span>
                        Page {placement.page + 1} of {pages}
                      </span>
                      <button className="link" onClick={() => goPage(placement.page)}>
                        Show
                      </button>
                    </div>
                    <div className="mono coords">
                      <span>
                        x {mm(placement.x)} · y {mm(placement.y)} mm
                      </span>
                      <span>
                        {mm(placement.w)} × {mm(placement.h)} mm
                      </span>
                    </div>
                  </>
                )}
                <p className="muted small">Click a page to place the signature. Drag to move; drag the corner to resize.</p>
                <button
                  className="link"
                  onClick={() => placement && place(bottomRight(placement.page, doc.sizes[placement.page]))}
                  disabled={!placement}
                >
                  Reset to bottom-right
                </button>
              </section>

              <SignaturesPanel path={doc.info.path} count={doc.info.signatures} />
            </div>

            <div className="insp-foot">
              <button className="btn primary block" disabled={!canSign} onClick={() => setStep({ kind: "pin" })}>
                Sign document
              </button>
              <p className="muted small">
                Saves <span className="mono">{signedName(doc.info.name)}</span> next to the original
              </p>
            </div>
          </aside>
        )}
      </div>

      <footer className="statusbar">
        <TokenStatus certs={certs} error={certError} onRetry={refreshCerts} />
        <div className="spacer" />
        <span className="mono sb-item" title={driver ?? undefined}>
          {driver === undefined ? "" : driver ? baseName(driver) : "No PKCS#11 driver found"}
        </span>
        {doc && (
          <>
            <i className="sb-sep" />
            <span className="sb-item mono">
              Page {page + 1} of {pages} · {zoomPct}
            </span>
          </>
        )}
      </footer>

      {settingsOpen && (
        <Settings
          theme={theme}
          setTheme={setTheme}
          saved={saved}
          update={update}
          certs={certs}
          certError={certError}
          driver={driver}
          onRefresh={refreshCerts}
          onClose={() => setSettingsOpen(false)}
        />
      )}

      {(step.kind === "pin" || step.kind === "signing") && cert && doc && (
        <PinDialog
          cert={cert}
          docName={doc.info.name}
          busy={step.kind === "signing"}
          error={step.kind === "pin" ? step.error : undefined}
          onCancel={() => setStep({ kind: "idle" })}
          onSubmit={doSign}
        />
      )}

      {step.kind === "done" && (
        <Modal title="Document signed" icon={<CheckIcon size={16} />} tone="ok" onClose={() => setStep({ kind: "idle" })}>
          <p>The signed copy was saved next to the original.</p>
          <div className="file-row mono" title={step.result.output}>
            <FileIcon size={14} />
            <span>{step.result.name}</span>
          </div>
          <div className="dialog-actions">
            <button
              className="btn ghost"
              onClick={() => {
                setStep({ kind: "idle" });
                setDoc(null);
              }}
            >
              Sign another
            </button>
            <div className="spacer" />
            <button className="btn" onClick={() => api.revealFile(step.result.output)}>
              Show in folder
            </button>
            <button className="btn primary" autoFocus onClick={() => api.openFile(step.result.output)}>
              Open
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

// -------------------------------------------------------------- components

function TokenStatus({ certs, error, onRetry }: { certs: Cert[] | null; error: string | null; onRetry: () => void }) {
  if (certs === null)
    return (
      <span className="sb-item token">
        <i className="sq" /> Looking for token…
      </span>
    );
  if (certs.length === 0)
    return (
      <button className="sb-item token bad" onClick={onRetry} title={error ?? ""}>
        <i className="sq" /> No token detected — <u>Check again</u>
      </button>
    );
  return (
    <span className="sb-item token ok" title={`${certs[0].tokenLabel} · ${certs[0].issuer}`}>
      <i className="sq" /> {certs[0].tokenLabel} · {certs[0].name}
    </span>
  );
}

function PinDialog(props: {
  cert: Cert;
  docName: string;
  busy: boolean;
  error?: ApiError;
  onCancel: () => void;
  onSubmit: (pin: string) => void;
}) {
  const [pin, setPin] = useState("");
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (props.error) setPin("");
    input.current?.focus();
  }, [props.error]);
  const locked = props.error?.kind === "pinLocked";
  const pinError = props.error && (props.error.kind === "wrongPin" || props.error.kind === "pinLocked");
  return (
    <Modal title="Enter token PIN" onClose={props.busy ? undefined : props.onCancel}>
      <dl className="kv compact">
        <dt>Signer</dt>
        <dd className="strong">{props.cert.name}</dd>
        <dt>Token</dt>
        <dd>{props.cert.tokenLabel}</dd>
        <dt>Document</dt>
        <dd className="mono ellipsis">{props.docName}</dd>
      </dl>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (pin && !props.busy) props.onSubmit(pin);
        }}
      >
        <label htmlFor="pin">PIN</label>
        <input
          id="pin"
          ref={input}
          type="password"
          className={`pin ${pinError ? "invalid" : ""}`}
          value={pin}
          onChange={(e) => setPin(e.target.value)}
          disabled={props.busy || locked}
          autoComplete="off"
          spellCheck={false}
        />
        {props.error ? (
          <p className="inline-error">
            <AlertIcon size={14} /> {props.error.message}
          </p>
        ) : (
          <p className="muted small">The token locks after several wrong attempts. The PIN is never saved.</p>
        )}
        <div className="dialog-actions">
          <div className="spacer" />
          <button type="button" className="btn" onClick={props.onCancel} disabled={props.busy}>
            Cancel
          </button>
          <button type="submit" className="btn primary" disabled={!pin || props.busy || locked}>
            {props.busy ? "Signing…" : "Sign"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

const THEMES: { value: ThemePref; label: string }[] = [
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
  { value: "system", label: "System" },
];

function Settings(props: {
  theme: ThemePref;
  setTheme: (t: ThemePref) => void;
  saved: Saved;
  update: (p: Partial<Saved>) => void;
  certs: Cert[] | null;
  certError: string | null;
  driver: string | null | undefined;
  onRefresh: () => void;
  onClose: () => void;
}) {
  const { onClose } = props;
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  const panel = useRef<HTMLDivElement>(null);
  useEffect(() => {
    panel.current?.querySelector<HTMLElement>("button")?.focus();
  }, []);
  const cert = props.certs?.[0];
  return (
    <div className="panel-backdrop" onPointerDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="settings" role="dialog" aria-label="Settings" ref={panel}>
        <div className="settings-head">
          <h2>Settings</h2>
          <button className="tb-btn" onClick={onClose} title="Close (Esc)" aria-label="Close">
            <CloseIcon />
          </button>
        </div>

        <div className="settings-body">
          <section>
            <h3>Appearance</h3>
            <div className="segmented" role="radiogroup" aria-label="Theme">
              {THEMES.map((t) => (
                <button
                  key={t.value}
                  role="radio"
                  aria-checked={props.theme === t.value}
                  className={props.theme === t.value ? "on" : ""}
                  onClick={() => props.setTheme(t.value)}
                >
                  {t.label}
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
          </section>

          <section>
            <h3>Remembered position</h3>
            <div className="setting-row">
              <span className="muted small">
                {props.saved.box ? "New PDFs open with the box where you last placed it." : "New PDFs open with the box at the bottom-right of the last page."}
              </span>
              <button className="btn" onClick={() => props.update({ box: null })} disabled={!props.saved.box}>
                Reset
              </button>
            </div>
          </section>

          <section>
            <h3>DSC token</h3>
            <dl className="kv">
              <dt>Status</dt>
              <dd className={cert ? "ok" : props.certs ? "bad" : undefined}>
                {cert ? `${cert.tokenLabel} · ${cert.name}` : props.certs ? "Not connected" : "Checking…"}
              </dd>
              {cert && (
                <>
                  <dt>Issuer</dt>
                  <dd>{cert.issuer}</dd>
                </>
              )}
              <dt>Driver</dt>
              <dd className="mono wrap">{props.driver === undefined ? "…" : (props.driver ?? "Not found")}</dd>
            </dl>
            {!cert && props.certError && <p className="muted small">{props.certError}</p>}
            <button className="btn" onClick={props.onRefresh}>
              <RefreshIcon size={14} /> Check again
            </button>
          </section>

          <section>
            <h3>About</h3>
            <div className="about">
              <Logo size={28} />
              <div>
                <div>
                  <strong>TrackMySign</strong> <span className="mono muted">{__APP_VERSION__}</span>
                </div>
                <span className="muted small">Signs PDFs with your DSC. Nothing leaves this computer.</span>
                <button className="link" onClick={() => api.openWebsite()}>
                  sign.rahuldk.in
                </button>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function Modal(props: { title: string; icon?: React.ReactNode; tone?: "ok"; children: React.ReactNode; onClose?: () => void }) {
  const { onClose } = props;
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose?.();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  return (
    <div className="backdrop" onPointerDown={(e) => e.target === e.currentTarget && onClose?.()}>
      <div className="dialog" role="dialog" aria-modal="true" aria-label={props.title}>
        <div className="dialog-title">
          {props.icon && <span className={`dialog-icon ${props.tone ?? ""}`}>{props.icon}</span>}
          <h2>{props.title}</h2>
        </div>
        <div className="dialog-body">{props.children}</div>
      </div>
    </div>
  );
}

export function Logo({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden className="logo">
      <rect width="64" height="64" rx="6.4" style={{ fill: "var(--logo-bg)" }} />
      <path d="M14 40c6-10 10-14 13-14 4 0-2 12 2 12s6-8 9-8 1 6 4 6 5-3 8-5" style={{ stroke: "var(--logo-fg)" }} strokeWidth="4.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M14 49h36" style={{ stroke: "var(--logo-fg)" }} strokeOpacity=".45" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}
