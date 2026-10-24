// "Sign other files…": any file that is not a PDF (Word, Excel, ZIP, XML,
// images) signed with the DSC as a standard CMS / PKCS#7 signature, a
// `.p7s` next to it or a `.p7m` that carries it (`sign_files`). Lists each
// file with its size, SHA-256 and the signature already next to it,
// checked (`file_info`); a `.p7s` / `.p7m` opened here is checked, and the
// file inside a `.p7m` can be saved.

import { useCallback, useEffect, useState } from "react";
import * as api from "./api";
import type { ApiError, Cert, FileInfo } from "./api";
import { PinDialog } from "./App";
import { t, tx } from "./i18n";
import { errorText, translateMessage } from "./i18n/errors";
import { AlertIcon, CheckIcon, CloseIcon, FileIcon } from "./icons";
import { SignatureItem } from "./SignaturesPanel";
import "./filesign.css";

type Loaded = FileInfo | { path: string; failed: string };

type Result = { state: "signing" } | { state: "done"; output: string; name: string } | { state: "failed"; message: string };

type Step = { kind: "idle" } | { kind: "pin"; error?: ApiError } | { kind: "signing" } | { kind: "running" };

function fileName(path: string): string {
  return path.split(/[\\/]/).pop() ?? path;
}

function sizeText(n: number): string {
  if (n < 1024) return `${n.toLocaleString()} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toLocaleString(undefined, { maximumFractionDigits: 1 })} KB`;
  return `${(n / 1024 / 1024).toLocaleString(undefined, { maximumFractionDigits: 1 })} MB`;
}

const failedLoad = (f: Loaded): f is { path: string; failed: string } => "failed" in f;

export function FileSignDialog(props: {
  paths: string[];
  setPaths: (paths: string[]) => void;
  certs: Cert[] | null;
  certIndex: number;
  setCertIndex: (i: number) => void;
  /** Timestamp server from Settings, and whether timestamps are on there. */
  tsaUrl: string | null;
  timestamp: boolean;
  startFolder: string | null;
  onCertUsed: (cert: Cert) => void;
  onRefreshCerts: () => void;
  onClose: () => void;
}) {
  const { paths, setPaths, onClose } = props;
  const [infos, setInfos] = useState<Record<string, Loaded>>({});
  const [attached, setAttached] = useState(false);
  const [useTs, setUseTs] = useState(props.timestamp && !!props.tsaUrl);
  const [step, setStep] = useState<Step>({ kind: "idle" });
  const [results, setResults] = useState<Record<string, Result>>({});
  const [batchError, setBatchError] = useState<string | null>(null);
  const [extracted, setExtracted] = useState<{ path: string; output?: string; error?: string } | null>(null);
  const cert = props.certs?.[props.certIndex];

  const load = useCallback(async (list: string[]) => {
    const loaded = await Promise.all(
      list.map((path) =>
        api.fileInfo(path).then(
          (i): Loaded => i,
          (e): Loaded => ({ path, failed: errorText(api.errorOf(e)) }),
        ),
      ),
    );
    setInfos((cur) => ({ ...cur, ...Object.fromEntries(loaded.map((l) => [l.path, l])) }));
  }, []);

  useEffect(() => {
    load(paths.filter((p) => !(p in infos)));
    // Only files not loaded yet; signing reloads the ones it changed.
  }, [paths, load]);

  // Captured first, so Esc closes this dialog and nothing under it; the PIN
  // dialog on top handles its own.
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || step.kind !== "idle") return;
      e.stopPropagation();
      onClose();
    };
    window.addEventListener("keydown", k, true);
    return () => window.removeEventListener("keydown", k, true);
  }, [onClose, step.kind]);

  const shown = paths.map((p) => infos[p]);
  const signable = paths.filter((p) => {
    const i = infos[p];
    return i && !failedLoad(i) && i.kind === "file";
  });
  const busy = step.kind !== "idle";

  const add = async () => {
    const more = await api.pickAnyFiles(props.startFolder);
    if (more.length) setPaths([...paths, ...more.filter((p) => !paths.includes(p))]);
  };

  const remove = (path: string) => setPaths(paths.filter((p) => p !== path));

  const sign = async (pin: string, skip?: "timestamp" | "ltv") => {
    if (!cert || !signable.length) return;
    const list = signable;
    let started = false;
    let finished = 0;
    setBatchError(null);
    setStep({ kind: "signing" });
    try {
      await api.signFiles(
        {
          paths: list,
          attached,
          certId: cert.id,
          driverPath: cert.driverPath,
          pin,
          timestamp: useTs && skip !== "timestamp" ? props.tsaUrl : null,
        },
        (p) => {
          if (!started) {
            started = true;
            setResults({});
            setStep({ kind: "running" });
          }
          const path = list[p.index];
          const r: Result =
            p.state === "signing" ? { state: "signing" } : p.state === "done" ? { state: "done", output: p.output, name: p.name } : { state: "failed", message: translateMessage(p.message) };
          if (p.state !== "signing") finished++;
          setResults((cur) => ({ ...cur, [path]: r }));
        },
      );
      props.onCertUsed(cert);
      setStep({ kind: "idle" });
    } catch (e) {
      const err = api.errorOf(e);
      // A key that wants the PIN for every signature only checks it at the first file;
      // a timestamp server that is down fails at the first file too.
      const retry = err.kind === "wrongPin" || err.kind === "pinLocked" || err.kind === "timestamp";
      if (started && !(retry && finished === 0)) {
        setStep({ kind: "idle" });
        setBatchError(errorText(err));
      } else {
        setResults({});
        setStep({ kind: "pin", error: err });
        if (err.kind === "token" || err.kind === "expired") props.onRefreshCerts();
        return;
      }
    }
    load(list);
  };

  const saveOriginal = async (path: string) => {
    const output = await api.pickOriginalPath(path);
    if (!output) return;
    try {
      await api.extractSigned(path, output);
      setExtracted({ path, output });
    } catch (e) {
      setExtracted({ path, error: errorText(api.errorOf(e)) });
    }
  };

  return (
    <div className="backdrop" onPointerDown={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <div className="dialog files-dialog" role="dialog" aria-modal="true" aria-label={t("files.title")}>
        <div className="dialog-title">
          <h2>{t("files.title")}</h2>
          <div className="spacer" />
          <button className="tb-btn" onClick={onClose} disabled={busy} title={t("common.close")} aria-label={t("common.close")}>
            <CloseIcon />
          </button>
        </div>
        <div className="dialog-body">
          {paths.length === 0 && <p className="muted small">{t("files.empty")}</p>}
          <ul className="files-list">
            {paths.map((path, i) => {
              const f = shown[i];
              const r = results[path];
              return (
                <li key={path} className="files-item" title={path}>
                  <div className="files-head">
                    <FileIcon size={14} />
                    <span className="mono strong files-name">{fileName(path)}</span>
                    {f && !failedLoad(f) && <span className="muted small">{sizeText(f.size)}</span>}
                    <div className="spacer" />
                    <button className="tb-btn" onClick={() => remove(path)} disabled={busy} title={t("files.remove")} aria-label={t("files.removeFile", { name: fileName(path) })}>
                      <CloseIcon size={12} />
                    </button>
                  </div>
                  {!f ? (
                    <p className="muted small">{t("common.checking")}</p>
                  ) : failedLoad(f) ? (
                    <p className="inline-error">
                      <AlertIcon size={14} /> {f.failed}
                    </p>
                  ) : (
                    <FileDetails
                      f={f}
                      attached={attached}
                      onSaveOriginal={() => saveOriginal(path)}
                      extracted={extracted?.path === path ? extracted : null}
                    />
                  )}
                  {r && (
                    <p className={`files-result small ${r.state}`}>
                      {r.state === "signing" ? (
                        <span className="muted">{t("common.signing")}</span>
                      ) : r.state === "done" ? (
                        <>
                          <CheckIcon size={13} />
                          <span>{tx("files.signedAs", { name: <span className="mono">{r.name}</span> })}</span>
                          <button className="link" onClick={() => api.revealFile(r.output)}>
                            {t("common.showInFolder")}
                          </button>
                        </>
                      ) : (
                        <>
                          <AlertIcon size={13} />
                          <span>{t("files.failed", { message: r.message })}</span>
                        </>
                      )}
                    </p>
                  )}
                </li>
              );
            })}
          </ul>

          {batchError && (
            <p className="inline-error">
              <AlertIcon size={14} /> {batchError}
            </p>
          )}

          <div className="files-options">
            <div className="segmented" role="radiogroup" aria-label={t("files.mode")}>
              <button role="radio" aria-checked={!attached} className={!attached ? "on" : ""} onClick={() => setAttached(false)} disabled={busy}>
                {t("files.detached")}
              </button>
              <button role="radio" aria-checked={attached} className={attached ? "on" : ""} onClick={() => setAttached(true)} disabled={busy}>
                {t("files.attached")}
              </button>
            </div>
            <p className="muted small">{attached ? t("files.attachedHelp") : t("files.detachedHelp")}</p>
            {props.tsaUrl && (
              <label className="check-row" title={props.tsaUrl}>
                <input type="checkbox" checked={useTs} onChange={(e) => setUseTs(e.target.checked)} disabled={busy} />
                {t("files.timestamp")}
              </label>
            )}
            {props.certs === null ? (
              <p className="muted small">{t("signer.looking")}</p>
            ) : !cert ? (
              <div className="warn-row">
                <AlertIcon size={14} />
                <div>
                  <strong>{t("signer.noCert")}</strong>
                  <span>{t("signer.plugIn")}</span>
                  <button className="link" onClick={props.onRefreshCerts}>
                    {t("common.checkAgain")}
                  </button>
                </div>
              </div>
            ) : props.certs.length > 1 ? (
              <select value={props.certIndex} onChange={(e) => props.setCertIndex(Number(e.target.value))} disabled={busy} aria-label={t("common.certificate")}>
                {props.certs.map((c, i) => (
                  <option key={i} value={i}>
                    {c.name} — {c.issuer}
                  </option>
                ))}
              </select>
            ) : (
              <p className="small">
                {t("common.signer")}: <strong>{cert.name}</strong> <span className="muted">· {cert.issuer}</span>
              </p>
            )}
            {cert?.expired && (
              <p className="inline-error">
                <AlertIcon size={14} /> {t("signer.expiredBody", { date: cert.validUntil })}
              </p>
            )}
            <p className="muted small">{t("files.format")}</p>
          </div>

          <div className="dialog-actions">
            <button className="btn" onClick={add} disabled={busy}>
              {t("files.add")}
            </button>
            <div className="spacer" />
            <button className="btn" onClick={onClose} disabled={busy}>
              {t("common.close")}
            </button>
            <button className="btn primary" onClick={() => setStep({ kind: "pin" })} disabled={busy || !signable.length || !cert || cert.expired}>
              {step.kind === "running" ? t("common.signing") : t("files.signN", { n: signable.length })}
            </button>
          </div>
        </div>
      </div>

      {(step.kind === "pin" || step.kind === "signing") && cert && (
        <PinDialog
          cert={cert}
          docName={signable.length === 1 ? fileName(signable[0]) : t("files.pinFiles", { n: signable.length })}
          busy={step.kind === "signing"}
          error={step.kind === "pin" ? step.error : undefined}
          onCancel={() => setStep({ kind: "idle" })}
          onSubmit={sign}
        />
      )}
    </div>
  );
}

function FileDetails(props: { f: FileInfo; attached: boolean; onSaveOriginal: () => void; extracted: { output?: string; error?: string } | null }) {
  const { f } = props;
  const sigName = f.signaturePath ? fileName(f.signaturePath) : null;
  const replaced = f.kind === "file" && (props.attached ? f.hasP7m : f.hasP7s);
  return (
    <>
      {f.sha256 && (
        <p className="files-hash small">
          <span className="muted">SHA-256</span> <span className="mono">{f.sha256}</span>
        </p>
      )}
      {f.kind === "signature" && (
        <p className="small muted">
          {f.signedPath ? t("files.signedFile", { name: fileName(f.signedPath) }) : f.check?.attached ? t("files.inside") : t("files.signedFileMissing", { name: fileName(f.path).replace(/\.p7s$/i, "") })}
        </p>
      )}
      {f.kind === "file" && !f.check && !f.error && <p className="small muted">{t("files.noSignature")}</p>}
      {f.kind === "file" && sigName && <p className="small muted">{t("files.signatureNext", { name: sigName })}</p>}
      {f.error && (
        <p className="inline-error">
          <AlertIcon size={14} /> {t("files.readFailed", { message: translateMessage(f.error) })}
        </p>
      )}
      {f.check && (
        <ul className="sig-list">
          <SignatureItem s={f.check} file />
        </ul>
      )}
      {f.kind === "signature" && f.check?.attached && (
        <div className="files-extract">
          <button className="btn" onClick={props.onSaveOriginal}>
            {t("files.saveOriginal")}
          </button>
          {props.extracted?.output && (
            <span className="small">
              <CheckIcon size={13} /> {tx("files.savedOriginal", { file: <span className="mono">{fileName(props.extracted.output)}</span> })}{" "}
              <button className="link" onClick={() => api.revealFile(props.extracted!.output!)}>
                {t("common.showInFolder")}
              </button>
            </span>
          )}
          {props.extracted?.error && <span className="small bad">{props.extracted.error}</span>}
        </div>
      )}
      {replaced && <p className="small bad">{t("files.replaces", { name: `${f.name}.${props.attached ? "p7m" : "p7s"}` })}</p>}
    </>
  );
}
