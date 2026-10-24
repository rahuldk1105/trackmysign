// "Verify folder…": checks the signatures of every PDF in a folder
// (`verify_folder`), lists each result as it arrives, opens a file in the
// viewer on click and exports the whole check as a PDF report or CSV.
// The run lives in App, so it survives closing the dialog to look at a file.

import { useCallback, useEffect, useState } from "react";
import * as api from "./api";
import type { FolderFile, FolderStatus } from "./api";
import { t, tx, type MessageKey } from "./i18n";
import { errorText, translateMessage } from "./i18n/errors";
import { AlertIcon, CheckIcon, CloseIcon, FolderIcon } from "./icons";
import "./folder.css";

export interface FolderRun {
  /** Tells this run's updates from an earlier one's. */
  id: number;
  folder: string;
  recursive: boolean;
  /** Tried on protected PDFs; in memory only. */
  password: string;
  /** Relative paths in check order; `file` is set once checked. */
  items: { relative: string; file?: FolderFile }[] | null;
  running: boolean;
  stopped: boolean;
  error?: string;
}

type Filter = "all" | "problems" | "unsigned";

const STATUS: Record<FolderStatus, MessageKey> = {
  allValid: "folder.allValid",
  invalid: "folder.invalid",
  changed: "folder.changed",
  unsigned: "folder.statusUnsigned",
  unreadable: "folder.unreadable",
  password: "folder.needsPassword",
};

const tone = (s: FolderStatus) => (s === "allValid" ? "ok" : s === "invalid" || s === "changed" ? "bad" : s === "unsigned" ? "" : "warn");

/** Needs a look: not valid, or not checked at all. */
const isProblem = (s: FolderStatus) => s !== "allValid" && s !== "unsigned";

function shows(filter: Filter, f?: FolderFile): boolean {
  if (filter === "all") return true;
  if (!f) return false;
  return filter === "unsigned" ? f.status === "unsigned" : isProblem(f.status);
}

/** "7 files: 2 all valid, 2 with problems, 1 unsigned, 1 unreadable", as the PDF report says it. */
function summary(files: FolderFile[]): string {
  const count = (...s: FolderStatus[]) => files.filter((f) => s.includes(f.status)).length;
  const line = t("folder.summary", {
    n: files.length,
    valid: count("allValid"),
    problems: count("invalid", "changed"),
    unsigned: count("unsigned"),
    unreadable: count("unreadable"),
  });
  const locked = count("password");
  return locked ? `${line}, ${t("folder.summaryPassword", { n: locked })}` : line;
}

function fileName(path: string): string {
  return path.split(/[\\/]/).pop() ?? path;
}

/** Starts a check of `folder`; `setRun` receives every update. */
export async function startFolderRun(folder: string, recursive: boolean, password: string, setRun: (f: (r: FolderRun | null) => FolderRun | null) => void) {
  const id = Date.now();
  setRun(() => ({ id, folder, recursive, password, items: null, running: true, stopped: false }));
  const mine = (r: FolderRun | null) => r?.id === id;
  try {
    const stopped = await api.verifyFolder(folder, recursive, password, (p) =>
      setRun((r) => {
        if (!mine(r)) return r;
        if (p.state === "found") return { ...r!, items: p.files.map((relative) => ({ relative })) };
        const items = (r!.items ?? []).map((it, i) => (i === p.index ? { ...it, file: p.file } : it));
        return { ...r!, items };
      }),
    );
    setRun((r) => (mine(r) ? { ...r!, running: false, stopped } : r));
  } catch (e) {
    setRun((r) => (mine(r) ? { ...r!, running: false, error: errorText(api.errorOf(e)) } : r));
  }
}

export function FolderDialog(props: {
  run: FolderRun | null;
  /** Where the folder picker starts, and the folder offered before the first run. */
  folder: string | null;
  setRun: (f: (r: FolderRun | null) => FolderRun | null) => void;
  onOpen: (path: string, password?: string) => void;
  onClose: () => void;
}) {
  const { run, setRun, onClose } = props;
  const [folder, setFolder] = useState<string | null>(run?.folder ?? props.folder);
  const [recursive, setRecursive] = useState(run?.recursive ?? true);
  const [password, setPassword] = useState(run?.password ?? "");
  const [filter, setFilter] = useState<Filter>("all");
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const running = !!run?.running;

  // Captured first, so Esc closes this dialog and nothing under it.
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      e.stopPropagation();
      onClose();
    };
    window.addEventListener("keydown", k, true);
    return () => window.removeEventListener("keydown", k, true);
  }, [onClose]);

  const choose = async () => {
    const picked = await api.pickFolder(folder ?? props.folder);
    if (picked) setFolder(picked);
  };

  const start = useCallback(() => {
    if (!folder) return;
    setFilter("all");
    setSaved(null);
    setExportError(null);
    startFolderRun(folder, recursive, password, setRun);
  }, [folder, recursive, password, setRun]);

  const save = async (ext: "pdf" | "csv") => {
    if (!run) return;
    const output = await api.pickFolderExport(run.folder, ext);
    if (!output) return;
    setExporting(true);
    setExportError(null);
    try {
      await api.exportFolder(output, ext);
      setSaved(output);
    } catch (e) {
      setExportError(errorText(api.errorOf(e)));
    } finally {
      setExporting(false);
    }
  };

  const items = run?.items ?? [];
  const checked = items.flatMap((it) => (it.file ? [it.file] : []));
  const counts: Record<Filter, number> = {
    all: items.length,
    problems: checked.filter((f) => isProblem(f.status)).length,
    unsigned: checked.filter((f) => f.status === "unsigned").length,
  };
  const shown = items.filter((it) => shows(filter, it.file));
  const finished = run && !run.running && !run.error && run.items !== null;
  const changed = run && (folder !== run.folder || recursive !== run.recursive || password !== run.password);

  return (
    <div className="backdrop" onPointerDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="dialog folder-dialog" role="dialog" aria-modal="true" aria-label={t("folder.title")}>
        <div className="dialog-title">
          <h2>{t("folder.title")}</h2>
          <div className="spacer" />
          <button className="tb-btn" onClick={onClose} title={t("common.close")} aria-label={t("common.close")}>
            <CloseIcon />
          </button>
        </div>
        <div className="dialog-body">
          <div className="folder-pick">
            <div className="file-row mono" title={folder ?? undefined}>
              <FolderIcon size={14} />
              <span className={folder ? undefined : "muted"}>{folder ?? t("folder.none")}</span>
            </div>
            <button className="btn" onClick={choose} disabled={running}>
              {t("folder.choose")}
            </button>
          </div>
          <div className="folder-options">
            <label className="check-row">
              <input type="checkbox" checked={recursive} onChange={(e) => setRecursive(e.target.checked)} disabled={running} />
              {t("folder.subfolders")}
            </label>
            <div className="folder-password">
              <label htmlFor="folder-password">{t("folder.password")}</label>
              <input
                id="folder-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={running}
                autoComplete="off"
                title={t("folder.passwordHint")}
              />
            </div>
            <button className="btn primary" onClick={start} disabled={!folder || running}>
              {run && !changed ? t("folder.again") : t("folder.start")}
            </button>
          </div>

          {run && (
            <div className="folder-results">
              <div className="folder-status" aria-live="polite">
                {run.error ? (
                  <p className="inline-error">
                    <AlertIcon size={14} /> {run.error}
                  </p>
                ) : run.items === null ? (
                  <p className="muted">{t("folder.finding")}</p>
                ) : run.running ? (
                  <>
                    <p>{t("folder.progress", { done: checked.length, total: items.length })}</p>
                    <div className="folder-bar">
                      <i style={{ width: `${items.length ? (100 * checked.length) / items.length : 0}%` }} />
                    </div>
                  </>
                ) : items.length === 0 ? (
                  <p className="muted">{run.recursive ? t("folder.noPdfsDeep") : t("folder.noPdfs")}</p>
                ) : (
                  <p className="strong">
                    {summary(checked)}
                    {run.stopped && <span className="bad"> · {t("folder.stopped", { done: checked.length, total: items.length })}</span>}
                  </p>
                )}
              </div>

              {items.length > 0 && (
                <>
                  <div className="segmented folder-filter" role="radiogroup" aria-label={t("folder.filter")}>
                    {(["all", "problems", "unsigned"] as const).map((f) => (
                      <button key={f} role="radio" aria-checked={filter === f} className={filter === f ? "on" : ""} onClick={() => setFilter(f)}>
                        {t(`folder.filter.${f}`, { n: counts[f] })}
                      </button>
                    ))}
                  </div>
                  <div className="folder-table" role="table" aria-label={t("folder.title")}>
                    <div className="folder-row head" role="row">
                      <span role="columnheader">{t("folder.file")}</span>
                      <span role="columnheader">{t("folder.status")}</span>
                      <span role="columnheader" className="num">
                        {t("folder.signatures")}
                      </span>
                      <span role="columnheader">{t("folder.signedBy")}</span>
                    </div>
                    <div className="folder-rows">
                      {shown.length === 0 && <p className="muted small folder-empty">{t("folder.emptyFilter")}</p>}
                      {shown.map(({ relative, file }) => (
                        <button
                          key={relative}
                          role="row"
                          className={`folder-row ${file ? tone(file.status) : "waiting"}`}
                          disabled={!file}
                          onClick={() => file && props.onOpen(file.path, file.usedPassword ? run.password : undefined)}
                          title={file ? [t("folder.openHint", { name: fileName(relative) }), file.summary ?? (file.error && translateMessage(file.error))].filter(Boolean).join("\n") : relative}
                        >
                          <span role="cell" className="mono folder-name">
                            {relative}
                          </span>
                          <span role="cell" className="folder-state">
                            {!file ? (
                              <>
                                <i className="sq" /> {t("folder.waiting")}
                              </>
                            ) : (
                              <>
                                {file.status === "allValid" ? <CheckIcon size={12} /> : file.status !== "unsigned" && <AlertIcon size={12} />}
                                {t(STATUS[file.status])}
                              </>
                            )}
                          </span>
                          <span role="cell" className="num mono">
                            {file && (file.status === "unreadable" || file.status === "password" ? "—" : file.signatures)}
                          </span>
                          <span role="cell" className="folder-signers">
                            {file?.error ? <span className="muted">{translateMessage(file.error)}</span> : file?.signers.join(", ")}
                          </span>
                        </button>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </div>
          )}

          {exportError && <p className="inline-error">{t("folder.exportFailed", { message: exportError })}</p>}
          {saved && (
            <p className="folder-saved small">
              <CheckIcon size={13} />
              <span>{tx("folder.saved", { file: <span className="mono">{fileName(saved)}</span> })}</span>
              <button className="link" onClick={() => api.revealFile(saved)}>
                {t("common.showInFolder")}
              </button>
            </p>
          )}

          <div className="dialog-actions">
            <button className="btn" onClick={() => save("pdf")} disabled={!finished || !items.length || exporting} title={t("folder.exportHint")}>
              {t("report.export")}
            </button>
            <button className="btn" onClick={() => save("csv")} disabled={!finished || !items.length || exporting}>
              {t("folder.exportCsv")}
            </button>
            <div className="spacer" />
            {running ? (
              <button className="btn" onClick={() => api.stopFolderVerify()}>
                {t("folder.stop")}
              </button>
            ) : (
              <button className="btn" onClick={onClose}>
                {t("common.close")}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
