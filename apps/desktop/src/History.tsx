// "Signing history": every signature made on this computer, by the app and
// the command line, from the log in the app's data folder. Search and
// filters; a row shows its details and opens the signed copy; the entries
// shown export as a PDF or CSV; the log's hash chain can be checked.
// The settings (keep a history, how long, clear) are in Settings.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import type { HistoryEntry, HistoryIntegrity, HistoryOutcome, HistorySettings, HistorySource, Retention } from "./api";
import { currentLang, t, tx, type MessageKey } from "./i18n";
import { errorText, translateMessage } from "./i18n/errors";
import { AlertIcon, CheckIcon, CloseIcon } from "./icons";
import { ShareActions } from "./Share";
import "./history.css";

const IST = "Asia/Kolkata";
const SOURCES: HistorySource[] = ["manual", "batch", "watch", "portal"];
const RETENTION: Retention[] = ["forever", "year", "days90"];

/** A note about the history itself rather than a signature. */
const isMarker = (e: HistoryEntry) => ["cleared", "pruned", "paused", "resumed"].includes(e.action);

function fileName(path: string): string {
  return path.split(/[\\/]/).pop() ?? path;
}

/** "24 Oct 2026, 14:03 IST". */
function istTime(iso: string, seconds = false): string {
  const d = new Date(iso);
  const s = d.toLocaleString(currentLang(), {
    timeZone: IST,
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    ...(seconds ? { second: "2-digit" } : {}),
  });
  return `${s} IST`;
}

/** The day in India, `YYYY-MM-DD`, to compare with the date filters. */
function istDay(iso: string): string {
  return new Date(iso).toLocaleDateString("en-CA", { timeZone: IST });
}

function utcTime(iso: string): string {
  return `${new Date(iso).toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

function documentName(e: HistoryEntry): string {
  if (e.input?.path) return fileName(e.input.path);
  if (e.portal) return t("history.portalDoc", { pan: e.portal.pan });
  return "";
}

function actionText(e: HistoryEntry): string {
  return t(`history.action.${e.action}` as MessageKey);
}

interface Filters {
  query: string;
  from: string;
  to: string;
  source: HistorySource | "all";
  outcome: HistoryOutcome | "all";
}

const NO_FILTERS: Filters = { query: "", from: "", to: "", source: "all", outcome: "all" };

/** As `trackmysign history` filters: notes about the history itself show
 *  only while no filter looks for signatures. */
function matches(e: HistoryEntry, f: Filters): boolean {
  const day = istDay(e.time);
  if ((f.from && day < f.from) || (f.to && day > f.to)) return false;
  const q = f.query.trim().toLowerCase();
  if (isMarker(e)) return f.source === "all" && f.outcome === "all" && !q;
  if (f.source !== "all" && e.source !== f.source) return false;
  if (f.outcome !== "all" && e.outcome !== f.outcome) return false;
  if (!q) return true;
  return [e.input?.path, e.output?.path, e.cert?.subject, e.cert?.organization, e.portal?.pan, e.origin].some((s) => s?.toLowerCase().includes(q));
}

export function HistoryDialog(props: { onOpen: (path: string) => void; onSettings: () => void; onClose: () => void }) {
  const { onClose } = props;
  const [entries, setEntries] = useState<HistoryEntry[] | null>(null);
  const [settings, setSettings] = useState<HistorySettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const [selected, setSelected] = useState<number | null>(null);
  const [integrity, setIntegrity] = useState<HistoryIntegrity | "checking" | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  const load = useCallback(() => {
    api
      .historyEntries()
      .then((e) => {
        setEntries(e);
        setError(null);
      })
      .catch((e) => setError(errorText(api.errorOf(e))));
    api.historySettings().then(setSettings, () => {});
  }, []);

  useEffect(() => {
    load();
    const off = api.onHistoryChanged(() => {
      load();
      setIntegrity(null);
    });
    return () => {
      off.then((f) => f());
    };
  }, [load]);

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

  // Newest first.
  const shown = useMemo(() => (entries ?? []).filter((e) => matches(e, filters)).reverse(), [entries, filters]);
  const current = shown.find((e) => e.seq === selected) ?? null;
  const set = (p: Partial<Filters>) => setFilters((f) => ({ ...f, ...p }));
  const filtered = JSON.stringify(filters) !== JSON.stringify(NO_FILTERS);

  const check = async () => {
    setIntegrity("checking");
    try {
      setIntegrity(await api.historyCheck());
    } catch (e) {
      setIntegrity(null);
      setError(errorText(api.errorOf(e)));
    }
  };

  const save = async (ext: "pdf" | "csv") => {
    const output = await api.pickHistoryExport(ext);
    if (!output) return;
    setExporting(true);
    setExportError(null);
    try {
      await api.historyExport(output, ext, shown.map((e) => e.seq));
      setSaved(output);
    } catch (e) {
      setExportError(errorText(api.errorOf(e)));
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="backdrop" onPointerDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="dialog history-dialog" role="dialog" aria-modal="true" aria-label={t("history.title")}>
        <div className="dialog-title">
          <h2>{t("history.title")}</h2>
          <div className="spacer" />
          <button className="tb-btn" onClick={onClose} title={t("common.close")} aria-label={t("common.close")}>
            <CloseIcon />
          </button>
        </div>
        <div className="dialog-body">
          {settings && !settings.enabled && (
            <p className="history-off small">
              <AlertIcon size={13} />
              <span>{t("history.off")}</span>
              <button className="link" onClick={props.onSettings}>
                {t("common.settings")}
              </button>
            </p>
          )}
          <div className="history-filters">
            <input
              type="search"
              className="history-search"
              value={filters.query}
              onChange={(e) => set({ query: e.target.value })}
              placeholder={t("history.search")}
              aria-label={t("history.search")}
            />
            <label className="history-date">
              <span>{t("history.from")}</span>
              <input type="date" value={filters.from} max={filters.to || undefined} onChange={(e) => set({ from: e.target.value })} />
            </label>
            <label className="history-date">
              <span>{t("history.to")}</span>
              <input type="date" value={filters.to} min={filters.from || undefined} onChange={(e) => set({ to: e.target.value })} />
            </label>
            <select value={filters.source} onChange={(e) => set({ source: e.target.value as Filters["source"] })} aria-label={t("history.source")}>
              <option value="all">{t("history.source.all")}</option>
              {SOURCES.map((s) => (
                <option key={s} value={s}>
                  {t(`history.source.${s}`)}
                </option>
              ))}
            </select>
            <select value={filters.outcome} onChange={(e) => set({ outcome: e.target.value as Filters["outcome"] })} aria-label={t("history.outcome")}>
              <option value="all">{t("history.outcome.all")}</option>
              <option value="signed">{t("history.signed")}</option>
              <option value="failed">{t("history.failed")}</option>
            </select>
            {filtered && (
              <button className="btn ghost" onClick={() => setFilters(NO_FILTERS)}>
                {t("common.reset")}
              </button>
            )}
          </div>

          {error ? (
            <p className="inline-error">
              <AlertIcon size={14} /> {error}
            </p>
          ) : entries === null ? (
            <p className="muted">{t("history.loading")}</p>
          ) : (
            <>
              <p className="muted small history-count">
                {filtered ? t("history.shownOf", { shown: shown.length, total: entries.length }) : t("history.count", { n: entries.length })}
              </p>
              <div className="history-table" role="table" aria-label={t("history.title")}>
                <div className="history-row head" role="row">
                  <span role="columnheader">{t("history.date")}</span>
                  <span role="columnheader">{t("common.document")}</span>
                  <span role="columnheader">{t("history.actionCol")}</span>
                  <span role="columnheader">{t("common.certificate")}</span>
                  <span role="columnheader">{t("history.outcome")}</span>
                </div>
                <div className="history-rows">
                  {shown.length === 0 && <p className="muted small history-empty">{entries.length ? t("history.emptyFilter") : t("history.empty")}</p>}
                  {shown.map((e) => (
                    <button
                      key={e.seq}
                      role="row"
                      className={`history-row ${e.outcome ?? "note"} ${e.seq === selected ? "on" : ""}`}
                      aria-selected={e.seq === selected}
                      onClick={() => setSelected(e.seq === selected ? null : e.seq)}
                      title={utcTime(e.time)}
                    >
                      <span role="cell" className="mono">
                        {istTime(e.time)}
                      </span>
                      <span role="cell" className="history-doc">
                        {documentName(e)}
                      </span>
                      <span role="cell">
                        {actionText(e)}
                        {e.source && e.source !== "manual" && e.source !== "portal" && <span className="muted"> · {t(`history.source.${e.source}`)}</span>}
                      </span>
                      <span role="cell">{e.cert?.subject}</span>
                      <span role="cell" className="history-outcome">
                        {e.outcome === "signed" ? (
                          <>
                            <CheckIcon size={12} /> {t("history.signed")}
                          </>
                        ) : e.outcome === "failed" ? (
                          <>
                            <AlertIcon size={12} /> {t("history.failed")}
                          </>
                        ) : (
                          e.removed !== undefined && <span className="muted">{t("history.removed", { n: e.removed })}</span>
                        )}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
              {current && <EntryDetails entry={current} onOpen={props.onOpen} />}
            </>
          )}

          {integrity && integrity !== "checking" && (
            <div className={`history-integrity ${integrity.problems.length ? "bad" : "ok"}`} aria-live="polite">
              <p>
                {integrity.problems.length ? <AlertIcon size={13} /> : <CheckIcon size={13} />}
                <span>
                  {integrity.problems.length ? t("history.notIntact", { n: integrity.problems.length }) : t("history.intact", { n: integrity.entries })}
                </span>
              </p>
              {integrity.problems.length > 0 && (
                <ul className="small">
                  {integrity.problems.map((p, i) => (
                    <li key={i}>{p.file ? t("history.problem", { file: p.file, line: p.line, message: translateMessage(p.message) }) : translateMessage(p.message)}</li>
                  ))}
                </ul>
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
            <button className="btn" onClick={check} disabled={integrity === "checking" || !entries?.length} title={t("history.checkHint")}>
              {integrity === "checking" ? t("common.checking") : t("history.check")}
            </button>
            <button className="btn" onClick={() => save("pdf")} disabled={!shown.length || exporting}>
              {t("history.exportPdf")}
            </button>
            <button className="btn" onClick={() => save("csv")} disabled={!shown.length || exporting}>
              {t("folder.exportCsv")}
            </button>
            <div className="spacer" />
            <button className="btn" onClick={onClose}>
              {t("common.close")}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function EntryDetails({ entry: e, onOpen }: { entry: HistoryEntry; onOpen: (path: string) => void }) {
  const rows: [string, React.ReactNode][] = [[t("history.time"), `${istTime(e.time, true)} · ${utcTime(e.time)}`]];
  rows.push([t("history.actionCol"), e.source ? `${actionText(e)} · ${t(`history.source.${e.source}`)}` : actionText(e)]);
  if (e.error) rows.push([t("history.error"), translateMessage(e.error)]);
  if (e.origin) rows.push([t("history.origin"), e.origin]);
  if (e.input?.path) rows.push([t("history.original"), <span className="mono">{e.input.path}</span>]);
  if (e.input?.sha256) rows.push([t("history.originalHash"), <span className="mono hash">{e.input.sha256}</span>]);
  if (e.output) rows.push([t("history.signedCopy"), <span className="mono">{e.output.path}</span>]);
  if (e.output?.sha256) rows.push([t("history.signedHash"), <span className="mono hash">{e.output.sha256}</span>]);
  if (e.portal) {
    rows.push([t("history.pan"), <span className="mono">{e.portal.pan}</span>]);
    rows.push([t("history.signedData"), e.portal.data ? <span className="mono hash">{e.portal.data}</span> : <span className="muted">{t("history.textHashed")}</span>]);
    rows.push([t("history.signedDataHash"), <span className="mono hash">{e.portal.sha256}</span>]);
  }
  if (e.cert) {
    rows.push([t("common.signer"), e.cert.organization ? `${e.cert.subject} (${e.cert.organization})` : e.cert.subject]);
    rows.push([t("common.issuer"), e.cert.issuer]);
    rows.push([t("history.serial"), <span className="mono">{e.cert.serial}</span>]);
    rows.push([t("history.fingerprint"), <span className="mono hash">{e.cert.fingerprint}</span>]);
  }
  if (e.pages?.length) rows.push([t("common.pages"), e.pages.join(", ")]);
  if (e.ctc) rows.push([t("ctc.title"), e.ctc.length ? e.ctc.join(", ") : t("placement.allPages")]);
  if (e.field) rows.push([t("common.field"), <span className="mono">{e.field}</span>]);
  if (e.reason) rows.push([t("common.reason"), e.reason]);
  if (e.location) rows.push([t("common.location"), e.location]);
  if (e.certify) rows.push([t("history.certification"), t("history.certifyLevel", { n: e.certify })]);
  if (e.timestamp || e.ltv) rows.push([t("history.timestampLtv"), [e.timestamp, e.ltv ? t("history.ltv") : null].filter(Boolean).join(" · ")]);
  rows.push([t("history.program"), `TrackMy Sign ${e.program}`]);
  const output = e.output?.path;
  return (
    <div className="history-details">
      <dl>
        {rows.map(([k, v]) => (
          <div key={k}>
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
      {output && e.outcome === "signed" && (
        <div className="history-file-actions">
          <button className="btn" onClick={() => onOpen(output)}>
            {t("history.openSigned")}
          </button>
          <button className="btn ghost" onClick={() => api.revealFile(output)}>
            {t("common.showInFolder")}
          </button>
        </div>
      )}
      {output && e.outcome === "signed" && <ShareActions key={output} paths={[output]} ghost />}
    </div>
  );
}

/** Settings → Signing history. */
export function HistorySettingsSection(props: { onOpenHistory: () => void }) {
  const [settings, setSettings] = useState<HistorySettings | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cleared, setCleared] = useState(false);

  useEffect(() => {
    api.historySettings().then(setSettings, (e) => setError(errorText(api.errorOf(e))));
  }, []);

  const update = async (enabled: boolean, retention: Retention) => {
    setError(null);
    try {
      setSettings(await api.historySetSettings(enabled, retention));
    } catch (e) {
      setError(errorText(api.errorOf(e)));
    }
  };

  const clear = async () => {
    setError(null);
    try {
      await api.historyClear();
      setConfirm(false);
      setCleared(true);
    } catch (e) {
      setError(errorText(api.errorOf(e)));
    }
  };

  return (
    <section>
      <h3>{t("history.title")}</h3>
      <label className="check-row">
        <input type="checkbox" checked={settings?.enabled ?? true} disabled={!settings} onChange={(e) => settings && update(e.target.checked, settings.retention)} />
        {t("settings.historyOn")}
      </label>
      <p className="muted small">{t("settings.historyHint")}</p>
      <label id="s-history-keep">{t("settings.historyKeep")}</label>
      <div className="segmented" role="radiogroup" aria-labelledby="s-history-keep">
        {RETENTION.map((r) => (
          <button
            key={r}
            role="radio"
            aria-checked={settings?.retention === r}
            className={settings?.retention === r ? "on" : ""}
            disabled={!settings}
            onClick={() => settings && update(settings.enabled, r)}
          >
            {t(`settings.retention.${r}`)}
          </button>
        ))}
      </div>
      {settings?.retention !== "forever" && settings && <p className="muted small">{t("settings.historyRetentionHint")}</p>}
      {confirm ? (
        <div className="history-confirm">
          <p className="small">{t("settings.historyClearConfirm")}</p>
          <div className="setting-row">
            <button className="btn danger" onClick={clear}>
              {t("settings.historyClearYes")}
            </button>
            <button className="btn ghost" onClick={() => setConfirm(false)}>
              {t("common.cancel")}
            </button>
          </div>
        </div>
      ) : (
        <div className="setting-row">
          {cleared ? (
            <span className="muted small">{t("settings.historyCleared")}</span>
          ) : (
            <span className="muted mono history-folder" title={settings?.folder}>
              {settings?.folder}
            </span>
          )}
          <button className="btn" onClick={props.onOpenHistory}>
            {t("settings.historyOpen")}
          </button>
          <button className="btn" onClick={() => setConfirm(true)}>
            {t("settings.historyClear")}
          </button>
        </div>
      )}
      {error && (
        <p className="inline-error">
          <AlertIcon size={14} /> {error}
        </p>
      )}
    </section>
  );
}
