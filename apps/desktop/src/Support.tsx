// Help & support: a support report the user reads in full before copying or
// saving it (`support_report` in src-tauri/src/support.rs). Nothing is sent
// anywhere; "Open GitHub issue" only opens the issue form with the version
// filled in, and the user pastes the report there.

import { useEffect, useState } from "react";
import * as api from "./api";
import type { SupportInclude } from "./api";
import { currentLang, t, type MessageKey } from "./i18n";
import { errorText } from "./i18n/errors";
import { lastUpdateCheck } from "./updater";
import { AlertIcon, CheckIcon } from "./icons";
import "./support.css";

const OPEN = "trackmysign-support-report";

/** Opens the support report from anywhere, an error message say. */
export function openSupportReport() {
  window.dispatchEvent(new Event(OPEN));
}

/** Whether the support report is open; opened by [`openSupportReport`] too. */
export function useSupportReport(): [boolean, (open: boolean) => void] {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    const show = () => setOpen(true);
    window.addEventListener(OPEN, show);
    return () => window.removeEventListener(OPEN, show);
  }, []);
  return [open, setOpen];
}

/** "Report a problem", next to an error. */
export function ReportProblemLink() {
  return (
    <button type="button" className="link report-link" onClick={openSupportReport}>
      {t("support.reportProblem")}
    </button>
  );
}

/** Settings kept by the window that the report mentions. */
export interface SupportSettings {
  timestamp: boolean;
  tsaUrl: string;
  ltv: boolean;
  outDir: string;
  autoUpdate: boolean;
  language: string;
}

/** The last update check, in English like the rest of the report; none in the Store build. */
function updaterText(auto: boolean): string | null {
  if (__STORE__) return null;
  return lastUpdateCheck() ?? (auto ? "Not checked since the app started" : "Not checked; the check on launch is turned off");
}

const INCLUDE: { key: keyof SupportInclude; label: MessageKey; hint: MessageKey }[] = [
  { key: "names", label: "support.includeNames", hint: "support.includeNamesHint" },
  { key: "serials", label: "support.includeSerials", hint: "support.includeSerialsHint" },
  { key: "paths", label: "support.includePaths", hint: "support.includePathsHint" },
];

export function SupportDialog(props: { settings: SupportSettings; onClose: () => void }) {
  const { onClose } = props;
  // As they were when the dialog opened.
  const [settings] = useState(props.settings);
  const [include, setInclude] = useState<SupportInclude>({ names: false, serials: false, paths: false });
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setText(null);
    setError(null);
    setDone(null);
    api
      .supportReport({
        include,
        timestamp: settings.timestamp,
        tsaUrl: settings.tsaUrl,
        ltv: settings.ltv,
        outDir: settings.outDir,
        autoUpdate: settings.autoUpdate,
        updater: updaterText(settings.autoUpdate),
        locale: navigator.language,
        language: settings.language === "system" ? `system (${currentLang()})` : settings.language,
      })
      .then(
        (r) => live && setText(r),
        (e) => live && setError(errorText(api.errorOf(e))),
      );
    return () => {
      live = false;
    };
  }, [include, settings]);

  // Captured first, so Esc closes this dialog and not a panel under it.
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      e.stopPropagation();
      onClose();
    };
    window.addEventListener("keydown", k, true);
    return () => window.removeEventListener("keydown", k, true);
  }, [onClose]);

  const run = async (action: () => Promise<string | null>) => {
    setError(null);
    setDone(null);
    try {
      setDone(await action());
    } catch (e) {
      setError(errorText(api.errorOf(e)));
    }
  };
  const copy = () =>
    run(async () => {
      try {
        await navigator.clipboard.writeText(text ?? "");
      } catch {
        throw { kind: "other", message: t("support.copyFailed") };
      }
      return t("support.copied");
    });
  const save = () =>
    run(async () => {
      const path = await api.pickSupportPath();
      if (!path) return null;
      await api.supportSave(path, text ?? "");
      return t("support.saved", { path });
    });
  const issue = () =>
    run(async () => {
      await api.supportOpenIssue();
      return t("support.issueOpened");
    });

  return (
    <div className="backdrop" onPointerDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="dialog support-dialog" role="dialog" aria-modal="true" aria-label={t("support.title")}>
        <div className="dialog-title">
          <h2>{t("support.title")}</h2>
        </div>
        <div className="dialog-body">
          <p className="small">{t("support.intro")}</p>
          <div className="support-include">
            {INCLUDE.map((o) => (
              <label key={o.key} className="check-row" title={t(o.hint)}>
                <input type="checkbox" checked={include[o.key]} onChange={(e) => setInclude({ ...include, [o.key]: e.target.checked })} />
                {t(o.label)}
              </label>
            ))}
          </div>
          <textarea
            className="support-preview"
            readOnly
            value={text ?? ""}
            placeholder={error ? "" : t("support.building")}
            aria-label={t("support.preview")}
            spellCheck={false}
          />
          {error && (
            <p className="inline-error">
              <AlertIcon size={14} /> {error}
            </p>
          )}
          {done && (
            <p className="inline-note">
              <CheckIcon size={14} /> <span className="support-done">{done}</span>
            </p>
          )}
          <div className="dialog-actions">
            <button className="btn" onClick={copy} disabled={!text}>
              {t("support.copy")}
            </button>
            <button className="btn" onClick={save} disabled={!text}>
              {t("support.save")}
            </button>
            <button className="btn" onClick={issue} title={t("support.openIssueHint")}>
              {t("support.openIssue")}
            </button>
            <div className="spacer" />
            <button className="btn primary" autoFocus onClick={onClose}>
              {t("common.close")}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/** Settings → Help & support. */
export function HelpSettings() {
  const [count, setCount] = useState<number | null>(null);
  useEffect(() => {
    api.supportLogCount().then(setCount, () => setCount(null));
  }, []);
  const clear = async () => {
    await api.supportClearLog().catch(() => {});
    setCount(0);
  };
  return (
    <section>
      <h3>{t("support.section")}</h3>
      <p className="muted small">{t("support.sectionHint")}</p>
      <button className="btn" onClick={openSupportReport}>
        {t("support.create")}
      </button>
      <div className="setting-row support-log">
        <span className="muted small">{count ? t("support.logCount", { n: count }) : t("support.logEmpty")}</span>
        <button className="btn" onClick={clear} disabled={!count}>
          {t("support.clearLog")}
        </button>
      </div>
    </section>
  );
}
