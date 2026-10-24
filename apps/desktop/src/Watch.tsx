// Watch folder: the Settings section, the status-bar item while watching,
// and the PIN dialog that starts a session (`watch_*` commands in
// src-tauri/src/watch.rs).

import { useCallback, useEffect, useRef, useState } from "react";
import * as api from "./api";
import type { ApiError, Cert, ImageChoice, PinStatus, WatchConfig, WatchLogEntry, WatchStatus } from "./api";
import { Modal } from "./App";
import { currentLang, t, type MessageKey } from "./i18n";
import { errorText, translateMessage } from "./i18n/errors";
import { describePage, toWatchPreset, type Preset } from "./presets";
import { sameStyle, type StampStyle } from "./stamp";
import { AlertIcon, FolderIcon } from "./icons";
import "./watch.css";

const baseName = (path: string) => path.split(/[\\/]/).filter(Boolean).pop() ?? path;

/** Session status, read again whenever the backend says it changed. */
export function useWatch() {
  const [status, setStatus] = useState<WatchStatus | null>(null);
  const refresh = useCallback(() => {
    api.watchStatus().then(setStatus, () => {});
  }, []);
  useEffect(() => {
    refresh();
    const off = api.onWatchChanged(refresh);
    return () => {
      off.then((f) => f());
    };
  }, [refresh]);
  return { status, setStatus, refresh };
}

const ENDED: Record<NonNullable<WatchStatus["ended"]>["kind"], MessageKey | null> = {
  timeUp: "watch.endedTimeUp",
  slept: "watch.endedSlept",
  dailyLimit: "watch.endedDailyLimit",
  token: null,
  folder: null,
  other: null,
};

function endedText(e: NonNullable<WatchStatus["ended"]>): string {
  const key = ENDED[e.kind];
  return key ? t(key) : t("watch.endedProblem", { message: translateMessage(e.message) });
}

export function WatchStatusItem(props: { status: WatchStatus | null; dismissed: boolean; onOpen: () => void; onStop: () => void }) {
  const s = props.status;
  if (s?.active) {
    return (
      <span className="sb-item watch-sb">
        <button className="watch-sb-text ok" onClick={props.onOpen} title={s.active.folder}>
          {t("watch.on", { folder: baseName(s.active.folder), n: s.active.signed })}
        </button>
        <button className="watch-sb-stop" onClick={props.onStop}>
          {t("watch.stopShort")}
        </button>
      </span>
    );
  }
  if (s?.ended && !props.dismissed) {
    return (
      <span className="sb-item watch-sb">
        <button className="watch-sb-text bad" onClick={props.onOpen} title={endedText(s.ended)}>
          {t("watch.statusEnded")}
        </button>
      </span>
    );
  }
  return null;
}

const DURATIONS: { minutes: number; label: MessageKey }[] = [
  { minutes: 60, label: "watch.hour1" },
  { minutes: 480, label: "watch.hours8" },
  { minutes: 0, label: "watch.untilStopped" },
];

const KIND: Record<WatchLogEntry["kind"], MessageKey> = {
  started: "watch.kindStarted",
  stopped: "watch.kindStopped",
  signed: "watch.kindSigned",
  failed: "watch.kindFailed",
  skipped: "watch.kindSkipped",
};

function clock(unix: number, withDate = false): string {
  const d = new Date(unix * 1000);
  const time = d.toLocaleTimeString(currentLang(), { hour: "2-digit", minute: "2-digit" });
  return withDate ? `${d.toLocaleDateString(currentLang(), { day: "2-digit", month: "short" })} ${time}` : time;
}

function samePreset(a: api.WatchPreset, p: Preset): boolean {
  return (
    a.reason === p.reason &&
    a.location === p.location &&
    (p.image === undefined || a.image === p.image) &&
    (p.style === undefined || sameStyle(a.style, p.style)) &&
    JSON.stringify(a.placement) === JSON.stringify(p.placement)
  );
}

export function WatchSettings(props: {
  status: WatchStatus | null;
  onStatus: (s: WatchStatus) => void;
  presets: Preset[];
  defaults: { reason: string; location: string; image: ImageChoice; style: StampStyle | null; tsaUrl: string };
  /** The certificate a session would sign with. */
  cert?: Cert;
}) {
  const { status } = props;
  const [draft, setDraft] = useState<WatchConfig | null>(status?.config ?? null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [pinOpen, setPinOpen] = useState(false);
  const saved = status?.config;
  useEffect(() => {
    if (saved) setDraft(saved);
  }, [saved]);

  if (!status || !draft) return null;
  const active = status.active;
  const locked = !!active || busy;

  const save = async (patch: Partial<WatchConfig>) => {
    const next = { ...draft, ...patch, preset: { ...draft.preset, ...patch.preset } };
    setDraft(next);
    setError(null);
    try {
      props.onStatus(await api.watchSave(next));
    } catch (e) {
      setError(errorText(api.errorOf(e)));
    }
  };
  const chooseInput = async () => {
    const dir = await api.pickFolder(draft.input || null);
    if (dir) save({ input: dir });
  };
  const chooseOutput = async () => {
    const dir = await api.pickFolder(draft.output || draft.input || null);
    if (dir) save({ output: dir });
  };
  const choosePreset = (name: string) => {
    const preset = props.presets.find((p) => p.name === name) ?? null;
    const { pages, timestamp, ltv } = draft.preset;
    save({ preset: toWatchPreset(preset, props.defaults, { pages, timestamp, ltv }) });
  };
  const stop = async () => {
    setBusy(true);
    try {
      props.onStatus(await api.watchStop());
    } finally {
      setBusy(false);
    }
  };

  const p = draft.preset;
  const listed = props.presets.find((x) => x.name === p.name);
  const box = p.placement
    ? `${describePage(p.placement.page)}, ${p.placement.w} × ${p.placement.h} mm`
    : t("watch.boxDefault");
  const outputPath = draft.output || (draft.input ? `${draft.input.replace(/[\\/]+$/, "")}${draft.input.includes("\\") ? "\\" : "/"}signed` : "");
  return (
    <section>
      <h3>{t("watch.title")}</h3>
      <p className="muted small">{t("watch.intro")}</p>
      <p className="watch-trust small">
        <AlertIcon size={14} /> {t("watch.trust")}
      </p>

      {active ? (
        <>
          <dl className="kv">
            <dt>{t("common.status")}</dt>
            <dd className="ok">{t("watch.on", { folder: baseName(active.folder), n: active.signed })}</dd>
            <dt>{t("watch.folder")}</dt>
            <dd className="mono wrap">{active.folder}</dd>
            <dt>{t("watch.output")}</dt>
            <dd className="mono wrap">{active.output}</dd>
            <dt>{t("watch.ends")}</dt>
            <dd>{active.until ? t("watch.until", { time: clock(active.until) }) : t("watch.untilQuit")}</dd>
          </dl>
          <button className="btn" onClick={stop} disabled={busy}>
            {t("watch.stop")}
          </button>
        </>
      ) : (
        <>
          {status.ended && (
            <p className="inline-error">
              <AlertIcon size={14} /> {endedText(status.ended)}
            </p>
          )}
          <label>{t("watch.folder")}</label>
          <div className="setting-row out-dir">
            <span className={draft.input ? "mono" : "muted small"}>{draft.input || t("watch.noFolder")}</span>
            <button className="btn" onClick={chooseInput} disabled={locked}>
              <FolderIcon size={14} /> {draft.input ? t("settings.change") : t("settings.choose")}
            </button>
          </div>

          <label>{t("watch.output")}</label>
          <div className="segmented" role="radiogroup" aria-label={t("watch.output")}>
            <button role="radio" aria-checked={!draft.output} className={!draft.output ? "on" : ""} onClick={() => save({ output: "" })} disabled={locked}>
              {t("watch.outputInside")}
            </button>
            <button role="radio" aria-checked={!!draft.output} className={draft.output ? "on" : ""} onClick={chooseOutput} disabled={locked}>
              {t("watch.outputFolder")}
            </button>
          </div>
          {outputPath && (
            <div className="setting-row out-dir">
              <span className="mono">{outputPath}</span>
              {draft.output && (
                <button className="btn" onClick={chooseOutput} disabled={locked}>
                  {t("settings.change")}
                </button>
              )}
            </div>
          )}
          <label className="check-row">
            <input type="checkbox" checked={draft.moveDone} onChange={(e) => save({ moveDone: e.target.checked })} disabled={locked} />
            {t("watch.moveDone")}
          </label>
          <p className="muted small">{draft.moveDone ? t("watch.failedHint") : t("watch.keepHint")}</p>

          <label htmlFor="watch-preset">{t("watch.preset")}</label>
          <select id="watch-preset" value={listed ? p.name : ""} onChange={(e) => choosePreset(e.target.value)} disabled={locked}>
            <option value="">{t("watch.defaults")}</option>
            {props.presets.map((x) => (
              <option key={x.name} value={x.name}>
                {x.name}
              </option>
            ))}
          </select>
          <p className="muted small">
            {[p.reason || t("watch.noReason"), p.location, box].filter(Boolean).join(" · ")}
            {p.name && (!listed || !samePreset(p, listed)) && <> {t("watch.presetCopy", { name: p.name })}</>}
          </p>

          <label htmlFor="watch-pages">{t("watch.pages")}</label>
          <input
            id="watch-pages"
            className="mono"
            value={p.pages}
            placeholder="all, 1-3"
            onChange={(e) => setDraft({ ...draft, preset: { ...p, pages: e.target.value } })}
            onBlur={() => p.pages !== saved?.preset.pages && save({})}
            disabled={locked}
            spellCheck={false}
          />
          <p className="muted small">{t("watch.pagesHint")}</p>

          <label className="check-row">
            <input
              type="checkbox"
              checked={!!p.timestamp}
              onChange={(e) => save({ preset: { ...p, timestamp: e.target.checked ? props.defaults.tsaUrl : null } })}
              disabled={locked}
            />
            {t("watch.timestamp")}
          </label>
          <label className="check-row">
            <input type="checkbox" checked={p.ltv} onChange={(e) => save({ preset: { ...p, ltv: e.target.checked } })} disabled={locked} />
            {t("watch.ltv")}
          </label>

          <label htmlFor="watch-limit">{t("watch.dailyLimit")}</label>
          <input
            id="watch-limit"
            className="watch-limit"
            type="number"
            min={0}
            value={draft.dailyLimit}
            onChange={(e) => setDraft({ ...draft, dailyLimit: Math.max(0, Math.floor(Number(e.target.value) || 0)) })}
            onBlur={() => draft.dailyLimit !== saved?.dailyLimit && save({})}
            disabled={locked}
          />
          <p className="muted small">{t("watch.dailyLimitHint", { n: status.signedToday })}</p>

          <label>{t("watch.duration")}</label>
          <div className="segmented" role="radiogroup" aria-label={t("watch.duration")}>
            {DURATIONS.map((d) => (
              <button
                key={d.minutes}
                role="radio"
                aria-checked={draft.minutes === d.minutes}
                className={draft.minutes === d.minutes ? "on" : ""}
                onClick={() => save({ minutes: d.minutes })}
                disabled={locked}
              >
                {t(d.label)}
              </button>
            ))}
          </div>
          <label className="check-row">
            <input type="checkbox" checked={draft.stopOnSleep} onChange={(e) => save({ stopOnSleep: e.target.checked })} disabled={locked} />
            {t("watch.stopOnSleep")}
          </label>
          <p className="muted small">{t("watch.quitHint")}</p>

          {error && (
            <p className="inline-error">
              <AlertIcon size={14} /> {error}
            </p>
          )}
          <div className="setting-row">
            <span className="muted small">{props.cert ? "" : t("watch.needCert")}</span>
            <button className="btn primary" onClick={() => setPinOpen(true)} disabled={locked || !draft.input || !props.cert || !!error}>
              {t("watch.start")}
            </button>
          </div>
        </>
      )}

      <h4 className="watch-log-head">{t("watch.log")}</h4>
      {status.log.length === 0 ? (
        <p className="muted small">{t("watch.logEmpty")}</p>
      ) : (
        <ul className="watch-log">
          {status.log.map((l, i) => (
            <li key={i} className={l.kind} title={[l.file, l.output].filter(Boolean).join("\n")}>
              <span className="mono muted">{clock(l.time, true)}</span>
              <span className="watch-log-kind">{t(KIND[l.kind])}</span>
              <span className="mono">{l.file ? baseName(l.file) : ""}</span>
              {l.message && <span className="small watch-log-msg">{translateMessage(l.message)}</span>}
            </li>
          ))}
        </ul>
      )}

      {pinOpen && props.cert && (
        <WatchPinDialog
          cert={props.cert}
          config={draft}
          onCancel={() => setPinOpen(false)}
          onStarted={(s) => {
            setPinOpen(false);
            props.onStatus(s);
          }}
        />
      )}
    </section>
  );
}

function WatchPinDialog(props: { cert: Cert; config: WatchConfig; onCancel: () => void; onStarted: (s: WatchStatus) => void }) {
  const [pin, setPin] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [pinState, setPinState] = useState<PinStatus | null>(null);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    api.pinStatus(props.cert.id, props.cert.driverPath).then(setPinState, () => {});
    input.current?.focus();
  }, [props.cert.id, props.cert.driverPath]);

  const start = async () => {
    if (!pin || busy) return;
    setBusy(true);
    setError(null);
    try {
      props.onStarted(await api.watchStart(props.cert.id, props.cert.driverPath, pin));
    } catch (e) {
      setError(api.errorOf(e));
      setPin("");
      setBusy(false);
      input.current?.focus();
    }
  };
  const locked = error?.kind === "pinLocked" || (!error && !!pinState?.locked);
  const warning = pinState?.locked ? t("pin.locked") : pinState?.finalTry ? t("pin.finalTry") : pinState?.countLow ? t("pin.countLow") : null;
  const duration = DURATIONS.find((d) => d.minutes === props.config.minutes);
  return (
    <Modal title={t("watch.pinTitle")} icon={<AlertIcon size={16} />} onClose={busy ? undefined : props.onCancel}>
      <p>{t("watch.pinIntro")}</p>
      <dl className="kv compact">
        <dt>{t("common.signer")}</dt>
        <dd className="strong">{props.cert.name}</dd>
        <dt>{t("common.token")}</dt>
        <dd>{props.cert.tokenLabel}</dd>
        <dt>{t("watch.folder")}</dt>
        <dd className="mono ellipsis" title={props.config.input}>
          {props.config.input}
        </dd>
        <dt>{t("watch.duration")}</dt>
        <dd>{duration ? t(duration.label) : t("watch.minutes", { n: props.config.minutes })}</dd>
        <dt>{t("watch.dailyLimit")}</dt>
        <dd>{props.config.dailyLimit || t("watch.noLimit")}</dd>
      </dl>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          start();
        }}
      >
        <label htmlFor="watch-pin">{t("common.pin")}</label>
        <input
          id="watch-pin"
          ref={input}
          type="password"
          className={`pin ${error?.kind === "wrongPin" || error?.kind === "pinLocked" ? "invalid" : ""}`}
          value={pin}
          onChange={(e) => setPin(e.target.value)}
          disabled={busy || locked}
          autoComplete="off"
          spellCheck={false}
        />
        {error ? (
          <p className="inline-error">
            <AlertIcon size={14} /> {errorText(error)}
          </p>
        ) : warning ? (
          <p className="inline-error">
            <AlertIcon size={14} /> {warning}
          </p>
        ) : (
          <p className="muted small">{t("watch.pinHint")}</p>
        )}
        <div className="dialog-actions">
          <div className="spacer" />
          <button type="button" className="btn" onClick={props.onCancel} disabled={busy}>
            {t("common.cancel")}
          </button>
          <button type="submit" className="btn primary" disabled={!pin || busy || locked}>
            {busy ? t("watch.starting") : t("watch.startShort")}
          </button>
        </div>
      </form>
    </Modal>
  );
}
