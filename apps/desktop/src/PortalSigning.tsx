// GST portal signing: the Settings section that turns the local signer on,
// the status-bar item, and the approval dialog shown for every request the
// portal page sends (`portal_*` commands in src-tauri/src/portal.rs).

import { useCallback, useEffect, useRef, useState } from "react";
import * as api from "./api";
import type { ApiError, PinStatus, PortalCert, PortalRequest, PortalStatus } from "./api";
import { Modal } from "./App";
import { daysLeftText } from "./expiry";
import { t, type MessageKey } from "./i18n";
import { errorText, translateMessage } from "./i18n/errors";
import { AlertIcon, RefreshIcon, ShieldIcon } from "./icons";
import "./portal.css";

/** Listener status, and the request waiting for the user. */
export function usePortal() {
  const [status, setStatus] = useState<PortalStatus | null>(null);
  const [request, setRequest] = useState<(PortalRequest & { gone?: boolean }) | null>(null);
  const refresh = useCallback(() => {
    api.portalStatus().then(setStatus, () => {});
  }, []);
  useEffect(() => {
    refresh();
    api.portalPending().then((r) => r && setRequest(r), () => {});
    const offs = [
      api.onPortalRequest((r) => {
        setRequest(r);
        refresh();
      }),
      api.onPortalClosed((id) => {
        setRequest((cur) => (cur && cur.id === id ? { ...cur, gone: true } : cur));
        refresh();
      }),
    ];
    return () => offs.forEach((p) => p.then((off) => off()));
  }, [refresh]);
  return { status, setStatus, refresh, request, done: () => setRequest(null) };
}

export function PortalStatusItem({ status, onClick }: { status: PortalStatus | null; onClick: () => void }) {
  if (!status?.enabled) return null;
  const on = status.port !== null;
  return (
    <button className={`sb-item portal-sb ${on ? "ok" : "bad"}`} onClick={onClick} title={status.error ? translateMessage(status.error) : t("portal.statusTitle")}>
      {on ? t("portal.statusOn", { port: status.port! }) : t("portal.statusOff")}
    </button>
  );
}

const host = (origin: string) => origin.replace(/^https:\/\//, "");

const KIND: Record<PortalRequest["kind"], MessageKey> = {
  registration: "portal.kindRegistration",
  digest: "portal.kindDigest",
  text: "portal.kindText",
};

export function PortalDialog(props: { request: PortalRequest & { gone?: boolean }; onDone: () => void }) {
  const { request } = props;
  const [certs, setCerts] = useState<PortalCert[] | null>(null);
  const [certError, setCertError] = useState<string | null>(null);
  const [certId, setCertId] = useState("");
  const [pin, setPin] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [pinState, setPinState] = useState<PinStatus | null>(null);
  const input = useRef<HTMLInputElement>(null);

  const usable = useCallback((c: PortalCert) => c.canSign && !(request.expiryCheck && c.expired), [request.expiryCheck]);
  const loadCerts = useCallback(() => {
    setCerts(null);
    setCertError(null);
    api.portalCertificates(request.pan).then(
      (list) => {
        setCerts(list);
        const pick = list.find((c) => c.matchesPan && usable(c)) ?? list.find(usable);
        setCertId(pick?.id ?? "");
      },
      (e) => {
        setCerts([]);
        setCertError(errorText(api.errorOf(e)));
      },
    );
  }, [request.pan, usable]);
  useEffect(loadCerts, [loadCerts]);

  const cert = certs?.find((c) => c.id === certId);
  useEffect(() => {
    setPinState(null);
    if (cert) api.pinStatus(cert.id, cert.driverPath).then(setPinState, () => {});
    input.current?.focus();
  }, [cert]);

  const cancel = () => {
    api.portalCancel(request.id);
    props.onDone();
  };
  const sign = async () => {
    if (!cert || !pin || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.portalSign(request.id, cert.id, cert.driverPath, pin);
      props.onDone();
    } catch (e) {
      setError(api.errorOf(e));
      setPin("");
      setBusy(false);
      input.current?.focus();
    }
  };

  if (request.gone && !busy) {
    return (
      <Modal title={t("portal.goneTitle")} icon={<AlertIcon size={16} />} onClose={props.onDone}>
        <p>{t("portal.goneBody")}</p>
        <div className="dialog-actions">
          <div className="spacer" />
          <button className="btn primary" autoFocus onClick={props.onDone}>
            {t("common.close")}
          </button>
        </div>
      </Modal>
    );
  }

  const locked = error?.kind === "pinLocked" || (!error && !!pinState?.locked);
  const warning = pinState?.locked
    ? t("pin.locked")
    : pinState?.finalTry
      ? t("pin.finalTry")
      : pinState?.countLow
        ? t("pin.countLow")
        : null;
  return (
    <Modal title={t("portal.title", { host: host(request.origin) })} icon={<ShieldIcon size={16} />} onClose={busy ? undefined : cancel}>
      <p>{t("portal.onlyIf")}</p>
      <dl className="kv compact">
        <dt>{t("portal.site")}</dt>
        <dd className="strong">{request.origin}</dd>
        <dt>{t("portal.pan")}</dt>
        <dd className="mono">{request.pan || t("portal.notGiven")}</dd>
        <dt>{t("portal.signing")}</dt>
        <dd>{t(KIND[request.kind])}</dd>
        <dt>{t("portal.data")}</dt>
        <dd className="mono wrap portal-data">{request.toBeSigned}</dd>
      </dl>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          sign();
        }}
      >
        <label htmlFor="portal-cert">{t("common.certificate")}</label>
        {certs === null ? (
          <p className="muted small">{t("portal.reading")}</p>
        ) : certs.length === 0 ? (
          <div className="setting-row">
            <span className="small bad">{certError ?? t("portal.noCert")}</span>
            <button type="button" className="btn" onClick={loadCerts}>
              <RefreshIcon size={14} /> {t("common.checkAgain")}
            </button>
          </div>
        ) : (
          <select id="portal-cert" value={certId} onChange={(e) => setCertId(e.target.value)} disabled={busy}>
            {certs.map((c) => (
              <option key={c.id} value={c.id} disabled={!usable(c)}>
                {c.name} · {c.issuer} · {c.expired ? t("expiry.expired") : daysLeftText(c.daysLeft)}
                {c.matchesPan ? ` · ${t("portal.matchesPan")}` : ""}
              </option>
            ))}
          </select>
        )}
        {cert && !cert.matchesPan && request.pan && (
          <p className="muted small">{t("portal.panMismatch", { pan: request.pan })}</p>
        )}
        <label htmlFor="portal-pin">{t("common.pin")}</label>
        <input
          id="portal-pin"
          ref={input}
          type="password"
          className={`pin ${error?.kind === "wrongPin" || error?.kind === "pinLocked" ? "invalid" : ""}`}
          value={pin}
          onChange={(e) => setPin(e.target.value)}
          disabled={busy || locked || !cert}
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
          <p className="muted small">{t("portal.pinHint")}</p>
        )}
        <div className="dialog-actions">
          <div className="spacer" />
          <button type="button" className="btn" onClick={cancel} disabled={busy}>
            {t("common.cancel")}
          </button>
          <button type="submit" className="btn primary" disabled={!cert || !pin || busy || locked}>
            {busy ? t("common.signing") : t("common.sign")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function PortalSettings(props: { status: PortalStatus | null; onStatus: (s: PortalStatus) => void }) {
  const { status } = props;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [version, setVersion] = useState(status?.version ?? "");
  useEffect(() => setVersion(status?.version ?? ""), [status?.version]);

  const run = async (f: () => Promise<PortalStatus>) => {
    setBusy(true);
    setError(null);
    try {
      props.onStatus(await f());
    } catch (e) {
      setError(errorText(api.errorOf(e)));
      api.portalStatus().then(props.onStatus, () => {});
    } finally {
      setBusy(false);
    }
  };

  return (
    <section>
      <h3>{t("portal.settings")}</h3>
      {!status?.enabled ? (
        <>
          <p className="muted small">{t("portal.intro")}</p>
          <p className="muted small">
            {t("portal.introTrust", { confirm: /mac/i.test(navigator.platform) ? t("portal.macConfirm") : t("portal.windowsConfirm") })}
          </p>
          {status?.certificateLeft ? (
            <div className="setting-row">
              <span className="small bad">{t("portal.certLeft")}</span>
              <button className="btn" onClick={() => run(api.portalDisable)} disabled={busy}>
                {t("portal.removeCert")}
              </button>
            </div>
          ) : (
            <button className="btn" onClick={() => run(api.portalEnable)} disabled={busy || !status}>
              {busy ? t("portal.waiting") : t("portal.enable")}
            </button>
          )}
        </>
      ) : (
        <>
          <dl className="kv">
            <dt>{t("common.status")}</dt>
            <dd className={status.port !== null ? "ok" : "bad"}>
              {status.port !== null
                ? t("portal.on", { port: status.port })
                : status.error
                  ? translateMessage(status.error)
                  : t("portal.notRunning")}
            </dd>
            {status.validUntil && (
              <>
                <dt>{t("common.certificate")}</dt>
                <dd>{t("portal.validUntil", { date: status.validUntil })}</dd>
              </>
            )}
          </dl>
          {status.taken.length > 0 && status.port !== null && (
            <p className="muted small">{t("portal.taken", { ports: status.taken.join(", ") })}</p>
          )}
          <label htmlFor="portal-version">{t("portal.version")}</label>
          <div className="setting-row">
            <input
              id="portal-version"
              className="mono portal-version"
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              placeholder={status.defaultVersion}
              spellCheck={false}
            />
            <button className="btn" onClick={() => run(() => api.portalSetVersion(version))} disabled={busy || version.trim() === status.version}>
              {t("portal.apply")}
            </button>
          </div>
          <p className="muted small">{t("portal.versionHint", { version: status.defaultVersion })}</p>
          {status.log.length > 0 && (
            <>
              <h4>{t("portal.recent")}</h4>
              <ul className="portal-log mono">
                {status.log.slice(-6).map((l, i) => (
                  <li key={i}>{l}</li>
                ))}
              </ul>
            </>
          )}
          <button className="btn" onClick={() => run(api.portalDisable)} disabled={busy}>
            {busy ? t("portal.waiting") : t("portal.disable")}
          </button>
        </>
      )}
      {error && (
        <p className="inline-error">
          <AlertIcon size={14} /> {error}
        </p>
      )}
    </section>
  );
}
