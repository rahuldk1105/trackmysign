// GST portal signing: the Settings section that turns the local signer on,
// the status-bar item, and the approval dialog shown for every request the
// portal page sends (`portal_*` commands in src-tauri/src/portal.rs).

import { useCallback, useEffect, useRef, useState } from "react";
import * as api from "./api";
import type { ApiError, PinStatus, PortalCert, PortalRequest, PortalStatus } from "./api";
import { Modal } from "./App";
import { daysLeftText } from "./expiry";
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
    <button className={`sb-item portal-sb ${on ? "ok" : "bad"}`} onClick={onClick} title={status.error ?? "GST portal signing (Settings)"}>
      Portal signing: {on ? `on (port ${status.port})` : "not running"}
    </button>
  );
}

const host = (origin: string) => origin.replace(/^https:\/\//, "");

const KIND: Record<PortalRequest["kind"], string> = {
  registration: "DSC registration (your PAN)",
  digest: "Return or form (its hash)",
  text: "Text",
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
        setCertError(api.errorOf(e).message);
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
      <Modal title="The GST portal stopped waiting" icon={<AlertIcon size={16} />} onClose={props.onDone}>
        <p>The portal page was closed or waited too long, so nothing was signed. Start again from the portal.</p>
        <div className="dialog-actions">
          <div className="spacer" />
          <button className="btn primary" autoFocus onClick={props.onDone}>
            Close
          </button>
        </div>
      </Modal>
    );
  }

  const locked = error?.kind === "pinLocked" || (!error && !!pinState?.locked);
  const warning = pinState?.locked
    ? "The token PIN is locked. Contact your DSC provider to unlock it."
    : pinState?.finalTry
      ? "One attempt left before the token locks!"
      : pinState?.countLow
        ? "Careful: few attempts left before the token locks."
        : null;
  return (
    <Modal title={`${host(request.origin)} wants to sign with your DSC`} icon={<ShieldIcon size={16} />} onClose={busy ? undefined : cancel}>
      <p>Sign only if you started this on the GST portal just now.</p>
      <dl className="kv compact">
        <dt>Site</dt>
        <dd className="strong">{request.origin}</dd>
        <dt>PAN</dt>
        <dd className="mono">{request.pan || "not given"}</dd>
        <dt>Signing</dt>
        <dd>{KIND[request.kind]}</dd>
        <dt>Data</dt>
        <dd className="mono wrap portal-data">{request.toBeSigned}</dd>
      </dl>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          sign();
        }}
      >
        <label htmlFor="portal-cert">Certificate</label>
        {certs === null ? (
          <p className="muted small">Reading the token…</p>
        ) : certs.length === 0 ? (
          <div className="setting-row">
            <span className="small bad">{certError ?? "No certificate found. Plug in your DSC token."}</span>
            <button type="button" className="btn" onClick={loadCerts}>
              <RefreshIcon size={14} /> Check again
            </button>
          </div>
        ) : (
          <select id="portal-cert" value={certId} onChange={(e) => setCertId(e.target.value)} disabled={busy}>
            {certs.map((c) => (
              <option key={c.id} value={c.id} disabled={!usable(c)}>
                {c.name} · {c.issuer} · {c.expired ? "expired" : daysLeftText(c.daysLeft)}
                {c.matchesPan ? " · matches PAN" : ""}
              </option>
            ))}
          </select>
        )}
        {cert && !cert.matchesPan && request.pan && (
          <p className="muted small">
            This certificate does not show PAN {request.pan}. Use it only if it is the DSC registered for this PAN on the portal.
          </p>
        )}
        <label htmlFor="portal-pin">PIN</label>
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
            <AlertIcon size={14} /> {error.message}
          </p>
        ) : warning ? (
          <p className="inline-error">
            <AlertIcon size={14} /> {warning}
          </p>
        ) : (
          <p className="muted small">The signature goes back to the portal page only. The PIN is never saved.</p>
        )}
        <div className="dialog-actions">
          <div className="spacer" />
          <button type="button" className="btn" onClick={cancel} disabled={busy}>
            Cancel
          </button>
          <button type="submit" className="btn primary" disabled={!cert || !pin || busy || locked}>
            {busy ? "Signing…" : "Sign"}
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
      setError(api.errorOf(e).message);
      api.portalStatus().then(props.onStatus, () => {});
    } finally {
      setBusy(false);
    }
  };

  return (
    <section>
      <h3>GST portal signing</h3>
      {!status?.enabled ? (
        <>
          <p className="muted small">
            Lets the GST portal (gst.gov.in) ask TrackMySign for DSC signatures, in place of emSigner. TrackMySign then listens on this computer
            only (127.0.0.1), answers only gst.gov.in pages, and signs each request only after you approve it with your PIN.
          </p>
          <p className="muted small">
            Turning it on adds a certificate made for this computer to your user's trusted certificates, so the browser accepts the connection.
            {/mac/i.test(navigator.platform)
              ? " macOS asks for your password."
              : /linux/i.test(navigator.platform)
                ? " On Linux it goes into Chrome's and Firefox's certificate lists (needs certutil, from libnss3-tools); restart Firefox afterwards."
                : " Windows asks you to confirm."}{" "}
            The certificate can
            only vouch for 127.0.0.1, and the key that made it is deleted at once. Works while TrackMySign is running, also in the background (see Background below).
          </p>
          {status?.certificateLeft ? (
            <div className="setting-row">
              <span className="small bad">The certificate from before is still trusted.</span>
              <button className="btn" onClick={() => run(api.portalDisable)} disabled={busy}>
                Remove certificate
              </button>
            </div>
          ) : (
            <button className="btn" onClick={() => run(api.portalEnable)} disabled={busy || !status}>
              {busy ? "Waiting for confirmation…" : "Enable portal signing"}
            </button>
          )}
        </>
      ) : (
        <>
          <dl className="kv">
            <dt>Status</dt>
            <dd className={status.port !== null ? "ok" : "bad"}>
              {status.port !== null ? `On · wss://127.0.0.1:${status.port}` : (status.error ?? "Not running")}
            </dd>
            {status.validUntil && (
              <>
                <dt>Certificate</dt>
                <dd>Valid until {status.validUntil}</dd>
              </>
            )}
          </dl>
          {status.taken.length > 0 && status.port !== null && (
            <p className="muted small">
              Port {status.taken.join(", ")} is used by another program, probably emSigner. The portal tries it first; if emSigner answers
              there, the portal uses emSigner. Quit emSigner to sign with TrackMySign.
            </p>
          )}
          <label htmlFor="portal-version">emSigner version reported to the portal</label>
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
              Apply
            </button>
          </div>
          <p className="muted small">
            The portal only talks to the version it expects ({status.defaultVersion} at the time of writing). Change it if the portal says
            “Please install and use correct version of emSigner”.
          </p>
          {status.log.length > 0 && (
            <>
              <h4>Recent activity</h4>
              <ul className="portal-log mono">
                {status.log.slice(-6).map((l, i) => (
                  <li key={i}>{l}</li>
                ))}
              </ul>
            </>
          )}
          <button className="btn" onClick={() => run(api.portalDisable)} disabled={busy}>
            {busy ? "Waiting for confirmation…" : "Disable and remove"}
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
