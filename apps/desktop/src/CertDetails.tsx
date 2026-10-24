// "Certificate details": everything public about the selected DSC, and saving
// the certificate (never a key) as .cer, .pem or .p7b
// (`certificate_details` / `export_certificate` in src-tauri/src/certs.rs).

import { useEffect, useState } from "react";
import * as api from "./api";
import type { Cert, CertDetails, ExportFormat, NamedOid } from "./api";
import { daysLeftText } from "./expiry";
import { AlertIcon, CheckIcon } from "./icons";
import "./certdetails.css";

const named = (o: NamedOid) => (o.name ? `${o.name} (${o.oid})` : o.oid);

function Fingerprint({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () =>
    navigator.clipboard.writeText(value).then(
      () => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      },
      () => {},
    );
  return (
    <>
      <dt>{label}</dt>
      <dd className="fp">
        <span className="mono">{value}</span>
        <button className="link" onClick={copy} aria-label={`Copy ${label} fingerprint`}>
          {copied ? (
            <>
              <CheckIcon size={12} /> Copied
            </>
          ) : (
            "Copy"
          )}
        </button>
      </dd>
    </>
  );
}

export function CertDetailsDialog({ cert, onClose }: { cert: Cert; onClose: () => void }) {
  const [details, setDetails] = useState<CertDetails | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<string | null>(null);

  useEffect(() => {
    api.certificateDetails(cert.id, cert.driverPath).then(setDetails, (e) => setError(api.errorOf(e).message));
  }, [cert.id, cert.driverPath]);

  // Captured first, so Esc closes this dialog and not the Settings panel under it.
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      e.stopPropagation();
      if (!saving) onClose();
    };
    window.addEventListener("keydown", k, true);
    return () => window.removeEventListener("keydown", k, true);
  }, [onClose, saving]);

  const save = async (format: ExportFormat) => {
    setSaving(true);
    setError(null);
    try {
      const path = await api.exportCertificate(cert.id, cert.driverPath, format);
      if (path) setSaved(path);
    } catch (e) {
      setError(api.errorOf(e).message);
    } finally {
      setSaving(false);
    }
  };

  const d = details;
  return (
    <div className="backdrop" onPointerDown={(e) => e.target === e.currentTarget && !saving && onClose()}>
      <div className="dialog cert-dialog" role="dialog" aria-modal="true" aria-label="Certificate details">
        <div className="dialog-title">
          <h2>Certificate details</h2>
        </div>
        <div className="dialog-body">
          {!d && !error && <p className="muted">Reading the certificate…</p>}
          {d && (
            <>
              <dl className="kv">
                <dt>Name</dt>
                <dd className="strong">{d.name}</dd>
                {d.organization && (
                  <>
                    <dt>Organisation</dt>
                    <dd>{d.organization}</dd>
                  </>
                )}
                {d.subjectSerial && (
                  <>
                    <dt title="Subject serialNumber attribute; Indian DSCs usually hold a hash of the PAN here">Serial (PAN hash)</dt>
                    <dd className="mono">{d.subjectSerial}</dd>
                  </>
                )}
                {d.email && (
                  <>
                    <dt>Email</dt>
                    <dd>{d.email}</dd>
                  </>
                )}
                <dt>Issuer</dt>
                <dd title={d.issuer}>{d.issuerName}</dd>
                <dt>Serial number</dt>
                <dd className="mono">{d.serial}</dd>
                <dt>Valid from</dt>
                <dd>{d.validFrom}</dd>
                <dt>Valid until</dt>
                <dd className={d.daysLeft < 0 ? "bad" : undefined}>
                  {d.validUntil} <span className="muted">· {daysLeftText(d.daysLeft)}</span>
                </dd>
                <dt>Key</dt>
                <dd>{d.key}</dd>
                <dt>Key usage</dt>
                <dd>{d.keyUsage ? d.keyUsage.join(", ") : "Not restricted"}</dd>
                {d.extendedKeyUsage.length > 0 && (
                  <>
                    <dt>Extended usage</dt>
                    <dd>{d.extendedKeyUsage.map(named).join(", ")}</dd>
                  </>
                )}
                <dt>Policies</dt>
                <dd>
                  {d.policies.length === 0
                    ? "None"
                    : d.policies.map((p) => (
                        <div key={p.oid}>
                          {p.name ? (
                            <>
                              {p.name} <span className="mono muted">{p.oid}</span>
                            </>
                          ) : (
                            <span className="mono">{p.oid}</span>
                          )}
                        </div>
                      ))}
                </dd>
                <Fingerprint label="SHA-1" value={d.sha1} />
                <Fingerprint label="SHA-256" value={d.sha256} />
              </dl>

              <h4 className="cert-h">Chain</h4>
              <ol className="cert-chain">
                <li>
                  <strong>{d.name}</strong>
                  <span className="muted small">Your certificate</span>
                </li>
                {d.chain.map((c, i) => (
                  <li key={i}>
                    <span>{c.name}</span>
                    <span className="muted small">
                      {c.name === c.issuer ? "Root" : "CA"} · valid until {c.validUntil}
                      {c.builtIn ? " · built into TrackMySign" : ""}
                    </span>
                  </li>
                ))}
              </ol>
              {d.chain.length === 0 && <p className="muted small">The token holds no issuer certificates for this DSC.</p>}
              <p className="muted small">Only the public certificate is saved. The private key never leaves the token.</p>
            </>
          )}
          {error && (
            <p className="inline-error">
              <AlertIcon size={14} /> {error}
            </p>
          )}
          {saved && (
            <div className="file-row mono" title={saved}>
              <CheckIcon size={14} />
              <span>{saved}</span>
            </div>
          )}
          <div className="dialog-actions cert-actions">
            <button className="btn" disabled={!d || saving} onClick={() => save("der")}>
              Save certificate (.cer)
            </button>
            <button className="btn" disabled={!d || saving} onClick={() => save("pem")}>
              Save as PEM (.pem)
            </button>
            {d && d.chain.length > 0 && (
              <button className="btn" disabled={saving} onClick={() => save("chain")}>
                Save full chain (.p7b)
              </button>
            )}
            <div className="spacer" />
            <button className="btn primary" autoFocus onClick={onClose} disabled={saving}>
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
