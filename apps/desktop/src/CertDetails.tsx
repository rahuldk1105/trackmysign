// "Certificate details": everything public about the selected DSC, and saving
// the certificate (never a key) as .cer, .pem or .p7b
// (`certificate_details` / `export_certificate` in src-tauri/src/certs.rs).

import { useEffect, useState } from "react";
import * as api from "./api";
import type { Cert, CertDetails, ExportFormat, NamedOid } from "./api";
import { daysLeftText } from "./expiry";
import { t, type MessageKey } from "./i18n";
import { errorText } from "./i18n/errors";
import { AlertIcon, CheckIcon } from "./icons";
import "./certdetails.css";

/** Display names from trackmysign_core::certdetails, which are English. Class 1/2/3 stay as they are. */
const NAMES: Record<string, MessageKey> = {
  "Digital signature": "usage.digitalSignature",
  "Non-repudiation": "usage.nonRepudiation",
  "Key encipherment": "usage.keyEncipherment",
  "Data encipherment": "usage.dataEncipherment",
  "Key agreement": "usage.keyAgreement",
  "Certificate signing": "usage.certSign",
  "CRL signing": "usage.crlSign",
  "Encipher only": "usage.encipherOnly",
  "Decipher only": "usage.decipherOnly",
  "TLS server": "usage.tlsServer",
  "Client authentication": "usage.clientAuth",
  "Code signing": "usage.codeSigning",
  "Email protection": "usage.emailProtection",
  "Time stamping": "usage.timeStamping",
  "OCSP signing": "usage.ocspSigning",
  "Document signing": "usage.documentSigning",
  "Document signing (Microsoft)": "usage.documentSigningMs",
  "Smart card logon": "usage.smartCard",
  "Adobe authentic documents": "usage.adobe",
  "Any purpose": "usage.anyPurpose",
  "India PKI certificate policy (CA)": "policy.indiaPkiCa",
  "eKYC single factor": "policy.ekycSingle",
  "eKYC multi factor": "policy.ekycMulti",
};

const display = (name: string) => (NAMES[name] ? t(NAMES[name]) : name);
const named = (o: NamedOid) => (o.name ? `${display(o.name)} (${o.oid})` : o.oid);

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
        <button className="link" onClick={copy} aria-label={t("cert.copyFingerprint", { label })}>
          {copied ? (
            <>
              <CheckIcon size={12} /> {t("cert.copied")}
            </>
          ) : (
            t("cert.copy")
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
    api.certificateDetails(cert.id, cert.driverPath).then(setDetails, (e) => setError(errorText(api.errorOf(e))));
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
      setError(errorText(api.errorOf(e)));
    } finally {
      setSaving(false);
    }
  };

  const d = details;
  return (
    <div className="backdrop" onPointerDown={(e) => e.target === e.currentTarget && !saving && onClose()}>
      <div className="dialog cert-dialog" role="dialog" aria-modal="true" aria-label={t("cert.details")}>
        <div className="dialog-title">
          <h2>{t("cert.details")}</h2>
        </div>
        <div className="dialog-body">
          {!d && !error && <p className="muted">{t("cert.reading")}</p>}
          {d && (
            <>
              <dl className="kv">
                <dt>{t("common.name")}</dt>
                <dd className="strong">{d.name}</dd>
                {d.organization && (
                  <>
                    <dt>{t("cert.organisation")}</dt>
                    <dd>{d.organization}</dd>
                  </>
                )}
                {d.subjectSerial && (
                  <>
                    <dt title={t("cert.panSerialHint")}>{t("cert.panSerial")}</dt>
                    <dd className="mono">{d.subjectSerial}</dd>
                  </>
                )}
                {d.email && (
                  <>
                    <dt>{t("cert.email")}</dt>
                    <dd>{d.email}</dd>
                  </>
                )}
                <dt>{t("common.issuer")}</dt>
                <dd title={d.issuer}>{d.issuerName}</dd>
                <dt>{t("cert.serial")}</dt>
                <dd className="mono">{d.serial}</dd>
                <dt>{t("cert.validFrom")}</dt>
                <dd>{d.validFrom}</dd>
                <dt>{t("common.validUntil")}</dt>
                <dd className={d.daysLeft < 0 ? "bad" : undefined}>
                  {d.validUntil} <span className="muted">· {daysLeftText(d.daysLeft)}</span>
                </dd>
                <dt>{t("cert.key")}</dt>
                <dd>{d.key}</dd>
                <dt>{t("cert.keyUsage")}</dt>
                <dd>{d.keyUsage ? d.keyUsage.map(display).join(", ") : t("cert.notRestricted")}</dd>
                {d.extendedKeyUsage.length > 0 && (
                  <>
                    <dt>{t("cert.extendedUsage")}</dt>
                    <dd>{d.extendedKeyUsage.map(named).join(", ")}</dd>
                  </>
                )}
                <dt>{t("cert.policies")}</dt>
                <dd>
                  {d.policies.length === 0
                    ? t("cert.none")
                    : d.policies.map((p) => (
                        <div key={p.oid}>
                          {p.name ? (
                            <>
                              {display(p.name)} <span className="mono muted">{p.oid}</span>
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

              <h4 className="cert-h">{t("sig.chain")}</h4>
              <ol className="cert-chain">
                <li>
                  <strong>{d.name}</strong>
                  <span className="muted small">{t("cert.yours")}</span>
                </li>
                {d.chain.map((c, i) => (
                  <li key={i}>
                    <span>{c.name}</span>
                    <span className="muted small">
                      {t("cert.chainValid", { kind: t(c.name === c.issuer ? "cert.root" : "cert.ca"), date: c.validUntil })}
                      {c.builtIn ? ` · ${t("cert.builtIn")}` : ""}
                    </span>
                  </li>
                ))}
              </ol>
              {d.chain.length === 0 && <p className="muted small">{t("cert.noIssuers")}</p>}
              <p className="muted small">{t("cert.publicOnly")}</p>
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
              {t("cert.saveDer")}
            </button>
            <button className="btn" disabled={!d || saving} onClick={() => save("pem")}>
              {t("cert.savePem")}
            </button>
            {d && d.chain.length > 0 && (
              <button className="btn" disabled={saving} onClick={() => save("chain")}>
                {t("cert.saveChain")}
              </button>
            )}
            <div className="spacer" />
            <button className="btn primary" autoFocus onClick={onClose} disabled={saving}>
              {t("common.close")}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
