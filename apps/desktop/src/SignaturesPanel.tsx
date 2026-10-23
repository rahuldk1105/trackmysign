// Inspector section listing the signatures already in the open document,
// each checked by the Rust core (`verify_pdf`).

import { useEffect, useState } from "react";
import * as api from "./api";
import type { SignatureCheck } from "./api";
import { AlertIcon, ChevronDownIcon, ChevronUpIcon, ShieldIcon } from "./icons";
import "./signatures.css";

type Tone = "ok" | "bad" | "neutral";

function verdict(s: SignatureCheck): { tone: Tone; label: string } {
  if (s.status === "invalid") return { tone: "bad", label: "Invalid signature" };
  if (s.status === "unknown") return { tone: "neutral", label: "Could not be verified" };
  if (s.changes === "content") return { tone: "bad", label: "Document changed after signing" };
  return { tone: "ok", label: "Valid signature" };
}

function coverage(s: SignatureCheck): string {
  const later = `${s.laterRevisions} later revision${s.laterRevisions === 1 ? "" : "s"}`;
  switch (s.changes) {
    case "none":
      return "Whole document, unchanged";
    case "signatures":
      return `${later}: only signatures added`;
    case "form":
      return `${later}: form filled in or comments added`;
    case "content":
      return `${later}: content changed`;
    default:
      return `${later} (${s.bytesAfter.toLocaleString()} bytes), not analysed`;
  }
}

function SignatureItem({ s }: { s: SignatureCheck }) {
  const [open, setOpen] = useState(false);
  const { tone, label } = verdict(s);
  return (
    <li className={`sig-item ${tone}`}>
      <div className="sig-head">
        {tone === "ok" ? <ShieldIcon size={14} /> : <AlertIcon size={14} />}
        <strong>{label}</strong>
      </div>
      <dl className="kv">
        <dt>Signed by</dt>
        <dd className="strong">
          {s.signer ?? "Unknown"}
          {s.organization && <span className="sig-org"> · {s.organization}</span>}
        </dd>
        {s.issuer && (
          <>
            <dt>Issuer</dt>
            <dd>{s.issuer}</dd>
          </>
        )}
        {s.signingTime && (
          <>
            <dt>Signed at</dt>
            <dd className={s.timeInValidity === false ? "bad" : undefined}>{s.signingTime}</dd>
          </>
        )}
        {s.reason && (
          <>
            <dt>Reason</dt>
            <dd>{s.reason}</dd>
          </>
        )}
        {s.location && (
          <>
            <dt>Location</dt>
            <dd>{s.location}</dd>
          </>
        )}
        <dt>Coverage</dt>
        <dd className={s.changes === "content" ? "bad" : undefined}>{coverage(s)}</dd>
        <dt>Trust</dt>
        <dd className={s.trust === "cca" ? "ok" : undefined}>
          {s.trust === "cca" ? "Chains to CCA India 2022" : "Not checked"}
        </dd>
      </dl>
      {s.notes.length > 0 && (
        <ul className="sig-notes">
          {s.notes.map((n, i) => (
            <li key={i}>{n}</li>
          ))}
        </ul>
      )}
      <button className="link sig-more" onClick={() => setOpen(!open)} aria-expanded={open}>
        {open ? <ChevronUpIcon size={13} /> : <ChevronDownIcon size={13} />}
        {open ? "Fewer details" : "More details"}
      </button>
      {open && (
        <dl className="kv sig-details">
          <dt>Field</dt>
          <dd className="mono">{s.field}</dd>
          {s.certValidFrom && (
            <>
              <dt>Certificate</dt>
              <dd className={s.timeInValidity === false ? "bad" : undefined}>
                {s.certValidFrom} – {s.certValidUntil}
              </dd>
            </>
          )}
          <dt>Format</dt>
          <dd className="mono">{[s.subFilter, s.digest].filter(Boolean).join(", ") || "—"}</dd>
          {s.timestamped && (
            <>
              <dt>Timestamp</dt>
              <dd>Attached (not verified)</dd>
            </>
          )}
          {s.bytesAfter > 0 && (
            <>
              <dt>Added later</dt>
              <dd className="mono">{s.bytesAfter.toLocaleString()} bytes</dd>
            </>
          )}
          {s.chain.length > 0 && (
            <>
              <dt>Chain</dt>
              <dd>
                <ol className="sig-chain">
                  {s.chain.map((c, i) => (
                    <li key={i}>{c}</li>
                  ))}
                </ol>
              </dd>
            </>
          )}
        </dl>
      )}
    </li>
  );
}

export function SignaturesPanel({ path, password, count }: { path: string; password?: string; count: number }) {
  const [checks, setChecks] = useState<SignatureCheck[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setChecks(null);
    setError(null);
    api
      .verifyPdf(path, password)
      .then((c) => live && setChecks(c))
      .catch((e) => live && setError(api.errorOf(e).message));
    return () => {
      live = false;
    };
  }, [path, password]);

  if (count === 0 && (checks === null || checks.length === 0)) return null;
  return (
    <section className="signatures">
      <h3>Signatures{checks ? ` (${checks.length})` : ""}</h3>
      {error ? (
        <div className="warn-row">
          <AlertIcon size={14} />
          <div>
            <strong>Could not check signatures</strong>
            <span>{error}</span>
          </div>
        </div>
      ) : checks === null ? (
        <p className="muted small">Checking {count} signature{count === 1 ? "" : "s"}…</p>
      ) : (
        <ul className="sig-list">
          {checks.map((s) => (
            <SignatureItem key={s.field} s={s} />
          ))}
        </ul>
      )}
      <p className="muted small">Signing again keeps existing signatures valid.</p>
    </section>
  );
}
