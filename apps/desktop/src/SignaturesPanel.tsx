// Inspector section listing the signatures already in the open document,
// each checked by the Rust core (`verify_pdf`).

import { useEffect, useState } from "react";
import * as api from "./api";
import type { SignatureCheck } from "./api";
import { t, type MessageKey } from "./i18n";
import { errorText } from "./i18n/errors";
import { AlertIcon, ChevronDownIcon, ChevronUpIcon, ShieldIcon } from "./icons";
import "./signatures.css";

type Tone = "ok" | "bad" | "neutral";

function verdict(s: SignatureCheck): { tone: Tone; label: string } {
  if (s.status === "invalid") return { tone: "bad", label: t("sig.invalid") };
  if (s.status === "unknown") return { tone: "neutral", label: t("sig.unknown") };
  if (s.changes === "content") return { tone: "bad", label: t("sig.changed") };
  return { tone: "ok", label: s.certification ? t("sig.validCertification") : t("sig.valid") };
}

const ALLOWED: Record<NonNullable<SignatureCheck["certification"]>, MessageKey> = {
  1: "sig.allowed1",
  2: "sig.allowed2",
  3: "sig.allowed3",
};

function coverage(s: SignatureCheck): string {
  const later = t("sig.later", { n: s.laterRevisions });
  switch (s.changes) {
    case "none":
      return t("sig.whole");
    case "signatures":
      return t("sig.onlySignatures", { later });
    case "form":
      return t("sig.form", { later });
    case "content":
      return t("sig.content", { later });
    default:
      return t("sig.notAnalysed", { later, bytes: s.bytesAfter.toLocaleString() });
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
        <dt>{t("sig.signedBy")}</dt>
        <dd className="strong">
          {s.signer ?? t("sig.unknownSigner")}
          {s.organization && <span className="sig-org"> · {s.organization}</span>}
        </dd>
        {s.certification && (
          <>
            <dt>{t("sig.certifies")}</dt>
            <dd>{t("sig.level", { n: s.certification, allowed: t(ALLOWED[s.certification]) })}</dd>
          </>
        )}
        {s.issuer && (
          <>
            <dt>{t("common.issuer")}</dt>
            <dd>{s.issuer}</dd>
          </>
        )}
        {s.signingTime && (
          <>
            <dt>{t("sig.signedAt")}</dt>
            <dd className={s.timeInValidity === false ? "bad" : undefined}>{s.signingTime}</dd>
          </>
        )}
        {s.reason && (
          <>
            <dt>{t("common.reason")}</dt>
            <dd>{s.reason}</dd>
          </>
        )}
        {s.location && (
          <>
            <dt>{t("common.location")}</dt>
            <dd>{s.location}</dd>
          </>
        )}
        <dt>{t("sig.coverage")}</dt>
        <dd className={s.changes === "content" ? "bad" : undefined}>{coverage(s)}</dd>
        <dt>{t("sig.trust")}</dt>
        <dd className={s.trust === "cca" ? "ok" : undefined}>
          {s.trust === "cca" ? t("sig.cca") : t("sig.notChecked")}
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
        {open ? t("sig.fewer") : t("sig.more")}
      </button>
      {open && (
        <dl className="kv sig-details">
          <dt>{t("common.field")}</dt>
          <dd className="mono">{s.field}</dd>
          {s.certValidFrom && (
            <>
              <dt>{t("common.certificate")}</dt>
              <dd className={s.timeInValidity === false ? "bad" : undefined}>
                {s.certValidFrom} – {s.certValidUntil}
              </dd>
            </>
          )}
          <dt>{t("sig.format")}</dt>
          <dd className="mono">{[s.subFilter, s.digest].filter(Boolean).join(", ") || "—"}</dd>
          {s.timestamped && (
            <>
              <dt>{t("sig.timestamp")}</dt>
              <dd>{t("sig.attached")}</dd>
            </>
          )}
          {s.bytesAfter > 0 && (
            <>
              <dt>{t("sig.addedLater")}</dt>
              <dd className="mono">{t("sig.bytes", { n: s.bytesAfter.toLocaleString() })}</dd>
            </>
          )}
          {s.chain.length > 0 && (
            <>
              <dt>{t("sig.chain")}</dt>
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
      .catch((e) => live && setError(errorText(api.errorOf(e))));
    return () => {
      live = false;
    };
  }, [path, password]);

  if (count === 0 && (checks === null || checks.length === 0)) return null;
  return (
    <section className="signatures">
      <h3>{checks ? t("sig.titleN", { n: checks.length }) : t("sig.title")}</h3>
      {error ? (
        <div className="warn-row">
          <AlertIcon size={14} />
          <div>
            <strong>{t("sig.checkFailed")}</strong>
            <span>{error}</span>
          </div>
        </div>
      ) : checks === null ? (
        <p className="muted small">{t("sig.checking", { n: count })}</p>
      ) : (
        <ul className="sig-list">
          {checks.map((s) => (
            <SignatureItem key={s.field} s={s} />
          ))}
        </ul>
      )}
      <p className="muted small">
        {checks?.some((c) => c.certification === 1)
          ? t("sig.noChangesAllowed")
          : t("sig.keepsValid")}
      </p>
    </section>
  );
}
