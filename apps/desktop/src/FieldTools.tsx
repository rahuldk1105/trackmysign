// "Add signature fields": empty, named signature fields drawn on the pages
// for others (co-directors, the auditor, the company secretary) to sign
// later. Saved as a new PDF (`add_fields`), or added and one of them signed
// right away; the original is only read.

import { useEffect, useState } from "react";
import * as api from "./api";
import type { CertifyLevel, NewFieldArg } from "./api";
import { t } from "./i18n";
import { errorText } from "./i18n/errors";
import type { DraftBox, Placement } from "./PdfView";
import { AlertIcon, CloseIcon } from "./icons";
import "./fields.css";

/** Field names offered first; they go into the PDF as they are. */
export const FIELD_PRESETS = ["Director", "Director 2", "Company Secretary", "Auditor", "Chairman"];

export interface Draft extends DraftBox {
  tooltip: string;
  lock: "none" | "all" | "fields";
  /** Comma-separated names, for `lock: "fields"`. */
  lockFields: string;
}

/** The first preset not used yet, else "Signature N". */
export function nextName(used: string[]): string {
  const preset = FIELD_PRESETS.find((p) => !used.includes(p));
  if (preset) return preset;
  let n = 1;
  while (used.includes(`Signature ${n}`)) n++;
  return `Signature ${n}`;
}

export function newDraft(p: Placement, id: number, used: string[]): Draft {
  return { ...p, id, name: nextName(used), tooltip: "", lock: "none", lockFields: "" };
}

/** Why a name cannot be used, or null. */
function nameProblem(d: Draft, drafts: Draft[], existing: string[]): string | null {
  const name = d.name.trim();
  if (!name) return t("newFields.nameMissing");
  if (name.includes(".")) return t("newFields.nameDot");
  if (existing.includes(name) || drafts.some((o) => o.id !== d.id && o.name.trim() === name)) return t("newFields.nameTaken", { name });
  return null;
}

interface Props {
  path: string;
  password?: string;
  certified: CertifyLevel | null;
  /** Names of the fields already in the PDF. */
  existing: string[];
  drafts: Draft[];
  setDrafts: (d: Draft[]) => void;
  selected: number | null;
  onSelect: (id: number) => void;
  goPage: (page: number) => void;
  /** A certificate is ready to sign with. */
  canSign: boolean;
  onSaved: (output: string) => void;
  /** Add the fields and sign `mine` now. */
  onSignMine: (fields: NewFieldArg[], mine: NewFieldArg) => void;
  onClose: () => void;
}

export function FieldsPanel(props: Props) {
  const { drafts, setDrafts } = props;
  const [inOrder, setInOrder] = useState(true);
  const [seed, setSeed] = useState(false);
  const [mine, setMine] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const change = (id: number, patch: Partial<Draft>) => setDrafts(drafts.map((d) => (d.id === id ? { ...d, ...patch } : d)));
  const remove = (id: number) => {
    setDrafts(drafts.filter((d) => d.id !== id));
    if (mine === id) setMine(null);
  };

  // Delete removes the selected box, unless a text box has the keys.
  const { selected } = props;
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.key !== "Delete" || selected === null) return;
      if ((e.target as HTMLElement).closest("input, select, textarea")) return;
      setDrafts(drafts.filter((d) => d.id !== selected));
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [drafts, selected, setDrafts]);

  const problems = drafts.map((d) => nameProblem(d, drafts, props.existing));
  const ready = drafts.length > 0 && problems.every((p) => !p) && !busy;
  const mineDraft = drafts.find((d) => d.id === mine) ?? null;

  const args = (): NewFieldArg[] =>
    drafts.map((d, i) => {
      const listed = d.lockFields
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      return {
        name: d.name.trim(),
        page: d.page,
        rect: { x: d.x, y: d.y, w: d.w, h: d.h },
        tooltip: d.tooltip.trim() || null,
        order: inOrder ? i + 1 : null,
        lock: d.lock === "all" ? { kind: "all" } : d.lock === "fields" && listed.length ? { kind: "fields", fields: listed } : null,
        seed,
      };
    });

  const saveAs = async () => {
    const output = await api.pickFieldsPath(props.path);
    if (!output) return;
    setBusy(true);
    setError(null);
    try {
      props.onSaved(await api.addSignatureFields(props.path, props.password ?? null, args(), output));
    } catch (e) {
      setError(errorText(api.errorOf(e)));
    } finally {
      setBusy(false);
    }
  };

  const signMine = () => {
    const all = args();
    const i = drafts.findIndex((d) => d.id === mine);
    if (i >= 0) props.onSignMine(all, all[i]);
  };

  const move = (i: number, by: -1 | 1) => {
    const next = [...drafts];
    [next[i], next[i + by]] = [next[i + by], next[i]];
    setDrafts(next);
  };

  return (
    <>
      <div className="insp-scroll">
        <section>
          <h3>{t("newFields.title")}</h3>
          <p className="muted small">{t("newFields.hint")}</p>
          {props.certified && <p className="muted small">{t("newFields.certified")}</p>}
        </section>

        <section>
          <h3>{t("newFields.count", { n: drafts.length })}</h3>
          {drafts.length === 0 ? (
            <p className="muted small">{t("newFields.none")}</p>
          ) : (
            <ol className="new-fields">
              {drafts.map((d, i) => (
                <li key={d.id} className={props.selected === d.id ? "on" : undefined} onFocus={() => props.onSelect(d.id)}>
                  <div className="new-field-head">
                    {inOrder && <span className="mono new-field-n">{i + 1}</span>}
                    <input
                      value={d.name}
                      list="field-presets"
                      onChange={(e) => change(d.id, { name: e.target.value })}
                      aria-label={t("newFields.name")}
                      aria-invalid={!!problems[i]}
                      className={problems[i] ? "invalid" : undefined}
                      spellCheck={false}
                    />
                    <button className="tb-btn" onClick={() => remove(d.id)} title={t("newFields.remove")} aria-label={t("newFields.removeNamed", { name: d.name })}>
                      <CloseIcon size={12} />
                    </button>
                  </div>
                  {problems[i] && (
                    <p className="inline-error">
                      <AlertIcon size={14} /> {problems[i]}
                    </p>
                  )}
                  <input
                    value={d.tooltip}
                    onChange={(e) => change(d.id, { tooltip: e.target.value })}
                    placeholder={t("newFields.tooltipPlaceholder")}
                    aria-label={t("newFields.tooltip")}
                  />
                  <div className="new-field-row">
                    <select value={d.lock} onChange={(e) => change(d.id, { lock: e.target.value as Draft["lock"] })} aria-label={t("newFields.lock")}>
                      <option value="none">{t("newFields.lockNone")}</option>
                      <option value="all">{t("newFields.lockAll")}</option>
                      <option value="fields">{t("newFields.lockSome")}</option>
                    </select>
                    <button
                      className="link"
                      onClick={() => {
                        props.onSelect(d.id);
                        props.goPage(d.page);
                      }}
                    >
                      {t("common.pageN", { n: d.page + 1 })}
                    </button>
                    {inOrder && (
                      <>
                        <button className="link" onClick={() => move(i, -1)} disabled={i === 0} title={t("newFields.earlier")}>
                          ↑
                        </button>
                        <button className="link" onClick={() => move(i, 1)} disabled={i === drafts.length - 1} title={t("newFields.later")}>
                          ↓
                        </button>
                      </>
                    )}
                  </div>
                  {d.lock === "fields" && (
                    <input
                      value={d.lockFields}
                      onChange={(e) => change(d.id, { lockFields: e.target.value })}
                      placeholder={t("newFields.lockFieldsPlaceholder")}
                      aria-label={t("newFields.lockFields")}
                      spellCheck={false}
                    />
                  )}
                </li>
              ))}
            </ol>
          )}
          <datalist id="field-presets">
            {FIELD_PRESETS.map((p) => (
              <option key={p} value={p} />
            ))}
          </datalist>
        </section>

        <section>
          <h3>{t("newFields.options")}</h3>
          <label className="check-row">
            <input type="checkbox" checked={inOrder} onChange={(e) => setInOrder(e.target.checked)} />
            {t("newFields.inOrder")}
          </label>
          <p className="muted small">{t("newFields.inOrderHint")}</p>
          <label className="check-row">
            <input type="checkbox" checked={seed} onChange={(e) => setSeed(e.target.checked)} />
            {t("newFields.seed")}
          </label>
          <p className="muted small">{t("newFields.seedHint")}</p>
        </section>

        <section>
          <h3>{t("newFields.signMine")}</h3>
          <select value={mine ?? ""} onChange={(e) => setMine(e.target.value === "" ? null : Number(e.target.value))} aria-label={t("newFields.myField")}>
            <option value="">{t("newFields.myFieldNone")}</option>
            {drafts.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name}
              </option>
            ))}
          </select>
          <p className="muted small">{t("newFields.signMineHint")}</p>
        </section>
      </div>

      <div className="insp-foot">
        {error && (
          <p className="inline-error">
            <AlertIcon size={14} /> {error}
          </p>
        )}
        <button className="btn primary block" disabled={!ready} onClick={saveAs}>
          {busy ? t("newFields.saving") : t("newFields.saveAs")}
        </button>
        {mineDraft && (
          <button className="btn block" disabled={!ready || !props.canSign} onClick={signMine}>
            {t("newFields.saveAndSign", { name: mineDraft.name.trim() })}
          </button>
        )}
        <button className="btn block" onClick={props.onClose} disabled={busy}>
          {t("common.cancel")}
        </button>
        <p className="muted small">{t("newFields.original")}</p>
      </div>
    </>
  );
}
