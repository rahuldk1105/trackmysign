// "Certified true copy" in the signature type area: a stamp on every page
// (or chosen pages), signed with the document. Each stamp keeps its distance
// from a corner of the page; dragging one on the page moves them all. Its
// text and look are edited in the signature box designer (variant "ctc").

import type { ReactNode } from "react";
import type { CertifyLevel } from "./api";
import { t, type MessageKey } from "./i18n";
import { AlertIcon } from "./icons";
import type { CtcChoice } from "./presets";
import type { Corner, CtcStyle } from "./stamp";

const CORNERS: { value: Corner; label: MessageKey }[] = [
  { value: "top_left", label: "ctc.topLeft" },
  { value: "top_right", label: "ctc.topRight" },
  { value: "bottom_left", label: "ctc.bottomLeft" },
  { value: "bottom_right", label: "ctc.bottomRight" },
];

/** "all" (or nothing typed) stamps every page. */
export function allPages(spec: string): boolean {
  const s = spec.trim().toLowerCase();
  return s === "" || s === "all";
}

/** The stamp's lines, for previews outside the app, where nothing lays it out. */
export function ctcPreview(style: CtcStyle, name: string, organisation: string | null): string[] {
  const s = style.style;
  const org = s.organisation.trim() || organisation;
  const lines: Record<string, string | null> = {
    custom_1: s.custom_1.trim() || null,
    custom_2: s.custom_2.trim() || null,
    organisation: org ? `For ${org}` : null,
    name,
    role: s.role.trim() || null,
  };
  return (s.lines ?? []).map((f) => lines[f]).filter((l): l is string => !!l);
}

export function CtcSection(props: {
  on: boolean;
  choice: CtcChoice;
  /** Why the typed pages do not work, if they do not. */
  pagesError: string | null;
  /** Zero-based page in view, for a new custom selection. */
  currentPage: number;
  /** Signing into an empty signature field. */
  field: boolean;
  certified: CertifyLevel | null;
  onToggle: (on: boolean) => void;
  onChange: (choice: CtcChoice) => void;
  onDesign: () => void;
  /** The stamp preview. */
  children: ReactNode;
}) {
  const { choice } = props;
  const custom = !allPages(choice.pages);
  const setStyle = (patch: Partial<CtcStyle>) => props.onChange({ ...choice, style: { ...choice.style, ...patch } });
  return (
    <div className="ctc-options">
      <label className="check-row">
        <input type="checkbox" checked={props.on} onChange={(e) => props.onToggle(e.target.checked)} />
        {t("ctc.title")}
      </label>
      {!props.on ? (
        <p className="muted small">{t("ctc.hint")}</p>
      ) : (
        <>
          <label id="ctc-pages-label">{t("ctc.pages")}</label>
          <div className="segmented" role="radiogroup" aria-labelledby="ctc-pages-label">
            <button role="radio" aria-checked={!custom} className={!custom ? "on" : ""} onClick={() => props.onChange({ ...choice, pages: "all" })}>
              {t("placement.allPages")}
            </button>
            <button
              role="radio"
              aria-checked={custom}
              className={custom ? "on" : ""}
              onClick={() => !custom && props.onChange({ ...choice, pages: String(props.currentPage + 1) })}
            >
              {t("common.custom")}
            </button>
          </div>
          {custom && (
            <input
              className="mono"
              value={choice.pages}
              placeholder="1-3, 5"
              aria-label={t("ctc.pages")}
              spellCheck={false}
              onChange={(e) => props.onChange({ ...choice, pages: e.target.value })}
            />
          )}
          {props.pagesError && (
            <p className="inline-error">
              <AlertIcon size={14} /> {props.pagesError}
            </p>
          )}
          <label htmlFor="ctc-corner">{t("ctc.corner")}</label>
          <select id="ctc-corner" value={choice.style.corner} onChange={(e) => setStyle({ corner: e.target.value as Corner })}>
            {CORNERS.map((c) => (
              <option key={c.value} value={c.value}>
                {t(c.label)}
              </option>
            ))}
          </select>
          <p className="muted small">{t("ctc.dragHint")}</p>
          {props.children}
          <div className="appearance-design">
            <span className="muted small">{t("ctc.lookHint")}</span>
            <button className="btn" onClick={props.onDesign}>
              {t("appearance.design")}
            </button>
          </div>
          {props.field ? (
            <div className="warn-row">
              <AlertIcon size={14} />
              <div>
                <strong>{t("ctc.fieldTitle")}</strong>
                <span>{t("ctc.fieldBody")}</span>
              </div>
            </div>
          ) : (
            props.certified === 2 && (
              <div className="warn-row">
                <AlertIcon size={14} />
                <div>
                  <strong>{t("ctc.certifiedTitle")}</strong>
                  <span>{t("ctc.certifiedBody")}</span>
                </div>
              </div>
            )
          )}
        </>
      )}
    </div>
  );
}
