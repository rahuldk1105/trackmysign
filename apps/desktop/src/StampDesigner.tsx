// "Appearance → Design…": layout, text lines, typography, box and company
// seal of the signature box, with a preview drawn from the core's layout of
// the real box size. Saved into settings (and from there into presets).
// The "certified true copy" stamp is designed with the same dialog
// (`variant="ctc"`): text, typography, box and seal, no signature image.

import { useEffect, useState } from "react";
import * as api from "./api";
import type { ImageChoice } from "./api";
import { t, type MessageKey } from "./i18n";
import { AlertIcon, ChevronDownIcon, ChevronUpIcon, CloseIcon } from "./icons";
import {
  ALL_LINES,
  DARK_BLUE,
  DEFAULT_CTC_STYLE,
  DEFAULT_STYLE,
  STANDARD_BORDER,
  STANDARD_LINES,
  fullStyle,
  isHexColor,
  useStampDrawing,
  type DateFormat,
  type FontFamily,
  type LineField,
  type StampContent,
  type StampStyle,
} from "./stamp";
import { StampView } from "./StampView";

/** A picture in the app's data folder, as loaded for previews. */
export interface PictureInfo {
  url: string;
  /** Width / height. */
  aspect: number;
}

type Layout = "text" | "left" | "above" | "only";

const LAYOUTS: { value: Layout; label: MessageKey }[] = [
  { value: "text", label: "design.textOnly" },
  { value: "left", label: "design.imageLeft" },
  { value: "above", label: "design.imageAbove" },
  { value: "only", label: "design.imageOnly" },
];

const FIELD_LABELS: Record<LineField, MessageKey> = {
  signed_by_label: "design.field.signedByLabel",
  name: "design.field.name",
  signed_by: "design.field.signedBy",
  organisation: "design.field.organisation",
  role: "design.field.role",
  date: "design.field.date",
  reason: "design.field.reason",
  location: "design.field.location",
  custom_1: "design.field.custom1",
  custom_2: "design.field.custom2",
};

// Date formats are shown by pattern: the box is always printed in English.
const DATE_FORMATS: { value: DateFormat; label: string }[] = [
  { value: "classic", label: "YYYY.MM.DD HH:mm:ss +05:30" },
  { value: "dd_mm_yyyy_hh_mm", label: "DD-MM-YYYY HH:mm IST" },
  { value: "dd_mm_yyyy_hh_mm_ss", label: "DD-MM-YYYY HH:mm:ss IST" },
  { value: "dd_mmm_yyyy", label: "DD MMM YYYY" },
];

const FONTS: { value: FontFamily; label: string }[] = [
  { value: "helvetica", label: "Helvetica" },
  { value: "times", label: "Times" },
  { value: "courier", label: "Courier" },
];

/** Rows of the line list: the shown lines in order, then the others. */
function lineRows(style: StampStyle): { field: LineField; on: boolean }[] {
  const on = style.lines ?? STANDARD_LINES;
  return [...on.map((field) => ({ field, on: true })), ...ALL_LINES.filter((f) => !on.includes(f)).map((field) => ({ field, on: false }))];
}

function Segmented<T extends string>(props: { label: string; value: T; options: { value: T; label: string; disabled?: boolean }[]; onChange: (v: T) => void }) {
  return (
    <div className="segmented" role="radiogroup" aria-label={props.label}>
      {props.options.map((o) => (
        <button
          key={o.value}
          role="radio"
          aria-checked={props.value === o.value}
          className={props.value === o.value ? "on" : ""}
          disabled={o.disabled}
          onClick={() => props.onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/** Text as the box prints it, when that differs from what was typed. */
function usePrinted(text: string): string | null {
  const [printed, setPrinted] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    api.stampText(text).then((p) => live && setPrinted(p.trim() !== text.trim() ? p : null));
    return () => {
      live = false;
    };
  }, [text]);
  return printed;
}

function TextLine(props: { id: string; value: string; placeholder: string; onChange: (v: string) => void }) {
  const printed = usePrinted(props.value);
  return (
    <>
      <input id={props.id} value={props.value} maxLength={120} placeholder={props.placeholder} onChange={(e) => props.onChange(e.target.value)} />
      {printed !== null && <p className="muted small design-printed">{t("design.printedAs", { text: printed })}</p>}
    </>
  );
}

function ColorField(props: { id: string; value: string; onChange: (v: string) => void }) {
  const [text, setText] = useState(props.value);
  useEffect(() => setText(props.value), [props.value]);
  const ok = isHexColor(text);
  return (
    <div className="design-color">
      <input
        type="color"
        value={isHexColor(props.value) ? props.value : "#000000"}
        onChange={(e) => props.onChange(e.target.value.toUpperCase())}
        aria-label={t("design.pickColor")}
      />
      <input
        id={props.id}
        className={`mono ${ok ? "" : "invalid"}`}
        value={text}
        maxLength={7}
        onChange={(e) => {
          setText(e.target.value);
          if (isHexColor(e.target.value)) props.onChange(e.target.value.toUpperCase());
        }}
        title={ok ? undefined : t("design.invalidColor")}
      />
    </div>
  );
}

export function StampDesigner(props: {
  /** "ctc": the certified true copy stamp, saved as given (never null). */
  variant?: "ctc";
  style: StampStyle | null;
  image: ImageChoice;
  signature: PictureInfo | null;
  seal: PictureInfo | null;
  /** Box size in points for the preview: the placed box, or the usual one. */
  box: { w: number; h: number };
  content: Omit<StampContent, "style" | "image" | "seal">;
  /** Resolves true when a seal was chosen. */
  onChooseSeal: () => Promise<boolean>;
  onRemoveSeal: () => Promise<void>;
  sealError: string | null;
  onSave: (style: StampStyle | null, image: ImageChoice) => void;
  onClose: () => void;
}) {
  const { onClose } = props;
  const ctc = props.variant === "ctc";
  const standard = ctc ? DEFAULT_CTC_STYLE : DEFAULT_STYLE;
  const [style, setStyle] = useState<StampStyle>(() => (ctc ? { ...DEFAULT_CTC_STYLE, ...props.style } : fullStyle(props.style)));
  const [image, setImage] = useState<ImageChoice>(props.image);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);

  const set = (patch: Partial<StampStyle>) => setStyle((s) => ({ ...s, ...patch }));
  const layout: Layout = style.layout === "image_only" ? "only" : image === "off" || !props.signature ? "text" : image;
  const setLayout = (l: Layout) => {
    if (l === "only") {
      set({ layout: "image_only" });
      setImage(props.signature ? (image === "off" ? "left" : image) : "off");
    } else {
      set({ layout: "auto" });
      setImage(l === "text" ? "off" : l);
    }
  };
  const showsSeal = !!props.seal && !!style.seal;
  const content: StampContent = {
    ...props.content,
    style,
    image: props.signature && image !== "off" ? [props.signature.aspect, image] : null,
    seal: showsSeal && props.seal ? props.seal.aspect : null,
  };
  const drawing = useStampDrawing(content, props.box.w, props.box.h);
  // The preview at its real proportions, as wide as fits.
  const previewW = 380;
  const previewH = Math.min(220, (previewW * props.box.h) / props.box.w);

  const rows = lineRows(style);
  const setRows = (next: { field: LineField; on: boolean }[]) => {
    const lines = next.filter((r) => r.on).map((r) => r.field);
    set({ lines: !ctc && JSON.stringify(lines) === JSON.stringify(STANDARD_LINES) ? null : lines });
  };
  const move = (i: number, by: -1 | 1) => {
    const next = [...rows];
    [next[i], next[i + by]] = [next[i + by], next[i]];
    setRows(next);
  };
  const shown = rows.filter((r) => r.on).length;

  const textColor = style.text_color.toUpperCase() === "#000000" ? "black" : style.text_color.toUpperCase() === DARK_BLUE ? "blue" : "custom";
  const valid = isHexColor(style.text_color) && (style.border_color === null || isHexColor(style.border_color));

  const save = () => {
    if (!valid) return setError(t("design.invalidColor"));
    const s = { ...style, seal: props.seal ? style.seal : null };
    props.onSave(!ctc && JSON.stringify(s) === JSON.stringify(DEFAULT_STYLE) ? null : s, image);
  };

  const textOn = layout !== "only";
  const title = ctc ? t("ctc.designTitle") : t("design.title");
  return (
    <div className="backdrop" onPointerDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="dialog designer" role="dialog" aria-modal="true" aria-label={title}>
        <div className="dialog-title">
          <h2>{title}</h2>
          <div className="spacer" />
          <button className="tb-btn" onClick={onClose} title={t("common.close")} aria-label={t("common.close")}>
            <CloseIcon />
          </button>
        </div>
        <div className="dialog-body">
          <div className="designer-cols">
            <div className="designer-controls">
              {!ctc && (
                <section>
                  <h3>{t("design.layout")}</h3>
                  <Segmented
                    label={t("design.layout")}
                    value={layout}
                    onChange={setLayout}
                    options={LAYOUTS.map((l) => ({
                      value: l.value,
                      label: t(l.label),
                      disabled: (l.value === "left" || l.value === "above") && !props.signature ? true : l.value === "only" && !props.signature && !props.seal,
                    }))}
                  />
                  {!props.signature && <p className="muted small">{t("design.noImage")}</p>}
                </section>
              )}

              <section>
                <h3>{t("design.seal")}</h3>
                {props.seal ? (
                  <>
                    <div className="setting-row">
                      <img className="image-thumb" src={props.seal.url} alt={t("design.seal")} />
                      <button className="btn" onClick={props.onChooseSeal}>
                        {t("settings.replaceImage")}
                      </button>
                      <button
                        className="btn ghost"
                        onClick={async () => {
                          await props.onRemoveSeal();
                          set({ seal: null });
                        }}
                      >
                        {t("settings.remove")}
                      </button>
                    </div>
                    <label className="check-row">
                      <input
                        type="checkbox"
                        checked={!!style.seal}
                        onChange={(e) => set({ seal: e.target.checked ? { position: "right", opacity: 1 } : null })}
                      />
                      {ctc ? t("ctc.showSeal") : t("design.showSeal")}
                    </label>
                    {style.seal && (
                      <>
                        <Segmented
                          label={t("design.seal")}
                          value={style.seal.position}
                          onChange={(position) =>
                            set({ seal: { position, opacity: position === "behind" && style.seal!.opacity === 1 ? 0.25 : style.seal!.opacity } })
                          }
                          options={[
                            { value: "right", label: t("design.sealRight") },
                            { value: "behind", label: t("design.sealBehind") },
                          ]}
                        />
                        <label htmlFor="d-opacity">{t("design.opacity", { pct: Math.round(style.seal.opacity * 100) })}</label>
                        <input
                          id="d-opacity"
                          type="range"
                          min={10}
                          max={100}
                          step={5}
                          value={Math.round(style.seal.opacity * 100)}
                          onChange={(e) => set({ seal: { ...style.seal!, opacity: Number(e.target.value) / 100 } })}
                        />
                      </>
                    )}
                  </>
                ) : (
                  <div className="setting-row">
                    <span className="muted small">{t("design.sealHint")}</span>
                    <button
                      className="btn"
                      onClick={async () => {
                        if (await props.onChooseSeal()) set({ seal: style.seal ?? { position: "right", opacity: 1 } });
                      }}
                    >
                      {t("settings.choose")}
                    </button>
                  </div>
                )}
                {props.sealError && (
                  <p className="inline-error">
                    <AlertIcon size={14} /> {props.sealError}
                  </p>
                )}
              </section>

              {textOn && (
                <section>
                  <h3>{t("design.lines")}</h3>
                  <ul className="design-lines">
                    {rows.map((r, i) => (
                      <li key={r.field} className={r.on ? "" : "off"}>
                        <label className="check-row">
                          <input
                            type="checkbox"
                            checked={r.on}
                            disabled={r.on && shown === 1}
                            onChange={(e) => setRows(rows.map((x) => (x === r ? { ...x, on: e.target.checked } : x)))}
                          />
                          {t(FIELD_LABELS[r.field])}
                        </label>
                        {r.on && (
                          <span className="design-move">
                            <button
                              className="tb-btn"
                              disabled={i === 0}
                              onClick={() => move(i, -1)}
                              title={t("design.moveUp")}
                              aria-label={t("design.moveUp")}
                            >
                              <ChevronUpIcon />
                            </button>
                            <button
                              className="tb-btn"
                              disabled={i + 1 >= shown}
                              onClick={() => move(i, 1)}
                              title={t("design.moveDown")}
                              aria-label={t("design.moveDown")}
                            >
                              <ChevronDownIcon />
                            </button>
                          </span>
                        )}
                        {r.on && r.field === "organisation" && (
                          <TextLine
                            id="d-org"
                            value={style.organisation}
                            onChange={(organisation) => set({ organisation })}
                            placeholder={props.content.organisation ? t("design.orgFromCert", { org: props.content.organisation }) : t("design.orgPlaceholder")}
                          />
                        )}
                        {r.on && r.field === "role" && (
                          <TextLine id="d-role" value={style.role} onChange={(role) => set({ role })} placeholder={t("design.rolePlaceholder")} />
                        )}
                        {r.on && r.field === "custom_1" && (
                          <TextLine id="d-c1" value={style.custom_1} onChange={(custom_1) => set({ custom_1 })} placeholder={t("design.customPlaceholder")} />
                        )}
                        {r.on && r.field === "custom_2" && (
                          <TextLine id="d-c2" value={style.custom_2} onChange={(custom_2) => set({ custom_2 })} placeholder={t("design.customPlaceholder")} />
                        )}
                        {r.on && r.field === "date" && (
                          <select
                            value={style.date_format}
                            onChange={(e) => set({ date_format: e.target.value as DateFormat })}
                            aria-label={t("design.dateFormat")}
                          >
                            {DATE_FORMATS.map((f) => (
                              <option key={f.value} value={f.value}>
                                {f.label}
                              </option>
                            ))}
                          </select>
                        )}
                      </li>
                    ))}
                  </ul>
                  <p className="muted small">{t("design.latin")}</p>
                </section>
              )}

              {textOn && (
                <section>
                  <h3>{t("design.text")}</h3>
                  <Segmented label={t("design.font")} value={style.font} onChange={(font) => set({ font })} options={FONTS} />
                  <label className="check-row">
                    <input type="checkbox" checked={style.bold_name} onChange={(e) => set({ bold_name: e.target.checked })} />
                    {t("design.boldName")}
                  </label>
                  <label className="check-row">
                    <input type="checkbox" checked={style.bold_first_line} onChange={(e) => set({ bold_first_line: e.target.checked })} />
                    {t("design.boldFirst")}
                  </label>
                  <label id="d-size">{t("design.size")}</label>
                  <div className="design-pair">
                    <Segmented
                      label={t("design.size")}
                      value={style.font_size === null ? "auto" : "fixed"}
                      onChange={(v) => set({ font_size: v === "auto" ? null : 8 })}
                      options={[
                        { value: "auto", label: t("design.sizeAuto") },
                        { value: "fixed", label: t("design.sizeFixed") },
                      ]}
                    />
                    {style.font_size !== null && (
                      <input
                        type="number"
                        min={4}
                        max={36}
                        step={0.5}
                        value={style.font_size}
                        aria-labelledby="d-size"
                        onChange={(e) => {
                          const v = Number(e.target.value);
                          if (v >= 4 && v <= 36) set({ font_size: v });
                        }}
                      />
                    )}
                  </div>
                  <label>{t("design.color")}</label>
                  <div className="design-pair">
                    <Segmented
                      label={t("design.color")}
                      value={textColor}
                      onChange={(v) => set({ text_color: v === "black" ? "#000000" : v === "blue" ? DARK_BLUE : "#7A1F1F" })}
                      options={[
                        { value: "black", label: t("design.black") },
                        { value: "blue", label: t("design.darkBlue") },
                        { value: "custom", label: t("common.custom") },
                      ]}
                    />
                    {textColor === "custom" && <ColorField id="d-color" value={style.text_color} onChange={(text_color) => set({ text_color })} />}
                  </div>
                  <label>{t("design.align")}</label>
                  <Segmented
                    label={t("design.align")}
                    value={style.align}
                    onChange={(align) => set({ align })}
                    options={[
                      { value: "left", label: t("design.alignLeft") },
                      { value: "center", label: t("design.alignCenter") },
                    ]}
                  />
                </section>
              )}

              <section>
                <h3>{t("design.box")}</h3>
                <label className="check-row">
                  <input type="checkbox" checked={style.border} onChange={(e) => set({ border: e.target.checked })} />
                  {t("design.border")}
                </label>
                {style.border && (
                  <div className="design-pair">
                    <ColorField
                      id="d-border"
                      value={style.border_color ?? STANDARD_BORDER}
                      onChange={(c) => set({ border_color: c === STANDARD_BORDER ? null : c })}
                    />
                    <input
                      type="number"
                      min={0.1}
                      max={5}
                      step={0.1}
                      value={style.border_width}
                      aria-label={t("design.borderWidth")}
                      title={t("design.borderWidth")}
                      onChange={(e) => {
                        const v = Number(e.target.value);
                        if (v >= 0.1 && v <= 5) set({ border_width: v });
                      }}
                    />
                  </div>
                )}
                <label>{t("design.background")}</label>
                <Segmented
                  label={t("design.background")}
                  value={style.background}
                  onChange={(background) => set({ background })}
                  options={[
                    { value: "none", label: t("design.bgNone") },
                    { value: "light", label: t("design.bgLight") },
                  ]}
                />
                <label id="d-pad">{t("design.padding")}</label>
                <div className="design-pair">
                  <Segmented
                    label={t("design.padding")}
                    value={style.padding === null ? "auto" : "fixed"}
                    onChange={(v) => set({ padding: v === "auto" ? null : 4 })}
                    options={[
                      { value: "auto", label: t("design.sizeAuto") },
                      { value: "fixed", label: t("design.sizeFixed") },
                    ]}
                  />
                  {style.padding !== null && (
                    <input
                      type="number"
                      min={0}
                      max={20}
                      step={0.5}
                      value={style.padding}
                      aria-labelledby="d-pad"
                      onChange={(e) => {
                        const v = Number(e.target.value);
                        if (v >= 0 && v <= 20) set({ padding: v });
                      }}
                    />
                  )}
                </div>
                <label className="check-row">
                  <input type="checkbox" checked={style.tick} onChange={(e) => set({ tick: e.target.checked })} />
                  {t("design.tick")}
                </label>
                <p className="muted small">{t("design.tickHint")}</p>
              </section>
            </div>

            <div className="designer-preview">
              <div className="designer-sticky">
                <h3>{ctc ? t("ctc.preview") : t("appearance.preview")}</h3>
                <div className="designer-box" style={{ width: previewW, height: previewH }}>
                  {drawing ? (
                    <StampView drawing={drawing} urls={{ signature: props.signature?.url, seal: props.seal?.url }} />
                  ) : (
                    <span className="muted small">{t("design.noPreview")}</span>
                  )}
                </div>
                <p className="muted small">{t("design.previewSize", { w: Math.round(props.box.w * 0.3528), h: Math.round(props.box.h * 0.3528) })}</p>
              </div>
            </div>
          </div>

          {error && (
            <p className="inline-error">
              <AlertIcon size={14} /> {error}
            </p>
          )}
          <div className="dialog-actions">
            <button
              className="btn ghost"
              onClick={() => {
                setStyle(standard);
                if (style.layout === "image_only") setImage(props.signature ? "left" : "off");
              }}
            >
              {ctc ? t("ctc.standard") : t("design.standard")}
            </button>
            <div className="spacer" />
            <button className="btn" onClick={onClose}>
              {t("common.cancel")}
            </button>
            <button className="btn primary" onClick={save} disabled={!valid}>
              {t("common.save")}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
