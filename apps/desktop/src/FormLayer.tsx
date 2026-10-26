// Form fields of the PDF as inputs over the page, where the PDF puts them
// and scaled with it. PDF.js leaves form fields off the canvas, so these
// are what the reader sees. Their order in the page is the form's tab order.

import type { FormField, FormWidget } from "./api";
import { t } from "./i18n";
import "./form.css";

export interface FormState {
  /** In tab order. */
  fields: FormField[];
  /** What the user changed, by field name. */
  values: Record<string, string[]>;
  /** The form cannot be filled in (certified with no changes, XFA only). */
  disabled: boolean;
  /** Outline required fields that are empty. */
  showMissing: boolean;
  onChange: (name: string, value: string[]) => void;
}

export function valueOf(f: FormField, values: Record<string, string[]>): string[] {
  return values[f.name] ?? f.value;
}

export function isEmpty(v: string[]): boolean {
  return v.every((s) => !s.trim());
}

/** CSS selector of a field's first input, for focusing it from the side panel. */
export function fieldSelector(name: string): string {
  return `[data-form-field="${CSS.escape(name)}"]`;
}

/** Font size in points: the field's own, else one that fits the box. */
function fontSize(f: FormField, w: FormWidget, h: number): number {
  if (w.fontSize > 0) return w.fontSize;
  if (f.multiline || f.kind === "list") return 10;
  return Math.max(6, Math.min(12, h * 0.62));
}

export function FormLayer({ form, page, scale }: { form: FormState; page: number; scale: number }) {
  const placed = form.fields.flatMap((f) =>
    f.widgets.flatMap((w, i) => (w.page === page && w.rect ? [{ f, w, rect: w.rect, first: i === f.widgets.findIndex((x) => x.page === page && x.rect) }] : [])),
  );
  return (
    <>
      {placed.map(({ f, w, rect, first }, i) => {
        const value = valueOf(f, form.values);
        const missing = form.showMissing && f.required && !f.readOnly && isEmpty(value);
        const fs = fontSize(f, w, rect.h) * scale;
        const style: React.CSSProperties = {
          left: rect.x * scale,
          top: rect.y * scale,
          width: rect.w * scale,
          height: rect.h * scale,
          fontSize: fs,
          textAlign: w.align === 1 ? "center" : w.align === 2 ? "right" : "left",
        };
        const title = [
          f.label ?? f.name,
          f.required ? t("form.required") : null,
          f.readOnly ? t("form.readOnly") : null,
          f.lockedBy.length ? t("form.locked", { names: f.lockedBy.join(", ") }) : null,
        ]
          .filter(Boolean)
          .join(" · ");
        const common = {
          className: `form-field ${f.kind} ${f.comb ? "comb" : ""} ${missing ? "missing" : ""} ${f.lockedBy.length ? "locked" : ""}`,
          style,
          title,
          disabled: form.disabled || f.readOnly,
          "aria-label": f.label ?? f.name,
          "data-form-field": first ? f.name : undefined,
          onPointerDown: (e: React.PointerEvent) => e.stopPropagation(),
        };
        const set = (v: string[]) => form.onChange(f.name, v);
        switch (f.kind) {
          case "checkbox":
            return <input key={i} type="checkbox" {...common} checked={!!w.on && value.includes(w.on)} onChange={(e) => set(e.target.checked && w.on ? [w.on] : [])} />;
          case "radio":
            return <input key={i} type="radio" name={`form:${f.name}`} {...common} checked={!!w.on && value[0] === w.on} onChange={() => w.on && set([w.on])} />;
          case "combo":
            if (f.editable) {
              const list = `form-options-${i}-${page}`;
              return (
                <span key={i}>
                  <input {...common} list={list} value={value[0] ?? ""} onChange={(e) => set([e.target.value])} />
                  <datalist id={list}>
                    {f.options.map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </datalist>
                </span>
              );
            }
            return (
              <select key={i} {...common} value={value[0] ?? ""} onChange={(e) => set(e.target.value ? [e.target.value] : [])}>
                {!value.length && <option value="">{t("form.choose")}</option>}
                {f.options.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            );
          case "list":
            return (
              <select
                key={i}
                {...common}
                multiple={f.multiSelect}
                size={Math.max(2, f.options.length)}
                value={f.multiSelect ? value : (value[0] ?? "")}
                onChange={(e) => set(Array.from(e.target.selectedOptions, (o) => o.value))}
              >
                {f.options.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            );
          default: {
            const text = value[0] ?? "";
            if (f.multiline) return <textarea key={i} {...common} value={text} onChange={(e) => set([e.target.value])} />;
            // Comb: one character per box, as the PDF draws it.
            const comb = f.comb && f.maxLen ? (rect.w * scale) / f.maxLen : null;
            return (
              <input
                key={i}
                type={f.password ? "password" : "text"}
                {...common}
                style={comb ? { ...style, letterSpacing: comb - fs * 0.6, paddingLeft: (comb - fs * 0.6) / 2, textAlign: "left" } : style}
                maxLength={f.maxLen ?? undefined}
                value={text}
                onChange={(e) => set([e.target.value])}
              />
            );
          }
        }
      })}
    </>
  );
}
