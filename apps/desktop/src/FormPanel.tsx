// Inspector section for a PDF with a form: the fields in tab order with
// what they hold, required ones still empty, and saving a filled-in copy.
// Signing fills the form in first, so the signature covers the values.

import type { FormField } from "./api";
import { isEmpty, valueOf } from "./FormLayer";
import { t } from "./i18n";
import { translateMessage } from "./i18n/errors";
import { AlertIcon, LockIcon } from "./icons";

function summary(f: FormField, value: string[]): string {
  if (f.kind === "checkbox") return value.length ? t("form.checked") : t("form.unchecked");
  if (isEmpty(value)) return t("form.empty");
  if (f.password) return "•".repeat(Math.min(8, value[0].length));
  return value.map((v) => f.options.find((o) => o.value === v)?.label ?? v).join(", ");
}

export function FormPanel(props: {
  fields: FormField[];
  values: Record<string, string[]>;
  blocked: string | null;
  changed: number;
  saving: boolean;
  onPick: (f: FormField) => void;
  onReset: () => void;
  onSave: () => void;
}) {
  const { fields, values } = props;
  const missing = fields.filter((f) => f.required && !f.readOnly && isEmpty(valueOf(f, values)));
  return (
    <section>
      <h3>{t("form.title", { n: fields.length })}</h3>
      {props.blocked && (
        <div className="warn-row">
          <AlertIcon size={14} />
          <div>
            <span>{translateMessage(props.blocked)}</span>
          </div>
        </div>
      )}
      <ul className="field-list form-list" aria-label={t("form.list")}>
        {fields.map((f) => {
          const value = valueOf(f, values);
          const empty = f.required && !f.readOnly && isEmpty(value);
          return (
            <li key={f.name}>
              <button onClick={() => props.onPick(f)} title={f.label && f.label !== f.name ? `${f.label} (${f.name})` : f.name} className={f.name in values ? "edited" : undefined}>
                <span className="field-name">
                  {f.label ?? f.name}
                  {f.required && <span className={empty ? "form-req bad" : "form-req"}> *</span>}
                </span>
                {f.lockedBy.length > 0 && (
                  <span className="form-lock" title={t("form.locked", { names: f.lockedBy.join(", ") })}>
                    <LockIcon size={11} />
                  </span>
                )}
                <span className={`muted form-value ${f.readOnly ? "ro" : ""}`}>{summary(f, value)}</span>
              </button>
            </li>
          );
        })}
      </ul>
      {missing.length > 0 && !props.blocked && <p className="small form-missing">{t("form.requiredLeft", { n: missing.length })}</p>}
      {!props.blocked && <p className="muted small">{props.changed ? t("form.signFills", { n: props.changed }) : t("form.hint")}</p>}
      {props.changed > 0 && (
        <div className="form-actions">
          <button className="btn" onClick={props.onSave} disabled={props.saving}>
            {props.saving ? t("form.saving") : t("form.save")}
          </button>
          <button className="link" onClick={props.onReset} disabled={props.saving}>
            {t("form.reset")}
          </button>
        </div>
      )}
    </section>
  );
}
