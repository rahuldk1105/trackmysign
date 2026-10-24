// Settings section for running in the background: the tray (menu bar) icon,
// closing the window hides it, and the start at sign-in
// (`background_*` commands in src-tauri/src/background.rs).

import { useEffect, useState } from "react";
import * as api from "./api";
import type { BackgroundStatus } from "./api";
import { t } from "./i18n";
import { errorText } from "./i18n/errors";
import { AlertIcon } from "./icons";

const mac = /mac/i.test(navigator.platform);

/** `portalEnabled`: the default follows it, so the status is read again when it changes. */
export function BackgroundSettings(props: { portalEnabled: boolean | undefined }) {
  const [status, setStatus] = useState<BackgroundStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const tray = t(mac ? "background.menuBar" : "background.systemTray");
  useEffect(() => {
    api.backgroundStatus().then(setStatus, () => {});
  }, [props.portalEnabled]);

  const run = async (f: () => Promise<BackgroundStatus>) => {
    setBusy(true);
    setError(null);
    try {
      setStatus(await f());
    } catch (e) {
      setError(errorText(api.errorOf(e)));
      api.backgroundStatus().then(setStatus, () => {});
    } finally {
      setBusy(false);
    }
  };

  return (
    <section>
      <h3>{t("background.title")}</h3>
      <label className="check-row">
        <input
          type="checkbox"
          checked={!!status?.enabled}
          disabled={!status || busy}
          onChange={(e) => {
            const on = e.target.checked;
            run(() => api.backgroundSet(on));
          }}
        />
        {t("background.keep")}
      </label>
      <p className="muted small">{t("background.hint", { tray })}</p>
      <label className="check-row">
        <input
          type="checkbox"
          checked={!!status?.autostart}
          disabled={!status?.enabled || busy}
          onChange={(e) => {
            const on = e.target.checked;
            run(() => api.backgroundSetAutostart(on));
          }}
        />
        {t("background.autostart")}
      </label>
      <p className="muted small">{t("background.autostartHint", { tray })}</p>
      {error && (
        <p className="inline-error">
          <AlertIcon size={14} /> {error}
        </p>
      )}
    </section>
  );
}
