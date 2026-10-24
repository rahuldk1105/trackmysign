// Settings section for running in the background: the tray (menu bar) icon,
// closing the window hides it, and the start at sign-in
// (`background_*` commands in src-tauri/src/background.rs).

import { useEffect, useState } from "react";
import * as api from "./api";
import type { BackgroundStatus } from "./api";
import { AlertIcon } from "./icons";

const mac = /mac/i.test(navigator.platform);
const tray = mac ? "menu bar" : "system tray";

/** `portalEnabled`: the default follows it, so the status is read again when it changes. */
export function BackgroundSettings(props: { portalEnabled: boolean | undefined }) {
  const [status, setStatus] = useState<BackgroundStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api.backgroundStatus().then(setStatus, () => {});
  }, [props.portalEnabled]);

  const run = async (f: () => Promise<BackgroundStatus>) => {
    setBusy(true);
    setError(null);
    try {
      setStatus(await f());
    } catch (e) {
      setError(api.errorOf(e).message);
      api.backgroundStatus().then(setStatus, () => {});
    } finally {
      setBusy(false);
    }
  };

  return (
    <section>
      <h3>Background</h3>
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
        Keep running in the background
      </label>
      <p className="muted small">
        Closing the window leaves TrackMySign in the {tray}, so the GST portal can ask for signatures without opening the app first. Quit
        from its icon there.
      </p>
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
        Start TrackMySign when I sign in
      </label>
      <p className="muted small">Starts in the {tray}, without opening a window.</p>
      {error && (
        <p className="inline-error">
          <AlertIcon size={14} /> {error}
        </p>
      )}
    </section>
  );
}
