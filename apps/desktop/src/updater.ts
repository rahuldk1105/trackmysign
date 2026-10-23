// In-app updates: latest.json of the latest GitHub release (tauri.conf.json,
// plugins.updater) is checked, the installer downloaded and verified against the
// public key there, installed, and the app restarted.

import { useCallback, useEffect, useRef, useState } from "react";
import type { Update } from "@tauri-apps/plugin-updater";
import { inTauri } from "./api";

export interface AvailableUpdate {
  version: string;
  /** Release notes (GitHub's generated Markdown); may be empty. */
  notes: string;
}

export type UpdateState =
  | { kind: "idle" }
  | { kind: "checking"; manual: boolean }
  | { kind: "latest" }
  | { kind: "available"; update: AvailableUpdate; dismissed: boolean }
  /** `progress` is 0..1, or null while the size is unknown. */
  | { kind: "installing"; update: AvailableUpdate; progress: number | null }
  | { kind: "error"; message: string; update?: AvailableUpdate };

let pending: Update | null = null;

async function fetchUpdate(): Promise<AvailableUpdate | null> {
  if (!inTauri) {
    // UI development: open with ?update to see the banner.
    await new Promise((r) => setTimeout(r, 400));
    return location.search.includes("update") ? { version: "9.9.9", notes: "## What's Changed\n* Mock release notes" } : null;
  }
  const { check } = await import("@tauri-apps/plugin-updater");
  pending = await check();
  return pending ? { version: pending.version, notes: pending.body ?? "" } : null;
}

async function install(progress: (p: number | null) => void): Promise<void> {
  if (!inTauri) {
    for (let i = 1; i <= 10; i++) {
      await new Promise((r) => setTimeout(r, 150));
      progress(i / 10);
    }
    throw new Error("Updates can only be installed in the desktop app.");
  }
  if (!pending) throw new Error("No update downloaded. Check for updates again.");
  let total: number | null = null;
  let done = 0;
  // Windows: the installer closes the app itself and starts it again afterwards.
  await pending.downloadAndInstall((e) => {
    if (e.event === "Started") total = e.data.contentLength ?? null;
    else if (e.event === "Progress") done += e.data.chunkLength;
    progress(total ? Math.min(done / total, 1) : null);
  });
  const { relaunch } = await import("@tauri-apps/plugin-process");
  await relaunch();
}

function message(e: unknown): string {
  const m = e instanceof Error ? e.message : String(e);
  return m || "Unknown error";
}

/** Checks once on launch when `auto` is set; `check` is the manual button. */
export function useUpdater(auto: boolean) {
  const [state, setState] = useState<UpdateState>({ kind: "idle" });
  const busy = useRef(false);

  const run = useCallback(async (manual: boolean) => {
    if (busy.current) return;
    busy.current = true;
    setState({ kind: "checking", manual });
    try {
      const update = await fetchUpdate();
      setState(update ? { kind: "available", update, dismissed: false } : manual ? { kind: "latest" } : { kind: "idle" });
    } catch (e) {
      // Offline at launch is normal; only a manual check reports it.
      setState(manual ? { kind: "error", message: message(e) } : { kind: "idle" });
    } finally {
      busy.current = false;
    }
  }, []);

  const autoRef = useRef(auto);
  useEffect(() => {
    if (autoRef.current) run(false);
  }, [run]);

  const installUpdate = useCallback(async (update: AvailableUpdate) => {
    setState({ kind: "installing", update, progress: 0 });
    try {
      await install((progress) => setState({ kind: "installing", update, progress }));
    } catch (e) {
      setState({ kind: "error", message: message(e), update });
    }
  }, []);

  const dismiss = useCallback(
    () => setState((s) => (s.kind === "available" ? { ...s, dismissed: true } : s.kind === "error" ? { kind: "idle" } : s)),
    [],
  );

  return { state, check: () => run(true), install: installUpdate, dismiss };
}
