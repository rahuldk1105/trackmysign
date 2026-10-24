// Bar under the toolbar when a newer version is out: notes, install, progress.

import { useState } from "react";
import type { AvailableUpdate, UpdateState } from "./updater";
import { t, tx } from "./i18n";
import { translateMessage } from "./i18n/errors";
import { AlertIcon, CloseIcon } from "./icons";

/** GitHub's generated notes, readable as plain text. */
function plainNotes(md: string): string {
  return md
    .replace(/^#+\s*/gm, "")
    .replace(/^\s*[*-]\s+/gm, "• ")
    .replace(/\*\*(.*?)\*\*/g, "$1")
    .trim();
}

export function UpdateBanner(props: {
  state: UpdateState;
  /** Signing in progress: installing now would close the app mid-signature. */
  busy: boolean;
  onInstall: (u: AvailableUpdate) => void;
  onDismiss: () => void;
}) {
  const [notesOpen, setNotesOpen] = useState(false);
  const s = props.state;
  const update = s.kind === "available" && !s.dismissed ? s.update : s.kind === "installing" || s.kind === "error" ? s.update : undefined;
  if (!update) return null;
  const notes = plainNotes(update.notes);

  return (
    <div className="update-bar" role="status">
      <div className="update-row">
        {s.kind === "error" && <AlertIcon size={14} />}
        <span className="update-text">
          {s.kind === "error" ? (
            t("update.bannerFailed", { version: update.version, message: translateMessage(s.message) })
          ) : s.kind === "installing" ? (
            t("update.bannerDownloading", { version: update.version })
          ) : (
            tx("update.bannerAvailable", { name: <strong>TrackMySign {update.version}</strong> })
          )}
        </span>
        {notes && s.kind !== "installing" && (
          <button className="link" onClick={() => setNotesOpen((o) => !o)} aria-expanded={notesOpen}>
            {notesOpen ? t("update.hideNotes") : t("update.whatsNew")}
          </button>
        )}
        <div className="spacer" />
        {s.kind === "installing" ? (
          <>
            <div className="update-progress" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={s.progress === null ? undefined : Math.round(s.progress * 100)}>
              <i style={{ width: `${Math.round((s.progress ?? 0) * 100)}%` }} />
            </div>
            <span className="mono small muted">{s.progress === null ? "" : `${Math.round(s.progress * 100)}%`}</span>
          </>
        ) : (
          <>
            <button
              className="btn primary"
              onClick={() => props.onInstall(update)}
              disabled={props.busy}
              title={props.busy ? t("update.waitSigning") : t("update.restartHint")}
            >
              {s.kind === "error" ? t("common.tryAgain") : t("update.install")}
            </button>
            <button className="tb-btn" onClick={props.onDismiss} title={t("update.later")} aria-label={t("update.later")}>
              <CloseIcon />
            </button>
          </>
        )}
      </div>
      {notesOpen && notes && s.kind !== "installing" && <div className="update-notes">{notes}</div>}
    </div>
  );
}
