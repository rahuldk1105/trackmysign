// Passing a signed copy on (`share_*` commands in src-tauri/src/share.rs):
// Email…, Share… and Copy file next to Show in folder, in the "Document
// signed" dialog, the batch results, History and the Recent list. What this
// computer does not have (the share sheet on Linux) is not shown.

import { useEffect, useRef, useState } from "react";
import * as api from "./api";
import type { ShareAbilities } from "./api";
import { t } from "./i18n";
import { errorText } from "./i18n/errors";
import { AlertIcon, CheckIcon, ShareIcon } from "./icons";
import "./share.css";

const NONE: ShareAbilities = { email: false, share: false, copy: false };
let asked: Promise<ShareAbilities> | null = null;

function useAbilities(): ShareAbilities {
  const [abilities, setAbilities] = useState(NONE);
  useEffect(() => {
    (asked ??= api.shareAbilities().catch(() => NONE)).then(setAbilities);
  }, []);
  return abilities;
}

type Note = { ok: boolean; text: string };

/** The three actions; what one says afterwards (copied, attach by hand, an error) goes in `note`. */
function useShare() {
  const abilities = useAbilities();
  const [note, setNote] = useState<Note | null>(null);
  const run = async (f: () => Promise<string | null>) => {
    setNote(null);
    try {
      const text = await f();
      setNote(text ? { ok: true, text } : null);
      return !!text;
    } catch (e) {
      setNote({ ok: false, text: errorText(api.errorOf(e)) });
      return true;
    }
  };
  return {
    abilities,
    note,
    email: (paths: string[]) => run(async () => ((await api.shareEmail(paths)) === "attachByHand" ? t("share.attachByHand") : null)),
    share: (paths: string[], button: HTMLElement) =>
      run(async () => {
        await api.shareSheet(paths, button.getBoundingClientRect());
        return null;
      }),
    copy: (paths: string[]) =>
      run(async () => {
        await api.shareCopy(paths);
        return t("share.copied", { n: paths.length });
      }),
  };
}

function ShareNote({ note }: { note: Note | null }) {
  if (!note) return null;
  return (
    <p className={note.ok ? "share-note" : "share-note bad"} role="status">
      {note.ok ? <CheckIcon size={13} /> : <AlertIcon size={13} />}
      <span>{note.text}</span>
    </p>
  );
}

/** Email…, Share… and Copy file for `paths`, in a row of their own. */
export function ShareActions(props: { paths: string[]; disabled?: boolean; ghost?: boolean }) {
  const s = useShare();
  const { email, share, copy } = s.abilities;
  if (!props.paths.length || !(email || share || copy)) return null;
  const cls = props.ghost ? "btn ghost" : "btn";
  return (
    <div className="share-actions">
      {email && (
        <button className={cls} onClick={() => s.email(props.paths)} disabled={props.disabled} title={t("share.emailTitle")}>
          {t("share.email")}
        </button>
      )}
      {share && (
        <button className={cls} onClick={(e) => s.share(props.paths, e.currentTarget)} disabled={props.disabled} title={t("share.shareTitle")}>
          {t("share.share")}
        </button>
      )}
      {copy && (
        <button className={cls} onClick={() => s.copy(props.paths)} disabled={props.disabled} title={t("share.copyTitle")}>
          {t("share.copy", { n: props.paths.length })}
        </button>
      )}
      <ShareNote note={s.note} />
    </div>
  );
}

/** Where the menu goes: fixed, as the list scrolls and clips; above the button near the bottom. */
function menuPlace(button: HTMLElement): React.CSSProperties {
  const r = button.getBoundingClientRect();
  const right = window.innerWidth - r.right;
  return r.bottom + 200 > window.innerHeight ? { position: "fixed", bottom: window.innerHeight - r.top + 4, top: "auto", right } : { position: "fixed", top: r.bottom + 4, right };
}

/** A share button with a menu, for a row in a list (Recent). */
export function ShareMenu(props: { path: string; name: string; disabled?: boolean }) {
  const s = useShare();
  const [place, setPlace] = useState<React.CSSProperties | null>(null);
  const open = place !== null;
  const wrap = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!open) return;
    wrap.current?.querySelector<HTMLElement>(".menu button")?.focus();
    const close = () => setPlace(null);
    const down = (e: PointerEvent) => !wrap.current?.contains(e.target as Node) && close();
    const key = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      close();
      button.current?.focus();
    };
    window.addEventListener("pointerdown", down);
    window.addEventListener("keydown", key);
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    return () => {
      window.removeEventListener("pointerdown", down);
      window.removeEventListener("keydown", key);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
    };
  }, [open]);
  // The menu stays open while it has something to say.
  const act = async (f: () => Promise<boolean>) => {
    if (!(await f())) setPlace(null);
  };
  const paths = [props.path];
  const label = t("share.menu", { name: props.name });
  return (
    <div className="share-menu" ref={wrap}>
      <button
        ref={button}
        className="share-menu-btn"
        onClick={(e) => setPlace(open ? null : menuPlace(e.currentTarget))}
        disabled={props.disabled}
        title={label}
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
      >
        <ShareIcon size={13} />
      </button>
      {open && (
        <div className="menu" role="menu" aria-label={label} style={place}>
          {s.abilities.email && (
            <button role="menuitem" onClick={() => act(() => s.email(paths))} title={t("share.emailTitle")}>
              {t("share.email")}
            </button>
          )}
          {s.abilities.share && (
            <button role="menuitem" onClick={(e) => act(() => s.share(paths, e.currentTarget))} title={t("share.shareTitle")}>
              {t("share.share")}
            </button>
          )}
          {s.abilities.copy && (
            <button role="menuitem" onClick={() => act(() => s.copy(paths))} title={t("share.copyTitle")}>
              {t("share.copy", { n: 1 })}
            </button>
          )}
          <button
            role="menuitem"
            onClick={() => {
              setPlace(null);
              api.revealFile(props.path).catch(() => {});
            }}
          >
            {t("common.showInFolder")}
          </button>
          <ShareNote note={s.note} />
        </div>
      )}
    </div>
  );
}
