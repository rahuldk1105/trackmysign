// "Pages": prepares a document before it is signed. Pages are dragged into
// order, turned, deleted, blank pages inserted and other PDFs appended; the
// result is saved as a new PDF (`assemble_pages`), which then opens for
// signing. The original files are only read.

import { useCallback, useEffect, useRef, useState } from "react";
import type { PDFDocumentProxy } from "pdfjs-dist";
import * as api from "./api";
import type { PageItem, PageNotice } from "./api";
import { t } from "./i18n";
import { errorText } from "./i18n/errors";
import { loadPdf, type PageSize } from "./PdfView";
import { AlertIcon, CloseIcon, FileIcon, LockIcon, PlusIcon, RotateLeftIcon, RotateRightIcon, TrashIcon, UndoIcon } from "./icons";
import "./pages.css";

interface Source {
  path: string;
  name: string;
  password?: string;
  pdf: PDFDocumentProxy;
  /** Displayed sizes (the page's own rotation applied). */
  sizes: PageSize[];
  notices: PageNotice[];
}

type Tile = { key: number; source: number; page: number; rotate: number } | { key: number; source: null; width: number; height: number };

/** A PDF waiting for its password (or its owner password) before it can be used. */
interface Locked {
  path: string;
  name: string;
  owner: boolean;
  error?: string;
  /** The document the dialog was opened for: cancelling closes the dialog. */
  first: boolean;
}

const THUMB = 132;
const isMac = /mac/i.test(navigator.platform);

const baseName = (p: string) => p.split(/[\\/]/).pop() ?? p;

/** The tile's size on screen, its extra turn applied. */
function tileSize(tile: Tile, sources: Source[]): PageSize {
  if (tile.source === null) return { width: tile.width, height: tile.height };
  const s = sources[tile.source].sizes[tile.page];
  return tile.rotate % 180 ? { width: s.height, height: s.width } : s;
}

function Thumb(props: { pdf: PDFDocumentProxy; page: number; rotate: number; size: PageSize }) {
  const { pdf, page, rotate, size } = props;
  const canvas = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    let cancelled = false;
    let task: ReturnType<Awaited<ReturnType<PDFDocumentProxy["getPage"]>>["render"]> | null = null;
    (async () => {
      const p = await pdf.getPage(page + 1);
      if (cancelled || !canvas.current) return;
      const base = p.getViewport({ scale: 1 });
      const dpr = window.devicePixelRatio || 1;
      const vp = p.getViewport({ scale: (THUMB / Math.max(base.width, base.height)) * dpr });
      const c = canvas.current;
      c.width = Math.floor(vp.width);
      c.height = Math.floor(vp.height);
      task = p.render({ canvas: c, viewport: vp });
      await task.promise.catch(() => {});
    })();
    return () => {
      cancelled = true;
      task?.cancel();
    };
  }, [pdf, page]);
  // Drawn once as the page shows now; the extra turn is only a transform,
  // and a square of THUMB fits the page either way round.
  const k = THUMB / Math.max(size.width, size.height);
  return <canvas ref={canvas} style={{ width: size.width * k, height: size.height * k, transform: `rotate(${rotate}deg)` }} />;
}

export function PagesDialog(props: {
  path: string;
  password?: string;
  pdf: PDFDocumentProxy;
  sizes: PageSize[];
  onSaved: (output: string) => void;
  onClose: () => void;
}) {
  const { onClose } = props;
  const nextKey = useRef(0);
  const key = () => nextKey.current++;
  const [sources, setSources] = useState<Source[]>([]);
  /** Sources added so far, counted as they are added (adds run one after another). */
  const added = useRef(0);
  const [{ tiles, history }, setLayout] = useState<{ tiles: Tile[]; history: Tile[][] }>({ tiles: [], history: [] });
  const [locked, setLocked] = useState<Locked | null>(null);
  const [password, setPassword] = useState("");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [drag, setDrag] = useState<{ key: number; x: number; y: number; active: boolean; at: number | null } | null>(null);
  const [focus, setFocus] = useState<number | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const grid = useRef<HTMLUListElement>(null);
  const pwInput = useRef<HTMLInputElement>(null);

  /** Changes the pages, keeping the previous order for undo. */
  const change = useCallback((next: (cur: Tile[]) => Tile[]) => {
    setLayout((l) => {
      const n = next(l.tiles);
      return n === l.tiles ? l : { tiles: n, history: [...l.history.slice(-49), l.tiles] };
    });
    setConfirm(false);
    setSaveError(null);
  }, []);

  const undo = useCallback(() => {
    setLayout((l) => (l.history.length ? { tiles: l.history[l.history.length - 1], history: l.history.slice(0, -1) } : l));
    setConfirm(false);
  }, []);

  /** Adds a source and its pages (at the end). The first is the open document. */
  const add = useCallback(
    async (path: string, pw: string | undefined, first: boolean, opened?: { doc: PDFDocumentProxy; sizes: PageSize[] }) => {
      setLoadError(null);
      let notices: PageNotice[];
      try {
        notices = await api.pagesSource(path, pw);
      } catch (e) {
        const err = api.errorOf(e);
        if (err.kind === "password" || err.kind === "permission") {
          setLocked({ path, name: baseName(path), owner: err.kind === "permission", first, error: pw === undefined ? undefined : errorText(err) });
          setPassword("");
        } else if (first) {
          setLocked(null);
          setLoadError(errorText(err));
        } else {
          setLocked(null);
          setLoadError(t("pages.loadFailed", { name: baseName(path), message: errorText(err) }));
        }
        return;
      }
      try {
        const { doc: pdf, sizes } = opened ?? (await loadPdf(await api.readPdf(path), pw));
        setLocked(null);
        const source = added.current++;
        const pages: Tile[] = sizes.map((_, page) => ({ key: key(), source, page, rotate: 0 }));
        setSources((cur) => [...cur, { path, name: baseName(path), password: pw, pdf, sizes, notices }]);
        // The open document's pages are where undo stops.
        if (first) setLayout({ tiles: pages, history: [] });
        else change((tl) => [...tl, ...pages]);
      } catch (e) {
        setLocked(null);
        setLoadError(t("pages.loadFailed", { name: baseName(path), message: errorText(api.errorOf(e)) }));
      }
    },
    [change],
  );

  const started = useRef(false);
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    add(props.path, props.password, true, { doc: props.pdf, sizes: props.sizes });
  }, [add, props.path, props.password, props.pdf, props.sizes]);

  useEffect(() => {
    if (locked) pwInput.current?.focus();
  }, [locked]);

  const addPdfs = async () => {
    const paths = await api.pickPdfs(sources[0] ? sources[0].path.replace(/[\\/][^\\/]*$/, "") : null);
    for (const p of paths) await add(p, undefined, false);
  };

  // Esc closes this dialog and nothing under it; Ctrl+Z undoes.
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !saving) {
        e.stopPropagation();
        onClose();
      } else if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === "z" && !(e.target instanceof HTMLInputElement)) {
        e.preventDefault();
        e.stopPropagation();
        undo();
      }
    };
    window.addEventListener("keydown", k, true);
    return () => window.removeEventListener("keydown", k, true);
  }, [onClose, undo, saving]);

  const rotate = (k: number, by: number) =>
    change((cur) => cur.map((tl) => (tl.key === k && tl.source !== null ? { ...tl, rotate: (tl.rotate + by + 360) % 360 } : tl)));
  const remove = (k: number) => change((cur) => cur.filter((tl) => tl.key !== k));
  const insertBlank = (k: number) =>
    change((cur) => {
      const i = cur.findIndex((tl) => tl.key === k);
      const s = tileSize(cur[i], sources);
      return [...cur.slice(0, i + 1), { key: key(), source: null, width: s.width, height: s.height }, ...cur.slice(i + 1)];
    });
  const move = (k: number, to: number) =>
    change((cur) => {
      const from = cur.findIndex((tl) => tl.key === k);
      if (from < 0 || to === from || to === from + 1) return cur;
      const next = cur.filter((tl) => tl.key !== k);
      next.splice(to > from ? to - 1 : to, 0, cur[from]);
      return next;
    });

  // ---- dragging: pointer events, so it works the same in every web view
  /** Where a page dropped at (x, y) goes: before the nearest tile, or after it. */
  const dropIndex = (x: number, y: number): number | null => {
    const items = grid.current ? [...grid.current.querySelectorAll<HTMLElement>(".page-tile")] : [];
    let best: { i: number; d: number; after: boolean } | null = null;
    items.forEach((el, i) => {
      const r = el.getBoundingClientRect();
      const cx = r.left + r.width / 2;
      const cy = r.top + r.height / 2;
      const d = Math.hypot(x - cx, (y - cy) * 2);
      if (!best || d < best.d) best = { i, d, after: x > cx };
    });
    if (!best) return null;
    const b: { i: number; after: boolean } = best;
    return b.after ? b.i + 1 : b.i;
  };

  const onPointerDown = (e: React.PointerEvent, k: number) => {
    if (e.button !== 0 || (e.target as HTMLElement).closest("button")) return;
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    setDrag({ key: k, x: e.clientX, y: e.clientY, active: false, at: null });
  };
  const onPointerMove = (e: React.PointerEvent) => {
    if (!drag) return;
    const active = drag.active || Math.hypot(e.clientX - drag.x, e.clientY - drag.y) > 5;
    if (active) setDrag({ ...drag, active, at: dropIndex(e.clientX, e.clientY) });
  };
  const onPointerUp = () => {
    if (drag?.active && drag.at !== null) move(drag.key, drag.at);
    setDrag(null);
  };

  const onTileKey = (e: React.KeyboardEvent, k: number, i: number) => {
    if (e.key === "Delete" || e.key === "Backspace") {
      e.preventDefault();
      remove(k);
    } else if (e.altKey && (e.key === "ArrowLeft" || e.key === "ArrowRight")) {
      e.preventDefault();
      move(k, e.key === "ArrowLeft" ? Math.max(0, i - 1) : Math.min(tiles.length, i + 2));
    } else if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      e.preventDefault();
      const n = tiles[Math.min(tiles.length - 1, Math.max(0, i + (e.key === "ArrowLeft" ? -1 : 1)))];
      if (n) grid.current?.querySelector<HTMLElement>(`[data-key="${n.key}"]`)?.focus();
    }
  };

  // ---- saving
  const used = [...new Set(tiles.flatMap((tl) => (tl.source === null ? [] : [tl.source])))].sort((a, b) => a - b);
  const signed = used.flatMap((i) =>
    sources[i].notices.flatMap((n) => (n.kind === "signaturesRemoved" ? [{ name: sources[i].name, n: n.count }] : [])),
  );
  const lost = used.flatMap((i) =>
    sources[i].notices.flatMap((n) =>
      n.kind === "passwordRemoved"
        ? [t("pages.passwordRemoved", { name: sources[i].name })]
        : n.kind === "bookmarksDropped"
          ? [t("pages.bookmarks", { name: sources[i].name })]
          : [],
    ),
  );

  const save = async () => {
    if (!tiles.length || !sources.length) return;
    if (signed.length && !confirm) {
      setConfirm(true);
      return;
    }
    const output = await api.pickPreparedPath(sources[0].path);
    if (!output) return;
    setSaving(true);
    setSaveError(null);
    try {
      const items: PageItem[] = tiles.map((tl) =>
        tl.source === null
          ? { kind: "blank", width: tl.width, height: tl.height }
          : { kind: "page", source: used.indexOf(tl.source), page: tl.page, rotate: tl.rotate },
      );
      await api.assemblePages(
        used.map((i) => ({ path: sources[i].path, password: sources[i].password ?? null })),
        items,
        output,
      );
      props.onSaved(output);
    } catch (e) {
      setSaveError(errorText(api.errorOf(e)));
      setSaving(false);
    }
  };

  const unlock = (e: React.FormEvent) => {
    e.preventDefault();
    if (locked && password) add(locked.path, password, locked.first);
  };

  const label = (tl: Tile, i: number) =>
    tl.source === null ? t("pages.blank") : t("pages.tileLabel", { n: i + 1, name: sources[tl.source].name, page: tl.page + 1 });

  return (
    <div className="backdrop" onPointerDown={(e) => e.target === e.currentTarget && !saving && onClose()}>
      <div className="dialog pages-dialog" role="dialog" aria-modal="true" aria-label={t("pages.title")}>
        <div className="dialog-title">
          <h2>{t("pages.title")}</h2>
          <span className="muted">{t("pages.count", { n: tiles.length })}</span>
          <div className="spacer" />
          <button className="tb-btn" onClick={onClose} disabled={saving} title={t("common.close")} aria-label={t("common.close")}>
            <CloseIcon />
          </button>
        </div>
        <div className="dialog-body">
          <div className="pages-bar">
            <button className="btn" onClick={addPdfs} disabled={saving || !!locked || !sources.length}>
              <PlusIcon size={14} />
              {t("pages.addPdf")}
            </button>
            <button className="btn" onClick={undo} disabled={saving || !history.length} title={t("pages.undoKey", { key: isMac ? "⌘Z" : "Ctrl+Z" })}>
              <UndoIcon size={14} />
              {t("pages.undo")}
            </button>
            <span className="muted small">{t("pages.hint")}</span>
          </div>

          {locked && (
            <form className="pages-locked" onSubmit={unlock}>
              <LockIcon size={14} />
              <label htmlFor="pages-password">{t(locked.owner ? "pages.needsOwner" : "pages.needsPassword", { name: locked.name })}</label>
              <input
                id="pages-password"
                ref={pwInput}
                type="password"
                className={locked.error ? "invalid" : undefined}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
              <button type="submit" className="btn primary" disabled={!password}>
                {t("pages.unlock")}
              </button>
              <button type="button" className="btn" onClick={() => (locked.first ? onClose() : setLocked(null))}>
                {t("common.cancel")}
              </button>
              {locked.error && (
                <p className="inline-error">
                  <AlertIcon size={14} /> {locked.error}
                </p>
              )}
            </form>
          )}
          {loadError && (
            <p className="inline-error">
              <AlertIcon size={14} /> {loadError}
            </p>
          )}

          <ul
            ref={grid}
            className={`pages-grid ${drag?.active ? "dragging" : ""}`}
            role="list"
            aria-label={t("pages.title")}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onPointerCancel={() => setDrag(null)}
          >
            {tiles.map((tl, i) => {
              const size = tileSize(tl, sources);
              const before = drag?.active && drag.at === i;
              const after = drag?.active && drag.at === tiles.length && i === tiles.length - 1;
              return (
                <li
                  key={tl.key}
                  data-key={tl.key}
                  className={`page-tile ${drag?.active && drag.key === tl.key ? "lifted" : ""} ${before ? "drop-before" : ""} ${after ? "drop-after" : ""} ${focus === tl.key ? "on" : ""}`}
                  tabIndex={0}
                  aria-label={label(tl, i)}
                  title={label(tl, i)}
                  onPointerDown={(e) => onPointerDown(e, tl.key)}
                  onKeyDown={(e) => onTileKey(e, tl.key, i)}
                  onFocus={() => setFocus(tl.key)}
                  onBlur={() => setFocus((f) => (f === tl.key ? null : f))}
                >
                  <div className="page-thumb">
                    {tl.source === null ? (
                      <i className="page-blank" style={{ width: (THUMB * size.width) / Math.max(size.width, size.height), height: (THUMB * size.height) / Math.max(size.width, size.height) }} />
                    ) : (
                      <Thumb pdf={sources[tl.source].pdf} page={tl.page} rotate={tl.rotate} size={sources[tl.source].sizes[tl.page]} />
                    )}
                  </div>
                  <div className="page-caption">
                    <span className="mono">{i + 1}</span>
                    {tl.source === null ? (
                      <span className="muted">{t("pages.blank")}</span>
                    ) : (
                      <span className="page-source muted" title={sources[tl.source].name}>
                        {sources.length > 1 && (
                          <>
                            <FileIcon size={11} />
                            <span className="page-file">{sources[tl.source].name}</span>
                          </>
                        )}
                        <span>{t("common.pageN", { n: tl.page + 1 })}</span>
                      </span>
                    )}
                  </div>
                  <div className="page-actions">
                    <button className="tb-btn" onClick={() => rotate(tl.key, -90)} disabled={tl.source === null} title={t("pages.rotateLeft")} aria-label={t("pages.rotateLeft")}>
                      <RotateLeftIcon size={14} />
                    </button>
                    <button className="tb-btn" onClick={() => rotate(tl.key, 90)} disabled={tl.source === null} title={t("pages.rotateRight")} aria-label={t("pages.rotateRight")}>
                      <RotateRightIcon size={14} />
                    </button>
                    <button className="tb-btn" onClick={() => insertBlank(tl.key)} title={t("pages.insertBlank")} aria-label={t("pages.insertBlank")}>
                      <PlusIcon size={14} />
                    </button>
                    <button className="tb-btn" onClick={() => remove(tl.key)} title={t("pages.delete")} aria-label={t("pages.delete")}>
                      <TrashIcon size={14} />
                    </button>
                  </div>
                </li>
              );
            })}
            {sources.length > 0 && !tiles.length && <p className="muted pages-empty">{t("pages.empty")}</p>}
          </ul>

          {signed.map((s) => (
            <div className="warn-row" key={s.name}>
              <AlertIcon size={14} />
              <div>
                <strong>{t("pages.signedTitle")}</strong>
                <span>{t("pages.signedBody", { name: s.name, n: s.n })}</span>
              </div>
            </div>
          ))}
          {lost.map((l) => (
            <div className="warn-row calm" key={l}>
              <AlertIcon size={14} />
              <div>
                <span>{l}</span>
              </div>
            </div>
          ))}
          {saveError && <p className="inline-error">{t("pages.saveFailed", { message: saveError })}</p>}

          <div className="dialog-actions">
            <span className="muted small">{t("pages.original")}</span>
            <div className="spacer" />
            <button className="btn" onClick={confirm ? () => setConfirm(false) : onClose} disabled={saving}>
              {t("common.cancel")}
            </button>
            <button className="btn primary" onClick={save} disabled={saving || !tiles.length || !!locked}>
              {saving ? t("pages.saving") : confirm ? t("pages.saveAnyway") : t("pages.saveAs")}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
