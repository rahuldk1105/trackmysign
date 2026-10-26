import { useEffect, useLayoutEffect, useRef, useState } from "react";
import * as pdfjs from "pdfjs-dist/legacy/build/pdf.mjs";
import type { PDFDocumentProxy } from "pdfjs-dist";
// Legacy build: polyfills newer JS so it also runs in older system web views.
import workerUrl from "pdfjs-dist/legacy/build/pdf.worker.min.mjs?url";
import type { EmptyField, Rect } from "./api";
import { t } from "./i18n";
import { ctcPlaced, ctcRect, useStampDrawing, type CtcStyle, type StampContent } from "./stamp";
import { StampView, type StampUrls } from "./StampView";

pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;

export interface Placement extends Rect {
  page: number;
}

export interface PageSize {
  width: number;
  height: number;
}

/** Loads a PDF and reports page sizes in points (as displayed, rotation applied). */
export async function loadPdf(bytes: ArrayBuffer, password?: string): Promise<{ doc: PDFDocumentProxy; sizes: PageSize[] }> {
  const doc = await pdfjs.getDocument({ data: new Uint8Array(bytes), password }).promise;
  const sizes: PageSize[] = [];
  for (let i = 1; i <= doc.numPages; i++) {
    const vp = (await doc.getPage(i)).getViewport({ scale: 1 });
    sizes.push({ width: vp.width, height: vp.height });
  }
  return { doc, sizes };
}

/**
 * The box drawn on one page moved to another: each edge keeps its distance
 * from the nearer side of the page, clamped to fit. Mirrors `rect_on_page`
 * in the signing engine.
 */
export function placeOn(p: Placement, from: PageSize, to: PageSize, page: number): Placement {
  const w = Math.min(p.w, to.width);
  const h = Math.min(p.h, to.height);
  const x = p.x + p.w / 2 > from.width / 2 ? to.width - w - (from.width - p.x - p.w) : p.x;
  const y = p.y + p.h / 2 > from.height / 2 ? to.height - h - (from.height - p.y - p.h) : p.y;
  return {
    page,
    w,
    h,
    x: Math.min(Math.max(x, 0), to.width - w),
    y: Math.min(Math.max(y, 0), to.height - h),
  };
}

interface Props {
  doc: PDFDocumentProxy;
  sizes: PageSize[];
  placement: Placement | null;
  /** Pages that get the box; null for just the placement's page. */
  pages?: number[] | null;
  /** What the box shows, laid out by the core; `preview` lines outside the app. */
  stamp: StampContent;
  urls: StampUrls;
  preview: string[];
  /** Multiplier on fit-to-width (1 = fit). */
  zoom: number;
  onPlace: (p: Placement) => void;
  /** Reports the effective scale (1 = 100%) and the fit-to-width scale. */
  onScale?: (scale: number, fit: number) => void;
  /** Reports the page that currently fills the view. */
  onPageChange?: (page: number) => void;
  /** Scrolls to a page whenever this changes (`n` lets the same page be requested again). */
  goto?: { page: number; n: number } | null;
  /** Empty signature fields to highlight; clicking one calls `onPickField`. */
  fields?: EmptyField[];
  onPickField?: (f: EmptyField) => void;
  /** The box sits in this signature field: it cannot be moved or resized. */
  field?: string | null;
  /** "Certified true copy" stamps on `pages`; moving or resizing one moves them all. */
  ctc?: CtcView | null;
}

export interface CtcView {
  style: CtcStyle;
  pages: number[];
  content: StampContent;
  urls: StampUrls;
  /** Shown outside the app, where nothing lays the stamp out. */
  preview: string[];
  onChange: (style: CtcStyle) => void;
}

const MIN_W = 90;

const MIN_H = 30;

export function PdfView({
  doc,
  sizes,
  placement,
  pages,
  stamp,
  urls,
  preview,
  zoom,
  onPlace,
  onScale,
  onPageChange,
  goto,
  fields,
  onPickField,
  field,
  ctc,
}: Props) {
  const scroller = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);

  useLayoutEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setWidth(el.clientWidth));
    ro.observe(el);
    setWidth(el.clientWidth);
    return () => ro.disconnect();
  }, []);

  const maxPageWidth = Math.max(...sizes.map((s) => s.width));
  const fit = Math.min(1.6, Math.max(0.3, (width - 64) / maxPageWidth));
  const scale = Math.min(4, Math.max(0.25, fit * zoom));

  useEffect(() => {
    if (width) onScale?.(scale, fit);
  }, [scale, fit, width, onScale]);

  // Keep the same part of the document in view when the scale changes.
  const prevScale = useRef<{ doc: PDFDocumentProxy; scale: number } | null>(null);
  useLayoutEffect(() => {
    const el = scroller.current;
    const prev = prevScale.current;
    prevScale.current = { doc, scale };
    if (!el || !prev || prev.doc !== doc || prev.scale === scale) return;
    const mid = el.scrollTop + el.clientHeight / 2;
    el.scrollTop = Math.max(0, mid * (scale / prev.scale) - el.clientHeight / 2);
  }, [doc, scale]);

  // When a document opens, scroll so the signature box is in view.
  const scrolledFor = useRef<PDFDocumentProxy | null>(null);
  useLayoutEffect(() => {
    const el = scroller.current;
    if (!el || !width || !placement || scrolledFor.current === doc) return;
    const pageEl = el.querySelector(`[data-page="${placement.page}"]`) as HTMLElement | null;
    if (!pageEl) return;
    scrolledFor.current = doc;
    const boxMid = pageEl.offsetTop + (placement.y + placement.h / 2) * scale;
    el.scrollTop = Math.max(0, boxMid - el.clientHeight * 0.6);
    trackPage();
  }, [doc, placement, scale, width]);

  // Which page is in view: the last page whose top is above 40% of the viewport.
  const current = useRef(-1);
  const trackPage = () => {
    const el = scroller.current;
    if (!el) return;
    const line = el.scrollTop + el.clientHeight * 0.4;
    let page = 0;
    el.querySelectorAll<HTMLElement>("[data-page]").forEach((p, i) => {
      if (p.offsetTop <= line) page = i;
    });
    if (el.scrollHeight > el.clientHeight + 2 && el.scrollTop + el.clientHeight >= el.scrollHeight - 2) page = sizes.length - 1;
    if (page !== current.current) {
      current.current = page;
      onPageChange?.(page);
    }
  };
  useEffect(() => {
    current.current = -1;
  }, [doc]);

  useEffect(() => {
    const el = scroller.current;
    if (!el || !goto) return;
    const pageEl = el.querySelector(`[data-page="${goto.page}"]`) as HTMLElement | null;
    if (pageEl) el.scrollTo({ top: Math.max(0, pageEl.offsetTop - 20) });
  }, [goto]);

  return (
    <div className="pages" ref={scroller} onScroll={trackPage}>
      {sizes.map((s, i) => {
        let box: Placement | null = null;
        if (placement?.page === i) box = placement;
        else if (placement && pages?.includes(i)) box = placeOn(placement, sizes[placement.page], s, i);
        return (
          <Page
            key={i}
            doc={doc}
            index={i}
            size={s}
            scale={scale}
            placement={box}
            ghost={!!box && !!pages && !pages.includes(i)}
            stamp={stamp}
            urls={urls}
            preview={preview}
            onPlace={onPlace}
            fields={fields?.filter((f) => f.page === i && f.rect) ?? []}
            onPickField={onPickField}
            field={field ?? null}
            ctc={ctc?.pages.includes(i) ? ctc : null}
          />
        );
      })}
    </div>
  );
}

interface PageProps {
  doc: PDFDocumentProxy;
  index: number;
  size: PageSize;
  scale: number;
  placement: Placement | null;
  /** The box is drawn here but this page is not in the selection. */
  ghost: boolean;
  stamp: StampContent;
  urls: StampUrls;
  preview: string[];
  onPlace: (p: Placement) => void;
  fields: EmptyField[];
  onPickField?: (f: EmptyField) => void;
  field: string | null;
  ctc: CtcView | null;
}

function Page({ doc, index, size, scale, placement, ghost, stamp, urls, preview, onPlace, fields, onPickField, field, ctc }: PageProps) {
  const holder = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const el = holder.current;
    if (!el) return;
    const io = new IntersectionObserver(([e]) => e.isIntersecting && setVisible(true), { rootMargin: "600px" });
    io.observe(el);
    return () => io.disconnect();
  }, []);

  useEffect(() => {
    if (!visible || !canvas.current) return;
    let cancelled = false;
    let task: ReturnType<Awaited<ReturnType<PDFDocumentProxy["getPage"]>>["render"]> | null = null;
    (async () => {
      const page = await doc.getPage(index + 1);
      if (cancelled || !canvas.current) return;
      const dpr = window.devicePixelRatio || 1;
      const vp = page.getViewport({ scale: scale * dpr });
      const c = canvas.current;
      c.width = Math.floor(vp.width);
      c.height = Math.floor(vp.height);
      task = page.render({ canvas: c, viewport: vp });
      await task.promise.catch(() => {});
    })();
    return () => {
      cancelled = true;
      task?.cancel();
    };
  }, [visible, doc, index, scale]);

  const toPoints = (clientX: number, clientY: number) => {
    const r = holder.current!.getBoundingClientRect();
    return { x: (clientX - r.left) / scale, y: (clientY - r.top) / scale };
  };

  const clamp = (p: Placement): Placement => {
    const w = Math.min(Math.max(p.w, MIN_W), size.width);
    const h = Math.min(Math.max(p.h, MIN_H), size.height);
    return {
      page: index,
      w,
      h,
      x: Math.min(Math.max(p.x, 0), size.width - w),
      y: Math.min(Math.max(p.y, 0), size.height - h),
    };
  };

  const onPageDown = (e: React.PointerEvent) => {
    if ((e.target as HTMLElement).closest(".sig-box, .sig-field, .ctc-box")) return;
    const pt = toPoints(e.clientX, e.clientY);
    const w = placement?.w ?? 170;
    const h = placement?.h ?? 55;
    onPlace(clamp({ page: index, x: pt.x - w / 2, y: pt.y - h / 2, w, h }));
  };

  const drag = (mode: "move" | "resize") => (e: React.PointerEvent) => {
    if (!placement || field) return;
    e.stopPropagation();
    e.preventDefault();
    const start = toPoints(e.clientX, e.clientY);
    const orig = { ...placement };
    const move = (ev: PointerEvent) => {
      const pt = toPoints(ev.clientX, ev.clientY);
      const dx = pt.x - start.x;
      const dy = pt.y - start.y;
      onPlace(
        clamp(mode === "move" ? { ...orig, x: orig.x + dx, y: orig.y + dy } : { ...orig, w: orig.w + dx, h: orig.h + dy }),
      );
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  return (
    <div className="page-wrap" data-page={index}>
      <div
        className="page"
        ref={holder}
        style={{ width: size.width * scale, height: size.height * scale }}
        onPointerDown={onPageDown}
      >
        <canvas ref={canvas} style={{ width: "100%", height: "100%" }} />
        {fields.map(
          (f) =>
            f.rect && (
              <div
                key={f.name}
                className="sig-field"
                style={{ left: f.rect.x * scale, top: f.rect.y * scale, width: f.rect.w * scale, height: f.rect.h * scale }}
                onPointerDown={(e) => {
                  e.stopPropagation();
                  onPickField?.(f);
                }}
                title={t("fields.signInto", { name: f.name })}
              >
                <span>{f.name}</span>
              </div>
            ),
        )}
        {ctc && <CtcBox ctc={ctc} size={size} scale={scale} toPoints={toPoints} />}
        {placement && (
          <StampBox
            placement={placement}
            ghost={ghost}
            field={field}
            stamp={stamp}
            urls={urls}
            preview={preview}
            scale={scale}
            onMove={drag("move")}
            onResize={drag("resize")}
          />
        )}
      </div>
      <div className="page-num">{index + 1}</div>
    </div>
  );
}

const CTC_MIN_W = 40;
const CTC_MIN_H = 20;

/** One page's "certified true copy" stamp, placed by its corner rule. */
function CtcBox(props: { ctc: CtcView; size: PageSize; scale: number; toPoints: (x: number, y: number) => { x: number; y: number } }) {
  const { ctc, size, scale } = props;
  const r = ctcRect(ctc.style, size.width, size.height);
  const drawing = useStampDrawing(ctc.content, r.w, r.h);

  const drag = (mode: "move" | "resize") => (e: React.PointerEvent) => {
    e.stopPropagation();
    e.preventDefault();
    const start = props.toPoints(e.clientX, e.clientY);
    const move = (ev: PointerEvent) => {
      const pt = props.toPoints(ev.clientX, ev.clientY);
      const dx = pt.x - start.x;
      const dy = pt.y - start.y;
      const w = Math.min(Math.max(mode === "resize" ? r.w + dx : r.w, CTC_MIN_W), size.width);
      const h = Math.min(Math.max(mode === "resize" ? r.h + dy : r.h, CTC_MIN_H), size.height);
      const x = Math.min(Math.max(mode === "move" ? r.x + dx : r.x, 0), size.width - w);
      const y = Math.min(Math.max(mode === "move" ? r.y + dy : r.y, 0), size.height - h);
      ctc.onChange(ctcPlaced(ctc.style, { x, y, w, h }, size.width, size.height));
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  return (
    <div
      className={`sig-box ctc-box ${drawing ? "drawn" : ""}`}
      style={{ left: r.x * scale, top: r.y * scale, width: r.w * scale, height: r.h * scale, fontSize: 8 * scale }}
      onPointerDown={drag("move")}
      title={t("view.ctcBox")}
    >
      {drawing ? (
        <StampView drawing={drawing} urls={ctc.urls} />
      ) : (
        ctc.preview.map((l, i) => (
          <div key={i} className={i === 0 ? "sig-name" : undefined}>
            {l}
          </div>
        ))
      )}
      <div className="sig-resize" onPointerDown={drag("resize")} title={t("view.dragResize")} />
    </div>
  );
}

function boxTitle(ghost: boolean, field: string | null) {
  if (field) return t("view.fieldBox", { name: field });
  return ghost ? t("view.ghost") : t("view.dragMove");
}

function StampBox(props: {
  placement: Placement;
  ghost: boolean;
  field: string | null;
  stamp: StampContent;
  urls: StampUrls;
  preview: string[];
  scale: number;
  onMove: (e: React.PointerEvent) => void;
  onResize: (e: React.PointerEvent) => void;
}) {
  const { placement: p, scale } = props;
  const drawing = useStampDrawing(props.stamp, p.w, p.h);
  return (
    <div
      className={`sig-box ${drawing ? "drawn" : ""} ${props.ghost ? "ghost" : ""} ${props.field ? "in-field" : ""}`}
      style={{ left: p.x * scale, top: p.y * scale, width: p.w * scale, height: p.h * scale, fontSize: 8 * scale }}
      onPointerDown={props.onMove}
      title={boxTitle(props.ghost, props.field)}
    >
      {drawing ? (
        <StampView drawing={drawing} urls={props.urls} />
      ) : (
        props.preview.map((l, i) => (
          <div key={i} className={i === 1 ? "sig-name" : undefined}>
            {l}
          </div>
        ))
      )}
      {!props.field && <div className="sig-resize" onPointerDown={props.onResize} title={t("view.dragResize")} />}
    </div>
  );
}
