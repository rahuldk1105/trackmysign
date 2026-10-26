import { useEffect, useLayoutEffect, useRef, useState } from "react";
import * as pdfjs from "pdfjs-dist/legacy/build/pdf.mjs";
import type { PDFDocumentProxy } from "pdfjs-dist";
// Legacy build: polyfills newer JS so it also runs in older system web views.
import workerUrl from "pdfjs-dist/legacy/build/pdf.worker.min.mjs?url";
import type { EmptyField, Rect } from "./api";
import { FormLayer, type FormState } from "./FormLayer";
import { t } from "./i18n";
import { useStampDrawing, type StampContent } from "./stamp";
import { StampView, type StampUrls } from "./StampView";

pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;

export interface Placement extends Rect {
  page: number;
}

export interface PageSize {
  width: number;
  height: number;
}

/** A signature field being drawn for someone else to sign. */
export interface DraftBox extends Placement {
  id: number;
  name: string;
}

/** Drawing new signature fields: a drag on a page draws one, a click puts a box of the usual size. */
export interface DraftLayer {
  boxes: DraftBox[];
  selected: number | null;
  onSelect: (id: number) => void;
  onDraw: (p: Placement) => void;
  onChange: (id: number, p: Placement) => void;
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
  /** Form fields to fill in, shown as inputs over the pages. */
  form?: FormState | null;
  /** Signature fields being drawn; set instead of `placement`. */
  drafts?: DraftLayer | null;
}

const MIN_W = 90;

const MIN_H = 30;

/** Smallest new signature field. */
const DRAFT_MIN_W = 40;

const DRAFT_MIN_H = 20;

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
  form,
  drafts,
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
            form={form ?? null}
            drafts={drafts ?? null}
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
  drafts: DraftLayer | null;
  form: FormState | null;
}

function Page({ doc, index, size, scale, placement, ghost, stamp, urls, preview, onPlace, fields, onPickField, field, drafts, form }: PageProps) {
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

  /** The box drawn as it is being drawn. */
  const [drawing, setDrawing] = useState<Placement | null>(null);

  const clamp = (p: Placement, minW = MIN_W, minH = MIN_H): Placement => {
    const w = Math.min(Math.max(p.w, minW), size.width);
    const h = Math.min(Math.max(p.h, minH), size.height);
    return {
      page: index,
      w,
      h,
      x: Math.min(Math.max(p.x, 0), size.width - w),
      y: Math.min(Math.max(p.y, 0), size.height - h),
    };
  };

  const onPageDown = (e: React.PointerEvent) => {
    if ((e.target as HTMLElement).closest(".sig-box, .sig-field, .draft-field, .form-field")) return;
    if (drafts) return drawDraft(e);
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

  const drawDraft = (e: React.PointerEvent) => {
    if (!drafts || e.button !== 0) return;
    e.preventDefault();
    const start = toPoints(e.clientX, e.clientY);
    const box = (pt: { x: number; y: number }): Placement => ({
      page: index,
      x: Math.min(start.x, pt.x),
      y: Math.min(start.y, pt.y),
      w: Math.abs(pt.x - start.x),
      h: Math.abs(pt.y - start.y),
    });
    let last = box(start);
    const move = (ev: PointerEvent) => {
      last = box(toPoints(ev.clientX, ev.clientY));
      setDrawing(last);
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      setDrawing(null);
      // A click (or a tiny drag) puts a box of the usual size there.
      const drawn = last.w >= 8 && last.h >= 8 ? last : { page: index, x: start.x - 85, y: start.y - 27.5, w: 170, h: 55 };
      drafts.onDraw(clamp(drawn, DRAFT_MIN_W, DRAFT_MIN_H));
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  const dragDraft = (b: DraftBox, mode: "move" | "resize") => (e: React.PointerEvent) => {
    if (!drafts) return;
    e.stopPropagation();
    e.preventDefault();
    drafts.onSelect(b.id);
    const start = toPoints(e.clientX, e.clientY);
    const move = (ev: PointerEvent) => {
      const pt = toPoints(ev.clientX, ev.clientY);
      const dx = pt.x - start.x;
      const dy = pt.y - start.y;
      const p = mode === "move" ? { ...b, x: b.x + dx, y: b.y + dy } : { ...b, w: b.w + dx, h: b.h + dy };
      drafts.onChange(b.id, clamp(p, DRAFT_MIN_W, DRAFT_MIN_H));
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
        className={drafts ? "page draw-fields" : "page"}
        ref={holder}
        style={{ width: size.width * scale, height: size.height * scale }}
        onPointerDown={onPageDown}
      >
        <canvas ref={canvas} style={{ width: "100%", height: "100%" }} />
        {form && <FormLayer form={form} page={index} scale={scale} />}
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
        {drafts?.boxes
          .filter((b) => b.page === index)
          .map((b) => (
            <div
              key={b.id}
              className={`draft-field ${drafts.selected === b.id ? "on" : ""}`}
              style={{ left: b.x * scale, top: b.y * scale, width: b.w * scale, height: b.h * scale }}
              onPointerDown={dragDraft(b, "move")}
              title={t("view.dragMove")}
            >
              <span>{b.name || t("newFields.unnamed")}</span>
              <div className="sig-resize" onPointerDown={dragDraft(b, "resize")} title={t("view.dragResize")} />
            </div>
          ))}
        {drawing && (
          <div className="draft-field drawing" style={{ left: drawing.x * scale, top: drawing.y * scale, width: drawing.w * scale, height: drawing.h * scale }} />
        )}
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
