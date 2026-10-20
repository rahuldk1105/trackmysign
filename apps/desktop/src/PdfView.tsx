import { useEffect, useLayoutEffect, useRef, useState } from "react";
import * as pdfjs from "pdfjs-dist/legacy/build/pdf.mjs";
import type { PDFDocumentProxy } from "pdfjs-dist";
// Legacy build: polyfills newer JS so it also runs in older system web views.
import workerUrl from "pdfjs-dist/legacy/build/pdf.worker.min.mjs?url";
import type { Rect } from "./api";

pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;

export interface Placement extends Rect {
  page: number;
}

export interface PageSize {
  width: number;
  height: number;
}

/** Loads a PDF and reports page sizes in points (as displayed, rotation applied). */
export async function loadPdf(bytes: ArrayBuffer): Promise<{ doc: PDFDocumentProxy; sizes: PageSize[] }> {
  const doc = await pdfjs.getDocument({ data: new Uint8Array(bytes) }).promise;
  const sizes: PageSize[] = [];
  for (let i = 1; i <= doc.numPages; i++) {
    const vp = (await doc.getPage(i)).getViewport({ scale: 1 });
    sizes.push({ width: vp.width, height: vp.height });
  }
  return { doc, sizes };
}

interface Props {
  doc: PDFDocumentProxy;
  sizes: PageSize[];
  placement: Placement | null;
  preview: string[];
  onPlace: (p: Placement) => void;
}

const MIN_W = 90;

let measureCtx: CanvasRenderingContext2D | null = null;

/** Body font size (pt) so the lines fit the box — mirrors the PDF appearance. */
function fitFont(lines: string[], w: number, h: number): number {
  measureCtx ??= document.createElement("canvas").getContext("2d");
  const pad = Math.min(Math.max(Math.min(w, h) * 0.08, 1.5), 6);
  const scales = lines.map((_, i) => (i === 1 ? 1.15 : 1));
  let size = Math.min((h - 2 * pad) / scales.reduce((a, b) => a + b * 1.2, 0), 11);
  lines.forEach((l, i) => {
    if (!measureCtx) return;
    measureCtx.font = `${i === 1 ? "bold " : ""}100px Helvetica, Arial, sans-serif`;
    const per = (measureCtx.measureText(l).width / 100) * scales[i];
    if (per > 0) size = Math.min(size, (w - 2 * pad) / per);
  });
  return Math.max(size, 2);
}
const MIN_H = 30;

export function PdfView({ doc, sizes, placement, preview, onPlace }: Props) {
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
  const scale = Math.min(1.6, Math.max(0.3, (width - 64) / maxPageWidth));

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
  }, [doc, placement, scale, width]);

  return (
    <div className="pages" ref={scroller}>
      {sizes.map((s, i) => (
        <Page
          key={i}
          doc={doc}
          index={i}
          size={s}
          scale={scale}
          placement={placement?.page === i ? placement : null}
          preview={preview}
          onPlace={onPlace}
        />
      ))}
    </div>
  );
}

interface PageProps {
  doc: PDFDocumentProxy;
  index: number;
  size: PageSize;
  scale: number;
  placement: Placement | null;
  preview: string[];
  onPlace: (p: Placement) => void;
}

function Page({ doc, index, size, scale, placement, preview, onPlace }: PageProps) {
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
    if ((e.target as HTMLElement).closest(".sig-box")) return;
    const pt = toPoints(e.clientX, e.clientY);
    const w = placement?.w ?? 170;
    const h = placement?.h ?? 55;
    onPlace(clamp({ page: index, x: pt.x - w / 2, y: pt.y - h / 2, w, h }));
  };

  const drag = (mode: "move" | "resize") => (e: React.PointerEvent) => {
    if (!placement) return;
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
        {placement && (
          <div
            className="sig-box"
            style={{
              left: placement.x * scale,
              top: placement.y * scale,
              width: placement.w * scale,
              height: placement.h * scale,
              fontSize: fitFont(preview, placement.w, placement.h) * scale,
            }}
            onPointerDown={drag("move")}
            title="Drag to move"
          >
            {preview.map((l, i) => (
              <div key={i} className={i === 1 ? "sig-name" : undefined}>
                {l}
              </div>
            ))}
            <div className="sig-resize" onPointerDown={drag("resize")} title="Drag to resize" />
          </div>
        )}
      </div>
      <div className="page-num">Page {index + 1}</div>
    </div>
  );
}
