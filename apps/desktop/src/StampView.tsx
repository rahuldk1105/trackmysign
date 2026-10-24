// Draws a signature box as the core laid it out (see stamp.ts): the same
// rectangles, image places, font sizes and baselines as the PDF. Text is
// stretched to the width the PDF font gives it, so browser fonts with
// slightly other metrics still line up.

import { useId } from "react";
import type { Drawing, FontFamily, Rgb } from "./stamp";
import "./designer.css";

const FONT_CSS: Record<FontFamily, string> = {
  helvetica: "Helvetica, Arial, sans-serif",
  times: "'Times New Roman', Times, serif",
  courier: "'Courier New', Courier, monospace",
};

const css = ([r, g, b]: Rgb) => `rgb(${Math.round(r * 255)} ${Math.round(g * 255)} ${Math.round(b * 255)})`;

export interface StampUrls {
  signature?: string | null;
  seal?: string | null;
}

/** Fills its parent; the drawing is stretched to it. */
export function StampView({ drawing: d, urls }: { drawing: Drawing; urls: StampUrls }) {
  const clip = useId();
  const h = d.height;
  // PDF space has y up; SVG has y down.
  const flip = (y: number, height = 0) => h - y - height;
  return (
    <svg className="stamp-svg" viewBox={`0 0 ${d.width} ${h}`} preserveAspectRatio="none" aria-hidden>
      {d.background && <rect x={0} y={0} width={d.width} height={h} fill={css(d.background)} />}
      {d.border && (
        <rect
          x={d.border.width / 2}
          y={d.border.width / 2}
          width={d.width - d.border.width}
          height={h - d.border.width}
          fill="none"
          stroke={css(d.border.color)}
          strokeWidth={d.border.width}
        />
      )}
      {d.images.map((im, i) => {
        const url = im.kind === "signature" ? urls.signature : urls.seal;
        const [x, y, w, ih] = im.rect;
        return url ? <image key={i} href={url} x={x} y={flip(y, ih)} width={w} height={ih} opacity={im.opacity} preserveAspectRatio="none" /> : null;
      })}
      {d.clip && (
        <clipPath id={clip}>
          <rect x={d.clip[0]} y={flip(d.clip[1], d.clip[3])} width={d.clip[2]} height={d.clip[3]} />
        </clipPath>
      )}
      <g clipPath={d.clip ? `url(#${clip})` : undefined} fill={css(d.textColor)} fontFamily={FONT_CSS[d.font]} style={{ whiteSpace: "pre" }}>
        {d.text.map((t, i) => (
          <text
            key={i}
            x={t.x}
            y={flip(t.y)}
            fontSize={t.size}
            fontWeight={t.bold ? 700 : 400}
            textLength={t.width > 0 ? t.width : undefined}
            lengthAdjust="spacingAndGlyphs"
          >
            {t.text}
          </text>
        ))}
      </g>
      {d.tick && (
        <polyline
          points={[
            [0.12, 0.52],
            [0.4, 0.2],
            [0.88, 0.82],
          ]
            .map(([fx, fy]) => `${d.tick![0] + fx * d.tick![2]},${flip(d.tick![1] + fy * d.tick![3])}`)
            .join(" ")}
          fill="none"
          stroke="rgb(26 140 64)"
          strokeWidth={d.tick[2] * 0.14}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      )}
    </svg>
  );
}
