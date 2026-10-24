// Saved presets: reason, location and where the box goes, applied in one pick.

import type { ImageChoice } from "./api";
import { t } from "./i18n";
import type { PageSize, Placement } from "./PdfView";

/** Which page the box goes on: first, last, or a page number (1 = first). */
export type PageChoice = "first" | "last" | number;

export interface PresetPlacement {
  page: PageChoice;
  /** Millimetres from the top-left of the page. */
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface Preset {
  name: string;
  reason: string;
  location: string;
  placement: PresetPlacement | null;
  /** Missing in presets saved before images were supported: leave as is. */
  image?: ImageChoice;
}

const PT_PER_MM = 72 / 25.4;
const round = (v: number) => Math.round(v * 10) / 10;

export function pageChoice(page: number, pages: number): PageChoice {
  if (page === pages - 1) return "last";
  if (page === 0) return "first";
  return page + 1;
}

/** Zero-based page index for `choice` in a document of `pages` pages. */
export function resolvePage(choice: PageChoice, pages: number): number {
  if (choice === "first") return 0;
  if (choice === "last") return pages - 1;
  return Math.min(Math.max(choice - 1, 0), pages - 1);
}

export function describePage(choice: PageChoice): string {
  return choice === "first" ? t("preset.firstPage") : choice === "last" ? t("preset.lastPage") : t("common.pageN", { n: choice });
}

export function toPresetPlacement(p: Placement, pages: number): PresetPlacement {
  return {
    page: pageChoice(p.page, pages),
    x: round(p.x / PT_PER_MM),
    y: round(p.y / PT_PER_MM),
    w: round(p.w / PT_PER_MM),
    h: round(p.h / PT_PER_MM),
  };
}

/** The preset's box on this document, kept inside the page. */
export function fromPresetPlacement(pp: PresetPlacement, sizes: PageSize[]): Placement {
  const page = resolvePage(pp.page, sizes.length);
  const s = sizes[page];
  const w = Math.min(pp.w * PT_PER_MM, s.width);
  const h = Math.min(pp.h * PT_PER_MM, s.height);
  return {
    page,
    w,
    h,
    x: Math.min(Math.max(pp.x * PT_PER_MM, 0), s.width - w),
    y: Math.min(Math.max(pp.y * PT_PER_MM, 0), s.height - h),
  };
}

function samePlacement(a: PresetPlacement | null, b: PresetPlacement | null): boolean {
  if (!a || !b) return a === b;
  return a.page === b.page && a.x === b.x && a.y === b.y && a.w === b.w && a.h === b.h;
}

/** The preset that matches the current settings exactly, if any. */
export function activePreset(presets: Preset[], current: Omit<Preset, "name">): Preset | undefined {
  return presets.find(
    (p) =>
      p.reason === current.reason &&
      p.location === current.location &&
      (p.image === undefined || p.image === current.image) &&
      (!p.placement || samePlacement(p.placement, current.placement)),
  );
}
