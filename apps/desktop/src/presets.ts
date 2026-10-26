// Saved presets: reason, location, where the box goes and how it looks,
// applied in one pick.

import type { ImageChoice, WatchPreset } from "./api";
import { t } from "./i18n";
import type { PageSize, Placement } from "./PdfView";
import { sameCtc, sameStyle, type CtcStyle, type StampStyle } from "./stamp";

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

/** "Certified true copy" stamps as settings and presets keep them. */
export interface CtcChoice {
  style: CtcStyle;
  /** "all" or e.g. "1-3,5". */
  pages: string;
}

export function sameCtcChoice(a: CtcChoice | null, b: CtcChoice | null): boolean {
  if (!a || !b) return a === b;
  return a.pages.trim() === b.pages.trim() && sameCtc(a.style, b.style);
}

export interface Preset {
  name: string;
  reason: string;
  location: string;
  placement: PresetPlacement | null;
  /** Missing in presets saved before images were supported: leave as is. */
  image?: ImageChoice;
  /** Null for the standard box; missing in presets saved before designs: leave as is. */
  style?: StampStyle | null;
  /** Null for no stamps; missing in presets saved before stamps: leave as is. */
  ctc?: CtcChoice | null;
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

/**
 * The copy of a preset a watch folder signs with (the backend applies it, see
 * `trackmysign_core::watch::Preset`). `preset` null: the default reason and
 * location, bottom-right of the last page. Pages, timestamp and LTV are the
 * watch folder's own.
 */
export function toWatchPreset(
  preset: Preset | null,
  defaults: { reason: string; location: string; image: ImageChoice; style: StampStyle | null; ctc: CtcChoice | null },
  own: Pick<WatchPreset, "pages" | "timestamp" | "ltv">,
): WatchPreset {
  const ctc = preset?.ctc !== undefined ? preset.ctc : defaults.ctc;
  return {
    name: preset?.name ?? "",
    reason: preset?.reason ?? defaults.reason,
    location: preset?.location ?? defaults.location,
    placement: preset?.placement ?? null,
    image: preset?.image ?? defaults.image,
    style: preset?.style !== undefined ? preset.style : defaults.style,
    invisible: false,
    ctc: ctc?.style ?? null,
    ctcPages: ctc?.pages ?? "",
    ...own,
  };
}

/** The preset that matches the current settings exactly, if any. */
export function activePreset(presets: Preset[], current: Omit<Preset, "name">): Preset | undefined {
  return presets.find(
    (p) =>
      p.reason === current.reason &&
      p.location === current.location &&
      (p.image === undefined || p.image === current.image) &&
      (p.style === undefined || sameStyle(p.style, current.style)) &&
      (p.ctc === undefined || sameCtcChoice(p.ctc, current.ctc ?? null)) &&
      (!p.placement || samePlacement(p.placement, current.placement)),
  );
}
