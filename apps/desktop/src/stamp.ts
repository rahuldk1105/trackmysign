// The signature box style (`trackmysign_core::stamp::StampStyle`, saved in
// settings and presets as is) and the box as the core lays it out. Previews
// draw that layout instead of working it out again, so they match the PDF.

import { useEffect, useState } from "react";
import * as api from "./api";

export type StampLayout = "auto" | "text_only" | "image_left" | "image_above" | "image_only";
export type LineField = "signed_by_label" | "name" | "signed_by" | "organisation" | "role" | "date" | "reason" | "location" | "custom_1" | "custom_2";
export type DateFormat = "classic" | "dd_mm_yyyy_hh_mm" | "dd_mm_yyyy_hh_mm_ss" | "dd_mmm_yyyy";
export type FontFamily = "helvetica" | "times" | "courier";

export interface SealStyle {
  position: "right" | "behind";
  /** 0 to 1. */
  opacity: number;
}

export interface StampStyle {
  version: number;
  layout: StampLayout;
  /** Shown in this order; null for the standard lines. */
  lines: LineField[] | null;
  /** Empty: the certificate's O=. */
  organisation: string;
  role: string;
  custom_1: string;
  custom_2: string;
  date_format: DateFormat;
  font: FontFamily;
  bold_name: boolean;
  bold_first_line: boolean;
  /** Points; null to fit the box. */
  font_size: number | null;
  text_color: string;
  align: "left" | "center";
  border: boolean;
  /** Null: the standard blue. */
  border_color: string | null;
  border_width: number;
  background: "none" | "light";
  padding: number | null;
  tick: boolean;
  seal: SealStyle | null;
}

export const STANDARD_LINES: LineField[] = ["signed_by_label", "name", "date", "reason", "location"];
export const ALL_LINES: LineField[] = [...STANDARD_LINES, "signed_by", "organisation", "role", "custom_1", "custom_2"];
export const DARK_BLUE = "#1B3A8C";
/** What `border_color: null` draws. */
export const STANDARD_BORDER = "#215CAB";

export const DEFAULT_STYLE: StampStyle = {
  version: 1,
  layout: "auto",
  lines: null,
  organisation: "",
  role: "",
  custom_1: "",
  custom_2: "",
  date_format: "classic",
  font: "helvetica",
  bold_name: true,
  bold_first_line: false,
  font_size: null,
  text_color: "#000000",
  align: "left",
  border: true,
  border_color: null,
  border_width: 0.8,
  background: "none",
  padding: null,
  tick: false,
  seal: null,
};

/** A saved style with every field (older or hand-written ones may lack some). */
export function fullStyle(s: Partial<StampStyle> | null | undefined): StampStyle {
  return { ...DEFAULT_STYLE, ...s };
}

export function sameStyle(a: Partial<StampStyle> | null | undefined, b: Partial<StampStyle> | null | undefined): boolean {
  return JSON.stringify(fullStyle(a)) === JSON.stringify(fullStyle(b));
}

export const isHexColor = (s: string) => /^#[0-9a-fA-F]{6}$/.test(s.trim());

export type Rgb = [number, number, number];
/** `[x, y, w, h]`, points, origin at the bottom-left of the box. */
export type Area = [number, number, number, number];

export interface Drawing {
  width: number;
  height: number;
  font: FontFamily;
  background: Rgb | null;
  border: { color: Rgb; width: number } | null;
  images: { kind: "signature" | "seal"; rect: Area; opacity: number }[];
  textColor: Rgb;
  /** `y` is the baseline. */
  text: { text: string; bold: boolean; size: number; x: number; y: number; width: number }[];
  clip: Area | null;
  tick: Area | null;
}

/** What the box shows, apart from its size. */
export interface StampContent {
  style: StampStyle | null;
  name: string;
  organisation: string | null;
  reason: string;
  location: string;
  /** Width / height of the signature image shown, and where. */
  image: [number, "left" | "above"] | null;
  /** Width / height of the seal, when the style shows one. */
  seal: number | null;
}

// Every page with the box asks for the same layout: ask the core once.
const cache = new Map<string, Promise<Drawing | null>>();

function layout(content: StampContent, w: number, h: number): Promise<Drawing | null> {
  // The date in the box changes every minute.
  const key = JSON.stringify([content, w, h, Math.floor(Date.now() / 60000)]);
  let p = cache.get(key);
  if (!p) {
    if (cache.size > 200) cache.clear();
    p = api.stampPreview({ ...content, w, h }).catch(() => null);
    cache.set(key, p);
  }
  return p;
}

/**
 * The core's layout of a `w`×`h` box; until it arrives, the previous one
 * (stretched to the new size). Null outside the app.
 */
export function useStampDrawing(content: StampContent | null, w: number, h: number): Drawing | null {
  const [drawing, setDrawing] = useState<Drawing | null>(null);
  const key = content && JSON.stringify([content, w, h]);
  useEffect(() => {
    if (!content) return setDrawing(null);
    let live = true;
    layout(content, w, h).then((d) => live && setDrawing(d));
    return () => {
      live = false;
    };
    // `key` stands for content, w and h.
  }, [key]);
  return drawing;
}

// ------------------------------------------------- certified true copy

export type Corner = "top_right" | "top_left" | "bottom_right" | "bottom_left";

/** A "certified true copy" stamp (`trackmysign_core::ctc::CtcStyle`): its lines and look, size and corner. */
export interface CtcStyle {
  version: number;
  style: StampStyle;
  corner: Corner;
  /** Points from the corner's sides. */
  margin_x: number;
  margin_y: number;
  /** Points. */
  width: number;
  height: number;
}

export const CTC_LINES: LineField[] = ["custom_1", "organisation", "name", "role", "custom_2"];

/** What a new stamp looks like; mirrors `ctc_box_style` in the core. */
export const DEFAULT_CTC_STYLE: StampStyle = {
  ...DEFAULT_STYLE,
  lines: CTC_LINES,
  custom_1: "CERTIFIED TRUE COPY",
  role: "Director",
  bold_name: false,
  bold_first_line: true,
  align: "center",
};

export const DEFAULT_CTC: CtcStyle = {
  version: 1,
  style: DEFAULT_CTC_STYLE,
  corner: "top_right",
  margin_x: 36,
  margin_y: 36,
  width: 180,
  height: 72,
};

/** A saved stamp with every field. */
export function fullCtc(c: Partial<CtcStyle> | null | undefined): CtcStyle {
  return { ...DEFAULT_CTC, ...c, style: { ...DEFAULT_CTC_STYLE, ...c?.style } };
}

export function sameCtc(a: Partial<CtcStyle> | null | undefined, b: Partial<CtcStyle> | null | undefined): boolean {
  return JSON.stringify(fullCtc(a)) === JSON.stringify(fullCtc(b));
}

/** Where the stamp goes on a page displayed `w`×`h`; mirrors `CtcStyle::rect_on`. */
export function ctcRect(c: CtcStyle, w: number, h: number): { x: number; y: number; w: number; h: number } {
  const sw = Math.min(c.width, w);
  const sh = Math.min(c.height, h);
  const left = c.corner === "top_left" || c.corner === "bottom_left";
  const top = c.corner === "top_left" || c.corner === "top_right";
  const x = left ? c.margin_x : w - sw - c.margin_x;
  const y = top ? c.margin_y : h - sh - c.margin_y;
  return { x: Math.min(Math.max(x, 0), w - sw), y: Math.min(Math.max(y, 0), h - sh), w: sw, h: sh };
}

/** The stamp moved to `r` on a page displayed `w`×`h`: kept from the nearer corner. */
export function ctcPlaced(c: CtcStyle, r: { x: number; y: number; w: number; h: number }, w: number, h: number): CtcStyle {
  const left = r.x + r.w / 2 <= w / 2;
  const top = r.y + r.h / 2 <= h / 2;
  const round = (v: number) => Math.round(Math.max(v, 0) * 10) / 10;
  return {
    ...c,
    corner: top ? (left ? "top_left" : "top_right") : left ? "bottom_left" : "bottom_right",
    margin_x: round(left ? r.x : w - r.x - r.w),
    margin_y: round(top ? r.y : h - r.y - r.h),
    width: round(r.w),
    height: round(r.h),
  };
}
