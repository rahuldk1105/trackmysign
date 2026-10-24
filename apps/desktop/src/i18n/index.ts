// UI language: English, Hindi or Tamil. Messages live in typed catalogs
// (en.ts is the reference), `t` looks them up and fills in {placeholders}.
//
// The language is module state set by `useLanguage` while App renders, before
// any child renders, so every `t` call in a render pass agrees; App re-renders
// everything below it when the setting changes.

import { createElement, Fragment, useEffect, type ReactNode } from "react";
import { en, type Catalog, type MessageKey, type Plural } from "./en";
import { hi } from "./hi";
import { ta } from "./ta";

export type { MessageKey } from "./en";

export type Lang = "en" | "hi" | "ta";
export type LangPref = Lang | "system";

const catalogs: Record<Lang, Catalog> = { en, hi, ta };

/** Each language in its own script, for the picker. */
export const LANGUAGE_NAMES: Record<Lang, string> = { en: "English", hi: "हिन्दी", ta: "தமிழ்" };

export function isLangPref(v: unknown): v is LangPref {
  return v === "system" || v === "en" || v === "hi" || v === "ta";
}

/** The first of the OS's preferred languages that the app has, else English. */
export function systemLang(): Lang {
  const prefs = navigator.languages?.length ? navigator.languages : [navigator.language];
  for (const l of prefs) {
    const base = l?.toLowerCase().split("-")[0];
    if (base === "en" || base === "hi" || base === "ta") return base;
  }
  return "en";
}

export const resolveLang = (pref: LangPref): Lang => (pref === "system" ? systemLang() : pref);

let current: Lang = "en";
const rules: Partial<Record<Lang, Intl.PluralRules>> = {};

export const currentLang = () => current;

/** Sets the language for the render that is under way, and `<html lang>` for fonts and CSS. */
export function useLanguage(pref: LangPref): Lang {
  const lang = resolveLang(pref);
  current = lang;
  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);
  return lang;
}

type Vars = Record<string, string | number>;

function pick(key: MessageKey, n: unknown): string {
  const m: string | Plural = catalogs[current][key] ?? en[key];
  if (typeof m === "string") return m;
  const r = (rules[current] ??= new Intl.PluralRules(current));
  return r.select(Number(n)) === "one" ? m.one : m.other;
}

/** The message for `key`; a count message picks its form by `vars.n`. */
export function t(key: MessageKey, vars?: Vars): string {
  return pick(key, vars?.n).replace(/\{(\w+)\}/g, (all, name: string) => (vars && name in vars ? String(vars[name]) : all));
}

/** `t` for messages with markup inside: placeholders take elements as well as text. */
export function tx(key: MessageKey, vars: Record<string, ReactNode>): ReactNode {
  const parts = pick(key, vars.n).split(/\{(\w+)\}/);
  // split() with a group alternates text and placeholder names.
  return parts.map((p, i) => createElement(Fragment, { key: i }, i % 2 ? (p in vars ? vars[p] : `{${p}}`) : p));
}
