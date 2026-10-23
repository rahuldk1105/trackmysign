// Light / dark / follow-system theme, applied as <html data-theme>.

import { useEffect, useState } from "react";
import { inTauri } from "./api";

export type ThemePref = "light" | "dark" | "system";

const KEY = "trackmysign.theme";
const media = window.matchMedia("(prefers-color-scheme: dark)");

export function loadThemePref(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    if (v === "light" || v === "dark" || v === "system") return v;
  } catch {
    /* storage unavailable */
  }
  return "light";
}

function resolve(pref: ThemePref): "light" | "dark" {
  return pref === "system" ? (media.matches ? "dark" : "light") : pref;
}

/** Applies the theme to the page and the native title bar. */
export function applyTheme(pref: ThemePref) {
  const t = resolve(pref);
  document.documentElement.dataset.theme = t;
  if (inTauri) {
    import("@tauri-apps/api/window")
      .then(({ getCurrentWindow }) => getCurrentWindow().setTheme(pref === "system" ? null : t))
      .catch(() => {});
  }
}

export function useTheme(): [ThemePref, (p: ThemePref) => void] {
  const [pref, setPref] = useState<ThemePref>(loadThemePref);

  useEffect(() => {
    applyTheme(pref);
    try {
      localStorage.setItem(KEY, pref);
    } catch {
      /* storage unavailable */
    }
    if (pref !== "system") return;
    const onChange = () => applyTheme("system");
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [pref]);

  return [pref, setPref];
}
