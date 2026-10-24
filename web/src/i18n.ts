import en from "./i18n/en.json";
import fr from "./i18n/fr.json";
import pcm from "./i18n/pcm.json";

export const LANGS = { en, fr, pcm } as const;
export type Lang = keyof typeof LANGS;
export type Dict = typeof en;

export function pickLang(): Lang {
  try {
    const saved = localStorage.getItem("checkam.lang");
    if (saved && saved in LANGS) return saved as Lang;
  } catch {}
  return navigator.language?.startsWith("fr") ? "fr" : "en";
}

export function fill(s: string, vars: Record<string, string | number>): string {
  return s.replace(/\{(\w+)\}/g, (_, k) => String(vars[k] ?? ""));
}
