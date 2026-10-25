import en from "./i18n/en.json";
import fr from "./i18n/fr.json";

export const LANGS = { en, fr } as const;
export type Lang = keyof typeof LANGS;
export type Dict = typeof en;

// the phone's own language decides, unless the person chose the other one
export function pickLang(): Lang {
  try {
    const saved = localStorage.getItem("checkam.lang");
    if (saved === "en" || saved === "fr") return saved;
  } catch {}
  return (navigator.languages ?? [navigator.language]).some((l) => l?.toLowerCase().startsWith("fr")) ? "fr" : "en";
}

export function fill(s: string, vars: Record<string, string | number>): string {
  return s.replace(/\{(\w+)\}/g, (_, k) => String(vars[k] ?? ""));
}
