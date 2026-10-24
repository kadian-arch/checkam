import { useEffect, useState } from "react";
import { LANGS, pickLang, type Lang } from "./i18n";
import CheckPage from "./CheckPage";
import AlertsPage from "./AlertsPage";
import AnalystPage from "./AnalystPage";

type Tab = "check" | "alerts" | "analyst";
const tabFromHash = (): Tab => (["alerts", "analyst"].includes(location.hash.slice(1)) ? (location.hash.slice(1) as Tab) : "check");

export default function App() {
  const [lang, setLang] = useState<Lang>(pickLang);
  const [tab, setTab] = useState<Tab>(tabFromHash);
  const t = LANGS[lang];

  useEffect(() => {
    const on = () => setTab(tabFromHash());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  useEffect(() => {
    try { localStorage.setItem("checkam.lang", lang); } catch {}
    document.documentElement.lang = lang === "pcm" ? "en" : lang;
  }, [lang]);

  // text shared from another app ("Share to CheckAm") arrives as ?text=
  const shared = new URLSearchParams(location.search);
  const sharedText = [shared.get("title"), shared.get("text"), shared.get("url")].filter(Boolean).join("\n");

  return (
    <div className="shell">
      <header className="top">
        <a className="brand" href="#check" aria-label="CheckAm home">
          <img src="/icon.svg" alt="" width={32} height={32} />
          <span>Check<b>Am</b></span>
        </a>
        <div className="langs" role="group" aria-label={t.lang}>
          {(Object.keys(LANGS) as Lang[]).map((l) => (
            <button key={l} className={l === lang ? "on" : ""} onClick={() => setLang(l)}>{l === "pcm" ? "Pidgin" : l.toUpperCase()}</button>
          ))}
        </div>
      </header>

      <main>
        {tab === "check" && <CheckPage t={t} lang={lang} initial={sharedText} />}
        {tab === "alerts" && <AlertsPage t={t} lang={lang} />}
        {tab === "analyst" && <AnalystPage />}
      </main>

      <nav className="tabs">
        {(["check", "alerts", "analyst"] as Tab[]).map((k) => (
          <a key={k} href={`#${k}`} className={tab === k ? "on" : ""}>
            <span className="ico" aria-hidden>{k === "check" ? "✓" : k === "alerts" ? "!" : "◎"}</span>
            {k === "check" ? t.nav_check : k === "alerts" ? t.nav_alerts : t.nav_analyst}
          </a>
        ))}
      </nav>
    </div>
  );
}
