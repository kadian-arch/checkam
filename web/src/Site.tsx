import { useEffect, useRef, useState } from "react";
import { api, streamCheck, type Card, type TraceLine } from "./api";

// which of the six visible stages a live agent step belongs to
function phase(l: TraceLine): number {
  if (l.agent_name === "Intake") return 0;
  if (l.agent_name === "Planner") return 1;
  if (l.agent_name === "Investigator") {
    if (l.action === "genuine_twin") return 2;
    if (l.action.startsWith("world") || l.action === "campaign" || l.action === "model_judgement") return 3;
    return 1;
  }
  if (l.agent_name === "Critic") return 4;
  if (l.agent_name === "Reporter") return 5;
  return 0;
}
import { fill, LANGS, pickLang, type Dict, type Lang } from "./i18n";
import VerdictReport from "./VerdictReport";
import Logo from "./Logo";

type InstallEvent = Event & { prompt: () => Promise<void> };

function savedTheme(): "light" | "dark" | null {
  try {
    const saved = localStorage.getItem("checkam.theme");
    return saved === "light" || saved === "dark" ? saved : null;
  } catch { return null; }
}

function pickTheme(): "light" | "dark" {
  return savedTheme() ?? (window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light");
}

export default function Site() {
  const [lang, setLang] = useState<Lang>(pickLang);
  const [theme, setTheme] = useState<"light" | "dark">(pickTheme);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    // the phone status bar takes the page colour too
    document.querySelectorAll("meta[name=theme-color]").forEach((m) => m.setAttribute("content", theme === "light" ? "#f5f3ee" : "#090d14"));
  }, [theme]);
  useEffect(() => {
    // follow the phone's own setting until the person picks one
    const mq = window.matchMedia?.("(prefers-color-scheme: dark)");
    const on = (e: MediaQueryListEvent) => { if (!savedTheme()) setTheme(e.matches ? "dark" : "light"); };
    mq?.addEventListener("change", on);
    return () => mq?.removeEventListener("change", on);
  }, []);
  const toggleTheme = () => {
    const next = theme === "light" ? "dark" : "light";
    try { localStorage.setItem("checkam.theme", next); } catch {}
    setTheme(next);
  };
  const t = LANGS[lang];
  const [install, setInstall] = useState<InstallEvent | null>(null);
  const [stats, setStats] = useState<{ checks: number; flagged: number; alerts: number } | null>(null);

  useEffect(() => {
    try { localStorage.setItem("checkam.lang", lang); } catch {}
    document.documentElement.lang = lang;
  }, [lang]);
  useEffect(() => {
    const on = (e: Event) => { e.preventDefault(); setInstall(e as InstallEvent); };
    window.addEventListener("beforeinstallprompt", on);
    api.publicStats().then(setStats).catch(() => {});
    return () => window.removeEventListener("beforeinstallprompt", on);
  }, []);

  // text shared from another app ("Share → CheckAm") arrives as ?text=
  const q = new URLSearchParams(location.search);
  const shared = [q.get("title"), q.get("text"), q.get("url")].filter(Boolean).join("\n");

  return (
    <div className="site">
      <header className="masthead">
        <a className="brand" href="/" aria-label="CheckAm"><Logo /><span>Check<b>Am</b></span></a>
        <nav className="links">
          <a href="#how">{t.nav_how}</a>
          <a href="#alerts">{t.nav_alerts}</a>
          <a href="/analyst">{t.nav_analysts}</a>
        </nav>
        <div className="actions">
          <button className="theme" onClick={toggleTheme} aria-label={theme === "light" ? "Dark mode" : "Light mode"}>{theme === "light" ? "☾" : "☀"}</button>
          <button className="lang" onClick={() => setLang(lang === "en" ? "fr" : "en")} aria-label="Change language">{t.lang}</button>
          {install && <button className="pill-btn" onClick={() => install.prompt()}>{t.install}</button>}
        </div>
      </header>

      <main>
        <Hero t={t} lang={lang} shared={shared} />
        <Stats t={t} stats={stats} />
        <How t={t} />
        <Alerts t={t} lang={lang} />
        <section className="duo">
          <div className="panel install">
            <h3>{t.install_title}</h3>
            <p>{t.install_sub}</p>
            <div className="phone-steps"><span>SMS</span><i>→</i><span>Share</span><i>→</i><span className="hl">CheckAm</span></div>
            {install ? <button className="primary" onClick={() => install.prompt()}>{t.install}</button> : <p className="muted small">{t.install_ios}</p>}
          </div>
          <div className="panel analysts">
            <h3>{t.analyst_title}</h3>
            <p>{t.analyst_sub}</p>
            <a className="ghost" href="/analyst">{t.analyst_cta} →</a>
          </div>
        </section>
      </main>

      <footer className="foot">
        <div className="brand small"><Logo /><span>Check<b>Am</b></span></div>
        <p>{t.footer_data} <a href="https://doi.org/10.5281/zenodo.23287617" target="_blank" rel="noreferrer">DOI 10.5281/zenodo.23287617</a></p>
        <p className="muted small">Ground Truth · Open Agent Hackathon 2026 · Zetaris · Meterless · NVIDIA Nemotron</p>
      </footer>
    </div>
  );
}

function Hero({ t, lang, shared }: { t: Dict; lang: Lang; shared: string }) {
  const [text, setText] = useState(shared);
  const [sender, setSender] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [live, setLive] = useState<TraceLine[]>([]);
  const [card, setCard] = useState<Card | null>(null);
  const [err, setErr] = useState("");
  const top = useRef<HTMLElement>(null);
  const step = live.reduce((s, l) => Math.max(s, phase(l)), 0);
  const last = live[live.length - 1];
  // the verdict is decided before the explanation is written; show it the moment it exists
  const gate = live.find((l) => l.action === "verdict_gate");
  const early = gate ? (() => { try { return JSON.parse(gate.output_summary || "{}").verdict as string; } catch { return ""; } })() : "";

  async function go(who = sender) {
    if (!text.trim() && !file) return;
    setBusy(true);
    setErr("");
    setLive([]);
    try {
      const c = await streamCheck({ text, sender: who, language: lang, file }, (l) => setLive((x) => [...x, l]));
      if (c.error) setErr(c.error);
      else setCard(c);
      top.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch {
      setErr(t.error);
    } finally {
      setBusy(false);
    }
  }

  if (card) {
    return (
      <section className="hero report-wrap" ref={top} id="check">
        <VerdictReport card={card} t={t} onAgain={() => { setCard(null); setText(""); setSender(""); setFile(null); }}
          askSender={card.verdict === "cant_tell" && !sender.trim() ? (who) => { setSender(who); setCard(null); go(who); } : undefined} />
      </section>
    );
  }

  return (
    <section className="hero" ref={top} id="check">
      <div className="hero-copy">
        <p className="eyebrow"><span className="dot" />{t.eyebrow}</p>
        <h1>{t.hero_1}<br /><em>{t.hero_2}</em></h1>
        <p className="lede">{t.hero_sub}</p>
      </div>

      <div className={`console ${busy ? "busy" : ""}`}>
        <div className="console-bar"><span /><span /><span /><code>checkam://check</code></div>
        <label className="field">
          <span>{t.paste_label}</span>
          <textarea value={text} onChange={(e) => setText(e.target.value)} placeholder={t.paste_placeholder} rows={6} maxLength={4000} disabled={busy} />
        </label>
        <div className="row">
          <label className="field grow">
            <span>{t.sender_label}</span>
            <input value={sender} onChange={(e) => setSender(e.target.value)} placeholder={t.sender_placeholder} disabled={busy} />
          </label>
          <label className="file">
            <input type="file" accept="image/*" hidden onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            <svg viewBox="0 0 24 24" aria-hidden><path d="M4 7h3l2-2h6l2 2h3v12H4z M12 17a4 4 0 1 0 0-8 4 4 0 0 0 0 8z" /></svg>
            {file ? file.name.slice(0, 18) : t.screenshot}
          </label>
        </div>
        {file && <button className="link" onClick={() => setFile(null)}>{t.remove}</button>}

        {busy ? (
          <div className="live">
            <ol className="pipeline" aria-live="polite">
              {t.steps.map((s, i) => <li key={s} className={i < step ? "done" : i === step ? "now" : ""}><i />{s}</li>)}
            </ol>
            {early && (
              <p className={`early ${early}`} role="status"><b>{t[`verdict_${early}` as keyof Dict] as string}</b> <span>{t.writing_explanation}</span></p>
            )}
            {last && (
              <p className="ticker" key={live.length}>
                <b>{(t.agents as Record<string, string>)[last.agent_name] ?? last.agent_name}</b> <span>{(t.acts as Record<string, string>)[last.action] ?? t.working}</span>
                {last.sponsor !== "none" && <em className={`sp ${last.sponsor}`}>{last.sponsor === "nvidia" ? "Nemotron" : last.sponsor[0].toUpperCase() + last.sponsor.slice(1)}</em>}
                <small>{fill(t.steps_done, { n: live.length })}</small>
              </p>
            )}
          </div>
        ) : (
          <button className="primary" disabled={!text.trim() && !file} onClick={() => go()}>{t.check}<span aria-hidden>→</span></button>
        )}
        {err && <p className="error" role="alert">{err}</p>}
        <p className="privacy"><svg viewBox="0 0 24 24" aria-hidden><path d="M7 11V8a5 5 0 0 1 10 0v3M6 11h12v9H6z" /></svg>{t.privacy}</p>
      </div>
    </section>
  );
}

function Stats({ t, stats }: { t: Dict; stats: { checks: number; flagged: number } | null }) {
  return (
    <section className="stats">
      <div><b>{stats ? stats.checks.toLocaleString() : "–"}</b><span>{t.stat_checks}</span></div>
      <div><b>{stats ? stats.flagged.toLocaleString() : "–"}</b><span>{t.stat_flagged}</span></div>
      <div><b>220</b><span>{t.stat_reports}</span></div>
    </section>
  );
}

const AGENTS = ["intake", "planner", "investigator", "critic", "reporter"] as const;

function How({ t }: { t: Dict }) {
  return (
    <section className="how" id="how">
      <h2>{t.how_title}</h2>
      <p className="lede">{t.how_sub}</p>
      <ol className="agents">
        {AGENTS.map((a, i) => (
          <li key={a} style={{ animationDelay: `${i * 90}ms` }}>
            <span className="n">0{i + 1}</span>
            <h4>{a[0].toUpperCase() + a.slice(1)}</h4>
            <p>{t[`agent_${a}` as keyof Dict] as string}</p>
            {a === "critic" && <span className="loop">↺ sends work back</span>}
          </li>
        ))}
      </ol>
      <div className="sponsors">
        <span>Evidence in <b>Zetaris</b></span>
        <span>Campaign graph and guard by <b>Meterless</b></span>
        <span>Reasoning by <b>NVIDIA Nemotron</b></span>
      </div>
    </section>
  );
}

function Alerts({ t, lang }: { t: Dict; lang: Lang }) {
  const [alerts, setAlerts] = useState<any[] | null>(null);
  useEffect(() => { api.alerts().then((r) => setAlerts(r.alerts)).catch(() => setAlerts([])); }, []);
  const body = (a: any) => (lang === "fr" && a.body_fr) || a.body_en;
  return (
    <section className="alerts" id="alerts">
      <h2>{t.alerts_title}</h2>
      <p className="lede">{t.alerts_sub}</p>
      {alerts?.length === 0 && <p className="muted">{t.alerts_empty}</p>}
      <div className="alert-grid">
        {alerts?.slice(0, 6).map((a) => (
          <article key={a.id} className="alert">
            <header><time>{a.created.slice(0, 10)}</time>{a.signature && <span className="sig" title={a.signature}>✓ {t.verified}</span>}</header>
            <h3>{a.title}</h3>
            <p>{body(a)}</p>
            {a.numbers?.length > 0 && <footer>{a.numbers.map((n: string) => <code key={n}>{n}</code>)}</footer>}
          </article>
        ))}
      </div>
    </section>
  );
}

export { fill };
