import { useEffect, useState } from "react";
import { fill, LANGS, pickLang, type Lang } from "./i18n";
import Logo from "./Logo";

type R = { receipt: { id: string; created: string; verdict: string; confidence: number; scheme: string | null }; valid: boolean; reason?: string };

const TONE: Record<string, string> = { scam: "danger", suspicious: "caution", looks_genuine: "safe", cant_tell: "unsure" };

// A shared CheckAm answer, checked against CheckAm's signature. A doctored screenshot has no valid link.
export default function Receipt({ id }: { id: string }) {
  const [lang, setLang] = useState<Lang>(pickLang);
  const t = LANGS[lang];
  const [r, setR] = useState<R | null>(null);
  const [missing, setMissing] = useState(false);
  const [text, setText] = useState("");
  const [same, setSame] = useState<boolean | null>(null);

  useEffect(() => {
    document.title = `CheckAm · ${id}`;
    fetch(`/receipts/${encodeURIComponent(id)}`).then((x) => (x.ok ? x.json() : Promise.reject())).then(setR).catch(() => setMissing(true));
  }, [id]);

  async function match() {
    const x = await fetch(`/receipts/${encodeURIComponent(id)}/match`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }) });
    setSame(x.ok ? (await x.json()).same_message : null);
  }

  const v = r?.receipt.verdict ?? "cant_tell";
  const when = r ? new Date(r.receipt.created).toLocaleString(lang === "fr" ? "fr-FR" : "en-GB", { dateStyle: "long", timeStyle: "short" }) : "";
  const kind = r?.receipt.scheme ? (t.schemes as Record<string, string>)[r.receipt.scheme] : "";

  return (
    <div className="site receipt-page">
      <header className="masthead">
        <a className="brand" href="/" aria-label="CheckAm"><Logo /><span>Check<b>Am</b></span></a>
        <div className="actions"><button className="lang" onClick={() => setLang(lang === "en" ? "fr" : "en")}>{t.lang}</button></div>
      </header>
      <main className="receipt-main">
        {missing && (
          <section className="report unsure receipt-card">
            <h1 className="report-title">{t.rc_missing_title}</h1>
            <p className="report-explain">{t.rc_missing}</p>
          </section>
        )}
        {r && (
          <section className={`report ${r.valid ? TONE[v] : "danger"} receipt-card`}>
            <p className={`seal ${r.valid ? "ok" : "bad"}`}>{r.valid ? t.rc_valid : t.rc_invalid}</p>
            {r.valid && <div className="stamp"><span>{t[`verdict_${v}` as keyof typeof t] as string}</span></div>}
            <h1 className="report-title">{r.valid ? (kind ? fill(t.rc_kind, { kind }) : t[`verdict_${v}` as keyof typeof t] as string) : t.rc_forged}</h1>
            <dl className="rc-facts">
              <div><dt>{t.rc_number}</dt><dd className="mono">{r.receipt.id}</dd></div>
              <div><dt>{t.rc_when}</dt><dd>{when}</dd></div>
              <div><dt>{t.confidence}</dt><dd>{Math.round(r.receipt.confidence * 100)}%</dd></div>
            </dl>
            {r.valid && (
              <form className="rc-match" onSubmit={(e) => { e.preventDefault(); if (text.trim()) match(); }}>
                <label htmlFor="rc-text">{t.rc_match}</label>
                <textarea id="rc-text" value={text} onChange={(e) => { setText(e.target.value); setSame(null); }} maxLength={4000} rows={4} />
                <button className="ghost" disabled={!text.trim()}>{t.rc_match_btn}</button>
                {same !== null && <p className={`seal ${same ? "ok" : "bad"}`}>{same ? t.rc_same : t.rc_different}</p>}
              </form>
            )}
            <p className="muted small">{t.rc_how}</p>
          </section>
        )}
        <a className="primary" href="/">{t.rc_cta}<span aria-hidden>→</span></a>
      </main>
    </div>
  );
}
