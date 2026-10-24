import { useEffect, useRef, useState } from "react";
import { api, type Card } from "./api";
import { fill, type Dict, type Lang } from "./i18n";
import TraceView from "./TraceView";

export default function CheckPage({ t, lang, initial }: { t: Dict; lang: Lang; initial: string }) {
  const [text, setText] = useState(initial);
  const [sender, setSender] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [step, setStep] = useState(0);
  const [card, setCard] = useState<Card | null>(null);
  const [err, setErr] = useState("");
  const top = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!busy) return;
    setStep(0);
    const id = setInterval(() => setStep((s) => Math.min(s + 1, t.steps.length - 1)), 2600);
    return () => clearInterval(id);
  }, [busy, t.steps.length]);

  async function go() {
    if (!text.trim() && !file) return;
    setBusy(true);
    setErr("");
    setCard(null);
    try {
      const c = file ? await api.checkImage(file, text, lang) : await api.check(text, sender, lang);
      if (c.error) setErr(c.error);
      else setCard(c);
      setTimeout(() => top.current?.scrollIntoView({ behavior: "smooth" }), 50);
    } catch {
      setErr(t.error);
    } finally {
      setBusy(false);
    }
  }

  function reset() {
    setCard(null);
    setText("");
    setSender("");
    setFile(null);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  if (card) return <div ref={top}><Verdict card={card} t={t} onAgain={reset} /></div>;

  return (
    <section className="check" ref={top}>
      <h1>{t.tagline}</h1>
      <p className="lead">{t.intro}</p>

      <label className="field">
        <span>{t.paste_label}</span>
        <textarea value={text} onChange={(e) => setText(e.target.value)} placeholder={t.paste_placeholder} rows={6} maxLength={4000} />
      </label>
      <label className="field small">
        <span>{t.sender_label}</span>
        <input value={sender} onChange={(e) => setSender(e.target.value)} inputMode="tel" placeholder="6XX XX XX XX" />
      </label>

      <div className="row">
        <label className="ghost-btn">
          <input type="file" accept="image/*" hidden onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          📷 {file ? file.name.slice(0, 24) : t.screenshot}
        </label>
        {file && <button className="link" onClick={() => setFile(null)}>{t.remove}</button>}
      </div>

      <button className="primary" disabled={busy || (!text.trim() && !file)} onClick={go}>
        {busy ? t.checking : t.check}
      </button>

      {busy && (
        <ol className="progress" aria-live="polite">
          {t.steps.map((s, i) => <li key={s} className={i < step ? "done" : i === step ? "now" : ""}>{s}</li>)}
        </ol>
      )}
      {err && <p className="error" role="alert">{err}</p>}
      <p className="privacy">🔒 {t.privacy}</p>
    </section>
  );
}

const TONE: Record<Card["verdict"], string> = { scam: "danger", suspicious: "caution", looks_genuine: "safe", cant_tell: "unsure" };

function Verdict({ card, t, onAgain }: { card: Card; t: Dict; onAgain: () => void }) {
  const label = t[`verdict_${card.verdict}` as keyof Dict] as string;
  const twin = card.genuine_twin;
  const share = async () => {
    const msg = `${fill(t.share_text, { verdict: label })} ${location.origin}`;
    if (navigator.share) navigator.share({ text: msg }).catch(() => {});
    else location.href = `https://wa.me/?text=${encodeURIComponent(msg)}`;
  };
  return (
    <section className={`verdict ${TONE[card.verdict]}`}>
      <div className="vhead">
        <span className="pill">{label}</span>
        <span className="conf">{t.confidence} {Math.round(card.confidence * 100)}%</span>
      </div>
      <h1>{card.headline}</h1>
      <p className="explain">{card.explain}</p>

      {card.campaign && <div className="campaign">🔗 {fill(t.campaign_badge, { n: card.campaign.size })}</div>}

      {card.why.length > 0 && (
        <div className="block">
          <h2>{t.why}</h2>
          <ul className="why">
            {card.why.map((w, i) => (
              <li key={i} className={w.weight}>
                <span>{w.text}</span>
                {w.evidence.length > 0 && (
                  <details>
                    <summary>{t.evidence} ({w.evidence.length})</summary>
                    <ul className="ev">
                      {w.evidence.map((e, j) => <li key={j}><code>{e.table}</code> {e.id}{e.detail ? ` · ${e.detail}` : ""}</li>)}
                    </ul>
                  </details>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {twin && twin.text && (
        <div className="block twin">
          <h2>{t.twin_title} <small>({twin.operator}, {twin.kind})</small></h2>
          <blockquote>{twin.text}</blockquote>
          {twin.only_in_yours && twin.only_in_yours.length > 0 && (
            <p className="diff">{t.twin_only_yours}: {twin.only_in_yours.map((w) => <mark key={w}>{w}</mark>)}</p>
          )}
        </div>
      )}

      <div className="block">
        <h2>{t.do_now}</h2>
        <ul className="steps">{card.do_now.map((d) => <li key={d}>{d}</li>)}</ul>
      </div>
      {card.dont.length > 0 && (
        <div className="block">
          <h2>{t.dont}</h2>
          <ul className="steps dont">{card.dont.map((d) => <li key={d}>{d}</li>)}</ul>
        </div>
      )}

      <details className="how">
        <summary>{t.how_we_checked}</summary>
        <TraceView lines={card.trace} rounds={card.rounds} />
      </details>

      <div className="row end">
        <button className="ghost-btn" onClick={share}>📣 {t.share}</button>
        <button className="primary inline" onClick={onAgain}>{t.check_another}</button>
      </div>
    </section>
  );
}
