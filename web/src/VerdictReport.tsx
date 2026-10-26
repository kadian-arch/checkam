import { useState } from "react";
import { api, type Card, type Evidence } from "./api";
import { fill, type Dict } from "./i18n";
import TraceView from "./TraceView";

const TONE: Record<Card["verdict"], string> = { scam: "danger", suspicious: "caution", looks_genuine: "safe", cant_tell: "unsure" };

// evidence in words anyone can read; table names, ids and scores stay in the trace for analysts
function source(e: Evidence, t: Dict): string {
  const key = (e.table === "message" ? (e.id === "sender" ? "src_sender" : "src_route") : `src_${e.table}`) as keyof Dict;
  const label = (t[key] as string) || t.evidence;
  return e.table === "genuine_messages" && e.operator ? `${label} (${e.operator.toUpperCase()})` : label;
}

function plain(e: Evidence, t: Dict): string {
  if (e.table === "world_model") return fill(t.n_linked, { n: (e.count ?? 0) + 1 });
  if (e.table === "genuine_messages") return e.text ? `"${e.text.slice(0, 140)}"` : "";
  if (e.table === "messages" || e.table === "nemotron") return e.detail ? `"${e.detail}"` : "";
  return e.detail ?? "";
}

export default function VerdictReport({ card, t, onAgain, askSender, followUp }: { card: Card; t: Dict; onAgain: () => void; askSender?: (who: string) => void; followUp?: (answer: string) => void }) {
  const [who, setWho] = useState("");
  const [answer, setAnswer] = useState("");
  const [flagOpen, setFlagOpen] = useState(false);
  const [flagged, setFlagged] = useState(false);
  const [flagNote, setFlagNote] = useState("");
  const sendFlag = (suggested: string) =>
    api.flag(card.check_id, suggested, flagNote).then(() => setFlagged(true)).catch(() => setFlagged(true));
  const label = t[`verdict_${card.verdict}` as keyof Dict] as string;
  const twin = card.genuine_twin;
  const share = () => {
    // the signed answer travels with the warning, so the person receiving it can check it is real
    const msg = card.receipt ? `${fill(t.share_receipt, { verdict: label })} ${card.receipt.url}` : `${fill(t.share_text, { verdict: label })} ${location.origin}`;
    if (navigator.share) navigator.share({ text: msg }).catch(() => {});
    else window.open(`https://wa.me/?text=${encodeURIComponent(msg)}`, "_blank", "noopener");
  };
  return (
    <article className={`report ${TONE[card.verdict]}`}>
      <header className="report-head">
        <div className="stamp" aria-label={label}><span>{label}</span></div>
        <div className="meter" aria-label={`${Math.round(card.confidence * 100)}% ${t.confidence}`}>
          <i style={{ width: `${Math.round(card.confidence * 100)}%` }} />
          <small>{Math.round(card.confidence * 100)}% {t.confidence}</small>
        </div>
      </header>

      <h1 className="report-title">{card.headline}</h1>
      <p className="report-explain">{card.explain}</p>
      {card.campaign && <p className="campaign"><span className="pulse" />{fill(t.campaign_badge, { n: card.campaign.size })}</p>}

      {askSender && (
        <form className="sheet ask" onSubmit={(e) => { e.preventDefault(); if (who.trim()) askSender(who.trim()); }}>
          <h2>{t.ask_sender_title}</h2>
          <p className="muted">{t.ask_sender_sub}</p>
          <div className="row">
            <input value={who} onChange={(e) => setWho(e.target.value)} maxLength={80} placeholder={t.sender_placeholder} aria-label={t.ask_sender_title} />
            <button className="primary inline" disabled={!who.trim()}>{t.check_again}</button>
          </div>
        </form>
      )}

      {followUp && card.questions && card.questions.length > 0 && (
        <form className="sheet ask" onSubmit={(e) => { e.preventDefault(); if (answer.trim()) followUp(answer.trim()); }}>
          <h2>{t.followup_title}</h2>
          <ul className="questions">{card.questions.map((q) => <li key={q}>{q}</li>)}</ul>
          <textarea value={answer} onChange={(e) => setAnswer(e.target.value)} rows={3} maxLength={1000} placeholder={t.followup_placeholder} aria-label={t.followup_title} />
          <button className="primary inline" disabled={!answer.trim()}>{t.check_again}</button>
        </form>
      )}

      <div className="report-grid">
        {card.why.length > 0 && (
          <section className="sheet why">
            <h2>{t.why}</h2>
            <ol>
              {card.why.map((w, i) => (
                <li key={i} className={w.weight}>
                  <p>{w.text}</p>
                  {w.evidence.length > 0 && (
                    <details>
                      <summary>{w.evidence.length} {t.evidence}</summary>
                      <ul>{w.evidence.map((e, j) => <li key={j}><b>{source(e, t)}</b>{plain(e, t) ? <span> {plain(e, t)}</span> : null}</li>)}</ul>
                    </details>
                  )}
                </li>
              ))}
            </ol>
          </section>
        )}

        <section className="sheet steps">
          <h2>{t.do_now}</h2>
          <ul className="do">{card.do_now.map((d) => <li key={d}>{d}</li>)}</ul>
          {card.dont.length > 0 && (<><h2>{t.dont}</h2><ul className="dont">{card.dont.map((d) => <li key={d}>{d}</li>)}</ul></>)}
        </section>
      </div>

      {twin?.text && (
        <section className="sheet twin">
          <h2>{t.twin_title} <small>{twin.operator} · {twin.kind}</small></h2>
          <blockquote>{twin.text}</blockquote>
          {twin.only_in_yours && twin.only_in_yours.length > 0 && (
            <p className="diff"><span>{t.twin_only_yours}</span>{twin.only_in_yours.map((w) => <mark key={w}>{w}</mark>)}</p>
          )}
        </section>
      )}

      <details className="sheet how-checked">
        <summary>{t.how_we_checked}</summary>
        <TraceView lines={card.trace} rounds={card.rounds} />
      </details>

      <footer className="report-actions">
        <button className="ghost" onClick={share}>{t.share}</button>
        {card.receipt && <a className="ghost" href={new URL(card.receipt.url).pathname} target="_blank" rel="noopener">{t.signed_answer}</a>}
        <button className="primary inline" onClick={onAgain}>{t.check_another}</button>
      </footer>
      {card.check_id && (
        <div className="flag">
          {flagged ? <p className="muted small">{t.flag_thanks}</p> : !flagOpen ? (
            <button className="link small" onClick={() => setFlagOpen(true)}>{t.flag_open}</button>
          ) : (
            <div className="flag-box">
              <p className="small">{t.flag_ask}</p>
              <input value={flagNote} onChange={(e) => setFlagNote(e.target.value)} maxLength={300} placeholder={t.flag_note} aria-label={t.flag_note} />
              <div className="row">
                <button className="ghost small" onClick={() => sendFlag("scam")}>{t.flag_is_scam}</button>
                <button className="ghost small" onClick={() => sendFlag("looks_genuine")}>{t.flag_is_genuine}</button>
                <button className="ghost small" onClick={() => sendFlag("not_sure")}>{t.flag_not_sure}</button>
              </div>
            </div>
          )}
        </div>
      )}
    </article>
  );
}
