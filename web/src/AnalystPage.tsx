import { useEffect, useState } from "react";
import { api } from "./api";
import TraceView from "./TraceView";

const KEY = "checkam.analyst";

export default function AnalystPage() {
  const [session, setSession] = useState<{ token: string; name: string } | null>(() => {
    try { return JSON.parse(sessionStorage.getItem(KEY) ?? "null"); } catch { return null; }
  });
  const save = (s: typeof session) => {
    setSession(s);
    try { s ? sessionStorage.setItem(KEY, JSON.stringify(s)) : sessionStorage.removeItem(KEY); } catch {}
  };
  if (!session) return <Login onIn={save} />;
  return <Desk token={session.token} name={session.name} onOut={() => save(null)} />;
}

function Login({ onIn }: { onIn: (s: { token: string; name: string }) => void }) {
  const [email, setEmail] = useState("");
  const [pw, setPw] = useState("");
  const [err, setErr] = useState("");
  const go = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const r = await api.login(email, pw);
      onIn({ token: r.token, name: r.analyst.name });
    } catch (x: any) {
      setErr(x.message);
    }
  };
  return (
    <section className="login">
      <h1>Analyst desk</h1>
      <p className="lead">For fraud teams, CERT and fact-checkers. Campaigns found by the agents from public reports, alerts and citizens' checks.</p>
      <form onSubmit={go}>
        <label className="field small"><span>Email</span><input value={email} onChange={(e) => setEmail(e.target.value)} type="email" autoComplete="username" required /></label>
        <label className="field small"><span>Password</span><input value={pw} onChange={(e) => setPw(e.target.value)} type="password" autoComplete="current-password" required /></label>
        <button className="primary">Sign in</button>
        {err && <p className="error">{err}</p>}
      </form>
    </section>
  );
}

function Desk({ token, name, onOut }: { token: string; name: string; onOut: () => void }) {
  const [camps, setCamps] = useState<any[] | null>(null);
  const [stats, setStats] = useState<any>(null);
  const [open, setOpen] = useState<string | null>(null);
  useEffect(() => {
    api.campaigns(token).then((r) => { setCamps(r.campaigns); setStats(r.checks); }).catch(() => onOut());
  }, [token]);
  if (open) return <Dossier token={token} id={open} onBack={() => setOpen(null)} />;
  return (
    <section className="desk">
      <div className="row between"><h1>Campaigns</h1><button className="link" onClick={onOut}>Sign out {name}</button></div>
      {stats && <p className="muted">{stats.total} citizen checks so far · {Object.entries(stats.by_verdict ?? {}).map(([k, v]) => `${v} ${k}`).join(" · ")}</p>}
      {camps === null && <p className="muted">Loading the campaign graph…</p>}
      {camps?.map((c) => (
        <button key={c.id} className="camp" onClick={() => setOpen(c.id)}>
          <div className="row between">
            <b>{c.size} linked records</b>
            {c.citizen_checks > 0 && <span className="pill small">{c.citizen_checks} citizen check{c.citizen_checks > 1 ? "s" : ""}</span>}
          </div>
          <div className="muted">{Object.entries(c.kinds).map(([k, v]) => `${v} ${k}`).join(" · ")} · {c.first_seen?.slice(0, 10)} → {c.last_seen?.slice(0, 10)}</div>
          <div className="chips">
            {c.numbers.slice(0, 3).map((n: string) => <code key={n}>{n}</code>)}
            {c.scam_types.slice(0, 3).map((s: string) => <span key={s}>{s.replace(/_/g, " ")}</span>)}
          </div>
          <div className="muted small">linked by: {c.signals.join(", ")}{c.review_pairs ? ` · ${c.review_pairs} pair(s) for review` : ""}</div>
        </button>
      ))}
    </section>
  );
}

function Dossier({ token, id, onBack }: { token: string; id: string; onBack: () => void }) {
  const [d, setD] = useState<any>(null);
  const [alert, setAlert] = useState<any>(null);
  const [done, setDone] = useState<string>("");
  useEffect(() => { api.dossier(token, id).then((x) => { setD(x); setAlert(x.alert); }); }, [id]);
  if (!d) return <section className="desk"><button className="link" onClick={onBack}>← Campaigns</button><p className="muted">The agents are investigating this campaign…</p></section>;
  const publish = async () => {
    const r = await api.publish(token, { ...alert, campaign_id: d.campaign_id, run_id: d.run_id });
    setDone(r.id);
  };
  return (
    <section className="desk dossier">
      <button className="link" onClick={onBack}>← Campaigns</button>
      <h1>{d.name}</h1>
      <p>{d.summary}</p>
      {d.how_it_works && <p className="muted">{d.how_it_works}</p>}
      <div className="facts">
        <div><b>{d.facts.members}</b><span>records</span></div>
        <div><b>{d.facts.citizen_checks}</b><span>citizen checks</span></div>
        <div><b>{(d.facts.reported_loss_fcfa ?? 0).toLocaleString()}</b><span>FCFA reported lost</span></div>
        <div><b>{d.facts.first_seen}</b><span>first seen</span></div>
      </div>

      <h2>Why these belong together</h2>
      <ul className="links">{d.links.map((l: any, i: number) => <li key={i}><code>{l.a.split(":").pop()}</code> ↔ <code>{l.b.split(":").pop()}</code> {l.why}</li>)}</ul>
      {d.review.length > 0 && <p className="muted small">For your review (borderline similarity): {d.review.map((r: any) => `${r.a} ↔ ${r.b}`).join(", ")}</p>}

      <h2>Members</h2>
      <ul className="members">
        {d.members.map((m: any) => (
          <li key={m.id}><span className={`kind ${m.kind}`}>{m.kind}</span> <code>{m.id}</code> {m.text}
            {m.url && <> · <a href={m.url} target="_blank" rel="noreferrer">source</a></>}</li>
        ))}
      </ul>

      <h2>Numbers</h2>
      <ul className="members">{d.numbers.map((n: any) => <li key={n.phone_id}><code>{n.phone_id}</code> reported {n.times_reported ?? 0}× · in alerts {n.times_in_alerts ?? 0}×</li>)}</ul>

      <h2>Recommended actions</h2>
      <ul className="steps">{d.recommended_actions.map((a: string) => <li key={a}>{a}</li>)}</ul>
      <p className="muted small">Limitation: {d.limitations}</p>

      <h2>Public alert</h2>
      {done ? <p className="ok">Published as {done}. It is live on the Alerts tab. <a href="#alerts">See it</a></p> : (
        <div className="editor">
          <label className="field small"><span>Title</span><input value={alert.title} onChange={(e) => setAlert({ ...alert, title: e.target.value })} /></label>
          <label className="field small"><span>English</span><textarea rows={3} value={alert.body_en} onChange={(e) => setAlert({ ...alert, body_en: e.target.value })} /></label>
          <label className="field small"><span>Français</span><textarea rows={3} value={alert.body_fr} onChange={(e) => setAlert({ ...alert, body_fr: e.target.value })} /></label>
          <label className="field small"><span>Pidgin</span><textarea rows={3} value={alert.body_pcm} onChange={(e) => setAlert({ ...alert, body_pcm: e.target.value })} /></label>
          <button className="primary" onClick={publish}>Approve and publish</button>
        </div>
      )}

      <details className="how"><summary>How the agents built this dossier</summary><TraceView lines={d.trace} /></details>
    </section>
  );
}
