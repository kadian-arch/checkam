import { useEffect, useMemo, useState } from "react";
import { api } from "./api";
import Logo from "./Logo";
import TraceView from "./TraceView";

const KEY = "checkam.analyst";
type Session = { token: string; name: string; org: string; role: string };
type View = { name: "overview" } | { name: "campaigns" } | { name: "dossier"; id: string } | { name: "checks" } | { name: "memory" } | { name: "alerts" } | { name: "admin" };

export default function Portal() {
  const [s, setS] = useState<Session | null>(() => {
    try { return JSON.parse(sessionStorage.getItem(KEY) ?? "null"); } catch { return null; }
  });
  const save = (x: Session | null) => {
    setS(x);
    try { x ? sessionStorage.setItem(KEY, JSON.stringify(x)) : sessionStorage.removeItem(KEY); } catch {}
  };
  useEffect(() => { document.title = "CheckAm Intel"; document.documentElement.dataset.theme = "dark"; }, []);
  return s ? <Desk s={s} out={() => save(null)} /> : <Login onIn={save} />;
}

function Login({ onIn }: { onIn: (s: Session) => void }) {
  const [email, setEmail] = useState("");
  const [pw, setPw] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const go = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const r = await api.login(email, pw);
      onIn({ token: r.token, name: r.analyst.name, org: r.analyst.org, role: r.analyst.role ?? "" });
    } catch {
      setErr("Wrong email or password.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="gate">
      <aside className="gate-art">
        <a className="brand" href="/"><Logo /><span>Check<b>Am</b> <small>Intel</small></span></a>
        <h1>See the campaign,<br />not just the message.</h1>
        <p>Citizen checks, scam reports and public alerts, linked by the agents into campaigns you can act on. Every link carries its evidence.</p>
        <ul className="gate-points">
          <li>Scam reports and checks linked into campaigns you can act on</li>
          <li>Every link shows the evidence behind it</li>
          <li>Public alerts are signed before they go out</li>
        </ul>
      </aside>
      <form className="gate-form" onSubmit={go}>
        <h2>Analyst sign-in</h2>
        <p className="muted small">Accounts are created by an administrator for verified fraud, CERT and fact-checking teams.</p>
        <label className="field"><span>Work email</span><input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required /></label>
        <label className="field"><span>Password</span><input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" required /></label>
        <button className="primary" disabled={busy}>{busy ? "Signing in" : "Sign in"}</button>
        {err && <p className="error">{err}</p>}
        <a className="link small" href="/">← Back to CheckAm</a>
      </form>
    </div>
  );
}

function Desk({ s, out }: { s: Session; out: () => void }) {
  const [view, setView] = useState<View>({ name: "overview" });
  const nav: [View["name"], string][] = [["overview", "Overview"], ["campaigns", "Campaigns"], ["checks", "Citizen checks"], ["memory", "Review & memory"], ["alerts", "Published alerts"], ...(s.role === "admin" ? [["admin", "Administration"] as [View["name"], string]] : [])];
  const guard = (p: Promise<any>) => p.catch((e) => { if (e.status === 401) out(); throw e; });
  return (
    <div className="desk">
      <aside className="rail">
        <a className="brand" href="/"><Logo /><span>Check<b>Am</b> <small>Intel</small></span></a>
        <nav>
          {nav.map(([k, label]) => (
            <button key={k} className={view.name === k || (k === "campaigns" && view.name === "dossier") ? "on" : ""} onClick={() => setView({ name: k } as View)}>{label}</button>
          ))}
        </nav>
        <div className="who"><b>{s.name}</b><span>{s.org}</span><button className="link small" onClick={out}>Sign out</button></div>
      </aside>
      <main className="pane">
        {view.name === "overview" && <Overview token={s.token} guard={guard} open={(id) => setView({ name: "dossier", id })} />}
        {view.name === "campaigns" && <Campaigns token={s.token} guard={guard} open={(id) => setView({ name: "dossier", id })} />}
        {view.name === "dossier" && <Dossier token={s.token} guard={guard} id={view.id} back={() => setView({ name: "campaigns" })} />}
        {view.name === "checks" && <Checks token={s.token} guard={guard} />}
        {view.name === "memory" && <Memory token={s.token} guard={guard} />}
        {view.name === "alerts" && <PublishedAlerts />}
        {view.name === "admin" && s.role === "admin" && <AdminView token={s.token} guard={guard} />}
      </main>
    </div>
  );
}

type G = (p: Promise<any>) => Promise<any>;
const VERDICTS = ["scam", "suspicious", "cant_tell", "looks_genuine"] as const;
const VLABEL: Record<string, string> = { scam: "Scam", suspicious: "Be careful", cant_tell: "Can't tell", looks_genuine: "Genuine" };

function Overview({ token, guard, open }: { token: string; guard: G; open: (id: string) => void }) {
  const [st, setSt] = useState<any>(null);
  const [camps, setCamps] = useState<any[]>([]);
  // operator view first proposed by Chelsey in her FraudLens 360 mock-up
  const [op, setOp] = useState("");
  useEffect(() => {
    guard(api.stats(token, op)).then(setSt).catch(() => {});
  }, [token, op]);
  useEffect(() => {
    guard(api.campaigns(token)).then((r) => setCamps(r.campaigns)).catch(() => {});
  }, [token]);
  const days = useMemo(() => {
    const m = new Map<string, Record<string, number>>();
    for (const r of st?.by_day ?? []) m.set(r.day, { ...(m.get(r.day) ?? {}), [r.verdict]: r.n });
    return [...m.entries()].sort(([a], [b]) => a.localeCompare(b)).slice(-14);
  }, [st]);
  if (!st) return <p className="muted">Loading the desk…</p>;
  const flagged = (st.by_verdict.scam ?? 0) + (st.by_verdict.suspicious ?? 0);
  return (
    <>
      <header className="pane-head"><h1>Overview</h1><p className="muted">Live from the case store and the campaign graph.</p></header>
      <div className="ops" role="group" aria-label="Operator">
        {OPS.map(([k, label]) => (
          <button key={k} className={`op ${k || "all"} ${op === k ? "on" : ""}`} onClick={() => setOp(k)} aria-pressed={op === k}>
            {label}{k && st.by_operator?.[k] ? <small>{st.by_operator[k].checks}</small> : null}
          </button>
        ))}
      </div>
      <div className="kpis">
        <Kpi label="Citizen checks" value={st.total} />
        <Kpi label="FCFA kept from scammers" value={st.kept_fcfa} sub="amounts in messages flagged before money moved" tone="safe" />
        <Kpi label="Flagged as scam or risky" value={flagged} sub={st.total ? `${Math.round((100 * flagged) / st.total)}% of checks` : ""} tone="danger" />
        <Kpi label="Active campaigns" value={camps.length} sub={`${camps.filter((c) => c.citizen_checks).length} fed by citizen checks`} tone="signal" />
        <Kpi label="Alerts published" value={st.alerts} tone="safe" />
      </div>
      <div className="cards">
        <section className="card wide">
          <h3>Checks per day</h3>
          <DayBars days={days} />
          <Legend />
        </section>
        <section className="card">
          <h3>Verdicts</h3>
          <Stack counts={st.by_verdict} />
        </section>
        <section className="card">
          <h3>By operator <small>checks, flagged</small></h3>
          <ul className="bars ops-bars">{OPS.filter(([k]) => k).map(([k, label]) => {
            const r = st.by_operator?.[k] ?? { checks: 0, flagged: 0 };
            const max = Math.max(1, ...Object.values<any>(st.by_operator ?? {}).map((x) => x.checks));
            return <li key={k}><span>{label}</span><i className={`op-${k}`} style={{ width: `${(100 * r.checks) / max}%` }} /><b>{r.checks} · {r.flagged}</b></li>;
          })}</ul>
        </section>
        <section className="card">
          <h3>Latest flagged checks</h3>
          {st.flagged?.length ? (
            <ul className="feed">{st.flagged.map((f: any) => (
              <li key={f.id} className={f.verdict}>
                <span className={`chip v-${f.verdict}`}>{f.verdict === "scam" ? "Scam" : "Risky"}</span>
                <p>{f.masked_text.slice(0, 110)}</p>
                <small>{(f.operator || "other").toUpperCase()} · {f.created.slice(5, 16).replace("T", " ")}{f.amount_fcfa ? ` · ${f.amount_fcfa.toLocaleString()} FCFA` : ""}</small>
              </li>
            ))}</ul>
          ) : <p className="muted small">Nothing flagged yet.</p>}
        </section>
        <section className="card">
          <h3>Most reported numbers <small>(codes, never real numbers)</small></h3>
          <Bars rows={st.top_numbers} mono />
        </section>
        <section className="card">
          <h3>Scam types in flagged checks</h3>
          <Bars rows={st.top_types.map((r: any) => ({ ...r, key: r.key.replace(/_/g, " ") }))} />
        </section>
        <section className="card wide">
          <h3>Campaigns to look at first</h3>
          <CampTable camps={camps.slice(0, 6)} open={open} />
        </section>
      </div>
    </>
  );
}

const OPS: [string, string][] = [["", "All operators"], ["mtn", "MTN"], ["orange", "Orange"], ["camtel", "Camtel"], ["other", "Other"]];

function Kpi({ label, value, sub, tone }: { label: string; value: any; sub?: string; tone?: string }) {
  return <div className={`kpi ${tone ?? ""}`}><span>{label}</span><b>{typeof value === "number" ? value.toLocaleString() : value}</b>{sub && <small>{sub}</small>}</div>;
}

function DayBars({ days }: { days: [string, Record<string, number>][] }) {
  if (!days.length) return <p className="muted small">No checks yet.</p>;
  const max = Math.max(...days.map(([, v]) => Object.values(v).reduce((a, b) => a + b, 0)), 1);
  const W = 640, H = 150, bw = W / days.length;
  return (
    <svg viewBox={`0 0 ${W} ${H + 18}`} className="chart" role="img" aria-label="Checks per day by verdict">
      {days.map(([day, v], i) => {
        let y = H;
        return (
          <g key={day}>
            {VERDICTS.map((k) => {
              const h = ((v[k] ?? 0) / max) * (H - 6);
              y -= h;
              return h > 0 ? <rect key={k} x={i * bw + (bw - Math.min(bw * 0.64, 40)) / 2} y={y} width={Math.min(bw * 0.64, 40)} height={h} className={`v-${k}`} rx="2" /> : null;
            })}
            <text x={i * bw + bw / 2} y={H + 14} textAnchor="middle">{day.slice(5)}</text>
          </g>
        );
      })}
    </svg>
  );
}

function Legend() {
  return <p className="legend">{VERDICTS.map((k) => <span key={k}><i className={`v-${k}`} />{VLABEL[k]}</span>)}</p>;
}

function Stack({ counts }: { counts: Record<string, number> }) {
  const total = VERDICTS.reduce((a, k) => a + (counts[k] ?? 0), 0) || 1;
  return (
    <div className="stack">
      <div className="stack-bar">{VERDICTS.map((k) => counts[k] ? <i key={k} className={`v-${k}`} style={{ width: `${(100 * counts[k]) / total}%` }} /> : null)}</div>
      <ul>{VERDICTS.map((k) => <li key={k}><i className={`v-${k}`} />{VLABEL[k]}<b>{counts[k] ?? 0}</b></li>)}</ul>
    </div>
  );
}

function Bars({ rows, mono }: { rows: { key: string; n: number }[]; mono?: boolean }) {
  if (!rows?.length) return <p className="muted small">Nothing yet.</p>;
  const max = Math.max(...rows.map((r) => r.n));
  return <ul className="bars">{rows.map((r) => <li key={r.key}><span className={mono ? "mono" : ""}>{r.key}</span><i style={{ width: `${(100 * r.n) / max}%` }} /><b>{r.n}</b></li>)}</ul>;
}

function CampTable({ camps, open }: { camps: any[]; open: (id: string) => void }) {
  if (!camps.length) return <p className="muted small">The graph has not linked anything yet.</p>;
  return (
    <table className="tbl">
      <thead><tr><th>Records</th><th>Citizen checks</th><th>Signals</th><th>Numbers</th><th>Scam types</th><th>Last seen</th><th /></tr></thead>
      <tbody>
        {camps.map((c) => (
          <tr key={c.id} onClick={() => open(c.id)}>
            <td><b>{c.size}</b> <small className="muted">{Object.entries(c.kinds).map(([k, v]) => `${v} ${k}`).join(" · ")}</small></td>
            <td>{c.citizen_checks ? <span className="chip signal">{c.citizen_checks}</span> : "–"}</td>
            <td>{c.signals.join(", ")}</td>
            <td className="mono">{c.numbers.slice(0, 2).join(" ") || "–"}</td>
            <td>{c.scam_types.slice(0, 2).map((s: string) => s.replace(/_/g, " ")).join(", ") || "–"}</td>
            <td className="mono">{c.last_seen?.slice(0, 10)}</td>
            <td className="go">Open →</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Campaigns({ token, guard, open }: { token: string; guard: G; open: (id: string) => void }) {
  const [camps, setCamps] = useState<any[] | null>(null);
  useEffect(() => { guard(api.campaigns(token)).then((r) => setCamps(r.campaigns)).catch(() => {}); }, [token]);
  return (
    <>
      <header className="pane-head"><h1>Campaigns</h1><p className="muted">Records the World Model links by a shared number, a shared link, or near-identical wording. Citizen-fed campaigns first.</p></header>
      {camps ? <section className="card wide flat"><CampTable camps={camps} open={open} /></section> : <p className="muted">Loading the campaign graph…</p>}
    </>
  );
}

function Dossier({ token, guard, id, back }: { token: string; guard: G; id: string; back: () => void }) {
  const [d, setD] = useState<any>(null);
  const [alert, setAlert] = useState<any>(null);
  const [done, setDone] = useState<any>(null);
  const [err, setErr] = useState("");
  useEffect(() => { guard(api.dossier(token, id)).then((x) => { setD(x); setAlert(x.alert); }).catch(() => {}); }, [id]);
  if (!d) return <><button className="link" onClick={back}>← Campaigns</button><p className="muted">The agents are investigating this campaign: pulling records from Zetaris, checking every link, writing the dossier…</p></>;
  const publish = async () => {
    setErr("");
    try {
      setDone(await guard(api.publish(token, { ...alert, campaign_id: d.campaign_id, run_id: d.run_id })));
    } catch (e: any) {
      setErr(e.message);
    }
  };
  return (
    <>
      <button className="link" onClick={back}>← Campaigns</button>
      <header className="pane-head"><h1>{d.name}</h1><p>{d.summary}</p>{d.how_it_works && <p className="muted">{d.how_it_works}</p>}</header>
      <div className="kpis">
        <Kpi label="Linked records" value={d.facts.members} />
        <Kpi label="Citizen checks" value={d.facts.citizen_checks} tone="signal" />
        <Kpi label="Reported loss (FCFA)" value={d.facts.reported_loss_fcfa ?? 0} tone="danger" />
        <Kpi label="First seen" value={d.facts.first_seen} />
        <Kpi label="Last seen" value={d.facts.last_seen} />
      </div>
      <div className="cards">
        <section className="card wide">
          <h3>Why these records belong together</h3>
          <ul className="links">{d.links.map((l: any, i: number) => <li key={i}><code>{l.a.split(":").pop()}</code><i>↔</i><code>{l.b.split(":").pop()}</code><span>{l.why}</span></li>)}</ul>
          {d.review.length > 0 && <p className="muted small">For your review (borderline similarity): {d.review.map((r: any) => `${r.a} ↔ ${r.b}`).join(", ")}</p>}
        </section>
        <section className="card wide">
          <h3>Members</h3>
          <table className="tbl">
            <thead><tr><th>Kind</th><th>Id</th><th>What it says</th><th>Source</th></tr></thead>
            <tbody>{d.members.map((m: any) => (
              <tr key={m.id}><td><span className={`chip ${m.kind}`}>{m.kind}</span></td><td className="mono">{m.id}</td><td>{m.text}</td>
                <td>{m.url ? <a href={m.url} target="_blank" rel="noreferrer">{m.outlet}</a> : m.region || m.date || "–"}</td></tr>
            ))}</tbody>
          </table>
        </section>
        <section className="card">
          <h3>Numbers involved</h3>
          <ul className="bars plain">{d.numbers.map((n: any) => <li key={n.phone_id}><span className="mono">{n.phone_id}</span><b>{n.times_reported ?? 0} reports · {n.times_in_alerts ?? 0} alerts</b></li>)}</ul>
        </section>
        <section className="card">
          <h3>Recommended actions</h3>
          <ul className="actions-list">{d.recommended_actions.map((a: string) => <li key={a}>{a}</li>)}</ul>
          <p className="muted small">Limitation: {d.limitations}</p>
        </section>
        <section className="card wide publish">
          <h3>Public alert <small>signed and published to every CheckAm user</small></h3>
          {done ? (
            <div className="published">
              <p><b>Published as {done.id}.</b> It is live on the public alerts feed.</p>
              <p className="mono small">contract {done.contract?.contractId} · approvals {done.approvals?.join(", ")}</p>
              {done.signature && <p className="mono small">ed25519 {done.signature.slice(0, 32)}… · chain {done.hash?.slice(0, 16)}…</p>}
            </div>
          ) : (
            <div className="editor">
              <div className="two">
                <label className="field"><span>Title (English)</span><input value={alert.title} onChange={(e) => setAlert({ ...alert, title: e.target.value })} /></label>
                <label className="field"><span>Titre (français)</span><input value={alert.title_fr ?? ""} placeholder="Left empty, it is translated for you" onChange={(e) => setAlert({ ...alert, title_fr: e.target.value })} /></label>
              </div>
              <div className="two">
                <label className="field"><span>English</span><textarea rows={4} value={alert.body_en} onChange={(e) => setAlert({ ...alert, body_en: e.target.value })} /></label>
                <label className="field"><span>Français</span><textarea rows={4} value={alert.body_fr} onChange={(e) => setAlert({ ...alert, body_fr: e.target.value })} /></label>
              </div>
              <button className="primary inline" onClick={publish}>Approve, sign and publish</button>
              {err && <p className="error">{err}</p>}
            </div>
          )}
        </section>
        <details className="card wide"><summary>How the agents built this dossier</summary><TraceView lines={d.trace} /></details>
      </div>
    </>
  );
}

function Checks({ token, guard }: { token: string; guard: G }) {
  const [rows, setRows] = useState<any[] | null>(null);
  useEffect(() => { guard(api.checks(token)).then((r) => setRows(r.checks)).catch(() => {}); }, [token]);
  return (
    <>
      <header className="pane-head"><h1>Citizen checks</h1><p className="muted">Stored without the person's number. Numbers inside messages appear only as codes.</p></header>
      <section className="card wide flat">
        {!rows ? <p className="muted">Loading…</p> : (
          <table className="tbl">
            <thead><tr><th>When</th><th>Verdict</th><th>Message (masked)</th><th>Numbers</th><th>Campaign</th><th>Run</th></tr></thead>
            <tbody>{rows.map((c) => (
              <tr key={c.id}><td className="mono">{c.created.slice(0, 16).replace("T", " ")}</td><td><span className={`chip v-${c.verdict}`}>{VLABEL[c.verdict]}</span></td>
                <td className="clip">{c.masked_text}</td><td className="mono">{c.numbers.join(" ") || "–"}</td><td className="mono">{c.campaign_id ? c.campaign_id.slice(-6) : "–"}</td>
                <td className="mono"><a href={`/traces/${c.run_id}`} target="_blank" rel="noreferrer">{c.run_id}</a></td></tr>
            ))}</tbody>
          </table>
        )}
      </section>
    </>
  );
}

// people's "this looks wrong" waits here; what an analyst confirms becomes memory (Meterless H-MEM) and
// later checks of similar messages recall it as evidence
function Memory({ token, guard }: { token: string; guard: G }) {
  const [flags, setFlags] = useState<any[] | null>(null);
  const [mem, setMem] = useState<{ health: any; memories: any[] } | null>(null);
  const [note, setNote] = useState<Record<string, string>>({});
  const [msg, setMsg] = useState("");
  const load = () => {
    guard(api.flags(token)).then((r) => setFlags(r.flags)).catch(() => setFlags([]));
    guard(api.memory(token)).then(setMem).catch(() => setMem(null));
  };
  useEffect(load, [token]);
  const act = (f: any, action: "confirm" | "dismiss", verdict = "") =>
    guard(api.review(token, f.id, action, verdict, note[f.id] ?? "")).then(() => { setMsg(action === "confirm" ? "Saved to memory. Similar checks will recall it." : "Dismissed."); load(); }).catch(() => setMsg("Could not save."));
  const sleep = () => guard(api.sleep(token)).then((r) => { setMsg(`Sleep cycle done: ${r.report.consolidated} consolidated, ${r.report.archived} archived.`); load(); }).catch(() => setMsg("Memory engine unavailable."));
  return (
    <>
      <header className="pane-head"><h1>Review & memory</h1>
        <p className="muted">When people say an answer looks wrong, it waits here. What you confirm is remembered by the Meterless H-MEM engine, and the agents recall it on similar messages. Nothing a citizen sends changes an answer by itself.</p></header>
      {msg && <p className="note">{msg}</p>}
      <section className="card wide flat">
        <h3>Waiting for review {flags ? `(${flags.length})` : ""}</h3>
        {!flags ? <p className="muted">Loading…</p> : flags.length === 0 ? <p className="muted">Nothing waiting.</p> : (
          <table className="tbl">
            <thead><tr><th>When</th><th>Answer given</th><th>Person says</th><th>Message (masked)</th><th>Note</th><th>Decide</th></tr></thead>
            <tbody>{flags.map((f) => (
              <tr key={f.id}><td className="mono">{f.created.slice(0, 16).replace("T", " ")}</td>
                <td><span className={`chip v-${f.verdict}`}>{VLABEL[f.verdict] ?? f.verdict}</span></td>
                <td>{VLABEL[f.suggested] ?? "Not sure"}</td><td className="clip">{f.masked_text}</td>
                <td><input className="mini" defaultValue={f.note} onChange={(e) => setNote({ ...note, [f.id]: e.target.value })} aria-label="Analyst note" /></td>
                <td className="actions">
                  <button className="ghost small" onClick={() => act(f, "confirm", "scam")}>Scam</button>
                  <button className="ghost small" onClick={() => act(f, "confirm", "looks_genuine")}>Genuine</button>
                  <button className="link small" onClick={() => act(f, "dismiss")}>Dismiss</button>
                </td></tr>
            ))}</tbody>
          </table>
        )}
      </section>
      <section className="card wide flat">
        <h3>What CheckAm remembers {mem?.health ? `(${mem.health.memories}, ${mem.health.long_term} settled)` : ""}</h3>
        <p className="muted small">Corrections start in working memory; the daily sleep cycle settles the ones that keep proving right and lets one-offs fade. Every change is in the H-MEM trust ledger.</p>
        <button className="ghost small" onClick={sleep}>Run the sleep cycle now</button>
        {!mem ? <p className="muted">Memory engine unavailable.</p> : (
          <table className="tbl">
            <thead><tr><th>Kind</th><th>Verdict</th><th>Layer</th><th>What was learned</th><th>From</th></tr></thead>
            <tbody>{mem.memories.slice().reverse().map((m) => (
              <tr key={m.id}><td>{m.kind}</td><td><span className={`chip v-${m.verdict}`}>{VLABEL[m.verdict] ?? m.verdict}</span></td>
                <td className="mono">{m.layer}</td><td className="clip">{m.content}</td><td className="mono small">{m.source}</td></tr>
            ))}</tbody>
          </table>
        )}
      </section>
    </>
  );
}

function PublishedAlerts() {
  const [rows, setRows] = useState<any[] | null>(null);
  useEffect(() => { api.alerts().then((r) => setRows(r.alerts)).catch(() => setRows([])); }, []);
  return (
    <>
      <header className="pane-head"><h1>Published alerts</h1><p className="muted">Each alert carries an Ed25519 signature and a hash link to the alert before it. Anyone can verify one at /alerts/verify.</p></header>
      <div className="cards">{rows?.map((a) => (
        <section key={a.id} className="card">
          <h3>{a.title}</h3><p>{a.body_en}</p>
          <p className="mono small">{a.id} · {a.created.slice(0, 16)} · by {a.published_by}</p>
          {a.signature && <p className="mono small sig">✓ signed {a.signature.slice(0, 24)}…</p>}
        </section>
      ))}</div>
    </>
  );
}


// The administrator desk: only an account with the admin role sees it, and the server checks the role again on every call.
const SETTING_LABELS: [string, string, string][] = [
  ["check_keep_days", "Keep saved checks (days)", "After this, a check is counted into monthly totals, archived and removed from the live database and the campaign graph."],
  ["archive_keep_days", "Keep the compressed archive (days)", "Extra time the archive stays after the live period. 0 means no archive: old checks are deleted outright."],
  ["answer_keep_days", "Keep the answer cache (days)", "Cached answers make a repeated message instant."],
  ["alert_show_days", "Show an alert on the public page (days)", "Older alerts leave the page but stay in the signed log, so their proof still verifies."],
];

function AdminView({ token, guard }: { token: string; guard: G }) {
  const [ov, setOv] = useState<any>(null);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [form, setForm] = useState<Record<string, number>>({});
  const [msg, setMsg] = useState("");
  const [preview, setPreview] = useState<any>(null);
  const [delId, setDelId] = useState("");
  const [people, setPeople] = useState<any[]>([]);
  const [np, setNp] = useState({ email: "", name: "", org: "", password: "" });
  const load = () => {
    guard(api.adminOverview(token)).then((x) => { setOv(x); setForm(x.settings); }).catch(() => setMsg("Could not load. Are you signed in as the administrator?"));
    guard(api.adminAlerts(token)).then((x) => setAlerts(x.alerts)).catch(() => {});
    guard(api.adminAnalysts(token)).then((x) => setPeople(x.analysts)).catch(() => {});
  };
  useEffect(load, [token]);
  const say = (m: string) => { setMsg(m); window.scrollTo({ top: 0, behavior: "smooth" }); };
  const saveSettings = () => guard(api.adminSettings(token, form)).then(() => { say("Settings saved."); load(); }).catch((e) => say(e.message || "Could not save"));
  const dry = () => guard(api.adminRetention(token, true)).then(setPreview).catch((e) => say(e.message));
  const run = () => {
    if (!window.confirm("Archive and delete everything older than the keep period? This cannot be undone, apart from the compressed archive.")) return;
    guard(api.adminRetention(token, false)).then((r) => { say(`Cleanup done: ${r.archived ?? 0} checks archived, ${r.deleted?.checks ?? 0} removed.`); setPreview(null); load(); }).catch((e) => say(e.message));
  };
  const retract = (a: any) => {
    const reason = window.prompt(`Why take down "${a.title}"? (kept in the admin log)`, "");
    if (reason === null) return;
    guard(api.adminRetract(token, a.id, reason)).then(() => { say("Alert taken off the public page. The signed record is kept."); load(); }).catch((e) => say(e.message));
  };
  const restore = (a: any) => guard(api.adminRestore(token, a.id)).then(() => { say("Alert is public again."); load(); }).catch((e) => say(e.message));
  const del = () => {
    if (!window.confirm(`Delete check ${delId} everywhere (database, signed answer, review flags, campaign graph)?`)) return;
    guard(api.adminDeleteCheck(token, delId.trim())).then((r) => { say(`Deleted: ${r.checks} check, ${r.receipts} signed answer, ${r.flags} flags.`); setDelId(""); load(); }).catch((e) => say(e.message || "Could not delete"));
  };
  const addPerson = () => guard(api.adminAddAnalyst(token, np)).then(() => { say(`Account created for ${np.email}.`); setNp({ email: "", name: "", org: "", password: "" }); load(); }).catch((e) => say(e.message || "Could not create the account (password needs 12 characters or more)"));
  const removePerson = (email: string) => {
    if (!window.confirm(`Remove the account ${email}? They will no longer be able to sign in.`)) return;
    guard(api.adminRemoveAnalyst(token, email)).then(() => { say(`Removed ${email}.`); load(); }).catch((e) => say(e.message));
  };
  const download = async (name: string) => {
    const r = await fetch(`/admin/archive/${name}`, { headers: { Authorization: `Bearer ${token}` } });
    if (!r.ok) return say("Could not download that archive.");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(await r.blob());
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  if (!ov) return <p className="muted">{msg || "Loading administration…"}</p>;
  const c = ov.counts;
  return (
    <>
      <header className="pane-head"><h1>Administration</h1><p className="muted">Only this account can change retention, take alerts down or delete a check. Every action is written to the log at the bottom.</p></header>
      {msg && <p className="note" role="status">{msg}</p>}

      <section className="card wide">
        <h3>What is stored</h3>
        <div className="adm-tiles">
          {([["Saved checks", c.checks], ["Archived checks (counted)", c.archived_checks], ["Cached answers", c.answers_cached], ["Open review flags", c.flags_open],
            ["Published alerts", c.alerts], ["Taken down", c.alerts_hidden], ["Analyst accounts", c.analysts]] as [string, number][]).map(([k, v]) => (
            <div key={k}><b>{v}</b><span>{k}</span></div>
          ))}
        </div>
        <p className="muted small">Campaign graph: {ov.engine ? `${ov.engine.observations} observations, ${ov.engine.edges} links` : "not reachable"}.</p>
      </section>

      <section className="card wide">
        <h3>Retention</h3>
        <div className="adm-form">
          {SETTING_LABELS.map(([k, label, help]) => (
            <label key={k} className="field"><span>{label}</span>
              <input type="number" min={0} value={form[k] ?? ""} onChange={(e) => setForm({ ...form, [k]: Number(e.target.value) })} />
              <small className="muted">{help}</small></label>
          ))}
        </div>
        <div className="row">
          <button className="primary inline" onClick={saveSettings}>Save settings</button>
          <button className="ghost" onClick={dry}>Preview the cleanup</button>
          <button className="ghost danger" onClick={run}>Run the cleanup now</button>
        </div>
        {preview && <p className="mono small">Would archive {preview.checks_due} checks. Would remove: {Object.entries(preview.would_delete).map(([k, v]) => `${v} ${k}`).join(", ")}. Nothing has changed yet.</p>}
        {ov.last_retention && <p className="muted small">Last cleanup {ov.last_retention.at?.slice(0, 16)} by {ov.last_retention.by}: {ov.last_retention.archived ?? 0} archived, {ov.last_retention.deleted?.checks ?? 0} removed.</p>}
        <h4>Archive files</h4>
        {ov.archive.length === 0 ? <p className="muted small">None yet.</p> : (
          <ul className="adm-list">{ov.archive.map((f: any) => (
            <li key={f.name}><span className="mono">{f.name}</span><span className="muted small">{(f.bytes / 1024).toFixed(1)} KB</span><button className="link small" onClick={() => download(f.name)}>Download</button></li>
          ))}</ul>
        )}
      </section>

      <section className="card wide">
        <h3>Published alerts</h3>
        <p className="muted small">Taking an alert down removes it from the public page. The signed record stays in the log, so the chain still verifies.</p>
        <ul className="adm-list">{alerts.map((a) => (
          <li key={a.id}>
            <span><b>{a.title}</b> <span className="muted small">{a.created.slice(0, 10)}{a.title_fr ? "" : " · no French title"}{a.hidden ? ` · taken down${a.reason ? `: ${a.reason}` : ""}` : ""}</span></span>
            {a.hidden ? <button className="link small" onClick={() => restore(a)}>Restore</button> : <button className="link small" onClick={() => retract(a)}>Take down</button>}
          </li>
        ))}</ul>
      </section>

      <section className="card wide">
        <h3>Accounts</h3>
        <ul className="adm-list">{people.map((p) => (
          <li key={p.email}><span><b>{p.name}</b> <span className="muted small">{p.email} · {p.org || "no organisation"} · {p.role}</span></span>
            {p.role === "admin" ? <span className="muted small">set on the host</span> : <button className="link small" onClick={() => removePerson(p.email)}>Remove</button>}</li>
        ))}</ul>
        <h4>Add an analyst</h4>
        <div className="adm-form">
          <label className="field"><span>Work email</span><input value={np.email} onChange={(e) => setNp({ ...np, email: e.target.value })} autoComplete="off" /></label>
          <label className="field"><span>Name</span><input value={np.name} onChange={(e) => setNp({ ...np, name: e.target.value })} /></label>
          <label className="field"><span>Organisation</span><input value={np.org} onChange={(e) => setNp({ ...np, org: e.target.value })} /></label>
          <label className="field"><span>Password (12 characters or more)</span><input type="password" value={np.password} onChange={(e) => setNp({ ...np, password: e.target.value })} autoComplete="new-password" /></label>
        </div>
        <button className="primary inline" disabled={!np.email || !np.name || np.password.length < 12} onClick={addPerson}>Create account</button>
      </section>

      <section className="card wide">
        <h3>Delete one check</h3>
        <p className="muted small">Removes it from the database, its signed answer, any review flags and the campaign graph.</p>
        <div className="row">
          <input value={delId} onChange={(e) => setDelId(e.target.value)} placeholder="C-1a2b3c4d" aria-label="Check id" />
          <button className="ghost danger" disabled={!/^C-[0-9a-f]{8}$/.test(delId.trim())} onClick={del}>Delete</button>
        </div>
      </section>

      <section className="card wide">
        <h3>Administration log</h3>
        <ul className="adm-list">{ov.audit.map((a: any, i: number) => (
          <li key={i}><span className="mono small">{a.at.slice(0, 16)}</span><span>{a.who}</span><span><b>{a.action}</b> <span className="muted small">{a.detail}</span></span></li>
        ))}</ul>
      </section>
    </>
  );
}
