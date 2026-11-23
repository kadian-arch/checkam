import { useEffect, useMemo, useState } from "react";
import { api, type LoginResult } from "./api";
import Logo from "./Logo";
import TraceView from "./TraceView";

const KEY = "checkam.analyst";
type Session = { token: string; name: string; org: string; role: string };
type View = { name: "overview" } | { name: "campaigns" } | { name: "dossier"; id: string } | { name: "checks" } | { name: "memory" } | { name: "alerts" } | { name: "admin" } | { name: "check"; id: string };

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
  const [step, setStep] = useState<"password" | "setup" | "code" | "recovery">("password");
  const [challenge, setChallenge] = useState("");
  const [code, setCode] = useState("");
  const [key, setKey] = useState<{ secret: string; uri: string } | null>(null);
  const [saved, setSaved] = useState<{ session: Session; codes: string[] } | null>(null);
  const [qr, setQr] = useState("");
  // the QR code is made in the browser from the key; it is loaded only on this screen
  useEffect(() => { if (key) import("qrcode").then((m) => m.toDataURL(key.uri, { margin: 1, width: 220 })).then(setQr).catch(() => setQr("")); }, [key]);
  const session = (r: LoginResult): Session => ({ token: r.token ?? "", name: r.analyst?.name ?? "", org: r.analyst?.org ?? "", role: r.analyst?.role ?? "" });
  const run = async (f: () => Promise<void>, fallback: string) => {
    setBusy(true);
    setErr("");
    try { await f(); } catch (e) { setErr((e as Error).message || fallback); } finally { setBusy(false); }
  };
  const password = (e: React.FormEvent) => {
    e.preventDefault();
    run(async () => {
      let r: LoginResult;
      try { r = await api.login(email, pw); } catch { throw new Error("Wrong email or password."); }
      if (r.token) return onIn(session(r));
      setChallenge(r.challenge ?? "");
      setCode("");
      if (r.step === "setup") setKey(await api.twofaStart(r.challenge ?? ""));
      setStep(r.step === "setup" ? "setup" : "code");
    }, "Could not sign in.");
  };
  const second = (e: React.FormEvent) => {
    e.preventDefault();
    run(async () => {
      if (step === "setup") {
        const r = await api.twofaSetup(challenge, code);
        setSaved({ session: session(r), codes: r.recovery_codes ?? [] });
        setStep("recovery");
      } else {
        onIn(session(await api.twofaVerify(challenge, code)));
      }
    }, "That code did not work.");
  };
  const grouped = (key?.secret.match(/.{1,4}/g) ?? []).join(" ");
  return (
    <div className="gate">
      <aside className="gate-art">
        <a className="brand" href="/"><Logo /><span>Check<b>Am</b> <small>Intel</small></span></a>
        <h1>See the campaign,<br />not just the message.</h1>
        <p>Citizen checks, scam reports and public alerts, linked into campaigns you can act on. Every link carries its evidence.</p>
        <ul className="gate-points">
          <li>Scam reports and checks linked into campaigns you can act on</li>
          <li>Every link shows the evidence behind it</li>
          <li>Public alerts are signed before they go out</li>
        </ul>
      </aside>
      {step === "password" && (
        <form className="gate-form" onSubmit={password}>
          <h2>Analyst sign-in</h2>
          <p className="muted small">Accounts are created by an administrator for verified fraud, CERT and fact-checking teams.</p>
          <label className="field"><span>Work email</span><input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required /></label>
          <label className="field"><span>Password</span><input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" required /></label>
          <button className="primary" disabled={busy}>{busy ? "Signing in" : "Sign in"}</button>
          {err && <p className="error" role="alert">{err}</p>}
          <a className="link small" href="/">← Back to CheckAm</a>
        </form>
      )}
      {step === "setup" && (
        <form className="gate-form" onSubmit={second}>
          <h2>Set up two-step sign-in</h2>
          <p className="muted small">This account can change and delete things, so a password alone is not enough. Add CheckAm to an authenticator app once (Google Authenticator, Microsoft Authenticator, Authy or 1Password).</p>
          {qr && <img className="setup-qr" src={qr} alt="QR code that adds CheckAm to your authenticator app" width={200} height={200} />}
          <ol className="setup-steps">
            <li>On your phone, open the app, choose to add an account and scan the code above. Signing in from your phone? <a href={key?.uri}>Tap here to open the app instead</a>.</li>
            <li>Cannot scan? Choose to enter a setup key and type this one (spaces do not matter):<div className="setup-key mono" aria-label="Setup key">{grouped}</div>
              <button type="button" className="link small" onClick={() => navigator.clipboard?.writeText(key?.secret ?? "")}>Copy the key</button></li>
            <li>Type the 6-digit code the app now shows:</li>
          </ol>
          <label className="field"><span>6-digit code</span><input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" maxLength={7} required /></label>
          <button className="primary" disabled={busy || code.replace(/\s/g, "").length !== 6}>{busy ? "Checking" : "Confirm and continue"}</button>
          {err && <p className="error" role="alert">{err}</p>}
          <button type="button" className="link small" onClick={() => { setStep("password"); setErr(""); setPw(""); }}>← Start again</button>
        </form>
      )}
      {step === "code" && (
        <form className="gate-form" onSubmit={second}>
          <h2>Enter your code</h2>
          <p className="muted small">Open your authenticator app and type the 6-digit code for CheckAm. Lost your phone? Type one of your recovery codes instead (like a1b2-c3d4). Each works once.</p>
          <label className="field"><span>Code</span><input value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" maxLength={9} required autoFocus /></label>
          <button className="primary" disabled={busy || code.trim().length < 6}>{busy ? "Checking" : "Sign in"}</button>
          {err && <p className="error" role="alert">{err}</p>}
          <button type="button" className="link small" onClick={() => { setStep("password"); setErr(""); setPw(""); }}>← Back</button>
        </form>
      )}
      {step === "recovery" && saved && (
        <div className="gate-form">
          <h2>Save your recovery codes</h2>
          <p className="muted small">If you lose your phone, each of these signs you in once. They are shown only now. Store them somewhere safe, away from the phone (a password manager is ideal).</p>
          <ul className="recovery mono">{saved.codes.map((c) => <li key={c}>{c}</li>)}</ul>
          <button type="button" className="ghost" onClick={() => navigator.clipboard?.writeText(saved.codes.join("\n"))}>Copy all</button>
          <button type="button" className="primary" onClick={() => onIn(saved.session)}>I have saved them, continue</button>
        </div>
      )}
    </div>
  );
}

function Desk({ s, out }: { s: Session; out: () => void }) {
  const [view, setView] = useState<View>({ name: "overview" });
  const [toast, setToast] = useState("");
  const say = (m: string) => { setToast(m); window.clearTimeout((say as unknown as { t?: number }).t); (say as unknown as { t?: number }).t = window.setTimeout(() => setToast(""), 8000); };
  const nav: [View["name"], string][] = [["overview", "Overview"], ["campaigns", "Campaigns"], ["checks", "Citizen checks"], ["memory", "Review & memory"], ["alerts", "Published alerts"], ...(s.role === "admin" ? [["admin", "Administration"] as [View["name"], string]] : [])];
  const guard = (p: Promise<any>) => p.catch((e) => { if (e.status === 401) out(); throw e; });
  return (
    <div className="desk">
      <aside className="rail">
        <a className="brand" href="/"><Logo /><span>Check<b>Am</b> <small>Intel</small></span></a>
        <nav>
          {nav.map(([k, label]) => (
            <button key={k} className={view.name === k || (k === "campaigns" && view.name === "dossier") || (k === "checks" && view.name === "check") ? "on" : ""} onClick={() => setView({ name: k } as View)}>{label}</button>
          ))}
        </nav>
        <div className="who"><b>{s.name}</b><span>{s.org}</span><button className="link small" onClick={out}>Sign out</button></div>
      </aside>
      <main className="pane">
        {view.name === "overview" && <Overview token={s.token} guard={guard} open={(id) => setView({ name: "dossier", id })} />}
        {view.name === "campaigns" && <Campaigns token={s.token} guard={guard} open={(id) => setView({ name: "dossier", id })} />}
        {view.name === "dossier" && <Dossier token={s.token} guard={guard} id={view.id} back={() => setView({ name: "campaigns" })} />}
        {view.name === "checks" && <Checks token={s.token} guard={guard} open={(id) => setView({ name: "check", id })} />}
        {view.name === "check" && <CheckDetail token={s.token} guard={guard} id={view.id} say={say} back={() => setView({ name: "checks" })} openCampaign={(id) => setView({ name: "dossier", id })} />}
        {view.name === "memory" && <Memory token={s.token} guard={guard} say={say} open={(id) => setView({ name: "check", id })} />}
        {view.name === "alerts" && <PublishedAlerts />}
        {view.name === "admin" && s.role === "admin" && <AdminView token={s.token} guard={guard} notify={say} />}
      </main>
      {toast && <div className="toast" role="status" aria-live="polite"><span>{toast}</span><button className="link" onClick={() => setToast("")} aria-label="Dismiss">×</button></div>}
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
  if (!d) return <><button className="link" onClick={back}>← Campaigns</button><p className="muted">The agents are investigating this campaign: pulling the records, checking every link, writing the dossier…</p></>;
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

function Checks({ token, guard, open }: { token: string; guard: G; open: (id: string) => void }) {
  const [rows, setRows] = useState<any[] | null>(null);
  useEffect(() => { guard(api.checks(token)).then((r) => setRows(r.checks)).catch(() => {}); }, [token]);
  return (
    <>
      <header className="pane-head"><h1>Citizen checks</h1><p className="muted">Stored without the person's number. Numbers inside messages appear only as codes. Click a check to see everything held about it.</p></header>
      <section className="card wide flat">
        {!rows ? <p className="muted">Loading…</p> : (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead><tr><th>When</th><th>Verdict</th><th>Message (masked)</th><th>Numbers</th><th>Campaign</th><th /></tr></thead>
              <tbody>{rows.map((c) => (
                <tr key={c.id} tabIndex={0} onClick={() => open(c.id)} onKeyDown={(e) => { if (e.key === "Enter") open(c.id); }} title="Open this check">
                  <td className="mono">{c.created.slice(0, 16).replace("T", " ")}</td><td><span className={`chip v-${c.verdict}`}>{VLABEL[c.verdict]}</span></td>
                  <td className="clip">{c.masked_text}</td><td className="mono">{c.numbers.join(" ") || "–"}</td><td className="mono">{c.campaign_id ? c.campaign_id.slice(-6) : "–"}</td>
                  <td className="go">Open ›</td></tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

// people's "this looks wrong" waits here; what an analyst confirms becomes memory (Meterless H-MEM) and
// later checks of similar messages recall it as evidence
function Memory({ token, guard, say, open }: { token: string; guard: G; say: (m: string) => void; open: (id: string) => void }) {
  const [flags, setFlags] = useState<any[] | null>(null);
  const [mem, setMem] = useState<{ health: any; memories: any[] } | null>(null);
  const [note, setNote] = useState<Record<string, string>>({});
  const load = () => {
    guard(api.flags(token)).then((r) => setFlags(r.flags)).catch(() => setFlags([]));
    guard(api.memory(token)).then(setMem).catch(() => setMem(null));
  };
  useEffect(load, [token]);
  const act = (f: any, action: "confirm" | "dismiss", verdict = "") =>
    guard(api.review(token, f.id, action, verdict, note[f.id] ?? "")).then(() => { say(action === "confirm" ? "Saved. CheckAm will remember this and recall it on similar messages." : "Report dismissed. The answer stays as it was."); load(); }).catch((e) => say(e.message || "Could not save."));
  const sleep = () => guard(api.sleep(token)).then((r) => { say(`Memory settled: ${r.report.consolidated} moved to long-term memory, ${r.report.archived} faded.`); load(); }).catch(() => say("The memory engine is not reachable."));
  return (
    <>
      <header className="pane-head"><h1>Review & memory</h1>
        <p className="muted">When someone says an answer looks wrong, it waits here. Open a report to see the whole check, then confirm what it really was. CheckAm remembers what you confirm and recalls it on similar messages. Nothing a citizen sends changes an answer by itself.</p></header>
      <section className="card wide flat">
        <h3>Waiting for review {flags ? `(${flags.length})` : ""}</h3>
        {!flags ? <p className="muted">Loading…</p> : flags.length === 0 ? <p className="muted">Nothing waiting.</p> : (
          <ul className="flag-list">{flags.map((f) => (
            <li key={f.id} className="flag-card" tabIndex={0} role="button" title="Open the whole check" onClick={() => open(f.check_id)} onKeyDown={(e) => { if (e.key === "Enter" && e.target === e.currentTarget) open(f.check_id); }}>
              <div className="flag-meta">
                <span className="mono">{f.created.slice(0, 16).replace("T", " ")}</span>
                <span>Answer given <span className={`chip v-${f.verdict}`}>{VLABEL[f.verdict] ?? f.verdict}</span></span>
                <span>Person says <b>{VLABEL[f.suggested] ?? "not sure"}</b></span>
                <span className="go">Open ›</span>
              </div>
              <p className="flag-text">{f.masked_text}</p>
              <div className="flag-actions" onClick={(e) => e.stopPropagation()}>
                <input className="mini" defaultValue={f.note} placeholder="Your note (optional)" onChange={(e) => setNote({ ...note, [f.id]: e.target.value })} aria-label="Analyst note" />
                <button className="ghost small" title="Confirm this was a scam. CheckAm remembers it and warns on similar messages." onClick={() => act(f, "confirm", "scam")}>It is a scam</button>
                <button className="ghost small" title="Confirm this was genuine. CheckAm remembers it so similar real messages are not flagged." onClick={() => act(f, "confirm", "looks_genuine")}>It is genuine</button>
                <button className="link small" title="The report is mistaken. Close it and keep the answer as it was." onClick={() => act(f, "dismiss")}>Dismiss</button>
              </div>
            </li>
          ))}</ul>
        )}
      </section>
      <section className="card wide flat">
        <h3>What CheckAm remembers {mem?.health ? `(${mem.health.memories}, ${mem.health.long_term} settled)` : ""}</h3>
        <p className="muted small">A correction starts in short-term memory. Once a day the memory settles the ones that keep proving right into long-term memory and lets one-offs fade. Every change is recorded.</p>
        <button className="ghost small" title="Runs the daily settling now. Corrections that keep proving right move to long-term memory; one-off ones fade. It also runs by itself once a day, so you rarely need this." onClick={sleep}>Settle memory now</button>
        {!mem ? <p className="muted">The memory engine is not reachable.</p> : (
          <div className="tbl-wrap">
            <table className="tbl static">
              <thead><tr><th>Kind</th><th>Verdict</th><th>Memory</th><th>What was learned</th><th>From</th></tr></thead>
              <tbody>{mem.memories.slice().reverse().map((m) => (
                <tr key={m.id}><td>{m.kind}</td><td><span className={`chip v-${m.verdict}`}>{VLABEL[m.verdict] ?? m.verdict}</span></td>
                  <td className="mono">{m.layer}</td><td className="clip">{m.content}</td><td className="mono small">{m.source}</td></tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

function CheckDetail({ token, guard, id, say, back, openCampaign }: { token: string; guard: G; id: string; say: (m: string) => void; back: () => void; openCampaign: (id: string) => void }) {
  const [d, setD] = useState<any>(null);
  const [gone, setGone] = useState(false);
  const [note, setNote] = useState("");
  const load = () => guard(api.checkDetail(token, id)).then((x) => { setD(x); setGone(false); }).catch(() => setGone(true));
  useEffect(() => { setD(null); setNote(""); load(); }, [id]);
  if (gone) return <><button className="link" onClick={back}>← Back</button><p className="muted">This check is no longer in the live database. It may have been archived or deleted.</p></>;
  if (!d) return <p className="muted">Loading…</p>;
  const c = d.check;
  const openFlags = d.flags.filter((f: any) => f.status === "open");
  const decide = (verdict: string) => {
    const call = openFlags.length ? api.review(token, openFlags[0].id, "confirm", verdict, note) : api.correct(token, c.id, verdict, note);
    guard(call).then(() => { say("Saved. CheckAm will remember this and recall it on similar messages."); setNote(""); load(); }).catch((e) => say(e.message || "Could not save."));
  };
  const dismiss = () => guard(api.review(token, openFlags[0].id, "dismiss", "", note)).then(() => { say("Report dismissed. The answer stays as it was."); load(); }).catch((e) => say(e.message || "Could not save."));
  const facts: [string, React.ReactNode][] = [
    ["Checked", c.created.slice(0, 16).replace("T", " ")],
    ["Answer given", <span className={`chip v-${c.verdict}`}>{VLABEL[c.verdict] ?? c.verdict}</span>],
    ["Kind of scam", c.scheme || (c.scam_types || []).join(", ") || "–"],
    ["Language", c.language || "–"], ["Arrived as", c.channel || "–"], ["Operator", c.operator || "–"],
    ["Amount (FCFA)", c.amount_fcfa ?? "–"],
    ["Numbers (codes)", <span className="mono">{(c.numbers || []).join(" ") || "–"}</span>],
    ["Links", <span className="mono">{(c.links || []).join(" ") || "–"}</span>],
    ["Campaign", c.campaign_id ? <button className="link" onClick={() => openCampaign(c.campaign_id)}>Open campaign {String(c.campaign_id).slice(-6)} ›</button> : "–"],
  ];
  return (
    <>
      <button className="link" onClick={back}>← Back</button>
      <header className="pane-head"><h1>Check {c.id}</h1><p className="muted">Everything CheckAm holds about this check. The message is stored with numbers as codes.</p></header>
      <section className="card wide">
        <h3>Message (masked)</h3>
        <blockquote className="msg-quote">{c.masked_text}</blockquote>
      </section>
      <section className="card wide">
        <h3>What was found</h3>
        <dl className="detail-grid">{facts.map(([k, v]) => (<div key={k}><dt>{k}</dt><dd>{v}</dd></div>))}</dl>
        {d.receipt && <p className="small"><a href={`/v/${c.id}`} target="_blank" rel="noreferrer">Open the signed answer people see when it is shared ›</a></p>}
      </section>
      <section className="card wide">
        <h3>Your decision</h3>
        {openFlags.length > 0 ? <p className="muted small">{openFlags.length === 1 ? "Someone reported this answer as wrong" : `${openFlags.length} people reported this answer as wrong`}
          {openFlags[0].suggested ? `, saying it is ${VLABEL[openFlags[0].suggested] ?? "not sure"}` : ""}.</p>
          : <p className="muted small">No one has reported this answer. You can still correct it if you know better.</p>}
        <input className="mini wide-input" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Why (optional). Kept with the correction." aria-label="Note" />
        <div className="row">
          <button className="ghost" title="Confirm this was a scam. CheckAm remembers it and warns on similar messages." onClick={() => decide("scam")}>It is a scam</button>
          <button className="ghost" title="Confirm this was genuine. CheckAm remembers it so similar real messages are not flagged." onClick={() => decide("looks_genuine")}>It is genuine</button>
          {openFlags.length > 0 && <button className="link" title="The report is mistaken. Close it and keep the answer as it was." onClick={dismiss}>Dismiss the report</button>}
        </div>
        {d.flags.length > 0 && (<><h4>Reports on this check</h4><ul className="adm-list">{d.flags.map((f: any) => (
          <li key={f.id}><span className="mono small">{f.created.slice(0, 16).replace("T", " ")}</span><span>says {VLABEL[f.suggested] ?? "not sure"}{f.note ? `: ${f.note}` : ""}</span><span className="muted small">{f.status}{f.reviewed_by ? ` by ${f.reviewed_by}` : ""}</span></li>
        ))}</ul></>)}
      </section>
      <details className="card wide how-checked">
        <summary>Every step the agents took ({d.trace.length})</summary>
        {d.trace.length ? <TraceView lines={d.trace} /> : <p className="muted small">The step log for this check is no longer available.</p>}
      </details>
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

function AdminView({ token, guard, notify }: { token: string; guard: G; notify: (m: string) => void }) {
  const [ov, setOv] = useState<any>(null);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [form, setForm] = useState<Record<string, number>>({});
  const [msg, setMsg] = useState("");
  const [preview, setPreview] = useState<any>(null);
  const [delId, setDelId] = useState("");
  const [people, setPeople] = useState<any[]>([]);
  const [np, setNp] = useState({ email: "", name: "", org: "", password: "" });
  const [editing, setEditing] = useState<string | null>(null);
  const [ed, setEd] = useState({ name: "", org: "", password: "" });
  const load = () => {
    guard(api.adminOverview(token)).then((x) => { setOv(x); setForm(x.settings); }).catch(() => setMsg("Could not load. Are you signed in as the administrator?"));
    guard(api.adminAlerts(token)).then((x) => setAlerts(x.alerts)).catch(() => {});
    guard(api.adminAnalysts(token)).then((x) => setPeople(x.analysts)).catch(() => {});
  };
  useEffect(load, [token]);
  const say = (m: string) => { setMsg(m); notify(m); };
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
  const saveEdit = (email: string) => {
    const body: Record<string, string> = { email, name: ed.name, org: ed.org };
    if (ed.password) body.password = ed.password;
    guard(api.adminUpdateAnalyst(token, body)).then(() => { say(ed.password ? `Updated ${email} and changed the password.` : `Updated ${email}.`); setEditing(null); load(); }).catch((e) => say(e.message || "Could not update (a new password needs 12 characters or more)."));
  };
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
          <button className="primary inline" title="Save the retention periods above" onClick={saveSettings}>Save settings</button>
          <button className="ghost" title="Shows what the cleanup would archive and delete, without changing anything" onClick={dry}>Preview the cleanup</button>
          <button className="ghost danger" title="Archives and deletes everything older than the keep period, now. It also runs by itself every day." onClick={run}>Run the cleanup now</button>
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
            {a.hidden ? <button className="link small" title="Show this alert on the public page again" onClick={() => restore(a)}>Restore</button> : <button className="link small" title="Remove this alert from the public page. The signed record stays." onClick={() => retract(a)}>Take down</button>}
          </li>
        ))}</ul>
      </section>

      <section className="card wide">
        <h3>Accounts</h3>
        <ul className="adm-list">{people.map((p) => (
          <li key={p.email} className="acct">
            <span><b>{p.name}</b> <span className="muted small">{p.email} · {p.org || "no organisation"} · {p.role}</span></span>
            <span className="acct-actions">
              <button className="link small" title="Change the name, the organisation or the password" onClick={() => { setEditing(editing === p.email ? null : p.email); setEd({ name: p.name, org: p.org || "", password: "" }); }}>{editing === p.email ? "Close" : "Edit"}</button>
              {p.role === "admin" ? <span className="muted small">set on the host</span> : <button className="link small" title="Remove this account. They can no longer sign in." onClick={() => removePerson(p.email)}>Remove</button>}
            </span>
            {editing === p.email && (
              <div className="acct-edit">
                <label className="field"><span>Name</span><input value={ed.name} onChange={(e) => setEd({ ...ed, name: e.target.value })} /></label>
                <label className="field"><span>Organisation</span><input value={ed.org} onChange={(e) => setEd({ ...ed, org: e.target.value })} /></label>
                <label className="field"><span>New password (leave empty to keep the current one)</span><input type="password" value={ed.password} onChange={(e) => setEd({ ...ed, password: e.target.value })} autoComplete="new-password" /></label>
                <button className="primary inline" disabled={!ed.name || (ed.password.length > 0 && ed.password.length < 12)} onClick={() => saveEdit(p.email)}>Save changes</button>
                {ed.password.length > 0 && ed.password.length < 12 && <small className="muted">{ed.password.length} of 12 characters</small>}
              </div>
            )}
          </li>
        ))}</ul>
        <h4>Add an analyst</h4>
        <div className="adm-form">
          <label className="field"><span>Work email</span><input value={np.email} onChange={(e) => setNp({ ...np, email: e.target.value })} autoComplete="off" /></label>
          <label className="field"><span>Name</span><input value={np.name} onChange={(e) => setNp({ ...np, name: e.target.value })} /></label>
          <label className="field"><span>Organisation</span><input value={np.org} onChange={(e) => setNp({ ...np, org: e.target.value })} /></label>
          <label className="field"><span>Password (12 characters or more)</span><input type="password" value={np.password} onChange={(e) => setNp({ ...np, password: e.target.value })} autoComplete="new-password" /></label>
        </div>
        <button className="primary inline" disabled={!np.email || !np.name || np.password.length < 12} onClick={addPerson}>Create account</button>
        {(!np.email || !np.name || np.password.length < 12) && <p className="muted small">{!np.email ? "Enter the work email." : !np.name ? "Enter the name." : `The password needs 12 characters or more (${np.password.length} so far).`}</p>}
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
