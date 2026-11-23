export type Evidence = { table: string; id: string; detail?: string; text?: string; operator?: string; kind?: string; only_in_yours?: string[]; similarity?: number; members?: string[]; count?: number; verdict?: string };
export type Why = { text: string; weight: "strong" | "medium" | "weak"; evidence: Evidence[] };
export type TraceLine = {
  timestamp: string; run_id: string; agent_name: string; action: string; input_summary: string | null; output_summary: string | null;
  target_agent: string | null; confidence: number | null; retry_count: number; status: string; sponsor: string; latency_ms: number | null;
};
export type Verdict = "scam" | "suspicious" | "looks_genuine" | "cant_tell";
export type Radar = { days: number; checks: number; flagged: number; top: { scheme: string; n: number }[] };
export type PublicStats = { checks: number; flagged: number; alerts: number; radar?: Radar; retention?: { keep_months: number; archive_months: number } };
export type Card = {
  check_id: string; run_id: string; verdict: Verdict; confidence: number; evidence_level?: "strong" | "positive" | "limited" | "none" | "quiet"; quiet?: boolean; nothing?: boolean; headline: string;
  explain: string; why: Why[]; language: string; do_now: string[]; dont: string[]; questions?: string[]; ask_sender?: boolean; genuine_twin: Evidence | null;
  campaign: { id: string; size: number } | null; rounds: number; trace: TraceLine[]; error?: string;
  receipt?: { id: string; url: string }; cached?: number; scheme?: string | null;
};

export type LoginResult = { token?: string; analyst?: { name: string; email: string; org: string; role?: string }; step?: "setup" | "code"; challenge?: string; recovery_codes?: string[] };

// sign-in calls answer with their own sentence (wrong password, wrong code, too many tries), so they are read as they come
async function authPost<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(typeof j.detail === "string" ? j.detail : "Something went wrong. Try again.");
  return j as T;
}

async function call<T>(path: string, init: RequestInit = {}, token?: string): Promise<T> {
  const headers: Record<string, string> = { ...(init.headers as Record<string, string>) };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (init.body && !(init.body instanceof FormData)) headers["Content-Type"] = "application/json";
  const r = await fetch(path, { ...init, headers });
  if (r.status === 401) throw Object.assign(new Error("signed-out"), { status: 401 });
  if (!r.ok) {
    // the server answers with a sentence, or with a list of what is wrong with the form: say it in words
    const d = (await r.json().catch(() => ({}))).detail;
    throw new Error(typeof d === "string" ? d : Array.isArray(d) ? d.map((x: { loc?: unknown[]; msg?: string }) => `${(x.loc ?? []).slice(-1)[0] ?? ""} ${x.msg ?? ""}`.trim()).join("; ") : r.statusText);
  }
  return r.json();
}

// Runs a check and reports every agent step the moment it happens (server-sent events over POST).
export const MAX_SHOTS = 6;

export type Context = { channel?: string; relation?: string; wants?: string[]; dictated?: boolean };

export async function streamCheck(input: { text: string; sender: string; language: string; files?: File[]; context?: Context },
                                  onStep: (l: TraceLine) => void): Promise<Card> {
  let init: RequestInit;
  let path = "/check/stream";
  if (input.files?.length) {
    const f = new FormData();
    for (const shot of input.files) f.append("image", shot);  // same field, kept in order: one conversation
    f.append("text", input.text);
    f.append("sender", input.sender);
    f.append("language", input.language);
    if (input.context) f.append("context", JSON.stringify(input.context));
    init = { method: "POST", body: f };
    path = "/check/image/stream";
  } else {
    init = { method: "POST", body: JSON.stringify({ text: input.text, sender: input.sender, language: input.language, context: input.context ?? {} }), headers: { "Content-Type": "application/json" } };
  }
  const r = await fetch(path, init);
  if (!r.ok || !r.body) throw new Error((await r.json().catch(() => ({}))).detail ?? r.statusText);
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const chunk = buf.slice(0, i);
      buf = buf.slice(i + 2);
      const ev = /^event: (\w+)/m.exec(chunk)?.[1];
      const data = /^data: (.*)$/m.exec(chunk)?.[1];
      if (!ev || !data) continue;
      const payload = JSON.parse(data);
      if (ev === "step") onStep(payload);
      else if (ev === "card") return payload as Card;
      else if (ev === "error") throw new Error(payload.detail);
    }
  }
  throw new Error("The check ended without an answer");
}

export const api = {
  check: (text: string, sender: string, language: string) =>
    call<Card>("/check", { method: "POST", body: JSON.stringify({ text, sender, language }) }),
  checkImage: (files: File | File[], text: string, language: string) => {
    const f = new FormData();
    for (const shot of [files].flat()) f.append("image", shot);
    f.append("text", text);
    f.append("language", language);
    return call<Card>("/check/image", { method: "POST", body: f });
  },
  alerts: () => call<{ alerts: any[] }>("/alerts"),
  publicStats: () => call<PublicStats>("/stats/public"),
  login: (email: string, password: string) => authPost<LoginResult>("/auth/login", { email, password }),
  twofaStart: (challenge: string) => authPost<{ secret: string; uri: string }>("/auth/2fa/start", { challenge }),
  twofaSetup: (challenge: string, code: string) => authPost<LoginResult>("/auth/2fa/setup", { challenge, code }),
  twofaVerify: (challenge: string, code: string) => authPost<LoginResult>("/auth/2fa/verify", { challenge, code }),
  adminOverview: (t: string) => call<any>("/admin/overview", {}, t),
  adminSettings: (t: string, body: Record<string, number>) => call<any>("/admin/settings", { method: "POST", body: JSON.stringify(body) }, t),
  adminRetention: (t: string, dry_run: boolean) => call<any>("/admin/retention", { method: "POST", body: JSON.stringify({ dry_run }) }, t),
  adminAnalysts: (t: string) => call<{ analysts: any[] }>("/admin/analysts", {}, t),
  adminAddAnalyst: (t: string, body: Record<string, string>) => call<any>("/admin/analysts", { method: "POST", body: JSON.stringify(body) }, t),
  adminRemoveAnalyst: (t: string, email: string) => call<any>("/admin/analysts/delete", { method: "POST", body: JSON.stringify({ email }) }, t),
  adminUpdateAnalyst: (t: string, body: Record<string, string>) => call<any>("/admin/analysts/update", { method: "POST", body: JSON.stringify(body) }, t),
  checkDetail: (t: string, id: string) => call<any>(`/analyst/checks/${id}`, {}, t),
  adminAlerts: (t: string) => call<{ alerts: any[]; show_days: number }>("/admin/alerts", {}, t),
  adminRetract: (t: string, id: string, reason: string) => call<any>(`/admin/alerts/${id}/retract`, { method: "POST", body: JSON.stringify({ reason }) }, t),
  adminRestore: (t: string, id: string) => call<any>(`/admin/alerts/${id}/restore`, { method: "POST" }, t),
  adminDeleteCheck: (t: string, check_id: string) => call<any>("/admin/checks/delete", { method: "POST", body: JSON.stringify({ check_id }) }, t),
  stats: (t: string, operator = "") => call<any>(`/analyst/stats${operator ? `?operator=${operator}` : ""}`, {}, t),
  campaigns: (t: string) => call<{ campaigns: any[]; checks: any }>("/analyst/campaigns", {}, t),
  dossier: (t: string, id: string) => call<any>(`/analyst/campaigns/${id}`, {}, t),
  checks: (t: string) => call<{ checks: any[]; stats: any }>("/analyst/checks", {}, t),
  publish: (t: string, body: any) => call<any>("/analyst/alerts", { method: "POST", body: JSON.stringify(body) }, t),
  afterAction: (b: { acted: string; verdict: string; scheme: string; brands: string[]; why: string[]; language: string }) =>
    call<{ steps: string[] }>("/advice/after", { method: "POST", body: JSON.stringify(b) }),
  flag: (checkId: string, suggested: string, note: string) =>
    call<{ ok: boolean }>(`/checks/${checkId}/flag`, { method: "POST", body: JSON.stringify({ suggested, note }) }),
  flags: (t: string) => call<{ flags: any[] }>("/analyst/flags", {}, t),
  review: (t: string, id: string, action: "confirm" | "dismiss", verdict: string, note: string) =>
    call<any>(`/analyst/flags/${id}`, { method: "POST", body: JSON.stringify({ action, verdict, note }) }, t),
  correct: (t: string, checkId: string, verdict: string, note: string) =>
    call<any>(`/analyst/checks/${checkId}/correct`, { method: "POST", body: JSON.stringify({ action: "confirm", verdict, note }) }, t),
  memory: (t: string) => call<{ health: any; memories: any[] }>("/analyst/memory", {}, t),
  sleep: (t: string) => call<any>("/analyst/memory/sleep", { method: "POST" }, t),
};
