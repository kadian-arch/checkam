export type Evidence = { table: string; id: string; detail?: string; text?: string; operator?: string; kind?: string; only_in_yours?: string[]; similarity?: number; members?: string[] };
export type Why = { text: string; weight: "strong" | "medium" | "weak"; evidence: Evidence[] };
export type TraceLine = {
  timestamp: string; run_id: string; agent_name: string; action: string; input_summary: string | null; output_summary: string | null;
  target_agent: string | null; confidence: number | null; retry_count: number; status: string; sponsor: string; latency_ms: number | null;
};
export type Card = {
  check_id: string; run_id: string; verdict: "scam" | "suspicious" | "looks_genuine" | "cant_tell"; confidence: number; headline: string;
  explain: string; why: Why[]; language: string; do_now: string[]; dont: string[]; genuine_twin: Evidence | null;
  campaign: { id: string; size: number } | null; rounds: number; trace: TraceLine[]; error?: string;
};

async function call<T>(path: string, init: RequestInit = {}, token?: string): Promise<T> {
  const headers: Record<string, string> = { ...(init.headers as Record<string, string>) };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (init.body && !(init.body instanceof FormData)) headers["Content-Type"] = "application/json";
  const r = await fetch(path, { ...init, headers });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail ?? r.statusText);
  return r.json();
}

export const api = {
  check: (text: string, sender: string, language: string) =>
    call<Card>("/check", { method: "POST", body: JSON.stringify({ text, sender, language }) }),
  checkImage: (file: File, text: string, language: string) => {
    const f = new FormData();
    f.append("image", file);
    f.append("text", text);
    f.append("language", language);
    return call<Card>("/check/image", { method: "POST", body: f });
  },
  alerts: () => call<{ alerts: any[] }>("/alerts"),
  login: (email: string, password: string) =>
    call<{ token: string; analyst: { name: string; email: string; org: string } }>("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  campaigns: (t: string) => call<{ campaigns: any[]; checks: any }>("/analyst/campaigns", {}, t),
  dossier: (t: string, id: string) => call<any>(`/analyst/campaigns/${id}`, {}, t),
  checks: (t: string) => call<{ checks: any[]; stats: any }>("/analyst/checks", {}, t),
  publish: (t: string, body: any) => call<any>("/analyst/alerts", { method: "POST", body: JSON.stringify(body) }, t),
  health: () => call<any>("/health"),
};
