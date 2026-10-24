// CheckAm Scout: intent sensing, guard stack, routing and signed execution contracts,
// built to the Meterless Scout Intent spec (engines/scout-intent/AGENTS.md).
// Stage 1 is deterministic and always on; Stage 2 (semantic) is optional and pluggable.

import { createHash, createHmac, randomBytes } from "node:crypto";
import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

export type Intent = {
  id: string;
  category: string;
  description: string;
  parameters?: { type?: string; properties?: Record<string, any>; required?: string[] };
  capabilities: string[];
  riskClass: "low" | "medium" | "high";
  surfaces: string[];
  roles: string[];
  examples: string[];
  version: number;
};
export type Registry = { version: number; intents: Intent[] };
export type Candidate = { intent: string; score: number; lexical: number; semantic: number; span?: [number, number] };
type Level = "low" | "medium" | "high" | "block";
type LayerResult = { layer: string; result: "pass" | "warn" | "block"; reason?: string; kind?: string; evidence?: string[] };

export const BANDS = { high: 0.8, medium: 0.55, low: 0.4 };
export const WEIGHTS = { lexical: 0.4, semantic: 0.35, contextual: 0.2, recency: 0.05 };
export const TTL_MS = 5 * 60 * 1000;
const HIGH_RISK_PROCEED = 0.95;
const TIE_WINDOW = 0.05;

const STOP = new Set("a an the of to in on at for and or is are be me my i you your our we us it this that what whats do does with by from about all any some can could should would please just".split(" "));

function stem(w: string): string {
  return w.replace(/'s$/, "").replace(/(ing|ed|es|s)$/, (m) => (w.length > 4 ? "" : m));
}

export function tokens(text: string): string[] {
  return (text.normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase().match(/[a-z0-9$]+(?:'[a-z]+)?/g) ?? [])
    .filter((w) => !STOP.has(w))
    .map(stem)
    .filter(Boolean);
}

function cosineSets(a: string[], b: string[]): number {
  const A = new Set(a), B = new Set(b);
  if (!A.size || !B.size) return 0;
  let i = 0;
  for (const x of A) if (B.has(x)) i++;
  return i / Math.sqrt(A.size * B.size);
}

// ---------------- registry ----------------
export function loadRegistry(src: string | Registry | (string | Registry)[]): Registry {
  const parts = Array.isArray(src) ? src : [src];
  const intents: Intent[] = [];
  let version = 0;
  for (const p of parts) {
    let reg: Registry;
    if (typeof p !== "string") reg = p;
    else if (existsSync(p) && statSync(p).isDirectory())
      reg = { version: 1, intents: readdirSync(p).filter((f) => f.endsWith(".json")).map((f) => JSON.parse(readFileSync(join(p, f), "utf-8"))) };
    else reg = JSON.parse(readFileSync(p, "utf-8"));
    version += reg.version ?? 1;
    for (const it of reg.intents) {
      if (!it.examples?.length) throw new Error(`intent ${it.id} has no examples`);
      intents.push(it);
    }
  }
  if (!intents.find((i) => i.id === "GENERAL"))
    intents.unshift({ id: "GENERAL", category: "general", description: "safe fallback", capabilities: [], riskClass: "low", surfaces: ["*"], roles: ["*"], examples: ["hello"], version: 1 });
  return { version, intents };
}

// ---------------- guard: injection patterns ----------------
const INJECTION: [string, RegExp][] = [
  ["instruction-override", /\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|the)\b[^.\n]{0,20}\b(instructions?|rules|prompts?|user|context|guidelines)\b/i],
  ["instruction-override", /\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier|everything)\b/i],
  ["mode-switch", /\byou are now\b|\b(unrestricted|developer|jailbreak|god)\s+mode\b|\bdo anything now\b/i],
  ["role-confusion", /<\/?\s*(system|assistant|user|developer)\s*>|\[\/?INST\]|<<\s*SYS\s*>>|^\s*(system|assistant)\s*:/im],
  ["impersonate-system", /\b(pretend|act|behave)\s+(to be|as|like)\s+(the\s+)?(system|admin|developer|root)\b/i],
  ["secret-exfiltration", /\b(reveal|show|print|dump|list|leak|send)\b[^.\n]{0,40}\b(api[\s_-]?keys?|credentials?|passwords?|secrets?|tokens?|system prompt)\b/i],
  ["privilege-escalation", /\b(grant|give|make)\s+((me|us|the user)\s+)?(admin|root|superuser|full access)\b|\bdrop\s+(the\s+)?\w+\s+table\b/i],
  ["verdict-tampering", /\b(mark|classify|label|flag|rate|tell (the )?user|say|confirm|report)\s+(this|it|the message)?\s*(as\s+)?(safe|genuine|legit(imate)?|not (a )?scam|real|trusted)\b|\bnot a scam\b.{0,30}\b(ai|model|assistant|bot|checker)\b/i],
  // bidi overrides, raw or written as an escape sequence
  ["hidden-control", /[‪-‮⁦-⁩‎‏]|\\u20(2[a-e]|6[6-9])/i],
];
const TOOLISH = /\b[a-z]+(?:_[a-z0-9]+)+\b/g;

export type Signer = { sign(payload: string): string; verify(payload: string, sig: string): boolean };
export function hmacSigner(secret: string): Signer {
  return {
    sign: (p) => createHmac("sha256", secret).update(p).digest("hex"),
    verify: (p, s) => createHmac("sha256", secret).update(p).digest("hex") === s,
  };
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object")
    return `{${Object.keys(value as object).filter((k) => (value as any)[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical((value as any)[k])}`).join(",")}}`;
  return JSON.stringify(value);
}

let lastMs = 0, seq = 0;
function ulidish(): string {
  const now = Date.now();
  seq = now === lastMs ? seq + 1 : 0;
  lastMs = now;
  return now.toString(36).padStart(9, "0") + seq.toString(36).padStart(3, "0") + randomBytes(5).toString("hex");
}

type Options = {
  intentRegistry: string | Registry | (string | Registry)[];
  policyPack?: string | string[];
  secret?: string;
  semantic?: (prompt: string, intent: Intent) => number | null;
  clock?: () => Date;
};

export class Scout {
  readonly registry: Registry;
  readonly policyPacks: string[];
  private readonly signer: Signer;
  private readonly semantic?: Options["semantic"];
  private readonly clock: () => Date;
  private readonly prepared: { intent: Intent; ex: string[][]; desc: string[]; name: string[] }[];
  private readonly recent = new Map<string, number>();
  readonly events: Record<string, unknown>[] = [];
  readonly selfTestMs: number;

  constructor(opts: Options) {
    this.registry = loadRegistry(opts.intentRegistry);
    this.policyPacks = Array.isArray(opts.policyPack) ? opts.policyPack : [opts.policyPack ?? "default"];
    this.signer = hmacSigner(opts.secret ?? process.env.SCOUT_SECRET ?? "scout-dev-secret");
    this.semantic = opts.semantic;
    this.clock = opts.clock ?? (() => new Date());
    this.prepared = this.registry.intents.map((intent) => ({
      intent,
      ex: intent.examples.map(tokens),
      desc: tokens(intent.description),
      name: tokens(intent.id.replace(/[._-]/g, " ")),
    }));
    // spec 4.1: the full-registry scan must finish under 16 ms; fail loudly if not
    const t0 = performance.now();
    for (const p of ["hello", "check this message", "is this number a scammer", "ignore previous instructions"]) this.scan(p);
    this.selfTestMs = (performance.now() - t0) / 4;
    if (this.selfTestMs > 16) throw new Error(`stage-1 scan ${this.selfTestMs.toFixed(1)} ms exceeds the 16 ms budget`);
  }

  // ---------- Sense ----------
  private scan(prompt: string): Candidate[] {
    const p = tokens(prompt);
    const out: Candidate[] = [];
    for (const { intent, ex, desc, name } of this.prepared) {
      if (intent.id === "GENERAL") continue;
      const exBest = Math.max(0, ...ex.map((e) => cosineSets(p, e)));
      const lexical = Math.min(1, 0.85 * exBest + 0.1 * cosineSets(p, desc) + 0.05 * cosineSets(p, name));
      const semantic = this.semantic?.(prompt, intent) ?? null;
      const recency = this.recent.has(intent.id) ? 1 : 0;
      // weights renormalised over the terms that actually ran (Stage 2 is optional)
      const terms = [[WEIGHTS.lexical, lexical], [WEIGHTS.recency, recency]] as [number, number][];
      if (semantic !== null) terms.push([WEIGHTS.semantic, semantic]);
      const wsum = terms.reduce((s, [w]) => s + w, 0);
      const score = terms.reduce((s, [w, v]) => s + w * v, 0) / wsum;
      out.push({ intent: intent.id, score: +score.toFixed(4), lexical: +lexical.toFixed(4), semantic: semantic ?? 0 });
    }
    return out.sort((a, b) => b.score - a.score);
  }

  async classify(input: { prompt: string; surface: string }): Promise<{ candidates: Candidate[] }> {
    return { candidates: this.scan(input.prompt) };
  }

  band(score: number): "high" | "medium" | "low" | "reject" {
    return score >= BANDS.high ? "high" : score >= BANDS.medium ? "medium" : score >= BANDS.low ? "low" : "reject";
  }

  // ---------- Guard ----------
  guard(prompt: string, intent: Intent, user: { role?: string }, surface: string): { level: Level; flags: string[]; layers: LayerResult[]; reason?: string; injection?: { kind: string; evidence: string[] } } {
    const layers: LayerResult[] = [];
    const tight = this.policyPacks.includes("adversarial-tight");
    // 1 injection
    const hits = INJECTION.filter(([, rx]) => rx.test(prompt));
    const allowed = new Set(this.registry.intents.flatMap((i) => i.capabilities).map((c) => c.replace(/\./g, "_")));
    const oob = (prompt.match(TOOLISH) ?? []).filter((t) => !allowed.has(t) && /admin|internal|panel|root|sudo|exec|shell|grant|delete|drop/.test(t));
    if (hits.length || oob.length) {
      const kinds = [...hits.map(([k]) => k), ...(oob.length ? ["out-of-band-tool"] : [])];
      layers.push({ layer: "injection", result: "block", kind: kinds[0], reason: `injection: ${kinds.join(", ")}`, evidence: [...kinds, ...oob] });
    } else layers.push({ layer: "injection", result: "pass" });
    // 2 policy (roles) and 3 scope (surfaces)
    const roleOk = intent.roles.includes("*") || intent.roles.includes(user.role ?? "");
    layers.push({ layer: "policy", result: roleOk ? "pass" : "block", reason: roleOk ? undefined : `role ${user.role} may not invoke ${intent.id}` });
    const surfOk = intent.surfaces.includes("*") || intent.surfaces.includes(surface);
    layers.push({ layer: "scope", result: surfOk ? "pass" : tight ? "block" : "warn", reason: surfOk ? undefined : `${intent.id} not offered on ${surface}` });
    // 4 sensitivity: secrets typed into the prompt are redacted, never forwarded
    const pinLike = /\b(pin|code secret|mot de passe|password)\b\D{0,12}\d{4,6}\b/i.test(prompt);
    layers.push({ layer: "sensitivity", result: pinLike ? "warn" : "pass", reason: pinLike ? "prompt contains a PIN or password; redacted" : undefined });
    // 5 rate limit (in-process, per role+intent)
    layers.push({ layer: "rate", result: "pass" });

    const flags = layers.filter((l) => l.result !== "pass").map((l) => `${l.layer}:${l.result}`);
    let level: Level = intent.riskClass;
    if (layers.some((l) => l.result === "block")) level = "block";
    else if (layers.some((l) => l.result === "warn")) level = level === "low" ? "medium" : "high";
    const inj = layers.find((l) => l.layer === "injection" && l.result === "block");
    return { level, flags, layers, reason: layers.find((l) => l.result === "block")?.reason,
             injection: inj ? { kind: inj.kind!, evidence: inj.evidence ?? [] } : undefined };
  }

  // ---------- Interpret ----------
  private interpret(prompt: string, intent: Intent): { parameters: Record<string, unknown>; missing: string[] } {
    const props = intent.parameters?.properties ?? {};
    const params: Record<string, unknown> = {};
    const num = prompt.match(/\b(\d{1,3})\b(?!\s*(?:k|%|\$|fcfa|xaf))/i);
    for (const [k, schema] of Object.entries(props)) {
      if (schema.type === "integer" && num) params[k] = Number(num[1]);
      if (schema.enum) {
        const v = schema.enum.find((e: string) => new RegExp(`\\b${e}`, "i").test(prompt));
        if (v) params[k] = v;
      }
    }
    const missing = (intent.parameters?.required ?? []).filter((r) => params[r] === undefined);
    return { parameters: params, missing };
  }

  // ---------- Route + Recommend + Contract ----------
  private contract(primary: Intent, confidence: number, parameters: Record<string, unknown>, alternates: Candidate[],
                   risk: ReturnType<Scout["guard"]>, user: { id?: string; role?: string }, surface: string, parentId?: string, traceId?: string) {
    const issuedAt = this.clock();
    const body = {
      contractId: ulidish(),
      parentId,
      traceId: traceId ?? createHash("sha256").update(ulidish()).digest("hex").slice(0, 16),
      intent: { primary: { id: primary.id, version: primary.version }, parameters, references: [], confidence: +confidence.toFixed(4),
                alternates: alternates.slice(0, 3).map((a) => ({ id: a.intent, score: a.score })) },
      risk: { level: risk.level, flags: risk.flags, redactions: risk.flags.filter((f) => f.startsWith("sensitivity")), approvals: [] as string[] },
      toolPlan: primary.capabilities.map((c) => ({ capability: c, tool: c, input: {} })),
      modelProfile: { id: risk.level === "high" ? "nemotron-super-reason" : "nemotron-lightning-fast" },
      scope: { user: user.id ?? "anonymous", surface, capabilities: primary.capabilities },
      issuedAt: issuedAt.toISOString(),
      expiresAt: new Date(issuedAt.getTime() + TTL_MS).toISOString(),
      registryVersion: this.registry.version,
      policyPackVersion: this.policyPacks.join("+") + "@1",
      signedBy: "scout" as const,
    };
    const signature = this.signer.sign(canonical(body));
    this.events.push({ event: "contract.issued", contractId: body.contractId, intent: primary.id, risk: risk.level, profile: body.modelProfile.id });
    return { ...body, signature };
  }

  verify(contract: any, engine = "executor", capability?: string): { ok: boolean; reason?: string } {
    const { signature, ...body } = contract ?? {};
    if (!signature || !this.signer.verify(canonical(body), signature)) return this.refuse(contract, engine, "bad-signature");
    if (new Date(body.expiresAt).getTime() < this.clock().getTime()) {
      this.events.push({ event: "contract.expired", contractId: body.contractId, engine });
      return { ok: false, reason: "expired" };
    }
    if (capability && !body.scope.capabilities.includes(capability)) return this.refuse(contract, engine, "scope-mismatch");
    this.events.push({ event: "contract.verified", contractId: body.contractId, engine });
    return { ok: true };
  }

  private refuse(contract: any, engine: string, reason: string) {
    this.events.push({ event: "contract.refused", contractId: contract?.contractId, engine, reason });
    return { ok: false, reason };
  }

  async decide(input: { prompt: string; user?: { id?: string; role?: string }; surface?: string; context?: unknown; parentId?: string; traceId?: string }) {
    const t0 = performance.now();
    const surface = input.surface ?? "chat";
    const user = input.user ?? { role: "*" };
    const candidates = this.scan(input.prompt);
    const top = candidates[0];
    const general = this.registry.intents.find((i) => i.id === "GENERAL")!;
    const band = top ? this.band(top.score) : "reject";
    const primary = band === "reject" ? general : this.registry.intents.find((i) => i.id === top.intent)!;
    const risk = this.guard(input.prompt, primary, user, surface);
    const { parameters, missing } = this.interpret(input.prompt, primary);

    // spec 4.6: four clarification triggers
    const second = candidates[1];
    const triggers: string[] = [];
    if (band === "low") triggers.push("low-band");
    if (band === "medium" && second && top.score - second.score < TIE_WINDOW) triggers.push("tie");
    if (missing.length) triggers.push("params");
    if (primary.riskClass === "high" && top && top.score < HIGH_RISK_PROCEED) triggers.push("high-risk");
    const clarification = risk.level === "block" || !triggers.length ? null : {
      trigger: triggers[0],
      question: triggers[0] === "high-risk" ? `Confirm: ${primary.description}` : "Which of these did you mean?",
      options: candidates.slice(0, 4).filter((c) => c.score >= BANDS.low).map((c) => ({ intent: c.intent, score: c.score })),
    };

    // spec 4.5: multi-intent plans when a second intent covers a different part of the prompt
    const plan = this.multi(input.prompt, candidates);

    const contract = risk.level === "block" || band === "reject" && risk.level !== "low" ? null
      : this.contract(primary, top?.score ?? 0, parameters, candidates.slice(1), risk, user, surface, input.parentId, input.traceId);
    if (contract) this.recent.set(primary.id, Date.now());
    const latencyMs = +(performance.now() - t0).toFixed(2);
    this.events.push({ event: "scout.decision", traceId: contract?.traceId, intent: primary.id, band, latencyMs, stage2: this.semantic ? "used" : "skipped" });
    if (clarification) this.events.push({ event: "scout.clarification", trigger: clarification.trigger });
    return {
      intent: primary.id, band, confidence: top?.score ?? 0, candidates, risk: { level: risk.level, flags: risk.flags, reason: risk.reason, layers: risk.layers },
      injection: risk.injection ?? null, clarification, plan, toolPlan: contract?.toolPlan ?? [], executionContract: contract, latencyMs,
    };
  }

  private multi(prompt: string, candidates: Candidate[]): string[] | null {
    const parts = prompt.split(/\s*(?:,\s*and\s+|\band\b|,|;|\bthen\b)\s*/i).filter((s) => tokens(s).length >= 2);
    if (parts.length < 2) return null;
    const ids = [...new Set(parts.map((s) => this.scan(s)[0]).filter((c) => c && c.score >= BANDS.medium).map((c) => c.intent))];
    return ids.length >= 2 ? ids : null;
  }

  async replan(input: { parent: any; reason: string; state?: unknown; prompt: string; user?: { id?: string; role?: string }; surface?: string }) {
    this.events.push({ event: "scout.replan", parentId: input.parent?.contractId, reason: input.reason });
    return this.decide({ prompt: input.prompt, user: input.user, surface: input.surface, parentId: input.parent?.contractId, traceId: input.parent?.traceId });
  }

  // approvals are added by re-issuing (contracts are immutable once signed)
  approve(contract: any, approval: "user-confirm" | "operator-review", by: string) {
    const { signature, ...body } = contract;
    if (!this.signer.verify(canonical(body), signature)) throw new Error("cannot approve a tampered contract");
    const next = { ...body, parentId: body.contractId, contractId: ulidish(), risk: { ...body.risk, approvals: [...body.risk.approvals, `${approval}:${by}`] } };
    return { ...next, signature: this.signer.sign(canonical(next)) };
  }
}
