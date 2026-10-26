// HTTP surface for CheckAm's memory. What analysts correct and confirm is remembered here, so a later
// check of a similar message starts from what people already learned. Only the API writes; only
// analyst-approved knowledge goes in (a citizen's "this looks wrong" waits for an analyst first).
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import fs from "node:fs";
import { HMEM, type FeedbackKind } from "../reference/index.ts";

const PORT = Number(process.env.HMEM_PORT ?? 8792);
const DIR = process.env.HMEM_DIR ?? "data/hmem";
fs.mkdirSync(DIR, { recursive: true });
const mem = new HMEM({ persistDir: DIR, actor: "checkam" });
const DAY = 24 * 3600 * 1000;

async function body(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > 64 * 1024) throw new Error("body too large");
    chunks.push(c as Buffer);
  }
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf-8")) : {};
}

function send(res: ServerResponse, code: number, data: unknown): void {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(data));
}

const KINDS = new Set(["correction", "finding", "alert"]);
const VERDICTS = new Set(["scam", "suspicious", "looks_genuine"]);

// what one memory says, in the shape the agents read
function view(m: any, relevance?: number) {
  const tag = (p: string) => (m.tags as string[]).find((t) => t.startsWith(p))?.slice(p.length);
  return { id: m.id, content: m.content, verdict: tag("verdict:"), kind: tag("kind:"), layer: m.layer, confidence: m.confidence,
           source: m.source, learned: m.provenance?.learnedAt, refs: m.provenance?.refs ?? [], relevance };
}

function sleepNow() {
  const preview = mem.sleep.preview();
  const report = mem.sleep.execute(preview);
  for (const c of mem.conflicts.scan()) mem.conflicts.autoResolve(c);
  mem.store.persist();
  return { preview, report };
}

createServer(async (req, res) => {
  const t0 = Date.now();
  try {
    const url = new URL(req.url ?? "/", "http://x");
    if (req.method === "GET" && url.pathname === "/health") {
      const all = mem.store.all();
      return send(res, 200, { ok: true, memories: all.length, long_term: all.filter((m) => m.layer === "long_term").length, ledger: mem.ledger.stats() });
    }
    if (req.method === "POST" && url.pathname === "/remember") {
      const b = await body(req);
      const content = String(b.content ?? "").slice(0, 1200);
      if (!content.trim() || !KINDS.has(b.kind) || (b.verdict && !VERDICTS.has(b.verdict)))
        return send(res, 400, { error: "content, kind (correction|finding|alert) and a valid verdict are required" });
      const m = mem.add({
        content, type: "factual", layer: b.kind === "correction" ? "working" : "long_term",
        tags: [`kind:${b.kind}`, ...(b.verdict ? [`verdict:${b.verdict}`] : []), ...((b.tags ?? []) as string[]).slice(0, 6).map(String)],
        confidence: Math.min(1, Math.max(0.5, Number(b.confidence ?? 0.9))),
        source: String(b.source ?? "analyst"),
        provenance: { origin: b.kind === "correction" ? "user_correction" : "manual", learnedAt: Date.now(), label: String(b.label ?? b.kind), refs: ((b.refs ?? []) as string[]).slice(0, 5).map(String) },
      });
      mem.store.persist();
      return send(res, 200, { memory: view(m), ms: Date.now() - t0 });
    }
    if (req.method === "POST" && url.pathname === "/recall") {
      const b = await body(req);
      const q = mem.query(String(b.query ?? "").slice(0, 2000), { topN: Math.min(Number(b.topN ?? 3), 10), threshold: Number(b.threshold ?? 0.35) });
      return send(res, 200, { memories: q.memories.map((r) => view(r.memory, Math.round(r.relevance * 1000) / 1000)), strategy: q.trace.strategy, ms: Date.now() - t0 });
    }
    if (req.method === "POST" && url.pathname === "/feedback") {
      const b = await body(req);
      if (!["helpful", "not_helpful", "wrong"].includes(b.kind) || !mem.store.get(String(b.id))) return send(res, 400, { error: "unknown memory or feedback kind" });
      mem.feedback(String(b.id), b.kind as FeedbackKind);
      mem.store.persist();
      return send(res, 200, { ok: true });
    }
    if (req.method === "POST" && url.pathname === "/sleep") return send(res, 200, { ...sleepNow(), ms: Date.now() - t0 });
    if (req.method === "GET" && url.pathname === "/memories") return send(res, 200, { memories: mem.store.all().slice(-Number(url.searchParams.get("n") ?? 50)).map((m) => view(m)) });
    if (req.method === "GET" && url.pathname === "/ledger") return send(res, 200, { ledger: mem.ledger.all().slice(-Number(url.searchParams.get("n") ?? 50)) });
    send(res, 404, { error: "not found" });
  } catch (err) {
    send(res, 400, { error: (err as Error).message });
  }
}).listen(PORT, "0.0.0.0", () => console.log(`h-mem on :${PORT}, dir ${DIR}`));

// the sleep cycle runs once a day: repeated corrections settle into long-term memory, one-offs fade
setInterval(() => { try { sleepNow(); } catch (e) { console.error("sleep failed", e); } }, DAY).unref();
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => { mem.store.persist(); process.exit(0); });
