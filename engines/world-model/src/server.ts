// HTTP surface for the campaign graph. The Python agents call this; nothing else writes the world.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { WorldModel, campaigns, contextFor, type Observation, type Campaign } from "./index.js";

const PORT = Number(process.env.WORLD_MODEL_PORT ?? 8790);
const FILE = process.env.WORLD_MODEL_FILE ?? "data/world.json";
const world = new WorldModel({ storage: "file", path: FILE, namespace: "checkam" });

// official operator domains are the impersonated party, never a scammer signature
const OFFICIAL = /(^|\.)(mtn\.cm|orange\.cm|camtel\.cm|mtnonline\.com|orangemoney\.cm)$/i;

let cache: Campaign[] | null = null;
const all = () => (cache ??= campaigns(world));

async function body(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf-8")) : {};
}

function send(res: ServerResponse, code: number, data: unknown): void {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(data));
}

function clean(list: Observation[]): Observation[] {
  return list.map((o) => ({ ...o, entities: o.entities.filter((e) => !(e.type === "link" && OFFICIAL.test(e.name))) }));
}

const obsId = (kind: string, id: string) => `observation:${kind}:${id}`;

createServer(async (req, res) => {
  const t0 = Date.now();
  try {
    const url = new URL(req.url ?? "/", "http://x");
    if (req.method === "GET" && url.pathname === "/health") return send(res, 200, { ok: true, ...world.stats() });
    if (req.method === "POST" && url.pathname === "/ingest") {
      const { observations } = await body(req);
      const r = await world.ingest(clean(observations ?? []));
      if (r.changed) cache = null;
      return send(res, 200, { ...r, ms: Date.now() - t0 });
    }
    if (req.method === "GET" && url.pathname === "/campaigns") return send(res, 200, { campaigns: all(), ms: Date.now() - t0 });
    if (req.method === "GET" && url.pathname === "/context") {
      const id = obsId(url.searchParams.get("source") ?? "stop-arnaque-237", url.searchParams.get("id") ?? "");
      if (!world.entity(id)) return send(res, 404, { error: `unknown observation ${id}` });
      return send(res, 200, { ...contextFor(world, id, all()), ms: Date.now() - t0 });
    }
    if (req.method === "GET" && url.pathname === "/observation") {
      const id = obsId(url.searchParams.get("source") ?? "stop-arnaque-237", url.searchParams.get("id") ?? "");
      const e = world.entity(id);
      if (!e) return send(res, 404, { error: `unknown observation ${id}` });
      const { embedding, ...attrs } = e.attrs as any;
      return send(res, 200, { ...e, attrs });
    }
    if (req.method === "GET" && url.pathname === "/audit") return send(res, 200, { audit: world.audit().slice(-Number(url.searchParams.get("n") ?? 50)) });
    send(res, 404, { error: "not found" });
  } catch (err) {
    send(res, 400, { error: (err as Error).message });
  }
}).listen(PORT, "0.0.0.0", () => console.log(`world-model on :${PORT}, file ${FILE}`));

for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => { world.flush(); process.exit(0); });
