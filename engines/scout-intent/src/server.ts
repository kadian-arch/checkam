// HTTP surface for Scout. The API asks for decisions and has contracts verified here.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Scout } from "./index.js";

const here = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.SCOUT_PORT ?? 8791);
const scout = new Scout({
  intentRegistry: process.env.SCOUT_REGISTRY ?? join(here, "..", "registry", "checkam.json"),
  policyPack: ["default", "adversarial-tight"],
  secret: process.env.SCOUT_SECRET ?? process.env.CHECKAM_SECRET,
});

async function body(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf-8")) : {};
}
const send = (res: ServerResponse, code: number, data: unknown) => {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(data));
};

createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", "http://x");
    if (req.method === "GET" && url.pathname === "/health")
      return send(res, 200, { ok: true, intents: scout.registry.intents.length, registryVersion: scout.registry.version, stage1ScanMs: +scout.selfTestMs.toFixed(3) });
    if (req.method === "POST" && url.pathname === "/decide") return send(res, 200, await scout.decide(await body(req)));
    if (req.method === "POST" && url.pathname === "/verify") {
      const b = await body(req);
      return send(res, 200, scout.verify(b.contract, b.engine ?? "checkam-api", b.capability));
    }
    if (req.method === "POST" && url.pathname === "/approve") {
      const b = await body(req);
      return send(res, 200, { contract: scout.approve(b.contract, b.approval ?? "operator-review", b.by ?? "analyst") });
    }
    if (req.method === "GET" && url.pathname === "/events") return send(res, 200, { events: scout.events.slice(-100) });
    send(res, 404, { error: "not found" });
  } catch (err) {
    send(res, 400, { error: (err as Error).message });
  }
}).listen(PORT, "0.0.0.0", () => console.log(`scout on :${PORT}, ${scout.registry.intents.length} intents, stage-1 ${scout.selfTestMs.toFixed(2)} ms`));
