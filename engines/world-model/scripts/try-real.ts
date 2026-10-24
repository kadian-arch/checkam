// Ingest the public Stop Arnaque 237 reports and alerts and print the campaigns found.
import { readFileSync } from "node:fs";
import { WorldModel, campaigns, type Observation } from "../src/index.js";

const dir = process.argv[2] ?? "D:/StopArnaque237/data/details";
const rows = (f: string) => readFileSync(`${dir}/${f}`, "utf-8").trim().split("\n").map((l) => JSON.parse(l));
const arr = (v: unknown): string[] => (Array.isArray(v) ? v.filter(Boolean).map(String) : v ? [String(v)] : []);

const obs: Observation[] = [];
for (const r of rows("reports.jsonl")) {
  const ents = [
    ...arr(r.phone_ids).concat(arr(r.sender_phone_id)).map((n) => ({ type: "number", name: n })),
    ...arr(r.domains).map((d) => ({ type: "link", name: d })),
    ...arr(r.scam_types).map((t) => ({ type: "scam_type", name: t })),
  ];
  obs.push({
    externalId: r.id, kind: "report", at: "2026-10-01T00:00:00.000Z",
    text: [r.message_text, r.call_description].filter(Boolean).join(" "),
    source: { kind: "stop-arnaque-237", at: "2026-10-10T00:00:00.000Z" }, entities: ents,
  });
}
for (const a of rows("public_alerts.jsonl")) {
  const ents = [
    ...arr(a.phone_ids).map((n) => ({ type: "number", name: n })),
    ...arr(a.domains).map((d) => ({ type: "link", name: d })),
    ...arr(a.scam_types).map((t) => ({ type: "scam_type", name: t })),
    ...arr(a.impersonated).map((b) => ({ type: "brand", name: b })),
  ];
  obs.push({
    externalId: a.id, kind: "alert", at: a.date_published ? `${a.date_published}T00:00:00.000Z` : "2026-01-01T00:00:00.000Z",
    title: a.title, text: a.example_message ?? "",
    source: { kind: "stop-arnaque-237", at: "2026-10-10T00:00:00.000Z" }, entities: ents,
  });
}

const world = new WorldModel({ storage: "memory", namespace: "try" });
const t0 = Date.now();
console.log("ingest", await world.ingest(obs), "again", await world.ingest(obs), `${Date.now() - t0} ms`);
const c = campaigns(world);
console.log("stats", world.stats());
console.log("campaigns", c.length);
for (const k of c) {
  const ids = k.members.map((m) => m.split(":").pop());
  console.log(`- ${k.id} n=${k.members.length} [${ids.join(" ")}]`);
  for (const l of k.links.slice(0, 4)) console.log(`     ${l.a.split(":").pop()} ~ ${l.b.split(":").pop()} : ${l.why}`);
}
