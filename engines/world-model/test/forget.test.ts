import { test } from "node:test";
import assert from "node:assert/strict";
import { WorldModel } from "../src/index.js";

const obs = (id: string, at: string, kind: string, entities: { type: string; name: string }[]) => ({
  externalId: id, text: `text of ${id}`, at, kind: "scam", entities, source: { kind, at },
});

test("forget removes old check observations, their links and unreferenced entities, and nothing else", async () => {
  const w = new WorldModel();
  await w.ingest([
    obs("C-old1", "2025-01-10T00:00:00Z", "checkam-check", [{ type: "number", name: "655-aaaaaa" }, { type: "link", name: "bad.example" }]),
    obs("C-new1", "2026-11-01T00:00:00Z", "checkam-check", [{ type: "number", name: "655-aaaaaa" }]),
    obs("R-data1", "2025-01-05T00:00:00Z", "stop-arnaque-237", [{ type: "number", name: "677-bbbbbb" }]),
  ]);
  const before = w.stats();
  const r = w.forget("checkam-check", { before: "2026-01-01T00:00:00Z" });
  assert.equal(r.observations, 1);
  assert.ok(r.edges >= 2);
  assert.equal(r.entities, 1, "the link only the old check mentioned is gone; the number a newer check still mentions stays");
  const after = w.stats();
  assert.equal(after.observations, before.observations - 1);
  assert.ok(w.entity("observation:checkam-check:C-new1"));
  assert.ok(w.entity("observation:stop-arnaque-237:R-data1"), "the open dataset is never touched");
  assert.equal(w.entity("observation:checkam-check:C-old1"), undefined);
  assert.ok(w.audit().some((a) => a.op === "forget"));
  assert.ok(!JSON.stringify(w.audit()).includes("text of"), "the audit never holds message text");
});

test("forget by id removes exactly that check", async () => {
  const w = new WorldModel();
  await w.ingest([
    obs("C-a", "2026-11-01T00:00:00Z", "checkam-check", [{ type: "number", name: "650-cccccc" }]),
    obs("C-b", "2026-11-02T00:00:00Z", "checkam-check", [{ type: "number", name: "650-cccccc" }]),
  ]);
  const r = w.forget("checkam-check", { ids: ["C-a"] });
  assert.equal(r.observations, 1);
  assert.ok(w.entity("observation:checkam-check:C-b"));
  assert.equal(w.entity("observation:checkam-check:C-a"), undefined);
});

test("forgetting nothing is harmless", async () => {
  const w = new WorldModel();
  const r = w.forget("checkam-check", { before: "2000-01-01T00:00:00Z" });
  assert.deepEqual(r, { observations: 0, edges: 0, entities: 0 });
});
