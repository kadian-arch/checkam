// Campaign clustering over the world model (spec section 4.3, stream-cluster aggregate).
// Coarse bucket: observations that share a signature entity (phone number code, link)
// belong together. Refine: wording similarity (embedding cosine, or shingle Jaccard when
// there are no embeddings). Union-find collapses the buckets into campaigns.

import { createHash } from "node:crypto";
import { decide, type Entity, type WorldModel } from "./index.js";

export const SIGNATURE_TYPES = ["number", "link"];
export const SHINGLE_JACCARD = 0.5;

export type Link = { a: string; b: string; why: string; score: number; band: "auto-merge" | "review" };

export type Campaign = {
  id: string;
  members: string[];
  links: Link[];
  review: Link[];
  numbers: string[];
  links_: string[];
  brands: string[];
  scamTypes: string[];
  firstSeenAt: string;
  lastSeenAt: string;
  kinds: Record<string, number>;
};

const sha = (s: string) => createHash("sha256").update(s).digest("hex");

function cosine(a: number[], b: number[]): number {
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  return na && nb ? dot / Math.sqrt(na * nb) : 0;
}

export function shingles(text: string, k = 5): Set<string> {
  const t = text
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/\[[a-z_]+(:[^\]]*)?\]/g, " ")
    .replace(/\d+/g, "#")
    .replace(/[^a-z#]+/g, " ")
    .trim();
  const out = new Set<string>();
  for (let i = 0; i + k <= t.length; i++) out.add(t.slice(i, i + k));
  return out;
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (!a.size || !b.size) return 0;
  let inter = 0;
  for (const x of a) if (b.has(x)) inter++;
  return inter / (a.size + b.size - inter);
}

class UnionFind {
  private p = new Map<string, string>();
  find(x: string): string {
    if (!this.p.has(x)) this.p.set(x, x);
    let r = x;
    while (this.p.get(r) !== r) r = this.p.get(r)!;
    this.p.set(x, r);
    return r;
  }
  union(a: string, b: string): void {
    const ra = this.find(a), rb = this.find(b);
    if (ra !== rb) this.p.set(ra < rb ? rb : ra, ra < rb ? ra : rb);
  }
}

function textOf(o: Entity): string {
  const a = o.attrs as Record<string, any>;
  return [a.text, a.example].filter(Boolean).join(" ");
}

export function campaigns(world: WorldModel, opts: { minWords?: number } = {}): Campaign[] {
  const minWords = opts.minWords ?? 8;
  const graph = world.view("graph");
  const obs = world.entities("observation").filter((o) => (o.attrs as any).kind !== "genuine");
  const uf = new UnionFind();
  const links: Link[] = [];
  const review: Link[] = [];

  // coarse bucket: shared signature entities
  for (const sig of world.entities().filter((e) => SIGNATURE_TYPES.includes(e.type))) {
    const members = graph.neighborsOf(sig.id, { via: "mentions", direction: "in" }).filter((m) => m.type === "observation" && (m.attrs as any).kind !== "genuine");
    for (let i = 1; i < members.length; i++) {
      uf.union(members[0].id, members[i].id);
      links.push({ a: members[0].id, b: members[i].id, why: `same ${sig.type} ${sig.name}`, score: 1, band: "auto-merge" });
    }
  }

  // refine: wording similarity
  const sh = new Map(obs.map((o) => [o.id, shingles(textOf(o))]));
  const words = (o: Entity) => textOf(o).split(/\s+/).filter(Boolean).length;
  for (let i = 0; i < obs.length; i++) {
    for (let j = i + 1; j < obs.length; j++) {
      const a = obs[i], b = obs[j];
      if (words(a) < minWords || words(b) < minWords) continue;
      const ea = (a.attrs as any).embedding as number[] | undefined;
      const eb = (b.attrs as any).embedding as number[] | undefined;
      // spec 4.3: co-cluster when overlap Jaccard >= 0.5 OR embedding cosine >= 0.85 (0.82 goes to review)
      const lex = jaccard(sh.get(a.id)!, sh.get(b.id)!);
      const cos = ea && eb && ea.length === eb.length ? cosine(ea, eb) : 0;
      let score: number, band: ReturnType<typeof decide>, why: string;
      if (lex >= SHINGLE_JACCARD) {
        score = lex;
        band = "auto-merge";
        why = `wording overlap ${lex.toFixed(3)}`;
      } else {
        score = cos;
        band = decide(cos);
        why = `meaning similarity ${cos.toFixed(3)} (Nemotron embeddings)`;
      }
      if (band === "auto-merge") {
        uf.union(a.id, b.id);
        links.push({ a: a.id, b: b.id, why, score, band });
      } else if (band === "review") {
        review.push({ a: a.id, b: b.id, why, score, band });
      }
    }
  }

  const groups = new Map<string, string[]>();
  for (const o of obs) {
    const r = uf.find(o.id);
    groups.set(r, [...(groups.get(r) ?? []), o.id]);
  }

  const out: Campaign[] = [];
  for (const members of groups.values()) {
    if (members.length < 2) continue;
    members.sort();
    const set = new Set(members);
    const mentioned = members.flatMap((m) => graph.neighborsOf(m, { via: "mentions" }));
    const names = (t: string) => [...new Set(mentioned.filter((e) => e.type === t).map((e) => e.name ?? e.id))].sort();
    const ents = members.map((m) => world.entity(m)!);
    const ats = ents.map((e) => String((e.attrs as any).at ?? e.firstSeenAt)).sort();
    const kinds: Record<string, number> = {};
    for (const e of ents) {
      const k = String((e.attrs as any).kind ?? "other");
      kinds[k] = (kinds[k] ?? 0) + 1;
    }
    out.push({
      id: `cmp_${sha(members[0]).slice(0, 12)}`,
      members,
      links: links.filter((l) => set.has(l.a) && set.has(l.b)),
      review: review.filter((l) => set.has(l.a) || set.has(l.b)),
      numbers: names("number"),
      links_: names("link"),
      brands: names("brand"),
      scamTypes: names("scam_type"),
      firstSeenAt: ats[0],
      lastSeenAt: ats[ats.length - 1],
      kinds,
    });
  }
  return out.sort((a, b) => b.members.length - a.members.length || a.id.localeCompare(b.id));
}

// Context builder (spec section 8.2): what the world knows that is relevant to one observation.
export function contextFor(world: WorldModel, observationId: string, all?: Campaign[]) {
  const camp = (all ?? campaigns(world)).find((c) => c.members.includes(observationId));
  const graph = world.view("graph");
  const mentioned = graph.neighborsOf(observationId, { via: "mentions" });
  const alsoSeen = mentioned
    .filter((e) => SIGNATURE_TYPES.includes(e.type))
    .map((e) => ({
      entity: { type: e.type, name: e.name },
      seenIn: graph.neighborsOf(e.id, { via: "mentions", direction: "in" }).filter((o) => o.id !== observationId).map((o) => o.id),
    }));
  return { observationId, campaign: camp ?? null, mentioned: mentioned.map((e) => ({ type: e.type, name: e.name })), alsoSeen };
}
