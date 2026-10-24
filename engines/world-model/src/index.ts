// CheckAm world model: the campaign graph, built to the Meterless World Model spec
// (engines/world-model/AGENTS.md). Event-sourced, content-derived ids, idempotent
// ingest, bitemporal edges, provenance on every write, append-only audit.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export type Provenance = { kind: string; at: string | Date; by?: string; url?: string; runId?: string };
type StoredProvenance = Omit<Provenance, "at"> & { at: string };

export type Entity = {
  id: string;
  type: string;
  name?: string;
  aliases: string[];
  attrs: Record<string, unknown>;
  source: StoredProvenance;
  firstSeenAt: string;
  lastSeenAt: string;
};

export type Edge = {
  id: string;
  from: string;
  type: string;
  to: string;
  validFrom?: string;
  validTo?: string;
  supersededBy?: string;
  attrs?: Record<string, unknown>;
  source: StoredProvenance;
};

export type Observation = {
  externalId: string;
  title?: string;
  text?: string;
  at: string;
  source: Provenance;
  kind?: string;
  entities: { type: string; name: string }[];
  attrs?: Record<string, unknown>;
  embedding?: number[];
};

export type AuditEntry = { seq: number; op: string; id: string; at: string };

export const SCHEMA_VERSION = 1;
export const AUTO_MERGE = 0.85;
export const REVIEW = 0.82;

export function normalizeName(name: string): string {
  return name
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[  -​  　]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

const sha = (s: string) => createHash("sha256").update(s).digest("hex");

export function entityIdFromName(type: string, name: string): string {
  return `ent_${sha(`${type}:${normalizeName(name)}`).slice(0, 16)}`;
}

export function entityIdFromKey(type: string, system: string, id: string): string {
  return `${type}:${system}:${id}`;
}

// merge banding for similarity scores (spec section 7.1)
export function decide(similarity: number): "auto-merge" | "review" | "new" {
  if (similarity >= AUTO_MERGE) return "auto-merge";
  if (similarity >= REVIEW) return "review";
  return "new";
}

const iso = (d: string | Date) => (d instanceof Date ? d : new Date(d)).toISOString();

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value as object).filter((k) => (value as any)[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${stable((value as any)[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

type Options = { storage?: "memory" | "file"; path?: string; namespace?: string; clock?: () => Date };

type State = {
  schemaVersion: number;
  entities: Record<string, Entity>;
  edges: Record<string, Edge>;
  observations: Record<string, { hash: string; entityId: string }>;
  audit: AuditEntry[];
};

export class WorldModel {
  private s: State;
  private readonly file?: string;
  private readonly clock: () => Date;
  readonly namespace: string;

  constructor(opts: Options = {}) {
    this.namespace = opts.namespace ?? "default";
    this.clock = opts.clock ?? (() => new Date());
    this.file = opts.storage === "file" ? opts.path : undefined;
    this.s = { schemaVersion: SCHEMA_VERSION, entities: {}, edges: {}, observations: {}, audit: [] };
    if (this.file && existsSync(this.file)) {
      const loaded = JSON.parse(readFileSync(this.file, "utf-8")) as State;
      if (loaded.schemaVersion !== SCHEMA_VERSION) throw new Error(`world schema ${loaded.schemaVersion} != ${SCHEMA_VERSION}`);
      this.s = loaded;
    }
  }

  private batching = false;

  private timer: ReturnType<typeof setTimeout> | null = null;

  // spec 3.4: debounce writes (~300 ms) so a burst of upserts is one write
  private persist(): void {
    if (!this.file || this.batching || this.timer) return;
    this.timer = setTimeout(() => this.flush(), 300);
  }

  flush(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    if (!this.file) return;
    mkdirSync(dirname(this.file), { recursive: true });
    writeFileSync(this.file, JSON.stringify(this.s));
  }

  private log(op: string, id: string): void {
    const seq = (this.s.audit.at(-1)?.seq ?? 0) + 1;
    this.s.audit.push({ seq, op, id, at: this.clock().toISOString() });
  }

  private checkSource(source: Provenance | undefined): StoredProvenance {
    if (!source || !source.kind || !source.at) throw new Error("rejected: write without provenance");
    return { ...source, at: iso(source.at) };
  }

  async upsertEntity(input: {
    type: string;
    name?: string;
    externalKey?: { system: string; id: string };
    attrs?: Record<string, unknown>;
    source?: Provenance;
  }): Promise<Entity> {
    const source = this.checkSource(input.source);
    const id = input.externalKey
      ? entityIdFromKey(input.type, input.externalKey.system, input.externalKey.id)
      : input.name
        ? entityIdFromName(input.type, input.name)
        : (() => { throw new Error("rejected: entity needs a name or an external key"); })();
    const prev = this.s.entities[id];
    const next: Entity = prev
      ? {
          ...prev,
          aliases: input.name && !prev.aliases.includes(input.name) ? [...prev.aliases, input.name].sort() : prev.aliases,
          attrs: { ...prev.attrs, ...(input.attrs ?? {}) },
          firstSeenAt: source.at < prev.firstSeenAt ? source.at : prev.firstSeenAt,
          lastSeenAt: source.at > prev.lastSeenAt ? source.at : prev.lastSeenAt,
        }
      : {
          id,
          type: input.type,
          name: input.name,
          aliases: input.name ? [input.name] : [],
          attrs: input.attrs ?? {},
          source,
          firstSeenAt: source.at,
          lastSeenAt: source.at,
        };
    if (!prev || stable(prev) !== stable(next)) {
      this.s.entities[id] = next;
      this.log(prev ? "entity.update" : "entity.create", id);
      this.persist();
    }
    return next;
  }

  // Bitemporal relate. exclusive (default) closes the open edge of the same from+type.
  async relate(input: {
    from: string;
    type: string;
    to: string;
    validFrom?: string;
    attrs?: Record<string, unknown>;
    source?: Provenance;
    exclusive?: boolean;
  }): Promise<Edge> {
    const source = this.checkSource(input.source);
    const validFrom = input.validFrom ? iso(input.validFrom) : source.at;
    const id = `rel_${sha(`${input.from}|${input.type}|${input.to}|${validFrom}`).slice(0, 16)}`;
    if (this.s.edges[id]) return this.s.edges[id];
    if (input.exclusive !== false) {
      for (const e of Object.values(this.s.edges)) {
        if (e.from === input.from && e.type === input.type && !e.validTo && e.to !== input.to) {
          e.validTo = validFrom;
          e.supersededBy = id;
          this.log("edge.close", e.id);
        }
      }
    }
    const edge: Edge = { id, from: input.from, type: input.type, to: input.to, validFrom, attrs: input.attrs, source };
    this.s.edges[id] = edge;
    this.log("edge.create", id);
    this.persist();
    return edge;
  }

  // Idempotent stream ingest: same observation, same hash, no change.
  async ingest(batch: Observation[]): Promise<{ changed: boolean; added: number; updated: number }> {
    let added = 0;
    let updated = 0;
    this.batching = true;
    try {
    for (const o of batch) {
      const hash = sha(stable({ ...o, embedding: undefined }));
      const seen = this.s.observations[o.externalId];
      if (seen && seen.hash === hash) continue;
      const source: Provenance = { ...o.source, at: o.source.at ?? o.at };
      const obs = await this.upsertEntity({
        type: "observation",
        externalKey: { system: o.source.kind, id: o.externalId },
        attrs: { title: o.title, text: o.text, kind: o.kind, at: iso(o.at), ...(o.attrs ?? {}), embedding: o.embedding },
        source,
      });
      const targets = new Set(o.entities.map((ent) => entityIdFromName(ent.type, ent.name)));
      if (seen) {
        // reprocessing: detach edges to entities this observation no longer mentions (step 1, reconcile)
        for (const e of Object.values(this.s.edges)) {
          if (e.from === obs.id && !e.validTo && !targets.has(e.to)) {
            e.validTo = iso(o.at);
            this.log("edge.close", e.id);
          }
        }
      }
      for (const ent of o.entities) {
        const target = await this.upsertEntity({ type: ent.type, name: ent.name, source });
        await this.relate({ from: obs.id, type: "mentions", to: target.id, validFrom: iso(o.at), source, exclusive: false });
      }
      this.s.observations[o.externalId] = { hash, entityId: obs.id };
      if (seen) updated++;
      else added++;
    }
    } finally {
      this.batching = false;
    }
    this.persist();
    return { changed: added + updated > 0, added, updated };
  }

  entity(id: string): Entity | undefined {
    return this.s.entities[id];
  }

  entities(type?: string): Entity[] {
    return Object.values(this.s.entities).filter((e) => !type || e.type === type);
  }

  edges(): Edge[] {
    return Object.values(this.s.edges);
  }

  audit(): AuditEntry[] {
    return [...this.s.audit];
  }

  // Canonical shape: records only, no audit and no wall-clock fields.
  stateShapeCanonical(): string {
    const entities = Object.values(this.s.entities).sort((a, b) => a.id.localeCompare(b.id));
    const edges = Object.values(this.s.edges).sort((a, b) => a.id.localeCompare(b.id));
    return sha(stable({ entities, edges }));
  }

  view(name: "graph") {
    if (name !== "graph") throw new Error(`unknown view ${name}`);
    const live = (e: Edge, at?: string) =>
      at ? (!e.validFrom || e.validFrom <= at) && (!e.validTo || e.validTo > at) : !e.validTo;
    return {
      neighborsOf: (id: string, opts: { via?: string; at?: string; direction?: "out" | "in" | "both" } = {}) => {
        const at = opts.at ? iso(opts.at) : undefined;
        const dir = opts.direction ?? "out";
        const out: Entity[] = [];
        for (const e of Object.values(this.s.edges)) {
          if (opts.via && e.type !== opts.via) continue;
          if (!live(e, at)) continue;
          let other: string | undefined;
          if ((dir === "out" || dir === "both") && e.from === id) other = e.to;
          if ((dir === "in" || dir === "both") && e.to === id) other = e.from;
          const ent = other ? this.s.entities[other] : undefined;
          if (ent && !out.includes(ent)) out.push(ent);
        }
        return out;
      },
    };
  }

  stats() {
    const byType: Record<string, number> = {};
    for (const e of Object.values(this.s.entities)) byType[e.type] = (byType[e.type] ?? 0) + 1;
    return {
      schemaVersion: this.s.schemaVersion,
      entities: byType,
      edges: Object.keys(this.s.edges).length,
      openEdges: Object.values(this.s.edges).filter((e) => !e.validTo).length,
      observations: Object.keys(this.s.observations).length,
      auditLength: this.s.audit.length,
    };
  }
}

export { campaigns, contextFor } from "./campaigns.js";
