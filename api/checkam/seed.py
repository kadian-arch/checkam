"""Zetaris -> Meterless World Model. Reads reports and alerts through the data adapter and ingests
them as observations (idempotent: re-running changes nothing). Embeddings are cached on disk."""
import hashlib
import json

from . import config
from .adapters import nvidia, world
from .adapters.data import data
from .trace import Trace

DB = config.ZETARIS_DB
CACHE = config.DATA_DIR / "embeddings.json"
OFFICIAL_DOMAINS = ("mtn.cm", "orange.cm", "camtel.cm")


def _arr(v) -> list[str]:
    if v is None:
        return []
    return [str(x) for x in v if x] if isinstance(v, list) else [str(v)]


def _vectors(texts: dict[str, str], trace: Trace) -> dict[str, list[float]]:
    cache = json.loads(CACHE.read_text()) if CACHE.exists() else {}
    key = lambda t: hashlib.sha256(f"{config.MODEL_EMBED}|{t}".encode()).hexdigest()[:20]
    todo = {i: t for i, t in texts.items() if t and key(t) not in cache}
    ids = list(todo)
    for start in range(0, len(ids), 48):
        batch = ids[start:start + 48]
        vecs = nvidia.embed([todo[i] for i in batch], trace)
        if not vecs:
            break
        for i, v in zip(batch, vecs):
            cache[key(todo[i])] = [round(x, 5) for x in v]
    if todo:
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(cache))
    return {i: cache[key(t)] for i, t in texts.items() if t and key(t) in cache}


def observations(trace: Trace) -> list[dict]:
    reps = data().sql(f"SELECT id, message_text, call_description, phone_ids, sender_phone_id, domains, scam_types, region, channel FROM {DB}.reports", trace, agent="Seed", why="reports for the campaign graph")
    alr = data().sql(f"SELECT id, title, example_message, phone_ids, domains, scam_types, impersonated, date_published, source FROM {DB}.public_alerts", trace, agent="Seed", why="alerts for the campaign graph")
    out = []
    for r in reps:
        nums = _arr(r["phone_ids"]) + _arr(r["sender_phone_id"])
        out.append({"externalId": r["id"], "kind": "report", "at": "2026-10-10T00:00:00.000Z",
                    "text": " ".join(x for x in (r["message_text"], r["call_description"]) if x),
                    "attrs": {"region": r["region"], "channel": r["channel"]},
                    "source": {"kind": world.SOURCE, "at": "2026-10-10T00:00:00.000Z"},
                    "entities": [{"type": "number", "name": n} for n in sorted(set(nums))] +
                                [{"type": "link", "name": d} for d in _arr(r["domains"]) if not d.endswith(OFFICIAL_DOMAINS)] +
                                [{"type": "scam_type", "name": t} for t in _arr(r["scam_types"])]})
    for a in alr:
        at = f"{a['date_published']}T00:00:00.000Z" if a["date_published"] else "2026-01-01T00:00:00.000Z"
        out.append({"externalId": a["id"], "kind": "alert", "at": at, "title": a["title"], "text": a["example_message"] or "",
                    "attrs": {"outlet": a["source"]},
                    "source": {"kind": world.SOURCE, "at": "2026-10-10T00:00:00.000Z"},
                    "entities": [{"type": "number", "name": n} for n in _arr(a["phone_ids"])] +
                                [{"type": "link", "name": d} for d in _arr(a["domains"]) if not d.endswith(OFFICIAL_DOMAINS)] +
                                [{"type": "scam_type", "name": t} for t in _arr(a["scam_types"])] +
                                [{"type": "brand", "name": b} for b in _arr(a["impersonated"])]})
    vecs = _vectors({o["externalId"]: o["text"] for o in out if len(o["text"].split()) >= 8}, trace)
    for o in out:
        if o["externalId"] in vecs:
            o["embedding"] = vecs[o["externalId"]]
    return out


def run() -> dict:
    trace = Trace(echo=False)
    obs = observations(trace)
    result = world.ingest(obs, trace, agent="Seed") or {"error": "world model unreachable"}
    trace.log("Seed", "done", output={"observations": len(obs), **result}, sponsor="meterless")
    return {"observations": len(obs), "with_embeddings": sum(1 for o in obs if "embedding" in o), **result, "run_id": trace.run_id}


if __name__ == "__main__":
    print(run())
