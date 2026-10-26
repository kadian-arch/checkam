"""Honest evaluation on the labelled Stop Arnaque 237 messages (87 scam, 180 genuine).

Leave-one-out: each message is checked with its own source record hidden from every tool and from
the Critic's re-counts, so a message can never be confirmed by itself. Nothing is stored and the
campaign graph is not touched.

  python api/scripts/evaluate.py --split all --workers 6               # whatever mode .env gives
  python api/scripts/evaluate.py --split test --workers 4 --tag full
  MODEL_API_KEY= python api/scripts/evaluate.py --tag rules             # agents without Nemotron
"""
import argparse
import difflib
import json
import os
import re
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "api"))
os.environ.setdefault("CHECKAM_SEED_ON_START", "false")
# the learned weights were trained on these very messages: scoring with them here would flatter us
os.environ["CHECKAM_LEARNED"] = "off"

from checkam import agents, config  # noqa: E402
from checkam.adapters.data import data  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--split", default="all", choices=["all", "train", "test"])
ap.add_argument("--workers", type=int, default=4)
ap.add_argument("--tag", default="run")
ap.add_argument("--limit", type=int, default=0)
ap.add_argument("--sample", type=int, default=0, help="stratified random sample of this size (seed 7)")
ap.add_argument("--ids", default="", help="comma-separated ids to re-run, e.g. the misses of a previous run")
ap.add_argument("--with-sender", action="store_true", help="also give the sender the person saw on their phone")
ap.add_argument("--loose", action="store_true", help="hide only the message's own record (default also hides near-copies of it)")
args = ap.parse_args()

where = "" if args.split == "all" else f" WHERE split = '{args.split}'"
rows = data().sql(f"SELECT id, text, label, origin, text_type, language, split FROM {config.ZETARIS_DB}.messages{where}", why="evaluation set")
rows.sort(key=lambda r: r["id"])
if args.ids:
    keep = set(args.ids.split(","))
    rows = [r for r in rows if r["id"] in keep]
if args.limit:
    rows = rows[: args.limit]
if args.sample:
    import random
    rnd = random.Random(7)
    pos = [r for r in rows if r["label"] == "scam"]
    neg = [r for r in rows if r["label"] != "scam"]
    k = args.sample
    rows = rnd.sample(pos, min(len(pos), k * len(pos) // len(rows) + 1)) + rnd.sample(neg, min(len(neg), k - k * len(pos) // len(rows) - 1))

senders = {}
if args.with_sender:
    for g in data().sql(f"SELECT id, sender_shown FROM {config.ZETARIS_DB}.genuine_messages", why="sender names"):
        senders[g["id"]] = g["sender_shown"] or ""
    for r in data().sql(f"SELECT id, sender, sender_phone_id FROM {config.ZETARIS_DB}.reports", why="report senders"):
        senders[r["id"]] = f"[PHONE:{r['sender_phone_id']}]" if r["sender_phone_id"] else (r["sender"] or "")


# the same scam often sits in the data twice (a report and the public alert that quotes it, a reposted
# screenshot): hiding only the message's own record would let a near-copy answer for it
everything = data().sql(f"SELECT id, text FROM {config.ZETARIS_DB}.messages", why="near-copies to hide")


def _norm(s: str) -> str:
    return re.sub(r"\[[A-Z_]+(?::[^\]]*)?\]|[^\w]+", " ", s or "").lower().strip()


def near_copies(r) -> tuple:
    me = _norm(r["text"])
    if args.loose or not me:
        return (r["id"],)
    return (r["id"],) + tuple(o["id"] for o in everything
                              if o["id"] != r["id"] and difflib.SequenceMatcher(None, me, _norm(o["text"])).ratio() >= 0.75)


# the meaning vectors are ready before the first message, so every message is scored the same way
agents.warm_embeddings(data().sql(f"SELECT id, text, scam_types, channel, language FROM {config.ZETARIS_DB}.messages WHERE label = 'scam'", why="scam wording"))


def one(r):
    t0 = time.time()
    try:
        c = agents.run_check(r["text"], sender=senders.get(r["id"], ""), holdout=near_copies(r), persist=False, echo=False)
        return {**r, "verdict": c.get("verdict", "error"), "confidence": c.get("confidence"), "seconds": round(time.time() - t0, 1),
                "rounds": c.get("rounds"), "why": [w["text"] for w in c.get("why", [])][:3],
                # what each agent found, so the evidence weights can be learned (api/scripts/learn_weights.py)
                "signals": [{"tool": f["tool"], "direction": f["direction"], "weight": f["weight"], "status": f["status"]} for f in c.get("findings", [])],
                "profile": c.get("profile"), "sender_given": bool(senders.get(r["id"]))}
    except Exception as e:
        return {**r, "verdict": "error", "error": str(e)[:200], "seconds": round(time.time() - t0, 1)}


t0 = time.time()
with ThreadPoolExecutor(max_workers=args.workers) as pool:
    results = list(pool.map(one, rows))
elapsed = time.time() - t0

POS = {"scam", "suspicious"}
tp = sum(1 for r in results if r["label"] == "scam" and r["verdict"] in POS)
fn = sum(1 for r in results if r["label"] == "scam" and r["verdict"] not in POS)
fp = sum(1 for r in results if r["label"] != "scam" and r["verdict"] in POS)
tn = sum(1 for r in results if r["label"] != "scam" and r["verdict"] not in POS)
cant = sum(1 for r in results if r["verdict"] == "cant_tell")
prec = tp / (tp + fp) if tp + fp else 0
rec = tp / (tp + fn) if tp + fn else 0
f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
fpr = fp / (fp + tn) if fp + tn else 0
by = Counter((r["label"], r["verdict"]) for r in results)
origin = Counter((r["origin"], r["text_type"], r["verdict"] in POS) for r in results if r["label"] == "scam")

mode = f"data={data().mode}, nemotron={'on' if config.MODEL_API_KEY else 'off'}"
summary = {"tag": args.tag, "split": args.split, "with_sender": args.with_sender, "near_copies_hidden": not args.loose, "n": len(results), "mode": mode, "seconds": round(elapsed), "precision": round(prec, 4),
           "recall": round(rec, 4), "f1": round(f1, 4), "false_alarm_rate": round(fpr, 4), "cant_tell": cant,
           "confusion": {f"{k[0]}->{k[1]}": v for k, v in sorted(by.items())},
           "recall_by_source": {f"{k[0]}/{k[1]}": v for k, v in sorted(origin.items(), key=str)}}
out = ROOT / "evals" / f"results-{args.tag}-{args.split}.json"
out.parent.mkdir(exist_ok=True)
out.write_text(json.dumps({"summary": summary, "results": results}, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
print(json.dumps(summary, indent=2))
print("misses:")
for r in results:
    if (r["label"] == "scam") != (r["verdict"] in POS):
        print(f"  {r['id']} {r['label']} -> {r['verdict']} | {r['text'][:110]!r}")

# the Java bridge to Zetaris can keep the process alive after the work is done; leave cleanly
sys.stdout.flush()
os._exit(0)
