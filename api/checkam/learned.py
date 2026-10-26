"""Evidence weights learned from the labelled messages (api/scripts/learn_weights.py), applied at run time.

The learner and the live server build the row of signals with the same function, so a weight always means
the same thing. Without a weights file nothing changes: the hand-set rule decides alone."""
import json
import math
import os
from functools import lru_cache
from pathlib import Path

W = {"strong": 3, "medium": 2, "weak": 1}
TOOLS = ["number_history", "link_history", "link_check", "similar_scams", "genuine_twin", "sender", "model_judgement", "campaign",
         "scam_type_stats", "memory", "no_harm_path", "official_route", "claim", "opportunity", "unverified_credit", "forged_receipt"]
FACTS = ["pin", "hidden", "injection", "forged_date", "ussd_to_person", "click", "promise", "retold", "official_route"]
# the kind of sender is left out on purpose: in the labelled data most scams arrived without one and most genuine
# messages came from operator names, so a weight on it would learn how the data was collected, not the message
NAMES = [f"{t}:{d}" for t in TOOLS for d in ("scam", "genuine")] + FACTS + ["demands", "has_link", "claims"]
FILE = Path(__file__).parent / "data" / "learned_weights.json"


def features(signals: list[dict], profile: dict) -> list[float]:
    acc: dict[str, float] = {}
    for s in signals:
        if s.get("status") == "accepted" and s.get("direction") in ("scam", "genuine") and s.get("tool") in TOOLS:
            k = f"{s['tool']}:{s['direction']}"
            acc[k] = acc.get(k, 0) + W.get(s.get("weight"), 1)
    p = profile or {}
    row = [acc.get(f"{t}:{d}", 0) / 3 for t in TOOLS for d in ("scam", "genuine")]
    row += [1.0 if p.get(f) else 0.0 for f in FACTS]
    return row + [min(p.get("demands", 0), 3) / 3, 1.0 if p.get("links") else 0.0, min(len(p.get("claims") or []), 3) / 3]


@lru_cache(maxsize=1)
def _model() -> dict | None:
    if os.environ.get("CHECKAM_LEARNED", "on") == "off":
        return None  # evaluation scores the agents themselves; the weights are scored by cross-validation
    try:
        m = json.loads(FILE.read_text(encoding="utf-8"))
        return m if m.get("names") == NAMES else None  # weights for another row shape are never applied
    except (OSError, ValueError):
        return None


def probability(signals: list[dict], profile: dict) -> float | None:
    m = _model()
    if not m:
        return None
    z = m["bias"] + sum(w * x for w, x in zip(m["weights"], features(signals, profile)))
    return 1 / (1 + math.exp(-max(-30, min(30, z))))


def threshold() -> float:
    return (_model() or {}).get("threshold", 0.5)
