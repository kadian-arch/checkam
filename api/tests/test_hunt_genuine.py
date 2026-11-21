"""88 ordinary messages written by an independent tester (families, schools, bills, churches, clinics, jobs, codes).
Some are honestly ambiguous (a stranger asking you for money, a pledge to a mobile number), so this is a rate, not a
per-message rule: no genuine message may be called a scam, and at most one in six may be flagged or left unsure."""
import json
from pathlib import Path

from checkam import agents

CASES = json.loads((Path(__file__).resolve().parents[2] / "evals" / "hunt_genuine_candidates.json").read_text(encoding="utf-8"))


def test_ordinary_messages_are_rarely_flagged_and_never_called_a_scam():
    verdicts = [agents.run_check(c["text"], sender=c["sender"], persist=False, echo=False)["verdict"] for c in CASES]
    assert "scam" not in verdicts
    clean = sum(v == "looks_genuine" for v in verdicts)
    assert clean >= len(CASES) * 5 / 6, f"{clean} of {len(CASES)} clean"
