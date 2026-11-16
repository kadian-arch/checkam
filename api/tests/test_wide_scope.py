"""Scams that are not about a mobile money message (romance, blackmail, fake officials, login links, concours,
rentals, crypto) and harmless everyday messages, judged by the rules alone, with no model to lean on."""
import json
from pathlib import Path

import pytest

from checkam import agents

CASES = json.loads((Path(__file__).resolve().parents[2] / "evals" / "wide_scope.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CASES, ids=[c["kind"] for c in CASES])
def test_wide_scope(case):
    card = agents.run_check(case["text"], sender=case.get("sender", ""), persist=False, echo=False)
    if case["label"] == "scam":
        assert card.get("verdict") in ("scam", "suspicious"), "a scam was let through"
    else:
        assert card.get("verdict") not in ("scam", "suspicious"), "a harmless message was flagged"


def test_the_unit_of_money_is_not_needed_to_see_a_pay_now_get_more_offer():
    assert agents.stake_and_return("Invest 20000 and get 60000 in 3 days")
    assert not agents.stake_and_return("Call 677123456 and get 2 tickets")
    assert not agents.stake_and_return("Pay 5000 and get your receipt, reference 123456")
