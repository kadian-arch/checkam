"""Scams that are not money messages (romance, blackmail, fake officials, login links, concours, rentals, crypto),
ordinary genuine messages beside the fakes built like them, and messages that cannot be judged from their text
alone. Judged by the rules only, with no model to lean on.

Labels: scam = must be flagged (scam or be careful); genuine = must not be flagged; unverifiable = may be neither
accused nor cleared (be careful, or not sure), because the text alone cannot prove which it is."""
import json
from pathlib import Path

import pytest

from checkam import agents

EVALS = Path(__file__).resolve().parents[2] / "evals"
CASES = [c for name in ("wide_scope", "everyday", "real_messages", "redteam_scams") for c in json.loads((EVALS / f"{name}.json").read_text(encoding="utf-8"))]
FLAGGED = ("scam", "suspicious")


def right(label: str, verdict: str | None) -> bool:
    if label == "scam":
        return verdict in FLAGGED
    if label == "unverifiable":
        return verdict in ("suspicious", "cant_tell")
    return verdict not in FLAGGED


@pytest.mark.parametrize("case", CASES, ids=[f"{i}-{c['kind']}" for i, c in enumerate(CASES)])
def test_wide_scope(case):
    card = agents.run_check(case["text"], sender=case.get("sender", ""), persist=False, echo=False)
    assert right(case["label"], card.get("verdict")), f"{case['label']} message got {card.get('verdict')}"


def test_the_unit_of_money_is_not_needed_to_see_a_pay_now_get_more_offer():
    assert agents.stake_and_return("Invest 20000 and get 60000 in 3 days")
    assert not agents.stake_and_return("Call 677123456 and get 2 tickets")
    assert not agents.stake_and_return("Pay 5000 and get your receipt, reference 123456")


def test_a_message_with_only_soft_signs_is_never_called_a_scam():
    card = agents.run_check(next(c["text"] for c in CASES if c["kind"] == "job_ad_private_number"), persist=False, echo=False)
    assert card["verdict"] != "scam" and card["evidence_level"] in ("limited", "none")
    assert "scam" not in card["headline"].lower() and "fake" not in card["headline"].lower()


def test_emoji_numbering_is_not_a_hidden_character():
    from checkam import privacy
    assert privacy.strip_invisible("1️⃣ BUSINESS MANAGER \U0001F469‍\U0001F4BC")[1] == 0
    assert privacy.strip_invisible("sen​d the co​de")[1] == 2  # inside a word it still is one


def test_french_un_and_the_word_who_are_not_an_institution():
    from checkam.adapters import linkcheck
    assert linkcheck.claimed("un recrutement de jeunes, une femme qui sait cuisiner") is None
    assert linkcheck.claimed("Vaccination campaign by the WHO")[0] == "an international organisation"


def test_the_card_never_says_the_opposite_of_its_verdict():
    assert agents.contradicts("Bank hiring scam targets job seekers", "looks_genuine")
    assert not agents.contradicts("This is not a scam", "looks_genuine")
    assert not agents.contradicts("No sign of a scam here", "looks_genuine")
    assert agents.contradicts("This message looks genuine", "suspicious")
    assert not agents.contradicts("Nothing here is safe to trust", "scam")
