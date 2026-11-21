"""A greeting is not a message to judge, and harmless is not the same as genuine."""
import pytest

from checkam import agents


@pytest.mark.parametrize("text", ["hi", "Hello, how are you?", "Bonjour", "Good morning!", "thanks", "Salut ça va ?", "ok"])
def test_a_greeting_gets_a_friendly_note_not_a_verdict(text):
    card = agents.run_check(text, persist=False, echo=False)
    assert card.get("nothing") and "verdict" not in card and card["error"]


def test_a_greeting_that_goes_on_to_ask_something_is_still_checked():
    card = agents.run_check("Hello dear, please send me 5000 on 677123456 today", persist=False, echo=False)
    assert card.get("verdict") in ("scam", "suspicious")


def test_a_harmless_message_nobody_vouches_for_is_nothing_to_check_not_genuine():
    card = agents.run_check("Good morning my love, did you sleep well? I will call you after class.", persist=False, echo=False)
    assert card["verdict"] == "looks_genuine" and card["quiet"] and card["evidence_level"] == "quiet"
    assert "genuine" not in card["headline"].lower()


def test_a_real_operator_message_is_still_called_genuine():
    card = agents.run_check("Y'ello! Your MoMo balance is 12 450 FCFA. Dial *126# for more services.", sender="MTN", persist=False, echo=False)
    assert card["verdict"] == "looks_genuine" and not card["quiet"]
