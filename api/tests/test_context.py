"""What the reader says about a message (how it came, who it claims to be, what it wants) is used, and can only add caution."""
from checkam import agents


def test_a_named_request_is_added_to_what_was_detected():
    facts = {"asks": ["click_link"]}
    ctx = agents.apply_context(facts, {"wants": ["money", "bogus"], "channel": "voice_note", "relation": "claims_known"})
    assert set(facts["asks"]) == {"click_link", "send_money"}
    assert facts["reported_channel"] == "voice_note" and facts["relation"] == "claims_known"
    assert ctx["wants"] == ["money"]


def test_unknown_values_and_non_dicts_are_ignored():
    facts = {"asks": []}
    assert agents.apply_context(facts, {"channel": "x", "relation": "y", "wants": "money"}) == {}
    assert agents.apply_context(facts, "text") == {}
    assert facts["asks"] == []


def test_someone_i_know_on_a_new_number_asking_for_money_is_hard_evidence():
    text = "Hi it's me, I changed my number. Please help me with something small today."
    plain = agents.run_check(text, sender="6 70 00 00 00", persist=False, echo=False)
    told = agents.run_check(text, sender="6 70 00 00 00", persist=False, echo=False,
                            context={"relation": "claims_known", "wants": ["money"]})
    assert told["verdict"] in ("scam", "suspicious")
    assert told["verdict"] != "looks_genuine" and plain["verdict"] != "looks_genuine"


def test_context_never_clears_a_scam():
    text = "Send your MoMo PIN to claim your 500000 FCFA prize"
    card = agents.run_check(text, sender="6 70 00 00 00", persist=False, echo=False, context={"relation": "known", "channel": "sms"})
    assert card["verdict"] == "scam"
