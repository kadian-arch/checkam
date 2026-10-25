"""The full agent loop in sample mode: no keys, no Zetaris, no engines. Real logic, same SQL."""
import json
from pathlib import Path

from checkam import agents, store

FIX = Path(__file__).parent / "fixtures"


def lines(trace):
    return [(l["agent_name"], l["action"]) for l in trace]


def test_mistaken_transfer_with_known_number_is_a_scam():
    card = agents.run_check("Please I sent 25000 to your MTN number by mistake, send it back to [PHONE:654-jwmukg] fast")
    assert card["verdict"] == "scam"
    assert any("starting 654" in w["text"] and "reported" in w["text"] for w in card["why"])
    assert not any("654-jwmukg" in w["text"] for w in card["why"])  # citizens see plain words, never internal codes
    steps = lines(card["trace"])
    for agent in ("Intake", "Planner", "Investigator", "Critic", "Reporter"):
        assert any(a == agent for a, _ in steps), agent
    assert ("Critic", "verify") in steps and ("Critic", "verdict_gate") in steps


def test_critic_recounts_numbers_in_the_data():
    card = agents.run_check("Send back the money to [PHONE:654-jwmukg] it was a mistake")
    verify = [l for l in card["trace"] if l["agent_name"] == "Critic" and l["action"] == "sql"]
    assert verify, "the Critic must query the data itself, not trust the Investigator"


def test_pin_request_is_a_scam_even_without_history():
    card = agents.run_check("MTN: your account is blocked. Reply with your PIN code to unblock it today")
    assert card["verdict"] in ("scam", "suspicious")
    assert any("PIN" in w["text"] for w in card["why"])


def test_genuine_operator_message_is_not_flagged():
    card = agents.run_check("Get up to 5000U bonus when you buy a bundle from 100U. Dial *222# to enjoy this limited-time offer")
    assert card["verdict"] == "looks_genuine"


def test_empty_input_is_refused_politely():
    assert "error" in agents.run_check("   ")


def test_checks_are_stored_without_the_real_number():
    agents.run_check("Return my 10000, I sent it by mistake. Call 677 99 88 77")
    rows = store.recent_checks(5)
    assert rows and all("99 88 77" not in r["masked_text"] for r in rows)


def test_trace_file_is_written_per_run():
    card = agents.run_check("Congratulations you won 400000 FCFA, call 694 11 22 33 to collect")
    from checkam import config
    assert (config.LOG_DIR / f"trace-{card['run_id']}.jsonl").exists()


def test_chelsey_fixtures_are_clean_if_present():
    f = FIX / "fresh_messages.jsonl"
    if not f.exists():
        return
    import re
    for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        assert set(row) >= {"text", "language", "label"}, f"line {n}: needs text, language, label"
        assert not re.search(r"\d{6,}|\d{3}[ .-]\d{2}[ .-]\d{2}[ .-]\d{2}", row["text"]), f"line {n}: replace phone numbers with XXX"
