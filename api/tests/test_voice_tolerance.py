import json
import pathlib

from checkam import agents, privacy

CASES = json.loads((pathlib.Path(__file__).parents[2] / "evals" / "pidgin_voice.json").read_text(encoding="utf-8"))


def test_spoken_numbers_become_digits_and_ordinary_words_stay():
    assert "655112233" in privacy.normalize_spoken("send to six five five one one two two three three")
    assert "50000 francs" in privacy.normalize_spoken("fifty thousand francs")
    assert "20000 francs" in privacy.normalize_spoken("vingt mille francs")
    assert privacy.normalize_spoken("I have two children and five reasons") == "I have two children and five reasons"


def test_pidgin_spoken_and_elder_messages_are_judged_by_meaning_not_by_grammar():
    wrong = []
    for c in CASES:
        card = agents.run_check(c["text"], sender=c.get("sender", ""), persist=False, echo=False)
        flagged = card.get("verdict") in ("scam", "suspicious")
        if flagged != (c["label"] == "scam"):
            wrong.append(c["kind"])
    assert not wrong, wrong
