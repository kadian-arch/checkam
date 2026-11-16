"""Robustness by transformation. How a message is written changes; what it is does not. The same message with
emoji, WhatsApp bold, extra spacing or a greeting must get the same kind of answer, and a scam that hides
zero-width characters in its words must still be caught. New scams are mostly variants of old ones, so
a check that survives rewrites is worth more than one more rule. Emoji numbering read as hidden characters
(found by tracing a WhatsApp job ad) is the kind of fault this is meant to catch next time."""
import json
import re
from pathlib import Path

import pytest

from checkam import agents
from test_wide_scope import CASES, right

TRANSFORMS = {
    "emoji": lambda t: "✅ " + t + " \U0001F64F",
    "keycaps": lambda t: "\n".join(f"{i + 1}️⃣ {line}" if line.strip() else line for i, line in enumerate(t.split("\n"))),
    "bold": lambda t: "*" + t.split("\n", 1)[0] + "*" + ("\n" + t.split("\n", 1)[1] if "\n" in t else ""),
    "spacing": lambda t: "  " + t.replace(". ", ".  ").replace("\n", " \n") + "\n\n",
    "greeting": lambda t: "Hello everyone,\n\n" + t,
}
# what a scammer does to slip past a filter: only for the scams, and only a few of them to keep the run short
EVASIONS = {
    "zero_width": lambda t: re.sub(r"(?<=\w{4})(?=\w)", "​", t),
}


def run(text, sender=""):
    return agents.run_check(text, sender=sender, persist=False, echo=False).get("verdict")


@pytest.mark.parametrize("name", TRANSFORMS)
def test_formatting_does_not_change_the_answer(name):
    wrong = []
    for c in CASES:
        if not right(c["label"], run(c["text"], c.get("sender", ""))):
            continue  # a base case that is already wrong is another test's failure
        got = run(TRANSFORMS[name](c["text"]), c.get("sender", ""))
        if not right(c["label"], got):
            wrong.append(f"{c['kind']} ({c['label']}) -> {got}")
    assert not wrong, f"{name} changed the answer for: " + "; ".join(wrong)


@pytest.mark.parametrize("name", EVASIONS)
def test_hiding_characters_in_a_scam_does_not_get_it_through(name):
    wrong = []
    for c in (c for c in CASES if c["label"] == "scam"):
        if run(c["text"], c.get("sender", "")) not in agents.__dict__.get("FLAGGED_VERDICTS", ("scam", "suspicious")):
            continue
        got = run(EVASIONS[name](c["text"]), c.get("sender", ""))
        if got not in ("scam", "suspicious"):
            wrong.append(f"{c['kind']} -> {got}")
    assert not wrong, f"{name} let through: " + "; ".join(wrong)
