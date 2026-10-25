"""The app's wording files must stay in step: same keys, same placeholders, valid JSON."""
import json
import re
from pathlib import Path

I18N = Path(__file__).resolve().parents[2] / "web" / "src" / "i18n"


def load(name):
    return json.loads((I18N / f"{name}.json").read_text(encoding="utf-8"))


def placeholders(v):
    return sorted(re.findall(r"\{(\w+)\}", json.dumps(v, ensure_ascii=False)))


def test_every_language_has_every_key():
    en = load("en")
    for lang in ("fr",):
        other = load(lang)
        assert set(other) == set(en), f"{lang}: missing {set(en) - set(other)}, extra {set(other) - set(en)}"


def test_placeholders_survive_translation():
    en = load("en")
    for lang in ("fr",):
        other = load(lang)
        for k in en:
            assert placeholders(other[k]) == placeholders(en[k]), f"{lang}.{k} must keep {placeholders(en[k])}"


def test_progress_steps_line_up():
    assert len(load("fr")["steps"]) == len(load("en")["steps"])
