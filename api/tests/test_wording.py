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


def test_the_language_check_uses_real_dictionaries_not_guesses():
    from checkam import wording
    for s, lang in [("N'importe qui peut taper un message « vous avez reçu de l'argent »", "fr"), ("Arnaque : argent « envoyé par erreur »", "fr"),
                    ("Où est passé l'argent ? Une boîte de réception pleine", "fr"), ("Dial *126# yourself to see your real balance", "en")]:
        assert wording.well_written(s, lang), s
    for s, lang in [("vous avez reù de l'argent", "fr"), ("Composez vous-mîme le code", "fr"), ("Vous devez verifier votre compte immediatement", "fr"),
                    ("ne demande ni argent, ni code, ni lien exterior", "fr"), ("Follow-up message asks to return 25000 XAF", "fr"),
                    ("Il demande des frais avant de verser un gain", "en")]:
        assert not wording.well_written(s, lang), s
