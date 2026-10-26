"""Is a sentence the model wrote really in the person's language, and spelled right?

Checked against full French and English word lists instead of guessed patterns: a sentence counts as French
when most of its words are French words, and it is garbled when a word exists only with its accent
("telephone" for "téléphone"), when an accented word is no word at all ("reù"), or when an English word
slips into French ("exterior"). Names, brands, links, numbers and codes are not judged. Anything that fails
is replaced by our own sentence, written in both languages."""
import re
import unicodedata
from functools import lru_cache

from spellchecker import SpellChecker

_DICT = {"fr": SpellChecker(language="fr", distance=1), "en": SpellChecker(language="en", distance=1)}
ACCENTED = re.compile(r"[àâäçéèêëîïôöùûüÿœæ]", re.I)
# words Cameroonian French uses as they are
LOANWORDS = {"money", "mobile", "momo", "iphone", "android", "whatsapp", "telegram", "facebook", "sms", "ok", "anti", "bonus", "data",
             "internet", "cash", "pin", "otp", "code", "link", "app", "promo", "orange", "mtn", "camtel", "nexttel", "safari", "chrome"}
# prefixes that make a real verb from a real verb: revérifier, réessayer, redemander
PREFIXES = ("ré", "re", "r", "dé", "pré", "sur", "sous", "auto", "anti", "contre")
# letters French writes only in a handful of words; anywhere else they are a garbled accent
RARE = re.compile(r"[ìòÌÒ]")
REAL_U_GRAVE = {"où"}
REAL_I_CIRC = ("île", "maîtr", "connaî", "paraî", "naî", "plaî", "fraîch", "boîte", "dîn", "abîm", "gîte", "chaîn", "traîn", "entraî", "aîné", "huîtr", "épîtr", "goût")


def _plain(w: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFD", w) if unicodedata.category(c) != "Mn")


def _words(s: str) -> list[str]:
    """Lower-case words worth judging: no links, handles, numbers, codes, or names and brands in capitals."""
    s = re.sub(r"(?i)\S*(?:https?://|www\.|@|\.[a-z]{2,4}\b)\S*", " ", s or "")
    first = (s.split() or [""])[0]
    out = []
    for raw in re.findall(r"[^\W\d_]+(?:['’][^\W\d_]+)?", s):
        w = re.split(r"['’]", raw)[-1]  # l'argent -> argent, qu'il -> il
        if len(w) < 2 or (raw.isupper() and len(raw) > 1) or (raw[0].isupper() and raw != first.strip("«»\"'(")):
            continue  # Jean, MTN, MoMo: names and brands are not spelling
        if w.lower() not in LOANWORDS:
            out.append(w.lower())
    return out


@lru_cache(maxsize=8192)
def _known(w: str, lang: str) -> bool:
    if w in _DICT[lang]:
        return True
    if lang == "fr":
        return any(w.startswith(p) and len(w) - len(p) >= 4 and w[len(p):] in _DICT["fr"] for p in PREFIXES)
    return False


@lru_cache(maxsize=1)
def _accent_index() -> frozenset:
    """Every French word that needs an accent, written without it."""
    return frozenset(_plain(w) for w in _DICT["fr"].word_frequency.keys() if ACCENTED.search(w) and _plain(w) not in _DICT["fr"])


def share(s: str, lang: str) -> float:
    words = _words(s)
    return sum(_known(w, lang) for w in words) / len(words) if words else 1.0


def _bad_accent(w: str) -> bool:
    if RARE.search(w):
        return True
    if "ù" in w and w not in REAL_U_GRAVE:
        return True
    return "î" in w and not any(k in w for k in REAL_I_CIRC)


def garbled(s: str, lang: str = "fr") -> bool:
    for w in _words(s):
        if lang == "fr" and _bad_accent(w):
            return True
        if _known(w, lang):
            continue
        if lang == "fr":
            if w in _accent_index():
                return True  # "telephone", "verifiez": the word exists only with its accents
            if len(w) >= 4 and _known(w, "en"):
                return True  # an English word slipped into French ("exterior")
    return False


def well_written(s: str, lang: str) -> bool:
    """In the person's language and spelled right; short fragments are let through."""
    if lang not in _DICT or not s or not s.strip():
        return bool(s and s.strip())
    words = _words(s)
    if len(words) < 3:
        return not garbled(s, lang)
    other = "en" if lang == "fr" else "fr"
    mine, theirs = share(s, lang), share(s, other)
    return mine >= 0.7 and mine >= theirs and not garbled(s, lang)
