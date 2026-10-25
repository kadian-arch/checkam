"""Phones, links and masking. Same HMAC pseudonym scheme as the Stop Arnaque 237 release,
so a number pasted by a citizen matches the codes in the published data without anyone
ever seeing the real number."""
import base64
import hashlib
import hmac
import re
import json
from functools import lru_cache
from pathlib import Path

from . import config

_SEP = r"[ .\-]?"
CM_PHONE = re.compile(
    r"(?<![\d\w+])(?:(?:\((?:\+|00)?237\)|(?:\+|00)?237)\+?" + _SEP + r")?([26](?:" + _SEP + r"\d){8})(?!\d)(?!\s*(?:f?cfa|xaf|francs?|frs)\b)",
    re.I,
)
TOKEN = re.compile(r"\[PHONE:([0-9a-z]{3}-[a-z]{6}|intl-[a-z]{6})\]")
URL = re.compile(r"(?i)\b((?:https?://|www\.)[^\s<>\"']+|(?:[a-z0-9-]+(?:\[\.\]|\.))+(?:com|cm|net|org|click|xyz|top|info|online|site|link|me|io|app)\b(?:/[^\s]*)?)")
INVISIBLE = re.compile(r"[\U000E0000-\U000E007F\U000E0100-\U000E01EF︀-︎​-‏⁠-⁤﻿­]|(?<=\w)️")
PIN_ASK = re.compile(r"(?i)\b(pin|code secret|mot de passe|password|otp|code de (?:confirmation|v[ée]rification)|\*126\*|#150)\b")

# public operator lines printed in their own messages (kept as they are)
OFFICIAL = {"650528787", "698717171", "690009500", "690009300", "690009200", "670362187"}
DOMAINS = {"mtn.cm", "orange.cm", "camtel.cm", "mtnonline.com"}
SENDER_NAMES: set[str] = set()


def load_channels(path: Path = Path(__file__).parent / "data" / "official_channels.json") -> None:
    """Sourced operator channels from data/official_channels.json add to the built-in lists, never replace them."""
    if not path.exists():
        return
    for op in json.loads(path.read_text(encoding="utf-8")).values():
        if not isinstance(op, dict) or not op.get("sources"):
            continue  # an entry without a source is not trusted
        OFFICIAL.update(re.sub(r"\D", "", n)[-9:] for n in op.get("whatsapp", []) + op.get("numbers", []) if len(re.sub(r"\D", "", n)) >= 9)
        DOMAINS.update(d.lower().removeprefix("www.").strip("/") for d in op.get("websites", []) if "." in d)
        SENDER_NAMES.update(re.sub(r"[\s'_-]", "", s).lower() for s in op.get("sender_names", []) if s.strip())


load_channels()
OFFICIAL_DOMAINS = re.compile(r"(?i)(^|\.)(" + "|".join(re.escape(d) for d in sorted(DOMAINS)) + r")$")


@lru_cache(maxsize=1)
def _key() -> bytes | None:
    if config.PSEUDONYM_KEY_B64:
        return base64.b64decode(config.PSEUDONYM_KEY_B64)
    if config.PSEUDONYM_KEY_FILE and Path(config.PSEUDONYM_KEY_FILE).exists():
        return Path(config.PSEUDONYM_KEY_FILE).read_bytes().strip()
    return None


def _code(value: str, key: bytes) -> str:
    digest = hmac.new(key, value.encode(), hashlib.sha256).digest()
    return "".join("abcdefghjkmnpqrstuvwxyz"[b % 23] for b in digest[:6])


def normalize_cm(raw: str):
    d = re.sub(r"\D", "", raw)
    if d.startswith("00237"):
        d = d[5:]
    elif d.startswith("237") and len(d) == 12:
        d = d[3:]
    return d if len(d) == 9 and d[0] in "26" else None


def pseudonym(digits: str) -> str | None:
    key = _key()
    return f"{digits[:3]}-{_code(digits, key)}" if key else None


def strip_invisible(text: str) -> tuple[str, int]:
    found = len(INVISIBLE.findall(text or ""))
    return INVISIBLE.sub("", text or ""), found


def extract(text: str) -> dict:
    """Numbers (as dataset codes), links and evasion signals found in a message."""
    clean, hidden = strip_invisible(text)
    numbers, official = [], []
    for m in CM_PHONE.finditer(clean):
        d = normalize_cm(m.group(0))
        if not d:
            continue
        if d in OFFICIAL:
            official.append(d)
            continue
        code = pseudonym(d)
        numbers.append({"code": code, "prefix": d[:3]})
    numbers += [{"code": c, "prefix": c[:3]} for c in TOKEN.findall(clean)]
    links = []
    for m in URL.findall(clean):
        host = re.sub(r"(?i)^https?://", "", m).replace("[.]", ".").split("/")[0].lower().removeprefix("www.")
        if host and host not in links:
            links.append(host)
    return {
        "text": clean,
        "numbers": numbers,
        "official_numbers": official,
        "links": [h for h in links if not OFFICIAL_DOMAINS.search(h)],
        "official_links": [h for h in links if OFFICIAL_DOMAINS.search(h)],
        "hidden_characters": hidden,
        "asks_for_secret": bool(PIN_ASK.search(clean)),
    }


def mask(text: str) -> str:
    """What gets stored for a citizen check: real numbers replaced by their codes."""
    clean, _ = strip_invisible(text)

    def rep(m):
        d = normalize_cm(m.group(0))
        if not d or d in OFFICIAL:
            return m.group(0)
        code = pseudonym(d)
        return f"[PHONE:{code}]" if code else "[PHONE]"

    return CM_PHONE.sub(rep, clean)
