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


CHANNELS_FILE = Path(__file__).parent / "data" / "official_channels.json"


def channel_problems(data) -> list[str]:
    """Everything that makes a channel list unsafe to trust. A wrong official number sends people to a
    scammer, so one problem rejects the whole file; the built-in lists stay in force."""
    if not isinstance(data, dict) or not data:
        return ["the file must be an object with one entry per operator"]
    problems, seen = [], {}
    for name, op in data.items():
        if not isinstance(op, dict):
            problems.append(f"{name}: must be an object")
            continue
        if not [s for s in op.get("sources", []) if isinstance(s, str) and s.startswith(("https://", "SMS received"))]:
            problems.append(f"{name}: every operator needs at least one source link or 'SMS received on (date)'")
        for key in ("sender_names", "short_codes", "whatsapp", "numbers", "websites", "sources"):
            v = op.get(key, [])
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                problems.append(f"{name}.{key}: must be a list of text values")
        for n in op.get("whatsapp", []) + op.get("numbers", []):
            digits = re.sub(r"\D", "", str(n))
            if len(digits) == 12 and digits.startswith("237"):
                digits = digits[3:]
            if not re.fullmatch(r"[26]\d{8}", digits):
                problems.append(f"{name}: {n} is not a 9-digit Cameroon number")
            elif digits in seen and seen[digits] != name:
                problems.append(f"{name}: {digits} is also listed for {seen[digits]}; one number cannot belong to two operators")
            seen.setdefault(digits, name)
        for code in op.get("short_codes", []):
            if not re.fullmatch(r"[*#]\d{2,4}(?:\*\d+)*\*?#|\d{3,5}", str(code).strip()):
                problems.append(f"{name}: '{code}' must be one code per item, like *126#")
        for d in op.get("websites", []):
            host = str(d).lower().removeprefix("https://").removeprefix("http://").removeprefix("www.").strip("/")
            if name.lower() not in host:
                problems.append(f"{name}: website {d} does not belong to {name}")
    return problems


def load_channels(path: Path = CHANNELS_FILE) -> list[str]:
    """Sourced operator channels add to the built-in lists, never replace them. A broken or unsafe file is
    ignored as a whole and reported; it never stops the app."""
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as e:
        return [f"not valid JSON: {e}"]
    problems = channel_problems(data)
    if problems:
        return problems
    for op in data.values():
        OFFICIAL.update(re.sub(r"\D", "", n)[-9:] for n in op.get("whatsapp", []) + op.get("numbers", []))
        DOMAINS.update(d.lower().removeprefix("https://").removeprefix("www.").strip("/") for d in op.get("websites", []))
        SENDER_NAMES.update(re.sub(r"[\s'_-]", "", s).lower() for s in op.get("sender_names", []) if s.strip())
    return []


CHANNEL_PROBLEMS = load_channels()
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


# a secret typed into a message ("my PIN is 4821", "code: 552190") is never stored
SECRET_CODE = re.compile(r"(?i)\b(pin|otp|code(?: secret)?|mot de passe|password|passcode|cvv)\b(\W{0,4}(?:is|est|:|=)?\W{0,3})(\d{4,8})\b")


def mask(text: str) -> str:
    """What gets stored for a citizen check: real numbers replaced by their codes, secret codes removed."""
    clean, _ = strip_invisible(text)
    clean = SECRET_CODE.sub(lambda m: f"{m.group(1)}{m.group(2)}[CODE]", clean)

    def rep(m):
        d = normalize_cm(m.group(0))
        if not d or d in OFFICIAL:
            return m.group(0)
        code = pseudonym(d)
        return f"[PHONE:{code}]" if code else "[PHONE]"

    return CM_PHONE.sub(rep, clean)
