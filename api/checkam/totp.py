"""Two-step sign-in for the administrator.

After the password, the administrator gives a six-digit code from an authenticator app (RFC 6238: Google
Authenticator, Microsoft Authenticator, Authy, 1Password and others all read it). Eight one-time recovery codes are
shown once at set-up for the day the phone is lost. The secret is stored encrypted, a code can be used only once, and
the password step hands back a short-lived challenge, never a session."""
import base64
import hashlib
import hmac
import os
import re
import secrets
import struct
import time
from urllib.parse import quote

from cryptography.fernet import Fernet

from . import config

STEP = 30  # seconds a code is valid for


def new_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 10**6
    return f"{number:06d}"


def code_at(secret: str, at: float | None = None) -> str:
    return _hotp(secret, int((time.time() if at is None else at) // STEP))


def verify(secret: str, code: str, last_step: int = 0, now: float | None = None) -> int | None:
    """The step the code belongs to, or None. A code from a step already used (or an older one) is refused, so a code
    seen over a shoulder cannot be replayed. One step either side allows for a slow clock."""
    code = re.sub(r"\s", "", code or "")
    if not re.fullmatch(r"\d{6}", code):
        return None
    current = int((time.time() if now is None else now) // STEP)
    for step in (current - 1, current, current + 1):
        if step > last_step and hmac.compare_digest(_hotp(secret, step), code):
            return step
    return None


def otpauth_uri(email: str, secret: str, issuer: str = "CheckAm") -> str:
    return f"otpauth://totp/{quote(issuer)}:{quote(email)}?secret={secret}&issuer={quote(issuer)}&digits=6&period={STEP}"


def _fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(("checkam-2fa|" + config.SECRET).encode()).digest()))


def seal(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def unseal(blob: str) -> str:
    return _fernet().decrypt(blob.encode()).decode()


def new_recovery_codes(n: int = 8) -> list[str]:
    return [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(n)]


def hash_code(code: str) -> str:
    return hashlib.sha256(("recovery|" + config.SECRET + "|" + code.strip().lower()).encode()).hexdigest()


def is_recovery_code(code: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{4}-[0-9a-f]{4}", (code or "").strip().lower()))


def challenge(email: str, purpose: str, ttl: int = 300) -> str:
    """Proof that the password was right, good for five minutes and for one purpose only (set up, or enter a code)."""
    exp = int(time.time()) + ttl
    sig = hmac.new(config.SECRET.encode(), f"{email}|{exp}|{purpose}".encode(), hashlib.sha256).hexdigest()
    return f"{email}|{exp}|{purpose}|{sig}"


def read_challenge(token: str, purpose: str) -> str | None:
    try:
        email, exp, why, sig = (token or "").split("|")
    except ValueError:
        return None
    good = hmac.new(config.SECRET.encode(), f"{email}|{exp}|{why}".encode(), hashlib.sha256).hexdigest()
    return email if why == purpose and hmac.compare_digest(sig, good) and int(exp) > time.time() else None
