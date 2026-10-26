"""Signed, hash-chained alert ledger. Every published alert is canonical JSON, hashed with the hash of
the alert before it, and signed with CheckAm's Ed25519 key. Anyone holding the public key can check that
an alert really came from CheckAm, that it was not edited, and that no alert was removed from the chain."""
import base64
import hashlib
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import config

GENESIS = "0" * 64
SIGNED_FIELDS = ("id", "created", "title", "body_en", "body_fr", "numbers", "campaign_id", "contract_id", "prev_hash")
_key: Ed25519PrivateKey | None = None


def _load() -> Ed25519PrivateKey:
    global _key
    if _key:
        return _key
    raw = config.env("CHECKAM_SIGNING_KEY")
    if raw:
        _key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(raw))
        return _key
    path = config.DATA_DIR / "signing_key"
    if path.exists():
        _key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(path.read_text().strip()))
    else:
        seed = os.urandom(32)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(base64.b64encode(seed).decode())
        _key = Ed25519PrivateKey.from_private_bytes(seed)
    return _key


def public_key_b64() -> str:
    return base64.b64encode(_load().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def canonical(alert: dict) -> bytes:
    return json.dumps({k: alert.get(k) for k in SIGNED_FIELDS}, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def seal(alert: dict, prev_hash: str | None) -> dict:
    alert = {**alert, "prev_hash": prev_hash or GENESIS}
    digest = hashlib.sha256(canonical(alert)).hexdigest()
    sig = base64.b64encode(_load().sign(digest.encode())).decode()
    return {**alert, "hash": digest, "signature": sig}


def verify(alert: dict, public_key: str | None = None) -> dict:
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key or public_key_b64()))
    digest = hashlib.sha256(canonical(alert)).hexdigest()
    if digest != alert.get("hash"):
        return {"valid": False, "reason": "content changed after signing"}
    try:
        pub.verify(base64.b64decode(alert.get("signature") or ""), digest.encode())
    except (InvalidSignature, ValueError):
        return {"valid": False, "reason": "signature does not match CheckAm's key"}
    return {"valid": True}


def verify_chain(alerts_oldest_first: list[dict]) -> dict:
    """The chain is the signed alerts, in order. An alert with no signature at all (published before signing
    existed, or slipped into the database by hand) never counts as CheckAm's: it is listed as unsigned."""
    unsigned = [a["id"] for a in alerts_oldest_first if not a.get("signature") and not a.get("hash")]
    signed = [a for a in alerts_oldest_first if a.get("signature") or a.get("hash")]
    r = _verify_signed(signed)
    return {**r, "unsigned": unsigned} if unsigned else r


def _verify_signed(alerts_oldest_first: list[dict]) -> dict:
    prev = GENESIS
    for a in alerts_oldest_first:
        if a.get("prev_hash") != prev:
            return {"valid": False, "broken_at": a["id"], "reason": "an alert before this one is missing or was changed"}
        r = verify(a)
        if not r["valid"]:
            return {"valid": False, "broken_at": a["id"], "reason": r["reason"]}
        prev = a["hash"]
    return {"valid": True, "length": len(alerts_oldest_first), "head": prev}


# ---------- verdict receipts: a CheckAm answer anyone can verify, so nobody can fake one ----------
RECEIPT_FIELDS = ("kind", "id", "created", "verdict", "confidence", "scheme", "text_sha256")


def text_fingerprint(text: str) -> str:
    """Same words, any spacing or case: the fingerprint a pasted copy of the message must match."""
    return hashlib.sha256(" ".join(text.lower().split()).encode()).hexdigest()


def sign_receipt(receipt: dict) -> dict:
    body = {k: receipt.get(k) for k in RECEIPT_FIELDS}
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    return {**body, "hash": digest, "signature": base64.b64encode(_load().sign(digest.encode())).decode()}


def verify_receipt(receipt: dict) -> dict:
    body = {k: receipt.get(k) for k in RECEIPT_FIELDS}
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    if digest != receipt.get("hash"):
        return {"valid": False, "reason": "the receipt was changed after CheckAm signed it"}
    try:
        _load().public_key().verify(base64.b64decode(receipt.get("signature") or ""), digest.encode())
    except (InvalidSignature, ValueError):
        return {"valid": False, "reason": "the signature is not CheckAm's"}
    return {"valid": True}
