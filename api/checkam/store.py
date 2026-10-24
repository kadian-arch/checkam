"""Case store: anonymised citizen checks, analyst accounts, published alerts (SQLite)."""
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone

from . import config

_lock = threading.Lock()
SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (
  id TEXT PRIMARY KEY, created TEXT, masked_text TEXT, verdict TEXT, confidence REAL, language TEXT,
  numbers TEXT, links TEXT, scam_types TEXT, campaign_id TEXT, run_id TEXT, channel TEXT
);
CREATE TABLE IF NOT EXISTS analysts (
  email TEXT PRIMARY KEY, name TEXT, org TEXT, role TEXT, salt TEXT, pw_hash TEXT, created TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY, created TEXT, published_by TEXT, campaign_id TEXT, title TEXT, body_en TEXT,
  body_fr TEXT, body_pcm TEXT, numbers TEXT, status TEXT, run_id TEXT
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db() -> sqlite3.Connection:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    return c


_conn = None


def conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = db()
    return _conn


def save_check(row: dict) -> None:
    with _lock:
        conn().execute(
            "INSERT OR REPLACE INTO checks VALUES (:id,:created,:masked_text,:verdict,:confidence,:language,:numbers,:links,:scam_types,:campaign_id,:run_id,:channel)",
            {**row, "numbers": json.dumps(row.get("numbers", [])), "links": json.dumps(row.get("links", [])),
             "scam_types": json.dumps(row.get("scam_types", []))})
        conn().commit()


def set_check_campaign(check_id: str, campaign_id: str | None) -> None:
    with _lock:
        conn().execute("UPDATE checks SET campaign_id=? WHERE id=?", (campaign_id, check_id))
        conn().commit()


def checks_with_number(code: str, exclude: str | None = None) -> list[dict]:
    rows = conn().execute("SELECT id, created, verdict FROM checks WHERE numbers LIKE ? AND id != ?",
                          (f'%"{code}"%', exclude or "")).fetchall()
    return [dict(r) for r in rows]


def recent_checks(limit: int = 50) -> list[dict]:
    rows = conn().execute("SELECT * FROM checks ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
    return [{**dict(r), "numbers": json.loads(r["numbers"]), "links": json.loads(r["links"]),
             "scam_types": json.loads(r["scam_types"])} for r in rows]


def check_stats() -> dict:
    c = conn()
    total = c.execute("SELECT count(*) FROM checks").fetchone()[0]
    by = {r[0]: r[1] for r in c.execute("SELECT verdict, count(*) FROM checks GROUP BY verdict")}
    return {"total": total, "by_verdict": by}


# ---------- analysts ----------
def _hash(password: str, salt: str) -> str:
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex()


def add_analyst(email: str, password: str, name: str, org: str = "", role: str = "analyst") -> None:
    salt = os.urandom(16).hex()
    with _lock:
        conn().execute("INSERT OR REPLACE INTO analysts VALUES (?,?,?,?,?,?,?)",
                       (email.lower(), name, org, role, salt, _hash(password, salt), now()))
        conn().commit()


def verify_analyst(email: str, password: str) -> dict | None:
    r = conn().execute("SELECT * FROM analysts WHERE email=?", (email.lower(),)).fetchone()
    if r and hmac.compare_digest(r["pw_hash"], _hash(password, r["salt"])):
        return {"email": r["email"], "name": r["name"], "org": r["org"], "role": r["role"]}
    return None


def make_token(email: str, ttl: int = 12 * 3600) -> str:
    exp = str(int(time.time()) + ttl)
    sig = hmac.new(config.SECRET.encode(), f"{email}|{exp}".encode(), hashlib.sha256).hexdigest()
    return f"{email}|{exp}|{sig}"


def read_token(token: str) -> str | None:
    try:
        email, exp, sig = token.split("|")
    except ValueError:
        return None
    good = hmac.new(config.SECRET.encode(), f"{email}|{exp}".encode(), hashlib.sha256).hexdigest()
    return email if hmac.compare_digest(sig, good) and int(exp) > time.time() else None


# ---------- alerts ----------
def publish_alert(row: dict) -> dict:
    row = {"id": "AL-" + uuid.uuid4().hex[:8], "created": now(), "status": "published", **row}
    with _lock:
        conn().execute("INSERT INTO alerts VALUES (:id,:created,:published_by,:campaign_id,:title,:body_en,:body_fr,:body_pcm,:numbers,:status,:run_id)",
                       {**row, "numbers": json.dumps(row.get("numbers", []))})
        conn().commit()
    return row


def alerts(limit: int = 50) -> list[dict]:
    rows = conn().execute("SELECT * FROM alerts WHERE status='published' ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
    return [{**dict(r), "numbers": json.loads(r["numbers"])} for r in rows]
