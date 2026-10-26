"""Case store: anonymised citizen checks, analyst accounts, published alerts (SQLite)."""
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

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
CREATE TABLE IF NOT EXISTS receipts (
  id TEXT PRIMARY KEY, created TEXT, receipt TEXT
);
CREATE TABLE IF NOT EXISTS answers (
  key TEXT PRIMARY KEY, created TEXT, card TEXT, hits INTEGER DEFAULT 0
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
    have = {r[1] for r in c.execute("PRAGMA table_info(alerts)")}
    for col in ("contract_id", "prev_hash", "hash", "signature"):
        if col not in have:
            c.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT")
    have = {r[1] for r in c.execute("PRAGMA table_info(checks)")}
    for col, kind in (("operator", "TEXT"), ("amount_fcfa", "INTEGER"), ("scheme", "TEXT")):
        if col not in have:
            c.execute(f"ALTER TABLE checks ADD COLUMN {col} {kind}")
    # checks saved before the operator column existed: read it back from the stored (masked) text
    c.execute("""UPDATE checks SET operator = CASE
        WHEN lower(masked_text) LIKE '%orange%' THEN 'orange'
        WHEN lower(masked_text) LIKE '%camtel%' OR lower(masked_text) LIKE '%blue %' THEN 'camtel'
        WHEN lower(masked_text) LIKE '%mtn%' OR lower(masked_text) LIKE '%momo%' OR lower(masked_text) LIKE '%mobile money%' OR lower(masked_text) LIKE '%mobilemoney%' THEN 'mtn'
        ELSE 'other' END WHERE operator IS NULL""")
    c.commit()
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
            "INSERT OR REPLACE INTO checks (id, created, masked_text, verdict, confidence, language, numbers, links, scam_types, campaign_id, run_id, channel, operator, amount_fcfa, scheme) "
            "VALUES (:id,:created,:masked_text,:verdict,:confidence,:language,:numbers,:links,:scam_types,:campaign_id,:run_id,:channel,:operator,:amount_fcfa,:scheme)",
            {"operator": "other", "amount_fcfa": None, "scheme": None, **row, "numbers": json.dumps(row.get("numbers", [])), "links": json.dumps(row.get("links", [])),
             "scam_types": json.dumps(row.get("scam_types", []))})
        conn().commit()


def set_check_campaign(check_id: str, campaign_id: str | None) -> None:
    with _lock:
        conn().execute("UPDATE checks SET campaign_id=? WHERE id=?", (campaign_id, check_id))
        conn().commit()


def checks_with_number(code: str, exclude: str | None = None) -> list[dict]:
    rows = conn().execute("SELECT id, created, verdict, masked_text FROM checks WHERE numbers LIKE ? AND id != ?",
                          (f'%"{code}"%', exclude or "")).fetchall()
    return [dict(r) for r in rows]


def recent_checks(limit: int = 50) -> list[dict]:
    rows = conn().execute("SELECT * FROM checks ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
    return [{**dict(r), "numbers": json.loads(r["numbers"]), "links": json.loads(r["links"]),
             "scam_types": json.loads(r["scam_types"])} for r in rows]


OPERATORS = ("mtn", "orange", "camtel", "other")


def analytics(days: int = 14, operator: str = "") -> dict:
    """Desk figures, for one operator or all. Every number is counted from stored checks; nothing is estimated."""
    c = conn()
    where, args = ("WHERE operator = ?", (operator,)) if operator in OPERATORS else ("", ())
    by_day = [dict(r) for r in c.execute(
        f"SELECT substr(created,1,10) AS day, verdict, count(*) AS n FROM checks {where} GROUP BY day, verdict ORDER BY day DESC LIMIT ?", (*args, days * 4))]
    by_operator = {r[0] or "other": {"checks": r[1], "flagged": r[2]} for r in c.execute(
        "SELECT operator, count(*), sum(verdict IN ('scam','suspicious')) FROM checks GROUP BY operator")}
    kept = c.execute(f"SELECT coalesce(sum(amount_fcfa), 0) FROM checks {where} {'AND' if where else 'WHERE'} verdict IN ('scam','suspicious')", args).fetchone()[0]
    flagged = [{k: r[k] for k in ("id", "created", "verdict", "confidence", "operator", "amount_fcfa", "masked_text")} for r in c.execute(
        f"SELECT * FROM checks {where} {'AND' if where else 'WHERE'} verdict IN ('scam','suspicious') ORDER BY created DESC LIMIT 8", args)]
    numbers: dict[str, int] = {}
    types: dict[str, int] = {}
    channels: dict[str, int] = {}
    for r in c.execute(f"SELECT numbers, scam_types, channel, verdict FROM checks {where}", args):
        if r["verdict"] in ("scam", "suspicious"):
            for n in json.loads(r["numbers"] or "[]"):
                numbers[n] = numbers.get(n, 0) + 1
            for t in json.loads(r["scam_types"] or "[]"):
                types[t] = types.get(t, 0) + 1
        channels[r["channel"] or "text"] = channels.get(r["channel"] or "text", 0) + 1
    top = lambda d, k=8: sorted(({"key": a, "n": b} for a, b in d.items()), key=lambda x: -x["n"])[:k]
    total = c.execute(f"SELECT count(*) FROM checks {where}", args).fetchone()[0]
    by = {r[0]: r[1] for r in c.execute(f"SELECT verdict, count(*) FROM checks {where} GROUP BY verdict", args)}
    return {"by_day": by_day, "top_numbers": top(numbers), "top_types": top(types), "channels": channels, "by_operator": by_operator,
            "kept_fcfa": int(kept or 0), "flagged": flagged, "operator": operator if operator in OPERATORS else "",
            "alerts": c.execute("SELECT count(*) FROM alerts WHERE status='published'").fetchone()[0], "total": total, "by_verdict": by}


def radar(days: int = 7) -> dict:
    """What scams are going round right now, from citizens' own checks. Counts only, nothing personal."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    c = conn()
    rows = c.execute("SELECT scheme, count(*) AS n FROM checks WHERE created >= ? AND verdict IN ('scam','suspicious') AND scheme IS NOT NULL "
                     "GROUP BY scheme ORDER BY n DESC LIMIT 6", (since,)).fetchall()
    week = c.execute("SELECT count(*), sum(verdict IN ('scam','suspicious')) FROM checks WHERE created >= ?", (since,)).fetchone()
    return {"days": days, "checks": week[0] or 0, "flagged": week[1] or 0, "top": [{"scheme": r["scheme"], "n": r["n"]} for r in rows]}


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
PUBLIC_ALERT_FIELDS = ("id", "created", "title", "body_en", "body_fr", "numbers", "campaign_id", "contract_id", "prev_hash", "hash", "signature")


def save_receipt(r: dict) -> None:
    with _lock:
        conn().execute("INSERT OR REPLACE INTO receipts VALUES (?,?,?)", (r["id"], r["created"], json.dumps(r)))
        conn().commit()


def get_receipt(rid: str) -> dict | None:
    r = conn().execute("SELECT receipt FROM receipts WHERE id=?", (rid,)).fetchone()
    return json.loads(r["receipt"]) if r else None


CACHE_HOURS = 6


# answers given by older rules are never served after a change: the key carries the rules' own fingerprint
_HERE = os.path.dirname(os.path.abspath(__file__))
RULES = hashlib.sha256(b"".join(open(os.path.join(_HERE, f), "rb").read() for f in ("agents.py", "advice.py", "privacy.py"))).hexdigest()[:12]


def cache_key(text: str, sender: str, language: str) -> str:
    """Same words, same sender, same language: spacing and case do not make a new message."""
    norm = " ".join(text.lower().split())
    return hashlib.sha256(f"{RULES}|{norm}|{sender.strip().lower()}|{language}".encode()).hexdigest()


def cache_get(key: str) -> dict | None:
    r = conn().execute("SELECT card, created, hits FROM answers WHERE key=?", (key,)).fetchone()
    if not r or (datetime.now(timezone.utc) - datetime.fromisoformat(r["created"])).total_seconds() > CACHE_HOURS * 3600:
        return None
    with _lock:
        conn().execute("UPDATE answers SET hits = hits + 1 WHERE key=?", (key,))
        conn().commit()
    return {**json.loads(r["card"]), "cached": r["hits"] + 1}


def cache_put(key: str, card: dict) -> None:
    with _lock:
        conn().execute("INSERT OR REPLACE INTO answers VALUES (?,?,?,0)", (key, now(), json.dumps(card, ensure_ascii=False, default=str)))
        conn().commit()


def cache_clear() -> None:
    with _lock:
        conn().execute("DELETE FROM answers")
        conn().commit()


def publish_alert(row: dict) -> dict:
    from . import ledger
    cache_clear()  # a new alert is new evidence: earlier answers are worked out again
    with _lock:
        last = conn().execute("SELECT hash FROM alerts WHERE status='published' AND hash IS NOT NULL ORDER BY rowid DESC LIMIT 1").fetchone()
        row = {"id": "AL-" + uuid.uuid4().hex[:8], "created": now(), "status": "published", "body_pcm": "", **row}
        row["numbers"] = list(row.get("numbers") or [])
        row = ledger.seal(row, last["hash"] if last else None)
        conn().execute("INSERT INTO alerts (id, created, published_by, campaign_id, title, body_en, body_fr, body_pcm, numbers, status, run_id, contract_id, prev_hash, hash, signature) "
                       "VALUES (:id,:created,:published_by,:campaign_id,:title,:body_en,:body_fr,:body_pcm,:numbers,:status,:run_id,:contract_id,:prev_hash,:hash,:signature)",
                       {**row, "numbers": json.dumps(row["numbers"])})
        conn().commit()
    return row


def alerts(limit: int = 50, oldest_first: bool = False) -> list[dict]:
    """Public view: never includes who published (analyst emails stay private)."""
    order = "ASC" if oldest_first else "DESC"
    rows = conn().execute(f"SELECT * FROM alerts WHERE status='published' ORDER BY rowid {order} LIMIT ?", (limit,)).fetchall()
    return [{k: (json.loads(r[k]) if k == "numbers" else r[k]) for k in PUBLIC_ALERT_FIELDS} for r in rows]
