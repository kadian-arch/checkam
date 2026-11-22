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
CREATE TABLE IF NOT EXISTS flags (
  id TEXT PRIMARY KEY, created TEXT, check_id TEXT, verdict TEXT, suggested TEXT, note TEXT, status TEXT, reviewed_by TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY, created TEXT, published_by TEXT, campaign_id TEXT, title TEXT, body_en TEXT,
  body_fr TEXT, body_pcm TEXT, numbers TEXT, status TEXT, run_id TEXT
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS monthly_stats (month TEXT, scheme TEXT, verdict TEXT, n INTEGER, PRIMARY KEY (month, scheme, verdict));
CREATE TABLE IF NOT EXISTS alert_i18n (alert_id TEXT PRIMARY KEY, title_fr TEXT);
CREATE TABLE IF NOT EXISTS alert_hidden (alert_id TEXT PRIMARY KEY, reason TEXT, at TEXT, by TEXT);
CREATE TABLE IF NOT EXISTS admin_2fa (email TEXT PRIMARY KEY, secret_enc TEXT, enrolled_at TEXT, last_step INTEGER DEFAULT 0, recovery TEXT DEFAULT '[]');
CREATE TABLE IF NOT EXISTS admin_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, who TEXT, action TEXT, detail TEXT);
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
    for verdict, n in c.execute("SELECT verdict, sum(n) FROM monthly_stats GROUP BY verdict"):  # checks already archived
        by[verdict] = by.get(verdict, 0) + (n or 0)
        total += n or 0
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


def add_flag(check_id: str, suggested: str, note: str) -> dict | None:
    """A person says an answer looks wrong. It waits for an analyst; it never changes an answer by itself."""
    c = conn().execute("SELECT verdict FROM checks WHERE id = ?", (check_id,)).fetchone()
    if not c:
        return None
    row = {"id": "F-" + uuid.uuid4().hex[:8], "created": now(), "check_id": check_id, "verdict": c["verdict"], "suggested": suggested,
           "note": note[:500], "status": "open", "reviewed_by": None}
    with _lock:
        conn().execute("INSERT INTO flags VALUES (:id, :created, :check_id, :verdict, :suggested, :note, :status, :reviewed_by)", row)
        conn().commit()
    return row


def open_flags(limit: int = 50) -> list[dict]:
    rows = conn().execute("SELECT f.*, c.masked_text FROM flags f LEFT JOIN checks c ON c.id = f.check_id WHERE f.status = 'open' ORDER BY f.created DESC LIMIT ?",
                          (limit,)).fetchall()
    return [dict(r) for r in rows]


def close_flag(flag_id: str, status: str, analyst: str) -> dict | None:
    with _lock:
        conn().execute("UPDATE flags SET status = ?, reviewed_by = ? WHERE id = ? AND status = 'open'", (status, analyst, flag_id))
        conn().commit()
    r = conn().execute("SELECT f.*, c.masked_text FROM flags f LEFT JOIN checks c ON c.id = f.check_id WHERE f.id = ?", (flag_id,)).fetchone()
    return dict(r) if r else None


def get_check(check_id: str) -> dict | None:
    r = conn().execute("SELECT * FROM checks WHERE id = ?", (check_id,)).fetchone()
    return dict(r) if r else None


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


def alerts(limit: int = 50, oldest_first: bool = False, display: bool = False) -> list[dict]:
    """Public view: never includes who published (analyst emails stay private). display=True is the home-page list:
    retracted alerts and alerts older than the display window are left out. The signed log (display=False) keeps all."""
    order = "ASC" if oldest_first else "DESC"
    rows = conn().execute(f"SELECT * FROM alerts WHERE status='published' ORDER BY rowid {order}" + ("" if display else " LIMIT ?"),
                          () if display else (limit,)).fetchall()
    hidden = {r[0] for r in conn().execute("SELECT alert_id FROM alert_hidden")}
    fr = {r[0]: r[1] for r in conn().execute("SELECT alert_id, title_fr FROM alert_i18n")}
    cut = (datetime.now(timezone.utc) - timedelta(days=settings()["alert_show_days"])).isoformat(timespec="seconds") if display else ""
    out = []
    for r in rows:
        if display and (r["id"] in hidden or r["created"] < cut):
            continue
        item = {k: (json.loads(r[k]) if k == "numbers" else r[k]) for k in PUBLIC_ALERT_FIELDS}
        item["title_fr"] = fr.get(r["id"]) or ""
        out.append(item)
    return out[:limit]


def set_title_fr(alert_id: str, title_fr: str) -> None:
    """The French title sits beside the signed record, not inside it: the signature covers the English title, and
    adding a field to old signed alerts would break their proof."""
    with _lock:
        conn().execute("INSERT OR REPLACE INTO alert_i18n VALUES (?,?)", (alert_id, title_fr[:200]))
        conn().commit()


def alerts_missing_title_fr() -> list[dict]:
    rows = conn().execute("SELECT a.id, a.title FROM alerts a LEFT JOIN alert_i18n i ON i.alert_id = a.id "
                          "WHERE a.status='published' AND (i.title_fr IS NULL OR i.title_fr = '')").fetchall()
    return [dict(r) for r in rows]


def retract_alert(alert_id: str, reason: str, who: str) -> bool:
    """Take an alert off the public page. The signed record stays in the log, so the chain still verifies."""
    if not conn().execute("SELECT 1 FROM alerts WHERE id=?", (alert_id,)).fetchone():
        return False
    with _lock:
        conn().execute("INSERT OR REPLACE INTO alert_hidden VALUES (?,?,?,?)", (alert_id, reason[:300], now(), who))
        conn().commit()
    return True


def restore_alert(alert_id: str) -> bool:
    with _lock:
        n = conn().execute("DELETE FROM alert_hidden WHERE alert_id=?", (alert_id,)).rowcount
        conn().commit()
    return n > 0


def all_alerts_for_admin() -> list[dict]:
    hidden = {r[0]: r[1] for r in conn().execute("SELECT alert_id, reason FROM alert_hidden")}
    out = []
    for a in alerts(10_000):
        out.append({"id": a["id"], "created": a["created"], "title": a["title"], "title_fr": a["title_fr"], "hidden": a["id"] in hidden, "reason": hidden.get(a["id"], "")})
    return out


# ---------- retention and administration ----------
DEFAULTS = {"check_keep_days": 730, "archive_keep_days": 2190, "answer_keep_days": 30, "alert_show_days": 90}
BOUNDS = {"check_keep_days": (30, 3650), "archive_keep_days": (0, 3650), "answer_keep_days": (1, 365), "alert_show_days": (7, 3650)}


def settings() -> dict:
    rows = {r[0]: r[1] for r in conn().execute("SELECT key, value FROM settings")}
    out = dict(DEFAULTS)
    for k in DEFAULTS:
        if k in rows:
            try:
                out[k] = int(rows[k])
            except ValueError:
                pass
    return out


def set_setting(key: str, value: str) -> None:
    with _lock:
        conn().execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, value))
        conn().commit()


def get_setting(key: str, default: str = "") -> str:
    r = conn().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r[0] if r else default


def update_settings(changes: dict) -> dict:
    for k, v in changes.items():
        if k not in DEFAULTS:
            raise ValueError(f"unknown setting {k}")
        lo, hi = BOUNDS[k]
        if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
            raise ValueError(f"{k} must be a whole number from {lo} to {hi}")
    for k, v in changes.items():
        set_setting(k, str(v))
    return settings()


def old_checks(cutoff: str) -> list[dict]:
    return [dict(r) for r in conn().execute("SELECT * FROM checks WHERE created < ? ORDER BY created", (cutoff,)).fetchall()]


def add_monthly(rows: list[dict]) -> None:
    """Anonymous counts by month, kind of scam and verdict: kept for good, so totals and trends survive the archive."""
    with _lock:
        for r in rows:
            conn().execute("INSERT INTO monthly_stats VALUES (?,?,?,1) ON CONFLICT(month, scheme, verdict) DO UPDATE SET n = n + 1",
                           ((r.get("created") or "")[:7], r.get("scheme") or "unknown", r.get("verdict") or "unknown"))
        conn().commit()


def delete_check(check_id: str) -> dict:
    """Remove one saved check and what hangs off it (its signed-answer record, review flags). Answers are cached by
    message, not by check, so the cache is cleared too."""
    with _lock:
        out = {
            "checks": conn().execute("DELETE FROM checks WHERE id = ?", (check_id,)).rowcount,
            "receipts": conn().execute("DELETE FROM receipts WHERE id = ?", (check_id,)).rowcount,
            "flags": conn().execute("DELETE FROM flags WHERE check_id = ?", (check_id,)).rowcount,
        }
        conn().commit()
    cache_clear()
    return out


def admin_log(who: str, action: str, detail: str = "") -> None:
    with _lock:
        conn().execute("INSERT INTO admin_audit (at, who, action, detail) VALUES (?,?,?,?)", (now(), who, action, detail[:500]))
        conn().commit()


def admin_audit(limit: int = 50) -> list[dict]:
    return [dict(r) for r in conn().execute("SELECT at, who, action, detail FROM admin_audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]


def analyst_role(email: str) -> str:
    r = conn().execute("SELECT role FROM analysts WHERE email=?", (email.lower(),)).fetchone()
    return (r["role"] if r else "") or ""


def counts() -> dict:
    c = conn()
    one = lambda sql: c.execute(sql).fetchone()[0]
    return {"checks": one("SELECT count(*) FROM checks"), "receipts": one("SELECT count(*) FROM receipts"), "answers_cached": one("SELECT count(*) FROM answers"),
            "flags_open": one("SELECT count(*) FROM flags WHERE status='open'"), "alerts": one("SELECT count(*) FROM alerts WHERE status='published'"),
            "alerts_hidden": one("SELECT count(*) FROM alert_hidden"), "archived_checks": one("SELECT coalesce(sum(n),0) FROM monthly_stats"),
            "analysts": one("SELECT count(*) FROM analysts")}


def purge_old() -> dict:
    """Delete what has outlived its use, using the retention settings. Open review flags are kept until an analyst has read them."""
    cfg = settings()
    cut = lambda days: (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    old, stale = cut(cfg["check_keep_days"]), cut(cfg["answer_keep_days"])
    out = {}
    with _lock:
        for name, sql, arg in (
            ("checks", "DELETE FROM checks WHERE created < ?", old),
            ("receipts", "DELETE FROM receipts WHERE created < ?", old),
            ("flags", "DELETE FROM flags WHERE created < ? AND status != 'open'", old),
            ("answers", "DELETE FROM answers WHERE created < ?", stale),
        ):
            out[name] = conn().execute(sql, (arg,)).rowcount
        conn().commit()
    return out


def purge_preview() -> dict:
    cfg = settings()
    cut = lambda days: (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    old, stale = cut(cfg["check_keep_days"]), cut(cfg["answer_keep_days"])
    q = lambda sql, arg: conn().execute(sql, (arg,)).fetchone()[0]
    return {"checks": q("SELECT count(*) FROM checks WHERE created < ?", old), "receipts": q("SELECT count(*) FROM receipts WHERE created < ?", old),
            "flags": q("SELECT count(*) FROM flags WHERE created < ? AND status != 'open'", old), "answers": q("SELECT count(*) FROM answers WHERE created < ?", stale)}


def list_analysts() -> list[dict]:
    return [dict(r) for r in conn().execute("SELECT email, name, org, role, created FROM analysts ORDER BY created").fetchall()]


def delete_analyst(email: str) -> bool:
    with _lock:
        n = conn().execute("DELETE FROM analysts WHERE email = ?", (email.lower(),)).rowcount
        conn().commit()
    return n > 0


def flags_for_check(check_id: str) -> list[dict]:
    return [dict(r) for r in conn().execute("SELECT id, created, verdict, suggested, note, status, reviewed_by FROM flags WHERE check_id = ? ORDER BY created DESC", (check_id,)).fetchall()]


def check_detail(check_id: str) -> dict | None:
    r = conn().execute("SELECT * FROM checks WHERE id = ?", (check_id,)).fetchone()
    if not r:
        return None
    d = dict(r)
    for k in ("numbers", "links", "scam_types"):
        try:
            d[k] = json.loads(d.get(k) or "[]")
        except ValueError:
            d[k] = []
    return d


def update_analyst(email: str, name: str | None, org: str | None, password: str | None) -> bool:
    """Change an account's name, organisation or password. The role never changes here."""
    r = conn().execute("SELECT * FROM analysts WHERE email = ?", (email.lower(),)).fetchone()
    if not r:
        return False
    salt, pw_hash = r["salt"], r["pw_hash"]
    if password:
        salt = os.urandom(16).hex()
        pw_hash = _hash(password, salt)
    with _lock:
        conn().execute("UPDATE analysts SET name = ?, org = ?, salt = ?, pw_hash = ? WHERE email = ?",
                       (name if name is not None else r["name"], org if org is not None else r["org"], salt, pw_hash, email.lower()))
        conn().commit()
    return True


# ---------- two-step sign-in (the administrator) ----------
def twofa_get(email: str) -> dict | None:
    r = conn().execute("SELECT * FROM admin_2fa WHERE email = ?", (email.lower(),)).fetchone()
    return dict(r) if r else None


def twofa_start(email: str, secret_enc: str) -> None:
    """A pending secret, replaced each time set-up is shown again, until a first code proves the phone has it."""
    with _lock:
        conn().execute("INSERT OR REPLACE INTO admin_2fa (email, secret_enc, enrolled_at, last_step, recovery) VALUES (?,?,NULL,0,'[]')", (email.lower(), secret_enc))
        conn().commit()


def twofa_enroll(email: str, step: int, recovery_hashes: list[str]) -> None:
    with _lock:
        conn().execute("UPDATE admin_2fa SET enrolled_at = ?, last_step = ?, recovery = ? WHERE email = ?", (now(), step, json.dumps(recovery_hashes), email.lower()))
        conn().commit()


def twofa_step(email: str, step: int) -> None:
    with _lock:
        conn().execute("UPDATE admin_2fa SET last_step = ? WHERE email = ?", (step, email.lower()))
        conn().commit()


def twofa_use_recovery(email: str, code_hash: str) -> bool:
    """A recovery code works once."""
    with _lock:
        r = conn().execute("SELECT recovery FROM admin_2fa WHERE email = ?", (email.lower(),)).fetchone()
        codes = json.loads(r["recovery"]) if r else []
        if code_hash not in codes:
            return False
        codes.remove(code_hash)
        conn().execute("UPDATE admin_2fa SET recovery = ? WHERE email = ?", (json.dumps(codes), email.lower()))
        conn().commit()
    return True


def twofa_clear(email: str) -> None:
    with _lock:
        conn().execute("DELETE FROM admin_2fa WHERE email = ?", (email.lower(),))
        conn().commit()


def analyst_public(email: str) -> dict | None:
    r = conn().execute("SELECT email, name, org, role FROM analysts WHERE email = ?", (email.lower(),)).fetchone()
    return dict(r) if r else None
