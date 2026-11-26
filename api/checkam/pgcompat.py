"""PostgreSQL behind the same small interface the case store uses for SQLite.

Set CHECKAM_DATABASE_URL (postgresql://user:password@host:5432/dbname) to keep the case store in PostgreSQL, for example
Huawei Cloud RDS for PostgreSQL, so that several instances of the service share one database. Without it the store stays in
SQLite exactly as before. The store writes its SQL once, in the SQLite dialect; this module translates the few places where
PostgreSQL differs (placeholders, "INSERT OR REPLACE", identifiers that are keywords) so nothing else has to change."""
import re
from decimal import Decimal

# column order and primary key of every table, used to turn INSERT OR REPLACE into an upsert
TABLES: dict[str, tuple[list[str], list[str]]] = {
    "checks": (["id", "created", "masked_text", "verdict", "confidence", "language", "numbers", "links", "scam_types", "campaign_id", "run_id", "channel",
                "operator", "amount_fcfa", "scheme"], ["id"]),
    "analysts": (["email", "name", "org", "role", "salt", "pw_hash", "created"], ["email"]),
    "receipts": (["id", "created", "receipt"], ["id"]),
    "answers": (["key", "created", "card", "hits"], ["key"]),
    "settings": (["key", "value"], ["key"]),
    "alert_i18n": (["alert_id", "title_fr"], ["alert_id"]),
    "alert_hidden": (["alert_id", "reason", "at", "by"], ["alert_id"]),
    "admin_2fa": (["email", "secret_enc", "enrolled_at", "last_step", "recovery"], ["email"]),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (
  id TEXT PRIMARY KEY, created TEXT, masked_text TEXT, verdict TEXT, confidence REAL, language TEXT,
  numbers TEXT, links TEXT, scam_types TEXT, campaign_id TEXT, run_id TEXT, channel TEXT,
  operator TEXT, amount_fcfa BIGINT, scheme TEXT
);
CREATE TABLE IF NOT EXISTS analysts (
  email TEXT PRIMARY KEY, name TEXT, org TEXT, role TEXT, salt TEXT, pw_hash TEXT, created TEXT
);
CREATE TABLE IF NOT EXISTS receipts (id TEXT PRIMARY KEY, created TEXT, receipt TEXT);
CREATE TABLE IF NOT EXISTS answers (key TEXT PRIMARY KEY, created TEXT, card TEXT, hits INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS flags (
  id TEXT PRIMARY KEY, created TEXT, check_id TEXT, verdict TEXT, suggested TEXT, note TEXT, status TEXT, reviewed_by TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY, created TEXT, published_by TEXT, campaign_id TEXT, title TEXT, body_en TEXT,
  body_fr TEXT, body_pcm TEXT, numbers TEXT, status TEXT, run_id TEXT,
  contract_id TEXT, prev_hash TEXT, hash TEXT, signature TEXT, rowid BIGSERIAL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS monthly_stats (month TEXT, scheme TEXT, verdict TEXT, n INTEGER, PRIMARY KEY (month, scheme, verdict));
CREATE TABLE IF NOT EXISTS alert_i18n (alert_id TEXT PRIMARY KEY, title_fr TEXT);
CREATE TABLE IF NOT EXISTS alert_hidden (alert_id TEXT PRIMARY KEY, reason TEXT, at TEXT, "by" TEXT);
CREATE TABLE IF NOT EXISTS admin_2fa (email TEXT PRIMARY KEY, secret_enc TEXT, enrolled_at TEXT, last_step INTEGER DEFAULT 0, recovery TEXT DEFAULT '[]');
CREATE TABLE IF NOT EXISTS admin_audit (id BIGSERIAL PRIMARY KEY, at TEXT, who TEXT, action TEXT, detail TEXT);
"""

_REPLACE = re.compile(r"^\s*INSERT\s+OR\s+REPLACE\s+INTO\s+(\w+)\s*(?:\(([^)]*)\))?\s*VALUES\s*(.*)$", re.I | re.S)
_NAMED = re.compile(r"(?<![:\w]):(\w+)")


def _quote(col: str) -> str:
    return '"' + col.strip().strip('"') + '"'


def translate(sql: str, params):
    """SQLite-dialect SQL and parameters in, PostgreSQL SQL and parameters out."""
    m = _REPLACE.match(sql)
    if m:
        table, cols, rest = m.group(1).lower(), m.group(2), m.group(3)
        order, pk = TABLES[table]
        names = [c.strip() for c in cols.split(",")] if cols else order
        updates = ", ".join(f"{_quote(c)} = EXCLUDED.{_quote(c)}" for c in names if c not in pk)
        sql = f"INSERT INTO {table} ({', '.join(_quote(c) for c in names)}) VALUES {rest} ON CONFLICT ({', '.join(_quote(c) for c in pk)}) DO " + \
              (f"UPDATE SET {updates}" if updates else "NOTHING")
    if params is None or (isinstance(params, (tuple, list)) and not params):
        return sql, None
    sql = sql.replace("%", "%%")
    if isinstance(params, dict):
        return _NAMED.sub(lambda mm: f"%({mm.group(1)})s", sql), params
    return sql.replace("?", "%s"), tuple(params)


class Row(dict):
    """A row readable by column name, like sqlite3.Row, and by position."""

    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return dict.__getitem__(self, key)


def _row_factory(cursor):
    names = [c.name for c in (cursor.description or [])]

    def make(values):
        return Row(zip(names, [int(v) if isinstance(v, Decimal) and v == v.to_integral_value() else (float(v) if isinstance(v, Decimal) else v) for v in values]))
    return make


class Conn:
    def __init__(self, url: str):
        import psycopg  # only needed when a PostgreSQL address is configured
        self._c = psycopg.connect(url, autocommit=True, row_factory=_row_factory)
        for statement in [s.strip() for s in SCHEMA.split(";") if s.strip()]:
            self._c.execute(statement)
        # checks saved before the operator column existed: read it back from the stored (masked) text
        self._c.execute("""UPDATE checks SET operator = CASE
            WHEN lower(masked_text) LIKE '%orange%' THEN 'orange'
            WHEN lower(masked_text) LIKE '%camtel%' OR lower(masked_text) LIKE '%blue %' THEN 'camtel'
            WHEN lower(masked_text) LIKE '%mtn%' OR lower(masked_text) LIKE '%momo%' OR lower(masked_text) LIKE '%mobile money%' OR lower(masked_text) LIKE '%mobilemoney%' THEN 'mtn'
            ELSE 'other' END WHERE operator IS NULL""")

    def execute(self, sql: str, params=()):
        sql2, params2 = translate(sql, params)
        return self._c.execute(sql2, params2)

    def commit(self):  # every statement is committed as it runs
        return None

    def close(self):
        self._c.close()
