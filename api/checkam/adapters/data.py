"""Data access. Zetaris is the source of record (JDBC first, REST second). Sample mode runs
the same SQL on the same parquet files with DuckDB, so the agents never know the difference."""
import json
import os
import threading
import uuid
from pathlib import Path

import httpx

from .. import config
from ..trace import Trace, timer

TABLES = ["messages", "reports", "public_alerts", "genuine_messages", "scam_numbers"]


def _py(v):
    # JDBC arrays come back as JSON text or Java objects; make them plain lists
    if isinstance(v, str) and v[:1] == "[" and v[-1:] == "]":
        try:
            return json.loads(v)
        except ValueError:
            return v
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if type(v).__name__.startswith("java.lang."):
        return str(v)
    if hasattr(v, "getArray"):
        v = v.getArray()
    try:
        return [_py(x) for x in v] if not isinstance(v, (bytes, dict)) else v
    except TypeError:
        return str(v)


class ZetarisJDBC:
    name = "zetaris-jdbc"

    def __init__(self):
        self._conn = None
        self._lock = threading.Lock()

    def _connect(self):
        if self._conn is None:
            import jaydebeapi
            if not os.environ.get("JAVA_HOME"):
                jdk = Path(r"C:\Program Files\Java")
                cand = sorted(jdk.glob("jdk-*")) if jdk.exists() else []
                if cand:
                    os.environ["JAVA_HOME"] = str(cand[-1])
            self._conn = jaydebeapi.connect("com.zetaris.lightning.jdbc.LightningDriver", config.ZETARIS_JDBC_URL,
                                            [config.ZETARIS_USER, config.ZETARIS_PASSWORD], config.ZETARIS_JDBC_JAR)
        return self._conn

    def query(self, sql: str) -> list[dict]:
        with self._lock:
            cur = self._connect().cursor()
            try:
                cur.execute(sql)
                cols = [d[0] for d in cur.description] if cur.description else []
                return [dict(zip(cols, map(_py, row))) for row in cur.fetchall()] if cols else []
            finally:
                cur.close()


class ZetarisREST:
    name = "zetaris-rest"

    def query(self, sql: str) -> list[dict]:
        r = httpx.post(f"{config.ZETARIS_REST_URL}/sql-editor/sqls/run", timeout=60,
                       headers={"Authorization": f"Bearer {config.ZETARIS_API_KEY}", "X-Org-ID": config.ZETARIS_ORG_ID,
                                "X-Request-ID": str(uuid.uuid4()), "Content-Type": "application/json"},
                       json={"sql": sql, "query": sql})
        r.raise_for_status()
        data = r.json()
        body = data.get("data", data) if isinstance(data, dict) else data
        if isinstance(body, dict) and "columns" in body and "rows" in body:
            cols = [c["name"] if isinstance(c, dict) else c for c in body["columns"]]
            return [dict(zip(cols, row)) for row in body["rows"]]
        if isinstance(body, list):
            return body
        raise RuntimeError(f"unexpected REST shape: {json.dumps(data)[:200]}")


class Sample:
    name = "sample-duckdb"

    def __init__(self, folder: Path = config.SAMPLE_DIR):
        import duckdb
        self.db = duckdb.connect()
        self._lock = threading.Lock()
        self.db.execute(f"CREATE SCHEMA {config.ZETARIS_DB}")
        for t in TABLES:
            p = folder / f"{t}.parquet"
            if p.exists():
                self.db.execute(f"CREATE VIEW {config.ZETARIS_DB}.{t} AS SELECT * FROM read_parquet('{p.as_posix()}')")

    def query(self, sql: str) -> list[dict]:
        with self._lock:
            cur = self.db.execute(sql)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, map(_py, row))) for row in cur.fetchall()]


class Data:
    """run_sql with a timeout-free fallback chain and a trace line per call."""

    def __init__(self):
        self.chain = [Sample()] if config.SAMPLE_MODE else [ZetarisJDBC(), ZetarisREST(), Sample()]

    @property
    def mode(self) -> str:
        return self.chain[0].name

    def sql(self, sql: str, trace: Trace | None = None, agent: str = "Investigator", why: str = "") -> list[dict]:
        last = None
        for i, backend in enumerate(self.chain):
            with timer() as t:
                try:
                    rows = backend.query(sql)
                except Exception as e:  # fall through to the next backend
                    last = e
                    rows = None
            sponsor = "zetaris" if backend.name.startswith("zetaris") else "none"
            if trace:
                trace.log(agent, "sql", input=sql, output=f"{len(rows)} rows" if rows is not None else f"error: {last}",
                          status="ok" if rows is not None else "error", sponsor=sponsor, latency_ms=t.ms,
                          retry=i, backend=backend.name, why=why)
            if rows is not None:
                if i:  # demote broken backends for the rest of the process
                    self.chain = self.chain[i:]
                return rows
        raise RuntimeError(f"all data backends failed: {last}")


_data: Data | None = None


def data() -> Data:
    global _data
    if _data is None:
        _data = Data()
    return _data
