"""Client for the campaign graph (Meterless World Model engine, TypeScript service)."""
from . import breaker

from .. import config
from ..trace import Trace, timer

SOURCE = "stop-arnaque-237"
CHECKS = "checkam-check"


def _call(method: str, path: str, trace: Trace | None, agent: str, action: str, **kw):
    with timer() as t:
        r = breaker.request("world", method, f"{config.WORLD_MODEL_URL}{path}", **kw)
        if r is None:
            data, ok = {"error": "world model unreachable"}, False
        else:
            data = r.json() if r.status_code < 500 else None
            ok = r.status_code < 400
    if trace:
        summary = {k: v for k, v in (data or {}).items() if k not in ("campaigns", "campaign", "audit")} if isinstance(data, dict) else data
        trace.log(agent, action, input=path, output=summary, status="ok" if ok else "error", sponsor="meterless", latency_ms=t.ms)
    return data if ok else None


def health() -> dict | None:
    return _call("GET", "/health", None, "", "")


def ingest(observations: list[dict], trace: Trace | None = None, agent: str = "Investigator") -> dict | None:
    return _call("POST", "/ingest", trace, agent, "world_ingest", json={"observations": observations})


def campaigns(trace: Trace | None = None, agent: str = "Investigator") -> list[dict]:
    out = _call("GET", "/campaigns", trace, agent, "world_campaigns")
    return (out or {}).get("campaigns", [])


def context(obs_id: str, source: str = CHECKS, trace: Trace | None = None, agent: str = "Investigator") -> dict | None:
    return _call("GET", f"/context?source={source}&id={obs_id}", trace, agent, "world_context")


def observation(obs_id: str, source: str = SOURCE) -> dict | None:
    return _call("GET", f"/observation?source={source}&id={obs_id}", None, "", "")
