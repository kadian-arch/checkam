"""Client for CheckAm's memory (Meterless H-MEM engine, TypeScript service): what analysts corrected and confirmed."""
from . import breaker

from .. import config
from ..trace import Trace, timer


def _call(method: str, path: str, trace: Trace | None, agent: str, action: str, **kw):
    with timer() as t:
        r = breaker.request("hmem", method, f"{config.HMEM_URL}{path}", **kw)
        data = r.json() if r is not None and r.status_code < 500 else None
        ok = r is not None and r.status_code < 400
    if trace:
        out = {"memories": len((data or {}).get("memories", []))} if isinstance(data, dict) and "memories" in data else data
        trace.log(agent, action, input=path, output=out if ok else "memory engine unreachable", status="ok" if ok else "error",
                  sponsor="meterless", latency_ms=t.ms)
    return data if ok else None


def health() -> dict | None:
    return _call("GET", "/health", None, "", "")


def recall(text: str, trace: Trace | None = None, top: int = 3) -> list[dict]:
    return (_call("POST", "/recall", trace, "Investigator", "memory_recall", json={"query": text[:2000], "topN": top}) or {}).get("memories", [])


def remember(content: str, kind: str, verdict: str, source: str, refs: list[str], trace: Trace | None = None, label: str = "") -> dict | None:
    return _call("POST", "/remember", trace, "Reporter", "memory_remember",
                 json={"content": content, "kind": kind, "verdict": verdict, "source": source, "refs": refs[:5], "label": label or kind})


def sleep(trace: Trace | None = None) -> dict | None:
    return _call("POST", "/sleep", trace, "Critic", "memory_sleep")


def memories(n: int = 50) -> list[dict]:
    return (_call("GET", f"/memories?n={n}", None, "", "") or {}).get("memories", [])
