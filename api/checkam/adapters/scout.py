"""Client for Scout (Meterless Scout Intent engine, TypeScript service): intent, guard, signed contracts."""
from . import breaker

from .. import config
from ..trace import Trace, timer


def _post(path: str, body: dict, trace: Trace | None, agent: str, action: str):
    with timer() as t:
        r = breaker.request("scout", "POST", f"{config.SCOUT_URL}{path}", json=body)
        data = r.json() if r is not None and r.status_code < 500 else None
    if trace:
        if data is None:
            trace.log(agent, action, output=f"scout unreachable", status="error", sponsor="meterless", latency_ms=t.ms)
        else:
            summary = {k: data.get(k) for k in ("intent", "band", "confidence", "ok", "reason") if k in data}
            if "risk" in data:
                summary["risk"] = data["risk"]["level"]
            if data.get("injection"):
                summary["injection"] = data["injection"]["kind"]
            if data.get("executionContract"):
                summary["contract"] = data["executionContract"]["contractId"]
            trace.log(agent, action, output=summary, sponsor="meterless", latency_ms=t.ms,
                      status="rejected" if summary.get("risk") == "block" else "ok")
    return data


def decide(prompt: str, surface: str, role: str, trace: Trace | None = None, agent: str = "Intake", user_id: str = "anonymous"):
    return _post("/decide", {"prompt": prompt, "surface": surface, "user": {"id": user_id, "role": role}}, trace, agent, "scout_decide")


def approve(contract: dict, by: str, trace: Trace | None = None):
    out = _post("/approve", {"contract": contract, "approval": "operator-review", "by": by}, trace, "Reporter", "scout_approve")
    return (out or {}).get("contract")


def verify(contract: dict, capability: str, trace: Trace | None = None) -> bool:
    out = _post("/verify", {"contract": contract, "capability": capability, "engine": "checkam-api"}, trace, "Reporter", "scout_verify")
    return bool(out and out.get("ok"))
