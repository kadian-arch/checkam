import json
import sys
import threading
import time
import uuid
from datetime import datetime, timezone

from . import config


def _short(v, n=200):
    from .privacy import mask
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, default=str)
    s = mask(s)
    return s if len(s) <= n else s[: n - 3] + "..."


class Trace:
    """One run: every agent step, Zetaris query and model call lands in logs/trace-<run_id>.jsonl."""

    def __init__(self, run_id: str | None = None, echo: bool = True, on_line=None):
        self.on_line = on_line  # live listener (the phone app streams every step as it happens)
        self._lock = threading.Lock()
        self.run_id = run_id or uuid.uuid4().hex[:12]
        self.lines: list[dict] = []
        self.echo = echo
        config.LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.path = config.LOG_DIR / f"trace-{self.run_id}.jsonl"

    def log(self, agent: str, action: str, *, input=None, output=None, target=None, confidence=None,
            retry=0, status="ok", sponsor="none", latency_ms=None, **extra) -> dict:
        line = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "run_id": self.run_id,
            "agent_name": agent,
            "action": action,
            "input_summary": _short(input) if input is not None else None,
            "output_summary": _short(output) if output is not None else None,
            "target_agent": target,
            "confidence": confidence,
            "retry_count": retry,
            "status": status,
            "sponsor": sponsor,
            "latency_ms": latency_ms,
            **extra,
        }
        with self._lock:  # agents log from parallel threads
            self.lines.append(line)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(line, ensure_ascii=False, default=str) + "\n")
        if self.on_line:
            try:
                self.on_line(line)
            except Exception:
                pass
        if self.echo:
            print(f"[{self.run_id}] {agent}.{action} {status} {sponsor} {line['output_summary'] or ''}"[:220], file=sys.stderr)
        return line


class timer:
    def __enter__(self):
        self.t = time.perf_counter()
        return self

    def __exit__(self, *a):
        self.ms = round((time.perf_counter() - self.t) * 1000)
