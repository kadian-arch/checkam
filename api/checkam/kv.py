"""Optional shared cache and counters in Redis (Huawei Cloud DCS for Redis, or any Redis).

Set CHECKAM_REDIS_URL (redis://:password@host:6379/0, or rediss:// for TLS) to turn it on. It carries two things that must be
shared when the service runs on more than one instance: repeat answers (so the second person with the same message gets the
answer in about a second) and the per-client request counters. Without it, or whenever Redis does not answer, everything keeps
working from the local database and memory: Redis is an accelerator, never a dependency."""
import os
import threading
import time

_client = None
_down_until = 0.0
_lock = threading.Lock()


def _make():
    url = os.environ.get("CHECKAM_REDIS_URL", "").strip()
    if not url:
        return None
    try:
        import redis  # imported only when configured
        return redis.Redis.from_url(url, socket_connect_timeout=1.0, socket_timeout=1.0, decode_responses=True)
    except Exception:
        return None


def client():
    """The Redis client, or None when it is not configured or was unreachable in the last 30 seconds."""
    global _client, _down_until
    if time.monotonic() < _down_until:
        return None
    with _lock:
        if _client is None:
            _client = _make()
    return _client


def failed() -> None:
    """Redis did not answer: stop asking for 30 seconds so every request is not slowed down."""
    global _down_until
    _down_until = time.monotonic() + 30


def enabled() -> bool:
    return client() is not None


def get(key: str) -> str | None:
    c = client()
    if c is None:
        return None
    try:
        return c.get(key)
    except Exception:
        failed()
        return None


def put(key: str, value: str, seconds: int) -> bool:
    c = client()
    if c is None:
        return False
    try:
        c.set(key, value, ex=seconds)
        return True
    except Exception:
        failed()
        return False


def incr(key: str, seconds: int) -> int | None:
    """Add one to a counter that expires after `seconds`; None when Redis is not available."""
    c = client()
    if c is None:
        return None
    try:
        n = c.incr(key)
        if n == 1:
            c.expire(key, seconds)
        return int(n)
    except Exception:
        failed()
        return None


def delete_prefix(prefix: str) -> None:
    c = client()
    if c is None:
        return
    try:
        for k in c.scan_iter(match=prefix + "*", count=200):
            c.delete(k)
    except Exception:
        failed()
