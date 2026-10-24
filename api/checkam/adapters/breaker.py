"""Fail fast when a local engine is down: short connect timeout, then skip it for a while."""
import time

import httpx

TIMEOUT = httpx.Timeout(10.0, connect=1.5)
_down: dict[str, float] = {}
COOL_OFF = 30.0


def request(service: str, method: str, url: str, **kw) -> httpx.Response | None:
    if not url.split("//", 1)[-1].split("/")[0] or time.monotonic() < _down.get(service, 0):
        return None
    try:
        r = httpx.request(method, url, timeout=TIMEOUT, **kw)
        _down.pop(service, None)
        return r
    except httpx.HTTPError:
        _down[service] = time.monotonic() + COOL_OFF
        return None
