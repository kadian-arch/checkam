"""Abuse limits and response headers. Checks call paid models, so every client gets a fair share;
sign-in is throttled against password guessing."""
import threading
import time
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse

# (requests, seconds) per client IP, per route group
LIMITS = {
    "check": [(8, 60), (60, 3600)],
    "login": [(5, 60), (20, 3600)],
    "analyst": [(120, 60)],
    "default": [(240, 60)],
}
_hits: dict[tuple[str, str], deque] = defaultdict(deque)
_lock = threading.Lock()

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
       "font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; "
       "base-uri 'none'; form-action 'self'; object-src 'none'")


def group(path: str) -> str:
    if path.startswith("/check") or path == "/run":
        return "check"
    if path.startswith("/auth"):
        return "login"
    if path.startswith("/analyst"):
        return "analyst"
    return "default"


def client_ip(request: Request) -> str:
    """The address our own proxy saw. A client can put anything at the start of X-Forwarded-For, so only
    the last entry (added by Render's proxy) is trusted; locally there is no proxy and the socket is used."""
    fwd = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    return fwd[-1] if fwd else (request.client.host if request.client else "?")


MAX_BODY = 8_000_000


def allowed(ip: str, g: str) -> tuple[bool, int]:
    now = time.monotonic()
    longest = max(w for _, w in LIMITS[g])
    with _lock:
        q = _hits[(ip, g)]
        while q and now - q[0] > longest:
            q.popleft()
        for n, window in LIMITS[g]:
            recent = sum(1 for t in q if now - t <= window)
            if recent >= n:
                oldest = next(t for t in q if now - t <= window)
                return False, int(window - (now - oldest)) + 1
        q.append(now)
    return True, 0


async def middleware(request: Request, call_next):
    size = request.headers.get("content-length", "")
    if size.isdigit() and int(size) > MAX_BODY:
        return JSONResponse({"detail": "Request too large."}, status_code=413)
    if request.method != "GET" or request.url.path.startswith(("/analyst", "/traces")):
        ok, wait = allowed(client_ip(request), group(request.url.path))
        if not ok:
            return JSONResponse({"detail": f"Too many requests. Try again in {wait} s."}, status_code=429, headers={"Retry-After": str(wait)})
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    if not request.url.path.startswith(("/docs", "/openapi")):
        resp.headers.setdefault("Content-Security-Policy", CSP)
    if request.headers.get("x-forwarded-proto") == "https":
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    path = request.url.path
    if path.startswith("/assets/"):
        resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"  # file names change with every build
    elif path.endswith((".png", ".svg", ".ico", ".webmanifest", ".woff2")):
        resp.headers.setdefault("Cache-Control", "public, max-age=86400")
    elif resp.headers.get("content-type", "").startswith("text/html"):
        resp.headers["Cache-Control"] = "no-cache"  # the page always asks for the newest build
    return resp


class Compress:
    """gzip for pages, scripts and JSON; never for the live agent streams, which must reach the phone step by step."""

    def __init__(self, app):
        from starlette.middleware.gzip import GZipMiddleware
        self.app, self.gzip = app, GZipMiddleware(app, minimum_size=800)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and not scope["path"].endswith("/stream"):
            await self.gzip(scope, receive, send)
        else:
            await self.app(scope, receive, send)
