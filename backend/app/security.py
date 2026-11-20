"""Security configuration and hardening for the Gozetci API.

Threat model: this service accepts *hostile* files by design (suspected malware)
and is meant to run on an analyst's own machine. The main risks are therefore:

- denial of service via crafted/huge uploads (CPU, memory, disk),
- other websites in the analyst's browser talking to the local API
  (CSRF-style cross-origin requests, DNS rebinding),
- exposing the API to the LAN by accident,
- leaking report contents through caches, framing or referrers.

All settings come from environment variables so the same code can run as a
localhost-only demo (the default) or a small shared team deployment.
"""
import asyncio
import hmac
import os
import re
import time
from collections import defaultdict, deque

from fastapi import Header, HTTPException, Request


def _env_list(name: str, default: str) -> list:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


class Settings:
    # Browser origins allowed to call the API (the Vite dev server by default).
    allowed_origins = _env_list(
        "GOZETCI_ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173",
    )
    # Host header allowlist - blocks DNS-rebinding attacks against the local API.
    allowed_hosts = _env_list("GOZETCI_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver")
    # Optional shared secret. Unset = no auth (fine for localhost-only use).
    api_key = os.getenv("GOZETCI_API_KEY", "")
    max_upload_bytes = _env_int("GOZETCI_MAX_UPLOAD_MB", 50) * 1024 * 1024
    # Analysis requests per client IP per minute.
    rate_limit_per_minute = _env_int("GOZETCI_RATE_LIMIT_PER_MINUTE", 30)
    # Analyses allowed to run at the same time (each is CPU-heavy).
    max_concurrent_analyses = _env_int("GOZETCI_MAX_CONCURRENT", 2)
    # Seconds a request may wait for a free analysis slot before getting 503.
    queue_timeout_seconds = _env_int("GOZETCI_QUEUE_TIMEOUT", 30)
    # Interactive /docs is off by default - it's an unnecessary attack surface.
    enable_docs = _env_bool("GOZETCI_ENABLE_DOCS", False)


settings = Settings()


# ---------------------------------------------------------------------------
# Input sanitising
# ---------------------------------------------------------------------------

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
SAMPLE_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$"


def sanitize_filename(name) -> str:
    """Client-supplied filenames are untrusted: drop any path, control chars
    and excess length before the name is echoed in JSON/HTML reports."""
    name = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = _CONTROL_CHARS.sub("", name).strip()
    return name[:255] or "upload.bin"


# ---------------------------------------------------------------------------
# Authentication (optional API key)
# ---------------------------------------------------------------------------

async def require_api_key(x_api_key: str = Header(default="", alias="X-API-Key")):
    if not settings.api_key:
        return
    # Constant-time comparison avoids leaking the key through response timing.
    if not hmac.compare_digest(x_api_key.encode(), settings.api_key.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# ---------------------------------------------------------------------------
# Rate limiting + concurrency limiting
# ---------------------------------------------------------------------------

class RateLimiter:
    """In-memory sliding-window limiter per client IP. Good enough for a
    single-process deployment; use a reverse proxy / Redis for more."""

    def __init__(self, limit: int, window_seconds: int = 60, max_clients: int = 10_000):
        self.limit = limit
        self.window = window_seconds
        self.max_clients = max_clients
        self._hits = defaultdict(deque)

    def check(self, key: str) -> bool:
        now = time.monotonic()
        if len(self._hits) > self.max_clients:
            self._hits.clear()  # bound memory if flooded with spoofed clients
        hits = self._hits[key]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True


rate_limiter = RateLimiter(settings.rate_limit_per_minute)
analysis_slots = asyncio.Semaphore(settings.max_concurrent_analyses)


async def enforce_rate_limit(request: Request):
    client = request.client.host if request.client else "unknown"
    if not rate_limiter.check(client):
        raise HTTPException(
            status_code=429,
            detail="Too many analysis requests - try again in a minute",
            headers={"Retry-After": "60"},
        )


# ---------------------------------------------------------------------------
# ASGI middlewares
# ---------------------------------------------------------------------------

async def _send_json_error(send, status: int, message: str):
    body = ('{"detail": "%s"}' % message).encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"x-content-type-options", b"nosniff"),
            (b"cache-control", b"no-store"),
        ],
    })
    await send({"type": "http.response.body", "body": body})


class BodySizeLimitMiddleware:
    """Rejects oversized request bodies *before* they are fully buffered or
    spooled to disk - checks Content-Length up front and also counts streamed
    bytes, so chunked uploads without a length can't bypass the limit."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        message = f"File too large (max {self.max_bytes // (1024 * 1024)}MB)"
        for key, value in scope.get("headers", []):
            if key == b"content-length":
                try:
                    length = int(value)
                except ValueError:
                    return await _send_json_error(send, 400, "Invalid Content-Length header")
                if length > self.max_bytes:
                    return await _send_json_error(send, 413, message)

        state = {"received": 0, "too_large": False, "replied": False}

        async def limited_receive():
            if state["too_large"]:
                return {"type": "http.disconnect"}
            msg = await receive()
            if msg["type"] == "http.request":
                state["received"] += len(msg.get("body", b""))
                if state["received"] > self.max_bytes:
                    state["too_large"] = True
                    return {"type": "http.disconnect"}
            return msg

        async def guarded_send(msg):
            # Whatever the app tries to answer after the limit tripped (usually
            # a parse error), replace it with one clean 413.
            if state["too_large"]:
                if not state["replied"]:
                    state["replied"] = True
                    await _send_json_error(send, 413, message)
                return
            await send(msg)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except Exception:
            if not state["too_large"]:
                raise
            if not state["replied"]:
                state["replied"] = True
                await _send_json_error(send, 413, message)


API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
# The HTML report only needs its own inline <style>; no scripts, images or fonts.
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")

        async def send_with_headers(msg):
            if msg["type"] == "http.response.start":
                headers = [(k, v) for k, v in msg.get("headers", []) if k.lower() != b"server"]
                extra = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"cross-origin-opener-policy": b"same-origin",
                    b"cross-origin-resource-policy": b"same-origin",
                    b"permissions-policy": b"camera=(), microphone=(), geolocation=(), interest-cohort=()",
                    # Reports describe possibly-sensitive incidents: never cache them.
                    b"cache-control": b"no-store",
                }
                if not path.startswith(DOCS_PATHS):
                    csp = REPORT_CSP if path.startswith("/api/report/") else API_CSP
                    extra[b"content-security-policy"] = csp.encode()
                existing = {k.lower() for k, _ in headers}
                headers += [(k, v) for k, v in extra.items() if k not in existing]
                msg = {**msg, "headers": headers}
            await send(msg)

        await self.app(scope, receive, send_with_headers)
