"""HTTP hardening: client IP behind proxies, login throttling and security headers."""
import threading
import time
from collections import deque
from fastapi import Request
from app.core.config import settings


def client_ip(request: Request | None) -> str | None:
    """Socket peer, or the address appended by the last trusted proxy (TRUSTED_PROXY_HOPS). Entries further left
    in X-Forwarded-For are written by the client and are never trusted."""
    if request is None: return None
    peer = request.client.host if request.client else None
    hops = settings.trusted_proxy_hops
    if hops <= 0: return peer
    chain = [x.strip() for x in request.headers.get("x-forwarded-for", "").split(",") if x.strip()]
    return chain[-hops][:64] if len(chain) >= hops else peer


class Throttle:
    """In-memory sliding window of failures per key. Per process: with several instances each one counts on its own."""

    def __init__(self, max_keys: int = 50_000):
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()
        self._max_keys = max_keys

    def _window(self) -> float:
        return settings.login_window_minutes * 60

    def _recent(self, key: str, now: float) -> deque:
        hits = self._hits.get(key)
        if hits is None: return deque()
        while hits and now - hits[0] > self._window(): hits.popleft()
        if not hits: self._hits.pop(key, None)
        return hits

    def retry_after(self, key: str, limit: int) -> int:
        """Seconds until the key may try again; 0 when it is not blocked."""
        if limit <= 0: return 0
        with self._lock:
            now = time.monotonic()
            hits = self._recent(key, now)
            return int(self._window() - (now - hits[0])) + 1 if len(hits) >= limit else 0

    def fail(self, key: str, limit: int) -> bool:
        """Record a failure; True when this one reaches the limit (the key becomes blocked)."""
        if limit <= 0: return False
        with self._lock:
            now = time.monotonic()
            hits = self._recent(key, now)
            if len(self._hits) >= self._max_keys and key not in self._hits:
                oldest = min(self._hits, key=lambda k: self._hits[k][-1])
                self._hits.pop(oldest)
            hits.append(now)
            self._hits[key] = hits
            return len(hits) == limit

    def reset(self, key: str) -> None:
        with self._lock: self._hits.pop(key, None)

    def clear(self) -> None:
        with self._lock: self._hits.clear()


login_throttle = Throttle()

# Same-origin web client with no third-party resources: own scripts, styles and fonts only. Inline style *attributes*
# are allowed (templates and SVG charts use them); inline <style> elements and inline scripts are not.
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; "
       "font-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; "
       "base-uri 'self'; form-action 'self'; frame-ancestors 'none'; manifest-src 'self'; worker-src 'none'")
# Swagger UI / ReDoc (only when API_DOCS_ENABLED=true) load their bundle from jsDelivr and run an inline bootstrap.
DOCS_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.redoc.ly; connect-src 'self'; worker-src blob:; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'")
DOCS_PATHS = ("/docs", "/redoc")


async def security_headers(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    headers = response.headers
    headers.setdefault("Content-Security-Policy", DOCS_CSP if path.startswith(DOCS_PATHS) else CSP)
    headers.setdefault("X-Content-Type-Options", "nosniff")
    headers.setdefault("X-Frame-Options", "DENY")
    headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
    headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    if not path.startswith(DOCS_PATHS):  # every resource of the web client is same-origin
        headers.setdefault("Cross-Origin-Embedder-Policy", "require-corp")
    if request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").split(",")[0].strip() == "https":
        headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if path.startswith("/api/") or path in {"/", "/legal"}:
        headers.setdefault("Cache-Control", "no-store")
    elif path.startswith("/static/"):  # file names are not versioned: revalidate (ETag) so a deploy is seen at once
        headers.setdefault("Cache-Control", "no-cache")
    return response
