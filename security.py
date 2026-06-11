"""Security layer for the chardihs_frontend relay.

Layers (each independently env-gated, see README):

  1. Authentication (AUTH_PASSWORD_HASH set) — HTTP Basic Auth verified
     against an argon2id hash, timing-safe on both username and password.
     A session cookie (HttpOnly, SameSite=Strict, Secure under TLS) is issued
     on successful auth and validated on the /ws upgrade, because the browser
     WebSocket API cannot send an Authorization header.
  2. Brute-force lockout — per-IP sliding window over FAILED auth attempts;
     an IP that fails too often gets 429 until the window drains.
  3. HTTP rate limit — per-IP sliding window over all non-WS requests.
  4. Security headers — CSP, nosniff, frame denial, referrer policy, and
     HSTS when TLS is on. Always applied.

Connection caps for /ws live in server.py (they need the relay's client set).
TLS itself is configured in server.py (ssl.SSLContext); this module only needs
to know whether it is on, for the Secure cookie flag and HSTS.
"""

import base64
import hmac
import logging
import secrets
import time
from collections import deque
from typing import Callable

from aiohttp import web

logger = logging.getLogger("chardihs_frontend.security")

SESSION_COOKIE = "chardihs_session"

# Brute-force lockout: more than this many FAILED auths per IP in the window -> 429
AUTH_FAIL_LIMIT = 5
AUTH_FAIL_WINDOW_S = 15 * 60

# General HTTP rate limit (page loads etc. — /ws is exempt, it has its own caps)
HTTP_RATE_LIMIT = 60
HTTP_RATE_WINDOW_S = 60


def client_ip(request: web.Request, trust_proxy: bool) -> str:
    """Best-effort client IP. Only honour X-Forwarded-For when explicitly
    told the app sits behind a trusted reverse proxy — the header is
    client-spoofable otherwise."""
    if trust_proxy:
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.remote or "unknown"


class SlidingWindowCounter:
    """Per-key event counter over a rolling time window."""

    def __init__(self, limit: int, window_s: float) -> None:
        self._limit = limit
        self._window_s = window_s
        self._events: dict[str, deque[float]] = {}

    def _prune(self, key: str, now: float) -> deque[float]:
        dq = self._events.setdefault(key, deque())
        cutoff = now - self._window_s
        while dq and dq[0] <= cutoff:
            dq.popleft()
        if not dq:
            # Don't let the dict grow unboundedly with one-off IPs
            self._events.pop(key, None)
            dq = self._events.setdefault(key, deque())
        return dq

    def record(self, key: str) -> None:
        now = time.monotonic()
        self._prune(key, now).append(now)

    def over_limit(self, key: str) -> bool:
        return len(self._prune(key, time.monotonic())) >= self._limit


class SessionStore:
    """Opaque 256-bit session tokens with TTL expiry."""

    def __init__(self, ttl_s: int) -> None:
        self._ttl_s = ttl_s
        self._sessions: dict[str, float] = {}  # token -> expiry timestamp

    @property
    def ttl_s(self) -> int:
        return self._ttl_s

    def create(self) -> str:
        now = time.time()
        for tok in [t for t, exp in self._sessions.items() if exp <= now]:
            del self._sessions[tok]
        token = secrets.token_hex(32)
        self._sessions[token] = now + self._ttl_s
        return token

    def validate(self, token: str | None) -> bool:
        if not token:
            return False
        expiry = self._sessions.get(token)
        if expiry is None:
            return False
        if time.time() > expiry:
            del self._sessions[token]
            return False
        return True


class Authenticator:
    """argon2id Basic Auth checker, timing-safe on username and password."""

    def __init__(self, username: str, password_hash: str) -> None:
        try:
            from argon2 import PasswordHasher
        except ImportError as exc:
            raise RuntimeError(
                "AUTH_PASSWORD_HASH is set but argon2-cffi is not installed. "
                "Run: pip install argon2-cffi"
            ) from exc
        self._ph = PasswordHasher()
        self._username = username
        self._password_hash = password_hash

    def check(self, request: web.Request) -> bool:
        header = request.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:]).decode("utf-8", errors="strict")
            username, sep, password = decoded.partition(":")
            if not sep:
                return False
        except Exception:
            return False

        # Constant-time username comparison prevents enumeration via timing
        username_ok = hmac.compare_digest(
            username.encode("utf-8"), self._username.encode("utf-8")
        )
        try:
            self._ph.verify(self._password_hash, password)
            password_ok = True
        except Exception:
            password_ok = False

        # Evaluate both before returning — no short-circuit timing leak
        return username_ok and password_ok


def _apply_headers(response: web.StreamResponse, tls_enabled: bool) -> None:
    """Security headers. Skipped for already-prepared (streaming WS) responses."""
    if response.prepared:
        return
    h = response.headers
    # The page uses inline <script>/<style>; connect-src must allow the WS upgrade.
    h["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    )
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Cache-Control"] = "no-store"
    if tls_enabled:
        h["Strict-Transport-Security"] = "max-age=31536000"


def make_security_middleware(
    authenticator: Authenticator | None,
    sessions: SessionStore,
    tls_enabled: bool,
    trust_proxy: bool,
) -> Callable:
    """Build the single aiohttp middleware: rate limit -> auth -> headers."""

    http_throttle = SlidingWindowCounter(HTTP_RATE_LIMIT, HTTP_RATE_WINDOW_S)
    auth_fail_throttle = SlidingWindowCounter(AUTH_FAIL_LIMIT, AUTH_FAIL_WINDOW_S)

    def _unauthorized() -> web.Response:
        return web.Response(
            status=401,
            headers={"WWW-Authenticate": 'Basic realm="chardihs", charset="UTF-8"'},
            text="Unauthorized",
        )

    @web.middleware
    async def security_mw(request: web.Request, handler: Callable) -> web.StreamResponse:
        ip = client_ip(request, trust_proxy)
        is_ws = request.path == "/ws"

        # --- HTTP rate limit (WS exempt — capped separately in the relay) ---
        if not is_ws:
            if http_throttle.over_limit(ip):
                return web.Response(status=429, text="Too many requests")
            http_throttle.record(ip)

        if authenticator is None:
            response = await handler(request)
            _apply_headers(response, tls_enabled)
            return response

        # --- WS upgrade: session cookie only ---
        if is_ws:
            if not sessions.validate(request.cookies.get(SESSION_COOKIE)):
                response = _unauthorized()
                _apply_headers(response, tls_enabled)
                return response
            return await handler(request)  # prepared WS response — no headers

        # --- HTTP: Basic Auth, with brute-force lockout on failures ---
        if auth_fail_throttle.over_limit(ip):
            logger.warning("Auth lockout for %s (too many failed attempts)", ip)
            response = web.Response(status=429, text="Too many failed login attempts")
            _apply_headers(response, tls_enabled)
            return response

        if not authenticator.check(request):
            # Only count attempts that actually presented credentials —
            # the browser's first, credential-less request is normal.
            if request.headers.get("Authorization"):
                auth_fail_throttle.record(ip)
                logger.warning("Failed auth attempt from %s", ip)
            response = _unauthorized()
            _apply_headers(response, tls_enabled)
            return response

        # Credentials OK — serve and issue the session cookie for the WS upgrade
        response = await handler(request)
        token = sessions.create()
        response.set_cookie(
            SESSION_COOKIE,
            token,
            httponly=True,
            secure=tls_enabled,
            samesite="Strict",
            max_age=sessions.ttl_s,
        )
        _apply_headers(response, tls_enabled)
        return response

    return security_mw
