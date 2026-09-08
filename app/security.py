"""Security headers, CSRF protection and rate limiting.

The Content-Security-Policy is strict on purpose: the app serves no external
assets, so ``default-src 'self'`` with no ``unsafe-inline`` and no
``unsafe-eval`` is achievable and enforced.
"""

from __future__ import annotations

import hmac
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from hashlib import sha256
from typing import Final

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response
from starlette.types import ASGIApp

CSRF_COOKIE = "notafter_csrf"
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

CONTENT_SECURITY_POLICY: Final = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self'",
        "font-src 'self'",
        "connect-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "object-src 'none'",
    )
)

SECURITY_HEADERS: Final[dict[str, str]] = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds the security headers to every response, errors included."""

    def __init__(self, app: ASGIApp, *, hsts: bool = False) -> None:
        super().__init__(app)
        self._hsts = hsts

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Add the headers to whatever the application returned."""
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if self._hsts:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


# --------------------------------------------------------------------------
# CSRF
# --------------------------------------------------------------------------


def _sign(secret: str, value: str) -> str:
    return hmac.new(secret.encode(), value.encode(), sha256).hexdigest()


def issue_csrf_token(secret: str) -> str:
    """Create a signed double-submit token.

    The token is ``<random>.<hmac>``: the cookie and the form field must both
    carry it, and an attacker's site can read neither.
    """
    nonce = secrets.token_urlsafe(24)
    return f"{nonce}.{_sign(secret, nonce)}"


def token_is_valid(secret: str, token: str | None) -> bool:
    """Check a token's signature in constant time."""
    if not token or "." not in token:
        return False
    nonce, _, signature = token.partition(".")
    return hmac.compare_digest(signature, _sign(secret, nonce))


async def verify_csrf(request: Request, secret: str) -> None:
    """Enforce double-submit CSRF on a state-changing request.

    Reading the form here is safe: Starlette caches the parsed form on the
    request, so the endpoint that runs next still sees its fields.

    Raises:
        HTTPException: 403 when the cookie and the submitted token disagree.
    """
    if request.method in SAFE_METHODS:
        return
    cookie_token = request.cookies.get(CSRF_COOKIE)
    sent = request.headers.get(CSRF_HEADER)
    if sent is None and request.headers.get("content-type", "").startswith(
        ("application/x-www-form-urlencoded", "multipart/form-data")
    ):
        form = await request.form()
        raw = form.get(CSRF_FORM_FIELD)
        sent = raw if isinstance(raw, str) else None
    if (
        not cookie_token
        or not sent
        or not hmac.compare_digest(cookie_token, sent)
        or not token_is_valid(secret, sent)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "That form had expired, so nothing was changed. Reload the page and try again."
            ),
        )


async def csrf_protect(request: Request) -> None:
    """Application-wide dependency that guards every unsafe request.

    Raises:
        HTTPException: 403 when the CSRF token is missing or does not match.
    """
    if request.url.path == "/healthz":
        return
    await verify_csrf(request, request.app.state.settings.secret_key)


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Refuse an oversized request before any of it is parsed.

    The CSRF check has to read the form to find the token, which means the
    multipart parser runs — and spools to disk — before the endpoint's own
    size check, and before authentication. Content-Length is checked here so
    that neither happens.
    """

    def __init__(self, app: ASGIApp, *, limit: int) -> None:
        super().__init__(app)
        self._limit = limit

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Reject on Content-Length; the ASGI server caps the rest."""
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self._limit:
            return JSONResponse(
                {
                    "code": "too_large",
                    "message": (
                        f"That request is larger than the "
                        f"{self._limit // 1024} KB limit. A certificate is only "
                        "a few kilobytes."
                    ),
                },
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            )
        return await call_next(request)


class CsrfCookieMiddleware(BaseHTTPMiddleware):
    """Keeps a valid CSRF cookie on the browser and on ``request.state``.

    It deliberately never touches the request body — verification happens in
    :func:`csrf_protect`, where Starlette's form cache makes the fields
    available to the endpoint afterwards.
    """

    def __init__(self, app: ASGIApp, *, secret: str, secure_cookie: bool = True) -> None:
        super().__init__(app)
        self._secret = secret
        self._secure = secure_cookie

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Issue a token when there is not already a valid one."""
        token = request.cookies.get(CSRF_COOKIE)
        issue = not token_is_valid(self._secret, token)
        if issue:
            token = issue_csrf_token(self._secret)
        request.state.csrf_token = token

        response = await call_next(request)
        if issue and token:
            response.set_cookie(
                CSRF_COOKIE,
                token,
                httponly=False,  # the upload script reads it to set the header
                samesite="strict",
                secure=self._secure,
                path="/",
                max_age=60 * 60 * 12,
            )
        return response


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Rate:
    """``limit`` actions per ``window`` seconds."""

    limit: int
    window: int

    @classmethod
    def parse(cls, spec: str) -> Rate:
        """Parse ``"20/hour"`` style specifications."""
        count, _, unit = spec.partition("/")
        seconds = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
        if not count.strip().isdigit() or unit.strip() not in seconds:
            msg = f"Rate limit must look like '20/hour', got {spec!r}"
            raise ValueError(msg)
        return cls(limit=int(count), window=seconds[unit.strip()])


class RateLimiter:
    """In-process sliding-window limiter, keyed by bucket and user.

    A single container serves this app, so an in-process limiter is both
    sufficient and one less dependency.
    """

    def __init__(self) -> None:
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def check(self, bucket: str, identity: str, rate: Rate, *, now: float | None = None) -> None:
        """Record an action, or refuse it.

        Raises:
            HTTPException: 429 with a plain-language retry hint.
        """
        moment = now if now is not None else time.monotonic()
        hits = self._hits[(bucket, identity)]
        cutoff = moment - rate.window
        while hits and hits[0] < cutoff:
            hits.popleft()
        if len(hits) >= rate.limit:
            retry_after = max(1, int(hits[0] + rate.window - moment))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"That is more than {rate.limit} attempts in a row. "
                    f"Wait {retry_after} seconds and try again."
                ),
                headers={"Retry-After": str(retry_after)},
            )
        hits.append(moment)

    def reset(self) -> None:
        """Forget all recorded actions (used by the test suite)."""
        self._hits.clear()


limiter = RateLimiter()
