"""Authentication, delegated to a trusted identity-aware proxy.

The app never sees a password. A provider turns an incoming request into a
:class:`User`; Cloudflare Access is the built-in one, and the
:class:`AuthProvider` protocol is the seam where an OIDC or other
trusted-header provider is added later.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

import jwt
from fastapi import Depends, HTTPException, Request, status
from jwt import PyJWKClient

from app.config import Settings, get_settings
from app.logging_setup import logger

ACCESS_JWT_HEADER = "Cf-Access-Jwt-Assertion"
ACCESS_JWT_COOKIE = "CF_Authorization"
DEV_USER_HEADER = "X-Dev-User"


class Role(StrEnum):
    """What a user is allowed to do."""

    VIEWER = "viewer"
    EDITOR = "editor"


@dataclass(frozen=True, slots=True)
class User:
    """An authenticated person."""

    email: str
    role: Role

    @property
    def is_editor(self) -> bool:
        """Whether this user may change anything."""
        return self.role is Role.EDITOR

    @property
    def display_name(self) -> str:
        """Short name shown in the header."""
        return self.email.split("@")[0] if self.email else "unknown"


class AuthError(HTTPException):
    """The request carries no usable identity."""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


class AuthProvider(Protocol):
    """Turns a request into a :class:`User`, or raises :class:`AuthError`."""

    name: str

    def authenticate(self, request: Request) -> User:
        """Return the user this request belongs to."""
        ...


def _role_for(email: str, settings: Settings) -> Role:
    """Editors are listed in ``EDITOR_EMAILS``; everyone else can only look."""
    return Role.EDITOR if email.lower() in settings.editor_email_set else Role.VIEWER


class CloudflareAccessProvider:
    """Validates the ``Cf-Access-Jwt-Assertion`` JWT on every request.

    Signing keys come from the team's ``/cdn-cgi/access/certs`` endpoint and
    are cached by :class:`jwt.PyJWKClient`, which refreshes them when an
    unknown key id appears.
    """

    name = "cloudflare"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        self._jwk_client: PyJWKClient | None = None

    @property
    def jwk_client(self) -> PyJWKClient:
        """Lazily built JWKS client, so start-up needs no network."""
        with self._lock:
            if self._jwk_client is None:
                self._jwk_client = PyJWKClient(
                    self._settings.cf_certs_url,
                    cache_keys=True,
                    lifespan=600,
                    timeout=10,
                )
            return self._jwk_client

    def _token_from(self, request: Request) -> str:
        """Read the Access token from its header or its cookie."""
        token = request.headers.get(ACCESS_JWT_HEADER) or request.cookies.get(ACCESS_JWT_COOKIE)
        if not token:
            raise AuthError(
                "This request did not come through Cloudflare Access. Open the "
                "application through its public hostname so Access can sign you in."
            )
        return token

    def authenticate(self, request: Request) -> User:
        """Validate the Access JWT and return the user it names."""
        token = self._token_from(request)
        try:
            signing_key = self.jwk_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                audience=self._settings.cf_access_aud,
                issuer=self._settings.cf_issuer,
                options={"require": ["exp", "iat", "aud", "iss"]},
            )
        except jwt.PyJWTError as exc:
            # The token itself is never logged.
            logger.warning("Access token rejected: %s", type(exc).__name__)
            raise AuthError(
                "Your Cloudflare Access session is not valid for this "
                "application. Reload the page to sign in again."
            ) from exc

        email = str(claims.get("email") or claims.get("common_name") or "").strip()
        if not email:
            raise AuthError(
                "The Access token carried no email address, so the app cannot "
                "tell who you are. Check the Access application's identity settings."
            )
        return User(email=email, role=_role_for(email, self._settings))


class DevHeaderProvider:
    """Local development only: trusts ``X-Dev-User``.

    :func:`app.config.Settings.validate_startup` and the run script keep this
    bound to 127.0.0.1, because the header is trivially forgeable.
    """

    name = "dev"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def authenticate(self, request: Request) -> User:
        """Return the user named by the development header."""
        email = (request.headers.get(DEV_USER_HEADER) or self._settings.dev_user_email).strip()
        if not email:
            raise AuthError("Set the X-Dev-User header to a user's email address.")
        return User(email=email, role=_role_for(email, self._settings))


def build_provider(settings: Settings | None = None) -> AuthProvider:
    """Return the provider named by ``AUTH_MODE``."""
    settings = settings or get_settings()
    if settings.auth_mode == "dev":
        logger.warning("AUTH_MODE=dev: identity is taken from the X-Dev-User header.")
        return DevHeaderProvider(settings)
    return CloudflareAccessProvider(settings)


def get_provider(request: Request) -> AuthProvider:
    """Return the provider stored on the application state."""
    provider: AuthProvider = request.app.state.auth_provider
    return provider


def current_user(request: Request) -> User:
    """FastAPI dependency: the authenticated viewer.

    Raises:
        AuthError: 401 when the request carries no valid identity.
    """
    user = get_provider(request).authenticate(request)
    request.state.user = user
    return user


def require_editor(user: User = Depends(current_user)) -> User:
    """FastAPI dependency: the user must be able to make changes.

    Raises:
        HTTPException: 403 for viewers.
    """
    if not user.is_editor:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "You can view this board but not change it. Ask an "
                "administrator to add your email address to EDITOR_EMAILS."
            ),
        )
    return user
