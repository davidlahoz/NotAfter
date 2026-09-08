"""Cloudflare Access token validation and the viewer/editor split."""

from __future__ import annotations

import datetime as dt

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Request
from sqlmodel import Session

from app.auth import AuthError, CloudflareAccessProvider, Role, User, _role_for
from app.config import Settings
from tests.conftest import EDITOR, Client
from tests.fixtures import make_cert

TEAM = "example"
AUD = "aud-tag-for-this-app"


@pytest.fixture(scope="module")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def cf_settings() -> Settings:
    return Settings(
        _env_file=None,
        auth_mode="cloudflare",
        cf_access_team=TEAM,
        cf_access_aud=AUD,
        editor_emails=EDITOR,
        secret_key="test-secret-key",
    )


def _token(
    key: rsa.RSAPrivateKey,
    *,
    audience: str = AUD,
    issuer: str = f"https://{TEAM}.cloudflareaccess.com",
    email: str = EDITOR,
    expires_in: int = 600,
) -> str:
    now = dt.datetime.now(dt.UTC)
    return jwt.encode(
        {
            "aud": audience,
            "iss": issuer,
            "email": email,
            "iat": int(now.timestamp()),
            "exp": int((now + dt.timedelta(seconds=expires_in)).timestamp()),
        },
        key,
        algorithm="RS256",
    )


class _StubJwks:
    """Stands in for the JWKS endpoint, which is not reachable in tests."""

    def __init__(self, key: rsa.RSAPrivateKey) -> None:
        self._public = key.public_key()

    def get_signing_key_from_jwt(self, _token: str) -> object:
        return type("Key", (), {"key": self._public})()


def _provider(cf_settings: Settings, key: rsa.RSAPrivateKey) -> CloudflareAccessProvider:
    provider = CloudflareAccessProvider(cf_settings)
    provider._jwk_client = _StubJwks(key)  # type: ignore[assignment]
    return provider


def _request(token: str | None) -> Request:
    headers = [(b"cf-access-jwt-assertion", token.encode())] if token else []
    return Request({"type": "http", "headers": headers, "method": "GET", "path": "/"})


def test_valid_token_identifies_an_editor(cf_settings: Settings, signing_key):
    user = _provider(cf_settings, signing_key).authenticate(_request(_token(signing_key)))
    assert user == User(email=EDITOR, role=Role.EDITOR)


def test_wrong_audience_is_rejected(cf_settings: Settings, signing_key):
    with pytest.raises(AuthError):
        _provider(cf_settings, signing_key).authenticate(
            _request(_token(signing_key, audience="some-other-app"))
        )


def test_wrong_issuer_is_rejected(cf_settings: Settings, signing_key):
    with pytest.raises(AuthError):
        _provider(cf_settings, signing_key).authenticate(
            _request(_token(signing_key, issuer="https://attacker.cloudflareaccess.com"))
        )


def test_expired_token_is_rejected(cf_settings: Settings, signing_key):
    with pytest.raises(AuthError):
        _provider(cf_settings, signing_key).authenticate(
            _request(_token(signing_key, expires_in=-60))
        )


def test_token_signed_by_another_key_is_rejected(cf_settings: Settings, signing_key):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AuthError):
        _provider(cf_settings, signing_key).authenticate(_request(_token(other)))


def test_missing_token_is_rejected(cf_settings: Settings, signing_key):
    with pytest.raises(AuthError):
        _provider(cf_settings, signing_key).authenticate(_request(None))


def test_unlisted_email_is_a_viewer(cf_settings: Settings):
    assert _role_for("someone@example.org", cf_settings) is Role.VIEWER
    assert _role_for(EDITOR.upper(), cf_settings) is Role.EDITOR


def test_cloudflare_mode_refuses_to_start_without_its_settings():
    from app.config import ConfigError

    settings = Settings(_env_file=None, auth_mode="cloudflare", secret_key="x")
    with pytest.raises(ConfigError) as caught:
        settings.validate_startup()
    assert "CF_ACCESS_TEAM" in str(caught.value)


def test_cloudflare_mode_refuses_the_development_secret():
    from app.config import ConfigError

    settings = Settings(
        _env_file=None, auth_mode="cloudflare", cf_access_team="t", cf_access_aud="a"
    )
    with pytest.raises(ConfigError) as caught:
        settings.validate_startup()
    assert "SECRET_KEY" in str(caught.value)


# --- Viewer vs editor over HTTP ------------------------------------------


def test_viewer_can_see_the_board(viewer: Client):
    assert viewer.get("/").status_code == 200


def test_viewer_cannot_reach_editor_pages(viewer: Client):
    for path in ("/certificates/new", "/settings", "/audit"):
        assert viewer.get(path).status_code == 403, path


def test_viewer_cannot_change_anything(viewer: Client, editor: Client, session: Session, outbox):
    cert = make_cert()
    editor.post_files(
        "/certificates/new/upload",
        files={"file": ("cert.pem", cert.pem, "application/octet-stream")},
        data={"label": "Integration PROD"},
        follow_redirects=False,
    )
    from app.models import Certificate

    stored = session.exec(__import__("sqlmodel").select(Certificate)).one()

    refused = [
        viewer.post_files(
            "/certificates/new/upload",
            files={"file": ("cert.pem", cert.pem, "application/octet-stream")},
            data={"label": "sneaky"},
        ),
        viewer.post_form(f"/certificates/{stored.id}/update", {"label": "changed"}),
        viewer.post_form(f"/certificates/{stored.id}/archive", {"reason": "no"}),
        viewer.post_form("/settings", {"contact_line": "changed"}),
        viewer.post_json("/api/jobs/run", {}),
    ]
    assert [response.status_code for response in refused] == [403] * 5
    session.refresh(stored)
    assert stored.label == "Integration PROD"


def test_csrf_token_is_required(editor: Client):
    editor.get("/")
    response = editor.post("/settings", data={"contact_line": "no token"}, follow_redirects=False)
    assert response.status_code == 403


def test_dev_mode_refuses_a_public_base_url():
    """Header-trust authentication must never be reachable from outside."""
    from app.config import ConfigError

    settings = Settings(_env_file=None, auth_mode="dev", base_url="https://certs.example.org")
    with pytest.raises(ConfigError) as caught:
        settings.validate_startup()
    assert "X-Dev-User" in str(caught.value)
    assert "AUTH_MODE=cloudflare" in str(caught.value)


@pytest.mark.parametrize(
    "base_url",
    ["http://127.0.0.1:8087", "http://localhost:8000", "http://[::1]:8000"],
)
def test_dev_mode_is_allowed_on_loopback(base_url: str):
    Settings(_env_file=None, auth_mode="dev", base_url=base_url).validate_startup()
