"""Security headers, the CSP, and the promise of no external origins."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.logging_setup import redact
from app.security import CONTENT_SECURITY_POLICY, Rate, RateLimiter
from tests.conftest import Client
from tests.fixtures import make_cert

APP_DIR = Path(__file__).resolve().parent.parent / "app"
EXTERNAL_URL_RE = re.compile(r"""["'(\s](https?:)?//(?!127\.0\.0\.1|localhost)[\w.-]+""")

ALLOWED_IN_TEXT = (
    "http://adaptivecards.io/schemas/adaptive-card.json",  # a JSON schema id, never fetched
    "https://certs.example.org",  # placeholder in documentation strings
    "http://www.w3.org/2000/svg",  # an XML namespace, never fetched
)


@pytest.mark.parametrize(
    "path", ["/", "/archive", "/certificates/new", "/settings", "/audit", "/healthz"]
)
def test_every_response_carries_the_security_headers(editor: Client, path: str):
    response = editor.get(path)
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_error_pages_carry_them_too(editor: Client):
    response = editor.get("/certificates/999999")
    assert response.status_code == 404
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY


def test_the_policy_forbids_inline_and_eval():
    assert "unsafe-inline" not in CONTENT_SECURITY_POLICY
    assert "unsafe-eval" not in CONTENT_SECURITY_POLICY
    assert CONTENT_SECURITY_POLICY.startswith("default-src 'self'")


def test_served_html_references_no_external_origin(editor: Client, session, outbox):
    editor.post_files(
        "/certificates/new/upload",
        files={"file": ("cert.pem", make_cert().pem, "application/octet-stream")},
        data={"label": "Integration PROD"},
    )
    for path in ("/", "/archive", "/certificates/new", "/settings", "/audit", "/certificates/1"):
        body = _strip_allowed(editor.get(path).text)
        found = EXTERNAL_URL_RE.findall(body)
        assert not found, f"{path} refers to {found[:3]}"


def test_static_assets_reference_no_external_origin():
    for asset in (APP_DIR / "static").iterdir():
        text = asset.read_text(encoding="utf-8", errors="replace")
        found = EXTERNAL_URL_RE.findall(_strip_allowed(text))
        assert not found, f"{asset.name} refers to {found[:3]}"


def test_templates_reference_no_external_origin():
    for template in (APP_DIR / "templates").glob("*.html"):
        text = _strip_allowed(template.read_text())
        assert not EXTERNAL_URL_RE.search(text), template.name


def _strip_allowed(text: str) -> str:
    for allowed in ALLOWED_IN_TEXT:
        text = text.replace(allowed, "")
    return text


# --- Logging --------------------------------------------------------------


def test_secrets_are_redacted_from_log_lines():
    assert "hunter2" not in redact("smtp password=hunter2")
    assert "logic.azure.com" not in redact(
        "posting to https://prod-1.westeurope.logic.azure.com/workflows/abc"
    )
    assert "MIIB" not in redact("-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----")
    assert "eyJhbGciOi" not in redact("token eyJhbGciOi.eyJzdWIi.signature")


# --- Rate limiting --------------------------------------------------------


def test_rate_limiter_refuses_after_the_limit():
    from fastapi import HTTPException

    limiter = RateLimiter()
    rate = Rate(limit=2, window=60)
    limiter.check("upload", "a@example.org", rate, now=0)
    limiter.check("upload", "a@example.org", rate, now=1)
    with pytest.raises(HTTPException) as caught:
        limiter.check("upload", "a@example.org", rate, now=2)
    assert caught.value.status_code == 429
    # A different user is unaffected, and the window slides.
    limiter.check("upload", "b@example.org", rate, now=2)
    limiter.check("upload", "a@example.org", rate, now=62)


def test_uploads_are_rate_limited(editor: Client, outbox):
    """The 21st upload in an hour is refused rather than parsed."""
    blob = make_cert().pem
    statuses = [
        editor.post_files(
            "/certificates/new/upload",
            files={"file": ("cert.pem", blob, "application/octet-stream")},
            data={"label": "Integration PROD"},
            follow_redirects=False,
        ).status_code
        for _ in range(21)
    ]
    assert statuses[:20] == [303] * 20
    assert statuses[20] == 429


def test_no_template_relies_on_inline_styles_or_scripts():
    """The CSP has no `unsafe-inline`, so inline style and script must not exist."""
    for template in (APP_DIR / "templates").glob("*.html"):
        text = template.read_text()
        assert 'style="' not in text, f"{template.name} uses a style attribute"
        assert "<style" not in text, f"{template.name} has an inline stylesheet"
        assert "<script>" not in text, f"{template.name} has an inline script"
        assert "javascript:" not in text, f"{template.name} has a javascript: URL"
        handler = re.search(r"\son(?:click|load|error|submit|change|input)\s*=", text)
        assert handler is None, f"{template.name} has an inline event handler"
