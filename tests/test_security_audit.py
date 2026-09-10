"""Regression tests for the findings of the security audit.

Each of these failed before the fix it guards.
"""

from __future__ import annotations

import datetime as dt

import pytest
from sqlmodel import Session, select

from app.config import Settings
from app.jobs import run_daily_job, run_expiry_escalation
from app.models import AppSettings, Certificate, CertSource
from app.notifier import Notifier
from app.notify import email as email_channel
from app.notify.teams import WebhookNotAllowed, post_card, validate_webhook_url
from tests.conftest import Client, Outbox


def _cert(session: Session, label: str, days: int = 7) -> Certificate:
    cert = Certificate(
        label=label,
        source=CertSource.UPLOAD,
        verified=True,
        not_after=dt.datetime.now() + dt.timedelta(days=days),
        fingerprint_sha256=f"fp-{label}",
    )
    session.add(cert)
    session.commit()
    session.refresh(cert)
    return cert


# --- A10: Server-Side Request Forgery -------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://127.0.0.1:8087/api/jobs/run",  # the app itself
        "https://127.0.0.1/hook",  # loopback by address
        "https://[::1]/hook",  # loopback, v6
        "https://10.0.0.5:6379/",  # internal service
        "file:///etc/passwd",  # scheme abuse
        "https://evil.example.net/hook",  # arbitrary host
    ],
)
def test_the_webhook_cannot_be_pointed_at_arbitrary_hosts(url: str):
    """The server fetches this URL, so it must not go wherever it is told."""
    suffixes = Settings(_env_file=None).teams_host_suffixes
    with pytest.raises(WebhookNotAllowed):
        validate_webhook_url(url, suffixes)


def test_a_genuine_workflow_url_is_accepted():
    suffixes = Settings(_env_file=None).teams_host_suffixes
    validate_webhook_url(
        "https://prod-12.westeurope.logic.azure.com/workflows/a/triggers/manual/paths/invoke",
        suffixes,
    )


async def test_delivery_refuses_a_disallowed_host_without_a_request():
    """Checked again at send time, not only where the value is saved."""
    with pytest.raises(WebhookNotAllowed):
        await post_card(
            "http://169.254.169.254/",
            {"type": "message"},
            allowed_suffixes=(".logic.azure.com",),
        )


# --- A04: one bad record must not stop the run ----------------------------


async def test_an_unusable_record_does_not_silence_every_other_one(
    session: Session, outbox: Outbox, app_settings: AppSettings, test_settings, monkeypatch
):
    """This is the whole product failing quietly, so it gets its own test."""
    real_send = email_channel.send_message

    async def explode_on_one(message: email_channel.Message, settings: Settings) -> None:
        if "Poison" in message.subject:
            raise ValueError("Header values may not contain linefeed characters")
        await real_send(message, settings)

    monkeypatch.setattr(email_channel, "send_message", explode_on_one)

    _cert(session, "Poison")
    _cert(session, "Innocent")

    run = await run_daily_job(session, Notifier(test_settings))

    assert run.failures == 1
    assert not run.ok
    subjects = " ".join(message.subject for message in outbox.mail)
    assert "Innocent" in subjects, "the healthy certificate must still be reported"


async def test_the_escalation_survives_one_bad_record(
    session: Session, outbox: Outbox, app_settings: AppSettings, test_settings, monkeypatch
):
    app_settings.teams_webhook_url = "https://example.org/webhook"
    session.add(app_settings)
    session.commit()
    _cert(session, "Poison", days=-2)
    _cert(session, "Innocent", days=-2)

    from app.notify import teams as teams_channel

    async def explode_on_one(url: str, payload, **kwargs) -> int:
        text = str(payload)
        if "Poison" in text:
            raise RuntimeError("boom")
        outbox.cards.append(payload)
        return 202

    monkeypatch.setattr(teams_channel, "post_card", explode_on_one)
    run = await run_expiry_escalation(session, Notifier(test_settings), now=dt.datetime.now())

    assert run.failures == 1
    assert len(outbox.cards) == 1


# --- Input that later becomes a mail header -------------------------------


def test_control_characters_never_reach_a_stored_field(
    editor: Client, session: Session, outbox: Outbox, app_settings: AppSettings
):
    from tests.fixtures import make_cert

    editor.post_files(
        "/certificates/new/upload",
        files={"file": ("c.pem", make_cert().pem, "application/octet-stream")},
        data={
            "label": "Integration\r\nBcc: attacker@evil.example",
            "environment": "PROD\r\nX-Bad: 1",
            "owner_email": "owner@example.org\r\nBcc: attacker@evil.example",
        },
    )
    cert = session.exec(select(Certificate)).one()
    for value in (cert.label, cert.environment, cert.owner_email):
        assert "\r" not in value and "\n" not in value, value
    assert cert.label == "IntegrationBcc: attacker@evil.example"


def test_a_free_text_field_cannot_be_unbounded(
    editor: Client, session: Session, outbox: Outbox, app_settings: AppSettings
):
    from tests.fixtures import make_cert

    editor.post_files(
        "/certificates/new/upload",
        files={"file": ("c.pem", make_cert().pem, "application/octet-stream")},
        data={"label": "A" * 5000},
    )
    cert = session.exec(select(Certificate)).one()
    assert len(cert.label) == 200


# --- Request size ----------------------------------------------------------


def test_an_oversized_body_is_refused_before_it_is_parsed(editor: Client):
    """Refused on Content-Length, so the multipart parser never runs."""
    response = editor.post(
        "/certificates/new/upload",
        content=b"A" * (2 * 1024 * 1024),
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 413
    assert "larger than" in response.json()["message"]


# --- Information disclosure -----------------------------------------------


async def test_healthz_names_no_certificate(
    editor: Client, session: Session, outbox: Outbox, app_settings: AppSettings, test_settings
):
    """It is unauthenticated so the container can call it."""
    outbox.fail_email = True
    _cert(session, "edi-gateway-prod.internal.example")
    await run_daily_job(session, Notifier(test_settings))

    body = editor.get("/healthz").json()
    rendered = str(body)
    assert "edi-gateway-prod" not in rendered
    assert "detail" not in body["last_job"]
    assert body["last_job"]["failures"] == 1, "the count is still reported"


def test_a_disallowed_webhook_is_refused_when_it_is_saved(
    editor: Client, session: Session, app_settings: AppSettings
):
    """Not only at send time — the person typing it should be told."""
    response = editor.post_form(
        "/settings",
        {"recipient_emails": "team@example.org", "teams_webhook_url": "http://169.254.169.254/"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "https://" in response.text
    session.refresh(app_settings)
    assert app_settings.teams_webhook_url == ""


def test_routes_enforce_the_settings_the_app_was_built_with(app, test_settings):
    """Routes read the application's settings, not the process's.

    A limit checked against one value and enforced against another is not a
    limit.
    """
    from fastapi import Request

    from app.routes.deps import get_config

    scope = {"type": "http", "headers": [], "method": "GET", "path": "/", "app": app}
    resolved = get_config(Request(scope))
    assert resolved is test_settings
    assert resolved.max_upload_bytes == test_settings.max_upload_bytes
