"""The pages themselves: what a reader sees, and what /healthz reports."""

from __future__ import annotations

import datetime as dt

from sqlmodel import Session, select

from app.models import AuditLog, Certificate, CertSource
from tests.conftest import Client
from tests.fixtures import make_cert


def _add(session: Session, label: str, days: int, **kwargs) -> Certificate:
    cert = Certificate(
        label=label,
        not_after=dt.datetime.now() + dt.timedelta(days=days),
        fingerprint_sha256=f"fp-{label}",
        source=CertSource.UPLOAD,
        verified=True,
        **kwargs,
    )
    session.add(cert)
    session.commit()
    session.refresh(cert)
    return cert


def test_board_sorts_by_soonest_expiry(viewer: Client, session: Session, app_settings):
    _add(session, "Later", 300)
    _add(session, "Sooner", 5)
    body = viewer.get("/").text
    assert body.index("Sooner") < body.index("Later")


def test_board_shows_the_countdown_and_the_plain_sentence(
    viewer: Client, session: Session, app_settings
):
    _add(session, "Integration PROD", 12, subject_cn="edi.example.org", environment="PROD")
    body = viewer.get("/").text
    assert "12" in body
    assert "days left" in body
    assert "Renew now." in body
    assert "Get the replacement in place this week." in body
    assert "edi.example.org" in body
    assert "PROD" in body


def test_board_formats_the_date_in_words(viewer: Client, session: Session, app_settings):
    cert = _add(session, "Integration PROD", 30)
    expected = f"{cert.not_after.day} {cert.not_after:%B %Y}"
    assert f"Valid until {expected}" in viewer.get("/").text


def test_board_explains_the_colours(viewer: Client, session: Session, app_settings):
    body = viewer.get("/").text
    assert "What the colours mean" in body
    assert "In date" in body and "Expired" in body
    assert "Renew now" in body and "Plan the renewal" in body


def test_the_board_carries_no_standing_advice(viewer: Client, session: Session, app_settings):
    """The board lists certificates; it does not lecture about them."""
    app_settings.contact_line = "Ask the integration team on the helpdesk."
    session.add(app_settings)
    session.commit()
    body = viewer.get("/").text
    assert "Ask the integration team on the helpdesk." not in body
    assert "refreshes itself every hour" not in body


async def test_the_contact_line_still_reaches_notifications(
    session: Session, outbox, app_settings, test_settings
):
    """Removing it from the board must not remove it from the messages."""
    import datetime as dt

    from app.jobs import run_daily_job
    from app.models import CertSource
    from app.notifier import Notifier

    app_settings.contact_line = "Ask the integration team on the helpdesk."
    app_settings.teams_webhook_url = "https://example.org/webhook"
    session.add(app_settings)
    session.add(
        Certificate(
            label="Integration PROD",
            source=CertSource.UPLOAD,
            verified=True,
            not_after=dt.datetime.now() + dt.timedelta(days=7),
            fingerprint_sha256="fp-contact",
        )
    )
    session.commit()

    await run_daily_job(session, Notifier(test_settings))
    assert "Ask the integration team on the helpdesk." in outbox.mail[0].text
    card = outbox.cards[0]["attachments"][0]["content"]["body"]
    assert any(
        "Ask the integration team on the helpdesk." in str(block.get("text", "")) for block in card
    )


def test_board_refreshes_itself_every_hour(viewer: Client, app_settings):
    assert '<meta http-equiv="refresh" content="3600">' in viewer.get("/").text


def test_expired_certificates_read_as_days_ago(viewer: Client, session: Session, app_settings):
    _add(session, "Old cert", -4)
    body = viewer.get("/").text
    assert "days ago" in body
    assert "This has already expired." in body


def test_detail_page_shows_the_facts(editor: Client, session: Session, outbox, app_settings):
    editor.post_files(
        "/certificates/new/upload",
        files={"file": ("cert.pem", make_cert("edi.example.org").pem, "application/octet-stream")},
        data={"label": "Integration PROD", "owner_email": "owner@example.org"},
    )
    cert = session.exec(select(Certificate)).one()
    body = editor.get(f"/certificates/{cert.id}").text

    assert "SHA-256 fingerprint" in body
    assert "Renew or replace" in body
    assert "Send test notification to me" in body
    assert "Archive this certificate" in body
    assert cert.subject_cn in body


def test_a_missing_certificate_explains_itself(viewer: Client):
    response = viewer.get("/certificates/424242")
    assert response.status_code == 404
    assert "no certificate with the number 424242" in response.text


def test_audit_trail_records_every_change(editor: Client, session: Session, outbox, app_settings):
    editor.post_files(
        "/certificates/new/upload",
        files={"file": ("cert.pem", make_cert().pem, "application/octet-stream")},
        data={"label": "Integration PROD"},
    )
    cert = session.exec(select(Certificate)).one()
    editor.post_form(f"/certificates/{cert.id}/update", {"label": "Renamed"})
    editor.post_form(
        "/settings", {"recipient_emails": "team@example.org", "contact_line": "Ask us"}
    )

    actions = [entry.action for entry in session.exec(select(AuditLog)).all()]
    assert "certificate.create" in actions
    assert "certificate.update" in actions
    assert "settings.update" in actions

    body = editor.get("/audit").text
    assert "certificate.create" in body
    assert "editor@example.org" in body


def test_audit_details_never_hold_file_contents(
    editor: Client, session: Session, outbox, app_settings
):
    editor.post_files(
        "/certificates/new/upload",
        files={"file": ("cert.pem", make_cert().pem, "application/octet-stream")},
        data={"label": "Integration PROD"},
    )
    for entry in session.exec(select(AuditLog)).all():
        rendered = str(entry.details_json)
        assert "BEGIN CERTIFICATE" not in rendered
        assert "MII" not in rendered


def test_healthz_reports_the_scheduler_and_the_last_run(
    editor: Client, session: Session, outbox, app_settings
):
    body = editor.get("/healthz").json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert "running" in body["scheduler"]
    assert body["last_job"] is None

    editor.post_json("/api/jobs/run", {})
    after = editor.get("/healthz").json()
    assert after["last_job"]["certificates_checked"] == 0
    assert after["last_job"]["ok"] is True


def test_settings_page_never_shows_the_stored_webhook(
    editor: Client, session: Session, app_settings
):
    secret = "https://example.org/workflows/super-secret-token"
    editor.post_form(
        "/settings",
        {"recipient_emails": "team@example.org", "teams_webhook_url": secret},
    )
    session.refresh(app_settings)
    assert app_settings.teams_webhook_url == secret

    body = editor.get("/settings").text
    assert secret not in body
    assert "A webhook is set" in body


def test_settings_round_trip(editor: Client, session: Session, app_settings):
    editor.post_form(
        "/settings",
        {
            "recipient_emails": "a@example.org, b@example.org",
            "calendar_recipient_emails": "c@example.org",
            "thresholds": "90, 30, 7",
            "warn_days": "45",
            "critical_days": "10",
            "contact_line": "Ask the integration team.",
            "notify_daily_when_expired": "1",
        },
    )
    session.refresh(app_settings)
    assert app_settings.recipient_emails == ["a@example.org", "b@example.org"]
    assert app_settings.calendar_recipient_emails == ["c@example.org"]
    assert app_settings.thresholds == [90, 30, 7]
    assert app_settings.warn_days == 45
    assert app_settings.critical_days == 10
    assert app_settings.notify_daily_when_expired is True


def test_test_email_button_sends_to_the_signed_in_user(
    editor: Client, session: Session, outbox, app_settings
):
    response = editor.post_form("/settings/test-email", {}, follow_redirects=False)
    assert response.status_code == 303
    assert outbox.mail[-1].to == ["editor@example.org"]
    assert outbox.mail[-1].subject == "No After — test email"


def test_teams_test_card_is_the_same_shape_as_a_real_one(
    editor: Client, session: Session, app_settings
):
    """A weaker test payload could pass while real notifications failed."""
    from app.notify.teams import build_card, build_test_card
    from app.services import sample_certificate

    cert = sample_certificate(session)
    real = build_card(cert, 30, detail_url="https://x.example.org/1", contact_line="Ask us.")
    test = build_test_card(cert, 30, detail_url="https://x.example.org/1", contact_line="Ask us.")

    real_content = real["attachments"][0]["content"]
    test_content = test["attachments"][0]["content"]
    assert test_content["version"] == real_content["version"]
    assert test_content["actions"] == real_content["actions"]
    assert [block["type"] for block in test_content["body"]][1:] == [
        block["type"] for block in real_content["body"]
    ]
    assert "Test message from No After" in test_content["body"][0]["text"]


async def test_teams_test_reports_the_status_the_webhook_returned(
    editor: Client, session: Session, outbox, app_settings, monkeypatch
):
    """A 202 means queued, not delivered, so the number has to be visible."""
    from app.notify import teams as teams_channel
    from app.services import record_audit  # noqa: F401

    app_settings.teams_webhook_url = "https://example.org/webhook"
    session.add(app_settings)
    session.commit()

    async def accepted(webhook_url: str, payload, **_kwargs) -> int:
        outbox.cards.append(payload)
        return 202

    monkeypatch.setattr(teams_channel, "post_card", accepted)
    response = editor.post_form("/settings/test-teams", {}, follow_redirects=False)

    assert response.status_code == 303
    assert "msg=teams-accepted" in response.headers["location"]
    assert "http=202" in response.headers["location"]

    entry = session.exec(select(AuditLog).where(AuditLog.target == "teams")).one()
    assert entry.details_json["http_status"] == 202

    page = editor.get("/settings").text
    assert "the webhook replied" in page
    assert "HTTP 202" in page
    assert "does not mean a card" in page


def test_settings_page_shows_the_exact_teams_payload(
    editor: Client, session: Session, app_settings
):
    body = editor.get("/settings").text
    assert "Show the JSON that is posted" in body
    assert "application/vnd.microsoft.card.adaptive" in body
    assert "AdaptiveCard" in body
