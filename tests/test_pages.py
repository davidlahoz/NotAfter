"""The pages themselves: what a reader sees, and what /healthz reports."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from sqlmodel import Session, select

from app.models import AuditLog, Certificate, CertSource
from tests.conftest import Client
from tests.fixtures import make_cert

APP_STATIC = Path(__file__).resolve().parent.parent / "app" / "static"


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
    """The sentence is on the group now, but a reader still meets it."""
    _add(session, "Integration PROD", 12, subject_cn="edi.example.org", environment="PROD")
    body = viewer.get("/").text
    assert "12" in body
    assert "days left" in body
    assert "Renew now" in body
    assert "Get the replacement in place this week." in body
    assert "edi.example.org" in body
    assert "PROD" in body


def test_the_board_says_a_status_once_however_many_share_it(
    viewer: Client, session: Session, app_settings
):
    """Repeated per row it becomes wallpaper; the eye stops reading it."""
    for index in range(4):
        _add(session, f"Urgent {index}", 5 + index)
    body = viewer.get("/").text

    sentence = "Get the replacement in place this week."
    assert body.count(sentence) == 1, "once for the group, not once per row"
    assert '<span class="group-count">4</span>' in body


def test_groups_run_most_urgent_first(viewer: Client, session: Session, app_settings):
    _add(session, "Fine", 300)
    _add(session, "Expired one", -3)
    _add(session, "Urgent", 4)
    _add(session, "Soon", 50)
    body = viewer.get("/").text
    order = [body.index(word) for word in ("Expired", "Renew now", "Plan the renewal", "In date")]
    assert order == sorted(order)


def test_board_formats_the_date_in_words(viewer: Client, session: Session, app_settings):
    cert = _add(session, "Integration PROD", 30)
    expected = f"{cert.not_after.day} {cert.not_after:%B %Y}"
    assert f"Valid until {expected}" in viewer.get("/").text


def test_each_group_says_where_its_line_falls(viewer: Client, session: Session, app_settings):
    """The numbers sit on the heading they describe, not in a key at the foot."""
    _add(session, "Expired one", -2)
    _add(session, "Urgent", 5)
    _add(session, "Soon", 50)
    _add(session, "Fine", 300)
    body = viewer.get("/").text

    assert "past the date" in body
    assert f"{app_settings.critical_days} days or fewer" in body
    assert f"{app_settings.warn_days} days or fewer" in body
    assert f"more than {app_settings.warn_days} days left" in body


def test_the_board_has_no_separate_legend(viewer: Client, session: Session, app_settings):
    """Once the groups say it in words, a key repeats all but the numbers."""
    _add(session, "Integration PROD", 12)
    body = viewer.get("/").text
    assert "Where the lines fall" not in body
    assert 'class="legend"' not in body
    # And each threshold is stated once, not twice.
    assert body.count(f"{app_settings.critical_days} days or fewer") == 1


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


# --- The audit trail is for people to read --------------------------------


def test_the_audit_trail_shows_no_python_repr(
    editor: Client, session: Session, outbox, app_settings
):
    """It used to render the stored mapping straight into the page."""
    from tests.fixtures import make_cert

    editor.post_files(
        "/certificates/new/upload",
        files={"file": ("c.pem", make_cert("edi.example.org").pem, "application/octet-stream")},
        data={"label": "Integration PROD"},
    )
    body = editor.get("/audit").text

    assert "{'label'" not in body
    assert "'source':" not in body
    assert "True}" not in body
    assert "&#39;" not in body, "no escaped Python quotes either"


def test_the_audit_trail_names_the_certificate_and_links_it(
    editor: Client, session: Session, outbox, app_settings
):
    from tests.fixtures import make_cert

    editor.post_files(
        "/certificates/new/upload",
        files={"file": ("c.pem", make_cert().pem, "application/octet-stream")},
        data={"label": "Integration PROD"},
    )
    cert = session.exec(select(Certificate)).one()
    body = editor.get("/audit").text

    assert "Registered a certificate" in body, "not the raw action identifier"
    assert f'<a href="/certificates/{cert.id}">Integration PROD</a>' in body
    assert f"certificate:{cert.id}<" not in body, "the internal id is not shown"


def test_a_fingerprint_is_shortened_in_the_audit_trail(
    editor: Client, session: Session, outbox, app_settings
):
    from tests.fixtures import make_cert

    editor.post_files(
        "/certificates/new/upload",
        files={"file": ("c.pem", make_cert().pem, "application/octet-stream")},
        data={"label": "Integration PROD"},
    )
    cert = session.exec(select(Certificate)).one()
    full = cert.fingerprint_sha256 or ""
    body = editor.get("/audit").text

    assert full not in body, "64 characters filled the row and told nobody anything"
    assert f"{full[:16]}…" in body


def test_the_certificate_name_is_not_said_twice_in_one_row(
    editor: Client, session: Session, outbox, app_settings
):
    from tests.fixtures import make_cert

    editor.post_files(
        "/certificates/new/upload",
        files={"file": ("c.pem", make_cert().pem, "application/octet-stream")},
        data={"label": "Integration PROD"},
    )
    body = editor.get("/audit").text
    row = body[
        body.index("Registered a certificate") : body.index("Registered a certificate") + 700
    ]
    assert row.count("Integration PROD") == 1


# --- The whole row, the summary, and empty states -------------------------


def test_the_whole_row_is_a_link_target(viewer: Client, session: Session, app_settings):
    """The label alone is a small target on a tall row, and smaller on a phone."""
    _add(session, "Integration PROD", 12)
    body = viewer.get("/").text
    assert '<article class="entry' in body

    css = (APP_STATIC / "notafter.css").read_text()
    assert ".entry-name a::after" in css, "the link is stretched over the row"
    assert ".entry { position: relative; }" in css
    # ...but the facts stay selectable rather than sitting under the overlay.
    assert ".entry-facts { position: relative; z-index: 1;" in css


def test_the_board_answers_how_many_need_attention(viewer: Client, session: Session, app_settings):
    _add(session, "Expired one", -2)
    _add(session, "Urgent", 5)
    _add(session, "Fine", 300)
    body = viewer.get("/").text
    assert "3 tracked" in body
    assert "2 need attention today" in body
    assert "<title>2 need attention" in body, "a pinned tab is worth glancing at"


def test_a_calm_board_says_so(viewer: Client, session: Session, app_settings):
    _add(session, "Fine", 300)
    body = viewer.get("/").text
    assert "all in date" in body
    assert "need attention" not in body


def test_an_empty_board_says_what_to_do(editor: Client, app_settings):
    body = editor.get("/").text
    assert "nothing to expire" in body
    assert "Register the first certificate" in body
    assert "type in the date if you do not have it" in body


def test_an_empty_history_says_why_it_is_empty(
    editor: Client, session: Session, outbox, app_settings, monkeypatch
):
    """Saying nothing has been sent is not useful; the reason is."""
    from app.config import Settings as ConfigSettings

    cert = _add(session, "Integration PROD", 12)
    monkeypatch.setattr(ConfigSettings, "email_configured", property(lambda self: False))
    body = editor.get(f"/certificates/{cert.id}").text
    assert "because email is not configured" in body


def test_a_muted_certificate_explains_its_silence(
    editor: Client, session: Session, outbox, app_settings
):
    cert = _add(session, "Quiet", 12)
    cert.muted = True
    session.add(cert)
    session.commit()
    body = editor.get(f"/certificates/{cert.id}").text
    assert "Reminders are muted" in body
