"""Manual entry, attaching, renewal and the calendar invites that follow."""

from __future__ import annotations

import datetime as dt

from sqlmodel import Session, select

from app.models import (
    CalendarInvite,
    Certificate,
    CertSource,
    CertStatus,
    InviteKind,
    InviteMethod,
)
from tests.conftest import Client, Outbox
from tests.fixtures import make_cert


def _register(client: Client, cert, label: str = "Integration PROD"):
    return client.post_files(
        "/certificates/new/upload",
        files={"file": ("cert.pem", cert.pem, "application/octet-stream")},
        data={"label": label, "environment": "PROD", "owner_email": "owner@example.org"},
        follow_redirects=False,
    )


def _only(session: Session, **where) -> Certificate:
    statement = select(Certificate)
    for name, value in where.items():
        statement = statement.where(getattr(Certificate, name) == value)
    return session.exec(statement).one()


# --- Manual entry ---------------------------------------------------------


def test_manual_entry_is_unverified(editor: Client, session: Session, outbox, app_settings):
    expiry = (dt.date.today() + dt.timedelta(days=200)).isoformat()
    response = editor.post_form(
        "/certificates/new/manual",
        {"label": "Partner AS2", "expiry_date": expiry, "environment": "TEST"},
        follow_redirects=False,
    )
    assert response.status_code == 303

    cert = _only(session)
    assert cert.source is CertSource.MANUAL
    assert cert.verified is False
    assert cert.not_after.date().isoformat() == expiry

    board = editor.get("/")
    assert "manual entry — unverified" in board.text


def test_a_bad_date_is_refused(editor: Client, session: Session):
    response = editor.post_form(
        "/certificates/new/manual", {"label": "x", "expiry_date": "not-a-date"}
    )
    assert response.status_code == 400
    assert session.exec(select(Certificate)).all() == []


def test_attaching_a_matching_certificate_verifies_the_record(
    editor: Client, session: Session, outbox: Outbox, app_settings
):
    cert = make_cert("edi.example.org", days_until_expiry=120)
    expiry = cert.certificate.not_valid_after_utc.date().isoformat()
    editor.post_form("/certificates/new/manual", {"label": "Partner AS2", "expiry_date": expiry})
    record = _only(session)

    response = editor.post_files(
        f"/certificates/{record.id}/attach",
        files={"file": ("cert.pem", cert.pem, "application/octet-stream")},
        follow_redirects=False,
    )
    assert response.status_code == 303

    session.refresh(record)
    assert record.verified is True
    assert record.source is CertSource.UPLOAD
    assert record.subject_cn == "edi.example.org"
    assert record.fingerprint_sha256 is not None


def test_attaching_a_different_expiry_needs_confirmation(
    editor: Client, session: Session, outbox, app_settings
):
    cert = make_cert(days_until_expiry=120)
    wrong_date = (dt.date.today() + dt.timedelta(days=45)).isoformat()
    editor.post_form(
        "/certificates/new/manual", {"label": "Partner AS2", "expiry_date": wrong_date}
    )
    record = _only(session)

    refused = editor.post_files(
        f"/certificates/{record.id}/attach",
        files={"file": ("cert.pem", cert.pem, "application/octet-stream")},
        follow_redirects=False,
    )
    assert refused.status_code == 409
    session.refresh(record)
    assert record.verified is False

    accepted = editor.post_files(
        f"/certificates/{record.id}/attach",
        files={"file": ("cert.pem", cert.pem, "application/octet-stream")},
        data={"confirm_replacement": "1"},
        follow_redirects=False,
    )
    assert accepted.status_code == 303
    session.refresh(record)
    assert record.verified is True
    assert record.not_after.date() == cert.certificate.not_valid_after_utc.date()


# --- Calendar invites -----------------------------------------------------


def test_registering_sends_two_invites(
    editor: Client, session: Session, outbox: Outbox, app_settings
):
    _register(editor, make_cert(days_until_expiry=200))

    invites = outbox.invites
    assert len(invites) == 2
    assert all(invite.method == "REQUEST" for invite in invites)
    assert all(invite.to == ["calendar@example.org", "owner@example.org"] for invite in invites)

    bodies = [invite.calendar.decode() for invite in invites if invite.calendar]
    assert any("SUMMARY:Certificate expires: Integration PROD" in body for body in bodies)
    assert any("SUMMARY:Renew certificate: Integration PROD" in body for body in bodies)
    for body in bodies:
        assert "METHOD:REQUEST" in body
        assert "SEQUENCE:0" in body
        assert "TRIGGER:-P7D" in body
        assert "TRIGGER:-P1D" in body
        # The library quotes a parameter value containing a space, per RFC 5545.
        assert 'ORGANIZER;CN="No After":MAILTO:noafter@example.org' in body

    stored = session.exec(select(CalendarInvite)).all()
    assert {invite.uid for invite in stored} == {
        f"cert-{stored[0].cert_id}-expiry@notafter",
        f"cert-{stored[0].cert_id}-renew@notafter",
    }


def test_archiving_cancels_the_invites(
    editor: Client, session: Session, outbox: Outbox, app_settings
):
    _register(editor, make_cert(days_until_expiry=200))
    record = _only(session)
    outbox.mail.clear()

    editor.post_form(
        f"/certificates/{record.id}/archive", {"reason": "No longer used"}, follow_redirects=False
    )

    cancels = outbox.invites
    assert len(cancels) == 2
    for invite in cancels:
        assert invite.method == "CANCEL"
        body = invite.calendar.decode() if invite.calendar else ""
        assert "METHOD:CANCEL" in body
        assert "STATUS:CANCELLED" in body
        assert "SEQUENCE:1" in body

    session.refresh(record)
    assert record.status is CertStatus.ARCHIVED


def test_renewal_supersedes_cancels_and_reinvites(
    editor: Client, session: Session, outbox: Outbox, app_settings
):
    old_cert = make_cert("edi.example.org", days_until_expiry=20)
    _register(editor, old_cert)
    old = _only(session)
    outbox.mail.clear()

    new_cert = make_cert("edi.example.org", days_until_expiry=400)
    response = editor.post_files(
        f"/certificates/{old.id}/renew",
        files={"file": ("new.pem", new_cert.pem, "application/octet-stream")},
        data={"label": "Integration PROD"},
        follow_redirects=False,
    )
    assert response.status_code == 303

    session.refresh(old)
    successor = session.get(Certificate, old.superseded_by_id)
    assert successor is not None
    assert old.status is CertStatus.ARCHIVED
    assert old.archive_reason == f"Replaced by record {successor.id}"
    assert successor.not_after.date() == new_cert.certificate.not_valid_after_utc.date()

    cancels = [invite for invite in outbox.invites if invite.method == InviteMethod.CANCEL.value]
    requests = [invite for invite in outbox.invites if invite.method == InviteMethod.REQUEST.value]
    assert len(cancels) == 2
    assert len(requests) == 2
    for invite in cancels:
        body = invite.calendar.decode() if invite.calendar else ""
        assert "SEQUENCE:1" in body
        assert f"UID:cert-{old.id}-" in body
    for invite in requests:
        body = invite.calendar.decode() if invite.calendar else ""
        assert f"UID:cert-{successor.id}-" in body


def test_renewing_with_the_same_file_is_refused(
    editor: Client, session: Session, outbox: Outbox, app_settings
):
    cert = make_cert(days_until_expiry=30)
    _register(editor, cert)
    record = _only(session)

    response = editor.post_files(
        f"/certificates/{record.id}/renew",
        files={"file": ("same.pem", cert.pem, "application/octet-stream")},
        follow_redirects=False,
    )
    assert response.status_code == 409
    session.refresh(record)
    assert record.status is CertStatus.ACTIVE


async def test_an_archived_certificate_gets_no_notifications(
    editor: Client, session: Session, outbox: Outbox, app_settings, test_settings
):
    from app.jobs import run_daily_job
    from app.notifier import Notifier

    _register(editor, make_cert(days_until_expiry=10))
    record = _only(session)
    editor.post_form(f"/certificates/{record.id}/archive", {"reason": "done"})
    outbox.mail.clear()

    run = await run_daily_job(session, Notifier(test_settings))
    assert run.notifications_sent == 0
    assert outbox.mail == []


def test_calendar_identifiers_do_not_follow_the_display_name(
    editor: Client, session: Session, outbox: Outbox, app_settings
):
    """UID and PRODID are stable identifiers, not branding.

    Renaming the application must never change them: calendar clients match
    an update or a cancellation to the event people already hold by UID, and
    a new one would orphan every invite ever sent.
    """
    _register(editor, make_cert(days_until_expiry=200))
    record = _only(session)
    bodies = [invite.calendar.decode() for invite in outbox.invites if invite.calendar]

    assert bodies
    for body in bodies:
        assert f"UID:cert-{record.id}-" in body
        assert "@notafter" in body
        assert "PRODID:-//NotAfter//" in body


# --- Calendar timings are settings, not constants -------------------------


def _ics_bodies(outbox: Outbox) -> list[str]:
    return [invite.calendar.decode() for invite in outbox.invites if invite.calendar]


def test_the_renewal_event_follows_the_configured_lead_time(
    editor: Client, session: Session, outbox: Outbox, app_settings
):
    app_settings.calendar_renew_lead_days = 90
    session.add(app_settings)
    session.commit()

    _register(editor, make_cert(days_until_expiry=200))
    cert = _only(session)
    expiry = cert.not_after.date()

    dates = {
        invite.kind.value: invite.event_date
        for invite in session.exec(select(CalendarInvite)).all()
    }
    assert dates["expiry"] == expiry
    assert dates["renew"] == expiry - dt.timedelta(days=90)

    renew_body = next(body for body in _ics_bodies(outbox) if "Renew certificate" in body)
    assert (expiry - dt.timedelta(days=90)).strftime("%Y%m%d") in renew_body
    assert "in 90 days" in renew_body.replace("\r\n ", "")


def test_the_alarms_follow_the_configured_days(
    editor: Client, session: Session, outbox: Outbox, app_settings
):
    app_settings.calendar_alarm_days = [21, 3]
    session.add(app_settings)
    session.commit()

    _register(editor, make_cert(days_until_expiry=200))
    for body in _ics_bodies(outbox):
        assert "TRIGGER:-P21D" in body
        assert "TRIGGER:-P3D" in body
        assert "TRIGGER:-P7D" not in body


async def test_changing_the_timing_moves_invites_people_already_have(
    editor: Client, session: Session, outbox: Outbox, app_settings
):
    """A new setting is useless if it only applies to future registrations."""
    _register(editor, make_cert(days_until_expiry=200))
    cert = _only(session)
    outbox.mail.clear()

    response = editor.post_form(
        "/settings",
        {
            "recipient_emails": "team@example.org",
            "calendar_recipient_emails": "calendar@example.org",
            "thresholds": "60, 30",
            "calendar_renew_lead_days": "45",
            "calendar_alarm_days": "14, 2",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "msg=calendar-retimed" in response.headers["location"]

    # Re-issued against the same UIDs with a higher SEQUENCE, so calendars
    # move the existing events instead of showing a second invitation.
    bodies = _ics_bodies(outbox)
    assert len(bodies) == 2
    for body in bodies:
        assert f"UID:cert-{cert.id}-" in body
        assert "SEQUENCE:1" in body
        assert "METHOD:REQUEST" in body
        assert "TRIGGER:-P14D" in body

    renew = session.exec(
        select(CalendarInvite).where(CalendarInvite.kind == InviteKind.RENEW)
    ).one()
    assert renew.event_date == cert.not_after.date() - dt.timedelta(days=45)


async def test_saving_settings_without_touching_the_timing_sends_nothing(
    editor: Client, session: Session, outbox: Outbox, app_settings
):
    _register(editor, make_cert(days_until_expiry=200))
    outbox.mail.clear()

    response = editor.post_form(
        "/settings",
        {
            "recipient_emails": "someone-else@example.org",
            "calendar_renew_lead_days": str(app_settings.calendar_renew_lead_days),
            "calendar_alarm_days": ", ".join(str(day) for day in app_settings.calendar_alarm_days),
        },
        follow_redirects=False,
    )
    assert "msg=settings-saved" in response.headers["location"]
    assert outbox.invites == [], "nobody should get an invite for an unrelated change"


def test_the_settings_page_offers_both_timings(editor: Client, app_settings):
    body = editor.get("/settings").text
    assert "Put the “renew” event this many days before expiry" in body
    assert "Remind attendees this many days before each event" in body
    assert "Send an email and a Teams card this many days before expiry" in body
