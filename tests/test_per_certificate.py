"""Each certificate can be chased on its own schedule, by its own people.

The Teams webhook stays global on purpose: a channel is a place people are
invited to in Teams, not a list this application maintains.
"""

from __future__ import annotations

import datetime as dt

import pytest
from sqlmodel import Session, select

from app.jobs import run_daily_job
from app.models import AppSettings, CalendarInvite, Certificate, CertSource, InviteKind
from app.notifier import Notifier
from tests.conftest import Client, Outbox


def _make(session: Session, label: str, days: int, **overrides) -> Certificate:
    cert = Certificate(
        label=label,
        owner_email=f"{label.lower().replace(' ', '-')}-owner@example.org",
        source=CertSource.UPLOAD,
        verified=True,
        not_after=dt.datetime.now() + dt.timedelta(days=days),
        fingerprint_sha256=f"fp-{label}",
        **overrides,
    )
    session.add(cert)
    session.commit()
    session.refresh(cert)
    return cert


@pytest.fixture
def notifier(test_settings) -> Notifier:
    return Notifier(test_settings)


# --- One message, not one each --------------------------------------------


async def test_one_email_goes_to_everyone_rather_than_one_each(
    session: Session, notifier: Notifier, outbox: Outbox, app_settings: AppSettings
):
    _make(
        session,
        "Integration PROD",
        7,
        extra_recipients=["ops@example.org", "duty@example.org"],
    )
    await run_daily_job(session, notifier)

    assert len(outbox.mail) == 1, "one message, addressed to all of them"
    assert outbox.mail[0].to == [
        "team@example.org",
        "ops@example.org",
        "duty@example.org",
        "integration-prod-owner@example.org",
    ]


def test_one_calendar_event_carries_every_attendee(
    editor: Client, session: Session, outbox: Outbox, app_settings: AppSettings
):
    from tests.fixtures import make_cert

    editor.post_files(
        "/certificates/new/upload",
        files={"file": ("c.pem", make_cert(days_until_expiry=200).pem, "application/octet-stream")},
        data={
            "label": "Integration PROD",
            "owner_email": "owner@example.org",
        },
    )
    cert = session.exec(select(Certificate)).one()
    cert.extra_recipients = ["ops@example.org"]
    session.add(cert)
    session.commit()
    outbox.mail.clear()

    editor.post_form(f"/certificates/{cert.id}/resend-invites", {})

    invites = outbox.invites
    assert len(invites) == 2, "one invite per event, not one per person"
    for invite in invites:
        body = invite.calendar.decode() if invite.calendar else ""
        attendees = [line for line in body.splitlines() if "ATTENDEE" in line or "MAILTO" in line]
        joined = " ".join(attendees)
        for address in ("calendar@example.org", "ops@example.org", "owner@example.org"):
            assert address in joined, f"{address} missing from the event"
        assert invite.to == ["calendar@example.org", "ops@example.org", "owner@example.org"]


# --- Its own schedule ------------------------------------------------------


async def test_a_certificate_follows_its_own_reminder_days(
    session: Session, notifier: Notifier, outbox: Outbox, app_settings: AppSettings
):
    """Global thresholds are 60/30/14/7/1; this one is chased at 90 and 45."""
    _make(session, "Special", 90, reminder_days=[90, 45])
    _make(session, "Ordinary", 90)

    await run_daily_job(session, notifier)
    assert [message.subject.split('"')[1] for message in outbox.mail] == ["Special"]

    outbox.mail.clear()
    await run_daily_job(session, notifier, on_date=dt.date.today() + dt.timedelta(days=32))
    chased = {message.subject.split('"')[1] for message in outbox.mail}
    assert chased == {"Ordinary"}, "the ordinary one hits its 60-day rule, the special one does not"


async def test_an_empty_override_follows_the_global_schedule(
    session: Session, notifier: Notifier, outbox: Outbox, app_settings: AppSettings
):
    cert = _make(session, "Ordinary", 60)
    assert cert.reminder_days is None
    assert cert.thresholds(app_settings) == app_settings.thresholds

    await run_daily_job(session, notifier)
    assert len(outbox.mail) == 1


def test_a_certificate_can_have_its_own_calendar_timing(
    editor: Client, session: Session, outbox: Outbox, app_settings: AppSettings
):
    from tests.fixtures import make_cert

    editor.post_files(
        "/certificates/new/upload",
        files={"file": ("c.pem", make_cert(days_until_expiry=300).pem, "application/octet-stream")},
        data={"label": "Integration PROD"},
    )
    cert = session.exec(select(Certificate)).one()
    outbox.mail.clear()

    response = editor.post_form(
        f"/certificates/{cert.id}/update",
        {
            "label": "Integration PROD",
            "calendar_renew_lead_days": "120",
            "calendar_alarm_days": "30, 5",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "msg=calendar-retimed" in response.headers["location"]

    session.refresh(cert)
    assert cert.renew_lead_days(app_settings) == 120

    renew = session.exec(
        select(CalendarInvite).where(CalendarInvite.kind == InviteKind.RENEW)
    ).one()
    assert renew.event_date == cert.not_after.date() - dt.timedelta(days=120)
    assert renew.sequence == 1, "an update to the same UID, not a new invitation"

    for invite in outbox.invites:
        body = invite.calendar.decode() if invite.calendar else ""
        assert "TRIGGER:-P30D" in body
        assert "TRIGGER:-P5D" in body


# --- Its own people --------------------------------------------------------


async def test_a_certificate_can_be_taken_off_the_default_list(
    session: Session, notifier: Notifier, outbox: Outbox, app_settings: AppSettings
):
    _make(
        session,
        "Quiet",
        7,
        extra_recipients=["only-me@example.org"],
        recipients_replace_defaults=True,
    )
    await run_daily_job(session, notifier)

    assert outbox.mail[0].to == ["only-me@example.org", "quiet-owner@example.org"]
    assert "team@example.org" not in outbox.mail[0].to


def test_the_detail_page_shows_the_effective_schedule(
    editor: Client, session: Session, app_settings: AppSettings
):
    cert = _make(session, "Special", 90, reminder_days=[90, 45])
    body = editor.get(f"/certificates/{cert.id}").text
    assert "90, 45 days before expiry" in body
    assert "Its own schedule." in body

    ordinary = _make(session, "Ordinary", 90)
    body = editor.get(f"/certificates/{ordinary.id}").text
    assert "Following the global schedule." in body


def test_changing_only_the_label_does_not_disturb_calendars(
    editor: Client, session: Session, outbox: Outbox, app_settings: AppSettings
):
    from tests.fixtures import make_cert

    editor.post_files(
        "/certificates/new/upload",
        files={"file": ("c.pem", make_cert(days_until_expiry=200).pem, "application/octet-stream")},
        data={"label": "Integration PROD"},
    )
    cert = session.exec(select(Certificate)).one()
    outbox.mail.clear()

    response = editor.post_form(
        f"/certificates/{cert.id}/update", {"label": "Renamed"}, follow_redirects=False
    )
    assert "msg=updated" in response.headers["location"]
    assert outbox.invites == [], "nobody should get an invite for a rename"
