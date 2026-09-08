"""Threshold rules, idempotency and the notification channels."""

from __future__ import annotations

import datetime as dt

import pytest
from sqlmodel import Session, select

from app.jobs import plan_for, run_daily_job
from app.models import (
    AppSettings,
    Certificate,
    CertSource,
    Channel,
    DeliveryStatus,
    NotificationLog,
)
from app.notifier import Notifier
from tests.conftest import APP_BASE_URL, Outbox


def _make(session: Session, *, days: int, label: str = "Integration PROD") -> Certificate:
    """A verified certificate expiring in ``days`` days."""
    cert = Certificate(
        label=label,
        environment="PROD",
        owner_email="owner@example.org",
        source=CertSource.UPLOAD,
        verified=True,
        subject_cn="edi.example.org",
        not_after=dt.datetime.now() + dt.timedelta(days=days),
        fingerprint_sha256=f"fp{days}{label}",
    )
    session.add(cert)
    session.commit()
    session.refresh(cert)
    return cert


@pytest.fixture
def notifier(test_settings) -> Notifier:
    return Notifier(test_settings)


# --- The threshold rule ---------------------------------------------------


def test_only_the_nearest_crossed_threshold_is_reported():
    cert = Certificate(label="x", not_after=dt.datetime.now() + dt.timedelta(days=30))
    plan = plan_for(cert, [60, 30, 14, 7, 1], today=dt.date.today(), notify_when_expired=True)
    assert plan is not None
    assert plan.threshold == 30
    assert plan.superseded == [60]


def test_nothing_is_due_before_the_first_threshold():
    cert = Certificate(label="x", not_after=dt.datetime.now() + dt.timedelta(days=90))
    assert plan_for(cert, [60, 30], today=dt.date.today(), notify_when_expired=True) is None


def test_an_expired_certificate_gets_a_daily_key():
    cert = Certificate(label="x", not_after=dt.datetime.now() - dt.timedelta(days=3))
    today = dt.date.today()
    plan = plan_for(cert, [60, 30], today=today, notify_when_expired=True)
    assert plan is not None
    assert plan.dedupe_key == f"expired:{today.isoformat()}"
    assert plan_for(cert, [60, 30], today=today, notify_when_expired=False) is None


# --- Idempotency ----------------------------------------------------------


async def test_running_the_job_twice_sends_each_notification_once(
    session: Session, notifier: Notifier, outbox: Outbox, app_settings: AppSettings
):
    _make(session, days=30)
    first = await run_daily_job(session, notifier)
    sent_after_first = len(outbox.mail)
    second = await run_daily_job(session, notifier)

    assert first.notifications_sent == 1
    assert second.notifications_sent == 0
    assert len(outbox.mail) == sent_after_first == 1
    assert "expires in 30 days" in outbox.mail[0].subject


async def test_a_restart_between_runs_does_not_duplicate(
    session: Session, notifier: Notifier, outbox: Outbox, app_settings: AppSettings
):
    _make(session, days=14)
    await run_daily_job(session, notifier)
    outbox.mail.clear()

    # A restart loses everything except the database.
    session.expunge_all()
    fresh = Notifier(notifier._settings)
    await run_daily_job(session, fresh)
    assert outbox.mail == []


async def test_thirty_day_rule_fires_after_the_sixty_day_one(
    session: Session, notifier: Notifier, outbox: Outbox, app_settings: AppSettings
):
    cert = _make(session, days=60)
    await run_daily_job(session, notifier, on_date=dt.date.today())
    assert [entry.threshold for entry in _logs(session, cert)] == [60]  # nothing skipped yet

    later = dt.date.today() + dt.timedelta(days=30)
    await run_daily_job(session, notifier, on_date=later)
    assert sorted(entry.threshold for entry in _logs(session, cert)) == [30, 60]
    assert "expires in 30 days" in outbox.mail[-1].subject


async def test_a_certificate_registered_late_does_not_replay_older_thresholds(
    session: Session, notifier: Notifier, outbox: Outbox, app_settings: AppSettings
):
    cert = _make(session, days=20)
    await run_daily_job(session, notifier)

    logs = {entry.threshold: entry.status for entry in _logs(session, cert)}
    assert logs[30] is DeliveryStatus.SENT
    assert logs[60] is DeliveryStatus.SKIPPED
    assert len(outbox.mail) == 1

    # Even when the 60-day rule is evaluated again, it stays silent.
    await run_daily_job(session, notifier, on_date=dt.date.today() + dt.timedelta(days=1))
    assert len(outbox.mail) == 1


async def test_a_failed_send_is_retried_on_the_next_run(
    session: Session, notifier: Notifier, outbox: Outbox, app_settings: AppSettings
):
    cert = _make(session, days=7)
    outbox.fail_email = True
    first = await run_daily_job(session, notifier)
    assert first.failures == 1
    assert not first.ok
    assert _log(session, cert, "t7").status is DeliveryStatus.ERROR

    outbox.fail_email = False
    second = await run_daily_job(session, notifier)
    assert second.notifications_sent == 1
    assert second.ok
    entry = _log(session, cert, "t7")
    assert entry.status is DeliveryStatus.SENT
    assert entry.attempts == 2


async def test_muted_certificates_are_left_alone(
    session: Session, notifier: Notifier, outbox: Outbox, app_settings: AppSettings
):
    cert = _make(session, days=7)
    cert.muted = True
    session.add(cert)
    session.commit()
    run = await run_daily_job(session, notifier)
    assert run.notifications_sent == 0
    assert outbox.mail == []


async def test_expired_certificates_are_reminded_once_a_day(
    session: Session, notifier: Notifier, outbox: Outbox, app_settings: AppSettings
):
    _make(session, days=-2)
    today = dt.date.today()
    await run_daily_job(session, notifier, on_date=today)
    await run_daily_job(session, notifier, on_date=today)
    assert len(outbox.mail) == 1
    assert "expired 2 days ago" in outbox.mail[0].subject

    await run_daily_job(session, notifier, on_date=today + dt.timedelta(days=1))
    assert len(outbox.mail) == 2


# --- Channels -------------------------------------------------------------


async def test_teams_card_is_posted_when_a_webhook_is_configured(
    session: Session, notifier: Notifier, outbox: Outbox, app_settings: AppSettings
):
    app_settings.teams_webhook_url = "https://example.org/webhook"
    session.add(app_settings)
    session.commit()
    _make(session, days=7)

    await run_daily_job(session, notifier)
    assert len(outbox.cards) == 1
    card = outbox.cards[0]["attachments"][0]["content"]
    assert card["version"] == "1.4"
    assert any("7 days left" in str(block.get("text", "")) for block in card["body"])
    assert card["actions"][0]["url"].startswith(f"{APP_BASE_URL}/certificates/")


async def test_recipients_include_the_owner_and_any_extras(
    session: Session, notifier: Notifier, outbox: Outbox, app_settings: AppSettings
):
    cert = _make(session, days=7)
    cert.extra_recipients = ["extra@example.org", "team@example.org"]
    session.add(cert)
    session.commit()

    await run_daily_job(session, notifier)
    assert outbox.mail[0].to == ["team@example.org", "extra@example.org", "owner@example.org"]


async def test_the_email_explains_what_to_do(
    session: Session, notifier: Notifier, outbox: Outbox, app_settings: AppSettings
):
    _make(session, days=7)
    await run_daily_job(session, notifier)
    message = outbox.mail[0]
    assert "What to do" in message.text
    assert "Ask whoever issues this certificate" in message.text
    assert f"{APP_BASE_URL}/certificates/" in message.text
    assert "<html" in message.html


def _log(session: Session, cert: Certificate, dedupe_key: str) -> NotificationLog:
    """The one log row for a certificate, channel and rule."""
    return session.exec(
        select(NotificationLog).where(
            NotificationLog.cert_id == cert.id,
            NotificationLog.channel == Channel.EMAIL,
            NotificationLog.dedupe_key == dedupe_key,
        )
    ).one()


def _logs(session: Session, cert: Certificate) -> list[NotificationLog]:
    return list(
        session.exec(
            select(NotificationLog).where(
                NotificationLog.cert_id == cert.id, NotificationLog.channel == Channel.EMAIL
            )
        ).all()
    )


def test_the_expiry_day_itself_always_notifies():
    """Day zero is not covered by the thresholds or by the expired reminders."""
    cert = Certificate(label="x", not_after=dt.datetime.now())
    plan = plan_for(cert, [60, 30, 14, 7, 1], today=dt.date.today(), notify_when_expired=True)
    assert plan is not None
    assert plan.days == 0
    assert plan.dedupe_key == "t0"

    # Even with the expired reminders switched off, and even if someone
    # configures a threshold list without a small value in it.
    quiet = plan_for(cert, [90], today=dt.date.today(), notify_when_expired=False)
    assert quiet is not None
    assert quiet.dedupe_key == "t0"


async def test_the_run_of_notifications_over_a_certificate_s_last_two_months(
    session: Session, notifier: Notifier, outbox: Outbox, app_settings: AppSettings
):
    """One card per rule, on the right day, and never the same one twice."""
    cert = _make(session, days=60)
    start = dt.date.today()
    subjects: list[tuple[int, str]] = []

    for offset in range(0, 65):
        day = start + dt.timedelta(days=offset)
        before = len(outbox.mail)
        await run_daily_job(session, notifier, on_date=day)
        for message in outbox.mail[before:]:
            subjects.append(((cert.not_after.date() - day).days, message.subject))

    days_notified = [days for days, _ in subjects]
    assert days_notified[:6] == [60, 30, 14, 7, 1, 0]
    assert "expires today" in subjects[5][1]
    # After the expiry date, one reminder a day and no gaps.
    assert days_notified[6:] == list(range(-1, -(len(days_notified) - 6) - 1, -1))
