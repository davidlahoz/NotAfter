"""The daily notification job and the in-process scheduler.

Thresholds are evaluated from ``not_after`` at run time — no "days remaining"
value is ever stored. Only the nearest threshold that has been crossed is
reported; the ones it overtook are recorded as superseded so they cannot fire
later.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlmodel import Session, col, desc, select

from app.config import Settings, get_settings
from app.db import load_app_settings, session_scope
from app.formatting import today as today_utc
from app.logging_setup import logger
from app.models import (
    EXPIRED_DAILY_THRESHOLD,
    EXPIRY_DAY_THRESHOLD,
    Certificate,
    Channel,
    DeliveryStatus,
    JobRun,
    utcnow,
)
from app.notifier import Notifier, expired_hour_key, expired_key, threshold_key
from app.services import active_for_notifications


@dataclass(frozen=True, slots=True)
class DueNotification:
    """One notification the job has decided to send."""

    certificate: Certificate
    days: int
    threshold: int
    dedupe_key: str
    superseded: list[int]


def plan_for(
    cert: Certificate,
    thresholds: list[int],
    *,
    today: date,
    notify_when_expired: bool,
) -> DueNotification | None:
    """Decide what, if anything, is due for one certificate today.

    A certificate 30 days from expiry reports the 30-day threshold, not the
    60-day one it passed earlier.

    Zero is always a threshold, whatever the configured list says: the day a
    certificate stops working is the one day nobody should hear nothing. It is
    not covered by the expired reminders either, which only begin once the
    date has passed.
    """
    days = cert.days_left(today)
    if days < 0:
        if not notify_when_expired:
            return None
        return DueNotification(
            certificate=cert,
            days=days,
            threshold=EXPIRED_DAILY_THRESHOLD,
            dedupe_key=expired_key(today),
            superseded=[],
        )

    effective = set(thresholds) | {EXPIRY_DAY_THRESHOLD}
    crossed = sorted(threshold for threshold in effective if days <= threshold)
    if not crossed:
        return None
    nearest = crossed[0]
    return DueNotification(
        certificate=cert,
        days=days,
        threshold=nearest,
        dedupe_key=threshold_key(nearest),
        superseded=crossed[1:],
    )


async def run_daily_job(
    session: Session,
    notifier: Notifier | None = None,
    *,
    trigger: str = "schedule",
    on_date: date | None = None,
) -> JobRun:
    """Send every notification that is due, exactly once.

    Safe to run repeatedly: the unique constraint on ``notification_log``
    means a second run — or a run after a restart — sends nothing new.
    """
    notifier = notifier or Notifier()
    app_settings = load_app_settings(session)
    reference = on_date or today_utc()

    run = JobRun(trigger=trigger)
    session.add(run)
    session.commit()
    session.refresh(run)

    channels = [Channel.EMAIL]
    if app_settings.teams_webhook_url:
        channels.append(Channel.TEAMS)

    sent = 0
    failures = 0
    problems: list[str] = []
    certificates = active_for_notifications(session)

    for cert in certificates:
        plan = plan_for(
            cert,
            app_settings.thresholds,
            today=reference,
            notify_when_expired=app_settings.notify_daily_when_expired,
        )
        if plan is None:
            continue
        if plan.superseded:
            notifier.mark_superseded(session, cert, plan.superseded, channels)

        # While a certificate is expired, Teams is driven by the hourly
        # escalation; sending here too would double up.
        due_channels = (
            [channel for channel in channels if channel is not Channel.TEAMS]
            if plan.days < 0 and app_settings.expired_teams_every_hours
            else channels
        )
        outcomes = await notifier.notify_expiry(
            session,
            cert,
            days=plan.days,
            threshold=plan.threshold,
            dedupe_key=plan.dedupe_key,
            app_settings=app_settings,
            channels=due_channels,
        )
        for outcome in outcomes:
            if outcome.status is DeliveryStatus.SENT:
                sent += 1
            elif outcome.status is DeliveryStatus.ERROR:
                failures += 1
                problems.append(f"{cert.label} ({outcome.channel.value}): {outcome.error}")

    run.finished_at = utcnow()
    run.certificates_checked = len(certificates)
    run.notifications_sent = sent
    run.failures = failures
    run.ok = failures == 0
    run.detail = "; ".join(problems[:5])[:1000] if problems else "all notifications delivered"
    session.add(run)
    session.commit()
    session.refresh(run)
    logger.info(
        "daily job (%s): %s certificates, %s sent, %s failed",
        trigger,
        run.certificates_checked,
        sent,
        failures,
    )
    return run


async def run_expiry_escalation(
    session: Session,
    notifier: Notifier | None = None,
    *,
    trigger: str = "schedule",
    now: datetime | None = None,
) -> JobRun:
    """Re-alert Teams about every expired certificate.

    Runs every hour. Each certificate that has passed its expiry date gets one
    Teams card per interval, and keeps getting them until it is renewed,
    archived or muted — those are the three things that take it out of
    :func:`active_for_notifications`.

    Like the daily run, this is safe to repeat: the dedupe key names the
    interval, so a restart or a catch-up run inside the same slot sends
    nothing new.
    """
    notifier = notifier or Notifier()
    app_settings = load_app_settings(session)
    moment = now or datetime.now(UTC).replace(tzinfo=None)

    run = JobRun(trigger=f"expiry-escalation:{trigger}")
    session.add(run)
    session.commit()
    session.refresh(run)

    sent = 0
    failures = 0
    problems: list[str] = []
    expired: list[Certificate] = []

    every_hours = app_settings.expired_teams_every_hours
    if every_hours and app_settings.teams_webhook_url:
        expired = [
            cert for cert in active_for_notifications(session) if cert.days_left(moment.date()) < 0
        ]
        key = expired_hour_key(moment, every_hours)
        for cert in expired:
            outcomes = await notifier.notify_expiry(
                session,
                cert,
                days=cert.days_left(moment.date()),
                threshold=EXPIRED_DAILY_THRESHOLD,
                dedupe_key=key,
                app_settings=app_settings,
                channels=[Channel.TEAMS],
            )
            for outcome in outcomes:
                if outcome.status is DeliveryStatus.SENT:
                    sent += 1
                elif outcome.status is DeliveryStatus.ERROR:
                    failures += 1
                    problems.append(f"{cert.label} (teams): {outcome.error}")

    run.finished_at = utcnow()
    run.certificates_checked = len(expired)
    run.notifications_sent = sent
    run.failures = failures
    run.ok = failures == 0
    run.detail = "; ".join(problems[:5])[:1000] if problems else "no expired certificates"
    session.add(run)
    session.commit()
    session.refresh(run)
    if expired:
        logger.info(
            "expiry escalation (%s): %s expired, %s alerted, %s failed",
            trigger,
            len(expired),
            sent,
            failures,
        )
    return run


def last_job_run(session: Session) -> JobRun | None:
    """The most recently started job run, for ``/healthz``."""
    return session.exec(select(JobRun).order_by(desc(col(JobRun.id))).limit(1)).first()


class NotificationScheduler:
    """Runs :func:`run_daily_job` once a day, in this process."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._scheduler = AsyncIOScheduler(timezone=self._settings.timezone)

    @property
    def running(self) -> bool:
        """Whether the scheduler thread is alive."""
        return bool(self._scheduler.running)

    @property
    def next_run_time(self) -> datetime | None:
        """When the daily job will next fire, if it is scheduled."""
        job = self._scheduler.get_job("daily-notifications")
        return job.next_run_time if job else None

    @property
    def next_escalation_time(self) -> datetime | None:
        """When the hourly expired-certificate alert will next fire."""
        job = self._scheduler.get_job("expiry-escalation")
        return job.next_run_time if job else None

    async def _run(self) -> None:
        with session_scope() as session:
            await run_daily_job(session, trigger="schedule")

    async def _run_escalation(self) -> None:
        with session_scope() as session:
            await run_expiry_escalation(session, trigger="schedule")

    def start(self) -> None:
        """Schedule the daily run at ``DAILY_RUN_TIME``."""
        if not self._settings.scheduler_enabled:
            logger.info("scheduler disabled by configuration")
            return
        hour, minute = (int(part) for part in self._settings.daily_run_time.split(":"))
        self._scheduler.add_job(
            self._run,
            CronTrigger(hour=hour, minute=minute, timezone=self._settings.timezone),
            id="daily-notifications",
            name="Daily certificate expiry notifications",
            replace_existing=True,
            misfire_grace_time=3600,
            coalesce=True,
            max_instances=1,
        )
        self._scheduler.add_job(
            self._run_escalation,
            CronTrigger(minute=0, timezone=self._settings.timezone),
            id="expiry-escalation",
            name="Repeat Teams alerts for expired certificates",
            replace_existing=True,
            misfire_grace_time=600,
            coalesce=True,
            max_instances=1,
        )
        self._scheduler.start()
        logger.info(
            "scheduler started: daily at %s %s, expiry escalation hourly",
            self._settings.daily_run_time,
            self._settings.timezone,
        )

    def shutdown(self) -> None:
        """Stop the scheduler without waiting for a running job."""
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)
