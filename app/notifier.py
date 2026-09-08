"""Notification orchestration: who gets told, once, and what was recorded.

Delivery itself lives in :mod:`app.notify`. This module decides recipients,
writes :class:`~app.models.NotificationLog` rows and keeps calendar invite
SEQUENCE numbers straight, so that a restart or a second job run can never
produce a duplicate message.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import date
from typing import Any

from sqlmodel import Session, select

from app.config import Settings, get_settings
from app.formatting import format_date
from app.logging_setup import logger
from app.models import (
    AppSettings,
    CalendarInvite,
    Certificate,
    Channel,
    DeliveryStatus,
    InviteKind,
    InviteMethod,
    NotificationLog,
    utcnow,
)
from app.notify import DeliveryError
from app.notify import email as email_channel
from app.notify import teams as teams_channel
from app.notify.ics import build_calendar, event_date_for, event_summary, event_uid


@dataclass(frozen=True, slots=True)
class SendOutcome:
    """What happened for one certificate on one channel."""

    channel: Channel
    status: DeliveryStatus
    error: str = ""

    @property
    def sent(self) -> bool:
        """Whether the message actually went out."""
        return self.status is DeliveryStatus.SENT


def threshold_key(threshold: int) -> str:
    """Dedupe key for a threshold notification."""
    return f"t{threshold}"


def expired_key(day: date) -> str:
    """Dedupe key for one day's 'still expired' reminder."""
    return f"expired:{day.isoformat()}"


class Notifier:
    """Sends notifications and records exactly what was sent."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    # -- addressing -----------------------------------------------------

    def recipients_for(self, cert: Certificate, app_settings: AppSettings) -> list[str]:
        """Default recipients plus the certificate's own, de-duplicated."""
        addresses = [
            *app_settings.recipient_emails,
            *cert.extra_recipients,
        ]
        if cert.owner_email:
            addresses.append(cert.owner_email)
        return _unique(addresses)

    def calendar_recipients_for(self, cert: Certificate, app_settings: AppSettings) -> list[str]:
        """Calendar invites may go to a different list than the emails."""
        addresses = list(app_settings.calendar_recipient_emails)
        if not addresses:
            addresses = list(app_settings.recipient_emails)
        addresses.extend(cert.extra_recipients)
        if cert.owner_email:
            addresses.append(cert.owner_email)
        return _unique(addresses)

    def detail_url(self, cert: Certificate) -> str:
        """Absolute link to a certificate's page, or to the board.

        The unsaved stand-in used to preview a notification has no id, and a
        link to a record that does not exist would be worse than none.
        """
        base = self._settings.base_url.rstrip("/")
        return f"{base}/certificates/{cert.id}" if cert.id else base

    # -- expiry notifications -------------------------------------------

    async def notify_expiry(
        self,
        session: Session,
        cert: Certificate,
        *,
        days: int,
        threshold: int,
        dedupe_key: str,
        app_settings: AppSettings,
    ) -> list[SendOutcome]:
        """Send this certificate's notification on every configured channel.

        A channel that already has a ``sent`` row for ``dedupe_key`` is
        skipped; a channel with an ``error`` row is retried.
        """
        outcomes: list[SendOutcome] = []
        recipients = self.recipients_for(cert, app_settings)

        if recipients and self._settings.smtp_configured:
            outcomes.append(
                await self._deliver(
                    session,
                    cert,
                    Channel.EMAIL,
                    threshold,
                    dedupe_key,
                    recipients,
                    lambda: self._send_expiry_email(cert, days, recipients, app_settings),
                )
            )
        if app_settings.teams_webhook_url:
            outcomes.append(
                await self._deliver(
                    session,
                    cert,
                    Channel.TEAMS,
                    threshold,
                    dedupe_key,
                    [],
                    lambda: self._send_expiry_card(cert, days, app_settings),
                )
            )
        return outcomes

    async def _send_expiry_email(
        self,
        cert: Certificate,
        days: int,
        recipients: list[str],
        app_settings: AppSettings,
    ) -> None:
        subject, text, html_body = email_channel.render_notification(
            cert,
            days,
            detail_url=self.detail_url(cert),
            contact_line=app_settings.contact_line,
            warn_days=app_settings.warn_days,
            critical_days=app_settings.critical_days,
        )
        await email_channel.send_message(
            email_channel.Message(to=recipients, subject=subject, text=text, html_body=html_body),
            self._settings,
        )

    async def _send_expiry_card(
        self, cert: Certificate, days: int, app_settings: AppSettings
    ) -> None:
        card = teams_channel.build_card(
            cert,
            days,
            detail_url=self.detail_url(cert),
            contact_line=app_settings.contact_line,
            warn_days=app_settings.warn_days,
            critical_days=app_settings.critical_days,
        )
        await teams_channel.post_card(app_settings.teams_webhook_url, card)

    async def _deliver(
        self,
        session: Session,
        cert: Certificate,
        channel: Channel,
        threshold: int,
        dedupe_key: str,
        recipients: list[str],
        send: Callable[[], Awaitable[None]],
    ) -> SendOutcome:
        """Run one delivery under the once-only guarantee."""
        existing = _find_log(session, cert, channel, dedupe_key)
        if existing is not None and existing.status is DeliveryStatus.SENT:
            return SendOutcome(channel, DeliveryStatus.SKIPPED, "already sent")
        if existing is not None and existing.status is DeliveryStatus.SKIPPED:
            return SendOutcome(channel, DeliveryStatus.SKIPPED, existing.error)

        try:
            await send()
        except DeliveryError as exc:
            outcome = SendOutcome(channel, DeliveryStatus.ERROR, str(exc))
        else:
            outcome = SendOutcome(channel, DeliveryStatus.SENT)

        _upsert_log(
            session,
            existing,
            cert=cert,
            channel=channel,
            threshold=threshold,
            dedupe_key=dedupe_key,
            recipients=recipients,
            outcome=outcome,
        )
        return outcome

    def mark_superseded(
        self,
        session: Session,
        cert: Certificate,
        thresholds: list[int],
        channels: list[Channel],
    ) -> None:
        """Record thresholds that were crossed but overtaken by a nearer one.

        Without this, a certificate registered when it already has 20 days
        left would later fire the 60- and 30-day reminders as well.
        """
        for threshold in thresholds:
            key = threshold_key(threshold)
            for channel in channels:
                if _find_log(session, cert, channel, key) is not None:
                    continue
                session.add(
                    NotificationLog(
                        cert_id=cert.id or 0,
                        channel=channel,
                        threshold=threshold,
                        dedupe_key=key,
                        status=DeliveryStatus.SKIPPED,
                        error="a nearer threshold was reported instead",
                        recipients=[],
                    )
                )
        session.commit()

    # -- calendar --------------------------------------------------------

    async def send_invites(
        self,
        session: Session,
        cert: Certificate,
        app_settings: AppSettings,
        *,
        method: InviteMethod = InviteMethod.REQUEST,
        kinds: tuple[InviteKind, ...] = (InviteKind.EXPIRY, InviteKind.RENEW),
    ) -> list[SendOutcome]:
        """Send (or cancel) this certificate's two calendar events.

        SEQUENCE is incremented on every send, which is what makes calendar
        clients replace the previous version of the event.
        """
        outcomes: list[SendOutcome] = []
        recipients = self.calendar_recipients_for(cert, app_settings)
        if not recipients or not self._settings.smtp_configured:
            return outcomes

        for kind in kinds:
            record = _find_invite(session, cert, kind)
            if method is InviteMethod.CANCEL and record is None:
                continue
            sequence = (record.sequence + 1) if record else 0
            error = ""
            status = DeliveryStatus.SENT
            try:
                await self._send_invite_email(
                    cert, kind, sequence, method, recipients, app_settings
                )
            except DeliveryError as exc:
                status, error = DeliveryStatus.ERROR, str(exc)

            if record is None:
                record = CalendarInvite(
                    cert_id=cert.id or 0,
                    kind=kind,
                    uid=event_uid(cert.id or 0, kind),
                    event_date=event_date_for(cert, kind),
                )
                session.add(record)
            record.sequence = sequence
            record.method = method
            record.event_date = event_date_for(cert, kind)
            record.recipients = recipients
            record.sent_at = utcnow()
            record.status = status
            record.error = error
            record.cancelled = method is InviteMethod.CANCEL
            outcomes.append(SendOutcome(Channel.EMAIL, status, error))

        session.commit()
        return outcomes

    async def _send_invite_email(
        self,
        cert: Certificate,
        kind: InviteKind,
        sequence: int,
        method: InviteMethod,
        recipients: list[str],
        app_settings: AppSettings,
    ) -> None:
        ical = build_calendar(
            cert,
            kind,
            sequence=sequence,
            method=method,
            organizer_email=self._settings.smtp_from,
            organizer_name=self._settings.smtp_from_name,
            attendees=recipients,
            detail_url=self.detail_url(cert),
        )
        summary = event_summary(cert, kind)
        verb = "Cancelled" if method is InviteMethod.CANCEL else "Calendar reminder"
        when = format_date(event_date_for(cert, kind))
        text = (
            f"{verb}: {summary}\n\n"
            f"Date: {when}\n"
            f"Certificate: {cert.label}\n"
            f"Expires: {format_date(cert.not_after)}\n\n"
            f"Details: {self.detail_url(cert)}\n\n"
            f"{app_settings.contact_line}\n"
        )
        await email_channel.send_message(
            email_channel.Message(
                to=recipients,
                subject=f"{verb}: {summary} ({when})",
                text=text,
                calendar=email_channel.Attachment(
                    filename="invite.ics", content=ical, method=method.value
                ),
            ),
            self._settings,
        )

    async def cancel_invites(
        self, session: Session, cert: Certificate, app_settings: AppSettings
    ) -> list[SendOutcome]:
        """Withdraw both calendar events for a certificate."""
        return await self.send_invites(session, cert, app_settings, method=InviteMethod.CANCEL)

    # -- tests -----------------------------------------------------------

    async def send_test_email(self, to: str, app_settings: AppSettings) -> None:
        """Prove the SMTP settings work.

        Raises:
            DeliveryError: if the mail server refused the message.
        """
        await email_channel.send_message(
            email_channel.Message(
                to=[to],
                subject="NotAfter test email",
                text=(
                    "This is a test message from NotAfter.\n\n"
                    "If you can read it, expiry notifications will reach this "
                    "address.\n\n"
                    f"{app_settings.contact_line}\n"
                ),
                html_body=(
                    "<p>This is a test message from NotAfter.</p>"
                    "<p>If you can read it, expiry notifications will reach "
                    "this address.</p>"
                ),
            ),
            self._settings,
        )

    async def send_test_card(self, cert: Certificate, app_settings: AppSettings) -> int:
        """Send a real-shaped card and return the status Teams replied with.

        A 2xx means the webhook accepted the request. With a Workflows
        webhook that is a ``202`` returned before the flow itself runs, so it
        is not proof that a card reached the channel.

        Raises:
            DeliveryError: if the webhook rejected the card.
        """
        return await teams_channel.post_card(
            app_settings.teams_webhook_url,
            self.build_test_payload(cert, app_settings),
        )

    def build_test_payload(self, cert: Certificate, app_settings: AppSettings) -> dict[str, Any]:
        """The exact JSON the test posts, so the settings page can show it."""
        return teams_channel.build_test_card(
            cert,
            cert.days_left(),
            detail_url=self.detail_url(cert),
            contact_line=app_settings.contact_line,
        )

    async def send_test_invite(self, to: str, cert: Certificate, app_settings: AppSettings) -> None:
        """Send a one-off invite so the operator can see how it renders.

        Raises:
            DeliveryError: if the mail server refused the message.
        """
        await self._send_invite_email(
            cert, InviteKind.RENEW, 0, InviteMethod.REQUEST, [to], app_settings
        )


def _unique(values: list[str]) -> list[str]:
    """Case-insensitively de-duplicate addresses, keeping their order."""
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        cleaned = value.strip()
        if cleaned and cleaned.lower() not in seen:
            seen.add(cleaned.lower())
            result.append(cleaned)
    return result


def _find_log(
    session: Session, cert: Certificate, channel: Channel, dedupe_key: str
) -> NotificationLog | None:
    return session.exec(
        select(NotificationLog).where(
            NotificationLog.cert_id == cert.id,
            NotificationLog.channel == channel,
            NotificationLog.dedupe_key == dedupe_key,
        )
    ).first()


def _find_invite(session: Session, cert: Certificate, kind: InviteKind) -> CalendarInvite | None:
    return session.exec(
        select(CalendarInvite).where(CalendarInvite.cert_id == cert.id, CalendarInvite.kind == kind)
    ).first()


def _upsert_log(
    session: Session,
    existing: NotificationLog | None,
    *,
    cert: Certificate,
    channel: Channel,
    threshold: int,
    dedupe_key: str,
    recipients: list[str],
    outcome: SendOutcome,
) -> None:
    """Create or update the log row for one delivery attempt."""
    if existing is None:
        session.add(
            NotificationLog(
                cert_id=cert.id or 0,
                channel=channel,
                threshold=threshold,
                dedupe_key=dedupe_key,
                status=outcome.status,
                error=outcome.error,
                recipients=recipients,
            )
        )
    else:
        existing.status = outcome.status
        existing.error = outcome.error
        existing.recipients = recipients
        existing.sent_at = utcnow()
        existing.attempts += 1
    session.commit()
    if outcome.status is DeliveryStatus.ERROR:
        logger.warning(
            "notification failed: cert=%s channel=%s key=%s",
            cert.id,
            channel.value,
            dedupe_key,
        )


__all__ = ["Notifier", "SendOutcome", "expired_key", "threshold_key"]
