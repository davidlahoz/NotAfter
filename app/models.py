"""Database models.

Only public certificate material is ever stored: see
:class:`Certificate`. There is deliberately no column that could hold a
private key, a password or an uploaded file.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Column, DateTime, UniqueConstraint
from sqlmodel import Field, SQLModel

DEFAULT_THRESHOLDS: list[int] = [60, 30, 14, 7, 1]
EXPIRED_DAILY_THRESHOLD = -1

#: "Expires today". Always notified on, whatever thresholds are configured.
EXPIRY_DAY_THRESHOLD = 0


def utcnow() -> datetime:
    """Current UTC time, without a tzinfo (SQLite stores naive datetimes)."""
    return datetime.now(UTC).replace(tzinfo=None)


class CertSource(StrEnum):
    """Where a record's expiry date came from."""

    UPLOAD = "upload"
    MANUAL = "manual"


class CertStatus(StrEnum):
    """Lifecycle state of a record."""

    ACTIVE = "active"
    ARCHIVED = "archived"


class Channel(StrEnum):
    """A delivery channel for notifications."""

    EMAIL = "email"
    TEAMS = "teams"


class DeliveryStatus(StrEnum):
    """Outcome of one delivery attempt."""

    SENT = "sent"
    ERROR = "error"
    SKIPPED = "skipped"


class InviteKind(StrEnum):
    """Which of the two calendar events a row describes."""

    EXPIRY = "expiry"
    RENEW = "renew"


class InviteMethod(StrEnum):
    """iCalendar METHOD used for an invite."""

    REQUEST = "REQUEST"
    CANCEL = "CANCEL"


class Certificate(SQLModel, table=True):
    """One registered certificate.

    ``pem`` holds the public certificate only. It is stored because it is
    public information and lets the app re-verify and de-duplicate without
    asking the user to upload again.
    """

    __tablename__ = "certificate"

    id: int | None = Field(default=None, primary_key=True)

    # --- What a human typed --------------------------------------------
    label: str = Field(index=True)
    environment: str = Field(default="", index=True)
    owner_email: str = Field(default="")
    notes: str = Field(default="")

    # --- Provenance ------------------------------------------------------
    source: CertSource = Field(default=CertSource.UPLOAD, index=True)
    verified: bool = Field(default=True, index=True)

    # --- Extracted from the certificate ----------------------------------
    subject_cn: str = Field(default="")
    subject_rfc4514: str = Field(default="")
    issuer_rfc4514: str = Field(default="")
    serial_decimal: str = Field(default="")
    not_before: datetime | None = Field(default=None, sa_column=Column(DateTime))
    not_after: datetime = Field(sa_column=Column(DateTime, nullable=False, index=True))
    fingerprint_sha256: str | None = Field(default=None, index=True, unique=True)
    sans: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    key_algorithm: str = Field(default="")
    key_size: int | None = Field(default=None)
    pem: str | None = Field(default=None)

    # --- Lifecycle -------------------------------------------------------
    status: CertStatus = Field(default=CertStatus.ACTIVE, index=True)
    archived_at: datetime | None = Field(default=None, sa_column=Column(DateTime))
    archive_reason: str = Field(default="")
    superseded_by_id: int | None = Field(default=None, foreign_key="certificate.id", index=True)

    # --- Notification preferences ----------------------------------------
    # Each of these is an override: null means "use the global setting", so a
    # certificate only differs where somebody has said it should.
    muted: bool = Field(default=False)
    extra_recipients: list[str] = Field(
        default_factory=list, sa_column=Column(JSON, nullable=False)
    )
    #: When set, ``extra_recipients`` is the whole audience for this
    #: certificate rather than an addition to the default recipients.
    recipients_replace_defaults: bool = Field(default=False)
    reminder_days: list[int] | None = Field(default=None, sa_column=Column(JSON))
    calendar_renew_lead_days: int | None = Field(default=None)
    calendar_alarm_days: list[int] | None = Field(default=None, sa_column=Column(JSON))

    created_at: datetime = Field(default_factory=utcnow, sa_column=Column(DateTime, nullable=False))
    updated_at: datetime = Field(default_factory=utcnow, sa_column=Column(DateTime, nullable=False))
    created_by: str = Field(default="")

    def days_left(self, on_date: date | None = None) -> int:
        """Days until expiry, computed at call time (never stored)."""
        reference = on_date or datetime.now(UTC).date()
        return (self.not_after.date() - reference).days

    @property
    def is_active(self) -> bool:
        """Whether this record still appears on the board."""
        return self.status == CertStatus.ACTIVE

    # -- Effective settings -------------------------------------------------
    # One place decides whether this certificate's own value or the global
    # default applies, so the job, the calendar and the page cannot disagree.

    def thresholds(self, defaults: AppSettings) -> list[int]:
        """Days before expiry that send an email and a Teams card."""
        return self.reminder_days if self.reminder_days else list(defaults.thresholds)

    def renew_lead_days(self, defaults: AppSettings) -> int:
        """How far before expiry this certificate's renewal event sits."""
        if self.calendar_renew_lead_days is None:
            return defaults.calendar_renew_lead_days
        return self.calendar_renew_lead_days

    def alarm_days(self, defaults: AppSettings) -> list[int]:
        """Reminders the attendee's calendar fires before each event."""
        if self.calendar_alarm_days is None:
            return list(defaults.calendar_alarm_days)
        return list(self.calendar_alarm_days)

    def has_own_schedule(self, defaults: AppSettings) -> bool:
        """Whether this certificate departs from the global schedule."""
        return (
            self.reminder_days is not None
            or self.calendar_renew_lead_days is not None
            or self.calendar_alarm_days is not None
        ) and (
            self.thresholds(defaults) != list(defaults.thresholds)
            or self.renew_lead_days(defaults) != defaults.calendar_renew_lead_days
            or self.alarm_days(defaults) != list(defaults.calendar_alarm_days)
        )


class NotificationLog(SQLModel, table=True):
    """One notification that was attempted for one certificate.

    The unique constraint is what makes sending idempotent: a restart or a
    second run of the daily job can never produce a duplicate message.
    ``dedupe_key`` is ``"t30"`` for a threshold or ``"expired:2027-04-08"``
    for a daily expired reminder.
    """

    __tablename__ = "notification_log"
    __table_args__ = (
        UniqueConstraint("cert_id", "channel", "dedupe_key", name="uq_notification_once"),
    )

    id: int | None = Field(default=None, primary_key=True)
    cert_id: int = Field(foreign_key="certificate.id", index=True)
    channel: Channel = Field(index=True)
    threshold: int
    dedupe_key: str = Field(index=True)
    sent_at: datetime = Field(default_factory=utcnow, sa_column=Column(DateTime, nullable=False))
    status: DeliveryStatus = Field(default=DeliveryStatus.SENT, index=True)
    error: str = Field(default="")
    recipients: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    attempts: int = Field(default=1)


class CalendarInvite(SQLModel, table=True):
    """A sent iCalendar invite, tracked so SEQUENCE can be incremented."""

    __tablename__ = "calendar_invite"
    __table_args__ = (UniqueConstraint("cert_id", "kind", name="uq_invite_kind"),)

    id: int | None = Field(default=None, primary_key=True)
    cert_id: int = Field(foreign_key="certificate.id", index=True)
    kind: InviteKind
    uid: str = Field(index=True)
    sequence: int = Field(default=0)
    method: InviteMethod = Field(default=InviteMethod.REQUEST)
    event_date: date
    recipients: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    sent_at: datetime = Field(default_factory=utcnow, sa_column=Column(DateTime, nullable=False))
    status: DeliveryStatus = Field(default=DeliveryStatus.SENT)
    error: str = Field(default="")
    cancelled: bool = Field(default=False)


class AuditLog(SQLModel, table=True):
    """Append-only record of everything that changed.

    ``details_json`` never contains file contents, passwords or webhook URLs.
    """

    __tablename__ = "audit_log"

    id: int | None = Field(default=None, primary_key=True)
    actor_email: str = Field(default="", index=True)
    action: str = Field(index=True)
    target: str = Field(default="", index=True)
    at: datetime = Field(default_factory=utcnow, sa_column=Column(DateTime, nullable=False))
    details_json: dict[str, Any] = Field(
        default_factory=dict, sa_column=Column(JSON, nullable=False)
    )


class AppSettings(SQLModel, table=True):
    """Editable global settings. Exactly one row, with ``id == 1``."""

    __tablename__ = "app_settings"

    id: int | None = Field(default=1, primary_key=True)
    recipient_emails: list[str] = Field(
        default_factory=list, sa_column=Column(JSON, nullable=False)
    )
    calendar_recipient_emails: list[str] = Field(
        default_factory=list, sa_column=Column(JSON, nullable=False)
    )
    teams_webhook_url: str = Field(default="")
    thresholds: list[int] = Field(
        default_factory=lambda: list(DEFAULT_THRESHOLDS),
        sa_column=Column(JSON, nullable=False),
    )
    notify_daily_when_expired: bool = Field(default=True)
    #: How long before expiry the "renew" calendar event is placed.
    calendar_renew_lead_days: int = Field(default=30)
    #: Reminders the attendee's calendar fires, in days before each event.
    calendar_alarm_days: list[int] = Field(
        default_factory=lambda: [7, 1], sa_column=Column(JSON, nullable=False)
    )
    #: While a certificate is expired, repeat the Teams alert this often.
    #: 0 turns the escalation off and leaves Teams on the daily schedule.
    expired_teams_every_hours: int = Field(default=1)
    warn_days: int = Field(default=60)
    critical_days: int = Field(default=30)
    contact_line: str = Field(
        default="If something here is red or amber, contact the integration team."
    )
    updated_at: datetime = Field(default_factory=utcnow, sa_column=Column(DateTime, nullable=False))


class JobRun(SQLModel, table=True):
    """Result of one run of the daily notification job (for /healthz)."""

    __tablename__ = "job_run"

    id: int | None = Field(default=None, primary_key=True)
    started_at: datetime = Field(default_factory=utcnow, sa_column=Column(DateTime, nullable=False))
    finished_at: datetime | None = Field(default=None, sa_column=Column(DateTime))
    trigger: str = Field(default="schedule")
    certificates_checked: int = Field(default=0)
    notifications_sent: int = Field(default=0)
    failures: int = Field(default=0)
    ok: bool = Field(default=True)
    detail: str = Field(default="")
