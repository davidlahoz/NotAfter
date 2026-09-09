"""Shared presentation helpers.

Kept in one place so the board, the emails, the Teams cards and the calendar
invites all describe a certificate with the same words. "Days left" is always
computed here from ``not_after``; it is never stored.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import StrEnum


class StatusLevel(StrEnum):
    """Traffic-light level of one certificate."""

    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class Status:
    """A level plus the plain words shown next to it."""

    level: StatusLevel
    word: str
    sentence: str


def today() -> date:
    """Today's date in UTC.

    One definition, used by the board, the job and the models, so that a
    countdown never disagrees with itself.
    """
    return datetime.now(UTC).date()


def format_date(value: date | datetime | None) -> str:
    """Format as ``8 April 2027``.

    Written without ``%-d`` so it behaves the same on every libc.
    """
    if value is None:
        return "—"
    day = value.day
    return f"{day} {value:%B %Y}"


def format_datetime(value: datetime | None) -> str:
    """Format as ``8 April 2027, 14:05 UTC``."""
    if value is None:
        return "—"
    return f"{format_date(value)}, {value:%H:%M} UTC"


def days_left(not_after: datetime, on_date: date | None = None) -> int:
    """Whole days from ``today`` until the expiry date."""
    reference = on_date or today()
    return (not_after.date() - reference).days


def countdown_phrase(days: int) -> str:
    """The big number line: ``30 days left``, ``expires today``, ``4 days ago``."""
    if days == 0:
        return "expires today"
    if days > 0:
        return f"{days} day{'s' if days != 1 else ''} left"
    overdue = abs(days)
    return f"{overdue} day{'s' if overdue != 1 else ''} ago"


def status_for(days: int, *, warn_days: int = 60, critical_days: int = 30) -> Status:
    """Translate a countdown into a level, a word and a sentence.

    The sentences are written for someone who does not know what a
    certificate is.
    """
    if days < 0:
        return Status(
            StatusLevel.EXPIRED,
            "Expired",
            "This has already expired. Anything using it may have stopped working.",
        )
    if days <= critical_days:
        return Status(
            StatusLevel.CRITICAL,
            "Renew now",
            "This stops working very soon. Get the replacement in place this week.",
        )
    if days <= warn_days:
        return Status(
            StatusLevel.WARNING,
            "Plan the renewal",
            "Start asking for the replacement now — issuing one can take weeks.",
        )
    return Status(
        StatusLevel.OK,
        "In date",
        "Nothing to do yet.",
    )


def threshold_phrase(level: StatusLevel, *, warn_days: int, critical_days: int) -> str:
    """Where this status begins, in days.

    It sits on the group heading rather than in a legend at the foot of the
    page: once the groups say what to do in words, a separate key repeats
    everything except these numbers.
    """
    match level:
        case StatusLevel.OK:
            return f"more than {warn_days} days left"
        case StatusLevel.WARNING:
            return f"{warn_days} days or fewer"
        case StatusLevel.CRITICAL:
            return f"{critical_days} days or fewer"
        case StatusLevel.EXPIRED:
            return "past the date"


def humanise_list(values: list[str], empty: str = "nobody") -> str:
    """``a, b and c`` for a list of addresses."""
    cleaned = [value for value in values if value]
    if not cleaned:
        return empty
    if len(cleaned) == 1:
        return cleaned[0]
    return f"{', '.join(cleaned[:-1])} and {cleaned[-1]}"


def fingerprint_groups(fingerprint: str) -> list[str]:
    """A hex fingerprint as colon-separated pairs, ready to be laid out.

    Returned as a list so the template can put a break opportunity after each
    pair. Joining them with a colon gives the usual display form.
    """
    return [fingerprint[index : index + 2].upper() for index in range(0, len(fingerprint), 2)]


#: Characters that have no place in a label, a name or an address, and that
#: break the things those values are later put into — mail headers above all.
_CONTROL = dict.fromkeys(range(32)) | {127: None}


def clean_text(value: str, *, limit: int = 200) -> str:
    """Strip control characters and trim a free-text field to a sane length.

    Applied where text enters the application rather than where it is used:
    by the time a label reaches a mail header it is too late to find out that
    it contains a newline.
    """
    return value.translate(_CONTROL).strip()[:limit]


#: What each audit action was, said in words. The raw identifier stays on the
#: row as a title attribute, because an audit trail has to stay precise.
AUDIT_ACTIONS: dict[str, str] = {
    "auth.signin": "Signed in",
    "certificate.create": "Registered a certificate",
    "certificate.update": "Changed a certificate",
    "certificate.attach": "Attached the certificate file",
    "certificate.renew": "Registered a replacement",
    "certificate.archive": "Archived a certificate",
    "certificate.restore": "Restored a certificate",
    "calendar.resend": "Re-sent the calendar invitation",
    "calendar.retimed": "Changed the calendar timing",
    "notification.test": "Sent a test notification",
    "settings.update": "Changed the settings",
    "settings.test": "Sent a test message",
    "settings.test_failed": "A test message failed",
    "job.run": "Ran the notification job",
}

#: Field names as a reader would say them.
_DETAIL_LABELS: dict[str, str] = {
    "not_after": "expires",
    "fingerprint_sha256": "fingerprint",
    "recorded_expiry": "date recorded by hand",
    "certificate_expiry": "date in the certificate",
    "confirmed_replacement": "replacement confirmed",
    "superseded_by": "replaced by record",
    "new_expiry": "new expiry",
    "teams_webhook_set": "Teams webhook",
    "notify_daily_when_expired": "daily while expired",
    "expired_teams_every_hours": "Teams repeat (hours)",
    "calendar_recipients": "calendar recipients",
    "certificates_checked": "certificates checked",
    "notifications_sent": "notifications sent",
    "certificates_updated": "certificates updated",
    "renew_lead_days": "renewal reminder (days)",
    "alarm_days": "calendar alarms (days)",
    "reminder_days": "reminder days",
    "recipients_replace_defaults": "replaces the default recipients",
    "http_status": "reply",
    "warn_days": "amber at (days)",
    "critical_days": "red at (days)",
}


def describe_action(action: str) -> str:
    """An audit action in words, falling back to the raw identifier."""
    return AUDIT_ACTIONS.get(action, action)


def format_details(details: dict[str, object], omit: Sequence[str] = ()) -> list[tuple[str, str]]:
    """Turn an audit entry's stored fields into readable pairs.

    The raw mapping used to be rendered straight into the page, so people
    read Python: quoted keys, ``True``, and a full 64-character fingerprint
    that pushed everything else out of the row. ``omit`` drops fields the row
    already states elsewhere.
    """
    pairs: list[tuple[str, str]] = []
    for key, value in details.items():
        if key in omit:
            continue
        name = _DETAIL_LABELS.get(key, key.replace("_", " "))
        pairs.append((name, _format_detail_value(key, value)))
    return pairs


def _format_detail_value(key: str, value: object) -> str:
    """One field's value, short enough to sit on a row."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) if value else "none"
    text = str(value)
    if "fingerprint" in key and len(text) > 20:
        # Enough to recognise, not enough to fill the row.
        return f"{text[:16]}…"
    if len(text) > 80:
        return f"{text[:79]}…"
    return text


def format_datetime_compact(value: datetime | None) -> str:
    """``8 Sep 2026, 14:45`` — a form that fits a table column."""
    if value is None:
        return "—"
    return f"{value.day} {value:%b %Y}, {value:%H:%M}"
