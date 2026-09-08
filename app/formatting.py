"""Shared presentation helpers.

Kept in one place so the board, the emails, the Teams cards and the calendar
invites all describe a certificate with the same words. "Days left" is always
computed here from ``not_after``; it is never stored.
"""

from __future__ import annotations

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


def humanise_list(values: list[str], empty: str = "nobody") -> str:
    """``a, b and c`` for a list of addresses."""
    cleaned = [value for value in values if value]
    if not cleaned:
        return empty
    if len(cleaned) == 1:
        return cleaned[0]
    return f"{', '.join(cleaned[:-1])} and {cleaned[-1]}"
