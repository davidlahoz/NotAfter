"""iCalendar invites for certificate expiry and renewal.

Two all-day events per certificate, with stable UIDs derived from the record
id so that later updates and cancellations replace the original event in
Outlook and Google Calendar rather than creating duplicates.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Final

from icalendar import Alarm, Calendar, Event, vCalAddress, vText

from app.formatting import format_date
from app.models import Certificate, InviteKind, InviteMethod

PRODID: Final = "-//NotAfter//Certificate expiry board//EN"
UID_DOMAIN: Final = "notafter"

#: Defaults for the two timings, used when settings do not say otherwise.
DEFAULT_ALARM_DAYS: Final = (7, 1)
DEFAULT_RENEW_LEAD_DAYS: Final = 30


def event_uid(cert_id: int, kind: InviteKind) -> str:
    """Stable UID for one of a certificate's two events."""
    return f"cert-{cert_id}-{kind.value}@{UID_DOMAIN}"


def event_date_for(
    cert: Certificate,
    kind: InviteKind,
    renew_lead_days: int = DEFAULT_RENEW_LEAD_DAYS,
) -> date:
    """Date of the expiry event, or of the renewal reminder before it."""
    expiry = cert.not_after.date()
    if kind is InviteKind.EXPIRY:
        return expiry
    return expiry - timedelta(days=max(renew_lead_days, 0))


def event_summary(cert: Certificate, kind: InviteKind) -> str:
    """Title shown in the attendee's calendar."""
    if kind is InviteKind.EXPIRY:
        return f"Certificate expires: {cert.label}"
    return f"Renew certificate: {cert.label}"


def _description(cert: Certificate, kind: InviteKind, detail_url: str, renew_lead_days: int) -> str:
    """Plain-language body of the calendar event."""
    expiry = format_date(cert.not_after)
    subject = cert.subject_cn or cert.label
    if kind is InviteKind.EXPIRY:
        opening = (
            f'The certificate "{cert.label}" ({subject}) expires today, {expiry}.'
            " Systems that rely on it may stop working until it is replaced."
        )
    else:
        opening = (
            f'Time to renew the certificate "{cert.label}" ({subject}).'
            f" It expires on {expiry}, in {renew_lead_days} "
            f"day{'' if renew_lead_days == 1 else 's'}."
        )
    lines = [
        opening,
        "",
        "Request the replacement certificate from whoever issues it, install it",
        "in the system that uses it, then register the new file in No After so",
        "this board and these reminders move to the new expiry date.",
        "",
        f"Details: {detail_url}",
    ]
    if cert.owner_email:
        lines.insert(1, f"Owner: {cert.owner_email}")
    return "\n".join(lines)


def build_calendar(
    cert: Certificate,
    kind: InviteKind,
    *,
    sequence: int,
    method: InviteMethod,
    organizer_email: str,
    organizer_name: str,
    attendees: list[str],
    detail_url: str,
    renew_lead_days: int = DEFAULT_RENEW_LEAD_DAYS,
    alarm_days: Sequence[int] = DEFAULT_ALARM_DAYS,
    now: datetime | None = None,
) -> bytes:
    """Render one VEVENT wrapped in a VCALENDAR with the given ``METHOD``."""
    calendar = Calendar()
    calendar.add("prodid", PRODID)
    calendar.add("version", "2.0")
    calendar.add("calscale", "GREGORIAN")
    calendar.add("method", method.value)

    event = Event()
    day = event_date_for(cert, kind, renew_lead_days)
    event.add("uid", event_uid(cert.id or 0, kind))
    event.add("dtstamp", now or datetime.now(UTC))
    event.add("dtstart", day)
    event.add("dtend", day + timedelta(days=1))
    event.add("summary", event_summary(cert, kind))
    event.add("description", _description(cert, kind, detail_url, renew_lead_days))
    event.add("sequence", sequence)
    event.add("transp", "TRANSPARENT")
    event.add("class", "PUBLIC")
    event.add("url", detail_url)
    event.add("status", "CANCELLED" if method is InviteMethod.CANCEL else "CONFIRMED")

    organizer = vCalAddress(f"MAILTO:{organizer_email}")
    organizer.params["cn"] = vText(organizer_name)
    event.add("organizer", organizer)

    for address in attendees:
        attendee = vCalAddress(f"MAILTO:{address}")
        attendee.params["cn"] = vText(address)
        attendee.params["cutype"] = vText("INDIVIDUAL")
        attendee.params["role"] = vText("REQ-PARTICIPANT")
        attendee.params["partstat"] = vText("NEEDS-ACTION")
        attendee.params["rsvp"] = vText("TRUE")
        event.add("attendee", attendee, encode=False)

    if method is InviteMethod.REQUEST:
        for days in sorted({day for day in alarm_days if day > 0}, reverse=True):
            alarm = Alarm()
            alarm.add("action", "DISPLAY")
            alarm.add("description", event_summary(cert, kind))
            alarm.add("trigger", timedelta(days=-days))
            event.add_component(alarm)

    calendar.add_component(event)
    ical: bytes = calendar.to_ical()
    return ical
