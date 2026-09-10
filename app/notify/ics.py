"""iCalendar events for certificate expiry.

One all-day event per certificate, on the expiry date, carrying every reminder
as a VALARM — including the one that says to start the renewal. A second event
would mean a second invitation to accept and a second thing to keep in step,
which is what alarms exist to avoid.

The UID is derived from the record id and is stable, so later updates and
cancellations replace the event in Outlook and Google Calendar rather than
creating duplicates.

These are published, not invited. A ``METHOD:REQUEST`` with attendees makes
the item a meeting, and Outlook then emails the organiser whenever somebody
accepts or declines it — which, for the send-only address these come from,
bounces back to the person who clicked as a delivery failure. Nobody needs to
accept a notice that a certificate expires, so there is nothing to respond
to: ``METHOD:PUBLISH``, no attendee list, no RSVP.
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


def alarms_for(renew_lead_days: int, alarm_days: Sequence[int]) -> list[int]:
    """Every reminder the one event carries, furthest ahead first.

    The renewal lead time is just the earliest alarm: "start renewing" and
    "this expires soon" are the same event seen from different distances.
    """
    days = {day for day in (*alarm_days, renew_lead_days) if day > 0}
    return sorted(days, reverse=True)


def event_summary(cert: Certificate, kind: InviteKind) -> str:
    """Title shown in the attendee's calendar."""
    if kind is InviteKind.EXPIRY:
        return f"Certificate expires: {cert.label}"
    return f"Renew certificate: {cert.label}"


def _description(
    cert: Certificate,
    kind: InviteKind,
    detail_url: str,
    renew_lead_days: int,
    notified: Sequence[str] = (),
) -> str:
    """Plain-language body of the calendar event.

    ``notified`` says who else received it. That used to be visible as the
    attendee list, which is the thing that made clients ask for a reply.
    """
    expiry = format_date(cert.not_after)
    subject = cert.subject_cn or cert.label
    if kind is InviteKind.EXPIRY:
        plural = "" if renew_lead_days == 1 else "s"
        opening = (
            f'The certificate "{cert.label}" ({subject}) expires on {expiry}.'
            " Systems that rely on it may stop working until it is replaced."
            f" This event reminds you {renew_lead_days} day{plural} beforehand,"
            " which is when to start the renewal."
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
    if notified:
        lines.insert(-2, f"Also told: {', '.join(notified)}")
        lines.insert(-2, "")
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
    cancelling = method is InviteMethod.CANCEL
    summary = event_summary(cert, kind)
    # If a client does not act on the cancellation, the title still says so.
    event.add("summary", f"Cancelled: {summary}" if cancelling else summary)
    event.add("description", _description(cert, kind, detail_url, renew_lead_days, attendees))
    event.add("sequence", sequence)
    event.add("transp", "TRANSPARENT")
    event.add("class", "PUBLIC")
    event.add("url", detail_url)
    event.add("status", "CANCELLED" if cancelling else "CONFIRMED")
    # Outlook reads this rather than TRANSP, and an expiry notice should not
    # make anyone look busy.
    event.add("x-microsoft-cdo-busystatus", "FREE")

    organizer = vCalAddress(f"MAILTO:{organizer_email}")
    organizer.params["cn"] = vText(organizer_name)
    event.add("organizer", organizer)

    # Attendees only under REQUEST, which this application no longer sends:
    # an attendee with RSVP=TRUE is what makes Outlook mail the organiser on
    # every accept and decline. Who else was told is stated in the
    # description instead, where it informs without soliciting a reply.
    if method is InviteMethod.REQUEST:
        for address in attendees:
            attendee = vCalAddress(f"MAILTO:{address}")
            attendee.params["cn"] = vText(address)
            attendee.params["cutype"] = vText("INDIVIDUAL")
            attendee.params["role"] = vText("REQ-PARTICIPANT")
            attendee.params["partstat"] = vText("NEEDS-ACTION")
            attendee.params["rsvp"] = vText("TRUE")
            event.add("attendee", attendee, encode=False)

    if not cancelling:
        reminders = (
            alarms_for(renew_lead_days, alarm_days)
            if kind is InviteKind.EXPIRY
            else sorted({day for day in alarm_days if day > 0}, reverse=True)
        )
        for days in reminders:
            alarm = Alarm()
            alarm.add("action", "DISPLAY")
            alarm.add("description", event_summary(cert, kind))
            alarm.add("trigger", timedelta(days=-days))
            event.add_component(alarm)

    calendar.add_component(event)
    ical: bytes = calendar.to_ical()
    return ical
