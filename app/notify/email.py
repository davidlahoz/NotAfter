"""Email delivery over SMTP, including calendar invites.

Message bodies are built here so that the same wording reaches every reader:
a short plain-text part and a matching HTML part, both explaining what the
certificate is, when it expires and what to do about it.
"""

from __future__ import annotations

import html
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

import aiosmtplib

from app.config import Settings
from app.formatting import countdown_phrase, format_date, status_for
from app.logging_setup import logger
from app.models import Certificate
from app.notify import DeliveryError


@dataclass(slots=True)
class Attachment:
    """A calendar invite carried alongside the message body."""

    filename: str
    content: bytes
    subtype: str = "calendar"
    method: str | None = None


@dataclass(slots=True)
class Message:
    """A message ready to hand to the SMTP server."""

    to: list[str]
    subject: str
    text: str
    html_body: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    calendar: Attachment | None = None


def build_email(message: Message, settings: Settings) -> EmailMessage:
    """Assemble the MIME structure.

    A calendar invite is added both as an alternative ``text/calendar`` part
    (which Outlook and Google Calendar act on) and as a downloadable
    attachment (which every other client can open).
    """
    email = EmailMessage()
    email["From"] = formataddr((settings.smtp_from_name, settings.smtp_from))
    email["To"] = ", ".join(message.to)
    email["Subject"] = message.subject
    email["Message-ID"] = make_msgid(domain=settings.smtp_from.split("@")[-1] or "notafter")
    email["Auto-Submitted"] = "auto-generated"

    email.set_content(message.text)
    if message.html_body:
        email.add_alternative(message.html_body, subtype="html")

    if message.calendar is not None:
        method = message.calendar.method or "REQUEST"
        email.add_alternative(
            message.calendar.content.decode("utf-8"),
            subtype="calendar",
            params={"method": method, "charset": "UTF-8", "component": "VEVENT"},
        )
        email.add_attachment(
            message.calendar.content,
            maintype="text",
            subtype="calendar",
            filename=message.calendar.filename,
            params={"method": method, "charset": "UTF-8"},
        )

    for attachment in message.attachments:
        email.add_attachment(
            attachment.content,
            maintype="text",
            subtype=attachment.subtype,
            filename=attachment.filename,
        )
    return email


async def send_message(message: Message, settings: Settings) -> None:
    """Send one message.

    Raises:
        DeliveryError: with a message that names the problem but never the
            credentials or the body.
    """
    if not settings.smtp_configured:
        raise DeliveryError(
            "Email is not configured. Set SMTP_HOST and SMTP_FROM in the "
            "environment and restart the app."
        )
    if not message.to:
        raise DeliveryError("No recipient addresses are configured for this message.")

    email = build_email(message, settings)
    try:
        await aiosmtplib.send(
            email,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_username or None,
            password=settings.smtp_password or None,
            start_tls=settings.smtp_use_starttls and not settings.smtp_use_tls,
            use_tls=settings.smtp_use_tls,
            timeout=settings.smtp_timeout,
            tls_context=ssl.create_default_context(),
        )
    except (aiosmtplib.SMTPException, ssl.SSLError, OSError) as exc:
        logger.warning("SMTP delivery failed: %s", type(exc).__name__)
        raise DeliveryError(
            f"The mail server at {settings.smtp_host}:{settings.smtp_port} "
            f"refused the message ({type(exc).__name__}). Check the SMTP "
            "settings, then use 'Send test email' on the settings page."
        ) from exc


# --------------------------------------------------------------------------
# Bodies
# --------------------------------------------------------------------------


def notification_subject(cert: Certificate, days: int) -> str:
    """``Certificate "Integration PROD" expires in 30 days (8 April 2027)``."""
    when = format_date(cert.not_after)
    if days < 0:
        return f'Certificate "{cert.label}" expired {countdown_phrase(days)} ({when})'
    if days == 0:
        return f'Certificate "{cert.label}" expires today ({when})'
    return f'Certificate "{cert.label}" expires in {countdown_phrase(days)} ({when})'


def _fact_lines(cert: Certificate) -> list[tuple[str, str]]:
    """The facts shown in both the text and HTML parts."""
    facts = [
        ("Certificate", cert.label),
        ("Expires", format_date(cert.not_after)),
        ("Common name", cert.subject_cn or "not recorded"),
        ("Issued by", cert.issuer_rfc4514 or "not recorded"),
        ("Environment", cert.environment or "not set"),
        ("Owner", cert.owner_email or "not set"),
    ]
    if not cert.verified:
        facts.append(("Note", "Entered by hand — the expiry date is unverified."))
    return facts


def render_notification(
    cert: Certificate,
    days: int,
    *,
    detail_url: str,
    contact_line: str,
    warn_days: int = 60,
    critical_days: int = 30,
) -> tuple[str, str, str]:
    """Return ``(subject, text, html)`` for an expiry notification."""
    status = status_for(days, warn_days=warn_days, critical_days=critical_days)
    subject = notification_subject(cert, days)
    headline = (
        f"{cert.label} — {countdown_phrase(days)}"
        if days >= 0
        else f"{cert.label} — expired {countdown_phrase(days)}"
    )

    facts = _fact_lines(cert)
    text_facts = "\n".join(f"  {name}: {value}" for name, value in facts)
    text = (
        f"{headline}\n\n"
        f"{status.sentence}\n\n"
        f"{text_facts}\n\n"
        "What to do\n"
        "  1. Ask whoever issues this certificate for a replacement.\n"
        "  2. Install it in the system that uses it.\n"
        "  3. Register the new file in NotAfter so this reminder moves on.\n\n"
        f"Details: {detail_url}\n\n"
        f"{contact_line}\n"
    )

    rows = "".join(
        f'<tr><th style="text-align:left;padding:4px 16px 4px 0;color:#6b7075;'
        f'font-weight:400;">{html.escape(name)}</th>'
        f'<td style="padding:4px 0;color:#232628;">{html.escape(value)}</td></tr>'
        for name, value in facts
    )
    colour = {
        "ok": "#1b7f4c",
        "warning": "#b8740a",
        "critical": "#b3261e",
        "expired": "#b3261e",
    }[status.level.value]
    html_body = f"""<!DOCTYPE html>
<html lang="en"><body style="margin:0;padding:24px;background:#f4f4f1;
color:#232628;font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;">
<div style="max-width:560px;margin:0 auto;">
<p style="margin:0 0 4px;color:{colour};font-size:14px;">{html.escape(status.word)}</p>
<h1 style="margin:0 0 12px;font-size:24px;font-weight:600;">{html.escape(headline)}</h1>
<p style="margin:0 0 20px;color:#232628;font-size:15px;">{html.escape(status.sentence)}</p>
<table style="border-collapse:collapse;font-size:14px;margin-bottom:20px;">{rows}</table>
<p style="margin:0 0 8px;font-size:15px;"><strong>What to do</strong></p>
<ol style="margin:0 0 20px;padding-left:20px;font-size:14px;line-height:1.6;">
<li>Ask whoever issues this certificate for a replacement.</li>
<li>Install it in the system that uses it.</li>
<li>Register the new file in NotAfter so this reminder moves on.</li>
</ol>
<p style="margin:0 0 20px;font-size:14px;">
<a href="{html.escape(detail_url)}" style="color:#ff4700;">Open this certificate in NotAfter</a></p>
<p style="margin:0;color:#6b7075;font-size:13px;">{html.escape(contact_line)}</p>
</div></body></html>"""
    return subject, text, html_body
