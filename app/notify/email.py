"""Email delivery, including calendar invites.

Two providers, chosen by ``EMAIL_PROVIDER``: Resend's HTTP API, and SMTP.
They are behind one function, :func:`send_message`, so nothing above this
module knows which is in use.

The difference that matters is calendar invites. Over SMTP the invite is a
``text/calendar; method=REQUEST`` alternative part, which is what makes
Outlook and Google Calendar show accept and decline buttons. Resend's API has
no way to express an alternative part, so there the invite travels as an
attachment with the same content type — still openable, but not a native
invite. Resend's own SMTP relay (``smtp.resend.com``) is the way to have
both.

Message bodies are built here so that the same wording reaches every reader:
a short plain-text part and a matching HTML part, both explaining what the
certificate is, when it expires and what to do about it.
"""

from __future__ import annotations

import base64
import html
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from typing import Any

import aiosmtplib
import httpx

from app.config import Settings
from app.formatting import countdown_phrase, format_date, status_for
from app.logging_setup import logger, redact
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
    email["From"] = formataddr((settings.from_name, settings.from_address))
    email["To"] = ", ".join(message.to)
    email["Subject"] = message.subject
    email["Message-ID"] = make_msgid(domain=settings.from_address.split("@")[-1] or "notafter")
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
    """Send one message through the configured provider.

    Raises:
        DeliveryError: with a message that names the problem but never the
            credentials or the body.
    """
    if not settings.email_configured:
        raise DeliveryError(
            "Email is not configured. Set EMAIL_FROM and, for Resend, "
            "RESEND_API_KEY in the environment, then restart the app."
        )
    if not message.to:
        raise DeliveryError("No recipient addresses are configured for this message.")

    if settings.email_provider == "resend":
        await _send_via_resend(message, settings)
    else:
        await _send_via_smtp(message, settings)


async def _send_via_resend(
    message: Message, settings: Settings, *, client: httpx.AsyncClient | None = None
) -> None:
    """POST the message to Resend.

    Raises:
        DeliveryError: naming the status Resend returned, never the API key.
    """
    payload: dict[str, Any] = {
        "from": formataddr((settings.from_name, settings.from_address)),
        "to": list(message.to),
        "subject": message.subject,
        "text": message.text,
    }
    if message.html_body:
        payload["html"] = message.html_body

    attachments = list(message.attachments)
    if message.calendar is not None:
        attachments.append(message.calendar)
    if attachments:
        payload["attachments"] = [
            {
                "filename": attachment.filename,
                "content": base64.b64encode(attachment.content).decode("ascii"),
                "content_type": _content_type_of(attachment),
            }
            for attachment in attachments
        ]

    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=20.0)
    try:
        response = await http.post(
            settings.resend_api_url,
            json=payload,
            headers={"Authorization": f"Bearer {settings.resend_api_key}"},
        )
    except httpx.HTTPError as exc:
        logger.warning("Resend request failed: %s", type(exc).__name__)
        raise DeliveryError(
            f"Resend could not be reached ({type(exc).__name__}). Check that "
            "the container has outbound access to api.resend.com."
        ) from exc
    finally:
        if owns_client:
            await http.aclose()

    if response.status_code >= 400:
        raise DeliveryError(_resend_error(response))


def _resend_error(response: httpx.Response) -> str:
    """Turn a Resend error response into advice.

    The upstream message is passed through :func:`redact` before it is used:
    it ends up in ``notification_log.error`` and on the settings page, and an
    API that echoed the key back would otherwise put it there.
    """
    detail = ""
    try:
        body = response.json()
    except ValueError:
        body = {}
    if isinstance(body, dict):
        detail = redact(str(body.get("message") or body.get("error") or ""))
    hint = {
        401: "The RESEND_API_KEY was not accepted. Check it in the Resend dashboard.",
        403: "Resend refused the sender. Verify the EMAIL_FROM domain in Resend.",
        422: "Resend rejected the message as invalid.",
        429: "Resend is rate limiting. The next run will retry.",
    }.get(response.status_code, "")
    parts = [f"Resend replied {response.status_code}"]
    if detail:
        # Resend's own message is usually the more specific of the two, so the
        # built-in hint is only there for when it says nothing useful.
        parts.append(detail)
    elif hint:
        parts.append(hint)
    return ". ".join(parts)


def _content_type_of(attachment: Attachment) -> str:
    """The MIME type for one attachment, with the iCalendar method if any."""
    if attachment.subtype == "calendar":
        method = attachment.method or "REQUEST"
        return f"text/calendar; method={method}; charset=UTF-8"
    return f"text/{attachment.subtype}; charset=UTF-8"


async def _send_via_smtp(message: Message, settings: Settings) -> None:
    """Hand the message to a mail server.

    Raises:
        DeliveryError: naming the server and the failure, never the password.
    """
    if not settings.smtp_host:
        raise DeliveryError(
            "EMAIL_PROVIDER is smtp but SMTP_HOST is not set. For Resend's "
            "relay use smtp.resend.com with username 'resend' and your API "
            "key as the password."
        )
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
        "  3. Register the new file in No After so this reminder moves on.\n\n"
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
<li>Register the new file in No After so this reminder moves on.</li>
</ol>
<p style="margin:0 0 20px;font-size:14px;">
<a href="{html.escape(detail_url)}" style="color:#ff4700;">Open this certificate in No After</a></p>
<p style="margin:0;color:#6b7075;font-size:13px;">{html.escape(contact_line)}</p>
</div></body></html>"""
    return subject, text, html_body
