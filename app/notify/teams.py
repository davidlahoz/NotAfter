"""Microsoft Teams delivery via a Workflows webhook.

The retired Office 365 connector format is deliberately not used: the payload
below is an Adaptive Card 1.4 posted to a Power Automate ("Workflows")
webhook URL. The URL itself is a secret and never appears in a log line or an
error message.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from ipaddress import ip_address
from typing import Any, Final
from urllib.parse import urlparse

import httpx

from app.formatting import countdown_phrase, format_date, status_for
from app.logging_setup import logger
from app.models import Certificate
from app.notify import DeliveryError

ADAPTIVE_CARD_VERSION: Final = "1.4"
MAX_ATTEMPTS: Final = 3
BACKOFF_SECONDS: Final = (1.0, 4.0)

_COLOUR = {"ok": "good", "warning": "warning", "critical": "attention", "expired": "attention"}


def build_card(
    cert: Certificate,
    days: int,
    *,
    detail_url: str,
    contact_line: str,
    warn_days: int = 60,
    critical_days: int = 30,
    repeat_hours: int = 0,
) -> dict[str, Any]:
    """Build the Adaptive Card payload for one certificate.

    ``repeat_hours`` adds a line saying how often the alert will come back and
    how to stop it, so nobody has to guess why it keeps arriving.
    """
    status = status_for(days, warn_days=warn_days, critical_days=critical_days)
    facts = [
        {"title": "Expires", "value": format_date(cert.not_after)},
        {"title": "Common name", "value": cert.subject_cn or "not recorded"},
        {"title": "Environment", "value": cert.environment or "not set"},
        {"title": "Owner", "value": cert.owner_email or "not set"},
    ]
    if not cert.verified:
        facts.append({"title": "Note", "value": "Entered by hand — expiry unverified."})

    body: list[dict[str, Any]] = [
        {
            "type": "TextBlock",
            "text": status.word,
            "weight": "Bolder",
            "color": _COLOUR[status.level.value],
            "spacing": "None",
        },
        {
            "type": "TextBlock",
            "text": f"{cert.label} — {countdown_phrase(days)}",
            "size": "Large",
            "weight": "Bolder",
            "wrap": True,
        },
        {"type": "TextBlock", "text": status.sentence, "wrap": True},
        {"type": "FactSet", "facts": facts},
        {
            "type": "TextBlock",
            "text": contact_line,
            "wrap": True,
            "isSubtle": True,
            "size": "Small",
        },
    ]
    if repeat_hours:
        every = "hour" if repeat_hours == 1 else f"{repeat_hours} hours"
        body.append(
            {
                "type": "TextBlock",
                "text": (
                    f"This alert repeats every {every} until the certificate is "
                    "renewed, archived or muted in No After."
                ),
                "wrap": True,
                "isSubtle": True,
                "size": "Small",
            }
        )

    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": ADAPTIVE_CARD_VERSION,
                    "body": body,
                    "actions": [
                        {
                            "type": "Action.OpenUrl",
                            "title": "Open in No After",
                            "url": detail_url,
                        }
                    ],
                },
            }
        ],
    }


def build_test_card(
    cert: Certificate,
    days: int,
    *,
    detail_url: str,
    contact_line: str,
) -> dict[str, Any]:
    """The 'send test Teams card' payload.

    Deliberately the *same* card as a real notification, with one line added
    to say it is a test. A test built from a simpler payload could succeed
    while the real one failed, which would make it worse than useless.
    """
    payload = build_card(cert, days, detail_url=detail_url, contact_line=contact_line)
    body = payload["attachments"][0]["content"]["body"]
    body.insert(
        0,
        {
            "type": "TextBlock",
            "text": "Test message from No After — this is what a reminder looks like.",
            "wrap": True,
            "isSubtle": True,
            "size": "Small",
        },
    )
    return payload


class WebhookNotAllowed(DeliveryError):
    """The webhook URL does not point where a Teams webhook should."""


def validate_webhook_url(url: str, allowed_suffixes: Sequence[str]) -> None:
    """Refuse a webhook the server should not be making requests to.

    The URL comes from whoever can edit the settings, and the server then
    fetches it. Without this, that is a way to have the server reach hosts
    the person cannot — cloud metadata, another container, an internal admin
    port — and the reply's status code comes back to them as an error
    message, which is enough to map what is listening.

    Raises:
        WebhookNotAllowed: with a message naming what is wrong.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise WebhookNotAllowed(
            "A Teams webhook URL must start with https://. "
            f"This one starts with {parsed.scheme or 'nothing'}://."
        )
    host = (parsed.hostname or "").lower()
    if not host:
        raise WebhookNotAllowed("That webhook URL has no hostname.")

    try:
        address = ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        raise WebhookNotAllowed("A Teams webhook URL names a Microsoft host, not an IP address.")

    if allowed_suffixes and not any(
        host == suffix.lstrip(".") or host.endswith(suffix) for suffix in allowed_suffixes
    ):
        allowed = ", ".join(allowed_suffixes)
        raise WebhookNotAllowed(
            f"That webhook points at {host}, which is not a Microsoft "
            f"workflow host. Expected one ending in: {allowed}. Copy the URL "
            "from the Teams workflow itself, or widen "
            "TEAMS_WEBHOOK_ALLOWED_HOSTS if you relay through your own host."
        )


async def post_card(
    webhook_url: str,
    payload: dict[str, Any],
    *,
    client: httpx.AsyncClient | None = None,
    max_attempts: int = MAX_ATTEMPTS,
    allowed_suffixes: Sequence[str] = (),
) -> int:
    """POST a card, retrying 429 and 5xx responses with a short backoff.

    Returns the HTTP status Teams replied with. Note what that does and does
    not mean: a Workflows webhook answers ``202 Accepted`` as soon as it has
    queued the flow, before any of the flow's own steps run. A 202 therefore
    proves the request arrived and was accepted — not that a card reached the
    channel. If one never appears, the flow's run history is where the reason
    is.

    Raises:
        DeliveryError: when every attempt failed. The URL is never included.
    """
    if not webhook_url:
        raise DeliveryError(
            "No Teams webhook is configured. Add a Workflows webhook URL on "
            "the settings page, or turn Teams notifications off."
        )
    # Checked again here, not only where it is saved: a value that reached the
    # database another way must still not be fetched.
    validate_webhook_url(webhook_url, allowed_suffixes)

    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=20.0)
    last_error = "unknown error"
    try:
        for attempt in range(1, max_attempts + 1):
            try:
                response = await http.post(webhook_url, json=payload)
            except httpx.HTTPError as exc:
                last_error = f"the request failed ({type(exc).__name__})"
            else:
                if response.status_code < 400:
                    return response.status_code
                last_error = f"Teams replied {response.status_code}"
                if response.status_code not in (408, 429) and response.status_code < 500:
                    break
            if attempt < max_attempts:
                await asyncio.sleep(BACKOFF_SECONDS[min(attempt - 1, len(BACKOFF_SECONDS) - 1)])
        logger.warning("Teams delivery failed after %s attempts", max_attempts)
        raise DeliveryError(
            f"The Teams card could not be delivered: {last_error}. Check that "
            "the Workflows webhook still exists and is not disabled, then use "
            "'Send test Teams card' on the settings page."
        )
    finally:
        if owns_client:
            await http.aclose()
