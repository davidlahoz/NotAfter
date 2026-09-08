"""Microsoft Teams delivery via a Workflows webhook.

The retired Office 365 connector format is deliberately not used: the payload
below is an Adaptive Card 1.4 posted to a Power Automate ("Workflows")
webhook URL. The URL itself is a secret and never appears in a log line or an
error message.
"""

from __future__ import annotations

import asyncio
from typing import Any, Final

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
) -> dict[str, Any]:
    """Build the Adaptive Card payload for one certificate."""
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
                            "title": "Open in NotAfter",
                            "url": detail_url,
                        }
                    ],
                },
            }
        ],
    }


def build_test_card(message: str) -> dict[str, Any]:
    """A small card used by the 'send test Teams card' action."""
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
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": "NotAfter test message",
                            "size": "Large",
                            "weight": "Bolder",
                        },
                        {"type": "TextBlock", "text": message, "wrap": True},
                    ],
                },
            }
        ],
    }


async def post_card(
    webhook_url: str,
    payload: dict[str, Any],
    *,
    client: httpx.AsyncClient | None = None,
    max_attempts: int = MAX_ATTEMPTS,
) -> None:
    """POST a card, retrying 429 and 5xx responses with a short backoff.

    Raises:
        DeliveryError: when every attempt failed. The URL is never included.
    """
    if not webhook_url:
        raise DeliveryError(
            "No Teams webhook is configured. Add a Workflows webhook URL on "
            "the settings page, or turn Teams notifications off."
        )

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
                    return
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
