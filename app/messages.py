"""Confirmation messages, addressed by code.

Redirects carry a short code rather than free text, so nothing a user typed
is ever reflected back into a page.
"""

from __future__ import annotations

from typing import Final

MESSAGES: Final[dict[str, str]] = {
    "created": "Certificate registered. Calendar invites have been sent.",
    "linked": "That certificate was already registered — here it is.",
    "manual-created": (
        "Expiry recorded. It is marked unverified until someone attaches the certificate file."
    ),
    "attached": "Certificate attached. This record is now verified.",
    "renewed": "Renewal registered. The previous certificate has been archived.",
    "updated": "Changes saved.",
    "archived": "Certificate archived. Its reminders and calendar events have stopped.",
    "restored": "Certificate restored to the board.",
    "invites-sent": "Calendar invites sent.",
    "test-sent": "Test notification sent.",
    "teams-accepted": (
        "The webhook accepted the card. A Teams Workflows webhook replies as "
        "soon as it has queued the flow, before the flow's own steps run — so "
        "if no card appears in the channel, open that flow's run history in "
        "Power Automate to see which step failed."
    ),
    "settings-saved": "Settings saved.",
    "job-run": "Notification run finished. See the audit trail for what was sent.",
}

ERRORS: Final[dict[str, str]] = {
    "smtp-unconfigured": (
        "Email is not configured, so nothing was sent. Set SMTP_HOST and "
        "SMTP_FROM in the environment."
    ),
    "no-teams": (
        "No Teams webhook is configured, so nothing was sent. Add a Workflows webhook URL below."
    ),
    "send-failed": (
        "The message could not be delivered. The exact error is shown under "
        "'Recent problems' on this page."
    ),
}


def lookup(code: str | None) -> str:
    """Return the sentence for a message code, or an empty string."""
    return MESSAGES.get(code or "", "")


def lookup_error(code: str | None) -> str:
    """Return the sentence for an error code, or an empty string."""
    return ERRORS.get(code or "", "")
