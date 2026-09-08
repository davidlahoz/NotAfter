"""Notification channels: email, Microsoft Teams and calendar invites."""

from __future__ import annotations


class DeliveryError(RuntimeError):
    """A notification could not be delivered.

    The message is safe to show and to store in ``notification_log.error``:
    callers construct it without webhook URLs or credentials.
    """

    @property
    def message(self) -> str:
        """The user-facing text, for handlers that build an HTTP response."""
        return str(self)
