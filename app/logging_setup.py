"""Logging that cannot leak secrets.

Every record passes through :class:`RedactingFilter`, which masks anything
that looks like a webhook URL, an SMTP password or a PEM block before the
line reaches a handler.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Final

_PATTERNS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    # Teams / generic webhook URLs.
    (
        re.compile(r"https://[\w.-]*(?:logic\.azure|webhook|office)[\w./-]*\S*", re.IGNORECASE),
        "https://[redacted-webhook]",
    ),
    # Anything shaped like a secret assignment.
    (
        re.compile(
            r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|webhook[_-]?url)"
            r"(\s*[=:]\s*)\S+"
        ),
        r"\1\2[redacted]",
    ),
    # PEM blocks of any kind, including certificates.
    (
        re.compile(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.DOTALL),
        "[redacted-pem]",
    ),
    # Bearer / JWT-looking strings.
    (
        re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+"),
        "[redacted-jwt]",
    ),
)


def redact(message: str) -> str:
    """Mask secrets in a string destined for a log line or an error page."""
    for pattern, replacement in _PATTERNS:
        message = pattern.sub(replacement, message)
    return message


class RedactingFilter(logging.Filter):
    """Applies :func:`redact` to the formatted message and its arguments."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact the record in place; always keeps the record."""
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: _redact_value(v) for k, v in record.args.items()}
            else:
                record.args = tuple(_redact_value(a) for a in record.args)
        return True


def _redact_value(value: Any) -> Any:
    return redact(value) if isinstance(value, str) else value


def configure_logging(level: str = "INFO") -> None:
    """Install the redacting filter on the root and uvicorn loggers.

    Request bodies are never logged: uvicorn's access log records only the
    method, path and status.
    """
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    redacting = RedactingFilter()
    for handler in logging.getLogger().handlers:
        handler.addFilter(redacting)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "notafter"):
        logger = logging.getLogger(name)
        logger.addFilter(redacting)
        for handler in logger.handlers:
            handler.addFilter(redacting)


logger = logging.getLogger("notafter")
