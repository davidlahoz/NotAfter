"""Application configuration, loaded from the environment only."""

from __future__ import annotations

import sys
from functools import lru_cache
from ipaddress import ip_address
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AuthMode = Literal["cloudflare", "dev"]
EmailProviderName = Literal["resend", "smtp"]

#: Placeholder secret. Running in ``cloudflare`` mode with this value set is
#: refused at start-up.
DEV_SECRET_KEY = "dev-insecure-secret-change-me"  # noqa: S105


class ConfigError(RuntimeError):
    """Raised when the environment is not a usable configuration."""


class Settings(BaseSettings):
    """Environment-provided settings.

    Nothing here is ever written to the database or a log line; secrets are
    redacted by :func:`app.logging_setup.redact` before anything is emitted.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Core -----------------------------------------------------------
    app_name: str = "NotAfter"
    base_url: str = "http://127.0.0.1:8000"
    secret_key: str = Field(
        default="dev-insecure-secret-change-me",
        description="HMAC key for CSRF tokens. Must be set in production.",
    )
    database_url: str = "sqlite:////data/notafter.db"
    log_level: str = "INFO"

    # --- Authentication -------------------------------------------------
    auth_mode: AuthMode = "cloudflare"
    cf_access_team: str = ""
    cf_access_aud: str = ""
    editor_emails: str = ""
    dev_user_email: str = "dev@example.org"

    # --- Scheduler ------------------------------------------------------
    scheduler_enabled: bool = True
    daily_run_time: str = "07:00"
    timezone: str = "UTC"

    # --- Email ----------------------------------------------------------
    #: "resend" posts to the Resend API; "smtp" talks to a mail server.
    email_provider: EmailProviderName = "resend"

    #: The address every message comes from. It is also the ORGANIZER of
    #: every calendar invite, so it must be a real mailbox on a domain the
    #: provider is allowed to send for.
    email_from: str = ""
    email_from_name: str = "No After"

    # Resend.
    resend_api_key: str = ""
    resend_api_url: str = "https://api.resend.com/emails"

    # SMTP. Also the way to use Resend's relay: smtp.resend.com, username
    # "resend", password the API key — which keeps calendar invites native.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_starttls: bool = True
    smtp_use_tls: bool = False
    smtp_timeout: int = 30

    # Superseded by EMAIL_FROM / EMAIL_FROM_NAME; still read so that an
    # existing .env keeps working.
    smtp_from: str = ""
    smtp_from_name: str = ""

    # --- Limits ---------------------------------------------------------
    max_upload_bytes: int = 256 * 1024
    upload_rate_limit: str = "20/hour"
    settings_rate_limit: str = "30/hour"

    @field_validator("daily_run_time")
    @classmethod
    def _validate_time(cls, value: str) -> str:
        parts = value.split(":")
        if len(parts) != 2 or not all(p.isdigit() for p in parts):
            msg = f"DAILY_RUN_TIME must look like '07:00', got {value!r}"
            raise ValueError(msg)
        hour, minute = int(parts[0]), int(parts[1])
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            msg = f"DAILY_RUN_TIME out of range: {value!r}"
            raise ValueError(msg)
        return value

    @property
    def editor_email_set(self) -> frozenset[str]:
        """Lower-cased set of addresses allowed to make changes."""
        return frozenset(
            item.strip().lower() for item in self.editor_emails.split(",") if item.strip()
        )

    @property
    def cf_issuer(self) -> str:
        """Expected ``iss`` claim of an Access token."""
        return f"https://{self.cf_access_team}.cloudflareaccess.com"

    @property
    def cf_certs_url(self) -> str:
        """Where Cloudflare publishes the Access signing keys."""
        return f"{self.cf_issuer}/cdn-cgi/access/certs"

    @property
    def base_url_is_loopback(self) -> bool:
        """Whether BASE_URL points at this machine and nowhere else."""
        host = urlparse(self.base_url).hostname or ""
        if host in {"localhost", "::1"}:
            return True
        try:
            return ip_address(host).is_loopback
        except ValueError:
            return False

    @property
    def from_address(self) -> str:
        """The address messages come from, honouring the older setting name."""
        return self.email_from or self.smtp_from

    @property
    def from_name(self) -> str:
        """The display name messages come from."""
        return self.email_from_name or self.smtp_from_name or "No After"

    @property
    def email_configured(self) -> bool:
        """Whether enough is set for email to be attempted."""
        if not self.from_address:
            return False
        if self.email_provider == "resend":
            return bool(self.resend_api_key)
        return bool(self.smtp_host)

    @property
    def email_warnings(self) -> list[str]:
        """What is stopping email from working, in words, or nothing."""
        if self.email_configured:
            return []
        problems: list[str] = []
        if not self.from_address:
            problems.append(
                "EMAIL_FROM is not set, so no email or calendar invite can be "
                "sent. Use an address on a domain verified in your provider; "
                "it is also the organiser of every calendar invite."
            )
        if self.email_provider == "resend" and not self.resend_api_key:
            problems.append("RESEND_API_KEY is not set, so no email can be sent.")
        if self.email_provider == "smtp" and not self.smtp_host:
            problems.append("SMTP_HOST is not set, so no email can be sent.")
        return problems

    @property
    def email_description(self) -> str:
        """One line describing how mail leaves, for the settings page."""
        if not self.email_configured:
            return "; ".join(self.email_warnings) or "not configured"
        if self.email_provider == "resend":
            return f"Resend, from {self.from_address}"
        return f"{self.smtp_host}:{self.smtp_port}, from {self.from_address}"

    def validate_startup(self) -> None:
        """Fail fast on configurations that would be unsafe to run.

        Raises:
            ConfigError: with a message that explains exactly what to set.
        """
        if self.auth_mode == "cloudflare":
            missing = [
                name
                for name, value in (
                    ("CF_ACCESS_TEAM", self.cf_access_team),
                    ("CF_ACCESS_AUD", self.cf_access_aud),
                )
                if not value
            ]
            if missing:
                msg = (
                    f"AUTH_MODE=cloudflare requires {' and '.join(missing)}. "
                    "CF_ACCESS_TEAM is your Cloudflare Access team name (the "
                    "'<team>' in https://<team>.cloudflareaccess.com) and "
                    "CF_ACCESS_AUD is the Application Audience tag of the "
                    "Access application in front of this app."
                )
                raise ConfigError(msg)
            if self.secret_key == DEV_SECRET_KEY:
                msg = (
                    "SECRET_KEY is still the built-in development value. "
                    "Generate one with: python -c "
                    "'import secrets; print(secrets.token_urlsafe(48))'"
                )
                raise ConfigError(msg)
        if self.auth_mode == "dev" and not self.base_url_is_loopback:
            msg = (
                "AUTH_MODE=dev takes the user's identity from an X-Dev-User "
                "header, which anyone can forge, so it may only be used "
                f"locally — but BASE_URL is {self.base_url!r}. Either set "
                "BASE_URL to a loopback address such as "
                "http://127.0.0.1:8087, or switch to AUTH_MODE=cloudflare "
                "and set CF_ACCESS_TEAM and CF_ACCESS_AUD."
            )
            raise ConfigError(msg)
        # Email is not a security boundary, so an incomplete mail
        # configuration must never stop the board from serving. It is
        # reported here, on the settings page and on /healthz instead.
        for warning in self.email_warnings:
            print(f"notafter: warning: {warning}", file=sys.stderr)
        if not self.editor_email_set:
            print(
                "notafter: warning: EDITOR_EMAILS is empty, so every "
                "authenticated user is read-only.",
                file=sys.stderr,
            )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()
