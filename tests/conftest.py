"""Test fixtures: an app on an in-memory database with a recorded mail sink."""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlmodel import Session

os.environ.setdefault("AUTH_MODE", "dev")
os.environ.setdefault("EDITOR_EMAILS", "editor@example.org")
os.environ.setdefault("SMTP_HOST", "smtp.example.org")
os.environ.setdefault("SMTP_FROM", "notafter@example.org")
os.environ.setdefault("BASE_URL", "https://certs.example.org")

from app import db as db_module
from app.config import Settings
from app.db import create_all
from app.main import create_app
from app.models import AppSettings
from app.notifier import Notifier
from app.notify import email as email_channel
from app.notify import teams as teams_channel
from app.security import CSRF_COOKIE, CSRF_HEADER, limiter

EDITOR = "editor@example.org"
VIEWER = "viewer@example.org"


@dataclass
class SentMail:
    """One message the app tried to send."""

    to: list[str]
    subject: str
    text: str
    html: str = ""
    calendar: bytes | None = None
    method: str | None = None


@dataclass
class Outbox:
    """Everything the app tried to send during a test."""

    mail: list[SentMail] = field(default_factory=list)
    cards: list[dict[str, Any]] = field(default_factory=list)
    fail_email: bool = False
    fail_teams: bool = False

    def clear(self) -> None:
        self.mail.clear()
        self.cards.clear()
        self.fail_email = False
        self.fail_teams = False

    @property
    def invites(self) -> list[SentMail]:
        return [item for item in self.mail if item.calendar is not None]


@pytest.fixture
def test_settings(tmp_path: Any) -> Settings:
    return Settings(
        _env_file=None,
        auth_mode="dev",
        editor_emails=EDITOR,
        database_url=f"sqlite:///{tmp_path}/test.db",
        base_url="https://certs.example.org",
        secret_key="test-secret-key",
        smtp_host="smtp.example.org",
        smtp_from="notafter@example.org",
        smtp_from_name="NotAfter",
        scheduler_enabled=False,
    )


@pytest.fixture
def outbox(monkeypatch: pytest.MonkeyPatch) -> Outbox:
    """Capture outgoing email and Teams cards instead of sending them."""
    box = Outbox()

    async def fake_send(message: email_channel.Message, settings: Settings) -> None:
        if box.fail_email:
            from app.notify import DeliveryError

            raise DeliveryError("the mail server refused the message (test)")
        if not settings.smtp_configured:
            from app.notify import DeliveryError

            raise DeliveryError("Email is not configured.")
        box.mail.append(
            SentMail(
                to=list(message.to),
                subject=message.subject,
                text=message.text,
                html=message.html_body,
                calendar=message.calendar.content if message.calendar else None,
                method=message.calendar.method if message.calendar else None,
            )
        )

    async def fake_post(webhook_url: str, payload: dict[str, Any], **_kwargs: Any) -> None:
        from app.notify import DeliveryError

        if box.fail_teams:
            raise DeliveryError("Teams replied 500 (test)")
        if not webhook_url:
            raise DeliveryError("No Teams webhook is configured.")
        box.cards.append(payload)

    monkeypatch.setattr(email_channel, "send_message", fake_send)
    monkeypatch.setattr(teams_channel, "post_card", fake_post)
    return box


@pytest.fixture
def app(test_settings: Settings, outbox: Outbox) -> Iterator[FastAPI]:
    """A fresh application on its own database."""
    limiter.reset()
    engine = db_module.build_engine(test_settings)
    db_module.set_engine(engine)
    create_all(engine)
    application = create_app(test_settings)
    application.state.notifier = Notifier(test_settings)
    yield application
    db_module.set_engine(None)
    engine.dispose()


@pytest.fixture
def session(app: FastAPI) -> Iterator[Session]:
    with Session(db_module.get_engine()) as db_session:
        yield db_session


class Client(TestClient):
    """Test client that carries an identity and a matching CSRF token."""

    def __init__(self, application: FastAPI, email: str) -> None:
        super().__init__(application, base_url="https://certs.example.org")
        self.headers["X-Dev-User"] = email

    def csrf(self) -> str:
        """Fetch a page so the CSRF cookie is set, then return the token."""
        self.get("/")
        return self.cookies.get(CSRF_COOKIE) or ""

    def post_form(self, url: str, data: dict[str, Any], **kwargs: Any) -> Any:
        payload = {**data, "csrf_token": self.csrf()}
        return self.post(url, data=payload, **kwargs)

    def post_files(
        self, url: str, files: dict[str, Any], data: dict[str, Any] | None = None, **kwargs: Any
    ) -> Any:
        payload = {**(data or {}), "csrf_token": self.csrf()}
        return self.post(url, data=payload, files=files, **kwargs)

    def post_json(self, url: str, payload: dict[str, Any], **kwargs: Any) -> Any:
        token = self.csrf()
        return self.post(url, json=payload, headers={CSRF_HEADER: token}, **kwargs)


@pytest.fixture
def editor(app: FastAPI) -> Iterator[Client]:
    with Client(app, EDITOR) as client:
        yield client


@pytest.fixture
def viewer(app: FastAPI) -> Iterator[Client]:
    with Client(app, VIEWER) as client:
        yield client


@pytest.fixture
def app_settings(session: Session) -> AppSettings:
    """The settings row, with recipients configured."""
    from app.db import load_app_settings

    settings = load_app_settings(session)
    settings.recipient_emails = ["team@example.org"]
    settings.calendar_recipient_emails = ["calendar@example.org"]
    session.add(settings)
    session.commit()
    session.refresh(settings)
    return settings
