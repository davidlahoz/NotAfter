"""The two ways mail leaves: Resend's API, and SMTP."""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest

from app.config import Settings
from app.notify import DeliveryError
from app.notify import email as email_channel

ICS = b"BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nEND:VCALENDAR\r\n"


def resend_settings(**overrides: Any) -> Settings:
    return Settings(
        _env_file=None,
        email_provider="resend",
        resend_api_key="re_test_key",
        email_from="no-after@example.org",
        email_from_name="No After",
        **overrides,
    )


def message(**overrides: Any) -> email_channel.Message:
    defaults: dict[str, Any] = {
        "to": ["team@example.org"],
        "subject": 'Certificate "Integration PROD" expires in 30 days',
        "text": "plain body",
        "html_body": "<p>rich body</p>",
    }
    defaults.update(overrides)
    return email_channel.Message(**defaults)


class Recorder:
    """Stands in for the Resend endpoint."""

    def __init__(self, status: int = 200, body: dict[str, Any] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self._status = status
        self._body = body if body is not None else {"id": "abc"}

    def client(self) -> httpx.AsyncClient:
        def handle(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return httpx.Response(self._status, json=self._body)

        return httpx.AsyncClient(transport=httpx.MockTransport(handle))

    @property
    def payload(self) -> dict[str, Any]:
        body: dict[str, Any] = json.loads(self.requests[-1].content)
        return body


async def test_a_notification_is_posted_to_resend():
    recorder = Recorder()
    async with recorder.client() as client:
        await email_channel._send_via_resend(message(), resend_settings(), client=client)

    request = recorder.requests[-1]
    assert str(request.url) == "https://api.resend.com/emails"
    assert request.headers["authorization"] == "Bearer re_test_key"

    payload = recorder.payload
    assert payload["from"] == "No After <no-after@example.org>"
    assert payload["to"] == ["team@example.org"]
    assert payload["text"] == "plain body"
    assert payload["html"] == "<p>rich body</p>"
    assert "attachments" not in payload


async def test_a_calendar_invite_keeps_its_method():
    """Outlook and Google need the METHOD to treat the file as an invite."""
    recorder = Recorder()
    invite = message(
        calendar=email_channel.Attachment(filename="invite.ics", content=ICS, method="CANCEL")
    )
    async with recorder.client() as client:
        await email_channel._send_via_resend(invite, resend_settings(), client=client)

    attachment = recorder.payload["attachments"][0]
    assert attachment["filename"] == "invite.ics"
    assert attachment["content_type"] == "text/calendar; method=CANCEL; charset=UTF-8"
    assert base64.b64decode(attachment["content"]) == ICS


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, "RESEND_API_KEY was not accepted"),
        (403, "Verify the EMAIL_FROM domain"),
        (422, "rejected the message as invalid"),
        (429, "rate limiting"),
    ],
)
async def test_a_silent_refusal_falls_back_to_our_own_advice(status: int, expected: str):
    recorder = Recorder(status=status, body={})
    with pytest.raises(DeliveryError) as caught:
        async with recorder.client() as client:
            await email_channel._send_via_resend(message(), resend_settings(), client=client)
    assert expected in str(caught.value)
    assert str(status) in str(caught.value)


async def test_resends_own_message_is_preferred_when_it_has_one():
    """It is more specific than anything this app could guess."""
    recorder = Recorder(status=403, body={"message": "The example.org domain is not verified."})
    with pytest.raises(DeliveryError) as caught:
        async with recorder.client() as client:
            await email_channel._send_via_resend(message(), resend_settings(), client=client)
    text = str(caught.value)
    assert "The example.org domain is not verified." in text
    assert "Verify the EMAIL_FROM domain" not in text, "advice should not be doubled"


async def test_the_api_key_never_appears_in_an_error():
    """Resend's text reaches the settings page and notification_log.

    So it is redacted where it is built, not where it is displayed — by then
    it has already been stored.
    """
    recorder = Recorder(status=401, body={"message": "invalid key re_test_key_abcdef"})
    with pytest.raises(DeliveryError) as caught:
        async with recorder.client() as client:
            await email_channel._send_via_resend(message(), resend_settings(), client=client)
    assert "re_test_key_abcdef" not in str(caught.value)
    assert "[redacted-api-key]" in str(caught.value)


async def test_a_network_failure_says_what_to_check():
    def explode(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    async with httpx.AsyncClient(transport=httpx.MockTransport(explode)) as client:
        with pytest.raises(DeliveryError) as caught:
            await email_channel._send_via_resend(message(), resend_settings(), client=client)
    assert "api.resend.com" in str(caught.value)


async def test_unconfigured_email_is_refused_before_any_request():
    blank = Settings(_env_file=None, email_provider="resend", resend_api_key="", email_from="")
    with pytest.raises(DeliveryError) as caught:
        await email_channel.send_message(message(), blank)
    assert "EMAIL_FROM" in str(caught.value)


async def test_smtp_mode_without_a_host_points_at_the_resend_relay():
    settings = Settings(_env_file=None, email_provider="smtp", email_from="a@example.org")
    with pytest.raises(DeliveryError) as caught:
        await email_channel._send_via_smtp(message(), settings)
    assert "smtp.resend.com" in str(caught.value)


def test_smtp_still_builds_a_native_invite():
    """The reason to prefer the relay: a real text/calendar alternative part."""
    settings = Settings(
        _env_file=None,
        email_provider="smtp",
        smtp_host="smtp.resend.com",
        email_from="no-after@example.org",
        email_from_name="No After",
    )
    built = email_channel.build_email(
        message(
            calendar=email_channel.Attachment(filename="invite.ics", content=ICS, method="REQUEST")
        ),
        settings,
    )
    types = {part.get_content_type() for part in built.walk()}
    assert "text/calendar" in types
    calendar_parts = [part for part in built.walk() if part.get_content_type() == "text/calendar"]
    assert any(part.get_param("method") == "REQUEST" for part in calendar_parts)
    assert built["From"] == "No After <no-after@example.org>"


def test_every_message_says_it_takes_no_replies():
    """The address only sends, and people should not learn that from a bounce."""
    import datetime as dt

    from app.models import Certificate
    from app.notify.email import NO_REPLY_NOTE, render_notification

    cert = Certificate(
        label="Integration PROD", not_after=dt.datetime.now() + dt.timedelta(days=30)
    )
    _subject, text, html_body = render_notification(
        cert, 30, detail_url="https://x/1", contact_line="Ask the integration team."
    )
    assert NO_REPLY_NOTE in text
    assert NO_REPLY_NOTE in html_body
