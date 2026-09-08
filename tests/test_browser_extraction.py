"""End-to-end proof that a .pfx never leaves the browser.

Marked ``browser`` and skipped unless Playwright and its Chromium build are
installed, so CI can run it optionally:

    pip install playwright && playwright install chromium
    pytest -m browser
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI

from tests.fixtures import make_cert, make_pkcs12, make_pkcs12_legacy

playwright_api = pytest.importorskip("playwright.sync_api", reason="playwright is not installed")

pytestmark = pytest.mark.browser

PASSWORD = "hunter2"
PORT = 8749
BASE = f"http://127.0.0.1:{PORT}"


class _Server(threading.Thread):
    """Runs the app in a background thread for the browser to talk to."""

    def __init__(self, application: FastAPI) -> None:
        super().__init__(daemon=True)
        config = uvicorn.Config(application, host="127.0.0.1", port=PORT, log_level="warning")
        self.server = uvicorn.Server(config)

    def run(self) -> None:
        self.server.run()

    def wait_until_ready(self, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.server.started:
                return
            time.sleep(0.05)
        raise RuntimeError("the test server did not start")


@pytest.fixture
def live_server(app: FastAPI) -> Iterator[str]:
    server = _Server(app)
    server.start()
    server.wait_until_ready()
    yield BASE
    server.server.should_exit = True
    server.join(timeout=10)


@pytest.mark.parametrize("scheme", ["modern", "legacy"])
def test_a_pkcs12_is_opened_in_the_page_and_only_pem_is_sent(
    live_server: str, tmp_path: Any, outbox, scheme: str
) -> None:
    """`legacy` is the Triple DES shape that Windows and keytool produce."""
    cert = make_cert("edi.example.org", days_until_expiry=120)
    pfx_path = tmp_path / "keystore.pfx"
    pfx_path.write_bytes(
        make_pkcs12(cert, password=PASSWORD.encode())
        if scheme == "modern"
        else make_pkcs12_legacy(cert, PASSWORD.encode())
    )

    sent_bodies: list[bytes] = []

    with playwright_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context(extra_http_headers={"X-Dev-User": "editor@example.org"})
        page = context.new_page()

        def record(request: Any) -> None:
            if request.method == "POST":
                body = request.post_data_buffer
                if body:
                    sent_bodies.append(body)

        page.on("request", record)
        page.goto(f"{live_server}/certificates/new")
        page.set_input_files("#file", str(pfx_path))

        page.wait_for_selector("input[type=password]", timeout=15_000)
        page.fill("input[type=password]", PASSWORD)
        page.get_by_role("button", name="Read the certificate").click()

        page.wait_for_selector("text=What will be saved", timeout=15_000)
        assert "edi.example.org" in page.content()
        assert "The private key and password stay on your computer." in page.content()

        page.fill("#upload-label", "Integration PROD")
        page.get_by_role("button", name="Register this certificate").click()
        page.wait_for_url(f"{live_server}/certificates/**", timeout=15_000)
        browser.close()

    assert sent_bodies, "the page sent nothing"
    combined = b"".join(sent_bodies)

    # What was sent is a JSON body carrying a certificate and nothing else.
    assert b"PRIVATE KEY" not in combined
    assert PASSWORD.encode() not in combined
    assert pfx_path.read_bytes()[:32] not in combined

    payload = json.loads(sent_bodies[-1])
    assert set(payload) <= {
        "label",
        "environment",
        "owner_email",
        "notes",
        "pem",
        "confirm_replacement",
    }
    assert payload["pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert "PRIVATE" not in payload["pem"]
