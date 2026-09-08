"""The FastAPI application: middleware, error pages and start-up checks."""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import Response

from app import __version__
from app.auth import AuthError, build_provider
from app.config import ConfigError, Settings, get_settings
from app.db import create_all, get_engine
from app.jobs import NotificationScheduler
from app.logging_setup import configure_logging, logger, redact
from app.notifier import Notifier
from app.routes import api, audit_page, board, certificates, settings_page
from app.security import CsrfCookieMiddleware, SecurityHeadersMiddleware, csrf_protect
from app.templating import render

STATIC_DIR = Path(__file__).parent / "static"


def _wants_json(request: Request) -> bool:
    """Whether to answer with JSON rather than an HTML error page."""
    return request.url.path.startswith("/api/") or "application/json" in request.headers.get(
        "accept", ""
    )


def _detail_parts(detail: Any) -> tuple[str, str]:
    """Split an exception detail into ``(code, message)``."""
    if isinstance(detail, dict):
        return str(detail.get("code", "error")), str(detail.get("message", ""))
    return "error", str(detail)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application.

    Raises:
        ConfigError: when the environment would not be safe to run in.
    """
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    settings.validate_startup()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        create_all(get_engine())
        scheduler = NotificationScheduler(settings)
        scheduler.start()
        application.state.scheduler = scheduler
        logger.info(
            "%s %s ready (auth mode: %s)", settings.app_name, __version__, settings.auth_mode
        )
        try:
            yield
        finally:
            scheduler.shutdown()

    application = FastAPI(
        title=settings.app_name,
        version=__version__,
        lifespan=lifespan,
        dependencies=[Depends(csrf_protect)],
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.state.settings = settings
    application.state.auth_provider = build_provider(settings)
    application.state.notifier = Notifier(settings)

    application.add_middleware(
        CsrfCookieMiddleware,
        secret=settings.secret_key,
        secure_cookie=settings.base_url.startswith("https://"),
    )
    application.add_middleware(
        SecurityHeadersMiddleware, hsts=settings.base_url.startswith("https://")
    )

    application.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    application.include_router(board.router)
    application.include_router(certificates.router)
    application.include_router(certificates.api_router)
    application.include_router(settings_page.router)
    application.include_router(audit_page.router)
    application.include_router(api.router)

    @application.exception_handler(AuthError)
    async def auth_error_handler(request: Request, exc: AuthError) -> Response:
        """Explain why the request was not accepted, without leaking tokens."""
        code, message = "unauthenticated", str(exc.detail)
        if _wants_json(request):
            return JSONResponse({"code": code, "message": message}, status_code=exc.status_code)
        return render(
            request,
            "error.html",
            {"title": "Not signed in", "heading": "Not signed in", "message": message},
            status_code=exc.status_code,
        )

    @application.exception_handler(HTTPException)
    async def http_error_handler(request: Request, exc: HTTPException) -> Response:
        """Render a plain-language error page or JSON body."""
        # `detail` is typed as a string but carries a structured dict for the
        # refusals the upload flow needs to act on.
        detail: Any = exc.detail
        code, message = _detail_parts(detail)
        message = redact(message)
        if _wants_json(request):
            body: dict[str, Any] = {"code": code, "message": message}
            if isinstance(detail, dict):
                body = {**detail, "code": code, "message": message}
            return JSONResponse(body, status_code=exc.status_code, headers=exc.headers)
        headings = {
            400: "That file was not accepted",
            403: "You cannot do that",
            404: "Not found",
            409: "That needs confirming",
            429: "Too many attempts",
        }
        return render(
            request,
            "error.html",
            {
                "title": headings.get(exc.status_code, "Something went wrong"),
                "heading": headings.get(exc.status_code, "Something went wrong"),
                "message": message,
                "detail": detail if isinstance(detail, dict) else None,
            },
            status_code=exc.status_code,
            headers=exc.headers,
        )

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> Response:
        """Turn a validation failure into an explanation, never an echo.

        The submitted values are deliberately not included in the response.
        """
        fields = sorted({str(error["loc"][-1]) for error in exc.errors()})
        message = (
            "Some fields were missing or not in the expected form: "
            f"{', '.join(fields)}. Nothing was saved."
        )
        if _wants_json(request):
            return JSONResponse({"code": "invalid_request", "message": message}, status_code=400)
        return render(
            request,
            "error.html",
            {"title": "Check the form", "heading": "Check the form", "message": message},
            status_code=400,
        )

    return application


def build() -> FastAPI:
    """Entry point for ``uvicorn app.main:build --factory``."""
    try:
        return create_app()
    except ConfigError as exc:
        print(f"notafter: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
