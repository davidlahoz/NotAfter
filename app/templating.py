"""Jinja2 environment and the helpers every template may use."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates
from starlette.responses import HTMLResponse

from app import __version__
from app.formatting import (
    countdown_phrase,
    days_left,
    format_date,
    format_datetime,
    humanise_list,
    status_for,
)
from app.messages import lookup, lookup_error
from app.parsing import format_fingerprint
from app.security import CSRF_FORM_FIELD

TEMPLATES_DIR = Path(__file__).parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals.update(
    app_version=__version__,
    csrf_field=CSRF_FORM_FIELD,
)
templates.env.filters.update(
    date=format_date,
    datetime=format_datetime,
    countdown=countdown_phrase,
    fingerprint=format_fingerprint,
    names=humanise_list,
)


def render(
    request: Request,
    template: str,
    context: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
    headers: Mapping[str, str] | None = None,
) -> HTMLResponse:
    """Render a template with the shared context every page needs."""
    user = getattr(request.state, "user", None)
    base: dict[str, Any] = {
        "request": request,
        "user": user,
        "csrf_token": getattr(request.state, "csrf_token", ""),
        "message": lookup(request.query_params.get("msg")),
        "error_message": lookup_error(request.query_params.get("err")),
        "status_for": status_for,
        "days_left": days_left,
    }
    base.update(context or {})
    return templates.TemplateResponse(
        request, template, base, status_code=status_code, headers=headers
    )
