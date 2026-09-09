"""The board: everything anyone who passes Access can see."""

from __future__ import annotations

from fastapi import APIRouter, Request
from sqlmodel import Session
from starlette.responses import HTMLResponse

from app.auth import User
from app.db import load_app_settings
from app.formatting import StatusLevel, today
from app.models import CertStatus
from app.routes.deps import DbSession, Viewer
from app.services import group_by_status, list_certificates
from app.templating import render

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def board(
    request: Request,
    session: Session = DbSession,
    user: User = Viewer,
) -> HTMLResponse:
    """Every active certificate, soonest expiry first."""
    app_settings = load_app_settings(session)
    certificates = list_certificates(session)
    archived_count = len(list_certificates(session, status=CertStatus.ARCHIVED))
    groups = group_by_status(
        certificates,
        warn_days=app_settings.warn_days,
        critical_days=app_settings.critical_days,
    )
    # Expired and "renew now" are the two that need somebody today. The tab
    # title carries the number too, so a pinned tab is worth glancing at.
    needing_attention = sum(
        group.count
        for group in groups
        if group.status.level in (StatusLevel.EXPIRED, StatusLevel.CRITICAL)
    )
    return render(
        request,
        "board.html",
        {
            "certificates": certificates,
            "groups": groups,
            "needing_attention": needing_attention,
            "app_settings": app_settings,
            "archived_count": archived_count,
            "today": today(),
            "title": (
                f"{needing_attention} need attention"
                if needing_attention
                else "Certificate expiry board"
            ),
        },
    )


@router.get("/archive", response_class=HTMLResponse)
def archive_list(
    request: Request,
    session: Session = DbSession,
    user: User = Viewer,
) -> HTMLResponse:
    """Certificates that have been replaced or retired."""
    app_settings = load_app_settings(session)
    return render(
        request,
        "archive.html",
        {
            "certificates": list_certificates(session, status=CertStatus.ARCHIVED),
            "app_settings": app_settings,
            "today": today(),
            "title": "Archive",
        },
    )
