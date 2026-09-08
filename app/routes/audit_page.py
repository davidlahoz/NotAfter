"""The audit trail."""

from __future__ import annotations

from fastapi import APIRouter, Request
from sqlmodel import Session, col, desc, select
from starlette.responses import HTMLResponse

from app.auth import User
from app.models import AuditLog
from app.routes.deps import DbSession, Editor
from app.templating import render

router = APIRouter(tags=["audit"])

PAGE_SIZE = 100


@router.get("/audit", response_class=HTMLResponse)
def audit_trail(
    request: Request,
    page: int = 1,
    session: Session = DbSession,
    user: User = Editor,
) -> HTMLResponse:
    """Every change, newest first."""
    page = max(page, 1)
    entries = list(
        session.exec(
            select(AuditLog)
            .order_by(desc(col(AuditLog.at)))
            .offset((page - 1) * PAGE_SIZE)
            .limit(PAGE_SIZE + 1)
        ).all()
    )
    has_next = len(entries) > PAGE_SIZE
    return render(
        request,
        "audit.html",
        {
            "entries": entries[:PAGE_SIZE],
            "page": page,
            "has_next": has_next,
            "title": "Audit trail",
        },
    )
