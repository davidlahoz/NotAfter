"""The audit trail."""

from __future__ import annotations

from fastapi import APIRouter, Request
from sqlmodel import Session, col, desc, select
from starlette.responses import HTMLResponse

from app.auth import User
from app.models import AuditLog, Certificate
from app.routes.deps import DbSession, Editor
from app.templating import render

router = APIRouter(tags=["audit"])

PAGE_SIZE = 100


def _labels_for(session: Session, entries: list[AuditLog]) -> dict[int, str]:
    """Certificate names for the rows that name one, so ids stay internal."""
    ids = {
        int(entry.target.removeprefix("certificate:"))
        for entry in entries
        if entry.target.startswith("certificate:")
        and entry.target.removeprefix("certificate:").isdigit()
    }
    if not ids:
        return {}
    found = session.exec(select(Certificate).where(col(Certificate.id).in_(ids))).all()
    return {cert.id: cert.label for cert in found if cert.id is not None}


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
    shown = entries[:PAGE_SIZE]
    return render(
        request,
        "audit.html",
        {
            "entries": shown,
            "labels": _labels_for(session, shown),
            "page": page,
            "has_next": has_next,
            "title": "Audit trail",
        },
    )
