"""Global settings, test messages and the notification problem list."""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from sqlmodel import Session, col, desc, select
from starlette.responses import HTMLResponse

from app.auth import User
from app.config import Settings
from app.db import load_app_settings
from app.jobs import last_job_run
from app.models import (
    DEFAULT_THRESHOLDS,
    AuditLog,
    Certificate,
    DeliveryStatus,
    NotificationLog,
    utcnow,
)
from app.notify import DeliveryError
from app.routes.deps import DbSession, Editor, get_config, get_notifier
from app.security import Rate, limiter
from app.services import record_audit, sample_certificate
from app.templating import render

router = APIRouter(prefix="/settings", tags=["settings"])

WEBHOOK_UNCHANGED = "keep"


def _split(value: str) -> list[str]:
    """Split a textarea or comma-separated field into addresses."""
    parts = value.replace("\n", ",").replace(";", ",").split(",")
    return [part.strip() for part in parts if part.strip()]


def _parse_thresholds(value: str) -> list[int]:
    """Read the threshold list, ignoring anything that is not a number."""
    numbers = sorted(
        {int(part) for part in _split(value) if part.lstrip("-").isdigit() and int(part) >= 0},
        reverse=True,
    )
    return numbers or list(DEFAULT_THRESHOLDS)


def _rate_limit(user: User, settings: Settings) -> None:
    limiter.check("settings", user.email, Rate.parse(settings.settings_rate_limit))


@router.get("", response_class=HTMLResponse)
def settings_page(
    request: Request,
    session: Session = DbSession,
    user: User = Editor,
) -> HTMLResponse:
    """Show the editable settings and anything that recently failed."""
    problems = list(
        session.exec(
            select(NotificationLog)
            .where(NotificationLog.status == DeliveryStatus.ERROR)
            .order_by(desc(col(NotificationLog.sent_at)))
            .limit(20)
        ).all()
    )
    labels = {
        cert.id: cert.label
        for cert in session.exec(select(Certificate)).all()
        if cert.id is not None
    }
    app_settings = load_app_settings(session)
    notifier = get_notifier(request)
    sample = sample_certificate(session)
    return render(
        request,
        "settings.html",
        {
            "app_settings": app_settings,
            "teams_payload": json.dumps(
                notifier.build_test_payload(sample, app_settings),
                indent=2,
                ensure_ascii=False,
            ),
            "teams_sample_label": sample.label,
            "last_teams_test": _last_teams_test(session),
            "env": get_config(),
            "problems": problems,
            "cert_labels": labels,
            "last_run": last_job_run(session),
            "title": "Settings",
        },
    )


@router.post("")
async def save_settings(
    request: Request,
    recipient_emails: Annotated[str, Form()] = "",
    calendar_recipient_emails: Annotated[str, Form()] = "",
    teams_webhook_url: Annotated[str, Form()] = "",
    remove_webhook: Annotated[str, Form()] = "",
    thresholds: Annotated[str, Form()] = "",
    notify_daily_when_expired: Annotated[str, Form()] = "",
    expired_teams_every_hours: Annotated[int, Form()] = 1,
    warn_days: Annotated[int, Form()] = 60,
    critical_days: Annotated[int, Form()] = 30,
    contact_line: Annotated[str, Form()] = "",
    session: Session = DbSession,
    user: User = Editor,
) -> RedirectResponse:
    """Save the settings.

    The webhook URL is only replaced when a new one is typed, so that the
    stored secret is never echoed back into the page.
    """
    _rate_limit(user, get_config())
    app_settings = load_app_settings(session)

    app_settings.recipient_emails = _split(recipient_emails)
    app_settings.calendar_recipient_emails = _split(calendar_recipient_emails)
    if remove_webhook:
        app_settings.teams_webhook_url = ""
    elif teams_webhook_url.strip():
        app_settings.teams_webhook_url = teams_webhook_url.strip()
    app_settings.thresholds = _parse_thresholds(thresholds)
    app_settings.notify_daily_when_expired = bool(notify_daily_when_expired)
    app_settings.expired_teams_every_hours = min(max(expired_teams_every_hours, 0), 24)
    app_settings.warn_days = max(warn_days, critical_days)
    app_settings.critical_days = min(warn_days, critical_days)
    app_settings.contact_line = contact_line.strip() or app_settings.contact_line
    app_settings.updated_at = utcnow()
    session.add(app_settings)
    session.commit()

    record_audit(
        session,
        user,
        "settings.update",
        "settings",
        {
            "recipients": len(app_settings.recipient_emails),
            "calendar_recipients": len(app_settings.calendar_recipient_emails),
            "thresholds": app_settings.thresholds,
            "teams_webhook_set": bool(app_settings.teams_webhook_url),
            "notify_daily_when_expired": app_settings.notify_daily_when_expired,
            "expired_teams_every_hours": app_settings.expired_teams_every_hours,
            "warn_days": app_settings.warn_days,
            "critical_days": app_settings.critical_days,
        },
    )
    return RedirectResponse("/settings?msg=settings-saved", status_code=303)


@router.post("/test-email")
async def test_email(
    request: Request,
    session: Session = DbSession,
    user: User = Editor,
) -> RedirectResponse:
    """Send a test email to the signed-in user."""
    _rate_limit(user, get_config())
    app_settings = load_app_settings(session)
    if not get_config().email_configured:
        return RedirectResponse("/settings?err=smtp-unconfigured", status_code=303)
    try:
        await get_notifier(request).send_test_email(user.email, app_settings)
    except DeliveryError as exc:
        _record_problem(session, user, "email", str(exc))
        return RedirectResponse("/settings?err=send-failed", status_code=303)
    record_audit(session, user, "settings.test", "email", {"to": user.email})
    return RedirectResponse("/settings?msg=test-sent", status_code=303)


@router.post("/test-teams")
async def test_teams(
    request: Request,
    session: Session = DbSession,
    user: User = Editor,
) -> RedirectResponse:
    """Post a test card to the configured Teams webhook."""
    _rate_limit(user, get_config())
    app_settings = load_app_settings(session)
    if not app_settings.teams_webhook_url:
        return RedirectResponse("/settings?err=no-teams", status_code=303)
    sample = sample_certificate(session)
    try:
        status_code = await get_notifier(request).send_test_card(sample, app_settings)
    except DeliveryError as exc:
        _record_problem(session, user, "teams", str(exc))
        return RedirectResponse("/settings?err=send-failed", status_code=303)
    record_audit(session, user, "settings.test", "teams", {"http_status": status_code})
    return RedirectResponse(f"/settings?msg=teams-accepted&http={status_code}", status_code=303)


@router.post("/test-invite")
async def test_invite(
    request: Request,
    session: Session = DbSession,
    user: User = Editor,
) -> RedirectResponse:
    """Send the signed-in user a sample calendar invite."""
    _rate_limit(user, get_config())
    app_settings = load_app_settings(session)
    if not get_config().email_configured:
        return RedirectResponse("/settings?err=smtp-unconfigured", status_code=303)

    sample = session.exec(select(Certificate).limit(1)).first()
    if sample is None:
        sample = Certificate(
            id=0,
            label="Example certificate",
            subject_cn="edi.example.org",
            not_after=utcnow().replace(microsecond=0),
        )
    try:
        await get_notifier(request).send_test_invite(user.email, sample, app_settings)
    except DeliveryError as exc:
        _record_problem(session, user, "calendar", str(exc))
        return RedirectResponse("/settings?err=send-failed", status_code=303)
    record_audit(session, user, "settings.test", "calendar", {"to": user.email})
    return RedirectResponse("/settings?msg=test-sent", status_code=303)


def _last_teams_test(session: Session) -> AuditLog | None:
    """The most recent Teams test, so its result stays visible afterwards."""
    return session.exec(
        select(AuditLog)
        .where(AuditLog.action == "settings.test", AuditLog.target == "teams")
        .order_by(desc(col(AuditLog.at)))
        .limit(1)
    ).first()


def _record_problem(session: Session, user: User, channel: str, error: str) -> None:
    """Write a failed test into the audit trail so it is visible later."""
    record_audit(
        session,
        user,
        "settings.test_failed",
        channel,
        {"error": error[:500]},
    )


__all__ = ["router"]
