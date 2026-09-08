"""Global settings, test messages and the notification problem list."""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlmodel import Session, col, desc, select
from starlette.responses import HTMLResponse

from app.auth import User
from app.config import Settings
from app.db import load_app_settings
from app.formatting import clean_text
from app.jobs import last_job_run
from app.models import (
    DEFAULT_THRESHOLDS,
    AppSettings,
    AuditLog,
    Certificate,
    DeliveryStatus,
    NotificationLog,
    utcnow,
)
from app.notify import DeliveryError
from app.notify.teams import WebhookNotAllowed, validate_webhook_url
from app.routes.deps import DbSession, Editor, get_config, get_notifier
from app.security import Rate, limiter
from app.services import list_certificates, record_audit, sample_certificate
from app.templating import render

router = APIRouter(prefix="/settings", tags=["settings"])

WEBHOOK_UNCHANGED = "keep"


def _split(value: str) -> list[str]:
    """Split a textarea or comma-separated field into addresses."""
    parts = value.replace("\n", ",").replace(";", ",").split(",")
    return [cleaned for part in parts if (cleaned := clean_text(part))]


def _parse_days(value: str, *, default: list[int]) -> list[int]:
    """Read a list of day counts, largest first, ignoring anything else."""
    numbers = sorted(
        {int(part) for part in _split(value) if part.isdigit() and int(part) > 0},
        reverse=True,
    )
    return numbers or default


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
            "env": get_config(request),
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
    calendar_renew_lead_days: Annotated[int, Form()] = 30,
    calendar_alarm_days: Annotated[str, Form()] = "",
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
    _rate_limit(user, get_config(request))
    app_settings = load_app_settings(session)

    app_settings.recipient_emails = _split(recipient_emails)
    app_settings.calendar_recipient_emails = _split(calendar_recipient_emails)
    if remove_webhook:
        app_settings.teams_webhook_url = ""
    elif teams_webhook_url.strip():
        candidate = teams_webhook_url.strip()
        # Refused here as well as at send time, so the person who typed it
        # finds out now rather than when a notification silently fails.
        try:
            validate_webhook_url(candidate, get_config(request).teams_host_suffixes)
        except WebhookNotAllowed as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "webhook_not_allowed", "message": exc.message},
            ) from exc
        app_settings.teams_webhook_url = candidate
    app_settings.thresholds = _parse_thresholds(thresholds)
    app_settings.notify_daily_when_expired = bool(notify_daily_when_expired)
    app_settings.expired_teams_every_hours = min(max(expired_teams_every_hours, 0), 24)

    # Calendar timings. Remember the old ones: changing them has no effect on
    # invites people already hold unless those invites are re-issued.
    previous_timings = (
        app_settings.calendar_renew_lead_days,
        list(app_settings.calendar_alarm_days),
    )
    app_settings.calendar_renew_lead_days = min(max(calendar_renew_lead_days, 0), 3650)
    app_settings.calendar_alarm_days = _parse_days(calendar_alarm_days, default=[7, 1])
    app_settings.warn_days = max(warn_days, critical_days)
    app_settings.critical_days = min(warn_days, critical_days)
    app_settings.contact_line = clean_text(contact_line, limit=300) or app_settings.contact_line
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
    changed_timings = previous_timings != (
        app_settings.calendar_renew_lead_days,
        list(app_settings.calendar_alarm_days),
    )
    if changed_timings:
        updated = await _reissue_invites(request, session, app_settings)
        record_audit(
            session,
            user,
            "calendar.retimed",
            "settings",
            {
                "renew_lead_days": app_settings.calendar_renew_lead_days,
                "alarm_days": app_settings.calendar_alarm_days,
                "certificates_updated": updated,
            },
        )
        return RedirectResponse("/settings?msg=calendar-retimed", status_code=303)
    return RedirectResponse("/settings?msg=settings-saved", status_code=303)


async def _reissue_invites(request: Request, session: Session, app_settings: AppSettings) -> int:
    """Re-send every active certificate's invites with the new timing.

    A calendar client only moves an event when it receives an update for the
    same UID with a higher SEQUENCE, which is exactly what ``send_invites``
    produces. Without this the new setting would apply to future
    registrations only, and quietly disagree with every invite already out
    there.
    """
    notifier = get_notifier(request)
    updated = 0
    for cert in list_certificates(session):
        outcomes = await notifier.send_invites(session, cert, app_settings)
        if outcomes:
            updated += 1
    return updated


@router.post("/test-email")
async def test_email(
    request: Request,
    session: Session = DbSession,
    user: User = Editor,
) -> RedirectResponse:
    """Send a test email to the signed-in user."""
    _rate_limit(user, get_config(request))
    app_settings = load_app_settings(session)
    if not get_config(request).email_configured:
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
    _rate_limit(user, get_config(request))
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
    _rate_limit(user, get_config(request))
    app_settings = load_app_settings(session)
    if not get_config(request).email_configured:
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
