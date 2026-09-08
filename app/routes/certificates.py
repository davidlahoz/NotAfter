"""Registering, viewing, renewing and archiving certificates."""

from __future__ import annotations

from datetime import date, datetime, time
from typing import Annotated, Any

from fastapi import APIRouter, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlmodel import Session, col, desc, select
from starlette.responses import HTMLResponse

from app.auth import User
from app.config import Settings
from app.db import load_app_settings
from app.formatting import today
from app.logging_setup import logger
from app.models import (
    AuditLog,
    CalendarInvite,
    Certificate,
    CertStatus,
    Channel,
    InviteKind,
    NotificationLog,
)
from app.notifier import Notifier
from app.notify import DeliveryError
from app.notify import email as email_channel
from app.notify.ics import alarms_for
from app.parsing import AmbiguousLeaf, CertificateFacts, UploadRejected, parse_upload
from app.routes.deps import (
    DbSession,
    Editor,
    Viewer,
    get_config,
    get_notifier,
    load_certificate,
    read_upload,
)
from app.security import Rate, limiter
from app.services import (
    ExpiryMismatch,
    ServiceError,
    archive,
    attach_facts,
    create_from_facts,
    create_manual,
    record_audit,
    renew,
    renewal_chain,
    restore,
    update_details,
)
from app.templating import render

router = APIRouter(prefix="/certificates", tags=["certificates"])
api_router = APIRouter(prefix="/api/certificates", tags=["certificates"])


class RegisterPayload(BaseModel):
    """What the in-browser extraction sends after reading a file locally.

    ``pem`` is a public certificate. There is deliberately no field that could
    carry a private key or a PKCS#12 password.
    """

    label: str = Field(min_length=1, max_length=200)
    environment: str = Field(default="", max_length=60)
    owner_email: str = Field(default="", max_length=200)
    notes: str = Field(default="", max_length=2000)
    pem: str = Field(min_length=1, max_length=256 * 1024)
    confirm_replacement: bool = False


def _rate_limit(user: User, settings: Settings) -> None:
    limiter.check("upload", user.email, Rate.parse(settings.upload_rate_limit))


def _reject(exc: UploadRejected) -> HTTPException:
    """Turn a refusal into a 400 whose body explains what to do instead.

    The upload itself is never logged — only its refusal code.
    """
    logger.info("upload refused: %s", exc.code)
    detail: dict[str, Any] = {"code": exc.code, "message": exc.message}
    if isinstance(exc, AmbiguousLeaf):
        detail["choices"] = [
            {
                "subject_cn": choice.subject_cn,
                "not_after": choice.not_after.date().isoformat(),
                "fingerprint_sha256": choice.fingerprint_sha256,
            }
            for choice in exc.choices
        ]
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def _parse_or_400(data: bytes, settings: Settings) -> CertificateFacts:
    """Run the refusal gate and the parser, mapping refusals to 400."""
    try:
        return parse_upload(data, limit=settings.max_upload_bytes)
    except UploadRejected as exc:
        raise _reject(exc) from exc


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


@router.get("/new", response_class=HTMLResponse)
def new_certificate_page(
    request: Request,
    session: Session = DbSession,
    user: User = Editor,
) -> HTMLResponse:
    """The three ways to register a certificate."""
    return render(
        request,
        "new.html",
        {
            "app_settings": load_app_settings(session),
            "title": "Register a certificate",
            "post_url": "/api/certificates",
        },
    )


@api_router.post("", status_code=status.HTTP_201_CREATED)
async def register_certificate(
    request: Request,
    payload: RegisterPayload,
    session: Session = DbSession,
    user: User = Editor,
) -> JSONResponse:
    """Register a certificate extracted in the browser.

    The body carries a PEM certificate only; anything else is refused by the
    same gate that guards the file upload path.
    """
    settings = get_config(request)
    _rate_limit(user, settings)
    facts = _parse_or_400(payload.pem.encode("utf-8"), settings)
    cert, created = create_from_facts(
        session,
        user,
        facts,
        label=payload.label,
        environment=payload.environment,
        owner_email=payload.owner_email,
        notes=payload.notes,
    )
    if created:
        await get_notifier(request).send_invites(session, cert, load_app_settings(session))
    return JSONResponse(
        status_code=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        content={
            "id": cert.id,
            "created": created,
            "url": f"/certificates/{cert.id}?msg={'created' if created else 'linked'}",
        },
    )


@router.post("/new/upload")
async def register_upload(
    request: Request,
    file: UploadFile,
    label: Annotated[str, Form()],
    environment: Annotated[str, Form()] = "",
    owner_email: Annotated[str, Form()] = "",
    notes: Annotated[str, Form()] = "",
    session: Session = DbSession,
    user: User = Editor,
) -> RedirectResponse:
    """Fallback for browsers without JavaScript.

    Accepts PEM, DER and PKCS#7 only. A PKCS#12 file is refused here with
    guidance, because the server never opens one.
    """
    settings = get_config(request)
    _rate_limit(user, settings)
    try:
        data = await read_upload(file, settings)
    except UploadRejected as exc:
        raise _reject(exc) from exc
    facts = _parse_or_400(data, settings)
    del data

    cert, created = create_from_facts(
        session,
        user,
        facts,
        label=label,
        environment=environment,
        owner_email=owner_email,
        notes=notes,
    )
    if created:
        await get_notifier(request).send_invites(session, cert, load_app_settings(session))
    code = "created" if created else "linked"
    return RedirectResponse(f"/certificates/{cert.id}?msg={code}", status_code=303)


@router.post("/new/manual")
async def register_manual(
    request: Request,
    label: Annotated[str, Form()],
    expiry_date: Annotated[str, Form()],
    environment: Annotated[str, Form()] = "",
    owner_email: Annotated[str, Form()] = "",
    subject_cn: Annotated[str, Form()] = "",
    issuer: Annotated[str, Form()] = "",
    notes: Annotated[str, Form()] = "",
    session: Session = DbSession,
    user: User = Editor,
) -> RedirectResponse:
    """Record an expiry date typed in by hand."""
    settings = get_config(request)
    _rate_limit(user, settings)
    try:
        not_after = datetime.combine(date.fromisoformat(expiry_date.strip()), time.min)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "bad_date",
                "message": (
                    "The expiry date must be a real date in the form 2027-04-08. Nothing was saved."
                ),
            },
        ) from exc

    cert = create_manual(
        session,
        user,
        label=label,
        not_after=not_after,
        environment=environment,
        owner_email=owner_email,
        notes=notes,
        subject_cn=subject_cn,
        issuer=issuer,
    )
    await get_notifier(request).send_invites(session, cert, load_app_settings(session))
    return RedirectResponse(f"/certificates/{cert.id}?msg=manual-created", status_code=303)


# --------------------------------------------------------------------------
# Detail
# --------------------------------------------------------------------------


@router.get("/{cert_id}", response_class=HTMLResponse)
def certificate_detail(
    request: Request,
    cert_id: int,
    session: Session = DbSession,
    user: User = Viewer,
) -> HTMLResponse:
    """Everything known about one certificate."""
    cert = load_certificate(cert_id, session)
    previous, successor = renewal_chain(session, cert)
    notifications = list(
        session.exec(
            select(NotificationLog)
            .where(NotificationLog.cert_id == cert.id)
            .order_by(desc(col(NotificationLog.sent_at)))
            .limit(50)
        ).all()
    )
    invites = list(
        session.exec(select(CalendarInvite).where(CalendarInvite.cert_id == cert.id)).all()
    )
    audit = list(
        session.exec(
            select(AuditLog)
            .where(AuditLog.target == f"certificate:{cert.id}")
            .order_by(desc(col(AuditLog.at)))
            .limit(50)
        ).all()
    )
    app_settings = load_app_settings(session)
    return render(
        request,
        "detail.html",
        {
            "cert": cert,
            "notify_recipients": get_notifier(request).recipients_for(cert, app_settings),
            "calendar_alarms": alarms_for(
                cert.renew_lead_days(app_settings), cert.alarm_days(app_settings)
            ),
            "previous": previous,
            "successor": successor,
            "notifications": notifications,
            "invites": invites,
            "audit": audit,
            "app_settings": app_settings,
            "today": today(),
            "title": cert.label,
        },
    )


# --------------------------------------------------------------------------
# Actions
# --------------------------------------------------------------------------


@router.post("/{cert_id}/update")
async def update_certificate(
    request: Request,
    cert_id: int,
    label: Annotated[str, Form()],
    environment: Annotated[str, Form()] = "",
    owner_email: Annotated[str, Form()] = "",
    notes: Annotated[str, Form()] = "",
    extra_recipients: Annotated[str, Form()] = "",
    recipients_replace_defaults: Annotated[str, Form()] = "",
    muted: Annotated[str, Form()] = "",
    reminder_days: Annotated[str, Form()] = "",
    calendar_renew_lead_days: Annotated[str, Form()] = "",
    calendar_alarm_days: Annotated[str, Form()] = "",
    session: Session = DbSession,
    user: User = Editor,
) -> RedirectResponse:
    """Edit this certificate's details and its own notification schedule.

    An empty schedule field means "use the global setting", so a certificate
    only differs where somebody has said it should.
    """
    _rate_limit(user, get_config(request))
    cert = load_certificate(cert_id, session)
    app_settings = load_app_settings(session)
    before = (
        cert.renew_lead_days(app_settings),
        cert.alarm_days(app_settings),
        cert.recipients_replace_defaults,
        list(cert.extra_recipients),
        cert.owner_email,
    )

    update_details(
        session,
        user,
        cert,
        label=label,
        environment=environment,
        owner_email=owner_email,
        notes=notes,
        extra_recipients=[part.strip() for part in extra_recipients.replace("\n", ",").split(",")],
        recipients_replace_defaults=bool(recipients_replace_defaults),
        muted=bool(muted),
        reminder_days=_day_list(reminder_days),
        calendar_renew_lead_days=_optional_int(calendar_renew_lead_days),
        calendar_alarm_days=_day_list(calendar_alarm_days),
    )

    # The calendar only moves an event when it receives an update for the same
    # UID, so a change to this certificate's timing or audience has to go out.
    after = (
        cert.renew_lead_days(app_settings),
        cert.alarm_days(app_settings),
        cert.recipients_replace_defaults,
        list(cert.extra_recipients),
        cert.owner_email,
    )
    if before != after and cert.status is not CertStatus.ARCHIVED:
        await get_notifier(request).send_invites(session, cert, app_settings)
        return RedirectResponse(f"/certificates/{cert_id}?msg=calendar-retimed", status_code=303)
    return RedirectResponse(f"/certificates/{cert_id}?msg=updated", status_code=303)


def _day_list(value: str) -> list[int] | None:
    """Parse a comma-separated day list, or ``None`` to inherit the default."""
    parts = [part.strip() for part in value.replace("\n", ",").split(",")]
    numbers = sorted(
        {int(part) for part in parts if part.isdigit() and int(part) > 0}, reverse=True
    )
    return numbers or None


def _optional_int(value: str) -> int | None:
    """Parse a number, or ``None`` to inherit the default."""
    cleaned = value.strip()
    if not cleaned.isdigit():
        return None
    return min(int(cleaned), 3650)


@router.post("/{cert_id}/archive")
async def archive_certificate(
    request: Request,
    cert_id: int,
    reason: Annotated[str, Form()] = "",
    session: Session = DbSession,
    user: User = Editor,
) -> RedirectResponse:
    """Archive a record and withdraw its calendar events."""
    _rate_limit(user, get_config(request))
    cert = load_certificate(cert_id, session)
    try:
        archive(session, user, cert, reason)
    except ServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "conflict", "message": exc.message},
        ) from exc
    await get_notifier(request).cancel_invites(session, cert, load_app_settings(session))
    return RedirectResponse(f"/certificates/{cert_id}?msg=archived", status_code=303)


@router.post("/{cert_id}/restore")
async def restore_certificate(
    request: Request,
    cert_id: int,
    session: Session = DbSession,
    user: User = Editor,
) -> RedirectResponse:
    """Put an archived record back on the board and re-send its invites."""
    _rate_limit(user, get_config(request))
    cert = load_certificate(cert_id, session)
    restore(session, user, cert)
    await get_notifier(request).send_invites(session, cert, load_app_settings(session))
    return RedirectResponse(f"/certificates/{cert_id}?msg=restored", status_code=303)


async def _apply_attach(
    request: Request,
    session: Session,
    user: User,
    cert: Certificate,
    facts: CertificateFacts,
    confirm: bool,
) -> None:
    """Attach a certificate to a manual record, then refresh its invites."""
    try:
        attach_facts(session, user, cert, facts, confirm_replacement=confirm)
    except ExpiryMismatch as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "expiry_mismatch",
                "message": exc.message,
                "recorded_expiry": exc.expected.isoformat(),
                "certificate_expiry": exc.found.isoformat(),
            },
        ) from exc
    except ServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "conflict", "message": exc.message},
        ) from exc
    await get_notifier(request).send_invites(session, cert, load_app_settings(session))


@router.post("/{cert_id}/attach")
async def attach_upload(
    request: Request,
    cert_id: int,
    file: UploadFile,
    confirm_replacement: Annotated[str, Form()] = "",
    session: Session = DbSession,
    user: User = Editor,
) -> RedirectResponse:
    """Upgrade a manual record by attaching the real certificate."""
    settings = get_config(request)
    _rate_limit(user, settings)
    cert = load_certificate(cert_id, session)
    try:
        data = await read_upload(file, settings)
    except UploadRejected as exc:
        raise _reject(exc) from exc
    facts = _parse_or_400(data, settings)
    del data
    await _apply_attach(request, session, user, cert, facts, bool(confirm_replacement))
    return RedirectResponse(f"/certificates/{cert_id}?msg=attached", status_code=303)


@api_router.post("/{cert_id}/attach")
async def attach_json(
    request: Request,
    cert_id: int,
    payload: RegisterPayload,
    session: Session = DbSession,
    user: User = Editor,
) -> JSONResponse:
    """Attach a browser-extracted certificate to a manual record."""
    settings = get_config(request)
    _rate_limit(user, settings)
    cert = load_certificate(cert_id, session)
    facts = _parse_or_400(payload.pem.encode("utf-8"), settings)
    await _apply_attach(request, session, user, cert, facts, payload.confirm_replacement)
    return JSONResponse(
        {"id": cert.id, "created": False, "url": f"/certificates/{cert.id}?msg=attached"}
    )


async def _apply_renew(
    request: Request,
    session: Session,
    user: User,
    old: Certificate,
    facts: CertificateFacts,
    label: str | None,
    notes: str,
) -> Certificate:
    """Register the successor, cancel the old events, invite for the new."""
    try:
        successor, _created = renew(session, user, old, facts, label=label or None, notes=notes)
    except ServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "conflict", "message": exc.message},
        ) from exc

    app_settings = load_app_settings(session)
    notifier = get_notifier(request)
    await notifier.cancel_invites(session, old, app_settings)
    await notifier.send_invites(session, successor, app_settings)
    return successor


@router.post("/{cert_id}/renew")
async def renew_upload(
    request: Request,
    cert_id: int,
    file: UploadFile,
    label: Annotated[str, Form()] = "",
    notes: Annotated[str, Form()] = "",
    session: Session = DbSession,
    user: User = Editor,
) -> RedirectResponse:
    """Replace a certificate with its successor (file upload path)."""
    settings = get_config(request)
    _rate_limit(user, settings)
    old = load_certificate(cert_id, session)
    try:
        data = await read_upload(file, settings)
    except UploadRejected as exc:
        raise _reject(exc) from exc
    facts = _parse_or_400(data, settings)
    del data
    successor = await _apply_renew(request, session, user, old, facts, label, notes)
    return RedirectResponse(f"/certificates/{successor.id}?msg=renewed", status_code=303)


@api_router.post("/{cert_id}/renew")
async def renew_json(
    request: Request,
    cert_id: int,
    payload: RegisterPayload,
    session: Session = DbSession,
    user: User = Editor,
) -> JSONResponse:
    """Replace a certificate with its successor (browser extraction path)."""
    settings = get_config(request)
    _rate_limit(user, settings)
    old = load_certificate(cert_id, session)
    facts = _parse_or_400(payload.pem.encode("utf-8"), settings)
    successor = await _apply_renew(request, session, user, old, facts, payload.label, payload.notes)
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "id": successor.id,
            "created": True,
            "url": f"/certificates/{successor.id}?msg=renewed",
        },
    )


@router.post("/{cert_id}/test-notification")
async def send_test_notification(
    request: Request,
    cert_id: int,
    session: Session = DbSession,
    user: User = Editor,
) -> RedirectResponse:
    """Send this certificate's notification to the signed-in user, now."""
    _rate_limit(user, get_config(request))
    cert = load_certificate(cert_id, session)
    app_settings = load_app_settings(session)
    notifier: Notifier = get_notifier(request)
    days = cert.days_left()

    subject, text, html_body = email_channel.render_notification(
        cert,
        days,
        detail_url=notifier.detail_url(cert),
        contact_line=app_settings.contact_line,
        warn_days=app_settings.warn_days,
        critical_days=app_settings.critical_days,
    )
    try:
        await email_channel.send_message(
            email_channel.Message(
                to=[user.email], subject=f"[test] {subject}", text=text, html_body=html_body
            ),
            get_config(request),
        )
    except DeliveryError:
        return RedirectResponse(f"/certificates/{cert_id}?err=send-failed", status_code=303)
    record_audit(
        session,
        user,
        "notification.test",
        f"certificate:{cert.id}",
        {"channel": Channel.EMAIL.value, "to": user.email},
    )
    return RedirectResponse(f"/certificates/{cert_id}?msg=test-sent", status_code=303)


@router.post("/{cert_id}/resend-invites")
async def resend_invites(
    request: Request,
    cert_id: int,
    session: Session = DbSession,
    user: User = Editor,
) -> RedirectResponse:
    """Send both calendar events again, with an incremented SEQUENCE."""
    _rate_limit(user, get_config(request))
    cert = load_certificate(cert_id, session)
    await get_notifier(request).send_invites(session, cert, load_app_settings(session))
    record_audit(
        session,
        user,
        "calendar.resend",
        f"certificate:{cert.id}",
        {"kinds": [kind.value for kind in InviteKind]},
    )
    return RedirectResponse(f"/certificates/{cert_id}?msg=invites-sent", status_code=303)


__all__ = ["api_router", "router"]
