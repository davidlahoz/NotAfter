"""Health check and the manually triggered notification run."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlmodel import Session

from app import __version__
from app.auth import User
from app.config import Settings
from app.jobs import NotificationScheduler, last_job_run, run_daily_job
from app.routes.deps import DbSession, Editor, get_config, get_notifier
from app.security import Rate, limiter
from app.services import record_audit

router = APIRouter(tags=["operations"])


@router.get("/healthz")
def healthz(request: Request, session: Session = DbSession) -> JSONResponse:
    """Liveness and readiness, including the scheduler and last job result.

    Unauthenticated on purpose: the container healthcheck calls it from
    inside the container, and it exposes no certificate data.
    """
    scheduler: NotificationScheduler | None = getattr(request.app.state, "scheduler", None)
    config: Settings = request.app.state.settings
    run = last_job_run(session)
    body: dict[str, Any] = {
        "status": "ok",
        "version": __version__,
        "database": "ok",
        "email": {
            "provider": config.email_provider,
            "configured": config.email_configured,
        },
        "scheduler": {
            "running": bool(scheduler and scheduler.running),
            "next_run": scheduler.next_run_time.isoformat()
            if scheduler and scheduler.next_run_time
            else None,
            "next_expiry_escalation": scheduler.next_escalation_time.isoformat()
            if scheduler and scheduler.next_escalation_time
            else None,
        },
        # Counts only. `detail` names certificates and quotes provider
        # errors, and this endpoint is deliberately unauthenticated so the
        # container can call it; the settings page shows the detail to people
        # who have signed in.
        "last_job": None
        if run is None
        else {
            "started_at": run.started_at.isoformat(),
            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
            "certificates_checked": run.certificates_checked,
            "notifications_sent": run.notifications_sent,
            "failures": run.failures,
            "ok": run.ok,
        },
    }
    if (run is not None and not run.ok) or not config.email_configured:
        body["status"] = "degraded"
    return JSONResponse(body)


@router.post("/api/jobs/run", response_model=None)
async def run_job_now(
    request: Request,
    session: Session = DbSession,
    user: User = Editor,
) -> JSONResponse | RedirectResponse:
    """Run the daily notification job immediately.

    Idempotent: anything already sent stays sent, and nothing is sent twice.
    """
    # A run reaches every provider this app talks to, so it is throttled like
    # any other action that sends something.
    limiter.check("settings", user.email, Rate.parse(get_config(request).settings_rate_limit))
    run = await run_daily_job(session, get_notifier(request), trigger=f"manual:{user.email}")
    record_audit(
        session,
        user,
        "job.run",
        "notifications",
        {
            "certificates_checked": run.certificates_checked,
            "notifications_sent": run.notifications_sent,
            "failures": run.failures,
        },
    )
    if "text/html" in request.headers.get("accept", ""):
        return RedirectResponse("/settings?msg=job-run", status_code=303)
    return JSONResponse(
        {
            "certificates_checked": run.certificates_checked,
            "notifications_sent": run.notifications_sent,
            "failures": run.failures,
            "ok": run.ok,
            "detail": run.detail,
        }
    )
