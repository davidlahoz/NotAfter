"""Shared route dependencies and small helpers."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request, UploadFile, status
from sqlmodel import Session

from app.auth import User, current_user, require_editor
from app.config import Settings, get_settings
from app.db import get_session
from app.models import Certificate
from app.notifier import Notifier
from app.parsing import UploadTooLarge

Viewer = Depends(current_user)
Editor = Depends(require_editor)
DbSession = Depends(get_session)


def get_notifier(request: Request) -> Notifier:
    """The notifier held on the application state."""
    notifier: Notifier = request.app.state.notifier
    return notifier


def get_config() -> Settings:
    """Environment settings, as a dependency for easy overriding in tests."""
    return get_settings()


def load_certificate(cert_id: int, session: Session = DbSession) -> Certificate:
    """Fetch a certificate or raise a 404 with a helpful message.

    Raises:
        HTTPException: 404 when there is no such record.
    """
    cert = session.get(Certificate, cert_id)
    if cert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"There is no certificate with the number {cert_id}. It may "
                "have been removed. Go back to the board to see what is there."
            ),
        )
    return cert


async def read_upload(file: UploadFile, settings: Settings) -> bytes:
    """Read an uploaded file into memory, refusing anything oversized.

    The bytes never reach the filesystem: the limit is well below Starlette's
    spool threshold, so the upload stays in memory and is discarded when this
    function's caller returns.

    Raises:
        UploadTooLarge: if the upload exceeds ``MAX_UPLOAD_BYTES``.
    """
    limit = settings.max_upload_bytes
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise UploadTooLarge(
            f"That file is larger than the {limit // 1024} KB limit. A single "
            "certificate is only a few kilobytes; you may have picked a "
            "keystore or an archive by mistake."
        )
    return data


__all__ = [
    "DbSession",
    "Editor",
    "User",
    "Viewer",
    "get_config",
    "get_notifier",
    "load_certificate",
    "read_upload",
]
