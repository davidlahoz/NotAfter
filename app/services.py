"""Certificate lifecycle operations and the audit trail.

Routes stay thin: everything that changes data goes through a function here,
so that every change is audited in the same way.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

from sqlmodel import Session, col, select

from app.auth import User
from app.formatting import (
    Status,
    StatusLevel,
    clean_text,
    status_for,
    threshold_phrase,
    today,
)
from app.models import (
    AuditLog,
    Certificate,
    CertSource,
    CertStatus,
    utcnow,
)
from app.parsing import CertificateFacts


class ServiceError(Exception):
    """An operation was refused. ``message`` is safe to show to the user."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ExpiryMismatch(ServiceError):
    """An attached certificate does not expire when the record says it does."""

    def __init__(self, message: str, expected: date, found: date) -> None:
        super().__init__(message)
        self.expected = expected
        self.found = found


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------


def record_audit(
    session: Session,
    actor: User | str,
    action: str,
    target: str,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Append one line to the audit trail.

    ``details`` must never contain file contents, passwords or webhook URLs;
    callers pass field names and short values only.
    """
    entry = AuditLog(
        actor_email=actor.email if isinstance(actor, User) else actor,
        action=action,
        target=target,
        details_json=details or {},
    )
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return entry


# --------------------------------------------------------------------------
# Queries
# --------------------------------------------------------------------------


def sample_certificate(session: Session) -> Certificate:
    """A certificate to demonstrate a notification with.

    A real one if there is one, so the test shows real wording; otherwise an
    unsaved stand-in with fictional details.
    """
    existing = session.exec(
        select(Certificate).where(Certificate.status == CertStatus.ACTIVE)
    ).first()
    if existing is not None:
        return existing
    return Certificate(
        id=0,
        label="Integration PROD",
        environment="PROD",
        owner_email="owner@example.org",
        subject_cn="edi.example.org",
        verified=True,
        not_after=utcnow() + timedelta(days=30),
    )


@dataclass(frozen=True, slots=True)
class StatusGroup:
    """Certificates that share a status, and what that status means."""

    status: Status
    certificates: list[Certificate]
    threshold: str

    @property
    def count(self) -> int:
        """How many certificates are in this state."""
        return len(self.certificates)


def group_by_status(
    certificates: list[Certificate],
    *,
    warn_days: int,
    critical_days: int,
    on_date: date | None = None,
) -> list[StatusGroup]:
    """Group the board by urgency, most urgent first.

    Written for a board with fifty rows rather than five. Ungrouped, the
    explanatory sentence repeats on every row until it stops being read, and
    nothing answers "is anything on fire" without counting.
    """
    reference = on_date or today()
    grouped: dict[StatusLevel, list[Certificate]] = {}
    meanings: dict[StatusLevel, Status] = {}
    for cert in certificates:
        state = status_for(
            cert.days_left(reference), warn_days=warn_days, critical_days=critical_days
        )
        grouped.setdefault(state.level, []).append(cert)
        meanings.setdefault(state.level, state)

    order = (
        StatusLevel.EXPIRED,
        StatusLevel.CRITICAL,
        StatusLevel.WARNING,
        StatusLevel.OK,
    )
    return [
        StatusGroup(
            status=meanings[level],
            certificates=grouped[level],
            threshold=threshold_phrase(level, warn_days=warn_days, critical_days=critical_days),
        )
        for level in order
        if level in grouped
    ]


def find_by_fingerprint(session: Session, fingerprint: str) -> Certificate | None:
    """Look a certificate up by its SHA-256 fingerprint."""
    return session.exec(
        select(Certificate).where(Certificate.fingerprint_sha256 == fingerprint)
    ).first()


def list_certificates(
    session: Session, *, status: CertStatus = CertStatus.ACTIVE
) -> list[Certificate]:
    """All certificates in a status, soonest expiry first."""
    return list(
        session.exec(
            select(Certificate)
            .where(Certificate.status == status)
            .order_by(col(Certificate.not_after).asc())
        ).all()
    )


def active_for_notifications(session: Session) -> list[Certificate]:
    """Active, unmuted certificates the daily job should consider."""
    return [cert for cert in list_certificates(session) if not cert.muted]


# --------------------------------------------------------------------------
# Creation
# --------------------------------------------------------------------------


def create_from_facts(
    session: Session,
    actor: User,
    facts: CertificateFacts,
    *,
    label: str,
    environment: str = "",
    owner_email: str = "",
    notes: str = "",
) -> tuple[Certificate, bool]:
    """Register an uploaded certificate.

    Returns ``(certificate, created)``. A certificate whose fingerprint is
    already registered links to the existing record instead of creating a
    second one.
    """
    existing = find_by_fingerprint(session, facts.fingerprint_sha256)
    if existing is not None:
        return existing, False

    cert = Certificate(
        label=clean_text(label),
        environment=clean_text(environment, limit=60),
        owner_email=clean_text(owner_email),
        notes=clean_text(notes, limit=2000),
        source=CertSource.UPLOAD,
        verified=True,
        subject_cn=facts.subject_cn,
        subject_rfc4514=facts.subject_rfc4514,
        issuer_rfc4514=facts.issuer_rfc4514,
        serial_decimal=facts.serial_decimal,
        not_before=facts.not_before,
        not_after=facts.not_after,
        fingerprint_sha256=facts.fingerprint_sha256,
        sans=list(facts.sans),
        key_algorithm=facts.key_algorithm,
        key_size=facts.key_size,
        pem=facts.pem,
        created_by=actor.email,
    )
    session.add(cert)
    session.commit()
    session.refresh(cert)
    record_audit(
        session,
        actor,
        "certificate.create",
        f"certificate:{cert.id}",
        {
            "label": cert.label,
            "source": cert.source.value,
            "not_after": cert.not_after.date().isoformat(),
            "fingerprint_sha256": cert.fingerprint_sha256,
        },
    )
    return cert, True


def create_manual(
    session: Session,
    actor: User,
    *,
    label: str,
    not_after: datetime,
    environment: str = "",
    owner_email: str = "",
    notes: str = "",
    subject_cn: str = "",
    issuer: str = "",
) -> Certificate:
    """Register an expiry date typed in by hand, marked unverified."""
    cert = Certificate(
        label=clean_text(label),
        environment=clean_text(environment, limit=60),
        owner_email=clean_text(owner_email),
        notes=clean_text(notes, limit=2000),
        source=CertSource.MANUAL,
        verified=False,
        subject_cn=clean_text(subject_cn),
        issuer_rfc4514=clean_text(issuer),
        not_after=not_after,
        created_by=actor.email,
    )
    session.add(cert)
    session.commit()
    session.refresh(cert)
    record_audit(
        session,
        actor,
        "certificate.create",
        f"certificate:{cert.id}",
        {
            "label": cert.label,
            "source": cert.source.value,
            "not_after": cert.not_after.date().isoformat(),
        },
    )
    return cert


def attach_facts(
    session: Session,
    actor: User,
    cert: Certificate,
    facts: CertificateFacts,
    *,
    confirm_replacement: bool = False,
) -> Certificate:
    """Upgrade a manual record to verified by attaching the real certificate.

    Raises:
        ExpiryMismatch: when the certificate expires on a different day than
            the record says and ``confirm_replacement`` is not set.
        ServiceError: when that certificate is already registered elsewhere.
    """
    duplicate = find_by_fingerprint(session, facts.fingerprint_sha256)
    if duplicate is not None and duplicate.id != cert.id:
        raise ServiceError(
            f'That certificate is already registered as "{duplicate.label}" '
            f"(record {duplicate.id}). Nothing was changed."
        )

    expected = cert.not_after.date()
    found = facts.not_after.date()
    if expected != found and not confirm_replacement:
        raise ExpiryMismatch(
            "The certificate you attached expires on a different day than the "
            "date recorded by hand. Check that it is the right file, then "
            "confirm to replace the recorded date.",
            expected,
            found,
        )

    cert.source = CertSource.UPLOAD
    cert.verified = True
    cert.subject_cn = facts.subject_cn
    cert.subject_rfc4514 = facts.subject_rfc4514
    cert.issuer_rfc4514 = facts.issuer_rfc4514
    cert.serial_decimal = facts.serial_decimal
    cert.not_before = facts.not_before
    cert.not_after = facts.not_after
    cert.fingerprint_sha256 = facts.fingerprint_sha256
    cert.sans = list(facts.sans)
    cert.key_algorithm = facts.key_algorithm
    cert.key_size = facts.key_size
    cert.pem = facts.pem
    cert.updated_at = utcnow()
    session.add(cert)
    session.commit()
    session.refresh(cert)
    record_audit(
        session,
        actor,
        "certificate.attach",
        f"certificate:{cert.id}",
        {
            "recorded_expiry": expected.isoformat(),
            "certificate_expiry": found.isoformat(),
            "confirmed_replacement": confirm_replacement,
            "fingerprint_sha256": cert.fingerprint_sha256,
        },
    )
    return cert


def renew(
    session: Session,
    actor: User,
    old: Certificate,
    facts: CertificateFacts,
    *,
    label: str | None = None,
    environment: str | None = None,
    owner_email: str | None = None,
    notes: str = "",
) -> tuple[Certificate, bool]:
    """Register a successor and archive the certificate it replaces.

    Returns ``(successor, created)``.

    Raises:
        ServiceError: when the successor is the same certificate as the one it
            would replace.
    """
    if facts.fingerprint_sha256 and facts.fingerprint_sha256 == old.fingerprint_sha256:
        raise ServiceError(
            "That is the same certificate that is already registered here, so "
            "there is nothing to renew. Upload the new file instead."
        )

    successor, created = create_from_facts(
        session,
        actor,
        facts,
        label=label if label is not None else old.label,
        environment=environment if environment is not None else old.environment,
        owner_email=owner_email if owner_email is not None else old.owner_email,
        notes=notes,
    )
    successor.extra_recipients = list(old.extra_recipients)
    old.superseded_by_id = successor.id
    old.status = CertStatus.ARCHIVED
    old.archived_at = utcnow()
    old.archive_reason = f"Replaced by record {successor.id}"
    old.updated_at = utcnow()
    session.add(old)
    session.add(successor)
    session.commit()
    session.refresh(old)
    session.refresh(successor)
    record_audit(
        session,
        actor,
        "certificate.renew",
        f"certificate:{old.id}",
        {"superseded_by": successor.id, "new_expiry": successor.not_after.date().isoformat()},
    )
    return successor, created


def update_details(
    session: Session,
    actor: User,
    cert: Certificate,
    *,
    label: str,
    environment: str,
    owner_email: str,
    notes: str,
    extra_recipients: list[str],
    muted: bool,
    recipients_replace_defaults: bool = False,
    reminder_days: list[int] | None = None,
    calendar_renew_lead_days: int | None = None,
    calendar_alarm_days: list[int] | None = None,
) -> Certificate:
    """Edit the human-entered fields and the per-certificate schedule."""
    changed = {
        name: value
        for name, value in (
            ("label", clean_text(label)),
            ("environment", clean_text(environment, limit=60)),
            ("owner_email", clean_text(owner_email)),
            ("muted", muted),
            ("recipients_replace_defaults", recipients_replace_defaults),
            ("reminder_days", reminder_days),
            ("calendar_renew_lead_days", calendar_renew_lead_days),
            ("calendar_alarm_days", calendar_alarm_days),
        )
        if getattr(cert, name) != value
    }
    cert.label = clean_text(label)
    cert.environment = clean_text(environment, limit=60)
    cert.owner_email = clean_text(owner_email)
    cert.notes = clean_text(notes, limit=2000)
    cert.extra_recipients = [
        cleaned for address in extra_recipients if (cleaned := clean_text(address))
    ]
    cert.recipients_replace_defaults = recipients_replace_defaults
    cert.muted = muted
    cert.reminder_days = reminder_days
    cert.calendar_renew_lead_days = calendar_renew_lead_days
    cert.calendar_alarm_days = calendar_alarm_days
    cert.updated_at = utcnow()
    session.add(cert)
    session.commit()
    session.refresh(cert)
    record_audit(session, actor, "certificate.update", f"certificate:{cert.id}", changed)
    return cert


def archive(session: Session, actor: User, cert: Certificate, reason: str) -> Certificate:
    """Soft-delete a record, keeping it for history.

    Raises:
        ServiceError: if the record is already archived.
    """
    if cert.status is CertStatus.ARCHIVED:
        raise ServiceError("That certificate is already archived.")
    cert.status = CertStatus.ARCHIVED
    cert.archived_at = utcnow()
    cert.archive_reason = clean_text(reason)
    cert.updated_at = utcnow()
    session.add(cert)
    session.commit()
    session.refresh(cert)
    record_audit(
        session,
        actor,
        "certificate.archive",
        f"certificate:{cert.id}",
        {"reason": cert.archive_reason},
    )
    return cert


def restore(session: Session, actor: User, cert: Certificate) -> Certificate:
    """Return an archived record to the board."""
    cert.status = CertStatus.ACTIVE
    cert.archived_at = None
    cert.archive_reason = ""
    cert.updated_at = utcnow()
    session.add(cert)
    session.commit()
    session.refresh(cert)
    record_audit(session, actor, "certificate.restore", f"certificate:{cert.id}", {})
    return cert


def renewal_chain(
    session: Session, cert: Certificate
) -> tuple[Certificate | None, Certificate | None]:
    """Return ``(previous, next)`` in the renewal chain."""
    previous = session.exec(
        select(Certificate).where(Certificate.superseded_by_id == cert.id)
    ).first()
    successor = session.get(Certificate, cert.superseded_by_id) if cert.superseded_by_id else None
    return previous, successor
