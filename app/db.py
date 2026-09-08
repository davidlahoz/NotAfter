"""Database engine and session handling (SQLite in WAL mode)."""

from __future__ import annotations

from collections.abc import Generator, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, create_engine, select

from app.config import Settings, get_settings
from app.models import AppSettings

_engine: Engine | None = None


def _configure_sqlite(dbapi_connection: Any, _record: Any) -> None:
    """Enable WAL and sane durability settings on every connection."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def build_engine(settings: Settings | None = None) -> Engine:
    """Create the SQLAlchemy engine, making the database directory if needed."""
    settings = settings or get_settings()
    url = settings.database_url
    if url.startswith("sqlite:///") and ":memory:" not in url:
        path = Path(url.removeprefix("sqlite:///"))
        path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        url,
        echo=False,
        connect_args={"check_same_thread": False} if url.startswith("sqlite") else {},
    )
    if url.startswith("sqlite"):
        event.listen(engine, "connect", _configure_sqlite)
    return engine


def get_engine() -> Engine:
    """Return the process-wide engine, creating it on first use."""
    global _engine
    if _engine is None:
        _engine = build_engine()
    return _engine


def set_engine(engine: Engine | None) -> None:
    """Replace the process-wide engine (used by the test suite)."""
    global _engine
    _engine = engine


def create_all(engine: Engine | None = None) -> None:
    """Create any missing tables and seed the settings row."""
    engine = engine or get_engine()
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        if session.exec(select(AppSettings)).first() is None:
            session.add(AppSettings(id=1))
            session.commit()


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a session."""
    with Session(get_engine()) as session:
        yield session


@contextmanager
def session_scope() -> Iterator[Session]:
    """Session for use outside a request (the scheduler, the CLI)."""
    with Session(get_engine()) as session:
        yield session


def load_app_settings(session: Session) -> AppSettings:
    """Return the settings row, creating it if this is a fresh database."""
    settings = session.get(AppSettings, 1)
    if settings is None:
        settings = AppSettings(id=1)
        session.add(settings)
        session.commit()
        session.refresh(settings)
    return settings
