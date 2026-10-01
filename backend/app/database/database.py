from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.database.base import Base
from app.models import (  # noqa: F401
    Account,
    AccountConnection,
    AccountPhoneNumber,
    AccountRecoveryEmail,
    AppPermission,
    BreachEvent,
    FixItem,
    Notification,
    PhoneNumber,
    RecoveryEmail,
    Reminder,
    RiskFactor,
    RiskSnapshot,
    Service,
    User,
)

DATABASE_URL = settings.DATABASE_URL
CONNECT_ARGS = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=CONNECT_ARGS, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    database_session = SessionLocal()
    try:
        yield database_session
    finally:
        database_session.close()


def check_database_connection() -> bool:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
