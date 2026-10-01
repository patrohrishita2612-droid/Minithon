from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[3]
BACKEND_DIR = Path(__file__).resolve().parents[2]
ENV_PATH = PROJECT_ROOT / ".env"

if ENV_PATH.exists():
    load_dotenv(ENV_PATH)


def _default_database_url() -> str:
    db_path = (BACKEND_DIR / "privacy_auditor.db").resolve()
    return f"sqlite:///{db_path.as_posix()}"


def _resolve_database_url(value: str | None) -> str:
    if not value:
        return _default_database_url()
    if value.startswith("sqlite:///:memory:"):
        return value
    if value.startswith("sqlite:///./"):
        relative_target = value.removeprefix("sqlite:///./")
        db_path = (BACKEND_DIR / relative_target).resolve()
        return f"sqlite:///{db_path.as_posix()}"
    if value.startswith("sqlite:///"):
        candidate = value.removeprefix("sqlite:///")
        if candidate and not candidate.startswith("/") and not candidate.startswith("C:/") and not candidate.startswith("C:\\"):
            db_path = (BACKEND_DIR / candidate).resolve()
            return f"sqlite:///{db_path.as_posix()}"
    return value


class Settings:
    DATABASE_URL: str = _resolve_database_url(os.getenv("DATABASE_URL"))
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    CORS_ORIGINS: list[str] = [
        origin.strip()
        for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
        if origin.strip()
    ]


settings = Settings()
