from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.database.database import get_db
from app.hygiene import analyze_account_hygiene, analyze_user_hygiene
from app.models.models import Account, User
from app.schemas.hygiene import AccountHygieneResponse, UserHygieneResponse
from app.utils.responses import api_error, api_success


router = APIRouter(prefix="/api", tags=["Privacy Hygiene"])


def _account_options():
    return (
        selectinload(Account.service),
        selectinload(Account.permissions),
        selectinload(Account.breach_events),
    )


@router.get(
    "/users/{user_id}/hygiene",
    summary="Analyze user account hygiene",
    description=(
        "Return deterministic account-age, activity, permission-review, and breach-correlation findings. "
        "The optional as_of date uses UTC calendar days and makes time-based results reproducible."
    ),
    response_model=UserHygieneResponse,
)
async def get_user_hygiene_endpoint(
    user_id: str,
    as_of: date | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if db.get(User, user_id) is None:
        api_error("USER_NOT_FOUND", "User not found.", status.HTTP_404_NOT_FOUND)

    accounts = db.scalars(
        select(Account)
        .where(Account.user_id == user_id)
        .options(*_account_options())
        .order_by(Account.created_at.asc(), Account.id.asc())
    ).all()
    response = analyze_user_hygiene(user_id, list(accounts), as_of)
    return api_success(response.model_dump())


@router.get(
    "/accounts/{account_id}/hygiene",
    summary="Analyze account hygiene",
    description=(
        "Return deterministic account-age, activity, permission-review, and breach-correlation findings. "
        "Sensitive account identifiers and recovery values are not returned."
    ),
    response_model=AccountHygieneResponse,
)
async def get_account_hygiene_endpoint(
    account_id: str,
    as_of: date | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    account = db.scalar(
        select(Account).where(Account.id == account_id).options(*_account_options())
    )
    if account is None:
        api_error("ACCOUNT_NOT_FOUND", "Account not found.", status.HTTP_404_NOT_FOUND)

    response = analyze_account_hygiene(account, as_of)
    return api_success(response.model_dump())