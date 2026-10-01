from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.algorithms.risk_engine import (
    calculate_account_risk,
    calculate_and_persist_user_risk,
    calculate_user_risk_summary,
    persist_risk_snapshot,
)
from app.database.database import get_db
from app.models.models import Account, RiskSnapshot, User
from app.risk_explanations import build_account_risk_explanations, build_user_risk_explanations
from app.schemas.risk_explanations import (
    AccountRiskExplanationApiResponse,
    UserRiskExplanationApiResponse,
)
from app.utils.responses import api_error, api_success

router = APIRouter(prefix="/api", tags=["Risk Analysis"])


def _require_user(db: Session, user_id: str) -> User:
    user = db.get(User, user_id)
    if not user:
        api_error("USER_NOT_FOUND", "User not found.", status.HTTP_404_NOT_FOUND)
    return user


@router.post(
    "/users/{user_id}/risk/calculate",
    summary="Calculate user privacy risk",
    description=(
        "Deterministic privacy risk calculation for a given user. "
        "The risk score is an exposure measurement, not a probability of compromise. "
        "The privacy score is the inverse summary of current exposure and is calculated from the same deterministic formula."
    ),
)
async def calculate_user_risk_endpoint(
    user_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Calculate deterministic privacy exposure for a user and persist the current snapshot."""
    _require_user(db, user_id)
    summary = calculate_and_persist_user_risk(db, user_id)
    return api_success(summary)


@router.get(
    "/accounts/{account_id}/risk",
    summary="Get account risk",
    description=(
        "Return the deterministic exposure score for one account. Risk score = exposure measurement, not a probability of compromise. "
        "Scores are derived from the current database state and are therefore deterministic."
    ),
)
async def get_account_risk_endpoint(
    account_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Return the current deterministic risk score for a single account."""
    account = db.get(Account, account_id)
    if not account:
        api_error("ACCOUNT_NOT_FOUND", "Account not found.", status.HTTP_404_NOT_FOUND)

    result = calculate_account_risk(db, account)
    return api_success(
        {
            "account_id": result["account_id"],
            "service_name": result["service_name"],
            "score": result["score"],
            "risk_level": result["risk_level"],
            "factors": result["factors"],
            "reasons": result["reasons"],
        }
    )


@router.get(
    "/users/{user_id}/risk",
    summary="Get user risk summary",
    description=(
        "Return a summary of the user's current exposure profile. Privacy score = inverse summary of exposure. "
        "Risk score remains a deterministic exposure measurement and is not a prediction of compromise probability."
    ),
)
async def get_user_risk_summary_endpoint(
    user_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Return the current privacy score and major exposure summary for a user."""
    _require_user(db, user_id)
    summary = calculate_user_risk_summary(db, user_id)
    return api_success(summary)


@router.get(
    "/users/{user_id}/risk/history",
    summary="Get risk history",
    description=(
        "Return stored risk snapshots in time order. This supports future progress tracking without generating AI explanations. "
        "The history reflects deterministic recalculations from the current database state."
    ),
)
async def get_user_risk_history_endpoint(
    user_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Return snapshot history for a user's privacy posture over time."""
    _require_user(db, user_id)
    snapshots = db.scalars(
        select(RiskSnapshot)
        .where(RiskSnapshot.user_id == user_id)
        .order_by(RiskSnapshot.snapshot_date.desc(), RiskSnapshot.id.asc())
    ).all()
    payload = [
        {
            "id": item.id,
            "user_id": item.user_id,
            "overall_score": item.overall_score,
            "risk_level": item.risk_level.value if hasattr(item.risk_level, "value") else str(item.risk_level),
            "total_accounts": item.total_accounts,
            "high_risk_accounts": item.high_risk_accounts,
            "critical_accounts": item.critical_accounts,
            "open_fix_count": item.open_fix_count,
            "single_point_count": item.single_point_count,
            "snapshot_date": item.snapshot_date.isoformat() if isinstance(item.snapshot_date, datetime) else item.snapshot_date,
            "created_at": item.created_at.isoformat() if isinstance(item.created_at, datetime) else item.created_at,
        }
        for item in snapshots
    ]
    return api_success(payload)


@router.get(
    "/users/{user_id}/risk/explanations",
    summary="Explain user privacy risk",
    description=(
        "Return deterministic explanations and consolidated recommendations derived from the current risk-engine results. "
        "This read-only endpoint does not create a risk snapshot."
    ),
    response_model=UserRiskExplanationApiResponse,
)
async def get_user_risk_explanations_endpoint(
    user_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _require_user(db, user_id)
    summary = calculate_user_risk_summary(db, user_id)
    account_ids = [item["account_id"] for item in summary.get("account_risks", [])]
    service_ids = (
        dict(db.execute(select(Account.id, Account.service_id).where(Account.id.in_(account_ids))).all())
        if account_ids
        else {}
    )
    response = build_user_risk_explanations(user_id, summary, service_ids)
    return api_success(response.model_dump())


@router.get(
    "/accounts/{account_id}/risk/explanations",
    summary="Explain account privacy risk",
    description=(
        "Return deterministic explanations and consolidated recommendations for an account, derived from the existing risk engine. "
        "Credentials and account identifiers are not included."
    ),
    response_model=AccountRiskExplanationApiResponse,
)
async def get_account_risk_explanations_endpoint(
    account_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    account = db.scalar(
        select(Account)
        .where(Account.id == account_id)
        .options(selectinload(Account.service), selectinload(Account.permissions), selectinload(Account.breach_events))
    )
    if account is None:
        api_error("ACCOUNT_NOT_FOUND", "Account not found.", status.HTTP_404_NOT_FOUND)

    result = calculate_account_risk(db, account)
    response = build_account_risk_explanations(account, result)
    return api_success(response.model_dump())
