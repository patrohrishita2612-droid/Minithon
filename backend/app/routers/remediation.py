from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.algorithms.risk_engine import calculate_account_risk, calculate_user_risk_summary
from app.database.database import get_db
from app.models.models import Account, User
from app.remediation import build_account_remediation_response, build_user_remediation_response
from app.risk_explanations import build_account_risk_explanations, build_user_risk_explanations
from app.schemas.remediation import AccountRemediationApiResponse, UserRemediationApiResponse
from app.utils.responses import api_error, api_success


router = APIRouter(prefix="/api", tags=["Privacy Remediation"])


@router.get(
    "/users/{user_id}/remediation",
    summary="Generate a user remediation plan",
    description=(
        "Generate a deterministic, read-only remediation preview from current risk findings and Step 6 recommendations. "
        "Items are not saved as FixItem records by this endpoint."
    ),
    response_model=UserRemediationApiResponse,
)
async def get_user_remediation_endpoint(
    user_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if db.get(User, user_id) is None:
        api_error("USER_NOT_FOUND", "User not found.", status.HTTP_404_NOT_FOUND)

    summary = calculate_user_risk_summary(db, user_id)
    account_results = summary.get("account_risks", [])
    account_ids = [result["account_id"] for result in account_results]
    service_ids = (
        dict(
            db.execute(
                select(Account.id, Account.service_id).where(
                    Account.user_id == user_id,
                    Account.id.in_(account_ids),
                )
            ).all()
        )
        if account_ids
        else {}
    )
    explanation = build_user_risk_explanations(user_id, summary, service_ids)
    response = build_user_remediation_response(user_id, explanation, account_results, service_ids)
    return api_success(response.model_dump())


@router.get(
    "/accounts/{account_id}/remediation",
    summary="Generate an account remediation plan",
    description=(
        "Generate a deterministic, read-only remediation preview for one account. "
        "The response contains no account identifiers or credentials."
    ),
    response_model=AccountRemediationApiResponse,
)
async def get_account_remediation_endpoint(
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

    risk_result = calculate_account_risk(db, account)
    explanation = build_account_risk_explanations(account, risk_result)
    response = build_account_remediation_response(account_id, explanation, risk_result)
    return api_success(response.model_dump())