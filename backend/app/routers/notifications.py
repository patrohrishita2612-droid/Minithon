from __future__ import annotations

from datetime import date, datetime, time, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.algorithms.risk_engine import calculate_account_risk, calculate_user_risk_summary
from app.database.database import get_db
from app.models.models import Account, Notification, User
from app.notifications import build_notification_counts, build_notifications, candidates_for_account
from app.remediation import build_account_remediation_response, build_user_remediation_response
from app.risk_explanations import build_account_risk_explanations, build_user_risk_explanations
from app.schemas.notifications import (
    AccountNotificationsResponse,
    AccountNotificationsSummary,
    NotificationService,
    UserNotificationsResponse,
    UserNotificationsSummary,
)
from app.utils.responses import api_error, api_success


router = APIRouter(prefix="/api", tags=["Privacy Notifications"])


def _account_options():
    return (
        selectinload(Account.service),
        selectinload(Account.permissions),
        selectinload(Account.breach_events),
    )


def _as_of_datetime(as_of: date | None) -> datetime | None:
    if as_of is None:
        return None
    return datetime.combine(as_of, time.max, tzinfo=timezone.utc)


def _persisted_for_user(db: Session, user_id: str) -> list[Notification]:
    return db.scalars(
        select(Notification)
        .where(Notification.user_id == user_id)
        .order_by(Notification.created_at.asc(), Notification.id.asc())
    ).all()


@router.get(
    "/users/{user_id}/notifications",
    summary="Generate user privacy notifications",
    description=(
        "Return deterministic, read-only notification candidates derived from current risk, hygiene, breach, and remediation findings. "
        "Candidates are not persisted; matching existing notification rows contribute read state and creation timestamp only."
    ),
    response_model=UserNotificationsResponse,
)
async def get_user_notifications_endpoint(
    user_id: str,
    as_of: date | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if db.get(User, user_id) is None:
        api_error("USER_NOT_FOUND", "User not found.", status.HTTP_404_NOT_FOUND)

    accounts = list(
        db.scalars(
            select(Account)
            .where(Account.user_id == user_id)
            .options(*_account_options())
            .order_by(Account.created_at.asc(), Account.id.asc())
        ).all()
    )
    risk_summary = calculate_user_risk_summary(db, user_id, now=_as_of_datetime(as_of))
    account_results = risk_summary.get("account_risks", [])
    account_ids = [result["account_id"] for result in account_results]
    service_ids = (
        {account.id: account.service_id for account in accounts if account.id in set(account_ids)}
        if account_ids
        else {}
    )
    risk_explanation = build_user_risk_explanations(user_id, risk_summary, service_ids)
    remediation = build_user_remediation_response(
        user_id,
        risk_explanation,
        account_results,
        service_ids,
    )
    persisted = _persisted_for_user(db, user_id)
    notifications = build_notifications(
        user_id,
        accounts,
        account_results,
        remediation.items,
        persisted=persisted,
        as_of=as_of,
    )
    counts = build_notification_counts(notifications)
    response = UserNotificationsSummary(user_id=user_id, notifications=notifications, **counts)
    return api_success(response.model_dump())


@router.get(
    "/accounts/{account_id}/notifications",
    summary="Generate account privacy notifications",
    description=(
        "Return deterministic, read-only notification candidates for one account. "
        "Sensitive account identifiers, recovery values, and stored notification message text are not returned."
    ),
    response_model=AccountNotificationsResponse,
)
async def get_account_notifications_endpoint(
    account_id: str,
    as_of: date | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    account = db.scalar(
        select(Account).where(Account.id == account_id).options(*_account_options())
    )
    if account is None:
        api_error("ACCOUNT_NOT_FOUND", "Account not found.", status.HTTP_404_NOT_FOUND)

    risk_result = calculate_account_risk(db, account, now=_as_of_datetime(as_of))
    risk_explanation = build_account_risk_explanations(account, risk_result)
    remediation = build_account_remediation_response(account.id, risk_explanation, risk_result)
    persisted = db.scalars(
        select(Notification)
        .where(Notification.user_id == account.user_id, Notification.account_id == account.id)
        .order_by(Notification.created_at.asc(), Notification.id.asc())
    ).all()
    notifications = candidates_for_account(
        account.user_id,
        account,
        risk_result,
        remediation.items,
        persisted=persisted,
        as_of=as_of,
    )
    counts = build_notification_counts(notifications)
    response = AccountNotificationsSummary(
        account_id=account.id,
        service=NotificationService(id=account.service_id, name=account.service.name if account.service else None),
        notifications=notifications,
        **counts,
    )
    return api_success(response.model_dump())