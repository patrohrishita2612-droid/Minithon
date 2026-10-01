from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.database.database import get_db
from app.models.models import Account, BreachEvent, User
from app.schemas.breaches import (
    AccountBreachesResponse,
    AccountBreachesSummary,
    BreachEventItem,
    UserBreachesResponse,
    UserBreachesSummary,
)
from app.utils.responses import api_error, api_success


router = APIRouter(prefix="/api", tags=["Breach Events"])


def _event_item(event: BreachEvent) -> BreachEventItem:
    assert event.account_id is not None
    return BreachEventItem(
        id=event.id,
        account_id=event.account_id,
        service_id=event.service_id,
        service_name=event.service.name if event.service else None,
        severity=event.severity.value if hasattr(event.severity, "value") else str(event.severity),
        breach_date=event.breach_date,
        created_at=event.created_at,
        is_simulated=event.is_simulated,
    )


@router.get(
    "/users/{user_id}/breaches",
    summary="List account-linked breach events for a user",
    description="Return safe breach metadata for events linked to accounts owned by this user; raw event text is omitted.",
    response_model=UserBreachesResponse,
)
async def list_user_breaches(user_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = db.get(User, user_id)
    if user is None:
        api_error("USER_NOT_FOUND", "User not found.", status.HTTP_404_NOT_FOUND)

    events = db.scalars(
        select(BreachEvent)
        .join(Account, BreachEvent.account_id == Account.id)
        .where(Account.user_id == user_id)
        .options(selectinload(BreachEvent.service))
        .order_by(BreachEvent.created_at.desc(), BreachEvent.id.asc())
    ).all()
    items = [_event_item(event) for event in events]
    return api_success(UserBreachesSummary(user_id=user_id, total=len(items), breaches=items).model_dump())


@router.get(
    "/accounts/{account_id}/breaches",
    summary="List account-linked breach events for an account",
    description="Return safe breach metadata for this account; raw event text is omitted.",
    response_model=AccountBreachesResponse,
)
async def list_account_breaches(account_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    account = db.scalar(select(Account).where(Account.id == account_id).options(selectinload(Account.service)))
    if account is None:
        api_error("ACCOUNT_NOT_FOUND", "Account not found.", status.HTTP_404_NOT_FOUND)

    events = db.scalars(
        select(BreachEvent)
        .where(BreachEvent.account_id == account_id)
        .options(selectinload(BreachEvent.service))
        .order_by(BreachEvent.created_at.desc(), BreachEvent.id.asc())
    ).all()
    items = [_event_item(event) for event in events]
    summary = AccountBreachesSummary(
        account_id=account.id,
        service_id=account.service_id,
        service_name=account.service.name if account.service else None,
        total=len(items),
        breaches=items,
    )
    return api_success(summary.model_dump())


@router.post(
    "/accounts/{account_id}/breaches",
    summary="Simulate a breach event for an account",
    description="Record a simulated breach event for this account and trigger risk recalculation.",
)
async def create_account_breach(
    account_id: str,
    payload: dict[str, Any] | None = None,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    from datetime import datetime, timezone
    from app.models.models import Severity
    from app.algorithms.risk_engine import calculate_and_persist_user_risk

    account = db.scalar(select(Account).where(Account.id == account_id).options(selectinload(Account.service)))
    if account is None:
        api_error("ACCOUNT_NOT_FOUND", "Account not found.", status.HTTP_404_NOT_FOUND)

    title = (payload or {}).get("title") or f"{account.display_name or (account.service.name if account.service else 'Account')} Breach Simulation"
    description = (payload or {}).get("description") or f"Simulated security compromise reported for {account.display_name or (account.service.name if account.service else 'account')}."
    sev_str = str((payload or {}).get("severity", "CRITICAL")).upper()
    try:
        sev = Severity(sev_str)
    except ValueError:
        sev = Severity.CRITICAL

    event = BreachEvent(
        service_id=account.service_id,
        account_id=account.id,
        title=title,
        description=description,
        severity=sev,
        breach_date=datetime.now(timezone.utc),
        is_simulated=True,
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    calculate_and_persist_user_risk(db, account.user_id)

    return api_success({
        "id": event.id,
        "account_id": event.account_id,
        "service_id": event.service_id,
        "service_name": account.service.name if account.service else None,
        "severity": event.severity.value,
        "title": event.title,
        "description": event.description,
        "breach_date": event.breach_date.isoformat() if event.breach_date else None,
        "created_at": event.created_at.isoformat(),
        "is_simulated": event.is_simulated,
    })


@router.delete(
    "/accounts/{account_id}/breaches",
    summary="Clear simulated breach events for an account",
)
async def clear_account_breaches(account_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    from app.algorithms.risk_engine import calculate_and_persist_user_risk

    account = db.scalar(select(Account).where(Account.id == account_id).options(selectinload(Account.service)))
    if account is None:
        api_error("ACCOUNT_NOT_FOUND", "Account not found.", status.HTTP_404_NOT_FOUND)

    events = db.scalars(
        select(BreachEvent).where(BreachEvent.account_id == account_id, BreachEvent.is_simulated.is_(True))
    ).all()
    count = len(events)
    for ev in events:
        db.delete(ev)
    db.commit()

    calculate_and_persist_user_risk(db, account.user_id)
    return api_success({"cleared": count, "account_id": account_id})
