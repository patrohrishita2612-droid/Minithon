from __future__ import annotations

from typing import Any
from datetime import datetime

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.database.database import get_db
from app.models.models import (
    Account,
    AccountConnection,
    AccountPhoneNumber,
    AccountRecoveryEmail,
    AppPermission,
    Service,
    User,
    AccountStatus,
    PasswordStrength,
    SignInMethod,
)
from app.schemas.models import AccountCreate, AccountUpdate
from app.utils.responses import api_error, api_success, serialize_value

router = APIRouter(prefix="/api", tags=["Accounts"])


def serialize_account(account: Account) -> dict[str, Any]:
    service = account.service
    return serialize_value({
        "id": account.id,
        "user_id": account.user_id,
        "service_id": account.service_id,
        "service": {
            "id": service.id if service else None,
            "name": service.name if service else None,
            "category": service.category if service else None,
        },
        "account_identifier": account.account_identifier,
        "display_name": account.display_name,
        "status": account.status,
        "sign_in_method": account.sign_in_method,
        "two_factor_enabled": account.two_factor_enabled,
        "password_reuse_group_id": account.password_reuse_group_id,
        "password_strength": account.password_strength,
        "password_last_changed": account.password_last_changed,
        "last_activity": account.last_activity,
        "is_active": account.is_active,
        "created_at": account.created_at,
        "updated_at": account.updated_at,
    })


@router.post("/accounts")
async def create_account(payload: AccountCreate, db: Session = Depends(get_db)) -> dict[str, Any]:
    if not payload.account_identifier or not payload.account_identifier.strip():
        api_error("INVALID_ACCOUNT_IDENTIFIER", "account_identifier cannot be empty.", status.HTTP_400_BAD_REQUEST)

    user = db.get(User, payload.user_id)
    if not user:
        api_error("USER_NOT_FOUND", "User not found.", status.HTTP_404_NOT_FOUND)

    service = db.get(Service, payload.service_id)
    if not service:
        api_error("SERVICE_NOT_FOUND", "Service not found.", status.HTTP_404_NOT_FOUND)

    try:
        AccountStatus(payload.status.value if isinstance(payload.status, AccountStatus) else payload.status)
    except ValueError:
        api_error("INVALID_ACCOUNT_STATUS", "Invalid account status.", status.HTTP_400_BAD_REQUEST)

    try:
        SignInMethod(payload.sign_in_method.value if isinstance(payload.sign_in_method, SignInMethod) else payload.sign_in_method)
    except ValueError:
        api_error("INVALID_SIGN_IN_METHOD", "Invalid sign_in_method.", status.HTTP_400_BAD_REQUEST)

    try:
        PasswordStrength(payload.password_strength.value if isinstance(payload.password_strength, PasswordStrength) else payload.password_strength)
    except ValueError:
        api_error("INVALID_PASSWORD_STRENGTH", "Invalid password_strength.", status.HTTP_400_BAD_REQUEST)

    account = Account(
        user_id=payload.user_id,
        service_id=payload.service_id,
        account_identifier=payload.account_identifier.strip(),
        display_name=payload.display_name,
        status=payload.status,
        sign_in_method=payload.sign_in_method,
        two_factor_enabled=payload.two_factor_enabled,
        password_reuse_group_id=payload.password_reuse_group_id,
        password_strength=payload.password_strength,
        password_last_changed=payload.password_last_changed,
        last_activity=payload.last_activity,
        is_active=payload.is_active,
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    return api_success(serialize_account(account))


@router.get("/accounts/{account_id}")
async def get_account(account_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    account = db.scalar(select(Account).where(Account.id == account_id).options(selectinload(Account.service)))
    if not account:
        api_error("ACCOUNT_NOT_FOUND", "Account not found.", status.HTTP_404_NOT_FOUND)
    return api_success(serialize_account(account))


@router.get("/users/{user_id}/accounts")
async def list_user_accounts(
    user_id: str,
    service_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    two_factor_enabled: bool | None = Query(default=None),
    sign_in_method: str | None = Query(default=None),
    is_active: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    user = db.get(User, user_id)
    if not user:
        api_error("USER_NOT_FOUND", "User not found.", status.HTTP_404_NOT_FOUND)

    criteria = [Account.user_id == user_id]
    if service_id:
        criteria.append(Account.service_id == service_id)
    if status:
        criteria.append(Account.status == status)
    if two_factor_enabled is not None:
        criteria.append(Account.two_factor_enabled == two_factor_enabled)
    if sign_in_method:
        criteria.append(Account.sign_in_method == sign_in_method)
    if is_active is not None:
        criteria.append(Account.is_active == is_active)

    stmt = select(Account).where(*criteria).options(selectinload(Account.service))
    total = db.scalar(select(func.count()).select_from(Account).where(*criteria)) or 0
    items = db.scalars(
        stmt.order_by(Account.created_at.desc(), Account.id.asc())
        .offset((page - 1) * limit)
        .limit(limit)
    ).all()
    payload = {
        "items": [serialize_account(item) for item in items],
        "page": page,
        "limit": limit,
        "total": total,
    }
    return api_success(payload)


@router.patch("/accounts/{account_id}")
async def update_account(account_id: str, payload: AccountUpdate, db: Session = Depends(get_db)) -> dict[str, Any]:
    account = db.get(Account, account_id)
    if not account:
        api_error("ACCOUNT_NOT_FOUND", "Account not found.", status.HTTP_404_NOT_FOUND)

    for field, value in payload.model_dump(exclude_unset=True).items():
        if field in {"user_id", "service_id"}:
            continue
        if value is not None:
            setattr(account, field, value)

    db.commit()
    db.refresh(account)
    return api_success(serialize_account(account))


@router.delete("/accounts/{account_id}")
async def delete_account(account_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    account = db.get(Account, account_id)
    if not account:
        api_error("ACCOUNT_NOT_FOUND", "Account not found.", status.HTTP_404_NOT_FOUND)

    for relation in [
        db.query(AccountConnection).filter((AccountConnection.source_account_id == account_id) | (AccountConnection.target_account_id == account_id)).all(),
        db.query(AccountRecoveryEmail).filter(AccountRecoveryEmail.account_id == account_id).all(),
        db.query(AccountPhoneNumber).filter(AccountPhoneNumber.account_id == account_id).all(),
        db.query(AppPermission).filter(AppPermission.account_id == account_id).all(),
    ]:
        for item in relation:
            db.delete(item)

    account.is_active = False
    account.status = AccountStatus.DELETED
    db.commit()
    return api_success({"deleted": True, "account_id": account_id, "soft_deleted": True})


@router.get("/users/{user_id}/footprint")
async def get_user_footprint(user_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = db.get(User, user_id)
    if not user:
        api_error("USER_NOT_FOUND", "User not found.", status.HTTP_404_NOT_FOUND)

    accounts = db.scalars(
        select(Account)
        .where(Account.user_id == user_id)
        .options(selectinload(Account.service))
        .order_by(Account.created_at.asc(), Account.id.asc())
    ).all()
    account_ids = [account.id for account in accounts]
    services = db.scalars(
        select(Service).where(Service.id.in_([account.service_id for account in accounts])).order_by(Service.name, Service.id)
    ).all()
    recovery_emails = db.scalars(
        select(AccountRecoveryEmail)
        .where(AccountRecoveryEmail.account_id.in_(account_ids))
        .order_by(AccountRecoveryEmail.account_id, AccountRecoveryEmail.id)
    ).all()
    phone_links = db.scalars(
        select(AccountPhoneNumber)
        .where(AccountPhoneNumber.account_id.in_(account_ids))
        .order_by(AccountPhoneNumber.account_id, AccountPhoneNumber.id)
    ).all()
    permissions = db.scalars(
        select(AppPermission)
        .where(AppPermission.account_id.in_(account_ids))
        .order_by(AppPermission.account_id, AppPermission.id)
    ).all()
    connections = db.scalars(
        select(AccountConnection)
        .where(AccountConnection.source_account_id.in_(account_ids), AccountConnection.target_account_id.in_(account_ids))
        .order_by(AccountConnection.id)
    ).all()

    user_payload = serialize_value({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    })
    account_payload = [serialize_account(account) for account in accounts]
    service_payload = [serialize_value({
        "id": item.id,
        "name": item.name,
        "category": item.category,
        "website": item.website,
        "description": item.description,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }) for item in services]
    recovery_email_payload = [serialize_value({
        "id": item.id,
        "account_id": item.account_id,
        "recovery_email_id": item.recovery_email_id,
    }) for item in recovery_emails]
    phone_payload = [serialize_value({
        "id": item.id,
        "account_id": item.account_id,
        "phone_number_id": item.phone_number_id,
    }) for item in phone_links]
    permission_payload = [serialize_value({
        "id": item.id,
        "account_id": item.account_id,
        "permission_type": item.permission_type,
        "description": item.description,
        "sensitivity": item.sensitivity,
        "granted": item.granted,
        "granted_at": item.granted_at,
        "last_reviewed_at": item.last_reviewed_at,
    }) for item in permissions]
    connection_payload = [serialize_value({
        "id": item.id,
        "source_account_id": item.source_account_id,
        "target_account_id": item.target_account_id,
        "connection_type": item.connection_type,
        "description": item.description,
        "is_active": item.is_active,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }) for item in connections]

    return api_success({
        "user": user_payload,
        "accounts": account_payload,
        "services": service_payload,
        "recovery_emails": recovery_email_payload,
        "phone_numbers": phone_payload,
        "connections": connection_payload,
        "permissions": permission_payload,
    })
