from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.models import Account, AppPermission
from app.schemas.models import AppPermissionCreate, AppPermissionUpdate
from app.utils.responses import api_error, api_success, serialize_value

router = APIRouter(prefix="/api", tags=["Permissions"])


@router.post("/accounts/{account_id}/permissions")
async def create_permission(account_id: str, payload: AppPermissionCreate, db: Session = Depends(get_db)) -> dict[str, Any]:
    account = db.get(Account, account_id)
    if not account:
        api_error("ACCOUNT_NOT_FOUND", "Account not found.", status.HTTP_404_NOT_FOUND)
    if payload.account_id is not None and payload.account_id != account.id:
        api_error("ACCOUNT_MISMATCH", "Permission account_id must match the account in the request path.", status.HTTP_400_BAD_REQUEST)

    permission = AppPermission(
        account_id=account.id,
        permission_type=payload.permission_type,
        description=payload.description,
        sensitivity=payload.sensitivity,
        granted=payload.granted,
        granted_at=payload.granted_at,
        last_reviewed_at=payload.last_reviewed_at,
    )
    db.add(permission)
    db.commit(); db.refresh(permission)
    return api_success(serialize_value({
        "id": permission.id,
        "account_id": permission.account_id,
        "permission_type": permission.permission_type,
        "description": permission.description,
        "sensitivity": permission.sensitivity,
        "granted": permission.granted,
        "granted_at": permission.granted_at,
        "last_reviewed_at": permission.last_reviewed_at,
        "created_at": permission.created_at,
        "updated_at": permission.updated_at,
    }))


@router.get("/accounts/{account_id}/permissions")
async def list_permissions(account_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    account = db.get(Account, account_id)
    if not account:
        api_error("ACCOUNT_NOT_FOUND", "Account not found.", status.HTTP_404_NOT_FOUND)
    permissions = db.scalars(
        select(AppPermission)
        .where(AppPermission.account_id == account_id)
        .order_by(AppPermission.created_at.asc(), AppPermission.id.asc())
    ).all()
    return api_success([serialize_value({
        "id": item.id,
        "account_id": item.account_id,
        "permission_type": item.permission_type,
        "description": item.description,
        "sensitivity": item.sensitivity,
        "granted": item.granted,
        "granted_at": item.granted_at,
        "last_reviewed_at": item.last_reviewed_at,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }) for item in permissions])


@router.patch("/permissions/{permission_id}")
async def update_permission(permission_id: str, payload: AppPermissionUpdate, db: Session = Depends(get_db)) -> dict[str, Any]:
    permission = db.get(AppPermission, permission_id)
    if not permission:
        api_error("PERMISSION_NOT_FOUND", "Permission not found.", status.HTTP_404_NOT_FOUND)

    for field, value in payload.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(permission, field, value)
    db.commit(); db.refresh(permission)
    return api_success(serialize_value({
        "id": permission.id,
        "account_id": permission.account_id,
        "permission_type": permission.permission_type,
        "description": permission.description,
        "sensitivity": permission.sensitivity,
        "granted": permission.granted,
        "granted_at": permission.granted_at,
        "last_reviewed_at": permission.last_reviewed_at,
        "created_at": permission.created_at,
        "updated_at": permission.updated_at,
    }))


@router.delete("/permissions/{permission_id}")
async def delete_permission(permission_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    permission = db.get(AppPermission, permission_id)
    if not permission:
        api_error("PERMISSION_NOT_FOUND", "Permission not found.", status.HTTP_404_NOT_FOUND)
    db.delete(permission)
    db.commit()
    return api_success({"deleted": True, "permission_id": permission_id})
