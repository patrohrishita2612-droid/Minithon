from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.models import Account, AccountConnection, ConnectionType, User
from app.schemas.models import AccountConnectionCreate
from app.utils.responses import api_error, api_success, serialize_value

router = APIRouter(prefix="/api", tags=["Connections"])


@router.post("/connections")
async def create_connection(payload: AccountConnectionCreate, db: Session = Depends(get_db)) -> dict[str, Any]:
    source_account = db.get(Account, payload.source_account_id)
    target_account = db.get(Account, payload.target_account_id)
    if not source_account or not target_account:
        api_error("ACCOUNT_NOT_FOUND", "Both source and target accounts must exist.", status.HTTP_404_NOT_FOUND)
    if source_account.user_id != target_account.user_id:
        api_error("CROSS_USER_RELATION", "Connected accounts must belong to the same user.", status.HTTP_400_BAD_REQUEST)
    if payload.source_account_id == payload.target_account_id:
        api_error("SELF_CONNECTION", "An account cannot connect to itself.", status.HTTP_400_BAD_REQUEST)

    try:
        ConnectionType(payload.connection_type.value if isinstance(payload.connection_type, ConnectionType) else payload.connection_type)
    except ValueError:
        api_error("INVALID_CONNECTION_TYPE", "Unsupported connection type.", status.HTTP_400_BAD_REQUEST)

    existing = db.scalar(
        select(AccountConnection).where(AccountConnection.source_account_id == payload.source_account_id)
        .where(AccountConnection.target_account_id == payload.target_account_id)
        .where(AccountConnection.connection_type == (payload.connection_type.value if isinstance(payload.connection_type, ConnectionType) else payload.connection_type))
    )
    if existing and existing.is_active:
        api_error("RELATION_EXISTS", "An active relationship already exists between these accounts.", status.HTTP_409_CONFLICT)

    connection = AccountConnection(
        source_account_id=payload.source_account_id,
        target_account_id=payload.target_account_id,
        connection_type=payload.connection_type,
        description=payload.description,
        is_active=payload.is_active,
    )
    db.add(connection)
    db.commit(); db.refresh(connection)
    return api_success(serialize_value({
        "id": connection.id,
        "source_account_id": connection.source_account_id,
        "target_account_id": connection.target_account_id,
        "connection_type": connection.connection_type,
        "description": connection.description,
        "is_active": connection.is_active,
        "created_at": connection.created_at,
        "updated_at": connection.updated_at,
    }))


@router.get("/connections/{connection_id}")
async def get_connection(connection_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    connection = db.get(AccountConnection, connection_id)
    if not connection:
        api_error("CONNECTION_NOT_FOUND", "Connection not found.", status.HTTP_404_NOT_FOUND)
    return api_success(serialize_value({
        "id": connection.id,
        "source_account_id": connection.source_account_id,
        "target_account_id": connection.target_account_id,
        "connection_type": connection.connection_type,
        "description": connection.description,
        "is_active": connection.is_active,
        "created_at": connection.created_at,
        "updated_at": connection.updated_at,
    }))


@router.get("/users/{user_id}/connections")
async def list_user_connections(user_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = db.get(User, user_id)
    if not user:
        api_error("USER_NOT_FOUND", "User not found.", status.HTTP_404_NOT_FOUND)
    accounts = db.scalars(select(Account.id).where(Account.user_id == user_id)).all()
    connections = db.scalars(
        select(AccountConnection).where(
            ((AccountConnection.source_account_id.in_(accounts)) | (AccountConnection.target_account_id.in_(accounts)))
        )
    ).all()
    return api_success([serialize_value({
        "id": item.id,
        "source_account_id": item.source_account_id,
        "target_account_id": item.target_account_id,
        "connection_type": item.connection_type,
        "description": item.description,
        "is_active": item.is_active,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }) for item in connections])


@router.delete("/connections/{connection_id}")
async def delete_connection(connection_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    connection = db.get(AccountConnection, connection_id)
    if not connection:
        api_error("CONNECTION_NOT_FOUND", "Connection not found.", status.HTTP_404_NOT_FOUND)
    db.delete(connection)
    db.commit()
    return api_success({"deleted": True, "connection_id": connection_id})
