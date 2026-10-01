from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.models import User
from app.schemas.models import UserCreate, UserUpdate
from app.utils.responses import api_error, api_success, serialize_value

router = APIRouter(prefix="/api/users", tags=["Users"])


@router.post("")
async def create_user(payload: UserCreate, db: Session = Depends(get_db)) -> dict[str, Any]:
    existing = db.scalar(select(User).where(User.email == payload.email))
    if existing:
        api_error("USER_EXISTS", "A user with this email already exists.", status.HTTP_409_CONFLICT)

    user = User(name=payload.name, email=payload.email)
    db.add(user)
    db.commit()
    db.refresh(user)
    return api_success(serialize_value({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }))


@router.get("")
async def list_users(email: str | None = Query(default=None), db: Session = Depends(get_db)) -> dict[str, Any]:
    stmt = select(User)
    if email:
        stmt = stmt.where(User.email == email)
    users = db.scalars(stmt).all()
    return api_success([serialize_value({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }) for user in users])


@router.get("/{user_id}")
async def get_user(user_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = db.get(User, user_id)
    if not user:
        api_error("USER_NOT_FOUND", "User not found.", status.HTTP_404_NOT_FOUND)
    return api_success(serialize_value({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }))


@router.patch("/{user_id}")
async def update_user(user_id: str, payload: UserUpdate, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = db.get(User, user_id)
    if not user:
        api_error("USER_NOT_FOUND", "User not found.", status.HTTP_404_NOT_FOUND)

    for field, value in payload.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(user, field, value)

    db.commit()
    db.refresh(user)
    return api_success(serialize_value({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }))


@router.delete("/{user_id}")
async def delete_user(user_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = db.get(User, user_id)
    if not user:
        api_error("USER_NOT_FOUND", "User not found.", status.HTTP_404_NOT_FOUND)

    db.delete(user)
    db.commit()
    return api_success({"deleted": True, "user_id": user_id})
