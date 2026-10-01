from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.algorithms.exposure_graph import build_exposure_graph, find_exposure_path
from app.database.database import get_db
from app.models.models import Account, User
from app.utils.responses import api_error, api_success

router = APIRouter(prefix="/api/users", tags=["Exposure Analysis"])


def _require_user_access(user_id: str, db: Session) -> User:
    user = db.get(User, user_id)
    if not user:
        api_error("USER_NOT_FOUND", "User not found.", status.HTTP_404_NOT_FOUND)
    return user


def _require_account_ownership(db: Session, user_id: str, account_id: str) -> Account:
    account = db.get(Account, account_id)
    if not account:
        api_error("ACCOUNT_NOT_FOUND", "Account not found.", status.HTTP_404_NOT_FOUND)
    if account.user_id != user_id:
        api_error(
            "ACCOUNT_NOT_IN_USER_GRAPH",
            "The account does not belong to the requested user.",
            status.HTTP_400_BAD_REQUEST,
        )
    return account


@router.get("/{user_id}/exposure/graph")
async def get_exposure_graph(
    user_id: str,
    db: Session = Depends(get_db),
    query_user_id: str | None = Query(default=None, alias="user_id"),
) -> dict[str, Any]:
    _require_user_access(user_id, db)
    if query_user_id and query_user_id != user_id:
        api_error("USER_MISMATCH", "Request does not match the user being analyzed.", status.HTTP_404_NOT_FOUND)
    graph = build_exposure_graph(db, user_id)
    return api_success(graph)


@router.get("/{user_id}/exposure/metrics")
async def get_exposure_metrics(
    user_id: str,
    db: Session = Depends(get_db),
    query_user_id: str | None = Query(default=None, alias="user_id"),
) -> dict[str, Any]:
    _require_user_access(user_id, db)
    if query_user_id and query_user_id != user_id:
        api_error("USER_MISMATCH", "Request does not match the user being analyzed.", status.HTTP_404_NOT_FOUND)
    graph = build_exposure_graph(db, user_id)
    return api_success(graph["structural_metrics"])


@router.get("/{user_id}/exposure/path")
async def get_exposure_path(
    user_id: str,
    source_account_id: str = Query(...),
    target_account_id: str = Query(...),
    db: Session = Depends(get_db),
    query_user_id: str | None = Query(default=None, alias="user_id"),
) -> dict[str, Any]:
    _require_user_access(user_id, db)
    if query_user_id and query_user_id != user_id:
        api_error("USER_MISMATCH", "Request does not match the user being analyzed.", status.HTTP_404_NOT_FOUND)
    if source_account_id == target_account_id:
        api_error("INVALID_PATH", "Source and target account must differ.", status.HTTP_400_BAD_REQUEST)

    _require_account_ownership(db, user_id, source_account_id)
    _require_account_ownership(db, user_id, target_account_id)

    graph = build_exposure_graph(db, user_id)
    result = find_exposure_path(graph, source_account_id, target_account_id)
    if not result["exists"]:
        return api_success({"exists": False, "path": [], "edges": [], "hops": 0})
    return api_success(result)
