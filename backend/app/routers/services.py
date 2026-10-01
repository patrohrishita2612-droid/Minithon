from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.models import Account, Service, ServiceCategory
from app.schemas.models import ServiceCreate, ServiceUpdate
from app.utils.responses import api_error, api_success, serialize_value

router = APIRouter(prefix="/api/services", tags=["Services"])


@router.post("")
async def create_service(payload: ServiceCreate, db: Session = Depends(get_db)) -> dict[str, Any]:
    service = Service(
        name=payload.name,
        category=payload.category,
        website=payload.website,
        description=payload.description,
    )
    db.add(service)
    db.commit()
    db.refresh(service)
    return api_success(serialize_value({
        "id": service.id,
        "name": service.name,
        "category": service.category,
        "website": service.website,
        "description": service.description,
        "created_at": service.created_at,
        "updated_at": service.updated_at,
    }))


@router.get("")
async def list_services(category: ServiceCategory | None = Query(default=None), db: Session = Depends(get_db)) -> dict[str, Any]:
    stmt = select(Service)
    if category is not None:
        stmt = stmt.where(Service.category == category)
    services = db.scalars(stmt.order_by(Service.name)).all()
    payload = [serialize_value({
        "id": service.id,
        "name": service.name,
        "category": service.category,
        "website": service.website,
        "description": service.description,
        "created_at": service.created_at,
        "updated_at": service.updated_at,
    }) for service in services]
    return api_success(payload)


@router.get("/{service_id}")
async def get_service(service_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    service = db.get(Service, service_id)
    if not service:
        api_error("SERVICE_NOT_FOUND", "Service not found.", status.HTTP_404_NOT_FOUND)
    return api_success(serialize_value({
        "id": service.id,
        "name": service.name,
        "category": service.category,
        "website": service.website,
        "description": service.description,
        "created_at": service.created_at,
        "updated_at": service.updated_at,
    }))


@router.patch("/{service_id}")
async def update_service(service_id: str, payload: ServiceUpdate, db: Session = Depends(get_db)) -> dict[str, Any]:
    service = db.get(Service, service_id)
    if not service:
        api_error("SERVICE_NOT_FOUND", "Service not found.", status.HTTP_404_NOT_FOUND)

    for field, value in payload.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(service, field, value)

    db.commit()
    db.refresh(service)
    return api_success(serialize_value({
        "id": service.id,
        "name": service.name,
        "category": service.category,
        "website": service.website,
        "description": service.description,
        "created_at": service.created_at,
        "updated_at": service.updated_at,
    }))


@router.delete("/{service_id}")
async def delete_service(service_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    service = db.get(Service, service_id)
    if not service:
        api_error("SERVICE_NOT_FOUND", "Service not found.", status.HTTP_404_NOT_FOUND)
    if db.query(Account).filter(Account.service_id == service_id).first():
        api_error("SERVICE_IN_USE", "Service cannot be deleted because it has related accounts.", status.HTTP_409_CONFLICT)
    db.delete(service)
    db.commit()
    return api_success({"deleted": True, "service_id": service_id})
