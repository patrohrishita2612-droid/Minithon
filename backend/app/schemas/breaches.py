from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class BreachEventItem(BaseModel):
    id: str
    account_id: str
    service_id: str
    service_name: str | None
    severity: str
    breach_date: datetime | None
    created_at: datetime
    is_simulated: bool


class UserBreachesSummary(BaseModel):
    user_id: str
    total: int
    breaches: list[BreachEventItem]


class AccountBreachesSummary(BaseModel):
    account_id: str
    service_id: str
    service_name: str | None
    total: int
    breaches: list[BreachEventItem]


class UserBreachesResponse(BaseModel):
    success: bool
    data: UserBreachesSummary


class AccountBreachesResponse(BaseModel):
    success: bool
    data: AccountBreachesSummary