from __future__ import annotations

from pydantic import BaseModel


class RemediationItem(BaseModel):
    fix_id: str | None = None
    title: str
    description: str
    priority: str
    severity: str
    category: str
    status: str = "OPEN"
    account_id: str | None = None
    service_id: str | None = None
    account_ids: list[str]
    service_ids: list[str]
    reason_code: str | None = None
    reason_codes: list[str]
    factor_code: str | None = None
    factor_codes: list[str]
    action: str
    impact: str
    evidence: list[str]
    risk_contribution: float


class RemediationPlan(BaseModel):
    total_open_items: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    items: list[RemediationItem]
    summary: str


class UserRemediationResponse(RemediationPlan):
    user_id: str


class AccountRemediationResponse(BaseModel):
    account_id: str
    service_id: str
    service: str | None
    risk_level: str
    risk_score: float
    total_open_items: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    items: list[RemediationItem]
    summary: str


class UserRemediationApiResponse(BaseModel):
    success: bool
    data: UserRemediationResponse


class AccountRemediationApiResponse(BaseModel):
    success: bool
    data: AccountRemediationResponse