from __future__ import annotations

from datetime import date

from pydantic import BaseModel, Field


class HygieneFinding(BaseModel):
    account_id: str
    service_id: str
    service_name: str | None
    finding_type: str
    severity: str
    title: str
    description: str
    evidence: list[str]
    recommended_action: str
    age_days: int | None = None
    confidence: str


class HygieneAccountResult(BaseModel):
    account_id: str
    service_id: str
    service_name: str | None
    account_status: str
    is_active: bool
    analysis_date: date
    account_age_days: int | None = Field(default=None, description="External service-account age; UNKNOWN when the database has no external creation timestamp.")
    account_age_status: str = Field(description="External account-age classification; currently UNKNOWN because created_at is the local inventory-record timestamp.")
    inventory_record_age_days: int | None
    inventory_record_age_status: str
    activity_status: str
    last_activity_date: date | None
    findings: list[HygieneFinding]


class HygieneUserSummary(BaseModel):
    user_id: str
    analysis_date: date
    total_accounts: int = Field(description="All account records owned by this user, including inactive or deleted statuses.")
    active_accounts: int = Field(description="Accounts marked active with recorded activity within the current activity window.")
    aging_accounts: int = Field(description="Accounts with recorded last activity in the Step 5 moderate-age window.")
    stale_accounts: int = Field(description="Accounts with more than 180 days since recorded last activity.")
    stale_inventory_records: int = Field(description="Local account inventory records at least 180 days old; not external account age.")
    inactive_accounts: int = Field(description="Accounts with old recorded activity or an explicit inactive account status.")
    unknown_activity_accounts: int = Field(description="Accounts with no recorded last_activity timestamp.")
    accounts_requiring_review: int = Field(description="Distinct accounts with at least one hygiene finding, including activity-data gaps.")
    accounts: list[HygieneAccountResult]
    findings: list[HygieneFinding]


class UserHygieneResponse(BaseModel):
    success: bool
    data: HygieneUserSummary


class AccountHygieneResponse(BaseModel):
    success: bool
    data: HygieneAccountResult