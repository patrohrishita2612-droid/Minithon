from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class RiskExplanation(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    factor_code: str
    title: str
    severity: str
    current_value: str | int | float | bool | None
    explanation: str
    impact: str
    recommendation: str
    priority: int
    related_account_id: str | None = None
    related_service_id: str | None = None
    reason_code: str | None = None
    risk_contribution: float


class RiskRecommendation(BaseModel):
    title: str
    recommendation: str
    severity: str
    priority: int
    factor_codes: list[str]
    related_account_ids: list[str]
    related_service_ids: list[str]
    evidence: list[str]


class AccountRiskExplanationResponse(BaseModel):
    account_id: str
    service_id: str
    service: str | None
    risk_level: str
    risk_score: float
    explanations: list[RiskExplanation]
    recommendations: list[RiskRecommendation]


class AccountRequiringAttention(BaseModel):
    account_id: str
    service: str | None
    risk_level: str
    risk_score: float
    factor_codes: list[str]


class RiskCategorySummary(BaseModel):
    factor_code: str
    title: str
    affected_accounts: int
    total_contribution: float


class UserRiskExplanationResponse(BaseModel):
    user_id: str
    overall_exposure: float
    privacy_score: float
    risk_level: str
    summary: str
    top_risks: list[RiskExplanation]
    recommendations: list[RiskRecommendation]
    accounts_requiring_attention: list[AccountRequiringAttention]
    category_summary: list[RiskCategorySummary]


class AccountRiskExplanationApiResponse(BaseModel):
    success: bool
    data: AccountRiskExplanationResponse


class UserRiskExplanationApiResponse(BaseModel):
    success: bool
    data: UserRiskExplanationResponse
