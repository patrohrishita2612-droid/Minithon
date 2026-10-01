from __future__ import annotations

from typing import Any

from app.schemas.remediation import (
    AccountRemediationResponse,
    RemediationItem,
    RemediationPlan,
    UserRemediationResponse,
)
from app.schemas.risk_explanations import (
    AccountRiskExplanationResponse,
    RiskRecommendation,
    UserRiskExplanationResponse,
)


_PRIORITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_FACTOR_RESULT_KEYS = {
    "AUTHENTICATION": "authentication",
    "PASSWORD_REUSE": "password_reuse",
    "PERMISSIONS": "permissions",
    "NETWORK": "network",
    "BREACH": "breach",
    "HYGIENE": "hygiene",
    "SINGLE_POINT_OF_FAILURE": "single_point_of_failure",
}
_FACTOR_CATEGORIES = {
    "AUTHENTICATION": "Authentication",
    "PASSWORD_REUSE": "Password reuse",
    "PERMISSIONS": "Permissions",
    "NETWORK": "Network/exposure",
    "BREACH": "Breach",
    "HYGIENE": "Hygiene/activity",
    "SINGLE_POINT_OF_FAILURE": "Structural single point of failure",
}
_FACTOR_REASON_CODES = {
    "AUTHENTICATION": "NO_2FA",
    "PASSWORD_REUSE": "PASSWORD_REUSE",
    "PERMISSIONS": "HIGH_PERMISSION",
    "NETWORK": "NETWORK_EXPOSURE",
    "BREACH": "BREACH",
    "HYGIENE": "INACTIVE_ACCOUNT",
    "SINGLE_POINT_OF_FAILURE": "SPOF",
}
_FACTOR_IMPACTS = {
    "AUTHENTICATION": "Adds a second sign-in protection step where the service supports it.",
    "PASSWORD_REUSE": "Reduces cross-account exposure if credentials are reused.",
    "PERMISSIONS": "Reduces unnecessary data or actions available through the account.",
    "NETWORK": "Reduces unnecessary account links when those links are removed.",
    "BREACH": "Supports response to the breach event recorded for the affected account or service.",
    "HYGIENE": "Reduces exposure only if the account is confirmed to be no longer needed.",
    "SINGLE_POINT_OF_FAILURE": "Reduces reliance on one account or recovery path where alternatives are supported.",
}


def _item_contribution(
    recommendation: RiskRecommendation,
    account_results: dict[str, dict[str, Any]],
) -> float:
    contributions = []
    for account_id in recommendation.related_account_ids:
        result = account_results.get(account_id, {})
        factors = result.get("factors", {})
        for factor_code in recommendation.factor_codes:
            result_key = _FACTOR_RESULT_KEYS.get(factor_code)
            if result_key:
                contributions.append(float(factors.get(result_key, {}).get("points", 0.0)))
    return max(contributions, default=0.0)


def build_remediation_items(
    recommendations: list[RiskRecommendation],
    account_results: list[dict[str, Any]],
    service_ids: dict[str, str],
) -> list[RemediationItem]:
    result_by_account = {result["account_id"]: result for result in account_results}
    items: list[RemediationItem] = []

    for recommendation in recommendations:
        factor_codes = sorted(set(recommendation.factor_codes))
        account_ids = sorted(set(recommendation.related_account_ids))
        related_service_ids = sorted(
            set(recommendation.related_service_ids)
            | {service_ids[account_id] for account_id in account_ids if account_id in service_ids}
        )
        reason_codes = sorted(
            {_FACTOR_REASON_CODES[code] for code in factor_codes if code in _FACTOR_REASON_CODES}
        )
        categories = sorted({_FACTOR_CATEGORIES[code] for code in factor_codes if code in _FACTOR_CATEGORIES})
        impacts = sorted({_FACTOR_IMPACTS[code] for code in factor_codes if code in _FACTOR_IMPACTS})
        severity = recommendation.severity.upper()
        priority = severity if severity in _PRIORITY_ORDER else "LOW"
        contribution = _item_contribution(recommendation, result_by_account)
        category = " / ".join(categories) if categories else "Privacy"

        items.append(
            RemediationItem(
                fix_id=None,
                title=recommendation.title,
                description=f"Generated from the deterministic {category.lower()} finding. Review its references before taking action.",
                priority=priority,
                severity=severity,
                category=category,
                status="OPEN",
                account_id=account_ids[0] if len(account_ids) == 1 else None,
                service_id=related_service_ids[0] if len(related_service_ids) == 1 else None,
                account_ids=account_ids,
                service_ids=related_service_ids,
                reason_code=reason_codes[0] if len(reason_codes) == 1 else None,
                reason_codes=reason_codes,
                factor_code=factor_codes[0] if len(factor_codes) == 1 else None,
                factor_codes=factor_codes,
                action=recommendation.recommendation,
                impact=" ".join(impacts),
                evidence=sorted(set(recommendation.evidence)),
                risk_contribution=contribution,
            )
        )

    return sorted(
        items,
        key=lambda item: (
            _PRIORITY_ORDER.get(item.priority, 4),
            -item.risk_contribution,
            item.factor_codes,
            item.account_ids,
            item.service_ids,
        ),
    )


def build_remediation_plan(items: list[RemediationItem]) -> RemediationPlan:
    counts = {priority: sum(item.priority == priority for item in items) for priority in _PRIORITY_ORDER}
    if items:
        summary = f"{len(items)} open remediation item(s) are derived from current deterministic findings."
    else:
        summary = "No remediation actions are supported by the current deterministic findings."
    return RemediationPlan(
        total_open_items=len(items),
        critical_count=counts["CRITICAL"],
        high_count=counts["HIGH"],
        medium_count=counts["MEDIUM"],
        low_count=counts["LOW"],
        items=items,
        summary=summary,
    )


def build_user_remediation_response(
    user_id: str,
    explanation: UserRiskExplanationResponse,
    account_results: list[dict[str, Any]],
    service_ids: dict[str, str],
) -> UserRemediationResponse:
    items = build_remediation_items(explanation.recommendations, account_results, service_ids)
    plan = build_remediation_plan(items)
    return UserRemediationResponse(user_id=user_id, **plan.model_dump())


def build_account_remediation_response(
    account_id: str,
    explanation: AccountRiskExplanationResponse,
    account_result: dict[str, Any],
) -> AccountRemediationResponse:
    items = build_remediation_items(
        explanation.recommendations,
        [account_result],
        {account_id: explanation.service_id},
    )
    plan = build_remediation_plan(items)
    return AccountRemediationResponse(
        account_id=account_id,
        service_id=explanation.service_id,
        service=explanation.service,
        risk_level=explanation.risk_level,
        risk_score=explanation.risk_score,
        **plan.model_dump(),
    )