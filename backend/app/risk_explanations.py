from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.algorithms.risk_engine import _risk_level_for_score
from app.models.models import Account
from app.schemas.risk_explanations import (
    AccountRequiringAttention,
    AccountRiskExplanationResponse,
    RiskCategorySummary,
    RiskExplanation,
    RiskRecommendation,
    UserRiskExplanationResponse,
)


_PRIORITY_BY_SEVERITY = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
_FACTORS: dict[str, dict[str, str]] = {
    "NO_2FA": {
        "factor_code": "AUTHENTICATION",
        "title": "Two-factor authentication is disabled",
        "impact": "A sign-in that depends on one verification method has less protection if that method is compromised.",
        "recommendation": "Enable two-factor authentication for this account where the service supports it.",
    },
    "PASSWORD_REUSE": {
        "factor_code": "PASSWORD_REUSE",
        "title": "A password-reuse group is recorded",
        "impact": "If credentials are reused, exposure at one service may increase risk to the other accounts in the recorded group.",
        "recommendation": "Review the recorded reuse group and use a unique password for each important account.",
    },
    "HIGH_PERMISSION": {
        "factor_code": "PERMISSIONS",
        "title": "Granted permissions increase exposure",
        "impact": "Broader granted access can expose more data or actions if this service account is compromised.",
        "recommendation": "Review granted permissions and revoke access that is no longer required.",
    },
    "NETWORK_EXPOSURE": {
        "factor_code": "NETWORK",
        "title": "Connected-account exposure is elevated",
        "impact": "Account connections can extend the set of accounts affected by a compromised or unavailable account.",
        "recommendation": "Review active account connections and remove links that are no longer needed.",
    },
    "BREACH": {
        "factor_code": "BREACH",
        "title": "A breach event is recorded",
        "impact": "Previously exposed service data can increase targeted access attempts or credential-reuse risk.",
        "recommendation": "Review the breach notice, change any affected credential still in use, and enable two-factor authentication.",
    },
    "INACTIVE_ACCOUNT": {
        "factor_code": "HYGIENE",
        "title": "Account activity needs review",
        "impact": "An account that is no longer monitored may retain access or recovery paths that are easy to overlook.",
        "recommendation": "Confirm whether this account is still needed; deactivate or remove it if it is not.",
    },
    "SPOF": {
        "factor_code": "SINGLE_POINT_OF_FAILURE",
        "title": "Structural single point of failure detected",
        "impact": "This account's position in the exposure graph makes its availability or compromise consequential to graph connectivity.",
        "recommendation": "Review dependent accounts and establish independent recovery or sign-in paths where supported.",
    },
}

_FACTOR_TITLES = {
    "AUTHENTICATION": "Authentication",
    "PASSWORD_REUSE": "Password reuse",
    "PERMISSIONS": "Permissions",
    "NETWORK": "Network exposure",
    "BREACH": "Breach exposure",
    "HYGIENE": "Activity hygiene",
    "SINGLE_POINT_OF_FAILURE": "Structural single point of failure",
}


def _priority(severity: str) -> int:
    return _PRIORITY_BY_SEVERITY.get(severity.upper(), 4)


def _build_recommendations(explanations: list[RiskExplanation]) -> list[RiskRecommendation]:
    grouped: dict[str, dict[str, Any]] = {}
    for item in explanations:
        group = grouped.setdefault(
            item.recommendation,
            {
                "title": item.title,
                "recommendation": item.recommendation,
                "severity": item.severity,
                "priority": item.priority,
                "factor_codes": set(),
                "related_account_ids": set(),
                "related_service_ids": set(),
                "evidence": set(),
                "contribution": 0.0,
            },
        )
        group["factor_codes"].add(item.factor_code)
        if item.related_account_id:
            group["related_account_ids"].add(item.related_account_id)
        if item.related_service_id:
            group["related_service_ids"].add(item.related_service_id)
        if item.reason_code:
            group["evidence"].add(f"{item.related_account_id or ''}:{item.reason_code}:{item.explanation}")
        group["contribution"] = max(group["contribution"], item.risk_contribution)
        if item.priority < group["priority"]:
            group["priority"] = item.priority
            group["severity"] = item.severity
            group["title"] = item.title

    recommendations = [
        RiskRecommendation(
            title=group["title"],
            recommendation=group["recommendation"],
            severity=group["severity"],
            priority=group["priority"],
            factor_codes=sorted(group["factor_codes"]),
            related_account_ids=sorted(group["related_account_ids"]),
            related_service_ids=sorted(group["related_service_ids"]),
            evidence=sorted(group["evidence"]),
        )
        for group in grouped.values()
    ]
    return sorted(
        recommendations,
        key=lambda item: (
            item.priority,
            -grouped[item.recommendation]["contribution"],
            item.factor_codes,
            item.recommendation,
        ),
    )


def _explanations_for_result(
    account_id: str,
    service_id: str,
    result: dict[str, Any],
    account: Account | None = None,
) -> list[RiskExplanation]:
    factor_values = result.get("factors", {})
    reasons = result.get("reasons", [])
    breach_count = len(account.breach_events) if account is not None else 0
    granted_permission_count = sum(1 for permission in account.permissions if permission.granted) if account is not None else 0
    graph_metric = result.get("graph_metric", {})
    explanations: list[RiskExplanation] = []

    for reason in reasons:
        reason_code = str(reason.get("code", ""))
        template = _FACTORS.get(reason_code)
        if template is None:
            continue

        factor_code = template["factor_code"]
        factor_key = factor_code.lower()
        if factor_code == "SINGLE_POINT_OF_FAILURE":
            factor_key = "single_point_of_failure"
        factor_data = factor_values.get(factor_key, {})
        contribution = float(factor_data.get("points", 0.0))
        severity = str(reason.get("severity", "LOW")).upper()

        if reason_code == "NO_2FA":
            if account is not None:
                sign_in_method = getattr(account.sign_in_method, "value", str(account.sign_in_method))
                current_value: str | int | float | bool | None = f"2FA disabled; sign-in method {sign_in_method}"
            else:
                current_value = False
            explanation = "The account's recorded two-factor authentication setting is disabled."
        elif reason_code == "PASSWORD_REUSE":
            current_value = "Recorded reuse-group association"
            explanation = "The backend records this account in a password-reuse group; this is grouping metadata, not verification of identical passwords."
        elif reason_code == "HIGH_PERMISSION":
            current_value = f"{granted_permission_count} granted permission(s)"
            explanation = f"{granted_permission_count} granted permission(s) contribute to the deterministic permission factor."
        elif reason_code == "NETWORK_EXPOSURE":
            degree = int(graph_metric.get("degree", 0))
            reachable = int(graph_metric.get("reachable_accounts", 0))
            current_value = f"{degree} direct connection(s); {reachable} reachable account(s)"
            explanation = "The exposure graph reports direct connections and reachable accounts for this account."
        elif reason_code == "BREACH":
            current_value = f"{breach_count} recorded breach event(s); severity {severity}"
            explanation = f"A breach event is recorded for this account with severity {severity}."
        elif reason_code == "INACTIVE_ACCOUNT":
            if account is not None and account.last_activity is None:
                current_value = "No activity timestamp recorded"
            elif account is not None and account.last_activity is not None:
                current_value = account.last_activity.isoformat()
            else:
                current_value = "Activity hygiene factor is elevated"
            explanation = "The deterministic activity-hygiene factor is elevated based on the account's recorded activity state."
        else:
            current_value = "Graph articulation point"
            explanation = "The exposure graph identifies this account as an articulation point."

        explanations.append(
            RiskExplanation(
                factor_code=factor_code,
                title=template["title"],
                severity=severity,
                current_value=current_value,
                explanation=explanation,
                impact=template["impact"],
                recommendation=template["recommendation"],
                priority=_priority(severity),
                related_account_id=account_id,
                related_service_id=service_id,
                reason_code=reason_code,
                risk_contribution=contribution,
            )
        )

    return sorted(
        explanations,
        key=lambda item: (item.priority, -item.risk_contribution, item.factor_code, item.reason_code or ""),
    )


def build_account_risk_explanations(account: Account, result: dict[str, Any]) -> AccountRiskExplanationResponse:
    explanations = _explanations_for_result(account.id, account.service_id, result, account)
    return AccountRiskExplanationResponse(
        account_id=account.id,
        service_id=account.service_id,
        service=account.service.name if account.service else None,
        risk_level=str(result["risk_level"]),
        risk_score=float(result["score"]),
        explanations=explanations,
        recommendations=_build_recommendations(explanations),
    )


def build_user_risk_explanations(
    user_id: str,
    summary: dict[str, Any],
    service_ids: dict[str, str] | None = None,
) -> UserRiskExplanationResponse:
    service_ids = service_ids or {}
    account_results = summary.get("account_risks", [])
    explanations: list[RiskExplanation] = []
    category_accounts: dict[str, set[str]] = defaultdict(set)
    category_contributions: dict[str, float] = defaultdict(float)
    attention: list[AccountRequiringAttention] = []

    for result in account_results:
        account_id = result["account_id"]
        service_id = service_ids.get(account_id, str(result.get("service_id", "")))
        account_explanations = _explanations_for_result(account_id, service_id, result)
        explanations.extend(account_explanations)
        active_factor_codes = sorted({item.factor_code for item in account_explanations})
        for factor_code in active_factor_codes:
            category_accounts[factor_code].add(account_id)
        for factor_key, factor_data in result.get("factors", {}).items():
            contribution = float(factor_data.get("points", 0.0))
            if contribution <= 0:
                continue
            factor_code = factor_key.upper()
            if factor_key == "single_point_of_failure":
                factor_code = "SINGLE_POINT_OF_FAILURE"
            category_contributions[factor_code] += contribution

        if str(result.get("risk_level", "LOW")).upper() != "LOW" or active_factor_codes:
            attention.append(
                AccountRequiringAttention(
                    account_id=account_id,
                    service=result.get("service_name"),
                    risk_level=str(result["risk_level"]),
                    risk_score=float(result["score"]),
                    factor_codes=active_factor_codes,
                )
            )

    explanations.sort(
        key=lambda item: (
            item.priority,
            -item.risk_contribution,
            item.factor_code,
            item.related_account_id or "",
            item.reason_code or "",
        )
    )
    attention.sort(key=lambda item: (-item.risk_score, item.account_id))

    category_summary = [
        RiskCategorySummary(
            factor_code=factor_code,
            title=_FACTOR_TITLES[factor_code],
            affected_accounts=len(category_accounts[factor_code]),
            total_contribution=round(category_contributions[factor_code], 2),
        )
        for factor_code in sorted(_FACTOR_TITLES)
    ]
    overall_exposure = float(summary["overall_exposure"])
    privacy_score = float(summary["privacy_score"])
    risk_level = _risk_level_for_score(overall_exposure)
    if account_results:
        summary_text = f"Current deterministic exposure is {risk_level.lower()} across {len(account_results)} active account(s)."
    else:
        summary_text = "No active accounts are recorded; there is no account exposure to evaluate."

    return UserRiskExplanationResponse(
        user_id=user_id,
        overall_exposure=overall_exposure,
        privacy_score=privacy_score,
        risk_level=risk_level,
        summary=summary_text,
        top_risks=explanations[:10],
        recommendations=_build_recommendations(explanations),
        accounts_requiring_attention=attention,
        category_summary=category_summary,
    )
