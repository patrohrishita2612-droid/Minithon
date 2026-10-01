from __future__ import annotations

import hashlib
from datetime import date, datetime, time, timezone
from typing import Any

from app.hygiene import analyze_account_hygiene
from app.models.models import Account, BreachEvent, Notification
from app.schemas.hygiene import HygieneAccountResult, HygieneFinding
from app.schemas.notifications import NotificationItem
from app.schemas.remediation import RemediationItem
from app.schemas.risk_explanations import RiskExplanation


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_REMEDIATION_ALERT_PRIORITIES = {"CRITICAL", "HIGH"}


def _enum_value(value: Any) -> str:
    return str(value.value if hasattr(value, "value") else value).upper()


def _candidate_key(user_id: str, account_id: str, notification_type: str, reason_code: str, source_id: str = "") -> str:
    identity = "|".join((user_id, account_id, notification_type, reason_code, source_id))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _make_candidate(
    *,
    user_id: str,
    account: Account,
    notification_type: str,
    title: str,
    severity: str,
    reason_code: str,
    explanation: str,
    recommended_action: str,
    evidence: list[str],
    risk_contribution: float | None = None,
    observed_at: datetime | None = None,
    source_id: str = "",
) -> NotificationItem:
    return NotificationItem(
        candidate_key=_candidate_key(user_id, account.id, notification_type, reason_code, source_id),
        type=notification_type,
        title=title,
        severity=severity.upper(),
        account_id=account.id,
        breach_event_id=source_id if notification_type == "BREACH_ALERT" else None,
        service_id=account.service_id,
        service_name=account.service.name if account.service else None,
        reason_code=reason_code,
        explanation=explanation,
        recommended_action=recommended_action,
        evidence=sorted(set(evidence)),
        risk_contribution=risk_contribution,
        observed_at=observed_at,
        is_read=False,
    )


def _risk_candidates(
    user_id: str,
    accounts_by_id: dict[str, Account],
    account_results: list[dict[str, Any]],
) -> list[NotificationItem]:
    candidates: list[NotificationItem] = []
    for result in account_results:
        account = accounts_by_id.get(result["account_id"])
        if account is None:
            continue
        risk_level = str(result["risk_level"]).upper()
        factors = result.get("factors", {})
        reasons = result.get("reasons", [])
        if risk_level in {"CRITICAL", "HIGH"}:
            notification_type = f"{risk_level}_RISK_ALERT"
            evidence = [
                str(reason.get("code", ""))
                for reason in reasons
                if reason.get("code")
            ]
            contribution = round(float(result.get("score", 0.0)), 2)
            candidates.append(
                _make_candidate(
                    user_id=user_id,
                    account=account,
                    notification_type=notification_type,
                    title=f"{risk_level.title()} privacy risk finding",
                    severity=risk_level,
                    reason_code="ACCOUNT_RISK_LEVEL",
                    explanation=f"The existing deterministic risk engine classifies this account as {risk_level.lower()} risk.",
                    recommended_action="Review the account's recorded risk factors and address the highest-priority supported findings.",
                    evidence=evidence or [f"Risk level: {risk_level}"],
                    risk_contribution=contribution,
                )
            )

        spof = factors.get("single_point_of_failure", {})
        if float(spof.get("normalized", 0.0)) > 0 and any(reason.get("code") == "SPOF" for reason in reasons):
            candidates.append(
                _make_candidate(
                    user_id=user_id,
                    account=account,
                    notification_type="STRUCTURAL_RISK_ALERT",
                    title="Structural single point of failure identified",
                    severity="HIGH",
                    reason_code="SPOF",
                    explanation="The exposure graph identifies this account as an articulation point in the user's account network.",
                    recommended_action="Review dependent accounts and consider independent recovery or sign-in paths where supported.",
                    evidence=["The deterministic exposure graph reports this account as an articulation point."],
                    risk_contribution=float(spof.get("points", 0.0)),
                )
            )
    return candidates


def _breach_candidates(user_id: str, accounts: list[Account]) -> list[NotificationItem]:
    candidates = []
    for account in accounts:
        for event in account.breach_events:
            if event.account_id != account.id:
                continue
            severity = _enum_value(event.severity)
            observed_at = event.breach_date or event.created_at
            candidates.append(
                _make_candidate(
                    user_id=user_id,
                    account=account,
                    notification_type="BREACH_ALERT",
                    title="Breach event recorded",
                    severity=severity,
                    reason_code="BREACH",
                    explanation="A breach event is recorded for this account; this does not indicate current compromise.",
                    recommended_action="Review the account and breach information; follow the service's guidance for affected credentials and authentication.",
                    evidence=[f"An account-linked breach event with {severity.lower()} severity is recorded."],
                    observed_at=observed_at,
                    source_id=event.id,
                )
            )
    return candidates


def _hygiene_candidates(user_id: str, accounts: list[Account], as_of: date) -> list[NotificationItem]:
    candidates: list[NotificationItem] = []
    for account in accounts:
        hygiene = analyze_account_hygiene(account, as_of)
        for finding in hygiene.findings:
            notification_type: str | None = None
            if finding.finding_type == "BREACHED_STALE_ACCOUNT":
                notification_type = "STALE_ACCOUNT_ALERT"
            elif finding.finding_type in {"ACCOUNT_INACTIVE", "ACCOUNT_VERY_INACTIVE"}:
                notification_type = "STALE_ACCOUNT_ALERT"
            elif finding.finding_type == "PERMISSION_REVIEW_REQUIRED":
                notification_type = "PERMISSION_REVIEW_ALERT"
            if notification_type is None:
                continue

            candidates.append(
                _make_candidate(
                    user_id=user_id,
                    account=account,
                    notification_type=notification_type,
                    title=finding.title,
                    severity=finding.severity,
                    reason_code=finding.finding_type,
                    explanation=finding.description,
                    recommended_action=finding.recommended_action,
                    evidence=finding.evidence,
                )
            )
    return candidates


def _remediation_candidates(
    user_id: str,
    accounts_by_id: dict[str, Account],
    remediation_items: list[RemediationItem],
) -> list[NotificationItem]:
    candidates = []
    for item in remediation_items:
        if item.priority.upper() not in _REMEDIATION_ALERT_PRIORITIES:
            continue
        for account_id in item.account_ids:
            account = accounts_by_id.get(account_id)
            if account is None:
                continue
            reason_code = item.reason_code or (item.reason_codes[0] if item.reason_codes else "REMEDIATION")
            candidates.append(
                _make_candidate(
                    user_id=user_id,
                    account=account,
                    notification_type="REMEDIATION_ALERT",
                    title=item.title,
                    severity=item.priority,
                    reason_code=reason_code,
                    explanation=item.description,
                    recommended_action=item.action,
                    evidence=item.evidence,
                    risk_contribution=item.risk_contribution,
                )
            )
    return candidates


def _merge_persisted_metadata(
    candidates: list[NotificationItem],
    persisted: list[Notification],
) -> list[NotificationItem]:
    unused_persisted = list(persisted)
    merged = []
    for candidate in candidates:
        match_index = next(
            (
                index
                for index, notification in enumerate(unused_persisted)
                if notification.account_id == candidate.account_id
                and notification.type.value == candidate.type
                and notification.title == candidate.title
                and notification.breach_event_id == candidate.breach_event_id
            ),
            None,
        )
        if match_index is None:
            merged.append(candidate)
            continue
        notification = unused_persisted.pop(match_index)
        merged.append(
            candidate.model_copy(
                update={
                    "notification_id": notification.id,
                    "created_at": notification.created_at,
                    "is_read": notification.is_read,
                }
            )
        )
    return merged


def build_notifications(
    user_id: str,
    accounts: list[Account],
    account_results: list[dict[str, Any]],
    remediation_items: list[RemediationItem],
    persisted: list[Notification] | None = None,
    as_of: date | None = None,
) -> list[NotificationItem]:
    analysis_date = as_of or datetime.now(timezone.utc).date()
    accounts_by_id = {account.id: account for account in accounts}
    candidates = [
        *_breach_candidates(user_id, accounts),
        *_risk_candidates(user_id, accounts_by_id, account_results),
        *_hygiene_candidates(user_id, accounts, analysis_date),
        *_remediation_candidates(user_id, accounts_by_id, remediation_items),
    ]
    unique: dict[str, NotificationItem] = {}
    for candidate in candidates:
        unique.setdefault(candidate.candidate_key, candidate)
    merged = _merge_persisted_metadata(list(unique.values()), persisted or [])
    return sorted(
        merged,
        key=lambda item: (
            _SEVERITY_ORDER.get(item.severity, 5),
            -(item.risk_contribution or 0.0),
            item.type,
            item.account_id,
            item.service_id,
            item.reason_code,
            item.candidate_key,
        ),
    )


def build_notification_counts(notifications: list[NotificationItem]) -> dict[str, int]:
    return {
        "total": len(notifications),
        "critical": sum(item.severity == "CRITICAL" for item in notifications),
        "high": sum(item.severity == "HIGH" for item in notifications),
        "medium": sum(item.severity == "MEDIUM" for item in notifications),
        "low": sum(item.severity == "LOW" for item in notifications),
        "unread": sum(not item.is_read for item in notifications),
    }


def candidates_for_account(
    user_id: str,
    account: Account,
    risk_result: dict[str, Any],
    remediation_items: list[RemediationItem],
    persisted: list[Notification] | None = None,
    as_of: date | None = None,
) -> list[NotificationItem]:
    return build_notifications(
        user_id=user_id,
        accounts=[account],
        account_results=[risk_result],
        remediation_items=remediation_items,
        persisted=persisted,
        as_of=as_of,
    )