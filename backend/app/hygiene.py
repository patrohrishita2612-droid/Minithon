from __future__ import annotations

"""Read-only hygiene analysis using account timestamps and recorded relationships.

Account.created_at measures when the local inventory row was recorded, not
when the external service account was created. Inventory-record age uses
CURRENT under 90 days, AGING from 90 days, STALE from 180 days, and VERY_STALE
from 365 days. Activity bands reuse Step 5's 30/90/180-day thresholds and
remain UNKNOWN when last_activity is absent.
"""

from collections import Counter
from datetime import date, datetime, timezone
from typing import Any

from app.algorithms.risk_engine import RISK_CONFIG
from app.models.models import Account, AccountStatus
from app.schemas.hygiene import HygieneAccountResult, HygieneFinding, HygieneUserSummary


ACCOUNT_AGE_THRESHOLDS = {"aging": 90, "stale": 180, "very_stale": 365}
PERMISSION_REVIEW_AGE_DAYS = 180
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _enum_value(value: Any) -> str:
    return str(value.value if hasattr(value, "value") else value).upper()


def _utc_date(value: datetime | None) -> date | None:
    if value is None:
        return None
    normalized = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    return normalized.date()


def _analysis_date(value: date | None) -> date:
    return value or datetime.now(timezone.utc).date()


def _age_days(value: datetime | None, as_of: date) -> int | None:
    value_date = _utc_date(value)
    if value_date is None:
        return None
    return max(0, (as_of - value_date).days)


def _inventory_record_age_status(age_days: int | None) -> str:
    if age_days is None:
        return "UNKNOWN"
    if age_days < ACCOUNT_AGE_THRESHOLDS["aging"]:
        return "CURRENT"
    if age_days < ACCOUNT_AGE_THRESHOLDS["stale"]:
        return "AGING"
    if age_days < ACCOUNT_AGE_THRESHOLDS["very_stale"]:
        return "STALE"
    return "VERY_STALE"


def _activity_status(last_activity: datetime | None, as_of: date) -> tuple[str, int | None]:
    age = _age_days(last_activity, as_of)
    if age is None:
        return "UNKNOWN", None

    thresholds = RISK_CONFIG["hygiene"]
    if age <= thresholds["recent_days"]:
        return "ACTIVE", age
    if age <= thresholds["moderate_days"]:
        return "AGING", age
    if age <= thresholds["old_days"]:
        return "INACTIVE", age
    return "VERY_INACTIVE", age


def _sort_findings(findings: list[HygieneFinding]) -> list[HygieneFinding]:
    return sorted(
        findings,
        key=lambda item: (
            _SEVERITY_ORDER.get(item.severity, 5),
            item.finding_type,
            item.account_id,
            item.service_id,
            item.age_days if item.age_days is not None else -1,
        ),
    )


def analyze_account_hygiene(account: Account, as_of: date | None = None) -> HygieneAccountResult:
    analysis_date = _analysis_date(as_of)
    service_name = account.service.name if account.service else None
    inventory_record_created_at = getattr(account, "created_at", None)
    inventory_record_age_days = _age_days(inventory_record_created_at, analysis_date)
    inventory_record_age_status = _inventory_record_age_status(inventory_record_age_days)
    account_age_days = None
    account_age_status = "UNKNOWN"
    last_activity_date = _utc_date(account.last_activity)
    activity_status, activity_age_days = _activity_status(account.last_activity, analysis_date)
    account_status = _enum_value(account.status)
    account_is_active = bool(account.is_active)
    findings: list[HygieneFinding] = []

    def add_finding(
        finding_type: str,
        severity: str,
        title: str,
        description: str,
        evidence: list[str],
        recommended_action: str,
        age: int | None,
    ) -> None:
        findings.append(
            HygieneFinding(
                account_id=account.id,
                service_id=account.service_id,
                service_name=service_name,
                finding_type=finding_type,
                severity=severity,
                title=title,
                description=description,
                evidence=evidence,
                recommended_action=recommended_action,
                age_days=age,
                confidence="HIGH",
            )
        )

    if inventory_record_age_status in {"STALE", "VERY_STALE"} and inventory_record_age_days is not None:
        age_severity = "MEDIUM" if inventory_record_age_status == "VERY_STALE" else "LOW"
        add_finding(
            "INVENTORY_RECORD_STALE",
            age_severity,
            "Account inventory record is old",
            "The local inventory record is old; this does not establish when the external service account was created or whether it is inactive.",
            [f"Inventory record date is {_utc_date(inventory_record_created_at).isoformat()}; record age is {inventory_record_age_days} days as of {analysis_date.isoformat()}."],
            "Verify the account's current status with a trusted service source and review whether this inventory entry is still accurate.",
            inventory_record_age_days,
        )

    if activity_status == "UNKNOWN":
        add_finding(
            "ACTIVITY_UNKNOWN",
            "LOW",
            "Activity information is unavailable",
            "No last_activity timestamp is stored, so this engine cannot classify recent activity or inactivity.",
            ["No last_activity timestamp is recorded for this account."],
            "Confirm recent activity through a trusted service source; no local activity timestamp is available.",
            None,
        )
    elif activity_status in {"INACTIVE", "VERY_INACTIVE"} and activity_age_days is not None:
        finding_type = "ACCOUNT_VERY_INACTIVE" if activity_status == "VERY_INACTIVE" else "ACCOUNT_INACTIVE"
        severity = "HIGH" if finding_type == "ACCOUNT_VERY_INACTIVE" else "MEDIUM"
        add_finding(
            finding_type,
            severity,
            "Account activity is very old" if finding_type == "ACCOUNT_VERY_INACTIVE" else "Account has no recent activity",
            f"The recorded last activity is {activity_age_days} days before the analysis date.",
            [f"Last activity date is {last_activity_date.isoformat()}; age is {activity_age_days} days as of {analysis_date.isoformat()}."],
            "Review whether this account is still needed; deactivate or remove it only if it is no longer required.",
            activity_age_days,
        )

    status_marked_inactive = account_status == AccountStatus.INACTIVE.value or (
        not account_is_active and account_status != AccountStatus.DELETED.value
    )
    if status_marked_inactive and activity_status not in {"INACTIVE", "VERY_INACTIVE"}:
        add_finding(
            "ACCOUNT_INACTIVE",
            "MEDIUM",
            "Account is marked inactive",
            "The stored account status indicates inactivity; this is separate from timestamp-based activity classification.",
                [f"Stored status is {account_status}; is_active is {str(account_is_active).lower()}."],
            "Confirm whether the stored status is current and review any remaining access or permissions.",
            None,
        )

    stale_activity = activity_status in {"INACTIVE", "VERY_INACTIVE"} or status_marked_inactive
    granted_permissions = [permission for permission in account.permissions if permission.granted]
    old_review_ages = [
        age
        for permission in granted_permissions
        if (age := _age_days(permission.last_reviewed_at, analysis_date)) is not None
        and age > PERMISSION_REVIEW_AGE_DAYS
    ]
    if granted_permissions and (stale_activity or old_review_ages):
        evidence = []
        if stale_activity:
            evidence.append(
                f"{len(granted_permissions)} granted permission(s) are attached to an account with stale activity or an inactive stored status."
            )
        if old_review_ages:
            evidence.append(
                f"{len(old_review_ages)} granted permission(s) have recorded review dates older than {PERMISSION_REVIEW_AGE_DAYS} days."
            )
        permission_age = max(old_review_ages, default=activity_age_days if stale_activity else None)
        add_finding(
            "PERMISSION_REVIEW_REQUIRED",
                "MEDIUM" if stale_activity else "LOW",
            "Granted permissions need review",
            "The database records granted permissions but does not record permission-use telemetry; this finding does not label them unused or excessive.",
            evidence,
            "Review the granted permissions and retain only those still required.",
            permission_age,
        )

    breach_events = list(account.breach_events)
    if breach_events and activity_status in {"INACTIVE", "VERY_INACTIVE"} and activity_age_days is not None:
        breach_severities = [_enum_value(event.severity) for event in breach_events]
        severity = min(breach_severities, key=lambda value: _SEVERITY_ORDER.get(value, 5))
        add_finding(
            "BREACHED_STALE_ACCOUNT",
            severity,
            "Recorded breach and stale activity require review",
            "This finding combines an account-linked breach record with old recorded activity; it does not indicate current compromise.",
            [
                f"{len(breach_events)} account-linked breach event(s) are recorded.",
                f"Last activity date is {last_activity_date.isoformat()}; age is {activity_age_days} days as of {analysis_date.isoformat()}.",
            ],
            "Review the breach information and account usage; change credentials only when supported by the event or service guidance, and consider closing the account only if it is no longer needed.",
            activity_age_days,
        )

    return HygieneAccountResult(
        account_id=account.id,
        service_id=account.service_id,
        service_name=service_name,
        account_status=account_status,
        is_active=account_is_active,
        analysis_date=analysis_date,
        account_age_days=account_age_days,
        account_age_status=account_age_status,
        inventory_record_age_days=inventory_record_age_days,
        inventory_record_age_status=inventory_record_age_status,
        activity_status=activity_status,
        last_activity_date=last_activity_date,
        findings=_sort_findings(findings),
    )


def analyze_user_hygiene(
    user_id: str,
    accounts: list[Account],
    as_of: date | None = None,
) -> HygieneUserSummary:
    analysis_date = _analysis_date(as_of)
    results = [analyze_account_hygiene(account, analysis_date) for account in accounts]
    results.sort(key=lambda item: (item.account_age_days if item.account_age_days is not None else -1, item.account_id))
    findings = _sort_findings([finding for result in results for finding in result.findings])
    review_account_ids = {finding.account_id for finding in findings}

    return HygieneUserSummary(
        user_id=user_id,
        analysis_date=analysis_date,
        total_accounts=len(results),
        active_accounts=sum(
            result.activity_status == "ACTIVE" and result.account_status == "ACTIVE" and result.is_active
            for result in results
        ),
        aging_accounts=sum(result.activity_status == "AGING" for result in results),
        stale_accounts=sum(result.activity_status == "VERY_INACTIVE" for result in results),
        stale_inventory_records=sum(result.inventory_record_age_status in {"STALE", "VERY_STALE"} for result in results),
        inactive_accounts=sum(
            result.activity_status in {"INACTIVE", "VERY_INACTIVE"}
            or result.account_status == AccountStatus.INACTIVE.value
            or (not result.is_active and result.account_status != AccountStatus.DELETED.value)
            for result in results
        ),
        unknown_activity_accounts=sum(result.activity_status == "UNKNOWN" for result in results),
        accounts_requiring_review=len(review_account_ids),
        accounts=results,
        findings=findings,
    )