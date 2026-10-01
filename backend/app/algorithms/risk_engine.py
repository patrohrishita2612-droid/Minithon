from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.algorithms.exposure_graph import build_exposure_graph
from app.models.models import (
    Account,
    AccountStatus,
    AppPermission,
    BreachEvent,
    FixItem,
    PermissionSensitivity,
    RiskFactor,
    RiskFactorType,
    RiskLevel,
    RiskSnapshot,
    Severity,
    SignInMethod,
    User,
)

RISK_CONFIG: dict[str, Any] = {
    "score_bounds": {"min": 0, "max": 100},
    "risk_thresholds": {"LOW": 24, "MEDIUM": 49, "HIGH": 74},
    "weights": {
        "AUTHENTICATION": 15,
        "PASSWORD_REUSE": 15,
        "PERMISSIONS": 20,
        "NETWORK": 20,
        "BREACH": 15,
        "HYGIENE": 5,
        "SINGLE_POINT_OF_FAILURE": 10,
    },
    "permission_sensitivity": {
        "LOW": 1,
        "MEDIUM": 3,
        "HIGH": 5,
        "CRITICAL": 7,
    },
    "breach_severity": {
        "LOW": 10,
        "MEDIUM": 20,
        "HIGH": 35,
        "CRITICAL": 50,
    },
    "hygiene": {
        "recent_days": 30,
        "moderate_days": 90,
        "old_days": 180,
    },
    "network": {"max_degree_factor": 10.0, "max_reach_factor": 10.0},
    "reuse_group": {"cutoff": 3},
}


def clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def _enum_value(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _default_now() -> datetime:
    return datetime.now(timezone.utc)


def _risk_level_for_score(score: float) -> str:
    thresholds = RISK_CONFIG["risk_thresholds"]
    if score <= thresholds["LOW"]:
        return RiskLevel.LOW.value
    if score <= thresholds["MEDIUM"]:
        return RiskLevel.MEDIUM.value
    if score <= thresholds["HIGH"]:
        return RiskLevel.HIGH.value
    return RiskLevel.CRITICAL.value


def _normalize_to_unit(value: float, ceiling: float) -> float:
    if ceiling <= 0:
        return 0.0
    return clamp(value / ceiling, 0.0, 1.0)


def _safe_days_since(value: datetime | None, now: datetime) -> int:
    if value is None:
        return 3650
    return max(0, (now - value.astimezone(timezone.utc)).days)


def _get_user_accounts(db: Session, user_id: str) -> list[Account]:
    return db.scalars(
        select(Account)
        .where(Account.user_id == user_id)
        .options(selectinload(Account.service), selectinload(Account.permissions), selectinload(Account.breach_events))
        .order_by(Account.created_at.asc(), Account.id.asc())
    ).all()


def _build_group_counts(accounts: list[Account]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for account in accounts:
        if account.password_reuse_group_id:
            counts[account.password_reuse_group_id] += 1
    return counts


def _build_graph_metrics(db: Session, user_id: str) -> dict[str, dict[str, Any]]:
    graph = build_exposure_graph(db, user_id)
    return {item["account_id"]: item for item in graph.get("structural_metrics", [])}


def _build_reason(code: str, severity: str, message: str) -> dict[str, str]:
    return {"code": code, "severity": severity, "message": message}


def calculate_account_risk(
    db: Session,
    account: Account,
    user_accounts: list[Account] | None = None,
    graph_metrics: dict[str, dict[str, Any]] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or _default_now()
    if user_accounts is None:
        user_accounts = _get_user_accounts(db, account.user_id)
    if graph_metrics is None:
        graph_metrics = _build_graph_metrics(db, account.user_id)

    total_accounts = len(user_accounts)
    group_counts = _build_group_counts(user_accounts)
    graph_metric = graph_metrics.get(account.id, {})
    permissions = [permission for permission in account.permissions if permission.granted]

    reasons: list[dict[str, str]] = []
    factor_points: dict[str, float] = {}
    factors: dict[str, dict[str, float]] = {}

    # Authentication protection
    if account.two_factor_enabled:
        auth_norm = 0.0
    else:
        auth_norm = 1.0 if account.sign_in_method == SignInMethod.PASSWORD else 0.75
        reasons.append(_build_reason("NO_2FA", "HIGH", "Two-factor authentication is disabled."))
    auth_points = RISK_CONFIG["weights"]["AUTHENTICATION"] * auth_norm
    factor_points["authentication"] = auth_points
    factors["authentication"] = {"normalized": round(auth_norm, 4), "points": round(auth_points, 4)}

    # Password reuse
    reuse_group = account.password_reuse_group_id
    reuse_norm = 0.0
    reuse_group_size = 0
    if reuse_group:
        reuse_group_size = group_counts.get(reuse_group, 0)
        if reuse_group_size > 1:
            reuse_norm = min(1.0, max(0.0, (reuse_group_size - 1) / float(RISK_CONFIG["reuse_group"]["cutoff"])))
            reasons.append(
                _build_reason(
                    "PASSWORD_REUSE",
                    "HIGH" if reuse_group_size >= 3 else "MEDIUM",
                    f"Password reuse connects this account to {reuse_group_size - 1} other accounts.",
                )
            )
    reuse_points = RISK_CONFIG["weights"]["PASSWORD_REUSE"] * reuse_norm
    factor_points["password_reuse"] = reuse_points
    factors["password_reuse"] = {"normalized": round(reuse_norm, 4), "points": round(reuse_points, 4)}

    # Permissions
    permission_total = sum(RISK_CONFIG["permission_sensitivity"].get(_enum_value(permission.sensitivity), 1) for permission in permissions)
    permission_norm = _normalize_to_unit(permission_total, 20.0)
    permission_points = RISK_CONFIG["weights"]["PERMISSIONS"] * permission_norm
    if permission_total > 0:
        reasons.append(
            _build_reason(
                "HIGH_PERMISSION",
                "MEDIUM" if permission_total < 10 else "HIGH",
                f"Granted permissions sum to {permission_total} sensitivity points across {len(permissions)} active permissions.",
            )
        )
    factor_points["permissions"] = permission_points
    factors["permissions"] = {"normalized": round(permission_norm, 4), "points": round(permission_points, 4)}

    # Network exposure
    max_degree = max((metric.get("degree", 0) for metric in graph_metrics.values()), default=0)
    max_reach = max((metric.get("reachable_accounts", 0) for metric in graph_metrics.values()), default=0)
    degree = int(graph_metric.get("degree", 0))
    reachable = int(graph_metric.get("reachable_accounts", 0))
    degree_norm = _normalize_to_unit(degree, max_degree) if max_degree else 0.0
    reach_norm = _normalize_to_unit(reachable, max_reach) if max_reach else 0.0
    network_norm = clamp((degree_norm + reach_norm) / 2.0, 0.0, 1.0)
    network_points = RISK_CONFIG["weights"]["NETWORK"] * network_norm
    if network_norm > 0:
        reasons.append(
            _build_reason(
                "NETWORK_EXPOSURE",
                "MEDIUM" if network_norm < 0.7 else "HIGH",
                f"This account is connected to {degree} other accounts and can reach {reachable} accounts through the exposure graph.",
            )
        )
    factor_points["network"] = network_points
    factors["network"] = {"normalized": round(network_norm, 4), "points": round(network_points, 4)}

    # Breach exposure
    breach_events = sorted(
        (event for event in account.breach_events if event is not None),
        key=lambda event: event.id,
    )
    breach_norm = 0.0
    breach_points = 0.0
    if breach_events:
        total_breach_weight = 0.0
        for event in breach_events:
            severity_weight = RISK_CONFIG["breach_severity"].get(_enum_value(event.severity), 20)
            if event.breach_date:
                days_since = _safe_days_since(event.breach_date, now)
                recency_factor = 1.0 if days_since <= 365 else 0.7 if days_since <= 1825 else 0.5
            else:
                recency_factor = 1.0
            total_breach_weight += severity_weight * recency_factor
        breach_norm = _normalize_to_unit(total_breach_weight, 80.0)
        breach_points = RISK_CONFIG["weights"]["BREACH"] * breach_norm
        for event in breach_events:
            reasons.append(
                _build_reason(
                    "BREACH",
                    _enum_value(event.severity),
                    "A known breach event is recorded for this account.",
                )
            )
    factor_points["breach"] = breach_points
    factors["breach"] = {"normalized": round(breach_norm, 4), "points": round(breach_points, 4)}

    # Hygiene / activity
    days_since_activity = _safe_days_since(account.last_activity, now)
    if getattr(account, "status", None) == AccountStatus.INACTIVE or not getattr(account, "is_active", True):
        hygiene_norm = 1.0
    elif days_since_activity <= RISK_CONFIG["hygiene"]["recent_days"]:
        hygiene_norm = 0.0
    elif days_since_activity <= RISK_CONFIG["hygiene"]["moderate_days"]:
        hygiene_norm = 0.35
    elif days_since_activity <= RISK_CONFIG["hygiene"]["old_days"]:
        hygiene_norm = 0.7
    else:
        hygiene_norm = 1.0
    hygiene_points = RISK_CONFIG["weights"]["HYGIENE"] * hygiene_norm
    if hygiene_norm > 0:
        reasons.append(
            _build_reason(
                "INACTIVE_ACCOUNT",
                "MEDIUM" if hygiene_norm < 0.7 else "HIGH",
                f"This account has been inactive for {days_since_activity} days and may have been forgotten.",
            )
        )
    factor_points["hygiene"] = hygiene_points
    factors["hygiene"] = {"normalized": round(hygiene_norm, 4), "points": round(hygiene_points, 4)}

    # Single point of failure exposure
    is_articulation = bool(graph_metric.get("is_articulation_point", False))
    spof_norm = 1.0 if is_articulation else 0.0
    spof_points = RISK_CONFIG["weights"]["SINGLE_POINT_OF_FAILURE"] * spof_norm
    if is_articulation:
        reasons.append(
            _build_reason(
                "SPOF",
                "HIGH",
                "This account is a structural single point of failure in the exposure graph.",
            )
        )
    factor_points["single_point_of_failure"] = spof_points
    factors["single_point_of_failure"] = {"normalized": round(spof_norm, 4), "points": round(spof_points, 4)}

    total_score = clamp(sum(factor_points.values()), 0.0, 100.0)
    risk_level = _risk_level_for_score(total_score)

    unique_reasons: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for reason in reasons:
        key = (reason["code"], reason["message"])
        if key in seen:
            continue
        seen.add(key)
        unique_reasons.append(reason)

    return {
        "account_id": account.id,
        "service_name": account.service.name if account.service else None,
        "score": round(total_score, 2),
        "risk_level": risk_level,
        "factors": factors,
        "reasons": unique_reasons,
        "graph_metric": graph_metric,
    }


def _top_reasons(reasons: list[dict[str, str]], limit: int = 3) -> list[dict[str, str]]:
    return reasons[:limit]


def calculate_user_risk_summary(db: Session, user_id: str, limit: int = 5, now: datetime | None = None) -> dict[str, Any]:
    user = db.get(User, user_id)
    if not user:
        raise ValueError("USER_NOT_FOUND")

    now = now or _default_now()
    accounts = _get_user_accounts(db, user_id)
    graph_metrics = _build_graph_metrics(db, user_id)
    results = [calculate_account_risk(db, account, accounts, graph_metrics, now) for account in accounts if account.is_active]
    sorted_results = sorted(results, key=lambda item: (-item["score"], item["account_id"]))

    exposure_average = sum(item["score"] for item in sorted_results) / len(sorted_results) if sorted_results else 0.0
    total_exposure = exposure_average
    high_risk_penalty = sum(max(0.0, item["score"] - 74.0) for item in sorted_results) / max(1, len(sorted_results)) * 0.2
    spof_penalty = (sum(1 for item in sorted_results if item["factors"]["single_point_of_failure"]["normalized"] > 0) / max(1, len(sorted_results))) * 12.0
    overall_exposure = clamp(total_exposure + high_risk_penalty + spof_penalty, 0.0, 100.0)
    privacy_score = clamp(100.0 - overall_exposure, 0.0, 100.0)

    distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for item in sorted_results:
        risk_level = item["risk_level"].lower()
        if risk_level == "low":
            distribution["low"] += 1
        elif risk_level == "medium":
            distribution["medium"] += 1
        elif risk_level == "high":
            distribution["high"] += 1
        else:
            distribution["critical"] += 1

    top_accounts = []
    for item in sorted_results[:limit]:
        top_accounts.append(
            {
                "account_id": item["account_id"],
                "service": item["service_name"],
                "score": item["score"],
                "risk_level": item["risk_level"],
                "top_reasons": _top_reasons(item["reasons"]),
            }
        )

    single_points = [
        {
            "account_id": item["account_id"],
            "service": item["service_name"],
            "score": item["score"],
            "risk_level": item["risk_level"],
            "reason": next((reason for reason in item["reasons"] if reason["code"] == "SPOF"), None),
        }
        for item in sorted_results
        if item["factors"]["single_point_of_failure"]["normalized"] > 0
    ]

    return {
        "user_id": user_id,
        "privacy_score": round(privacy_score, 2),
        "overall_privacy_score": round(privacy_score, 2),
        "average_exposure": round(exposure_average, 2),
        "overall_exposure": round(overall_exposure, 2),
        "risk_distribution": distribution,
        "top_risk_accounts": top_accounts,
        "single_points_of_failure": single_points,
        "risk_ranking": [
            {
                "account_id": item["account_id"],
                "score": item["score"],
                "risk_level": item["risk_level"],
                "factors": item["factors"],
                "reasons": item["reasons"],
            }
            for item in sorted_results
        ],
        "account_risks": sorted_results,
        "last_calculated_at": now.isoformat(),
    }


def persist_risk_factors(db: Session, user_id: str, account_results: list[dict[str, Any]]) -> None:
    account_ids = [result["account_id"] for result in account_results]
    if account_ids:
        existing = db.scalars(select(RiskFactor).where(RiskFactor.account_id.in_(account_ids))).all()
        for item in existing:
            db.delete(item)

    for result in account_results:
        for factor_name, values in result["factors"].items():
            if values["points"] <= 0:
                continue
            if factor_name == "authentication":
                factor_type = RiskFactorType.NO_2FA
            elif factor_name == "password_reuse":
                factor_type = RiskFactorType.PASSWORD_REUSE
            elif factor_name == "permissions":
                factor_type = RiskFactorType.HIGH_PERMISSION
            elif factor_name == "network":
                factor_type = RiskFactorType.RECOVERY_CENTRALITY
            elif factor_name == "breach":
                factor_type = RiskFactorType.BREACH
            elif factor_name == "hygiene":
                factor_type = RiskFactorType.INACTIVE_ACCOUNT
            elif factor_name == "single_point_of_failure":
                factor_type = RiskFactorType.RECOVERY_CENTRALITY
            else:
                factor_type = RiskFactorType.OTHER

            severity = Severity.MEDIUM
            if values["normalized"] >= 0.75:
                severity = Severity.HIGH
            elif values["normalized"] >= 0.4:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            db.add(
                RiskFactor(
                    account_id=result["account_id"],
                    factor_type=factor_type,
                    severity=severity,
                    weight=int(round(values["points"])),
                    description=result["reasons"][0]["message"] if result["reasons"] else None,
                )
            )
    db.commit()


def persist_risk_snapshot(db: Session, user_id: str, summary: dict[str, Any], now: datetime | None = None) -> RiskSnapshot:
    now = now or _default_now()
    risk_level = _risk_level_for_score(100.0 - float(summary["overall_privacy_score"]))
    snapshot = RiskSnapshot(
        user_id=user_id,
        overall_score=int(round(summary["overall_privacy_score"])),
        risk_level=RiskLevel(risk_level),
        total_accounts=len(summary.get("account_risks", [])),
        high_risk_accounts=sum(1 for item in summary.get("account_risks", []) if item["score"] >= 50.0),
        critical_accounts=sum(1 for item in summary.get("account_risks", []) if item["risk_level"] == RiskLevel.CRITICAL.value),
        open_fix_count=0,
        single_point_count=len(summary.get("single_points_of_failure", [])),
        snapshot_date=now,
    )
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return snapshot


def calculate_and_persist_user_risk(db: Session, user_id: str, limit: int = 5, now: datetime | None = None) -> dict[str, Any]:
    now = now or _default_now()
    user = db.get(User, user_id)
    if not user:
        raise ValueError("USER_NOT_FOUND")

    accounts = _get_user_accounts(db, user_id)
    graph_metrics = _build_graph_metrics(db, user_id)
    results = [calculate_account_risk(db, account, accounts, graph_metrics, now) for account in accounts if account.is_active]
    summary = calculate_user_risk_summary(db, user_id, limit=limit, now=now)
    persist_risk_factors(db, user_id, results)
    snapshot = persist_risk_snapshot(db, user_id, summary, now)
    summary["snapshot_id"] = snapshot.id
    summary["snapshot_date"] = snapshot.snapshot_date.isoformat()
    summary["last_calculated_at"] = snapshot.snapshot_date.isoformat()
    summary["risk_ranking"] = [
        {
            "account_id": item["account_id"],
            "score": item["score"],
            "risk_level": item["risk_level"],
            "factors": item["factors"],
            "reasons": item["reasons"],
        }
        for item in sorted(results, key=lambda value: (-value["score"], value["account_id"]))
    ]
    return summary
