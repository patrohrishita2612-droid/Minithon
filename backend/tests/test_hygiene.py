from __future__ import annotations

import json
from datetime import date, datetime, time, timedelta, timezone
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.database.database import SessionLocal
from app.main import app
from app.models.models import (
    Account,
    AppPermission,
    BreachEvent,
    FixItem,
    Notification,
    Reminder,
    RiskFactor,
    RiskSnapshot,
    Severity,
)


client = TestClient(app)
AS_OF = date(2026, 10, 1)


def _create_user() -> str:
    suffix = uuid4().hex
    response = client.post("/api/users", json={"name": "Hygiene User", "email": f"hygiene-{suffix}@example.com"})
    assert response.status_code == 200
    return response.json()["data"]["id"]


def _create_service() -> str:
    suffix = uuid4().hex
    response = client.post(
        "/api/services",
        json={"name": f"Hygiene Service {suffix}", "category": "PRODUCTIVITY", "website": "https://example.com"},
    )
    assert response.status_code == 200
    return response.json()["data"]["id"]


def _create_account(user_id: str, service_id: str, **overrides: object) -> str:
    payload: dict[str, object] = {
        "user_id": user_id,
        "service_id": service_id,
        "account_identifier": f"private-{uuid4().hex}@example.com",
        "display_name": "Private account name",
        "status": "ACTIVE",
        "sign_in_method": "PASSWORD",
        "two_factor_enabled": False,
        "password_reuse_group_id": None,
        "password_strength": "MEDIUM",
        "last_activity": "2026-09-30T00:00:00Z",
        "is_active": True,
    }
    payload.update(overrides)
    response = client.post("/api/accounts", json=payload)
    assert response.status_code == 200
    return response.json()["data"]["id"]


def _set_dates(account_id: str, created_days_ago: int, activity_days_ago: int | None) -> None:
    with SessionLocal() as db:
        account = db.get(Account, account_id)
        assert account is not None
        account.created_at = datetime.combine(AS_OF - timedelta(days=created_days_ago), time.min, tzinfo=timezone.utc)
        account.last_activity = (
            datetime.combine(AS_OF - timedelta(days=activity_days_ago), time.min, tzinfo=timezone.utc)
            if activity_days_ago is not None
            else None
        )
        db.commit()


def _count_for_user(model: type, user_id: str) -> int:
    with SessionLocal() as db:
        return int(db.scalar(select(func.count()).select_from(model).where(model.user_id == user_id)) or 0)


def _count_risk_factors_for_user(user_id: str) -> int:
    with SessionLocal() as db:
        statement = select(func.count(RiskFactor.id)).join(Account).where(Account.user_id == user_id)
        return int(db.scalar(statement) or 0)


def test_hygiene_routes_return_structured_data_and_openapi_paths() -> None:
    user_id = _create_user()
    service_id = _create_service()
    account_id = _create_account(user_id, service_id)

    user_response = client.get(f"/api/users/{user_id}/hygiene?as_of={AS_OF.isoformat()}")
    account_response = client.get(f"/api/accounts/{account_id}/hygiene?as_of={AS_OF.isoformat()}")
    assert user_response.status_code == 200
    assert user_response.json()["data"]["total_accounts"] == 1
    assert account_response.status_code == 200
    assert account_response.json()["data"]["service_id"] == service_id
    paths = client.get("/openapi.json").json()["paths"]
    assert "/api/users/{user_id}/hygiene" in paths
    assert "/api/accounts/{account_id}/hygiene" in paths
    assert client.get("/health").status_code == 200


def test_missing_user_and_account_use_existing_404_contract() -> None:
    user_response = client.get("/api/users/missing-user/hygiene")
    account_response = client.get("/api/accounts/missing-account/hygiene")
    assert user_response.status_code == 404
    assert user_response.json()["error"]["code"] == "USER_NOT_FOUND"
    assert account_response.status_code == 404
    assert account_response.json()["error"]["code"] == "ACCOUNT_NOT_FOUND"


def test_empty_user_and_user_isolation() -> None:
    user_id = _create_user()
    empty = client.get(f"/api/users/{user_id}/hygiene?as_of={AS_OF.isoformat()}").json()["data"]
    assert empty["total_accounts"] == 0
    assert empty["accounts"] == []
    assert empty["findings"] == []

    service_id = _create_service()
    own_account = _create_account(user_id, service_id)
    other_user_id = _create_user()
    other_account = _create_account(other_user_id, _create_service())
    data = client.get(f"/api/users/{user_id}/hygiene?as_of={AS_OF.isoformat()}").json()["data"]
    included_ids = {account["account_id"] for account in data["accounts"]}
    assert own_account in included_ids
    assert other_account not in included_ids


def test_inventory_record_age_is_not_claimed_as_external_account_age() -> None:
    user_id = _create_user()
    service_id = _create_service()
    ages_and_statuses = {
        89: "CURRENT",
        90: "AGING",
        179: "AGING",
        180: "STALE",
        364: "STALE",
        365: "VERY_STALE",
    }
    account_ids = {}
    for age in ages_and_statuses:
        account_id = _create_account(user_id, service_id)
        _set_dates(account_id, age, 1)
        account_ids[account_id] = (age, ages_and_statuses[age])

    first = client.get(f"/api/users/{user_id}/hygiene?as_of={AS_OF.isoformat()}").json()["data"]
    second = client.get(f"/api/users/{user_id}/hygiene?as_of={AS_OF.isoformat()}").json()["data"]
    assert first == second
    by_id = {account["account_id"]: account for account in first["accounts"]}
    for account_id, (age, expected_status) in account_ids.items():
        assert by_id[account_id]["account_age_days"] is None
        assert by_id[account_id]["account_age_status"] == "UNKNOWN"
        assert by_id[account_id]["inventory_record_age_days"] == age
        assert by_id[account_id]["inventory_record_age_status"] == expected_status
        assert by_id[account_id]["activity_status"] == "ACTIVE"
        assert "ACCOUNT_INACTIVE" not in {finding["finding_type"] for finding in by_id[account_id]["findings"]}


def test_activity_bands_and_missing_activity_are_not_conflated() -> None:
    user_id = _create_user()
    service_id = _create_service()
    activity_bands = {30: "ACTIVE", 31: "AGING", 90: "AGING", 91: "INACTIVE", 180: "INACTIVE", 181: "VERY_INACTIVE"}
    accounts: dict[str, tuple[int | None, str]] = {}
    for age, activity_status in activity_bands.items():
        account_id = _create_account(user_id, service_id)
        _set_dates(account_id, 5, age)
        accounts[account_id] = (age, activity_status)
    unknown_account = _create_account(user_id, service_id, last_activity=None)
    _set_dates(unknown_account, 5, None)
    marked_inactive = _create_account(user_id, service_id, status="INACTIVE", is_active=False, last_activity=None)
    _set_dates(marked_inactive, 5, None)

    summary = client.get(f"/api/users/{user_id}/hygiene?as_of={AS_OF.isoformat()}").json()["data"]
    by_id = {account["account_id"]: account for account in summary["accounts"]}
    for account_id, (age, activity_status) in accounts.items():
        account_result = by_id[account_id]
        assert account_result["activity_status"] == activity_status
        finding_types = {finding["finding_type"] for finding in account_result["findings"]}
        if activity_status == "INACTIVE":
            assert "ACCOUNT_INACTIVE" in finding_types
        elif activity_status == "VERY_INACTIVE":
            assert "ACCOUNT_VERY_INACTIVE" in finding_types
        else:
            assert not finding_types.intersection({"ACCOUNT_INACTIVE", "ACCOUNT_VERY_INACTIVE"})
    unknown = by_id[unknown_account]
    assert unknown["activity_status"] == "UNKNOWN"
    assert {finding["finding_type"] for finding in unknown["findings"]} == {"ACTIVITY_UNKNOWN"}
    explicit_status = by_id[marked_inactive]
    assert explicit_status["activity_status"] == "UNKNOWN"
    assert {finding["finding_type"] for finding in explicit_status["findings"]} == {"ACCOUNT_INACTIVE", "ACTIVITY_UNKNOWN"}
    assert summary["unknown_activity_accounts"] == 2


def test_breach_stale_correlation_and_permission_review_are_evidence_based() -> None:
    user_id = _create_user()
    service_id = _create_service()
    account_id = _create_account(
        user_id,
        service_id,
        account_identifier="private-account-identifier@example.com",
        last_activity="2020-01-01T00:00:00Z",
    )
    _set_dates(account_id, 700, 181)
    permission = client.post(
        f"/api/accounts/{account_id}/permissions",
        json={
            "permission_type": "PRIVATE_PERMISSION_NAME",
            "description": "private permission description must not be returned",
            "sensitivity": "MEDIUM",
            "granted": True,
            "last_reviewed_at": "2020-01-01T00:00:00Z",
        },
    )
    assert permission.status_code == 200
    with SessionLocal() as db:
        db.add(
            BreachEvent(
                service_id=service_id,
                account_id=account_id,
                title="private breach title must not be returned",
                description="private breach description must not be returned",
                severity=Severity.HIGH,
            )
        )
        db.commit()

    response = client.get(f"/api/accounts/{account_id}/hygiene?as_of={AS_OF.isoformat()}")
    assert response.status_code == 200
    result = response.json()["data"]
    finding_types = {finding["finding_type"] for finding in result["findings"]}
    assert "INVENTORY_RECORD_STALE" in finding_types
    assert "ACCOUNT_VERY_INACTIVE" in finding_types
    assert "BREACHED_STALE_ACCOUNT" in finding_types
    assert "PERMISSION_REVIEW_REQUIRED" in finding_types
    correlated = next(item for item in result["findings"] if item["finding_type"] == "BREACHED_STALE_ACCOUNT")
    assert "does not indicate current compromise" in correlated["description"]
    assert "private breach title" not in json.dumps(result)
    assert "private breach description" not in json.dumps(result)
    assert "private permission description" not in json.dumps(result)
    assert "PRIVATE_PERMISSION_NAME" not in json.dumps(result)
    assert "private-account-identifier" not in json.dumps(result)
    assert "UNUSED_PERMISSION" not in finding_types
    assert "ORPHANED_ACCOUNT" not in finding_types

    current_account = _create_account(user_id, service_id)
    _set_dates(current_account, 5, 1)
    old_review = client.post(
        f"/api/accounts/{current_account}/permissions",
        json={
            "permission_type": "REVIEWED_PERMISSION",
            "sensitivity": "LOW",
            "granted": True,
            "last_reviewed_at": datetime.combine(AS_OF - timedelta(days=181), time.min, tzinfo=timezone.utc).isoformat(),
        },
    )
    assert old_review.status_code == 200
    current_result = client.get(f"/api/accounts/{current_account}/hygiene?as_of={AS_OF.isoformat()}").json()["data"]
    assert "PERMISSION_REVIEW_REQUIRED" in {item["finding_type"] for item in current_result["findings"]}


def test_summary_counts_match_returned_account_data_and_get_is_read_only() -> None:
    user_id = _create_user()
    service_id = _create_service()
    active = _create_account(user_id, service_id)
    stale = _create_account(user_id, service_id, last_activity=None)
    _set_dates(stale, 400, None)

    models = (AppPermission, FixItem, Notification, Reminder, RiskFactor, RiskSnapshot)
    before = {model: _count_for_user(model, user_id) for model in models if hasattr(model, "user_id")}
    before["risk_factors"] = _count_risk_factors_for_user(user_id)
    first = client.get(f"/api/users/{user_id}/hygiene?as_of={AS_OF.isoformat()}")
    second = client.get(f"/api/users/{user_id}/hygiene?as_of={AS_OF.isoformat()}")
    after = {model: _count_for_user(model, user_id) for model in models if hasattr(model, "user_id")}
    after["risk_factors"] = _count_risk_factors_for_user(user_id)

    assert first.status_code == 200
    assert first.json() == second.json()
    assert before == after
    data = first.json()["data"]
    accounts = data["accounts"]
    findings = data["findings"]
    assert data["total_accounts"] == len(accounts) == 2
    assert data["accounts_requiring_review"] == len({finding["account_id"] for finding in findings})
    assert data["active_accounts"] == sum(account["activity_status"] == "ACTIVE" and account["account_status"] == "ACTIVE" and account["is_active"] for account in accounts)
    assert data["aging_accounts"] == sum(account["activity_status"] == "AGING" for account in accounts)
    assert data["stale_accounts"] == sum(account["activity_status"] == "VERY_INACTIVE" for account in accounts)
    assert data["stale_inventory_records"] == sum(account["inventory_record_age_status"] in {"STALE", "VERY_STALE"} for account in accounts)
    assert data["inactive_accounts"] == sum(
        account["activity_status"] in {"INACTIVE", "VERY_INACTIVE"}
        or account["account_status"] == "INACTIVE"
        or (not account["is_active"] and account["account_status"] != "DELETED")
        for account in accounts
    )
    assert data["unknown_activity_accounts"] == sum(account["activity_status"] == "UNKNOWN" for account in accounts)
    assert active in {account["account_id"] for account in accounts}