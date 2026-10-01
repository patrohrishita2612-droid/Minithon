from __future__ import annotations

import json
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.database.database import SessionLocal
from app.main import app
from app.models.models import BreachEvent, FixItem, Severity


client = TestClient(app)


def _create_user() -> str:
    suffix = uuid4().hex
    response = client.post("/api/users", json={"name": "Remediation User", "email": f"remediate-{suffix}@example.com"})
    assert response.status_code == 200
    return response.json()["data"]["id"]


def _create_service() -> str:
    suffix = uuid4().hex
    response = client.post(
        "/api/services",
        json={"name": f"Remediation Service {suffix}", "category": "PRODUCTIVITY", "website": "https://example.com"},
    )
    assert response.status_code == 200
    return response.json()["data"]["id"]


def _create_account(user_id: str, service_id: str, **overrides: object) -> str:
    payload: dict[str, object] = {
        "user_id": user_id,
        "service_id": service_id,
        "account_identifier": f"private-{uuid4().hex}@example.com",
        "display_name": "Private account label",
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


def _count_fixes(user_id: str) -> int:
    with SessionLocal() as db:
        return int(db.scalar(select(func.count()).select_from(FixItem).where(FixItem.user_id == user_id)) or 0)


def test_user_and_account_remediation_endpoints_return_structured_plans() -> None:
    user_id = _create_user()
    service_id = _create_service()
    account_id = _create_account(user_id, service_id)

    user_response = client.get(f"/api/users/{user_id}/remediation")
    account_response = client.get(f"/api/accounts/{account_id}/remediation")

    assert user_response.status_code == 200
    assert user_response.json()["data"]["user_id"] == user_id
    assert user_response.json()["data"]["total_open_items"] >= 1
    assert account_response.status_code == 200
    account_data = account_response.json()["data"]
    assert account_data["account_id"] == account_id
    assert account_data["service_id"] == service_id
    assert account_data["risk_score"] == client.get(f"/api/accounts/{account_id}/risk").json()["data"]["score"]
    assert all(item["status"] == "OPEN" and item["fix_id"] is None for item in account_data["items"])


def test_missing_user_and_account_keep_existing_404_contract() -> None:
    missing_user = client.get("/api/users/missing-user/remediation")
    missing_account = client.get("/api/accounts/missing-account/remediation")
    assert missing_user.status_code == 404
    assert missing_user.json()["error"]["code"] == "USER_NOT_FOUND"
    assert missing_account.status_code == 404
    assert missing_account.json()["error"]["code"] == "ACCOUNT_NOT_FOUND"


def test_empty_user_and_account_without_findings_return_empty_plans() -> None:
    user_id = _create_user()
    service_id = _create_service()
    empty_user = client.get(f"/api/users/{user_id}/remediation").json()["data"]
    assert empty_user["total_open_items"] == 0
    assert empty_user["items"] == []

    account_id = _create_account(user_id, service_id, two_factor_enabled=True, sign_in_method="GOOGLE_SSO")
    empty_account = client.get(f"/api/accounts/{account_id}/remediation").json()["data"]
    assert empty_account["risk_score"] == 0
    assert empty_account["items"] == []


def test_user_plan_isolated_deduplicated_and_get_does_not_persist_fixes() -> None:
    user_id = _create_user()
    service_id = _create_service()
    first_account = _create_account(user_id, service_id)
    second_account = _create_account(user_id, service_id)
    other_user = _create_user()
    other_account = _create_account(other_user, _create_service())

    before = _count_fixes(user_id)
    first = client.get(f"/api/users/{user_id}/remediation")
    second = client.get(f"/api/users/{user_id}/remediation")
    after = _count_fixes(user_id)

    assert first.status_code == second.status_code == 200
    data = first.json()["data"]
    assert first.json() == second.json()
    assert other_account not in json.dumps(data)
    assert after == before
    assert client.get(f"/api/users/{user_id}/risk/history").json()["data"] == []
    authentication_items = [item for item in data["items"] if item["factor_code"] == "AUTHENTICATION"]
    assert len(authentication_items) == 1
    assert authentication_items[0]["account_ids"] == sorted([first_account, second_account])
    assert authentication_items[0]["service_ids"] == [service_id]


def test_all_step5_findings_generate_supported_remediation_and_safe_evidence() -> None:
    user_id = _create_user()
    service_id = _create_service()
    old_account = _create_account(
        user_id,
        service_id,
        account_identifier="private-identifier-must-not-leak@example.com",
        password_reuse_group_id="private-reuse-group-must-not-leak",
        last_activity="2020-01-01T00:00:00Z",
    )
    central_account = _create_account(user_id, service_id, password_reuse_group_id="private-reuse-group-must-not-leak")
    breached_account = _create_account(user_id, service_id, two_factor_enabled=True)

    for target_id in (old_account, breached_account):
        connection = client.post(
            "/api/connections",
            json={"source_account_id": central_account, "target_account_id": target_id, "connection_type": "SSO", "is_active": True},
        )
        assert connection.status_code == 200
    for index in range(2):
        permission = client.post(
            f"/api/accounts/{central_account}/permissions",
            json={
                "permission_type": f"SENSITIVE_ACCESS_{index}",
                "description": "private permission description must not leak",
                "sensitivity": "CRITICAL",
                "granted": True,
            },
        )
        assert permission.status_code == 200

    with SessionLocal() as db:
        db.add(
            BreachEvent(
                service_id=service_id,
                account_id=breached_account,
                title="private breach title must not leak",
                description="private breach description must not leak",
                severity=Severity.HIGH,
            )
        )
        db.commit()

    response = client.get(f"/api/users/{user_id}/remediation")
    assert response.status_code == 200
    data = response.json()["data"]
    factor_codes = {factor for item in data["items"] for factor in item["factor_codes"]}
    assert factor_codes == {
        "AUTHENTICATION",
        "PASSWORD_REUSE",
        "PERMISSIONS",
        "NETWORK",
        "BREACH",
        "HYGIENE",
        "SINGLE_POINT_OF_FAILURE",
    }
    reason_codes = {reason for item in data["items"] for reason in item["reason_codes"]}
    assert reason_codes == {"NO_2FA", "PASSWORD_REUSE", "HIGH_PERMISSION", "NETWORK_EXPOSURE", "BREACH", "INACTIVE_ACCOUNT", "SPOF"}
    actions_by_factor = {
        factor_code: item["action"]
        for item in data["items"]
        for factor_code in item["factor_codes"]
    }
    assert actions_by_factor == {
        "AUTHENTICATION": "Enable two-factor authentication for this account where the service supports it.",
        "PASSWORD_REUSE": "Review the recorded reuse group and use a unique password for each important account.",
        "PERMISSIONS": "Review granted permissions and revoke access that is no longer required.",
        "NETWORK": "Review active account connections and remove links that are no longer needed.",
        "BREACH": "Review the breach notice, change any affected credential still in use, and enable two-factor authentication.",
        "HYGIENE": "Confirm whether this account is still needed; deactivate or remove it if it is not.",
        "SINGLE_POINT_OF_FAILURE": "Review dependent accounts and establish independent recovery or sign-in paths where supported.",
    }
    encoded = json.dumps(data)
    for secret in (
        "private-identifier-must-not-leak",
        "private-reuse-group-must-not-leak",
        "private permission description must not leak",
        "private breach title must not leak",
        "private breach description must not leak",
    ):
        assert secret not in encoded
    assert all(item["evidence"] and item["risk_contribution"] >= 0 for item in data["items"])


def test_remediation_priority_order_is_deterministic_and_routes_are_documented() -> None:
    user_id = _create_user()
    service_id = _create_service()
    accounts = [_create_account(user_id, service_id) for _ in range(3)]
    for source, target in zip(accounts, accounts[1:]):
        assert client.post(
            "/api/connections",
            json={"source_account_id": source, "target_account_id": target, "connection_type": "CONNECTED_SERVICE", "is_active": True},
        ).status_code == 200

    first = client.get(f"/api/users/{user_id}/remediation").json()["data"]
    second = client.get(f"/api/users/{user_id}/remediation").json()["data"]
    assert first == second
    priority_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    expected = sorted(
        first["items"],
        key=lambda item: (
            priority_rank[item["priority"]],
            -item["risk_contribution"],
            item["factor_codes"],
            item["account_ids"],
            item["service_ids"],
        ),
    )
    assert first["items"] == expected
    assert sum(first[key] for key in ("critical_count", "high_count", "medium_count", "low_count")) == first["total_open_items"]
    paths = client.get("/openapi.json").json()["paths"]
    assert "/api/users/{user_id}/remediation" in paths
    assert "/api/accounts/{account_id}/remediation" in paths
    assert client.get("/health").status_code == 200