from __future__ import annotations

import json
from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app
from app.database.database import SessionLocal
from app.models.models import BreachEvent, Severity


client = TestClient(app)


def _create_user_and_service() -> tuple[str, str]:
    suffix = uuid4().hex
    user = client.post("/api/users", json={"name": "Explanation User", "email": f"explain-{suffix}@example.com"})
    assert user.status_code == 200
    user_id = user.json()["data"]["id"]
    service = client.post(
        "/api/services",
        json={"name": f"Service {suffix}", "category": "PRODUCTIVITY", "website": "https://example.com"},
    )
    assert service.status_code == 200
    return user_id, service.json()["data"]["id"]


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


def test_user_explanations_are_scoped_deterministic_and_read_only() -> None:
    user_id, service_id = _create_user_and_service()
    account_id = _create_account(user_id, service_id, password_reuse_group_id="private-reuse-group")
    other_user_id, other_service_id = _create_user_and_service()
    other_account_id = _create_account(other_user_id, other_service_id)

    first = client.get(f"/api/users/{user_id}/risk/explanations")
    second = client.get(f"/api/users/{user_id}/risk/explanations")

    assert first.status_code == 200
    assert first.json() == second.json()
    data = first.json()["data"]
    assert data["user_id"] == user_id
    assert data["accounts_requiring_attention"][0]["account_id"] == account_id
    assert other_account_id not in json.dumps(data)
    assert client.get(f"/api/users/{user_id}/risk/history").json()["data"] == []


def test_account_explanations_use_existing_risk_results_without_leaking_identifiers() -> None:
    user_id, service_id = _create_user_and_service()
    account_id = _create_account(
        user_id,
        service_id,
        account_identifier="credential-must-not-appear@example.com",
        password_reuse_group_id="reuse-group-must-not-appear",
    )

    risk = client.get(f"/api/accounts/{account_id}/risk").json()["data"]
    response = client.get(f"/api/accounts/{account_id}/risk/explanations")
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["account_id"] == account_id
    assert data["service_id"] == service_id
    assert data["risk_score"] == risk["score"]
    assert data["risk_level"] == risk["risk_level"]
    assert "AUTHENTICATION" in {item["factor_code"] for item in data["explanations"]}
    encoded = json.dumps(data)
    assert "credential-must-not-appear" not in encoded
    assert "reuse-group-must-not-appear" not in encoded
    assert "account_identifier" not in encoded


def test_missing_resources_return_existing_404_contract() -> None:
    missing_user = client.get("/api/users/missing-user/risk/explanations")
    missing_account = client.get("/api/accounts/missing-account/risk/explanations")
    assert missing_user.status_code == 404
    assert missing_user.json()["error"]["code"] == "USER_NOT_FOUND"
    assert missing_account.status_code == 404
    assert missing_account.json()["error"]["code"] == "ACCOUNT_NOT_FOUND"


def test_empty_user_and_account_without_persisted_factors_are_supported() -> None:
    user_id, service_id = _create_user_and_service()
    empty = client.get(f"/api/users/{user_id}/risk/explanations")
    assert empty.status_code == 200
    assert empty.json()["data"]["overall_exposure"] == 0
    assert empty.json()["data"]["privacy_score"] == 100
    assert empty.json()["data"]["recommendations"] == []

    account_id = _create_account(user_id, service_id, two_factor_enabled=True, sign_in_method="GOOGLE_SSO")
    response = client.get(f"/api/accounts/{account_id}/risk/explanations")
    assert response.status_code == 200
    assert response.json()["data"]["risk_score"] == 0
    assert response.json()["data"]["explanations"] == []
    assert response.json()["data"]["recommendations"] == []


def test_recommendations_are_prioritized_and_consolidated_with_evidence() -> None:
    user_id, service_id = _create_user_and_service()
    first_id = _create_account(user_id, service_id, password_reuse_group_id="shared-group")
    second_id = _create_account(user_id, service_id, password_reuse_group_id="shared-group")
    for _ in range(2):
        permission = client.post(
            f"/api/accounts/{first_id}/permissions",
            json={"permission_type": "SENSITIVE_ACCESS", "sensitivity": "CRITICAL", "granted": True},
        )
        assert permission.status_code == 200

    response = client.get(f"/api/users/{user_id}/risk/explanations")
    assert response.status_code == 200
    data = response.json()["data"]
    recommendations = data["recommendations"]

    two_factor = next(item for item in recommendations if "two-factor authentication" in item["recommendation"])
    reuse = next(item for item in recommendations if "reuse group" in item["recommendation"])
    assert two_factor["priority"] < reuse["priority"]
    assert two_factor["related_account_ids"] == sorted([first_id, second_id])
    assert len([item for item in recommendations if item["recommendation"] == two_factor["recommendation"]]) == 1
    assert two_factor["evidence"]
    assert [item["priority"] for item in recommendations] == sorted(item["priority"] for item in recommendations)
    assert recommendations.index(two_factor) < recommendations.index(next(item for item in recommendations if item["recommendation"] == "Review granted permissions and revoke access that is no longer required."))
    assert any(first_id in item["related_account_ids"] for item in recommendations)


def test_user_explanations_map_all_step5_factors_without_echoing_breach_text() -> None:
    user_id, service_id = _create_user_and_service()
    old_account = _create_account(
        user_id,
        service_id,
        password_reuse_group_id="recorded-group",
        last_activity="2020-01-01T00:00:00Z",
    )
    central_account = _create_account(user_id, service_id, password_reuse_group_id="recorded-group")
    breached_account = _create_account(user_id, service_id, two_factor_enabled=True)

    for account_id in (old_account, breached_account):
        connection = client.post(
            "/api/connections",
            json={
                "source_account_id": central_account,
                "target_account_id": account_id,
                "connection_type": "SSO",
                "is_active": True,
            },
        )
        assert connection.status_code == 200

    for _ in range(2):
        permission = client.post(
            f"/api/accounts/{central_account}/permissions",
            json={"permission_type": "SENSITIVE_ACCESS", "sensitivity": "CRITICAL", "granted": True},
        )
        assert permission.status_code == 200

    with SessionLocal() as db:
        db.add(
            BreachEvent(
                service_id=service_id,
                account_id=breached_account,
                title="sensitive breach title must not be returned",
                description="sensitive breach description must not be returned",
                severity=Severity.HIGH,
            )
        )
        db.commit()

    response = client.get(f"/api/users/{user_id}/risk/explanations")
    assert response.status_code == 200
    data = response.json()["data"]
    factor_codes = {item["factor_code"] for item in data["top_risks"]}
    assert factor_codes == {
        "AUTHENTICATION",
        "PASSWORD_REUSE",
        "PERMISSIONS",
        "NETWORK",
        "BREACH",
        "HYGIENE",
        "SINGLE_POINT_OF_FAILURE",
    }
    assert "sensitive breach title" not in json.dumps(data)
    assert "sensitive breach description" not in json.dumps(data)
    assert all(item["related_service_ids"] for item in data["recommendations"])


def test_explanation_routes_are_listed_in_openapi() -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert "/api/users/{user_id}/risk/explanations" in paths
    assert "/api/accounts/{account_id}/risk/explanations" in paths
    assert client.get("/health").status_code == 200
    assert client.get("/api/health").status_code == 200


def test_explanation_layer_preserves_existing_user_scores_and_thresholds() -> None:
    user_id, service_id = _create_user_and_service()
    account_id = _create_account(user_id, service_id)

    before_account = client.get(f"/api/accounts/{account_id}/risk").json()["data"]
    before_user = client.get(f"/api/users/{user_id}/risk").json()["data"]
    account_explanations = client.get(f"/api/accounts/{account_id}/risk/explanations").json()["data"]
    user_explanations = client.get(f"/api/users/{user_id}/risk/explanations").json()["data"]

    assert account_explanations["risk_score"] == before_account["score"]
    assert account_explanations["risk_level"] == before_account["risk_level"]
    assert user_explanations["overall_exposure"] == before_user["overall_exposure"]
    assert user_explanations["privacy_score"] == before_user["privacy_score"]
    assert user_explanations["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}