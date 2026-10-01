from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_authentication_and_password_reuse_risk_scoring() -> None:
    user_response = client.post("/api/users", json={"name": "Risk User", "email": "risk-user@example.com"})
    user_id = user_response.json()["data"]["id"]

    service_response = client.post("/api/services", json={"name": "Google", "category": "EMAIL", "website": "https://google.com"})
    service_id = service_response.json()["data"]["id"]

    account_a = client.post(
        "/api/accounts",
        json={
            "user_id": user_id,
            "service_id": service_id,
            "account_identifier": "risk-user-google",
            "display_name": "Google",
            "status": "ACTIVE",
            "sign_in_method": "PASSWORD",
            "two_factor_enabled": False,
            "password_reuse_group_id": "group-1",
            "password_strength": "MEDIUM",
            "is_active": True,
        },
    )
    account_a_id = account_a.json()["data"]["id"]

    account_b = client.post(
        "/api/accounts",
        json={
            "user_id": user_id,
            "service_id": service_id,
            "account_identifier": "risk-user-gmail",
            "display_name": "Gmail",
            "status": "ACTIVE",
            "sign_in_method": "PASSWORD",
            "two_factor_enabled": True,
            "password_reuse_group_id": "group-1",
            "password_strength": "MEDIUM",
            "is_active": True,
        },
    )
    account_b_id = account_b.json()["data"]["id"]

    response = client.post(f"/api/users/{user_id}/risk/calculate")
    assert response.status_code == 200
    data = response.json()["data"]
    ranked = data["risk_ranking"]

    accounts_by_id = {item["account_id"]: item for item in ranked}
    assert accounts_by_id[account_a_id]["score"] >= accounts_by_id[account_b_id]["score"]
    assert "password_reuse" in accounts_by_id[account_a_id]["factors"]
    assert 0 <= accounts_by_id[account_a_id]["score"] <= 100
    assert data["overall_privacy_score"] >= 0
    assert data["overall_privacy_score"] <= 100


def test_risk_summary_history_and_isolation() -> None:
    user_response = client.post("/api/users", json={"name": "History User", "email": "history-user@example.com"})
    user_id = user_response.json()["data"]["id"]

    service_response = client.post("/api/services", json={"name": "Dropbox", "category": "CLOUD_STORAGE", "website": "https://dropbox.com"})
    service_id = service_response.json()["data"]["id"]

    client.post(
        "/api/accounts",
        json={
            "user_id": user_id,
            "service_id": service_id,
            "account_identifier": "history-user-dropbox",
            "display_name": "Dropbox",
            "status": "ACTIVE",
            "sign_in_method": "PASSWORD",
            "two_factor_enabled": False,
            "password_reuse_group_id": None,
            "password_strength": "STRONG",
            "last_activity": "2026-09-15T00:00:00Z",
            "is_active": True,
        },
    )

    calculate = client.post(f"/api/users/{user_id}/risk/calculate")
    assert calculate.status_code == 200

    summary = client.get(f"/api/users/{user_id}/risk")
    assert summary.status_code == 200
    summary_data = summary.json()["data"]
    assert "privacy_score" in summary_data
    assert "risk_distribution" in summary_data
    assert "top_risk_accounts" in summary_data

    history = client.get(f"/api/users/{user_id}/risk/history")
    assert history.status_code == 200
    assert len(history.json()["data"]) >= 1

    missing = client.get("/api/users/definitely-missing-user/risk")
    assert missing.status_code == 404


def test_account_risk_endpoint_and_reasons_are_safe() -> None:
    user_response = client.post("/api/users", json={"name": "Account Risk User", "email": "account-risk-user@example.com"})
    user_id = user_response.json()["data"]["id"]

    service_response = client.post("/api/services", json={"name": "GitHub", "category": "DEVELOPMENT", "website": "https://github.com"})
    service_id = service_response.json()["data"]["id"]

    account_response = client.post(
        "/api/accounts",
        json={
            "user_id": user_id,
            "service_id": service_id,
            "account_identifier": "account-risk-user-github",
            "display_name": "GitHub",
            "status": "ACTIVE",
            "sign_in_method": "PASSWORD",
            "two_factor_enabled": False,
            "password_reuse_group_id": "group-abc",
            "password_strength": "MEDIUM",
            "is_active": True,
        },
    )
    account_id = account_response.json()["data"]["id"]

    permission_response = client.post(
        f"/api/accounts/{account_id}/permissions",
        json={
            "permission_type": "REPO_ACCESS",
            "description": "Repository access",
            "sensitivity": "HIGH",
            "granted": True,
        },
    )
    assert permission_response.status_code == 200

    risk_response = client.get(f"/api/accounts/{account_id}/risk")
    assert risk_response.status_code == 200
    payload = risk_response.json()["data"]
    assert 0 <= payload["score"] <= 100
    assert payload["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert len(payload["reasons"]) >= 1
    assert all("password" not in reason["message"].lower() for reason in payload["reasons"] if reason.get("message"))
