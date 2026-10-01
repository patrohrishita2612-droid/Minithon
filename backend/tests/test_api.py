from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_create_user_and_get_user() -> None:
    payload = {"name": "Demo User", "email": "demo@example.com"}
    create_response = client.post("/api/users", json=payload)
    assert create_response.status_code == 200
    body = create_response.json()
    assert body["success"] is True
    user_id = body["data"]["id"]

    get_response = client.get(f"/api/users/{user_id}")
    assert get_response.status_code == 200
    assert get_response.json()["data"]["email"] == "demo@example.com"


def test_create_service_and_list_services() -> None:
    payload = {"name": "Google", "category": "EMAIL", "website": "https://google.com"}
    create_response = client.post("/api/services", json=payload)
    assert create_response.status_code == 200
    service_id = create_response.json()["data"]["id"]

    list_response = client.get("/api/services")
    assert list_response.status_code == 200
    assert any(item["id"] == service_id for item in list_response.json()["data"])


def test_create_account_and_list_user_accounts() -> None:
    user_response = client.post("/api/users", json={"name": "User A", "email": "usera@example.com"})
    user_id = user_response.json()["data"]["id"]

    service_response = client.post("/api/services", json={"name": "GitHub", "category": "DEVELOPMENT", "website": "https://github.com"})
    service_id = service_response.json()["data"]["id"]

    account_payload = {
        "user_id": user_id,
        "service_id": service_id,
        "account_identifier": "usera@github.com",
        "display_name": "GitHub Account",
        "status": "ACTIVE",
        "sign_in_method": "PASSWORD",
        "two_factor_enabled": False,
        "password_reuse_group_id": "reuse-group-1",
        "password_strength": "MEDIUM",
        "password_last_changed": "2026-08-01",
        "last_activity": "2026-09-25",
        "is_active": True,
    }
    create_response = client.post("/api/accounts", json=account_payload)
    assert create_response.status_code == 200
    account_id = create_response.json()["data"]["id"]

    list_response = client.get(f"/api/users/{user_id}/accounts")
    assert list_response.status_code == 200
    assert any(item["id"] == account_id for item in list_response.json()["data"]["items"])


def test_update_account_and_permissions_and_connections() -> None:
    user_response = client.post("/api/users", json={"name": "User B", "email": "userb@example.com"})
    user_id = user_response.json()["data"]["id"]

    service_response = client.post("/api/services", json={"name": "Google", "category": "EMAIL", "website": "https://google.com"})
    service_id = service_response.json()["data"]["id"]

    account_response = client.post(
        "/api/accounts",
        json={
            "user_id": user_id,
            "service_id": service_id,
            "account_identifier": "userb@gmail.com",
            "display_name": "Google Account",
            "status": "ACTIVE",
            "sign_in_method": "PASSWORD",
            "two_factor_enabled": False,
            "password_reuse_group_id": "reuse-group-2",
            "password_strength": "STRONG",
            "is_active": True,
        },
    )
    account_id = account_response.json()["data"]["id"]

    patch_response = client.patch(f"/api/accounts/{account_id}", json={"display_name": "Updated Google Account", "two_factor_enabled": True})
    assert patch_response.status_code == 200
    assert patch_response.json()["data"]["display_name"] == "Updated Google Account"

    permission_response = client.post(
        f"/api/accounts/{account_id}/permissions",
        json={
            "permission_type": "CONTACTS",
            "description": "Access to contacts",
            "sensitivity": "HIGH",
            "granted": True,
            "granted_at": "2026-09-01",
            "last_reviewed_at": "2026-09-20",
        },
    )
    assert permission_response.status_code == 200
    permission_id = permission_response.json()["data"]["id"]

    list_permissions = client.get(f"/api/accounts/{account_id}/permissions")
    assert list_permissions.status_code == 200
    assert any(item["id"] == permission_id for item in list_permissions.json()["data"])

    permission_patch = client.patch(f"/api/permissions/{permission_id}", json={"sensitivity": "CRITICAL"})
    assert permission_patch.status_code == 200
    assert permission_patch.json()["data"]["sensitivity"] == "CRITICAL"

    account_two_response = client.post(
        "/api/accounts",
        json={
            "user_id": user_id,
            "service_id": service_id,
            "account_identifier": "userb-alt@gmail.com",
            "display_name": "Google Alternate",
            "status": "ACTIVE",
            "sign_in_method": "GOOGLE_SSO",
            "two_factor_enabled": True,
            "password_reuse_group_id": "reuse-group-2",
            "password_strength": "MEDIUM",
            "is_active": True,
        },
    )
    second_account_id = account_two_response.json()["data"]["id"]

    connection_response = client.post(
        "/api/connections",
        json={
            "source_account_id": account_id,
            "target_account_id": second_account_id,
            "connection_type": "SSO",
            "description": "Google SSO login",
            "is_active": True,
        },
    )
    assert connection_response.status_code == 200
    connection_id = connection_response.json()["data"]["id"]

    get_connection = client.get(f"/api/connections/{connection_id}")
    assert get_connection.status_code == 200
    assert get_connection.json()["data"]["connection_type"] == "SSO"


def test_recovery_methods_linking_and_footprint() -> None:
    user_response = client.post("/api/users", json={"name": "User C", "email": "userc@example.com"})
    user_id = user_response.json()["data"]["id"]

    service_response = client.post("/api/services", json={"name": "Microsoft", "category": "PRODUCTIVITY", "website": "https://microsoft.com"})
    service_id = service_response.json()["data"]["id"]

    account_response = client.post(
        "/api/accounts",
        json={
            "user_id": user_id,
            "service_id": service_id,
            "account_identifier": "userc@microsoft.com",
            "display_name": "Microsoft Account",
            "status": "ACTIVE",
            "sign_in_method": "MICROSOFT_SSO",
            "two_factor_enabled": True,
            "password_reuse_group_id": "reuse-group-3",
            "password_strength": "STRONG",
            "is_active": True,
        },
    )
    account_id = account_response.json()["data"]["id"]

    email_response = client.post("/api/recovery/emails", json={"user_id": user_id, "email": "backup@example.com", "is_primary": True, "is_verified": True})
    assert email_response.status_code == 200
    email_id = email_response.json()["data"]["id"]

    phone_response = client.post("/api/recovery/phones", json={"user_id": user_id, "phone_number": "+919900000001", "is_primary": False, "is_verified": True})
    assert phone_response.status_code == 200
    phone_id = phone_response.json()["data"]["id"]

    link_email = client.post(f"/api/accounts/{account_id}/recovery-email/{email_id}")
    assert link_email.status_code == 200

    link_phone = client.post(f"/api/accounts/{account_id}/recovery-phone/{phone_id}")
    assert link_phone.status_code == 200

    footprint = client.get(f"/api/users/{user_id}/footprint")
    assert footprint.status_code == 200
    data = footprint.json()["data"]
    assert len(data["accounts"]) >= 1
    assert len(data["recovery_emails"]) >= 1
    assert len(data["phone_numbers"]) >= 1
    assert len(data["connections"]) >= 0


def test_validation_and_filters() -> None:
    user_response = client.post("/api/users", json={"name": "Filter User", "email": "filter@example.com"})
    user_id = user_response.json()["data"]["id"]

    service_response = client.post("/api/services", json={"name": "Dropbox", "category": "CLOUD_STORAGE", "website": "https://dropbox.com"})
    service_id = service_response.json()["data"]["id"]

    account_payload = {
        "user_id": user_id,
        "service_id": service_id,
        "account_identifier": "filter@dropbox.com",
        "display_name": "Dropbox",
        "status": "ACTIVE",
        "sign_in_method": "PASSWORD",
        "two_factor_enabled": True,
        "password_reuse_group_id": "reuse-filter-1",
        "password_strength": "MEDIUM",
        "is_active": True,
    }
    client.post("/api/accounts", json=account_payload)

    filtered = client.get(f"/api/users/{user_id}/accounts?two_factor_enabled=true&status=ACTIVE&service_id={service_id}&page=1&limit=10")
    assert filtered.status_code == 200
    assert len(filtered.json()["data"]["items"]) >= 1

    invalid_user = client.get("/api/users/not-a-real-id")
    assert invalid_user.status_code == 404

    invalid_service = client.post(
        "/api/accounts",
        json={
            "user_id": user_id,
            "service_id": "missing-service",
            "account_identifier": "missing@example.com",
            "display_name": "Bad service",
            "status": "ACTIVE",
            "sign_in_method": "PASSWORD",
            "two_factor_enabled": False,
            "password_reuse_group_id": "reuse-missing",
            "password_strength": "MEDIUM",
            "is_active": True,
        },
    )
    assert invalid_service.status_code == 404


def test_no_plaintext_password_field_is_exposed() -> None:
    response = client.post("/api/users", json={"name": "No Password", "email": "nopassword@example.com"})
    user = response.json()["data"]
    assert "password" not in user

    service = client.post("/api/services", json={"name": "Spotify", "category": "ENTERTAINMENT", "website": "https://spotify.com"})
    service_id = service.json()["data"]["id"]

    user_id = response.json()["data"]["id"]
    account = client.post(
        "/api/accounts",
        json={
            "user_id": user_id,
            "service_id": service_id,
            "account_identifier": "spotify-user",
            "display_name": "Spotify",
            "status": "ACTIVE",
            "sign_in_method": "PASSWORD",
            "password_reuse_group_id": "reuse-spotify",
            "password_strength": "MEDIUM",
            "is_active": True,
        },
    )
    payload = account.json()["data"]
    assert "password" not in payload
