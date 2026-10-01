from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _create_user(email: str) -> str:
    response = client.post("/api/users", json={"name": email.split("@")[0], "email": email})
    assert response.status_code == 200
    return response.json()["data"]["id"]


def _create_service(name: str, category: str = "EMAIL", website: str = "https://example.com") -> str:
    response = client.post("/api/services", json={"name": name, "category": category, "website": website})
    assert response.status_code == 200
    return response.json()["data"]["id"]


def _create_account(user_id: str, service_id: str, account_identifier: str, display_name: str, reuse_group: str | None = None) -> str:
    payload = {
        "user_id": user_id,
        "service_id": service_id,
        "account_identifier": account_identifier,
        "display_name": display_name,
        "status": "ACTIVE",
        "sign_in_method": "PASSWORD",
        "two_factor_enabled": False,
        "password_reuse_group_id": reuse_group,
        "password_strength": "MEDIUM",
        "is_active": True,
    }
    response = client.post("/api/accounts", json=payload)
    assert response.status_code == 200
    return response.json()["data"]["id"]


def test_zero_account_graph_is_empty() -> None:
    user_id = _create_user("empty@example.com")
    response = client.get(f"/api/users/{user_id}/exposure/graph")
    assert response.status_code == 200
    body = response.json()["data"]
    assert body["node_count"] == 0
    assert body["edge_count"] == 0
    assert body["nodes"] == []
    assert body["edges"] == []


def test_one_account_graph_has_one_node_and_no_edges() -> None:
    user_id = _create_user("single@example.com")
    service_id = _create_service("Single Service")
    account_id = _create_account(user_id, service_id, "single@service.com", "Single Account")

    response = client.get(f"/api/users/{user_id}/exposure/graph")
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["node_count"] == 1
    assert data["edge_count"] == 0
    assert any(node["id"] == account_id for node in data["nodes"])


def test_explicit_sso_connection_creates_edge() -> None:
    user_id = _create_user("sso@example.com")
    service_a = _create_service("Google")
    service_b = _create_service("GitHub")
    account_a = _create_account(user_id, service_a, "a@gmail.com", "Google")
    account_b = _create_account(user_id, service_b, "b@github.com", "GitHub")
    connection = client.post(
        "/api/connections",
        json={
            "source_account_id": account_a,
            "target_account_id": account_b,
            "connection_type": "SSO",
            "description": "SSO bridge",
            "is_active": True,
        },
    )
    assert connection.status_code == 200

    response = client.get(f"/api/users/{user_id}/exposure/graph")
    assert response.status_code == 200
    edges = response.json()["data"]["edges"]
    assert any(edge["type"] == "SSO" and {edge["source"], edge["target"]} == {account_a, account_b} for edge in edges)


def test_shared_recovery_email_creates_single_logical_edge() -> None:
    user_id = _create_user("recovery@example.com")
    service_a = _create_service("Google Mail")
    service_b = _create_service("Dropbox")
    account_a = _create_account(user_id, service_a, "a@google.com", "Google")
    account_b = _create_account(user_id, service_b, "b@dropbox.com", "Dropbox")
    email_response = client.post("/api/recovery/emails", json={"user_id": user_id, "email": "backup@example.com", "is_primary": True, "is_verified": True})
    assert email_response.status_code == 200
    email_id = email_response.json()["data"]["id"]
    assert client.post(f"/api/accounts/{account_a}/recovery-email/{email_id}").status_code == 200
    assert client.post(f"/api/accounts/{account_b}/recovery-email/{email_id}").status_code == 200

    response = client.get(f"/api/users/{user_id}/exposure/graph")
    assert response.status_code == 200
    edges = response.json()["data"]["edges"]
    matching = [e for e in edges if e["type"] == "RECOVERY_EMAIL" and {e["source"], e["target"]} == {account_a, account_b}]
    assert len(matching) == 1


def test_shared_phone_creates_edge() -> None:
    user_id = _create_user("phone@example.com")
    service_a = _create_service("Slack")
    service_b = _create_service("Discord")
    account_a = _create_account(user_id, service_a, "a@slack.com", "Slack")
    account_b = _create_account(user_id, service_b, "b@discord.com", "Discord")
    phone_response = client.post("/api/recovery/phones", json={"user_id": user_id, "phone_number": "+15550000001", "is_primary": True, "is_verified": True})
    assert phone_response.status_code == 200
    phone_id = phone_response.json()["data"]["id"]
    assert client.post(f"/api/accounts/{account_a}/recovery-phone/{phone_id}").status_code == 200
    assert client.post(f"/api/accounts/{account_b}/recovery-phone/{phone_id}").status_code == 200

    response = client.get(f"/api/users/{user_id}/exposure/graph")
    assert response.status_code == 200
    edges = response.json()["data"]["edges"]
    assert any(e["type"] == "RECOVERY_PHONE" and {e["source"], e["target"]} == {account_a, account_b} for e in edges)


def test_shared_password_group_creates_edge() -> None:
    user_id = _create_user("reuse@example.com")
    service_a = _create_service("Amazon")
    service_b = _create_service("Spotify")
    account_a = _create_account(user_id, service_a, "a@amazon.com", "Amazon", reuse_group="reuse-group-1")
    account_b = _create_account(user_id, service_b, "b@spotify.com", "Spotify", reuse_group="reuse-group-1")

    response = client.get(f"/api/users/{user_id}/exposure/graph")
    assert response.status_code == 200
    edges = response.json()["data"]["edges"]
    assert any(e["type"] == "SHARED_PASSWORD" and {e["source"], e["target"]} == {account_a, account_b} for e in edges)


def test_connected_components_and_degree() -> None:
    user_id = _create_user("components@example.com")
    service_a = _create_service("Service A")
    service_b = _create_service("Service B")
    service_c = _create_service("Service C")
    account_a = _create_account(user_id, service_a, "a@example.com", "A")
    account_b = _create_account(user_id, service_b, "b@example.com", "B")
    account_c = _create_account(user_id, service_c, "c@example.com", "C")
    client.post("/api/connections", json={"source_account_id": account_a, "target_account_id": account_b, "connection_type": "SSO", "description": "A-B", "is_active": True})
    client.post("/api/connections", json={"source_account_id": account_b, "target_account_id": account_c, "connection_type": "CONNECTED_SERVICE", "description": "B-C", "is_active": True})

    response = client.get(f"/api/users/{user_id}/exposure/graph")
    data = response.json()["data"]
    assert data["node_count"] == 3
    assert data["edge_count"] == 2
    assert len(data["connected_components"]) == 1
    assert data["connected_components"][0]["size"] == 3

    metrics = client.get(f"/api/users/{user_id}/exposure/metrics").json()["data"]
    by_id = {entry["account_id"]: entry for entry in metrics}
    assert by_id[account_a]["degree"] == 1
    assert by_id[account_b]["degree"] == 2
    assert by_id[account_c]["degree"] == 1


def test_articulation_points_and_path() -> None:
    user_id = _create_user("path@example.com")
    service_a = _create_service("A Service")
    service_b = _create_service("B Service")
    service_c = _create_service("C Service")
    service_d = _create_service("D Service")
    a = _create_account(user_id, service_a, "a@a.com", "A")
    b = _create_account(user_id, service_b, "b@b.com", "B")
    c = _create_account(user_id, service_c, "c@c.com", "C")
    d = _create_account(user_id, service_d, "d@d.com", "D")
    client.post("/api/connections", json={"source_account_id": a, "target_account_id": b, "connection_type": "SSO", "description": "A-B", "is_active": True})
    client.post("/api/connections", json={"source_account_id": b, "target_account_id": c, "connection_type": "RECOVERY_EMAIL", "description": "B-C", "is_active": True})
    client.post("/api/connections", json={"source_account_id": c, "target_account_id": d, "connection_type": "SHARED_PASSWORD", "description": "C-D", "is_active": True})

    graph = client.get(f"/api/users/{user_id}/exposure/graph").json()["data"]
    assert any(item["account_id"] == b for item in graph["articulation_points"])

    path = client.get(f"/api/users/{user_id}/exposure/path?source_account_id={a}&target_account_id={d}")
    assert path.status_code == 200
    body = path.json()["data"]
    assert body["exists"] is True
    assert body["hops"] >= 2
    assert body["path"][0]["account_id"] == a
    assert body["path"][-1]["account_id"] == d


def test_no_path_cross_user_and_unknown_account() -> None:
    owner_user = _create_user("owner@example.com")
    other_user = _create_user("other@example.com")
    service = _create_service("Owned Service")
    other_service = _create_service("Other Service")
    owner_account = _create_account(owner_user, service, "owner@owned.com", "Owned")
    other_account = _create_account(other_user, other_service, "other@other.com", "Other")

    path_response = client.get(f"/api/users/{owner_user}/exposure/path?source_account_id={owner_account}&target_account_id={other_account}")
    assert path_response.status_code == 400

    missing = client.get(f"/api/users/{owner_user}/exposure/path?source_account_id={owner_account}&target_account_id=missing-id")
    assert missing.status_code == 404

    denied = client.get(f"/api/users/{owner_user}/exposure/graph?user_id={other_user}")
    assert denied.status_code == 404


def test_graph_has_no_sensitive_data() -> None:
    user_id = _create_user("secret@example.com")
    service = _create_service("Sensitive")
    account = _create_account(user_id, service, "secret@sensitive.com", "Sensitive", reuse_group="group-xyz")
    email = client.post("/api/recovery/emails", json={"user_id": user_id, "email": "secret.backup@example.com", "is_primary": True, "is_verified": True})
    email_id = email.json()["data"]["id"]
    client.post(f"/api/accounts/{account}/recovery-email/{email_id}")

    response = client.get(f"/api/users/{user_id}/exposure/graph")
    data = response.json()["data"]
    for node in data["nodes"]:
        assert "password" not in str(node).lower()
        assert "oauth" not in str(node).lower()
        assert "token" not in str(node).lower()
    for edge in data["edges"]:
        assert "secret.backup@example.com" not in str(edge).lower()
        assert "+" not in str(edge).lower() or "RECOVERY_PHONE" not in str(edge).lower()
