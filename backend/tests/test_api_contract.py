from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.database.database import SessionLocal
from app.main import app
from app.models.models import (
    Account,
    AccountConnection,
    AccountPhoneNumber,
    AccountRecoveryEmail,
    AppPermission,
    BreachEvent,
    FixItem,
    Notification,
    PhoneNumber,
    Reminder,
    RecoveryEmail,
    RiskFactor,
    RiskSnapshot,
    Severity,
)


client = TestClient(app)
AS_OF = "2026-10-01"


def _create_user() -> str:
    response = client.post(
        "/api/users",
        json={"name": "Contract User", "email": f"contract-{uuid4().hex}@example.com"},
    )
    assert response.status_code == 200
    return response.json()["data"]["id"]


def _create_service() -> str:
    response = client.post(
        "/api/services",
        json={"name": f"Contract Service {uuid4().hex}", "category": "PRODUCTIVITY", "website": "https://example.com"},
    )
    assert response.status_code == 200
    return response.json()["data"]["id"]


def _create_account(user_id: str, service_id: str, **overrides: object) -> str:
    payload: dict[str, object] = {
        "user_id": user_id,
        "service_id": service_id,
        "account_identifier": f"contract-account-{uuid4().hex}@example.com",
        "display_name": "Contract account",
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


def _count_for_user(model: type, user_id: str) -> int:
    with SessionLocal() as db:
        return int(db.scalar(select(func.count()).select_from(model).where(model.user_id == user_id)) or 0)


def _count_user_risk_factors(user_id: str) -> int:
    with SessionLocal() as db:
        query = select(func.count(RiskFactor.id)).join(Account).where(Account.user_id == user_id)
        return int(db.scalar(query) or 0)


def _count_user_connections(user_id: str) -> int:
    with SessionLocal() as db:
        query = (
            select(func.count(AccountConnection.id))
            .join(Account, Account.id == AccountConnection.source_account_id)
            .where(Account.user_id == user_id)
        )
        return int(db.scalar(query) or 0)


def _count_user_permissions(user_id: str) -> int:
    with SessionLocal() as db:
        query = select(func.count(AppPermission.id)).join(Account).where(Account.user_id == user_id)
        return int(db.scalar(query) or 0)


def _count_user_breaches(user_id: str) -> int:
    with SessionLocal() as db:
        query = select(func.count(BreachEvent.id)).join(Account).where(Account.user_id == user_id)
        return int(db.scalar(query) or 0)


def _count_user_links(model: type, account_link: bool, user_id: str) -> int:
    with SessionLocal() as db:
        query = select(func.count(model.id))
        if account_link:
            query = query.join(Account, Account.id == model.account_id).where(Account.user_id == user_id)
        else:
            query = query.where(model.user_id == user_id)
        return int(db.scalar(query) or 0)


def test_frontend_contract_flow_and_openapi_inventory() -> None:
    user_id = _create_user()
    other_user_id = _create_user()
    service_id = _create_service()
    other_service_id = _create_service()
    account_id = _create_account(user_id, service_id)
    second_account_id = _create_account(user_id, service_id)
    other_account_id = _create_account(other_user_id, other_service_id)
    with SessionLocal() as db:
        db.add_all(
            [
                BreachEvent(service_id=service_id, account_id=account_id, title="first private event", severity=Severity.HIGH),
                BreachEvent(service_id=service_id, account_id=account_id, title="second private event", severity=Severity.CRITICAL),
            ]
        )
        db.commit()

    account_list = client.get(f"/api/users/{user_id}/accounts")
    assert account_list.status_code == 200
    assert {item["id"] for item in account_list.json()["data"]["items"]} == {account_id, second_account_id}

    graph = client.get(f"/api/users/{user_id}/exposure/graph")
    metrics = client.get(f"/api/users/{user_id}/exposure/metrics")
    path = client.get(f"/api/users/{user_id}/exposure/path?source_account_id={account_id}&target_account_id={second_account_id}")
    assert graph.status_code == metrics.status_code == path.status_code == 200
    assert other_account_id not in json.dumps(graph.json())
    assert len(metrics.json()["data"]) == 2

    assert client.get(f"/api/accounts/{account_id}/risk").status_code == 200
    assert client.get(f"/api/users/{user_id}/risk").status_code == 200
    first_risk = client.get(f"/api/users/{user_id}/risk").json()["data"]
    second_risk = client.get(f"/api/users/{user_id}/risk").json()["data"]
    assert first_risk["risk_ranking"] == second_risk["risk_ranking"]
    assert client.post(f"/api/users/{user_id}/risk/calculate").status_code == 200
    assert client.get(f"/api/users/{user_id}/risk/history").status_code == 200
    assert client.get(f"/api/users/{user_id}/risk/explanations").status_code == 200
    assert client.get(f"/api/accounts/{account_id}/risk/explanations").status_code == 200
    assert client.get(f"/api/users/{user_id}/remediation").status_code == 200
    assert client.get(f"/api/accounts/{account_id}/remediation").status_code == 200
    assert client.get(f"/api/users/{user_id}/hygiene?as_of={AS_OF}").status_code == 200
    assert client.get(f"/api/accounts/{account_id}/hygiene?as_of={AS_OF}").status_code == 200
    assert client.get(f"/api/users/{user_id}/notifications?as_of={AS_OF}").status_code == 200
    assert client.get(f"/api/accounts/{account_id}/notifications?as_of={AS_OF}").status_code == 200
    assert client.get(f"/api/users/{user_id}/breaches").status_code == 200
    assert client.get(f"/api/accounts/{account_id}/breaches").status_code == 200

    schema = client.get("/openapi.json").json()
    paths = schema["paths"]
    expected_paths = {
        "/health": {"get"},
        "/api/health": {"get"},
        "/api/users": {"post"},
        "/api/users/{user_id}": {"get", "patch", "delete"},
        "/api/services": {"get", "post"},
        "/api/services/{service_id}": {"get", "patch", "delete"},
        "/api/accounts": {"post"},
        "/api/accounts/{account_id}": {"get", "patch", "delete"},
        "/api/users/{user_id}/accounts": {"get"},
        "/api/users/{user_id}/footprint": {"get"},
        "/api/accounts/{account_id}/permissions": {"get", "post"},
        "/api/permissions/{permission_id}": {"patch", "delete"},
        "/api/recovery/emails": {"post"},
        "/api/recovery/emails/{email_id}": {"get", "patch", "delete"},
        "/api/recovery/phones": {"post"},
        "/api/recovery/phones/{phone_id}": {"patch", "delete"},
        "/api/recovery/users/{user_id}/recovery-emails": {"get"},
        "/api/recovery/users/{user_id}/recovery-phones": {"get"},
        "/api/accounts/{account_id}/recovery-email/{email_id}": {"post", "delete"},
        "/api/accounts/{account_id}/recovery-phone/{phone_id}": {"post", "delete"},
        "/api/connections": {"post"},
        "/api/connections/{connection_id}": {"get", "delete"},
        "/api/users/{user_id}/connections": {"get"},
        "/api/users/{user_id}/exposure/graph": {"get"},
        "/api/users/{user_id}/exposure/metrics": {"get"},
        "/api/users/{user_id}/exposure/path": {"get"},
        "/api/users/{user_id}/risk/calculate": {"post"},
        "/api/accounts/{account_id}/risk": {"get"},
        "/api/users/{user_id}/risk": {"get"},
        "/api/users/{user_id}/risk/history": {"get"},
        "/api/users/{user_id}/risk/explanations": {"get"},
        "/api/accounts/{account_id}/risk/explanations": {"get"},
        "/api/users/{user_id}/remediation": {"get"},
        "/api/accounts/{account_id}/remediation": {"get"},
        "/api/users/{user_id}/hygiene": {"get"},
        "/api/accounts/{account_id}/hygiene": {"get"},
        "/api/users/{user_id}/notifications": {"get"},
        "/api/accounts/{account_id}/notifications": {"get"},
        "/api/users/{user_id}/breaches": {"get"},
        "/api/accounts/{account_id}/breaches": {"get"},
    }
    for path_template, methods in expected_paths.items():
        assert methods.issubset(paths[path_template])
    assert "/api/hello" not in paths
    user_create_schema = paths["/api/users"]["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    assert user_create_schema.endswith("/UserCreate")
    account_list_parameters = {item["name"] for item in paths["/api/users/{user_id}/accounts"]["get"]["parameters"]}
    assert {"service_id", "status", "two_factor_enabled", "sign_in_method", "is_active", "page", "limit"}.issubset(account_list_parameters)
    assert paths["/api/users/{user_id}/hygiene"]["get"]["parameters"][0]["name"] in {"user_id", "as_of"}
    explanations_schema = paths["/api/users/{user_id}/risk/explanations"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    remediation_schema = paths["/api/users/{user_id}/remediation"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    hygiene_schema = paths["/api/users/{user_id}/hygiene"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    notifications_schema = paths["/api/users/{user_id}/notifications"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    assert explanations_schema.endswith("/UserRiskExplanationApiResponse")
    assert remediation_schema.endswith("/UserRemediationApiResponse")
    assert hygiene_schema.endswith("/UserHygieneResponse")
    assert notifications_schema.endswith("/UserNotificationsResponse")
    schema_text = json.dumps(schema).lower()
    for forbidden in ("password_hash", "hashed_password", "api_key", "access_token", "refresh_token", "groq_api_key"):
        assert forbidden not in schema_text
    property_names = {
        name
        for node in schema.get("components", {}).get("schemas", {}).values()
        if isinstance(node, dict)
        for name in node.get("properties", {})
    }
    assert "password" not in property_names
    schemas = schema["components"]["schemas"]
    assert "RecoveryEmailResponse" not in schemas
    assert "PhoneNumberResponse" not in schemas


def test_read_only_analysis_gets_do_not_write_and_are_user_scoped() -> None:
    user_id = _create_user()
    other_user_id = _create_user()
    service_id = _create_service()
    account_id = _create_account(user_id, service_id)
    second_account_id = _create_account(user_id, service_id)
    other_account = _create_account(other_user_id, _create_service())
    with SessionLocal() as db:
        db.add(
            BreachEvent(
                service_id=service_id,
                account_id=account_id,
                title="private breach title",
                description="private breach payload",
                severity="HIGH",
            )
        )
        db.commit()

    persisted_models = (FixItem, Notification, Reminder, RiskSnapshot, RecoveryEmail, PhoneNumber)
    before = {model.__name__: _count_for_user(model, user_id) for model in persisted_models}
    before["RiskFactor"] = _count_user_risk_factors(user_id)
    before["AppPermission"] = _count_user_permissions(user_id)
    before["BreachEvent"] = _count_user_breaches(user_id)
    before["AccountConnection"] = _count_user_connections(user_id)
    before["AccountRecoveryEmail"] = _count_user_links(AccountRecoveryEmail, True, user_id)
    before["AccountPhoneNumber"] = _count_user_links(AccountPhoneNumber, True, user_id)
    history_before = client.get(f"/api/users/{user_id}/risk/history").json()["data"]

    requests = [
        f"/api/accounts/{account_id}/risk",
        f"/api/users/{user_id}/risk",
        f"/api/users/{user_id}/risk/history",
        f"/api/users/{user_id}/risk/explanations",
        f"/api/accounts/{account_id}/risk/explanations",
        f"/api/users/{user_id}/remediation",
        f"/api/accounts/{account_id}/remediation",
        f"/api/users/{user_id}/hygiene?as_of={AS_OF}",
        f"/api/accounts/{account_id}/hygiene?as_of={AS_OF}",
        f"/api/users/{user_id}/notifications?as_of={AS_OF}",
        f"/api/accounts/{account_id}/notifications?as_of={AS_OF}",
        f"/api/users/{user_id}/exposure/graph",
        f"/api/users/{user_id}/exposure/metrics",
        f"/api/users/{user_id}/exposure/path?source_account_id={account_id}&target_account_id={second_account_id}",
        f"/api/users/{user_id}/breaches",
        f"/api/accounts/{account_id}/breaches",
        f"/api/users/{user_id}/footprint",
        f"/api/users/{user_id}/accounts",
        f"/api/users/{user_id}/connections",
        f"/api/recovery/users/{user_id}/recovery-emails",
        f"/api/recovery/users/{user_id}/recovery-phones",
    ]
    bodies = []
    for path in requests:
        response = client.get(path)
        assert response.status_code == 200, path
        bodies.append(response.text)

    after = {model.__name__: _count_for_user(model, user_id) for model in persisted_models}
    after["RiskFactor"] = _count_user_risk_factors(user_id)
    after["AppPermission"] = _count_user_permissions(user_id)
    after["BreachEvent"] = _count_user_breaches(user_id)
    after["AccountConnection"] = _count_user_connections(user_id)
    after["AccountRecoveryEmail"] = _count_user_links(AccountRecoveryEmail, True, user_id)
    after["AccountPhoneNumber"] = _count_user_links(AccountPhoneNumber, True, user_id)
    assert before == after
    assert client.get(f"/api/users/{user_id}/risk/history").json()["data"] == history_before
    assert other_account not in "".join(bodies)
    assert "private breach title" not in "".join(bodies)
    assert "private breach payload" not in "".join(bodies)


def test_permission_path_scope_filtered_totals_and_missing_resource_contracts() -> None:
    user_id = _create_user()
    service_id = _create_service()
    first_account = _create_account(user_id, service_id)
    second_account = _create_account(user_id, service_id, two_factor_enabled=True)
    other_user = _create_user()
    other_account = _create_account(other_user, _create_service())

    mismatch = client.post(
        f"/api/accounts/{first_account}/permissions",
        json={"account_id": other_account, "permission_type": "UNSAFE_OVERRIDE", "granted": True},
    )
    assert mismatch.status_code == 400
    assert mismatch.json()["error"]["code"] == "ACCOUNT_MISMATCH"

    filtered = client.get(f"/api/users/{user_id}/accounts?two_factor_enabled=true")
    assert filtered.status_code == 200
    assert filtered.json()["data"]["total"] == 1
    assert [item["id"] for item in filtered.json()["data"]["items"]] == [second_account]

    owner_graph = client.get(f"/api/users/{user_id}/exposure/graph").json()["data"]
    assert other_account not in json.dumps(owner_graph)
    cross_user_path = client.get(
        f"/api/users/{user_id}/exposure/path?source_account_id={first_account}&target_account_id={other_account}"
    )
    assert cross_user_path.status_code == 400

    missing_user = client.get("/api/users/not-a-real-user/hygiene")
    missing_account = client.get("/api/accounts/not-a-real-account/breaches")
    missing_breach_user = client.get("/api/users/not-a-real-user/breaches")
    missing_service = client.get("/api/services/not-a-real-service")
    invalid_body = client.post("/api/users", json={"name": "bad"})
    assert missing_user.status_code == missing_account.status_code == missing_breach_user.status_code == missing_service.status_code == 404
    assert all(response.json()["success"] is False and "error" in response.json() for response in (missing_user, missing_account, missing_breach_user, missing_service))
    assert invalid_body.status_code == 422
    assert invalid_body.json()["error"]["code"] == "VALIDATION_ERROR"