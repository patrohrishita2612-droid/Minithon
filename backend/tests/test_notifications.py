from __future__ import annotations

import json
from datetime import date, datetime, time, timedelta, timezone
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.database.database import SessionLocal
from app.main import app
from app.models.models import Account, BreachEvent, Notification, NotificationType, Severity


client = TestClient(app)
AS_OF = date(2026, 10, 1)


def _create_user() -> str:
    suffix = uuid4().hex
    response = client.post("/api/users", json={"name": "Notification User", "email": f"notice-{suffix}@example.com"})
    assert response.status_code == 200
    return response.json()["data"]["id"]


def _create_service() -> str:
    suffix = uuid4().hex
    response = client.post(
        "/api/services",
        json={"name": f"Notification Service {suffix}", "category": "PRODUCTIVITY", "website": "https://example.com"},
    )
    assert response.status_code == 200
    return response.json()["data"]["id"]


def _create_account(user_id: str, service_id: str, **overrides: object) -> str:
    payload: dict[str, object] = {
        "user_id": user_id,
        "service_id": service_id,
        "account_identifier": f"secret-identifier-{uuid4().hex}@example.com",
        "display_name": "Safe display label",
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


def _set_activity(account_id: str, days_ago: int | None) -> None:
    with SessionLocal() as db:
        account = db.get(Account, account_id)
        assert account is not None
        account.last_activity = (
            datetime.combine(AS_OF - timedelta(days=days_ago), time.min, tzinfo=timezone.utc)
            if days_ago is not None
            else None
        )
        db.commit()


def _count_notifications(user_id: str) -> int:
    with SessionLocal() as db:
        return int(db.scalar(select(func.count()).select_from(Notification).where(Notification.user_id == user_id)) or 0)


def _add_breach(user_id: str, account_id: str, service_id: str, severity: Severity = Severity.HIGH) -> str:
    with SessionLocal() as db:
        event = BreachEvent(
            service_id=service_id,
            account_id=account_id,
            title="private breach title must not leak",
            description="private breach payload must not leak",
            severity=severity,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event.id


def test_user_and_account_notification_endpoints_and_openapi() -> None:
    user_id = _create_user()
    service_id = _create_service()
    account_id = _create_account(user_id, service_id)
    _add_breach(user_id, account_id, service_id)

    user_response = client.get(f"/api/users/{user_id}/notifications?as_of={AS_OF.isoformat()}")
    account_response = client.get(f"/api/accounts/{account_id}/notifications?as_of={AS_OF.isoformat()}")
    assert user_response.status_code == account_response.status_code == 200
    assert user_response.json()["data"]["user_id"] == user_id
    assert account_response.json()["data"]["account_id"] == account_id
    assert account_response.json()["data"]["service"] == {"id": service_id, "name": account_response.json()["data"]["service"]["name"]}
    paths = client.get("/openapi.json").json()["paths"]
    assert "/api/users/{user_id}/notifications" in paths
    assert "/api/accounts/{account_id}/notifications" in paths
    assert client.get("/health").status_code == 200


def test_missing_user_and_account_preserve_404_contract() -> None:
    user_response = client.get("/api/users/missing-user/notifications")
    account_response = client.get("/api/accounts/missing-account/notifications")
    assert user_response.status_code == 404
    assert user_response.json()["error"]["code"] == "USER_NOT_FOUND"
    assert account_response.status_code == 404
    assert account_response.json()["error"]["code"] == "ACCOUNT_NOT_FOUND"


def test_breach_and_stale_alerts_use_only_supported_hygiene_data() -> None:
    user_id = _create_user()
    service_id = _create_service()
    stale_account = _create_account(user_id, service_id)
    unknown_account = _create_account(user_id, service_id, last_activity=None)
    old_inventory_only = _create_account(user_id, service_id)
    _set_activity(stale_account, 181)
    _set_activity(unknown_account, None)
    with SessionLocal() as db:
        inventory_account = db.get(Account, old_inventory_only)
        assert inventory_account is not None
        inventory_account.created_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
        db.commit()
    _add_breach(user_id, stale_account, service_id)

    data = client.get(f"/api/users/{user_id}/notifications?as_of={AS_OF.isoformat()}").json()["data"]
    stale = [item for item in data["notifications"] if item["account_id"] == stale_account]
    unknown = [item for item in data["notifications"] if item["account_id"] == unknown_account]
    old_inventory = [item for item in data["notifications"] if item["account_id"] == old_inventory_only]
    assert "BREACH_ALERT" in {item["type"] for item in stale}
    assert "STALE_ACCOUNT_ALERT" in {item["type"] for item in stale}
    assert all(item["reason_code"] != "ACTIVITY_UNKNOWN" for item in data["notifications"])
    assert "STALE_ACCOUNT_ALERT" not in {item["type"] for item in unknown}
    assert "STALE_ACCOUNT_ALERT" not in {item["type"] for item in old_inventory}


def test_risk_and_structural_alerts_use_existing_risk_engine_results() -> None:
    user_id = _create_user()
    service_id = _create_service()
    accounts = [_create_account(user_id, service_id) for _ in range(4)]
    for source, target in zip(accounts, accounts[1:]):
        response = client.post(
            "/api/connections",
            json={"source_account_id": source, "target_account_id": target, "connection_type": "CONNECTED_SERVICE", "is_active": True},
        )
        assert response.status_code == 200
    _add_breach(user_id, accounts[1], service_id, Severity.CRITICAL)
    _set_activity(accounts[1], 181)
    for index in range(3):
        permission = client.post(
            f"/api/accounts/{accounts[1]}/permissions",
            json={
                "permission_type": f"HIGH_IMPACT_{index}",
                "sensitivity": "CRITICAL",
                "granted": True,
            },
        )
        assert permission.status_code == 200
    _add_breach(user_id, accounts[0], service_id, Severity.CRITICAL)
    for index in range(3):
        permission = client.post(
            f"/api/accounts/{accounts[0]}/permissions",
            json={
                "permission_type": f"HIGH_RISK_ENDPOINT_{index}",
                "sensitivity": "CRITICAL",
                "granted": True,
            },
        )
        assert permission.status_code == 200

    data = client.get(f"/api/users/{user_id}/notifications?as_of={AS_OF.isoformat()}").json()["data"]
    types = {item["type"] for item in data["notifications"]}
    assert "CRITICAL_RISK_ALERT" in types
    assert "HIGH_RISK_ALERT" in types
    assert "STRUCTURAL_RISK_ALERT" in types
    breach_alerts = [item for item in data["notifications"] if item["type"] == "BREACH_ALERT"]
    assert len(breach_alerts) == 2


def test_permission_review_and_high_critical_remediation_alerts() -> None:
    user_id = _create_user()
    service_id = _create_service()
    account_id = _create_account(user_id, service_id, last_activity="2020-01-01T00:00:00Z")
    permission = client.post(
        f"/api/accounts/{account_id}/permissions",
        json={"permission_type": "PRIVATE_PERMISSION_NAME", "description": "private permission detail", "sensitivity": "CRITICAL", "granted": True},
    )
    assert permission.status_code == 200

    data = client.get(f"/api/users/{user_id}/notifications?as_of={AS_OF.isoformat()}").json()["data"]
    candidates = [item for item in data["notifications"] if item["account_id"] == account_id]
    assert "PERMISSION_REVIEW_ALERT" in {item["type"] for item in candidates}
    assert "REMEDIATION_ALERT" in {item["type"] for item in candidates}
    assert all(item["severity"] in {"CRITICAL", "HIGH"} for item in candidates if item["type"] == "REMEDIATION_ALERT")


def test_notifications_are_deterministic_deduplicated_and_get_is_read_only() -> None:
    user_id = _create_user()
    service_id = _create_service()
    account_id = _create_account(user_id, service_id)
    _add_breach(user_id, account_id, service_id)
    before = _count_notifications(user_id)

    first = client.get(f"/api/users/{user_id}/notifications?as_of={AS_OF.isoformat()}")
    second = client.get(f"/api/users/{user_id}/notifications?as_of={AS_OF.isoformat()}")
    after = _count_notifications(user_id)
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert before == after
    notifications = first.json()["data"]["notifications"]
    candidate_keys = [item["candidate_key"] for item in notifications]
    assert len(candidate_keys) == len(set(candidate_keys))
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    expected = sorted(
        notifications,
        key=lambda item: (
            severity_order[item["severity"]],
            -(item["risk_contribution"] or 0.0),
            item["type"],
            item["account_id"],
            item["service_id"],
            item["reason_code"],
            item["candidate_key"],
        ),
    )
    assert notifications == expected


def test_user_isolation_secret_exclusion_and_existing_read_status_merge() -> None:
    owner = _create_user()
    owner_service = _create_service()
    owner_account = _create_account(owner, owner_service, password_reuse_group_id="private-reuse-group")
    breach_id = _add_breach(owner, owner_account, owner_service)
    other_user = _create_user()
    other_account = _create_account(other_user, _create_service())

    with SessionLocal() as db:
        stored = Notification(
            user_id=owner,
            account_id=owner_account,
            breach_event_id=breach_id,
            type=NotificationType.BREACH_ALERT,
            title="Breach event recorded",
            message="secret message body must not be returned",
            is_read=True,
            created_at=datetime(2026, 9, 30, tzinfo=timezone.utc),
        )
        db.add(stored)
        db.commit()

    data = client.get(f"/api/users/{owner}/notifications?as_of={AS_OF.isoformat()}").json()["data"]
    encoded = json.dumps(data)
    assert other_account not in encoded
    for value in ("secret-identifier-", "private-reuse-group", "private breach title", "private breach payload", "secret message body"):
        assert value not in encoded
    persisted_match = next(item for item in data["notifications"] if item["type"] == "BREACH_ALERT")
    assert persisted_match["is_read"] is True
    assert persisted_match["notification_id"] is not None
    assert persisted_match["created_at"] == "2026-09-30T00:00:00"