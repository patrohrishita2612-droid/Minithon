from __future__ import annotations

from datetime import datetime, timezone, timedelta
from app.database.database import SessionLocal, init_db
from app.models.models import (
    User, Service, Account, ServiceCategory, AccountStatus, SignInMethod,
    AppPermission, PermissionSensitivity, AccountConnection, ConnectionType
)
from app.algorithms.risk_engine import calculate_and_persist_user_risk


def seed_demo_data() -> User:
    init_db()
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == "demo@company.com").first()
        if user:
            return user.id, user.name

        user = User(name="Demo User", email="demo@company.com")
        db.add(user)
        db.commit()
        db.refresh(user)

        # Services
        s_g = Service(name="Google", category=ServiceCategory.EMAIL, website="https://google.com")
        s_m = Service(name="Microsoft", category=ServiceCategory.PRODUCTIVITY, website="https://microsoft.com")
        s_s = Service(name="Spotify", category=ServiceCategory.ENTERTAINMENT, website="https://spotify.com")
        s_a = Service(name="Amazon", category=ServiceCategory.SHOPPING, website="https://amazon.com")
        s_gh = Service(name="GitHub", category=ServiceCategory.DEVELOPMENT, website="https://github.com")
        db.add_all([s_g, s_m, s_s, s_a, s_gh])
        db.commit()

        now = datetime.now(timezone.utc)
        # Accounts
        a_g = Account(
            user_id=user.id,
            service_id=s_g.id,
            account_identifier="demo@google.com",
            display_name="Google",
            two_factor_enabled=False,
            password_reuse_group_id="reuse-group-1",
            status=AccountStatus.ACTIVE,
            last_activity=now,
        )
        a_m = Account(
            user_id=user.id,
            service_id=s_m.id,
            account_identifier="demo@microsoft.com",
            display_name="Microsoft",
            two_factor_enabled=True,
            password_reuse_group_id=None,
            status=AccountStatus.ACTIVE,
            last_activity=now - timedelta(days=1),
        )
        a_s = Account(
            user_id=user.id,
            service_id=s_s.id,
            account_identifier="demo@spotify.com",
            display_name="Spotify",
            two_factor_enabled=False,
            password_reuse_group_id="reuse-group-1",
            status=AccountStatus.ACTIVE,
            last_activity=now - timedelta(days=2),
        )
        a_a = Account(
            user_id=user.id,
            service_id=s_a.id,
            account_identifier="demo@amazon.com",
            display_name="Amazon",
            two_factor_enabled=False,
            password_reuse_group_id="reuse-group-1",
            status=AccountStatus.ACTIVE,
            last_activity=now - timedelta(days=4),
        )
        a_gh = Account(
            user_id=user.id,
            service_id=s_gh.id,
            account_identifier="demo@github.com",
            display_name="GitHub",
            two_factor_enabled=True,
            password_reuse_group_id=None,
            status=AccountStatus.ACTIVE,
            last_activity=now - timedelta(days=5),
        )
        db.add_all([a_g, a_m, a_s, a_a, a_gh])
        db.commit()

        # Permissions
        p1 = AppPermission(account_id=a_g.id, permission_type="Broad account access", sensitivity=PermissionSensitivity.HIGH)
        p2 = AppPermission(account_id=a_m.id, permission_type="Calendar + profile", sensitivity=PermissionSensitivity.MEDIUM)
        p3 = AppPermission(account_id=a_s.id, permission_type="Profile + playback", sensitivity=PermissionSensitivity.LOW)
        p4 = AppPermission(account_id=a_a.id, permission_type="Broad account access", sensitivity=PermissionSensitivity.HIGH)
        db.add_all([p1, p2, p3, p4])
        db.commit()

        # Connections
        c1 = AccountConnection(source_account_id=a_g.id, target_account_id=a_s.id, connection_type=ConnectionType.SSO, description="Google SSO")
        c2 = AccountConnection(source_account_id=a_g.id, target_account_id=a_gh.id, connection_type=ConnectionType.SSO, description="Google OAuth")
        db.add_all([c1, c2])
        db.commit()

        # Initial risk audit snapshot
        calculate_and_persist_user_risk(db, user.id)
        user_id = user.id
        user_name = user.name
        return user_id, user_name


if __name__ == "__main__":
    u_id, u_name = seed_demo_data()
    print(f"Seed completed for user: {u_name} ({u_id})")
