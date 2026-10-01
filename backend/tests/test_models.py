from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.database.base import Base
from app.models.models import (
    Account,
    AccountConnection,
    AccountPhoneNumber,
    AccountRecoveryEmail,
    AccountStatus,
    AppPermission,
    ConnectionType,
    FixItem,
    FixType,
    PasswordStrength,
    RecoveryEmail,
    RiskFactor,
    RiskFactorType,
    RiskLevel,
    RiskSnapshot,
    Service,
    ServiceCategory,
    SignInMethod,
    User,
)


@pytest.fixture
def db_session() -> Session:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, future=True)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


def test_user_can_be_created(db_session: Session) -> None:
    user = User(name="Test User", email="user@example.com")
    db_session.add(user)
    db_session.commit()

    saved_user = db_session.query(User).filter_by(email="user@example.com").one()
    assert saved_user.name == "Test User"
    assert saved_user.id is not None


def test_service_can_be_created(db_session: Session) -> None:
    service = Service(name="GitHub", category=ServiceCategory.DEVELOPMENT, website="https://github.com")
    db_session.add(service)
    db_session.commit()

    saved_service = db_session.query(Service).filter_by(name="GitHub").one()
    assert saved_service.category == ServiceCategory.DEVELOPMENT


def test_account_can_belong_to_user_and_service(db_session: Session) -> None:
    user = User(name="Account Owner", email="owner@example.com")
    service = Service(name="Google", category=ServiceCategory.EMAIL)
    account = Account(
        user=user,
        service=service,
        account_identifier="owner@gmail.com",
        display_name="Owner",
        status=AccountStatus.ACTIVE,
        sign_in_method=SignInMethod.GOOGLE_SSO,
        two_factor_enabled=True,
        password_strength=PasswordStrength.STRONG,
        password_reuse_group_id="reuse-group-1",
    )

    db_session.add_all([user, service, account])
    db_session.commit()

    saved_account = db_session.query(Account).filter_by(account_identifier="owner@gmail.com").one()
    assert saved_account.user_id == user.id
    assert saved_account.service_id == service.id


def test_account_can_have_app_permissions(db_session: Session) -> None:
    user = User(name="Perm User", email="perm@example.com")
    service = Service(name="Instagram", category=ServiceCategory.SOCIAL_MEDIA)
    account = Account(user=user, service=service, account_identifier="permuser", display_name="Perm User")
    permission = AppPermission(
        account=account,
        permission_type="PHOTOS",
        description="Access to profile photos",
        granted=True,
    )

    db_session.add_all([user, service, account, permission])
    db_session.commit()

    saved_permission = db_session.query(AppPermission).filter_by(account_id=account.id).one()
    assert saved_permission.permission_type == "PHOTOS"


def test_two_accounts_can_be_connected(db_session: Session) -> None:
    user = User(name="Linked User", email="linked@example.com")
    google_service = Service(name="Google", category=ServiceCategory.EMAIL)
    github_service = Service(name="GitHub", category=ServiceCategory.DEVELOPMENT)
    google_account = Account(user=user, service=google_service, account_identifier="google-user", display_name="Google")
    github_account = Account(user=user, service=github_service, account_identifier="github-user", display_name="GitHub")
    connection = AccountConnection(
        source_account=google_account,
        target_account=github_account,
        connection_type=ConnectionType.SSO,
        description="Google SSO connects to GitHub-ish account",
    )

    db_session.add_all([user, google_service, github_service, google_account, github_account, connection])
    db_session.commit()

    saved_connection = db_session.query(AccountConnection).filter_by(source_account_id=google_account.id).one()
    assert saved_connection.target_account_id == github_account.id
    assert saved_connection.connection_type == ConnectionType.SSO


def test_self_connections_are_rejected(db_session: Session) -> None:
    user = User(name="Self User", email="self@example.com")
    service = Service(name="Discord", category=ServiceCategory.COMMUNICATION)
    account = Account(user=user, service=service, account_identifier="self-user")
    connection = AccountConnection(
        source_account=account,
        target_account=account,
        connection_type=ConnectionType.CONNECTED_SERVICE,
    )

    with pytest.raises(ValueError, match="cannot connect to itself"):
        connection.validate()


def test_account_connection_cannot_link_different_users(db_session: Session) -> None:
    user_a = User(name="A", email="a@example.com")
    user_b = User(name="B", email="b@example.com")
    service_a = Service(name="Slack", category=ServiceCategory.COMMUNICATION)
    service_b = Service(name="Dropbox", category=ServiceCategory.CLOUD_STORAGE)
    account_a = Account(user=user_a, service=service_a, account_identifier="a-account")
    account_b = Account(user=user_b, service=service_b, account_identifier="b-account")
    connection = AccountConnection(
        source_account=account_a,
        target_account=account_b,
        connection_type=ConnectionType.CONNECTED_SERVICE,
    )

    with pytest.raises(ValueError, match="different users"):
        connection.validate()


def test_recovery_email_can_be_associated_with_a_user_and_account(db_session: Session) -> None:
    user = User(name="Recovery User", email="recovery@example.com")
    service = Service(name="Microsoft", category=ServiceCategory.PRODUCTIVITY)
    account = Account(user=user, service=service, account_identifier="microsoft-user")
    recovery_email = RecoveryEmail(user=user, email="backup@example.com", is_primary=True, is_verified=True)
    link = AccountRecoveryEmail(account=account, recovery_email=recovery_email)

    db_session.add_all([user, service, account, recovery_email, link])
    db_session.commit()

    saved_link = db_session.query(AccountRecoveryEmail).filter_by(account_id=account.id).one()
    assert saved_link.recovery_email.email == "backup@example.com"


def test_fix_item_can_be_associated_with_account(db_session: Session) -> None:
    user = User(name="Fix User", email="fix@example.com")
    service = Service(name="Amazon", category=ServiceCategory.SHOPPING)
    account = Account(user=user, service=service, account_identifier="amazon-user")
    fix_item = FixItem(
        user=user,
        account=account,
        type=FixType.ENABLE_2FA,
        title="Enable 2FA",
        description="Add stronger login protection",
    )

    db_session.add_all([user, service, account, fix_item])
    db_session.commit()

    saved_fix = db_session.query(FixItem).filter_by(account_id=account.id).one()
    assert saved_fix.title == "Enable 2FA"


def test_risk_snapshot_can_be_stored(db_session: Session) -> None:
    user = User(name="Risk User", email="risk@example.com")
    snapshot = RiskSnapshot(
        user=user,
        overall_score=74,
        risk_level=RiskLevel.HIGH,
        total_accounts=6,
        high_risk_accounts=2,
        critical_accounts=1,
        open_fix_count=4,
        single_point_count=3,
    )

    db_session.add_all([user, snapshot])
    db_session.commit()

    saved_snapshot = db_session.query(RiskSnapshot).filter_by(user_id=user.id).one()
    assert saved_snapshot.overall_score == 74
    assert saved_snapshot.risk_level == RiskLevel.HIGH


def test_account_model_has_no_plaintext_password_field() -> None:
    assert "password" not in Account.__table__.columns.keys()
