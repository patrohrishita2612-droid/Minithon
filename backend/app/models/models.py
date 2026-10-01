from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from sqlalchemy import DateTime, Enum as SAEnum, ForeignKey, Index, String, Text, UniqueConstraint, event
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class ServiceCategory(str, Enum):
    SOCIAL_MEDIA = "SOCIAL_MEDIA"
    EMAIL = "EMAIL"
    CLOUD_STORAGE = "CLOUD_STORAGE"
    DEVELOPMENT = "DEVELOPMENT"
    FINANCE = "FINANCE"
    SHOPPING = "SHOPPING"
    ENTERTAINMENT = "ENTERTAINMENT"
    PRODUCTIVITY = "PRODUCTIVITY"
    COMMUNICATION = "COMMUNICATION"
    EDUCATION = "EDUCATION"
    HEALTH = "HEALTH"
    OTHER = "OTHER"


class AccountStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    DELETED = "DELETED"
    UNKNOWN = "UNKNOWN"


class SignInMethod(str, Enum):
    PASSWORD = "PASSWORD"
    GOOGLE_SSO = "GOOGLE_SSO"
    MICROSOFT_SSO = "MICROSOFT_SSO"
    APPLE_SSO = "APPLE_SSO"
    PHONE = "PHONE"
    MAGIC_LINK = "MAGIC_LINK"
    OTHER = "OTHER"


class PasswordStrength(str, Enum):
    UNKNOWN = "UNKNOWN"
    WEAK = "WEAK"
    MEDIUM = "MEDIUM"
    STRONG = "STRONG"


class ConnectionType(str, Enum):
    RECOVERY_EMAIL = "RECOVERY_EMAIL"
    RECOVERY_PHONE = "RECOVERY_PHONE"
    SHARED_PASSWORD = "SHARED_PASSWORD"
    SSO = "SSO"
    CONNECTED_SERVICE = "CONNECTED_SERVICE"
    OTHER = "OTHER"


class PermissionSensitivity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FixType(str, Enum):
    ENABLE_2FA = "ENABLE_2FA"
    CHANGE_REUSED_PASSWORD = "CHANGE_REUSED_PASSWORD"
    REMOVE_PERMISSION = "REMOVE_PERMISSION"
    DELETE_UNUSED_ACCOUNT = "DELETE_UNUSED_ACCOUNT"
    REVIEW_RECOVERY_METHOD = "REVIEW_RECOVERY_METHOD"
    REVIEW_SSO = "REVIEW_SSO"
    OTHER = "OTHER"


class FixPriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FixStatus(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    DISMISSED = "DISMISSED"


class ReminderType(str, Enum):
    PRIVACY_REVIEW = "PRIVACY_REVIEW"
    PASSWORD_REVIEW = "PASSWORD_REVIEW"
    PERMISSION_REVIEW = "PERMISSION_REVIEW"
    BREACH_FOLLOWUP = "BREACH_FOLLOWUP"
    OTHER = "OTHER"


class ReminderStatus(str, Enum):
    PENDING = "PENDING"
    SENT = "SENT"
    COMPLETED = "COMPLETED"
    DISMISSED = "DISMISSED"


class NotificationType(str, Enum):
    BREACH_ALERT = "BREACH_ALERT"
    RISK_ALERT = "RISK_ALERT"
    REMINDER = "REMINDER"
    FIX_REQUIRED = "FIX_REQUIRED"
    SYSTEM = "SYSTEM"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskFactorType(str, Enum):
    NO_2FA = "NO_2FA"
    PASSWORD_REUSE = "PASSWORD_REUSE"
    HIGH_PERMISSION = "HIGH_PERMISSION"
    RECOVERY_CENTRALITY = "RECOVERY_CENTRALITY"
    SSO_DEPENDENCY = "SSO_DEPENDENCY"
    BREACH = "BREACH"
    INACTIVE_ACCOUNT = "INACTIVE_ACCOUNT"
    WEAK_PASSWORD = "WEAK_PASSWORD"
    OTHER = "OTHER"


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)

    accounts: Mapped[list[Account]] = relationship(back_populates="user", cascade="all, delete-orphan")
    recovery_emails: Mapped[list[RecoveryEmail]] = relationship(back_populates="user", cascade="all, delete-orphan")
    phone_numbers: Mapped[list[PhoneNumber]] = relationship(back_populates="user", cascade="all, delete-orphan")
    fix_items: Mapped[list[FixItem]] = relationship(back_populates="user", cascade="all, delete-orphan")
    reminders: Mapped[list[Reminder]] = relationship(back_populates="user", cascade="all, delete-orphan")
    notifications: Mapped[list[Notification]] = relationship(back_populates="user", cascade="all, delete-orphan")
    risk_snapshots: Mapped[list[RiskSnapshot]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Service(Base, TimestampMixin):
    __tablename__ = "services"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[ServiceCategory] = mapped_column(SAEnum(ServiceCategory, native_enum=False), nullable=False, index=True)
    website: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    accounts: Mapped[list[Account]] = relationship(back_populates="service")
    breach_events: Mapped[list[BreachEvent]] = relationship(back_populates="service")


class Account(Base, TimestampMixin):
    __tablename__ = "accounts"
    __table_args__ = (
        Index("idx_account_user_service", "user_id", "service_id"),
        Index("idx_account_status_activity", "status", "last_activity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), nullable=False, index=True)

    account_identifier: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[AccountStatus] = mapped_column(SAEnum(AccountStatus, native_enum=False), default=AccountStatus.ACTIVE, nullable=False, index=True)
    sign_in_method: Mapped[SignInMethod] = mapped_column(SAEnum(SignInMethod, native_enum=False), default=SignInMethod.PASSWORD, nullable=False)
    two_factor_enabled: Mapped[bool] = mapped_column(default=False, nullable=False, index=True)
    password_reuse_group_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    password_strength: Mapped[PasswordStrength] = mapped_column(SAEnum(PasswordStrength, native_enum=False), default=PasswordStrength.UNKNOWN, nullable=False)
    password_last_changed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_activity: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)

    user: Mapped[User] = relationship(back_populates="accounts")
    service: Mapped[Service] = relationship(back_populates="accounts")
    permissions: Mapped[list[AppPermission]] = relationship(back_populates="account", cascade="all, delete-orphan")
    recovery_email_links: Mapped[list[AccountRecoveryEmail]] = relationship(back_populates="account", cascade="all, delete-orphan")
    phone_number_links: Mapped[list[AccountPhoneNumber]] = relationship(back_populates="account", cascade="all, delete-orphan")
    source_connections: Mapped[list[AccountConnection]] = relationship(
        foreign_keys="AccountConnection.source_account_id",
        back_populates="source_account",
        cascade="all, delete-orphan",
    )
    target_connections: Mapped[list[AccountConnection]] = relationship(
        foreign_keys="AccountConnection.target_account_id",
        back_populates="target_account",
        cascade="all, delete-orphan",
    )
    risk_factors: Mapped[list[RiskFactor]] = relationship(back_populates="account", cascade="all, delete-orphan")
    breach_events: Mapped[list[BreachEvent]] = relationship(back_populates="account")
    fix_items: Mapped[list[FixItem]] = relationship(back_populates="account")
    notifications: Mapped[list[Notification]] = relationship(back_populates="account")


class RecoveryEmail(Base, TimestampMixin):
    __tablename__ = "recovery_emails"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    is_primary: Mapped[bool] = mapped_column(default=False, nullable=False)
    is_verified: Mapped[bool] = mapped_column(default=False, nullable=False)

    user: Mapped[User] = relationship(back_populates="recovery_emails")
    account_links: Mapped[list[AccountRecoveryEmail]] = relationship(back_populates="recovery_email", cascade="all, delete-orphan")

    __table_args__ = (Index("idx_recovery_email_user_email", "user_id", "email"),)


class PhoneNumber(Base, TimestampMixin):
    __tablename__ = "phone_numbers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    phone_number: Mapped[str] = mapped_column(String(64), nullable=False)
    is_primary: Mapped[bool] = mapped_column(default=False, nullable=False)
    is_verified: Mapped[bool] = mapped_column(default=False, nullable=False)

    user: Mapped[User] = relationship(back_populates="phone_numbers")
    account_links: Mapped[list[AccountPhoneNumber]] = relationship(back_populates="phone_number", cascade="all, delete-orphan")

    __table_args__ = (Index("idx_phone_user_number", "user_id", "phone_number"),)


class AccountRecoveryEmail(Base, TimestampMixin):
    __tablename__ = "account_recovery_emails"
    __table_args__ = (UniqueConstraint("account_id", "recovery_email_id", name="uq_account_recovery_email"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), nullable=False, index=True)
    recovery_email_id: Mapped[str] = mapped_column(ForeignKey("recovery_emails.id"), nullable=False, index=True)

    account: Mapped[Account] = relationship(back_populates="recovery_email_links")
    recovery_email: Mapped[RecoveryEmail] = relationship(back_populates="account_links")


class AccountPhoneNumber(Base, TimestampMixin):
    __tablename__ = "account_phone_numbers"
    __table_args__ = (UniqueConstraint("account_id", "phone_number_id", name="uq_account_phone_number"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), nullable=False, index=True)
    phone_number_id: Mapped[str] = mapped_column(ForeignKey("phone_numbers.id"), nullable=False, index=True)

    account: Mapped[Account] = relationship(back_populates="phone_number_links")
    phone_number: Mapped[PhoneNumber] = relationship(back_populates="account_links")


class AccountConnection(Base, TimestampMixin):
    __tablename__ = "account_connections"
    __table_args__ = (
        UniqueConstraint("source_account_id", "target_account_id", "connection_type", name="uq_account_connection"),
        Index("idx_account_connection_source", "source_account_id", "connection_type"),
        Index("idx_account_connection_target", "target_account_id", "connection_type"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    source_account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), nullable=False, index=True)
    target_account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), nullable=False, index=True)
    connection_type: Mapped[ConnectionType] = mapped_column(SAEnum(ConnectionType, native_enum=False), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)

    source_account: Mapped[Account] = relationship(foreign_keys=[source_account_id], back_populates="source_connections")
    target_account: Mapped[Account] = relationship(foreign_keys=[target_account_id], back_populates="target_connections")

    def validate(self) -> None:
        source_account = self.source_account
        target_account = self.target_account

        if source_account is not None and target_account is not None and source_account is target_account:
            raise ValueError("An account cannot connect to itself.")

        source_account_id = self.source_account_id or getattr(source_account, "id", None)
        target_account_id = self.target_account_id or getattr(target_account, "id", None)
        if source_account_id and target_account_id and source_account_id == target_account_id:
            raise ValueError("An account cannot connect to itself.")

        source_user = getattr(source_account, "user", None)
        target_user = getattr(target_account, "user", None)
        if source_user is not None and target_user is not None and source_user is not target_user:
            raise ValueError("An account connection cannot link accounts from different users.")


@event.listens_for(AccountConnection, "before_insert")
@event.listens_for(AccountConnection, "before_update")
def validate_account_connection(mapper: Any, connection: Any, target: AccountConnection, **kwargs: Any) -> None:
    target.validate()


class AppPermission(Base, TimestampMixin):
    __tablename__ = "app_permissions"
    __table_args__ = (
        Index("idx_permission_account", "account_id", "permission_type"),
        Index("idx_permission_sensitivity", "sensitivity", "granted"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), nullable=False, index=True)
    permission_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    sensitivity: Mapped[PermissionSensitivity] = mapped_column(SAEnum(PermissionSensitivity, native_enum=False), default=PermissionSensitivity.MEDIUM, nullable=False, index=True)
    granted: Mapped[bool] = mapped_column(default=True, nullable=False)
    granted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    account: Mapped[Account] = relationship(back_populates="permissions")


class BreachEvent(Base):
    __tablename__ = "breach_events"
    __table_args__ = (
        Index("idx_breach_service", "service_id", "severity"),
        Index("idx_breach_account", "account_id", "severity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), nullable=False, index=True)
    account_id: Mapped[str | None] = mapped_column(ForeignKey("accounts.id"), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity, native_enum=False), default=Severity.MEDIUM, nullable=False, index=True)
    breach_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_simulated: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    service: Mapped[Service] = relationship(back_populates="breach_events")
    account: Mapped[Account | None] = relationship(back_populates="breach_events")


class FixItem(Base, TimestampMixin):
    __tablename__ = "fix_items"
    __table_args__ = (
        Index("idx_fix_user", "user_id", "status"),
        Index("idx_fix_account", "account_id", "priority"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    account_id: Mapped[str | None] = mapped_column(ForeignKey("accounts.id"), nullable=True, index=True)
    type: Mapped[FixType] = mapped_column(SAEnum(FixType, native_enum=False), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    priority: Mapped[FixPriority] = mapped_column(SAEnum(FixPriority, native_enum=False), default=FixPriority.MEDIUM, nullable=False, index=True)
    status: Mapped[FixStatus] = mapped_column(SAEnum(FixStatus, native_enum=False), default=FixStatus.PENDING, nullable=False, index=True)
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="fix_items")
    account: Mapped[Account | None] = relationship(back_populates="fix_items")


class Reminder(Base, TimestampMixin):
    __tablename__ = "reminders"
    __table_args__ = (
        Index("idx_reminder_user_due", "user_id", "scheduled_for"),
        Index("idx_reminder_status", "status", "scheduled_for"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    account_id: Mapped[str | None] = mapped_column(ForeignKey("accounts.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    reminder_type: Mapped[ReminderType] = mapped_column(SAEnum(ReminderType, native_enum=False), nullable=False, index=True)
    scheduled_for: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    status: Mapped[ReminderStatus] = mapped_column(SAEnum(ReminderStatus, native_enum=False), default=ReminderStatus.PENDING, nullable=False, index=True)

    user: Mapped[User] = relationship(back_populates="reminders")


class Notification(Base):
    __tablename__ = "notifications"
    __table_args__ = (
        Index("idx_notification_user", "user_id", "is_read"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    account_id: Mapped[str | None] = mapped_column(ForeignKey("accounts.id"), nullable=True)
    breach_event_id: Mapped[str | None] = mapped_column(ForeignKey("breach_events.id"), nullable=True)
    type: Mapped[NotificationType] = mapped_column(SAEnum(NotificationType, native_enum=False), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    is_read: Mapped[bool] = mapped_column(default=False, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    user: Mapped[User] = relationship(back_populates="notifications")
    account: Mapped[Account | None] = relationship(back_populates="notifications")


class RiskSnapshot(Base):
    __tablename__ = "risk_snapshots"
    __table_args__ = (
        Index("idx_risk_snapshot_user_date", "user_id", "snapshot_date"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    overall_score: Mapped[int] = mapped_column(nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(SAEnum(RiskLevel, native_enum=False), default=RiskLevel.MEDIUM, nullable=False)
    total_accounts: Mapped[int] = mapped_column(default=0, nullable=False)
    high_risk_accounts: Mapped[int] = mapped_column(default=0, nullable=False)
    critical_accounts: Mapped[int] = mapped_column(default=0, nullable=False)
    open_fix_count: Mapped[int] = mapped_column(default=0, nullable=False)
    single_point_count: Mapped[int] = mapped_column(default=0, nullable=False)
    snapshot_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    user: Mapped[User] = relationship(back_populates="risk_snapshots")


class RiskFactor(Base, TimestampMixin):
    __tablename__ = "risk_factors"
    __table_args__ = (
        Index("idx_risk_factor_account", "account_id", "factor_type"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), nullable=False, index=True)
    factor_type: Mapped[RiskFactorType] = mapped_column(SAEnum(RiskFactorType, native_enum=False), nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity, native_enum=False), default=Severity.MEDIUM, nullable=False)
    weight: Mapped[int] = mapped_column(default=0, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    account: Mapped[Account] = relationship(back_populates="risk_factors")
