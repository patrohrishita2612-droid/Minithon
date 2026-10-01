from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.models import (
    AccountConnection,
    AccountStatus,
    ConnectionType,
    FixPriority,
    FixStatus,
    FixType,
    NotificationType,
    PasswordStrength,
    PermissionSensitivity,
    ReminderStatus,
    ReminderType,
    RiskFactorType,
    RiskLevel,
    ServiceCategory,
    Severity,
    SignInMethod,
)


class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class UserCreate(BaseSchema):
    name: str
    email: str


class UserUpdate(BaseSchema):
    name: str | None = None
    email: str | None = None


class UserResponse(BaseSchema):
    id: str
    name: str
    email: str
    created_at: datetime
    updated_at: datetime


class ServiceCreate(BaseSchema):
    name: str
    category: ServiceCategory
    website: str | None = None
    description: str | None = None


class ServiceUpdate(BaseSchema):
    name: str | None = None
    category: ServiceCategory | None = None
    website: str | None = None
    description: str | None = None


class ServiceResponse(BaseSchema):
    id: str
    name: str
    category: ServiceCategory
    website: str | None = None
    description: str | None = None
    created_at: datetime
    updated_at: datetime


class AccountCreate(BaseSchema):
    user_id: str
    service_id: str
    account_identifier: str
    display_name: str | None = None
    status: AccountStatus = AccountStatus.ACTIVE
    sign_in_method: SignInMethod = SignInMethod.PASSWORD
    two_factor_enabled: bool = False
    password_reuse_group_id: str | None = None
    password_strength: PasswordStrength = PasswordStrength.UNKNOWN
    password_last_changed: datetime | None = None
    last_activity: datetime | None = None
    is_active: bool = True


class AccountUpdate(BaseSchema):
    account_identifier: str | None = None
    display_name: str | None = None
    status: AccountStatus | None = None
    sign_in_method: SignInMethod | None = None
    two_factor_enabled: bool | None = None
    password_reuse_group_id: str | None = None
    password_strength: PasswordStrength | None = None
    password_last_changed: datetime | None = None
    last_activity: datetime | None = None
    is_active: bool | None = None


class AccountResponse(BaseSchema):
    id: str
    user_id: str
    service_id: str
    account_identifier: str
    display_name: str | None = None
    status: AccountStatus
    sign_in_method: SignInMethod
    two_factor_enabled: bool
    password_reuse_group_id: str | None = None
    password_strength: PasswordStrength
    password_last_changed: datetime | None = None
    last_activity: datetime | None = None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class RecoveryEmailCreate(BaseSchema):
    user_id: str
    email: str
    is_primary: bool = False
    is_verified: bool = False


class RecoveryEmailUpdate(BaseSchema):
    email: str | None = None
    is_primary: bool | None = None
    is_verified: bool | None = None


class RecoveryEmailResponse(BaseSchema):
    id: str
    user_id: str
    email: str
    is_primary: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime


class PhoneNumberCreate(BaseSchema):
    user_id: str
    phone_number: str
    is_primary: bool = False
    is_verified: bool = False


class PhoneNumberUpdate(BaseSchema):
    phone_number: str | None = None
    is_primary: bool | None = None
    is_verified: bool | None = None


class PhoneNumberResponse(BaseSchema):
    id: str
    user_id: str
    phone_number: str
    is_primary: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime


class AccountConnectionCreate(BaseSchema):
    source_account_id: str
    target_account_id: str
    connection_type: ConnectionType
    description: str | None = None
    is_active: bool = True


class AccountConnectionUpdate(BaseSchema):
    source_account_id: str | None = None
    target_account_id: str | None = None
    connection_type: ConnectionType | None = None
    description: str | None = None
    is_active: bool | None = None


class AccountConnectionResponse(BaseSchema):
    id: str
    source_account_id: str
    target_account_id: str
    connection_type: ConnectionType
    description: str | None = None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class AppPermissionCreate(BaseSchema):
    account_id: str | None = None
    permission_type: str
    description: str | None = None
    sensitivity: PermissionSensitivity = PermissionSensitivity.MEDIUM
    granted: bool = True
    granted_at: datetime | None = None
    last_reviewed_at: datetime | None = None


class AppPermissionUpdate(BaseSchema):
    permission_type: str | None = None
    description: str | None = None
    sensitivity: PermissionSensitivity | None = None
    granted: bool | None = None
    granted_at: datetime | None = None
    last_reviewed_at: datetime | None = None


class AppPermissionResponse(BaseSchema):
    id: str
    account_id: str
    permission_type: str
    description: str | None = None
    sensitivity: PermissionSensitivity
    granted: bool
    granted_at: datetime | None = None
    last_reviewed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class BreachEventCreate(BaseSchema):
    service_id: str
    account_id: str | None = None
    title: str
    description: str | None = None
    severity: Severity = Severity.MEDIUM
    breach_date: datetime | None = None
    source: str | None = None
    is_simulated: bool = False


class BreachEventResponse(BaseSchema):
    id: str
    service_id: str
    account_id: str | None = None
    title: str
    description: str | None = None
    severity: Severity
    breach_date: datetime | None = None
    source: str | None = None
    is_simulated: bool
    created_at: datetime


class FixItemCreate(BaseSchema):
    user_id: str
    account_id: str | None = None
    type: FixType
    title: str
    description: str | None = None
    priority: FixPriority = FixPriority.MEDIUM
    status: FixStatus = FixStatus.PENDING
    due_date: datetime | None = None
    completed_at: datetime | None = None


class FixItemUpdate(BaseSchema):
    account_id: str | None = None
    type: FixType | None = None
    title: str | None = None
    description: str | None = None
    priority: FixPriority | None = None
    status: FixStatus | None = None
    due_date: datetime | None = None
    completed_at: datetime | None = None


class FixItemResponse(BaseSchema):
    id: str
    user_id: str
    account_id: str | None = None
    type: FixType
    title: str
    description: str | None = None
    priority: FixPriority
    status: FixStatus
    due_date: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class ReminderCreate(BaseSchema):
    user_id: str
    account_id: str | None = None
    title: str
    description: str | None = None
    reminder_type: ReminderType
    scheduled_for: datetime | None = None
    status: ReminderStatus = ReminderStatus.PENDING


class ReminderUpdate(BaseSchema):
    account_id: str | None = None
    title: str | None = None
    description: str | None = None
    reminder_type: ReminderType | None = None
    scheduled_for: datetime | None = None
    status: ReminderStatus | None = None


class ReminderResponse(BaseSchema):
    id: str
    user_id: str
    account_id: str | None = None
    title: str
    description: str | None = None
    reminder_type: ReminderType
    scheduled_for: datetime | None = None
    status: ReminderStatus
    created_at: datetime
    updated_at: datetime


class NotificationCreate(BaseSchema):
    user_id: str
    account_id: str | None = None
    breach_event_id: str | None = None
    type: NotificationType
    title: str
    message: str
    is_read: bool = False


class NotificationResponse(BaseSchema):
    id: str
    user_id: str
    account_id: str | None = None
    breach_event_id: str | None = None
    type: NotificationType
    title: str
    message: str
    is_read: bool
    created_at: datetime


class RiskSnapshotCreate(BaseSchema):
    user_id: str
    overall_score: int
    risk_level: RiskLevel = RiskLevel.MEDIUM
    total_accounts: int = 0
    high_risk_accounts: int = 0
    critical_accounts: int = 0
    open_fix_count: int = 0
    single_point_count: int = 0
    snapshot_date: datetime | None = None


class RiskSnapshotResponse(BaseSchema):
    id: str
    user_id: str
    overall_score: int
    risk_level: RiskLevel
    total_accounts: int
    high_risk_accounts: int
    critical_accounts: int
    open_fix_count: int
    single_point_count: int
    snapshot_date: datetime
    created_at: datetime


class RiskFactorCreate(BaseSchema):
    account_id: str
    factor_type: RiskFactorType
    severity: Severity = Severity.MEDIUM
    weight: int = 0
    description: str | None = None


class RiskFactorUpdate(BaseSchema):
    account_id: str | None = None
    factor_type: RiskFactorType | None = None
    severity: Severity | None = None
    weight: int | None = None
    description: str | None = None


class RiskFactorResponse(BaseSchema):
    id: str
    account_id: str
    factor_type: RiskFactorType
    severity: Severity
    weight: int
    description: str | None = None
    created_at: datetime
    updated_at: datetime
