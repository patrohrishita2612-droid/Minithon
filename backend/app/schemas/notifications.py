from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class NotificationItem(BaseModel):
    candidate_key: str
    notification_id: str | None = None
    type: str
    title: str
    severity: str
    account_id: str
    breach_event_id: str | None = None
    service_id: str
    service_name: str | None
    reason_code: str
    explanation: str
    recommended_action: str
    evidence: list[str]
    risk_contribution: float | None = None
    observed_at: datetime | None = None
    created_at: datetime | None = None
    is_read: bool = False


class UserNotificationsSummary(BaseModel):
    user_id: str
    total: int
    critical: int
    high: int
    medium: int
    low: int
    unread: int
    notifications: list[NotificationItem]


class NotificationService(BaseModel):
    id: str
    name: str | None


class AccountNotificationsSummary(BaseModel):
    account_id: str
    service: NotificationService
    total: int
    critical: int
    high: int
    medium: int
    low: int
    unread: int
    notifications: list[NotificationItem]


class UserNotificationsResponse(BaseModel):
    success: bool
    data: UserNotificationsSummary


class AccountNotificationsResponse(BaseModel):
    success: bool
    data: AccountNotificationsSummary