from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.models import Account, AccountPhoneNumber, AccountRecoveryEmail, PhoneNumber, RecoveryEmail, User
from app.schemas.models import PhoneNumberCreate, PhoneNumberUpdate, RecoveryEmailCreate, RecoveryEmailUpdate
from app.utils.responses import api_error, api_success, serialize_value

router = APIRouter(tags=["Recovery"])


@router.post("/api/recovery/emails")
async def create_recovery_email(payload: RecoveryEmailCreate, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = db.get(User, payload.user_id)
    if not user:
        api_error("USER_NOT_FOUND", "User not found.", status.HTTP_404_NOT_FOUND)

    record = RecoveryEmail(user_id=payload.user_id, email=payload.email, is_primary=payload.is_primary, is_verified=payload.is_verified)
    db.add(record)
    db.commit()
    db.refresh(record)
    return api_success(serialize_value({
        "id": record.id,
        "user_id": record.user_id,
        "is_primary": record.is_primary,
        "is_verified": record.is_verified,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }))


@router.get("/api/recovery/emails/{email_id}")
async def get_recovery_email(email_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    record = db.get(RecoveryEmail, email_id)
    if not record:
        api_error("RECOVERY_EMAIL_NOT_FOUND", "Recovery email not found.", status.HTTP_404_NOT_FOUND)
    return api_success(serialize_value({
        "id": record.id,
        "user_id": record.user_id,
        "is_primary": record.is_primary,
        "is_verified": record.is_verified,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }))


@router.patch("/api/recovery/emails/{email_id}")
async def update_recovery_email(email_id: str, payload: RecoveryEmailUpdate, db: Session = Depends(get_db)) -> dict[str, Any]:
    record = db.get(RecoveryEmail, email_id)
    if not record:
        api_error("RECOVERY_EMAIL_NOT_FOUND", "Recovery email not found.", status.HTTP_404_NOT_FOUND)

    for field, value in payload.model_dump(exclude_unset=True).items():
        if field in {"user_id"}:
            continue
        if value is not None:
            setattr(record, field, value)
    db.commit(); db.refresh(record)
    return api_success(serialize_value({
        "id": record.id,
        "user_id": record.user_id,
        "email": record.email,
        "is_primary": record.is_primary,
        "is_verified": record.is_verified,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }))


@router.delete("/api/recovery/emails/{email_id}")
async def delete_recovery_email(email_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    record = db.get(RecoveryEmail, email_id)
    if not record:
        api_error("RECOVERY_EMAIL_NOT_FOUND", "Recovery email not found.", status.HTTP_404_NOT_FOUND)
    db.delete(record)
    db.commit()
    return api_success({"deleted": True, "recovery_email_id": email_id})


@router.get("/api/recovery/users/{user_id}/recovery-emails")
async def get_user_recovery_emails(user_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = db.get(User, user_id)
    if not user:
        api_error("USER_NOT_FOUND", "User not found.", status.HTTP_404_NOT_FOUND)
    items = db.scalars(
        select(RecoveryEmail).where(RecoveryEmail.user_id == user_id).order_by(RecoveryEmail.created_at, RecoveryEmail.id)
    ).all()
    return api_success([serialize_value({
        "id": item.id,
        "user_id": item.user_id,
        "is_primary": item.is_primary,
        "is_verified": item.is_verified,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }) for item in items])


@router.post("/api/recovery/phones")
async def create_phone_number(payload: PhoneNumberCreate, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = db.get(User, payload.user_id)
    if not user:
        api_error("USER_NOT_FOUND", "User not found.", status.HTTP_404_NOT_FOUND)

    phone = PhoneNumber(user_id=payload.user_id, phone_number=payload.phone_number, is_primary=payload.is_primary, is_verified=payload.is_verified)
    db.add(phone)
    db.commit(); db.refresh(phone)
    return api_success(serialize_value({
        "id": phone.id,
        "user_id": phone.user_id,
        "is_primary": phone.is_primary,
        "is_verified": phone.is_verified,
        "created_at": phone.created_at,
        "updated_at": phone.updated_at,
    }))


@router.get("/api/recovery/users/{user_id}/recovery-phones")
async def get_user_phone_numbers(user_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = db.get(User, user_id)
    if not user:
        api_error("USER_NOT_FOUND", "User not found.", status.HTTP_404_NOT_FOUND)
    items = db.scalars(
        select(PhoneNumber).where(PhoneNumber.user_id == user_id).order_by(PhoneNumber.created_at, PhoneNumber.id)
    ).all()
    return api_success([serialize_value({
        "id": item.id,
        "user_id": item.user_id,
        "is_primary": item.is_primary,
        "is_verified": item.is_verified,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }) for item in items])


@router.patch("/api/recovery/phones/{phone_id}")
async def update_phone_number(phone_id: str, payload: PhoneNumberUpdate, db: Session = Depends(get_db)) -> dict[str, Any]:
    phone = db.get(PhoneNumber, phone_id)
    if not phone:
        api_error("PHONE_NUMBER_NOT_FOUND", "Phone number not found.", status.HTTP_404_NOT_FOUND)
    for field, value in payload.model_dump(exclude_unset=True).items():
        if field in {"user_id"}:
            continue
        if value is not None:
            setattr(phone, field, value)
    db.commit(); db.refresh(phone)
    return api_success(serialize_value({
        "id": phone.id,
        "user_id": phone.user_id,
        "is_primary": phone.is_primary,
        "is_verified": phone.is_verified,
        "created_at": phone.created_at,
        "updated_at": phone.updated_at,
    }))


@router.delete("/api/recovery/phones/{phone_id}")
async def delete_phone_number(phone_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    phone = db.get(PhoneNumber, phone_id)
    if not phone:
        api_error("PHONE_NUMBER_NOT_FOUND", "Phone number not found.", status.HTTP_404_NOT_FOUND)
    db.delete(phone)
    db.commit()
    return api_success({"deleted": True, "phone_id": phone_id})


@router.post("/api/accounts/{account_id}/recovery-email/{email_id}")
async def link_recovery_email_to_account(account_id: str, email_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    account = db.get(Account, account_id)
    if not account:
        api_error("ACCOUNT_NOT_FOUND", "Account not found.", status.HTTP_404_NOT_FOUND)
    recovery_email = db.get(RecoveryEmail, email_id)
    if not recovery_email:
        api_error("RECOVERY_EMAIL_NOT_FOUND", "Recovery email not found.", status.HTTP_404_NOT_FOUND)
    if account.user_id != recovery_email.user_id:
        api_error("CROSS_USER_RELATION", "Recovery email does not belong to the same user.", status.HTTP_400_BAD_REQUEST)
    existing = db.scalar(select(AccountRecoveryEmail).where(AccountRecoveryEmail.account_id == account_id).where(AccountRecoveryEmail.recovery_email_id == email_id))
    if existing:
        api_error("RELATION_EXISTS", "Recovery email is already linked to this account.", status.HTTP_409_CONFLICT)

    link = AccountRecoveryEmail(account_id=account_id, recovery_email_id=email_id)
    db.add(link)
    db.commit(); db.refresh(link)
    return api_success(serialize_value({"id": link.id, "account_id": link.account_id, "recovery_email_id": link.recovery_email_id}))


@router.delete("/api/accounts/{account_id}/recovery-email/{email_id}")
async def unlink_recovery_email_from_account(account_id: str, email_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    link = db.scalar(select(AccountRecoveryEmail).where(AccountRecoveryEmail.account_id == account_id).where(AccountRecoveryEmail.recovery_email_id == email_id))
    if not link:
        api_error("RELATION_NOT_FOUND", "Recovery email link not found.", status.HTTP_404_NOT_FOUND)
    db.delete(link)
    db.commit()
    return api_success({"deleted": True, "account_id": account_id, "recovery_email_id": email_id})


@router.post("/api/accounts/{account_id}/recovery-phone/{phone_id}")
async def link_phone_to_account(account_id: str, phone_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    account = db.get(Account, account_id)
    if not account:
        api_error("ACCOUNT_NOT_FOUND", "Account not found.", status.HTTP_404_NOT_FOUND)
    phone = db.get(PhoneNumber, phone_id)
    if not phone:
        api_error("PHONE_NUMBER_NOT_FOUND", "Phone number not found.", status.HTTP_404_NOT_FOUND)
    if account.user_id != phone.user_id:
        api_error("CROSS_USER_RELATION", "Phone number does not belong to the same user.", status.HTTP_400_BAD_REQUEST)
    existing = db.scalar(select(AccountPhoneNumber).where(AccountPhoneNumber.account_id == account_id).where(AccountPhoneNumber.phone_number_id == phone_id))
    if existing:
        api_error("RELATION_EXISTS", "Phone number is already linked to this account.", status.HTTP_409_CONFLICT)
    link = AccountPhoneNumber(account_id=account_id, phone_number_id=phone_id)
    db.add(link)
    db.commit(); db.refresh(link)
    return api_success(serialize_value({"id": link.id, "account_id": link.account_id, "phone_number_id": link.phone_number_id}))


@router.delete("/api/accounts/{account_id}/recovery-phone/{phone_id}")
async def unlink_phone_from_account(account_id: str, phone_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    link = db.scalar(select(AccountPhoneNumber).where(AccountPhoneNumber.account_id == account_id).where(AccountPhoneNumber.phone_number_id == phone_id))
    if not link:
        api_error("RELATION_NOT_FOUND", "Phone link not found.", status.HTTP_404_NOT_FOUND)
    db.delete(link)
    db.commit()
    return api_success({"deleted": True, "account_id": account_id, "phone_id": phone_id})
