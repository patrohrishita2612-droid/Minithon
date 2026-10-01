from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from fastapi import HTTPException


def api_success(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data}


def api_error(code: str, message: str, status_code: int = 400) -> None:
    raise HTTPException(status_code=status_code, detail={"code": code, "message": message})


def serialize_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [serialize_value(item) for item in value]
    if isinstance(value, dict):
        return {key: serialize_value(val) for key, val in value.items()}
    return value
