from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.database.database import init_db
from app.routers.accounts import router as accounts_router
from app.routers.breaches import router as breaches_router
from app.routers.connections import router as connections_router
from app.routers.exposure import router as exposure_router
from app.routers.hygiene import router as hygiene_router
from app.routers.notifications import router as notifications_router
from app.routers.permissions import router as permissions_router
from app.routers.recovery import router as recovery_router
from app.routers.remediation import router as remediation_router
from app.routers.risk import router as risk_router
from app.routers.services import router as services_router
from app.routers.users import router as users_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="Digital Footprint & Privacy Risk Auditor API",
        description=(
            "API foundation for privacy risk auditing, account inventory, and deterministic exposure analysis. "
            "Risk score = exposure measurement, not a probability of compromise. Privacy score = inverse summary of exposure "
            "and remains deterministic across equivalent database states."
        ),
        version="0.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, dict) else {"code": "HTTP_ERROR", "message": str(exc.detail)}
        return JSONResponse(
            status_code=exc.status_code,
            content={"success": False, "error": {"code": detail.get("code", "HTTP_ERROR"), "message": detail.get("message", str(exc.detail))}},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = exc.errors()
        message = errors[0].get("msg", "Request validation failed.") if errors else "Request validation failed."
        return JSONResponse(status_code=422, content={"success": False, "error": {"code": "VALIDATION_ERROR", "message": message}})

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": {"code": "INTERNAL_SERVER_ERROR", "message": "An internal server error occurred."}},
        )

    init_db()

    @app.on_event("startup")
    async def startup_event() -> None:
        init_db()
        if "test" not in settings.DATABASE_URL:
            try:
                from app.seed import seed_demo_data
                seed_demo_data()
            except Exception:
                pass

    app.include_router(users_router)
    app.include_router(services_router)
    app.include_router(accounts_router)
    app.include_router(breaches_router)
    app.include_router(recovery_router)
    app.include_router(permissions_router)
    app.include_router(connections_router)
    app.include_router(exposure_router)
    app.include_router(risk_router)
    app.include_router(remediation_router)
    app.include_router(hygiene_router)
    app.include_router(notifications_router)

    @app.get("/health")
    @app.get("/api/health")
    async def health() -> dict[str, object]:
        return {
            "success": True,
            "message": "Digital Footprint & Privacy Risk Auditor backend is running",
        }

    return app


app = create_app()
