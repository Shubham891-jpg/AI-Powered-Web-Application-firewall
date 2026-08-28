"""
Application Management API Endpoints (Phase 9).
Provides CRUD operations for multi-tenant protected upstream targets.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.database.database import async_session_factory
from app.database.models import Application
from app.database.repositories import ApplicationRepository
from app.config import settings

router = APIRouter(prefix="/applications", tags=["Applications"])

# Seed in-memory demo app
_demo_apps = [
    {
        "id": "app-001",
        "name": "E-Commerce Store API",
        "upstream_url": settings.UPSTREAM_URL,
        "is_active": True,
        "detection_mode": settings.DETECTION_MODE,
        "rate_limit_requests": settings.RATE_LIMIT_REQUESTS,
        "rate_limit_window_seconds": settings.RATE_LIMIT_WINDOW_SECONDS,
    }
]


class ApplicationCreate(BaseModel):
    name: str
    upstream_url: str
    is_active: bool = True
    detection_mode: str = "BLOCK"
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60


class ApplicationUpdate(BaseModel):
    name: Optional[str] = None
    upstream_url: Optional[str] = None
    is_active: Optional[bool] = None
    detection_mode: Optional[str] = None
    rate_limit_requests: Optional[int] = None
    rate_limit_window_seconds: Optional[int] = None


@router.get("")
async def list_applications():
    """Lists all configured protected applications."""
    if async_session_factory is not None:
        try:
            async with async_session_factory() as session:
                repo = ApplicationRepository(session)
                apps = await repo.get_all()
                if apps:
                    return [
                        {
                            "id": a.id,
                            "name": a.name,
                            "upstream_url": a.upstream_url,
                            "is_active": a.is_active,
                            "detection_mode": a.detection_mode,
                            "rate_limit_requests": a.rate_limit_requests,
                            "rate_limit_window_seconds": a.rate_limit_window_seconds,
                        }
                        for a in apps
                    ]
        except Exception:
            pass

    return _demo_apps


from app.security.ssrf import validate_upstream_url_safety, SSRFException

@router.post("")
async def create_application(payload: ApplicationCreate):
    """Registers a new upstream web application with SSRF validation."""
    try:
        validate_upstream_url_safety(payload.upstream_url)
    except SSRFException as e:
        raise HTTPException(status_code=400, detail=str(e))
    if async_session_factory is not None:
        try:
            async with async_session_factory() as session:
                repo = ApplicationRepository(session)
                app = Application(
                    name=payload.name,
                    upstream_url=payload.upstream_url,
                    is_active=payload.is_active,
                    detection_mode=payload.detection_mode,
                    rate_limit_requests=payload.rate_limit_requests,
                    rate_limit_window_seconds=payload.rate_limit_window_seconds,
                )
                created = await repo.create(app)
                await session.commit()
                return {
                    "id": created.id,
                    "name": created.name,
                    "upstream_url": created.upstream_url,
                    "is_active": created.is_active,
                    "detection_mode": created.detection_mode,
                    "rate_limit_requests": created.rate_limit_requests,
                }
        except Exception:
            pass

    new_app = {
        "id": f"app-{len(_demo_apps) + 1:03d}",
        **payload.model_dump(),
    }
    _demo_apps.append(new_app)
    return new_app


@router.patch("/{app_id}")
async def update_application(app_id: str, payload: ApplicationUpdate):
    """Updates configuration or detection mode for an application."""
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields provided for update")

    if payload.upstream_url:
        try:
            validate_upstream_url_safety(payload.upstream_url)
        except SSRFException as e:
            raise HTTPException(status_code=400, detail=str(e))

    if async_session_factory is not None:
        try:
            async with async_session_factory() as session:
                repo = ApplicationRepository(session)
                updated = await repo.update(app_id, **updates)
                await session.commit()
                if updated:
                    return {
                        "id": updated.id,
                        "name": updated.name,
                        "upstream_url": updated.upstream_url,
                        "is_active": updated.is_active,
                        "detection_mode": updated.detection_mode,
                        "rate_limit_requests": updated.rate_limit_requests,
                    }
        except Exception:
            pass

    for a in _demo_apps:
        if a["id"] == app_id:
            a.update(updates)
            return a

    raise HTTPException(status_code=404, detail="Application not found")
