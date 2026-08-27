"""
API Router Aggregator for AI-WAF v1 Endpoints.
"""

from fastapi import APIRouter
from app.api.health import router as health_router
from app.api.security_events import router as events_router
from app.config import settings

api_v1_router = APIRouter(prefix="/api/v1")

# Mount sub-routers
api_v1_router.include_router(events_router)


@api_v1_router.get("/config", tags=["Configuration"])
async def get_public_config():
    """Returns safe, public-facing configuration for dashboard."""
    return {
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
        "upstream_url": settings.UPSTREAM_URL,
        "detection_mode": settings.DETECTION_MODE,
        "thresholds": {
            "allow": settings.ALLOW_THRESHOLD,
            "flag": settings.FLAG_THRESHOLD,
            "block": settings.BLOCK_THRESHOLD,
        },
        "rate_limiting": {
            "requests": settings.RATE_LIMIT_REQUESTS,
            "window_seconds": settings.RATE_LIMIT_WINDOW_SECONDS,
        },
        "limits": {
            "max_body_bytes": settings.MAX_REQUEST_BODY_SIZE,
            "max_header_bytes": settings.MAX_HEADER_SIZE,
        },
    }
