"""
Health and readiness diagnostic endpoints for AI-WAF.
"""

import time
from fastapi import APIRouter
from app.config import settings
from app.database.database import check_database_health
from app.proxy.upstream import check_upstream_health
from app.rate_limit.limiter import check_redis_health
from app.schemas.responses import (
    HealthResponse,
    ServiceComponentHealth,
    SimpleHealthResponse,
)

router = APIRouter(tags=["Health Diagnostics"])

# Record system startup timestamp
START_TIME = time.time()


@router.get("/health", response_model=SimpleHealthResponse)
async def liveness_probe():
    """
    Lightweight liveness probe for orchestrators (Kubernetes, Docker healthcheck).
    Returns HTTP 200 if the FastAPI application process is alive.
    """
    return SimpleHealthResponse(status="ok")


@router.get("/api/health", response_model=HealthResponse)
async def readiness_probe():
    """
    Comprehensive readiness probe.
    Inspects all attached subsystems:
    1. Upstream protected application
    2. Redis rate-limiting cache
    3. PostgreSQL database connection
    4. Detection engine readiness
    """
    uptime = time.time() - START_TIME

    # Check upstream
    up_ok, up_lat, up_msg, up_code = await check_upstream_health()
    upstream_health = ServiceComponentHealth(
        name="protected_upstream",
        status="healthy" if up_ok else "unhealthy",
        latency_ms=up_lat,
        details={"url": settings.UPSTREAM_URL, "message": up_msg, "status_code": up_code},
    )

    # Check Redis
    red_ok, red_lat, red_msg = await check_redis_health()
    redis_health = ServiceComponentHealth(
        name="redis_cache",
        status="healthy" if red_ok else "degraded",
        latency_ms=red_lat,
        details={"url": settings.REDIS_URL, "message": red_msg},
    )

    # Check Database
    db_ok, db_lat, db_msg = await check_database_health()
    db_health = ServiceComponentHealth(
        name="postgres_database",
        status="healthy" if db_ok else "degraded",
        latency_ms=db_lat,
        details={"message": db_msg},
    )

    # Check Detection Engine
    from app.detection.detector import request_detector
    from app.detection.ml.classifier import ml_classifier
    active_rules = request_detector.rules
    ml_info = ml_classifier.get_info()
    detection_health = ServiceComponentHealth(
        name="detection_engine",
        status="healthy",
        latency_ms=0.5,
        details={
            "mode": settings.DETECTION_MODE,
            "rules_loaded": len(active_rules),
            "active_rule_ids": [r.rule_id for r in active_rules],
            "ml_enabled": settings.ML_ENABLED,
            "ml_model": ml_info,
            "thresholds": {
                "allow": settings.ALLOW_THRESHOLD,
                "flag": settings.FLAG_THRESHOLD,
                "block": settings.BLOCK_THRESHOLD,
            },
        },
    )

    components = {
        "upstream": upstream_health,
        "redis": redis_health,
        "database": db_health,
        "detection": detection_health,
    }

    # System status is degraded if optional subsystems (redis/db) are down, or unhealthy if upstream is down
    overall_status = "healthy"
    if not up_ok:
        overall_status = "degraded"
    if not red_ok or not db_ok:
        overall_status = "degraded"

    return HealthResponse(
        status=overall_status,
        version=settings.APP_VERSION,
        environment=settings.APP_ENV,
        uptime_seconds=round(uptime, 2),
        components=components,
    )
