"""
AI-WAF Gateway Application.
Production-style AI-powered Web Application Firewall and Reverse Proxy Gateway.
"""

from contextlib import asynccontextmanager
import time
import uuid
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.api.health import router as health_router
from app.api.routes import api_v1_router
from app.detection.ml.model_loader import initialize_ml_models
from app.proxy.upstream import close_http_client
from app.rate_limit.limiter import close_redis
from app.proxy.proxy import reverse_proxy_handler
from app.proxy.response_handler import create_blocked_response
from app.detection.detector import request_detector
from app.detection.preprocessing import RequestParser, RequestNormalizer
from app.logging.security_logger import security_logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for clean startup and resource cleanup."""
    # Startup: Load ML models
    initialize_ml_models()
    yield
    # Shutdown: Clean up connection pools
    await close_http_client()
    await close_redis()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-Powered Web Application Firewall & Security Monitoring Platform",
    lifespan=lifespan,
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
)

# CORS middleware for local frontend dashboard communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_and_inspection_middleware(request: Request, call_next):
    """
    Phase 2 Inspection & Request Pipeline Middleware:
    1. Assign X-Request-ID
    2. Check header size limits
    3. Exclude internal management routes (/health, /api/*) from proxy blocking
    4. Parse raw request into RawRequest model
    5. Generate NormalizedRequest & InspectedRequestContext
    6. Run real-time multi-vector threat detection
    7. Block, Flag, or Allow
    """
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    start_time = time.perf_counter()

    # Enforce header size limit
    header_size = sum(len(k) + len(v) for k, v in request.headers.items())
    if header_size > settings.MAX_HEADER_SIZE:
        return JSONResponse(
            status_code=431,
            content={"error": "Request Header Fields Too Large", "request_id": request_id},
        )

    path = request.url.path

    # Internal health and dashboard API endpoints bypass inspection & proxying
    if path == "/health" or path.startswith("/api/"):
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    client_ip = request.client.host if request.client else "unknown"

    # 1. Parse raw request
    raw_request = await RequestParser.parse_request(request, request_id, client_ip)

    # 2. Normalize and build inspection context
    context = RequestNormalizer.create_context(raw_request)

    # 3. Execute multi-vector threat detection
    decision, matched_rules, normalized_target = request_detector.inspect(context, request_id=request_id)
    latency_ms = (time.perf_counter() - start_time) * 1000.0

    # 4. Log security event if flagged or blocked
    if decision.action in ("BLOCK", "FLAG"):
        security_logger.log_event(
            request_id=request_id,
            client_ip=client_ip,
            method=request.method,
            path=path,
            attack_category=decision.classification,
            risk_score=decision.risk_score,
            action=decision.action,
            latency_ms=latency_ms,
            details={
                "reasons": decision.reasons,
                "matched_rules": [r.model_dump() for r in matched_rules],
                "explanation": decision.explanation.model_dump() if decision.explanation else None,
                "encoding_depth": context.normalized.encoding_depth,
                "has_null_bytes": context.normalized.has_null_bytes,
                "transformations": context.normalized.transformations,
                "raw_path": raw_request.path,
                "canonical_path": context.normalized.canonical_path,
                "raw_query": raw_request.raw_query,
            },
        )

    # 5. Terminate malicious requests with uniform HTTP 403
    if decision.action == "BLOCK":
        return create_blocked_response(request_id=request_id, status_code=403)

    # 6. Transparently forward permitted requests to the upstream protected app
    return await reverse_proxy_handler(request)


# Mount diagnostic and API routes
app.include_router(health_router)
app.include_router(api_v1_router)
