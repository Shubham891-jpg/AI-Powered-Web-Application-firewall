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
from app.database.database import async_session_factory
from app.database.models import SecurityEvent
from app.detection.detector import request_detector
from app.detection.ml.classifier import initialize_ml_models
from app.logging.security_logger import security_logger
from app.logging.event_queue import security_event_queue
from app.proxy.proxy import reverse_proxy_handler
from app.proxy.response_handler import create_blocked_response
from app.proxy.upstream import close_http_client
from app.rate_limit.limiter import close_redis, rate_limiter, create_rate_limited_response


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for clean startup and resource cleanup."""
    # Startup: Load ML models & start background event persistence worker
    initialize_ml_models()
    if async_session_factory:
        await security_event_queue.start(async_session_factory)
    yield
    # Shutdown: Clean up connection pools & flush background persistence queue
    if async_session_factory:
        await security_event_queue.stop(async_session_factory)
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

    # 0. Sliding-Window Rate Limit Check (Phase 8)
    rate_res = await rate_limiter.check_rate_limit(client_ip)
    if not rate_res.allowed:
        security_logger.log_event(
            request_id=request_id,
            client_ip=client_ip,
            method=request.method,
            path=path,
            attack_category="RATE_LIMIT_EXCEEDED",
            risk_score=85 if rate_res.is_burst else 70,
            action="BLOCK",
            latency_ms=(time.perf_counter() - start_time) * 1000.0,
            details={
                "is_burst": rate_res.is_burst,
                "current_count": rate_res.current_count,
                "limit": rate_res.limit,
                "retry_after": rate_res.retry_after,
            },
        )
        return create_rate_limited_response(request_id, rate_res)

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

        # Enqueue for non-blocking asynchronous PostgreSQL persistence (Phase 7)
        try:
            db_event = SecurityEvent(
                request_id=request_id,
                client_ip=client_ip,
                http_method=request.method,
                path=path,
                query_params=raw_request.query_params,
                headers={k: v for k, v in raw_request.headers.items() if k.lower() not in ("authorization", "cookie")},
                raw_payload=raw_request.body_text[:1000] if raw_request.body_text else "",
                normalized_payload=context.normalized.body_text[:1000] if context.normalized.body_text else "",
                attack_category=decision.classification,
                risk_score=decision.risk_score,
                ml_confidence=decision.explanation.ml_prediction.confidence if decision.explanation and decision.explanation.ml_prediction else None,
                action=decision.action,
                matched_rules=[r.model_dump() for r in matched_rules],
                primary_reason=decision.explanation.primary_reason if decision.explanation else "",
                ml_prediction=decision.explanation.ml_prediction.model_dump() if decision.explanation and decision.explanation.ml_prediction else {},
                contextual_penalties=[p.model_dump() for p in decision.explanation.contextual_penalties] if decision.explanation else [],
                explanation_json=decision.explanation.model_dump() if decision.explanation else {},
                response_status=403 if decision.action == "BLOCK" else 200,
                processing_latency_ms=latency_ms,
            )
            security_event_queue.enqueue(db_event)
        except Exception:
            pass

    # 5. Terminate malicious requests with uniform HTTP 403
    if decision.action == "BLOCK":
        return create_blocked_response(
            request_id=request_id,
            risk_score=decision.risk_score,
            category=decision.classification,
            status_code=403,
        )

    # 6. Transparently forward permitted requests to the upstream protected app
    return await reverse_proxy_handler(request, decision=decision, latency_ms=latency_ms)


# Mount diagnostic and API routes
app.include_router(health_router)
app.include_router(api_v1_router)
