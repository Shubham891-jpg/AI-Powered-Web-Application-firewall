"""
High-Performance Reverse Proxy Gateway (Phase 6).
Transparently forwards permitted client requests to the protected upstream application.
Supports all HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS),
RFC 7230 hop-by-hop stripping, proxy header tracking, security telemetry injection,
streaming responses, payload size protection, and resilient 502/504 error handling.
"""

import uuid
from typing import Optional
from fastapi import Request, Response
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask
import httpx

from app.config import settings
from app.detection.models import DecisionResult
from app.proxy.upstream import get_http_client
from app.proxy.headers import prepare_upstream_headers, prepare_downstream_headers
from app.proxy.response_handler import create_error_response


async def reverse_proxy_handler(
    request: Request,
    decision: Optional[DecisionResult] = None,
    latency_ms: float = 0.0,
) -> Response:
    """
    Asynchronously streams and proxies permitted requests to the upstream application.
    Enforces payload size safeguards and injects WAF security telemetry into responses.
    """
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    client_ip = request.client.host if request.client else "unknown"

    # 1. Verify Request Payload Size Limit
    content_length_header = request.headers.get("content-length")
    if content_length_header:
        try:
            cl_val = int(content_length_header)
            if cl_val > settings.MAX_REQUEST_BODY_SIZE:
                return create_error_response(
                    status_code=413,
                    error="Payload Too Large",
                    message=f"Request body exceeds maximum allowed size of {settings.MAX_REQUEST_BODY_SIZE} bytes",
                    request_id=request_id,
                )
        except ValueError:
            pass

    # 2. Read Request Body & Verify Body Size
    try:
        body = await request.body()
    except Exception as e:
        return create_error_response(
            status_code=400,
            error="Bad Request",
            message=f"Failed to read inbound request stream: {str(e)}",
            request_id=request_id,
        )

    if len(body) > settings.MAX_REQUEST_BODY_SIZE:
        return create_error_response(
            status_code=413,
            error="Payload Too Large",
            message=f"Request body exceeds maximum allowed size of {settings.MAX_REQUEST_BODY_SIZE} bytes",
            request_id=request_id,
        )

    # 3. Construct Target Upstream URL
    upstream_target = f"{settings.UPSTREAM_URL.rstrip('/')}{request.url.path}"
    if request.url.query:
        upstream_target = f"{upstream_target}?{request.url.query}"

    # 4. Prepare RFC 7230 Sanitized Upstream Headers
    upstream_headers = prepare_upstream_headers(
        request=request,
        request_id=request_id,
        client_ip=client_ip,
    )

    client = get_http_client()

    # 5. Build Upstream Forwarding Request
    try:
        upstream_req = client.build_request(
            method=request.method,
            url=upstream_target,
            headers=upstream_headers,
            content=body if request.method not in ("GET", "HEAD") else None,
        )

        upstream_resp = await client.send(upstream_req, stream=True)

        # 6. Prepare Sanitized Downstream Response Headers with Telemetry
        downstream_headers = prepare_downstream_headers(
            upstream_headers=upstream_resp.headers,
            decision=decision,
            request_id=request_id,
            latency_ms=latency_ms,
        )

        # 7. Stream Upstream Response Back to Client
        return StreamingResponse(
            upstream_resp.aiter_raw(),
            status_code=upstream_resp.status_code,
            headers=downstream_headers,
            background=BackgroundTask(upstream_resp.aclose),
        )

    except (httpx.ConnectError, httpx.ConnectTimeout):
        return create_error_response(
            status_code=502,
            error="Bad Gateway",
            message="Upstream protected application is unreachable or offline",
            request_id=request_id,
        )

    except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout):
        return create_error_response(
            status_code=504,
            error="Gateway Timeout",
            message=f"Upstream application timed out after {settings.REQUEST_TIMEOUT_SECONDS}s",
            request_id=request_id,
        )

    except Exception as e:
        return create_error_response(
            status_code=502,
            error="Bad Gateway",
            message=f"Reverse proxy encountered an unexpected transmission error: {str(e)}",
            request_id=request_id,
        )
