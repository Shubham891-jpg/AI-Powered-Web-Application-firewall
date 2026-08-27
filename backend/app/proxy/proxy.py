"""
Reverse proxy routing logic.
Connects inbound client requests to the protected upstream application.
"""

import uuid
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
import httpx

from app.config import settings
from app.proxy.upstream import get_http_client
from app.proxy.response_handler import sanitize_proxy_headers

router = APIRouter()


async def reverse_proxy_handler(request: Request) -> Response:
    """
    Transparent reverse proxy handler.
    Proxies permitted client requests to settings.UPSTREAM_URL.
    """
    client = get_http_client()
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    upstream_target = f"{settings.UPSTREAM_URL}{request.url.path}"
    if request.url.query:
        upstream_target = f"{upstream_target}?{request.url.query}"

    # Filter inbound headers
    req_headers = dict(request.headers)
    req_headers["X-Forwarded-For"] = request.client.host if request.client else "unknown"
    req_headers["X-Request-ID"] = request_id
    req_headers.pop("host", None)

    try:
        body = await request.body()
        upstream_resp = await client.request(
            method=request.method,
            url=upstream_target,
            headers=req_headers,
            content=body,
        )

        response_headers = sanitize_proxy_headers(upstream_resp.headers)
        response_headers["X-Request-ID"] = request_id

        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=response_headers,
        )
    except httpx.ConnectError:
        return JSONResponse(
            status_code=502,
            content={"error": "Bad Gateway: Upstream protected application unreachable", "request_id": request_id},
        )
    except httpx.TimeoutException:
        return JSONResponse(
            status_code=504,
            content={"error": "Gateway Timeout: Upstream application did not respond", "request_id": request_id},
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": "Internal Proxy Error", "request_id": request_id},
        )
