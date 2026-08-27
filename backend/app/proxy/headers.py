"""
Header Manipulation & RFC 7230 Sanitization for AI-WAF Reverse Proxy (Phase 6).
Handles hop-by-hop header removal, proxy forwarding tracking, and security telemetry injection.
"""

from typing import Mapping
from starlette.requests import Request
from app.detection.models import DecisionResult

# Standard RFC 7230 and RFC 2616 Hop-by-Hop headers that MUST NOT be forwarded
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


def sanitize_proxy_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Removes all hop-by-hop headers from the given header dictionary."""
    return {
        k: v
        for k, v in headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }


def prepare_upstream_headers(
    request: Request,
    request_id: str,
    client_ip: str,
) -> dict[str, str]:
    """
    Builds sanitized header map to forward to the protected upstream application.
    Strips hop-by-hop headers, manages X-Forwarded-* headers, and attaches X-Request-ID.
    """
    headers: dict[str, str] = {}

    for k, v in request.headers.items():
        k_lower = k.lower()
        if k_lower not in HOP_BY_HOP_HEADERS and k_lower != "host":
            headers[k] = v

    # 1. X-Forwarded-For: Append client IP
    existing_xff = request.headers.get("x-forwarded-for")
    if existing_xff:
        headers["X-Forwarded-For"] = f"{existing_xff}, {client_ip}"
    else:
        headers["X-Forwarded-For"] = client_ip

    # 2. X-Forwarded-Proto
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    headers["X-Forwarded-Proto"] = proto

    # 3. X-Forwarded-Host
    host = request.headers.get("host") or request.url.netloc
    headers["X-Forwarded-Host"] = host

    # 4. X-Request-ID
    headers["X-Request-ID"] = request_id

    return headers


def prepare_downstream_headers(
    upstream_headers: Mapping[str, str],
    decision: DecisionResult | None,
    request_id: str,
    latency_ms: float = 0.0,
) -> dict[str, str]:
    """
    Sanitizes upstream response headers and injects WAF security inspection telemetry.
    """
    downstream: dict[str, str] = {}

    # Strip hop-by-hop headers from upstream response
    for k, v in upstream_headers.items():
        if k.lower() not in HOP_BY_HOP_HEADERS:
            downstream[k] = v

    # Inject Request ID
    downstream["X-Request-ID"] = request_id

    # Inject WAF Security Telemetry Headers
    if decision:
        downstream["X-WAF-Action"] = decision.action
        downstream["X-WAF-Risk-Score"] = str(decision.risk_score)
        downstream["X-WAF-Category"] = decision.classification
        downstream["X-WAF-Latency"] = f"{latency_ms:.2f}ms"
        if decision.action == "FLAG":
            downstream["X-WAF-Flagged"] = "true"
    else:
        downstream["X-WAF-Action"] = "ALLOW"
        downstream["X-WAF-Risk-Score"] = "0"
        downstream["X-WAF-Category"] = "NORMAL"
        downstream["X-WAF-Latency"] = f"{latency_ms:.2f}ms"

    return downstream
