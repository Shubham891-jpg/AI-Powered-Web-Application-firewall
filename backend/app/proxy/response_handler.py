"""
Response handling and blocked response creation for WAF reverse proxy (Phase 6).
Ensures safe, uniform error structures without exposing internal detection heuristics.
"""

from typing import Mapping
from fastapi.responses import JSONResponse
from app.proxy.headers import HOP_BY_HOP_HEADERS, sanitize_proxy_headers


def create_blocked_response(
    request_id: str,
    risk_score: int = 85,
    category: str = "MALICIOUS",
    status_code: int = 403,
) -> JSONResponse:
    """
    Standard blocked response per specification (Section 21).
    Returns consistent HTTP 403 JSON payload: {"error": "Request blocked", "request_id": "..."}.
    Never exposes internal detection rules, regexes, or system internals to clients.
    """
    return JSONResponse(
        status_code=status_code,
        content={
            "error": "Request blocked",
            "request_id": request_id,
        },
        headers={
            "X-WAF-Action": "BLOCK",
            "X-WAF-Risk-Score": str(risk_score),
            "X-WAF-Category": category,
            "X-Request-ID": request_id,
        },
    )


def create_error_response(
    status_code: int,
    error: str,
    message: str,
    request_id: str,
) -> JSONResponse:
    """Creates a consistent JSON error response for proxy upstream failures."""
    return JSONResponse(
        status_code=status_code,
        content={
            "error": error,
            "message": message,
            "request_id": request_id,
        },
        headers={
            "X-WAF-Action": "ERROR",
            "X-Request-ID": request_id,
        },
    )
