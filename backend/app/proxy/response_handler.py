"""
Response handling and header manipulation for WAF reverse proxy.
"""

from typing import Mapping
from fastapi.responses import Response, JSONResponse

# Hop-by-hop headers that must not be forwarded by a reverse proxy
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


def create_blocked_response(request_id: str, status_code: int = 403) -> JSONResponse:
    """
    Standard blocked response per specification (Section 21).
    Never exposes internal detection details to clients.
    """
    return JSONResponse(
        status_code=status_code,
        content={
            "error": "Request blocked by security policy",
            "request_id": request_id,
        },
        headers={
            "X-WAF-Action": "BLOCK",
            "X-Request-ID": request_id,
        },
    )


def sanitize_proxy_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Strips hop-by-hop headers from upstream responses."""
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS
    }
