"""
Defensive Security Response Headers (Phase 10).
Injects browser defense-in-depth security headers on all downstream responses.
"""

from fastapi import Response

DEFENSIVE_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


def apply_defensive_headers(response: Response) -> Response:
    """Applies standard browser security headers to HTTP responses."""
    for header, value in DEFENSIVE_SECURITY_HEADERS.items():
        if header not in response.headers:
            response.headers[header] = value
    return response
