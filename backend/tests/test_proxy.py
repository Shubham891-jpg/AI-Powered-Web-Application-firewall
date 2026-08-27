"""
Tests for reverse proxy response handling and header filtering.
"""

from app.proxy.response_handler import sanitize_proxy_headers, create_blocked_response


def test_sanitize_proxy_headers_removes_hop_by_hop():
    inbound_headers = {
        "content-type": "application/json",
        "connection": "keep-alive",
        "keep-alive": "timeout=5",
        "x-custom-header": "security-tested",
        "transfer-encoding": "chunked",
    }
    sanitized = sanitize_proxy_headers(inbound_headers)
    assert "connection" not in sanitized
    assert "keep-alive" not in sanitized
    assert "transfer-encoding" not in sanitized
    assert sanitized["content-type"] == "application/json"
    assert sanitized["x-custom-header"] == "security-tested"


def test_create_blocked_response_structure():
    resp = create_blocked_response("req-12345")
    assert resp.status_code == 403
    assert resp.headers["X-WAF-Action"] == "BLOCK"
    assert resp.headers["X-Request-ID"] == "req-12345"
