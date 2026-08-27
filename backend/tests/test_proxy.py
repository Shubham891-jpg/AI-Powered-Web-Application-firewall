"""
Reverse Proxy Engine & Gateway Unit Tests (Phase 6).
Tests multi-method proxying, RFC 7230 hop-by-hop sanitization, proxy header forwarding,
telemetry injection, payload size guards, and resilient 502/504 error handling.
"""

from unittest.mock import AsyncMock, patch
import httpx
import pytest
from starlette.requests import Request
from starlette.datastructures import Headers

from app.proxy.headers import (
    sanitize_proxy_headers,
    prepare_upstream_headers,
    prepare_downstream_headers,
    HOP_BY_HOP_HEADERS,
)
from app.proxy.response_handler import create_blocked_response, create_error_response
from app.proxy.proxy import reverse_proxy_handler
from app.detection.models import DecisionResult


def test_sanitize_proxy_headers_removes_all_rfc7230_hop_by_hop():
    """Verifies that every hop-by-hop header is stripped while end-to-end headers persist."""
    inbound_headers = {
        "content-type": "application/json",
        "connection": "keep-alive",
        "keep-alive": "timeout=5",
        "proxy-authenticate": "Basic",
        "proxy-authorization": "Bearer token",
        "te": "trailers",
        "trailers": "X-Custom",
        "transfer-encoding": "chunked",
        "upgrade": "websocket",
        "authorization": "Bearer secret-token",
        "cookie": "session=abc123xyz",
        "x-custom-security": "verified",
    }

    sanitized = sanitize_proxy_headers(inbound_headers)

    for h in HOP_BY_HOP_HEADERS:
        assert h not in sanitized

    assert sanitized["content-type"] == "application/json"
    assert sanitized["authorization"] == "Bearer secret-token"
    assert sanitized["cookie"] == "session=abc123xyz"
    assert sanitized["x-custom-security"] == "verified"


def test_prepare_upstream_headers():
    """Verifies upstream header mapping, client IP chaining, and ID tracking."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/products",
        "query_string": b"",
        "headers": [
            (b"host", b"waf.example.com"),
            (b"user-agent", b"Mozilla/5.0 TestBrowser"),
            (b"connection", b"close"),
            (b"x-forwarded-for", b"203.0.113.195"),
        ],
    }
    request = Request(scope)

    upstream = prepare_upstream_headers(
        request=request,
        request_id="req-proxy-001",
        client_ip="198.51.100.2",
    )

    # Hop-by-hop and original host must be removed
    assert "connection" not in upstream
    assert "host" not in upstream

    # X-Forwarded-* headers must be properly set
    assert upstream["X-Forwarded-For"] == "203.0.113.195, 198.51.100.2"
    assert upstream["X-Forwarded-Proto"] == "http"
    assert upstream["X-Forwarded-Host"] == "waf.example.com"
    assert upstream["X-Request-ID"] == "req-proxy-001"
    assert upstream["user-agent"] == "Mozilla/5.0 TestBrowser"


def test_prepare_downstream_headers_injects_telemetry():
    """Verifies that downstream responses have hop-by-hop headers stripped and security telemetry injected."""
    upstream_headers = {
        "content-type": "application/json",
        "connection": "close",
        "transfer-encoding": "chunked",
        "set-cookie": "token=12345; Path=/",
        "server": "protected-demo-app",
    }

    decision = DecisionResult(
        risk_score=45,
        classification="SQL_INJECTION",
        action="FLAG",
        reasons=["Suspicious syntax"],
    )

    downstream = prepare_downstream_headers(
        upstream_headers=upstream_headers,
        decision=decision,
        request_id="req-downstream-001",
        latency_ms=2.34,
    )

    assert "connection" not in downstream
    assert "transfer-encoding" not in downstream
    assert downstream["content-type"] == "application/json"
    assert downstream["set-cookie"] == "token=12345; Path=/"
    assert downstream["X-Request-ID"] == "req-downstream-001"
    assert downstream["X-WAF-Action"] == "FLAG"
    assert downstream["X-WAF-Risk-Score"] == "45"
    assert downstream["X-WAF-Category"] == "SQL_INJECTION"
    assert downstream["X-WAF-Latency"] == "2.34ms"
    assert downstream["X-WAF-Flagged"] == "true"


def test_create_blocked_response_structure():
    """Verifies uniform HTTP 403 blocked response structure."""
    resp = create_blocked_response(
        request_id="req-block-001",
        risk_score=95,
        category="CROSS_SITE_SCRIPTING",
        status_code=403,
    )
    assert resp.status_code == 403
    assert resp.headers["X-WAF-Action"] == "BLOCK"
    assert resp.headers["X-WAF-Risk-Score"] == "95"
    assert resp.headers["X-WAF-Category"] == "CROSS_SITE_SCRIPTING"
    assert resp.headers["X-Request-ID"] == "req-block-001"

    import json
    body = json.loads(resp.body)
    assert body["error"] == "Request blocked"
    assert body["request_id"] == "req-block-001"


@pytest.mark.asyncio
async def test_proxy_payload_too_large_413():
    """Verifies that requests exceeding MAX_REQUEST_BODY_SIZE are rejected with HTTP 413."""
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/upload",
        "query_string": b"",
        "headers": [
            (b"host", b"waf.example.com"),
            (b"content-length", b"20000000"),  # 20MB > 10MB limit
        ],
    }
    request = Request(scope)

    resp = await reverse_proxy_handler(request)
    assert resp.status_code == 413

    import json
    body = json.loads(resp.body)
    assert body["error"] == "Payload Too Large"


@pytest.mark.asyncio
async def test_proxy_upstream_connect_error_502():
    """Verifies that an unreachable upstream returns HTTP 502 Bad Gateway without crashing."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/status",
        "query_string": b"",
        "headers": [
            (b"host", b"waf.example.com"),
            (b"x-request-id", b"req-err-502"),
        ],
    }
    async def mock_receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(scope, receive=mock_receive)

    mock_client = AsyncMock()
    mock_client.build_request.return_value = httpx.Request("GET", "http://unreachable:9999/status")
    mock_client.send.side_effect = httpx.ConnectError("Connection refused")

    with patch("app.proxy.proxy.get_http_client", return_value=mock_client):
        resp = await reverse_proxy_handler(request)
        assert resp.status_code == 502
        import json
        body = json.loads(resp.body)
        assert body["error"] == "Bad Gateway"
        assert body["request_id"] == "req-err-502"


@pytest.mark.asyncio
async def test_proxy_upstream_timeout_error_504():
    """Verifies that an upstream read timeout returns HTTP 504 Gateway Timeout."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/slow",
        "query_string": b"",
        "headers": [
            (b"host", b"waf.example.com"),
            (b"x-request-id", b"req-err-504"),
        ],
    }
    async def mock_receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(scope, receive=mock_receive)

    mock_client = AsyncMock()
    mock_client.build_request.return_value = httpx.Request("GET", "http://upstream:3000/slow")
    mock_client.send.side_effect = httpx.ReadTimeout("Read timed out after 10.0s")

    with patch("app.proxy.proxy.get_http_client", return_value=mock_client):
        resp = await reverse_proxy_handler(request)
        assert resp.status_code == 504
        import json
        body = json.loads(resp.body)
        assert body["error"] == "Gateway Timeout"
        assert body["request_id"] == "req-err-504"


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def test_proxy_methods_forwarding(method: str):
    """Verifies transparent forwarding for all 7 standard HTTP methods."""
    scope = {
        "type": "http",
        "method": method,
        "path": "/resource",
        "query_string": b"param=1",
        "headers": [
            (b"host", b"waf.example.com"),
            (b"x-request-id", b"req-method-test"),
        ],
    }

    async def mock_receive():
        return {"type": "http.request", "body": b'{"key": "value"}', "more_body": False}

    request = Request(scope, receive=mock_receive)

    # Mock streaming response from upstream
    mock_upstream_resp = AsyncMock(spec=httpx.Response)
    mock_upstream_resp.status_code = 200
    mock_upstream_resp.headers = httpx.Headers({"content-type": "application/json"})

    async def aiter_raw():
        yield b'{"status": "proxied_successfully"}'

    mock_upstream_resp.aiter_raw = aiter_raw
    mock_upstream_resp.aclose = AsyncMock()

    mock_client = AsyncMock()
    mock_client.build_request.return_value = httpx.Request(method, "http://upstream:3000/resource?param=1")
    mock_client.send.return_value = mock_upstream_resp

    with patch("app.proxy.proxy.get_http_client", return_value=mock_client):
        resp = await reverse_proxy_handler(request)
        assert resp.status_code == 200
        assert resp.headers["X-Request-ID"] == "req-method-test"
        assert resp.headers["X-WAF-Action"] == "ALLOW"
