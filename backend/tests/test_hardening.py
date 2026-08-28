"""
Security Hardening, SSRF Protection, and Credential Redaction Tests (Phase 10).
Tests admin authentication, SSRF metadata boundary checks, header/body redaction,
size limit guards (414, 431), and defensive response headers.
"""

import pytest
from fastapi import HTTPException
from httpx import AsyncClient, ASGITransport
from app.config import settings
from app.main import app
from app.security.auth import verify_admin_key
from app.security.ssrf import validate_upstream_url_safety, SSRFException
from app.security.redaction import redact_headers, redact_payload_text
from app.security.headers import apply_defensive_headers


@pytest.mark.asyncio
async def test_admin_auth_verification():
    """Validates that verify_admin_key accepts valid key and rejects invalid/missing."""
    # Valid key
    assert await verify_admin_key(api_key=settings.ADMIN_API_KEY) is True

    # Invalid key
    with pytest.raises(HTTPException) as exc_info:
        await verify_admin_key(api_key="wrong-admin-key")
    assert exc_info.value.status_code == 401

    # Missing key
    with pytest.raises(HTTPException) as exc_missing:
        await verify_admin_key(api_key=None)
    assert exc_missing.value.status_code == 401


def test_ssrf_blocks_cloud_metadata_ip():
    """Verifies that requests targeting AWS/GCP metadata service (169.254.169.254) are rejected."""
    with pytest.raises(SSRFException) as exc:
        validate_upstream_url_safety("http://169.254.169.254/latest/meta-data/")
    assert "forbidden network" in str(exc.value).lower()


def test_ssrf_blocks_unauthorized_internal_network():
    """Verifies that requests targeting arbitrary internal RFC 1918 subnets are rejected."""
    with pytest.raises(SSRFException) as exc:
        validate_upstream_url_safety("http://10.240.0.5:8080/admin")
    assert "unauthorized private network" in str(exc.value).lower()


def test_ssrf_allows_configured_upstream():
    """Verifies that whitelisted development and docker upstream hosts are allowed."""
    assert validate_upstream_url_safety("http://127.0.0.1:3000") is True
    assert validate_upstream_url_safety("http://localhost:8080") is True


def test_credential_redaction_in_headers():
    """Verifies that authentication tokens and cookies are masked in header maps."""
    raw_headers = {
        "Host": "api.protected.com",
        "Authorization": "Bearer super-secret-jwt-token-xyz",
        "Cookie": "session_id=abcdef123456; tracking=none",
        "X-API-Key": "secret-admin-key-777",
        "User-Agent": "Mozilla/5.0",
    }
    redacted = redact_headers(raw_headers)
    assert redacted["Authorization"] == "[REDACTED]"
    assert redacted["Cookie"] == "[REDACTED]"
    assert redacted["X-API-Key"] == "[REDACTED]"
    assert redacted["Host"] == "api.protected.com"
    assert redacted["User-Agent"] == "Mozilla/5.0"


def test_credential_redaction_in_json_and_text():
    """Verifies that passwords and credit card patterns are masked in payloads."""
    # JSON payload
    json_payload = '{"username": "alice", "password": "SuperSecretPassword123!", "api_key": "key-999"}'
    redacted_json = redact_payload_text(json_payload)
    assert "SuperSecretPassword123!" not in redacted_json
    assert "[REDACTED]" in redacted_json
    assert "alice" in redacted_json

    # Form text payload
    form_payload = "user=bob&password=PlaintextPassword&action=login"
    redacted_form = redact_payload_text(form_payload)
    assert "PlaintextPassword" not in redacted_form
    assert "[REDACTED]" in redacted_form


@pytest.mark.asyncio
async def test_uri_too_long_guard_414():
    """Verifies that requests with excessively long URIs are rejected with HTTP 414."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        long_query = "q=" + ("A" * 3000)
        resp = await client.get(f"/search?{long_query}")
        assert resp.status_code == 414
        data = resp.json()
        assert data["error"] == "URI Too Long"
        assert "X-Request-ID" in resp.headers


@pytest.mark.asyncio
async def test_header_fields_too_large_431():
    """Verifies that oversized headers trigger HTTP 431."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        huge_headers = {"X-Oversized-Header": "X" * (settings.MAX_HEADER_SIZE + 1024)}
        resp = await client.get("/search?q=normal", headers=huge_headers)
        assert resp.status_code == 431
        data = resp.json()
        assert data["error"] == "Request Header Fields Too Large"


@pytest.mark.asyncio
async def test_defensive_security_response_headers():
    """Verifies standard defense-in-depth security headers are present on proxy responses."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["X-XSS-Protection"] == "1; mode=block"
        assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
