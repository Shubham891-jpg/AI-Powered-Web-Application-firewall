"""
API and Health Endpoint Tests for AI-WAF Gateway.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.mark.asyncio
async def test_liveness_probe():
    """Validates that GET /health returns 200 OK."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "timestamp" in data


@pytest.mark.asyncio
async def test_readiness_probe():
    """Validates that GET /api/health returns detailed component diagnostic statuses."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "components" in data
        components = data["components"]
        assert "upstream" in components
        assert "redis" in components
        assert "database" in components
        assert "detection" in components
        assert components["detection"]["status"] == "healthy"


@pytest.mark.asyncio
async def test_public_config_endpoint():
    """Validates that GET /api/v1/config returns public configuration without secret leakage."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/config")
        assert response.status_code == 200
        data = response.json()
        assert "app_name" in data
        assert "thresholds" in data
        assert "detection_mode" in data
        # Ensure passwords and secret keys are NOT exposed
        assert "SECRET_KEY" not in data
        assert "POSTGRES_PASSWORD" not in data
        assert "REDIS_PASSWORD" not in data


@pytest.mark.asyncio
async def test_request_id_generation():
    """Validates that incoming requests receive an X-Request-ID header."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
        assert "X-Request-ID" in response.headers
        assert len(response.headers["X-Request-ID"]) > 10
