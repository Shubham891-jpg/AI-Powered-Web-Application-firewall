"""
Dashboard & Management API Unit Tests (Phase 9).
Tests security event queries, summary statistics, forensic details,
application management CRUD, and dynamic detection rule toggling.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.mark.asyncio
async def test_list_security_events_endpoint():
    """Verifies GET /api/v1/security-events returns paginated results."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/security-events?limit=10")
        assert resp.status_code == 200
        data = resp.json()
        assert "events" in data
        assert "total" in data
        assert isinstance(data["events"], list)
        assert len(data["events"]) > 0


@pytest.mark.asyncio
async def test_filter_security_events_by_category():
    """Verifies category filtering on security events."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/security-events?category=SQL_INJECTION")
        assert resp.status_code == 200
        data = resp.json()
        for ev in data["events"]:
            assert ev["attack_category"] == "SQL_INJECTION"


@pytest.mark.asyncio
async def test_filter_security_events_by_action():
    """Verifies action filtering on security events."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/security-events?action=BLOCK")
        assert resp.status_code == 200
        data = resp.json()
        for ev in data["events"]:
            assert ev["action"] == "BLOCK"


@pytest.mark.asyncio
async def test_dashboard_summary_endpoint():
    """Verifies GET /api/v1/security-events/summary aggregated metrics."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/security-events/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_requests" in data
        assert "blocked_requests" in data
        assert "attack_distribution" in data
        assert data["total_requests"] >= 0


@pytest.mark.asyncio
async def test_security_event_detail_endpoint():
    """Verifies GET /api/v1/security-events/{id} forensic breakdown."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/security-events/demo-ev-001")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "demo-ev-001"
        assert data["attack_category"] == "SQL_INJECTION"
        assert data["risk_score"] == 95
        assert "matched_rules" in data
        assert "ml_prediction" in data


@pytest.mark.asyncio
async def test_applications_management_crud():
    """Verifies GET, POST, and PATCH on /api/v1/applications."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. List
        list_resp = await client.get("/api/v1/applications")
        assert list_resp.status_code == 200
        assert isinstance(list_resp.json(), list)

        # 2. Create
        create_payload = {
            "name": "Test Staging Service",
            "upstream_url": "http://staging.local:4000",
            "is_active": True,
            "detection_mode": "FLAG_ONLY",
            "rate_limit_requests": 150,
        }
        create_resp = await client.post("/api/v1/applications", json=create_payload)
        assert create_resp.status_code == 200
        created = create_resp.json()
        assert created["name"] == "Test Staging Service"
        app_id = created["id"]

        # 3. Update
        update_resp = await client.patch(f"/api/v1/applications/{app_id}", json={"detection_mode": "BLOCK"})
        assert update_resp.status_code == 200
        assert update_resp.json()["detection_mode"] == "BLOCK"


@pytest.mark.asyncio
async def test_rules_management_endpoint():
    """Verifies GET and PATCH on /api/v1/rules."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # List
        rules_resp = await client.get("/api/v1/rules")
        assert rules_resp.status_code == 200
        rules = rules_resp.json()
        assert len(rules) > 0
        rule_id = rules[0]["rule_id"]

        # Toggle disable
        patch_resp = await client.patch(f"/api/v1/rules/{rule_id}", json={"enabled": False, "score": 92})
        assert patch_resp.status_code == 200
        updated = patch_resp.json()
        assert updated["enabled"] is False
        assert updated["score"] == 92

        # Toggle back
        await client.patch(f"/api/v1/rules/{rule_id}", json={"enabled": True, "score": 85})
