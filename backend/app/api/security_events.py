"""
Security Events and Metrics API Endpoints.
"""

from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter
from app.schemas.responses import DashboardSummaryResponse, SecurityEventResponse

router = APIRouter(prefix="/security-events", tags=["Security Events"])


@router.get("", response_model=List[SecurityEventResponse])
async def list_security_events(limit: int = 50):
    """Lists recent security events."""
    # In Phase 1 initial scaffold, return clean list or baseline structure
    return []


@router.get("/summary", response_model=DashboardSummaryResponse)
async def get_dashboard_summary():
    """Returns aggregated threat metrics for the dashboard."""
    return DashboardSummaryResponse(
        total_requests=0,
        allowed_requests=0,
        flagged_requests=0,
        blocked_requests=0,
        threat_rate_percentage=0.0,
        requests_per_second=0.0,
        avg_inspection_latency_ms=1.2,
        attack_distribution={
            "SQL_INJECTION": 0,
            "CROSS_SITE_SCRIPTING": 0,
            "COMMAND_INJECTION": 0,
            "PATH_TRAVERSAL": 0,
            "SUSPICIOUS": 0,
        },
    )
