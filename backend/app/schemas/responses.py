"""
Pydantic Response Schemas for AI-WAF API and Health Monitoring.
"""

from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field


class ServiceComponentHealth(BaseModel):
    name: str
    status: Literal["healthy", "degraded", "unhealthy", "disabled"]
    latency_ms: float | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    status: Literal["healthy", "degraded", "unhealthy"]
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    version: str
    environment: str
    uptime_seconds: float
    components: dict[str, ServiceComponentHealth]


class SimpleHealthResponse(BaseModel):
    status: str = "ok"
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class SecurityEventResponse(BaseModel):
    id: str
    request_id: str
    timestamp: datetime
    client_ip: str
    http_method: str
    path: str
    query_params: dict[str, Any] = Field(default_factory=dict)
    attack_category: str
    risk_score: int
    ml_confidence: float | None = None
    action: Literal["ALLOW", "FLAG", "BLOCK"]
    matched_rules: list[dict[str, Any]] = Field(default_factory=list)
    model_version: str | None = None
    response_status: int
    processing_latency_ms: float


class DashboardSummaryResponse(BaseModel):
    total_requests: int = 0
    allowed_requests: int = 0
    flagged_requests: int = 0
    blocked_requests: int = 0
    threat_rate_percentage: float = 0.0
    requests_per_second: float = 0.0
    avg_inspection_latency_ms: float = 0.0
    attack_distribution: dict[str, int] = Field(default_factory=dict)
