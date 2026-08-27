"""
Pydantic Request Schemas for AI-WAF API.
"""

from typing import Literal
from pydantic import BaseModel, Field


class ApplicationCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    upstream_url: str = Field(..., pattern=r"^https?://")
    detection_mode: Literal["BLOCK", "FLAG_ONLY", "MONITOR"] = "BLOCK"
    rate_limit_requests: int = Field(default=100, ge=1)
    rate_limit_window_seconds: int = Field(default=60, ge=1)


class RuleCreateRequest(BaseModel):
    rule_id: str = Field(..., min_length=3, max_length=50)
    name: str = Field(..., min_length=3, max_length=100)
    category: Literal["SQL_INJECTION", "XSS", "COMMAND_INJECTION", "PATH_TRAVERSAL", "SUSPICIOUS"]
    pattern: str = Field(..., min_length=1)
    score: int = Field(..., ge=0, le=100)
    enabled: bool = True
    description: str | None = None
