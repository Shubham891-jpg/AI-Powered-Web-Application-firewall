"""
Pydantic Models and Data Schemas for Threat Detection & Explainability (Phase 5).
Captures granular rule matches, ML probabilities, contextual penalties, and full audit explanations.
"""

from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, Field


class RuleMatchDetail(BaseModel):
    """Detailed audit information for an individual matched detection rule."""
    rule_id: str
    rule_name: str
    category: str
    confidence: str
    score: int
    reason: str
    indicators: list[str] = Field(default_factory=list)


class MLPredictionDetail(BaseModel):
    """Detailed metrics from the supervised ML classification."""
    model_config = {"protected_namespaces": ()}

    predicted_class: str
    confidence: float
    model_name: str
    model_version: str
    vectorizer_version: str
    latency_ms: float = 0.0


class ContextPenaltyDetail(BaseModel):
    """Heuristic contextual threat penalties applied to a request."""
    factor: str
    penalty_points: int
    reason: str


class InspectionExplanation(BaseModel):
    """
    Comprehensive explainability payload per Section 20 of specification.
    Provides complete transparency for security operations and SIEM telemetry.
    """
    request_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    decision: Literal["ALLOW", "FLAG", "BLOCK"]
    risk_score: int = Field(..., ge=0, le=100)
    category: str
    rule_matches: list[RuleMatchDetail] = Field(default_factory=list)
    ml_prediction: MLPredictionDetail
    contextual_penalties: list[ContextPenaltyDetail] = Field(default_factory=list)
    primary_reason: str
    latency_ms: float = 0.0


class DecisionResult(BaseModel):
    """Decision output produced by the Fusion Risk Engine."""
    risk_score: int = Field(..., ge=0, le=100)
    classification: str
    action: Literal["ALLOW", "FLAG", "BLOCK"]
    reasons: list[str] = Field(default_factory=list)
    rule_score: int = 0
    ml_confidence: float | None = None
    explanation: InspectionExplanation | None = None
