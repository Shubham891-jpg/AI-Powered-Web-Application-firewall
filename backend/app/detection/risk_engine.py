"""
AI-WAF Risk Engine.
Combines deterministic rule scores and ML classification probabilities
to calculate a final composite risk score (0-100) and security action.
"""

from typing import Literal
from pydantic import BaseModel, Field
from app.config import settings


class DecisionResult(BaseModel):
    risk_score: int = Field(..., ge=0, le=100)
    classification: str
    action: Literal["ALLOW", "FLAG", "BLOCK"]
    reasons: list[str] = Field(default_factory=list)
    rule_score: int = 0
    ml_confidence: float | None = None


class RiskEngine:
    def __init__(
        self,
        allow_threshold: int | None = None,
        flag_threshold: int | None = None,
        block_threshold: int | None = None,
        mode: str | None = None,
    ):
        self.allow_threshold = allow_threshold or settings.ALLOW_THRESHOLD
        self.flag_threshold = flag_threshold or settings.FLAG_THRESHOLD
        self.block_threshold = block_threshold or settings.BLOCK_THRESHOLD
        self.mode = mode or settings.DETECTION_MODE

    def evaluate(
        self,
        rule_score: int,
        rule_category: str,
        ml_class: str,
        ml_confidence: float,
        reasons: list[str],
    ) -> DecisionResult:
        """
        Computes composite risk score:
        Composite = 0.65 * rule_score + 0.35 * (ml_confidence * 100 if ml_class != 'NORMAL' else 0)
        """
        ml_score = 0.0
        if ml_class != "NORMAL":
            ml_score = ml_confidence * 100.0

        # Weighted calculation
        if rule_score > 0 and ml_score > 0:
            composite = 0.60 * rule_score + 0.40 * ml_score
        elif rule_score > 0:
            composite = float(rule_score)
        elif ml_score > 0:
            composite = 0.70 * ml_score
        else:
            composite = 0.0

        risk_score = min(100, max(0, int(round(composite))))

        # Determine primary threat category
        if rule_category != "NORMAL":
            primary_class = rule_category
        elif ml_class != "NORMAL":
            primary_class = ml_class
        else:
            primary_class = "NORMAL"

        # Determine action
        if risk_score >= self.block_threshold:
            action = "BLOCK"
        elif risk_score > self.allow_threshold:
            action = "FLAG"
        else:
            action = "ALLOW"

        # Enforce Detection Mode policy
        if self.mode == "FLAG_ONLY" and action == "BLOCK":
            action = "FLAG"
        elif self.mode == "MONITOR" and action in ("BLOCK", "FLAG"):
            action = "ALLOW"

        return DecisionResult(
            risk_score=risk_score,
            classification=primary_class,
            action=action,
            reasons=reasons,
            rule_score=rule_score,
            ml_confidence=ml_confidence,
        )


risk_engine = RiskEngine()
