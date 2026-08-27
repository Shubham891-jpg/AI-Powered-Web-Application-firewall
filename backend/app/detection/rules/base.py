"""
Base Rule Interface, Confidence Model, and Rule Registry for AI-WAF Rule Engine.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class RuleConfidence(str, Enum):
    """Detection confidence level per Section 9 specification."""
    NO_EVIDENCE = "NO_EVIDENCE"          # Score: 0
    SUSPICIOUS = "SUSPICIOUS"            # Score: 30 - 50
    LIKELY = "LIKELY"                    # Score: 51 - 79
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"  # Score: 80 - 100


def score_to_confidence(score: int) -> RuleConfidence:
    """Maps numerical threat score to standardized confidence enum."""
    if score >= 80:
        return RuleConfidence.HIGH_CONFIDENCE
    elif score >= 51:
        return RuleConfidence.LIKELY
    elif score >= 30:
        return RuleConfidence.SUSPICIOUS
    return RuleConfidence.NO_EVIDENCE


class RuleResult(BaseModel):
    """Structured inspection result returned by a security rule."""
    matched: bool = False
    category: str = "NORMAL"
    score: int = Field(default=0, ge=0, le=100)
    rule_id: str
    confidence: RuleConfidence = RuleConfidence.NO_EVIDENCE
    reason: str = ""
    indicators: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class BaseRule(ABC):
    """Abstract base class for all detection rules."""

    def __init__(self, rule_id: str, name: str, category: str, score: int):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.score = score
        self.enabled = True

    @abstractmethod
    def analyze(self, target_text: str) -> RuleResult:
        """Inspects target string and returns a RuleResult."""
        pass


class RuleRegistry:
    """Central registry managing loaded detection rules."""

    def __init__(self):
        self._rules: dict[str, BaseRule] = {}

    def register(self, rule: BaseRule):
        self._rules[rule.rule_id] = rule

    def unregister(self, rule_id: str):
        self._rules.pop(rule_id, None)

    def get(self, rule_id: str) -> Optional[BaseRule]:
        return self._rules.get(rule_id)

    def get_all_active(self) -> list[BaseRule]:
        return [r for r in self._rules.values() if r.enabled]

    def set_rule_enabled(self, rule_id: str, enabled: bool):
        if rule_id in self._rules:
            self._rules[rule_id].enabled = enabled
