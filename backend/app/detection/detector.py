"""
Unified Threat Detector Orchestrator for AI-WAF.
Coordinates normalization, rule execution through RuleRegistry, ML classification, and risk evaluation.
"""

from typing import Union
from app.detection.preprocessing import (
    InspectedRequestContext,
    RequestNormalizer,
    normalize_string,
)
from app.detection.rules.base import BaseRule, RuleRegistry, RuleResult, RuleConfidence
from app.detection.rules.sqli import SQLInjectionRule
from app.detection.rules.xss import XSSRule
from app.detection.rules.command_injection import CommandInjectionRule
from app.detection.rules.path_traversal import PathTraversalRule
from app.detection.ml.classifier import ml_classifier
from app.detection.risk_engine import risk_engine, DecisionResult


class RequestDetector:
    def __init__(self):
        self.registry = RuleRegistry()
        # Register core detection rules
        self.registry.register(SQLInjectionRule())
        self.registry.register(XSSRule())
        self.registry.register(CommandInjectionRule())
        self.registry.register(PathTraversalRule())

    @property
    def rules(self) -> list[BaseRule]:
        return self.registry.get_all_active()

    def inspect_context(
        self, context: InspectedRequestContext
    ) -> tuple[DecisionResult, list[RuleResult], str]:
        """
        Inspects an entire InspectedRequestContext across all HTTP attack vectors:
        Path, parameters, headers, and body.
        """
        matched_rules: list[RuleResult] = []
        highest_rule_score = 0
        primary_category = "NORMAL"
        reasons: list[str] = []

        # Heuristic anomalies from normalizer
        if context.normalized.encoding_depth > 1:
            reasons.append(
                f"Suspicious nested URL encoding detected (recursion depth: {context.normalized.encoding_depth})"
            )
            highest_rule_score = max(highest_rule_score, 45)
            primary_category = "SUSPICIOUS"

        if context.normalized.has_null_bytes:
            reasons.append("Dangerous null-byte (%00 / \\x00) injection attempt detected")
            highest_rule_score = max(highest_rule_score, 75)
            primary_category = "SUSPICIOUS"

        inspection_target = context.normalized.canonical_inspection_string

        # Execute registered active rules
        for rule in self.rules:
            result = rule.analyze(inspection_target)
            # If path traversal, also check raw path (e.g. %2e%2e%2f)
            if not result.matched and rule.category == "PATH_TRAVERSAL":
                result = rule.analyze(context.raw.path)

            if result.matched:
                matched_rules.append(result)
                reasons.append(f"[{result.confidence.value}] {result.reason}")
                if result.score > highest_rule_score:
                    highest_rule_score = result.score
                    primary_category = result.category

        # Execute ML classification on the normalized string
        ml_class, ml_conf = ml_classifier.predict(inspection_target)
        if ml_class != "NORMAL":
            reasons.append(f"ML classified as {ml_class} with {ml_conf:.2f} confidence")

        decision = risk_engine.evaluate(
            rule_score=highest_rule_score,
            rule_category=primary_category,
            ml_class=ml_class,
            ml_confidence=ml_conf,
            reasons=reasons,
        )

        return decision, matched_rules, inspection_target

    def inspect(
        self, target: Union[str, InspectedRequestContext]
    ) -> tuple[DecisionResult, list[RuleResult], str]:
        """
        Main inspection entry point.
        Supports both string payloads and complete InspectedRequestContext objects.
        """
        if isinstance(target, InspectedRequestContext):
            return self.inspect_context(target)

        # Fallback string inspection
        norm_result = normalize_string(target)
        normalized = norm_result.normalized

        matched_rules: list[RuleResult] = []
        highest_rule_score = 0
        primary_category = "NORMAL"
        reasons: list[str] = []

        if norm_result.is_multivalue_encoded:
            reasons.append("Suspicious multi-layer URL encoding detected")
            highest_rule_score = max(highest_rule_score, 45)
            primary_category = "SUSPICIOUS"

        for rule in self.rules:
            result = rule.analyze(normalized)
            if not result.matched:
                result = rule.analyze(target)
            if result.matched:
                matched_rules.append(result)
                reasons.append(f"[{result.confidence.value}] {result.reason}")
                if result.score > highest_rule_score:
                    highest_rule_score = result.score
                    primary_category = result.category

        ml_class, ml_conf = ml_classifier.predict(normalized)
        if ml_class != "NORMAL":
            reasons.append(f"ML classified as {ml_class} with {ml_conf:.2f} confidence")

        decision = risk_engine.evaluate(
            rule_score=highest_rule_score,
            rule_category=primary_category,
            ml_class=ml_class,
            ml_confidence=ml_conf,
            reasons=reasons,
        )

        return decision, matched_rules, normalized


request_detector = RequestDetector()
