"""
Unified Threat Detector Orchestrator for AI-WAF (Phase 5).
Coordinates request normalization, multi-tier rule execution through RuleRegistry,
supervised ML classification, and explainable risk evaluation through the Risk Engine.
"""

import time
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
from app.detection.risk_engine import risk_engine
from app.detection.models import DecisionResult


class RequestDetector:
    def __init__(self):
        self.registry = RuleRegistry()
        # Register core multi-tier detection rules
        self.registry.register(SQLInjectionRule())
        self.registry.register(XSSRule())
        self.registry.register(CommandInjectionRule())
        self.registry.register(PathTraversalRule())

    @property
    def rules(self) -> list[BaseRule]:
        return self.registry.get_all_active()

    def inspect_context(
        self, context: InspectedRequestContext, request_id: str = "req-0000"
    ) -> tuple[DecisionResult, list[RuleResult], str]:
        """
        Inspects an entire InspectedRequestContext across all HTTP attack vectors:
        Path, query parameters, headers, and body.
        """
        t0 = time.perf_counter()
        matched_rules: list[RuleResult] = []
        inspection_target = context.normalized.canonical_inspection_string

        # 1. Execute registered active rules
        for rule in self.rules:
            result = rule.analyze(inspection_target)
            # If path traversal, also check raw path (e.g. %2e%2e%2f)
            if not result.matched and rule.category == "PATH_TRAVERSAL":
                result = rule.analyze(context.raw.path)

            if result.matched:
                matched_rules.append(result)

        # 2. Execute ML classification on canonical inspection string
        ml_class, ml_conf = ml_classifier.predict(inspection_target)
        ml_info = ml_classifier.get_info()

        total_latency = (time.perf_counter() - t0) * 1000.0

        # 3. Evaluate through unified Risk Scoring Engine
        decision = risk_engine.evaluate(
            rule_results=matched_rules,
            ml_class=ml_class,
            ml_confidence=ml_conf,
            model_name=ml_info.get("model_name", "waf_classifier"),
            model_version=ml_info.get("model_version", "1.0.0"),
            vectorizer_version=ml_info.get("vectorizer_version", "1.0.0"),
            ml_latency_ms=ml_classifier.last_inference_latency_ms,
            request_id=request_id,
            path=context.raw.path,
            url_decode_depth=context.normalized.encoding_depth,
            has_null_bytes=context.normalized.has_null_bytes,
            has_unicode_anomalies=context.normalized.has_unicode_anomalies,
            total_latency_ms=total_latency,
        )

        return decision, matched_rules, inspection_target

    def inspect(
        self, target: Union[str, InspectedRequestContext], request_id: str = "req-0000"
    ) -> tuple[DecisionResult, list[RuleResult], str]:
        """
        Main inspection entry point.
        Supports both string payloads and complete InspectedRequestContext objects.
        """
        if isinstance(target, InspectedRequestContext):
            return self.inspect_context(target, request_id=request_id)

        # Fallback string inspection
        t0 = time.perf_counter()
        norm_result = normalize_string(target)
        normalized = norm_result.normalized

        matched_rules: list[RuleResult] = []
        for rule in self.rules:
            result = rule.analyze(normalized)
            if not result.matched:
                result = rule.analyze(target)
            if result.matched:
                matched_rules.append(result)

        ml_class, ml_conf = ml_classifier.predict(normalized)
        ml_info = ml_classifier.get_info()
        total_latency = (time.perf_counter() - t0) * 1000.0

        decision = risk_engine.evaluate(
            rule_results=matched_rules,
            ml_class=ml_class,
            ml_confidence=ml_conf,
            model_name=ml_info.get("model_name", "waf_classifier"),
            model_version=ml_info.get("model_version", "1.0.0"),
            vectorizer_version=ml_info.get("vectorizer_version", "1.0.0"),
            ml_latency_ms=ml_classifier.last_inference_latency_ms,
            request_id=request_id,
            path="/",
            url_decode_depth=norm_result.depth,
            has_null_bytes=norm_result.has_null_bytes,
            has_unicode_anomalies=norm_result.has_unicode_anomalies,
            total_latency_ms=total_latency,
        )

        return decision, matched_rules, normalized


request_detector = RequestDetector()
