"""
AI-WAF Risk Engine & Threat Fusion Pipeline (Phase 5).
Combines deterministic multi-tier rule scores, supervised ML classification probabilities,
and contextual request threat signals into a unified, explainable composite risk score.
"""

from typing import Any, Literal
from app.config import settings
from app.detection.models import (
    DecisionResult,
    InspectionExplanation,
    RuleMatchDetail,
    MLPredictionDetail,
    ContextPenaltyDetail,
)
from app.detection.rules.base import RuleResult


# Critical system and administrative paths carrying elevated baseline risk
SENSITIVE_PATHS = (
    "/admin",
    "/api/v1/config",
    "/auth",
    "/login",
    "/.env",
    "/.git",
    "/wp-admin",
    "/phpmyadmin",
    "/config",
    "/server-status",
    "/debug",
    "/metrics",
)


class RiskEngine:
    """
    Unified Risk Scoring and Decision Fusion Engine.
    Executes the fusion formula per Section 18-20 of the specification:
    Composite Risk = min(100, max(Override, w_rule * S_rule + w_ml * S_ml + Synergy + sum(Penalties)))
    """

    def __init__(
        self,
        allow_threshold: int | None = None,
        flag_threshold: int | None = None,
        block_threshold: int | None = None,
        mode: str | None = None,
        rule_weight: float = 0.60,
        ml_weight: float = 0.40,
    ):
        self.allow_threshold = allow_threshold if allow_threshold is not None else settings.ALLOW_THRESHOLD
        self.flag_threshold = flag_threshold if flag_threshold is not None else settings.FLAG_THRESHOLD
        self.block_threshold = block_threshold if block_threshold is not None else settings.BLOCK_THRESHOLD
        self.mode = mode or settings.DETECTION_MODE
        self.rule_weight = rule_weight
        self.ml_weight = ml_weight

    def calculate_context_penalties(
        self,
        path: str,
        url_decode_depth: int,
        has_null_bytes: bool,
        has_unicode_anomalies: bool,
    ) -> list[ContextPenaltyDetail]:
        """Calculates quantifiable contextual risk penalties."""
        penalties: list[ContextPenaltyDetail] = []

        # 1. Sensitive path probe
        norm_path = path.lower().split("?")[0]
        if any(norm_path.startswith(sp) for sp in SENSITIVE_PATHS):
            penalties.append(
                ContextPenaltyDetail(
                    factor="SENSITIVE_PATH_ACCESS",
                    penalty_points=15,
                    reason=f"Target path '{norm_path}' matches high-value administrative/sensitive resource pattern",
                )
            )

        # 2. Multi-pass URL decoding / evasion attempt
        if url_decode_depth > 1:
            penalty = 15 * (url_decode_depth - 1)
            penalties.append(
                ContextPenaltyDetail(
                    factor="NESTED_ENCODING_EVASION",
                    penalty_points=penalty,
                    reason=f"Nested URL encoding detected with recursion depth of {url_decode_depth}",
                )
            )

        # 3. Null-byte injection attempt
        if has_null_bytes:
            penalties.append(
                ContextPenaltyDetail(
                    factor="NULL_BYTE_INJECTION",
                    penalty_points=25,
                    reason="Null-byte sequence (%00 / \\x00) detected in request payload",
                )
            )

        # 4. Unicode fullwidth spoofing or compatibility anomalies
        if has_unicode_anomalies:
            penalties.append(
                ContextPenaltyDetail(
                    factor="UNICODE_HOMOGLYPH_ANOMALY",
                    penalty_points=10,
                    reason="Unicode NFKC transformation resolved non-standard fullwidth or homoglyph characters",
                )
            )

        return penalties

    def evaluate(
        self,
        rule_results: list[RuleResult],
        ml_class: str,
        ml_confidence: float,
        model_name: str = "waf_classifier",
        model_version: str = "1.0.0",
        vectorizer_version: str = "1.0.0",
        ml_latency_ms: float = 0.0,
        request_id: str = "req-0000",
        path: str = "/",
        url_decode_depth: int = 0,
        has_null_bytes: bool = False,
        has_unicode_anomalies: bool = False,
        total_latency_ms: float = 0.0,
    ) -> DecisionResult:
        """
        Fuses multi-tier rule matches, ML probabilities, and contextual signals into a DecisionResult.
        """
        # 1. Aggregate matched rules
        matched_rules = [r for r in rule_results if r.matched]
        rule_score = max([r.score for r in matched_rules], default=0)

        # Map to explainability details
        rule_details = [
            RuleMatchDetail(
                rule_id=r.rule_id,
                rule_name=r.rule_name,
                category=r.category,
                confidence=r.confidence.value,
                score=r.score,
                reason=r.reason,
                indicators=r.indicators,
            )
            for r in matched_rules
        ]

        # 2. Compute Machine Learning Threat Score
        if ml_class != "NORMAL":
            ml_score = ml_confidence * 100.0
        else:
            # Benign classification generates 0 to 10 points proportional to uncertainty
            ml_score = max(0.0, (1.0 - ml_confidence) * 20.0)

        # 3. Contextual Threat Penalties
        context_penalties = self.calculate_context_penalties(
            path=path,
            url_decode_depth=url_decode_depth,
            has_null_bytes=has_null_bytes,
            has_unicode_anomalies=has_unicode_anomalies,
        )
        context_points = sum(p.penalty_points for p in context_penalties)

        # 4. Corroboration Synergy Bonus
        synergy_bonus = 0.0
        if rule_score >= 50 and ml_class != "NORMAL" and ml_confidence >= 0.40:
            synergy_bonus = 15.0  # Rules and ML corroboration elevates attack into 90-100 range

        # 5. Base Weighted Calculation
        if rule_score > 0 and ml_class != "NORMAL":
            base_score = (self.rule_weight * rule_score) + (self.ml_weight * ml_score)
        elif rule_score > 0:
            base_score = float(rule_score)
        elif ml_class != "NORMAL":
            base_score = 0.75 * ml_score
        else:
            base_score = ml_score

        composite = base_score + synergy_bonus + context_points

        # 6. High-Confidence Rule Override (Section 19)
        # Any confirmed HIGH_CONFIDENCE rule match guarantees a score >= 85 (BLOCK)
        has_high_confidence_rule = any(r.confidence.value == "HIGH_CONFIDENCE" for r in matched_rules)
        if has_high_confidence_rule:
            override_score = max(85.0, float(rule_score))
            composite = max(composite, override_score)

        risk_score = min(100, max(0, int(round(composite))))

        # 7. Determine Primary Threat Category
        if matched_rules:
            # Order by score descending
            sorted_rules = sorted(matched_rules, key=lambda x: x.score, reverse=True)
            primary_class = sorted_rules[0].category
        elif ml_class != "NORMAL":
            primary_class = ml_class
        elif context_penalties:
            primary_class = "SUSPICIOUS"
        else:
            primary_class = "NORMAL"

        # 8. Primary Reason Compilation
        reasons: list[str] = []
        if matched_rules:
            for r in matched_rules:
                reasons.append(f"[{r.rule_id} / {r.confidence.value}] {r.reason}")
        if ml_class != "NORMAL":
            reasons.append(f"[ML_CLASSIFIER] Predicted {ml_class} (confidence: {ml_confidence:.1%})")
        for p in context_penalties:
            reasons.append(f"[CONTEXT_PENALTY] {p.factor} (+{p.penalty_points} pts): {p.reason}")

        if not reasons:
            reasons.append("Request passed all rule patterns, ML inspection, and contextual anomaly checks.")

        primary_reason = reasons[0]

        # 9. Map Action to Configured Thresholds
        if risk_score >= self.block_threshold:
            action: Literal["ALLOW", "FLAG", "BLOCK"] = "BLOCK"
        elif risk_score > self.allow_threshold:
            action = "FLAG"
        else:
            action = "ALLOW"

        # 10. Enforce Detection Mode Policy
        if self.mode == "FLAG_ONLY" and action == "BLOCK":
            action = "FLAG"
        elif self.mode == "MONITOR" and action in ("BLOCK", "FLAG"):
            action = "ALLOW"

        # 11. Compile Full Explainability Payload
        ml_detail = MLPredictionDetail(
            predicted_class=ml_class,
            confidence=round(ml_confidence, 4),
            model_name=model_name,
            model_version=model_version,
            vectorizer_version=vectorizer_version,
            latency_ms=round(ml_latency_ms, 3),
        )

        explanation = InspectionExplanation(
            request_id=request_id,
            decision=action,
            risk_score=risk_score,
            category=primary_class,
            rule_matches=rule_details,
            ml_prediction=ml_detail,
            contextual_penalties=context_penalties,
            primary_reason=primary_reason,
            latency_ms=round(total_latency_ms, 3),
        )

        return DecisionResult(
            risk_score=risk_score,
            classification=primary_class,
            action=action,
            reasons=reasons,
            rule_score=rule_score,
            ml_confidence=ml_confidence,
            explanation=explanation,
        )


# Singleton risk engine instance
risk_engine = RiskEngine()
