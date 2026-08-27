"""
Risk Engine & Detection Fusion Unit Tests (Phase 5).
Tests mathematical fusion formula, high-confidence overrides, ML corroboration,
contextual threat penalties, detection enforcement modes, and explainability payloads.
"""

import pytest
from app.detection.risk_engine import RiskEngine
from app.detection.rules.base import RuleResult, RuleConfidence
from app.detection.detector import request_detector
from app.detection.preprocessing import RawRequest, RequestNormalizer


def test_high_confidence_rule_override():
    """
    Section 19: High-confidence rule matches MUST override and force a BLOCK (score >= 85),
    even if the ML classifier predicts NORMAL with high probability.
    """
    engine = RiskEngine(allow_threshold=29, flag_threshold=69, block_threshold=70, mode="BLOCK")

    rule_result = RuleResult(
        matched=True,
        rule_id="SQLI-001",
        rule_name="SQL Injection Detector",
        category="SQL_INJECTION",
        confidence=RuleConfidence.HIGH_CONFIDENCE,
        score=85,
        reason="Detected UNION SELECT structural clause",
        indicators=["UNION SELECT"],
    )

    decision = engine.evaluate(
        rule_results=[rule_result],
        ml_class="NORMAL",
        ml_confidence=0.95,
        request_id="test-override-01",
    )

    assert decision.action == "BLOCK"
    assert decision.risk_score >= 85
    assert decision.classification == "SQL_INJECTION"
    assert decision.explanation is not None
    assert decision.explanation.decision == "BLOCK"
    assert len(decision.explanation.rule_matches) == 1
    assert decision.explanation.rule_matches[0].confidence == "HIGH_CONFIDENCE"


def test_corroborated_rule_and_ml_attack():
    """
    Section 19: When both rules and ML detect malicious intent,
    corroboration synergy bonus is added, elevating score into the 90-100 range.
    """
    engine = RiskEngine(allow_threshold=29, flag_threshold=69, block_threshold=70, mode="BLOCK")

    rule_result = RuleResult(
        matched=True,
        rule_id="XSS-001",
        rule_name="XSS Detector",
        category="CROSS_SITE_SCRIPTING",
        confidence=RuleConfidence.HIGH_CONFIDENCE,
        score=85,
        reason="Dangerous <script> tag detected",
        indicators=["<script>"],
    )

    decision = engine.evaluate(
        rule_results=[rule_result],
        ml_class="CROSS_SITE_SCRIPTING",
        ml_confidence=0.85,
        request_id="test-synergy-01",
    )

    assert decision.action == "BLOCK"
    assert decision.risk_score >= 90
    assert decision.classification == "CROSS_SITE_SCRIPTING"


def test_ml_suspicious_without_rule_match_falls_into_flag():
    """
    Section 19: If ML detects suspicious content with moderate confidence but no rules trigger,
    the score should fall into the FLAG category (30-69).
    """
    engine = RiskEngine(allow_threshold=29, flag_threshold=69, block_threshold=70, mode="BLOCK")

    decision = engine.evaluate(
        rule_results=[],
        ml_class="SQL_INJECTION",
        ml_confidence=0.60,
        request_id="test-flag-01",
    )

    assert decision.action == "FLAG"
    assert 30 <= decision.risk_score <= 69
    assert decision.classification == "SQL_INJECTION"


def test_benign_request_allows():
    """
    Verifies normal traffic receives low risk score (0-29) and ALLOW action.
    """
    engine = RiskEngine(allow_threshold=29, flag_threshold=69, block_threshold=70, mode="BLOCK")

    decision = engine.evaluate(
        rule_results=[],
        ml_class="NORMAL",
        ml_confidence=0.98,
        request_id="test-allow-01",
        path="/products/view",
    )

    assert decision.action == "ALLOW"
    assert decision.risk_score <= 29
    assert decision.classification == "NORMAL"


def test_contextual_penalties_accumulation():
    """
    Tests cumulative risk penalties for sensitive paths, null bytes, and nested encodings.
    """
    engine = RiskEngine(allow_threshold=29, flag_threshold=69, block_threshold=70, mode="BLOCK")

    # Sensitive path (/admin) + Null byte (%00)
    decision = engine.evaluate(
        rule_results=[],
        ml_class="NORMAL",
        ml_confidence=0.90,
        request_id="test-penalties-01",
        path="/admin/users",
        url_decode_depth=2,
        has_null_bytes=True,
    )

    # 15 (sensitive path) + 15 (depth 2) + 25 (null byte) = 55 points
    assert decision.risk_score >= 50
    assert decision.action == "FLAG"
    assert decision.classification == "SUSPICIOUS"
    assert len(decision.explanation.contextual_penalties) == 3


def test_detection_mode_enforcement():
    """
    Tests enforcement modes: BLOCK vs FLAG_ONLY vs MONITOR.
    """
    rule_result = RuleResult(
        matched=True,
        rule_id="RCE-001",
        rule_name="Command Injection",
        category="COMMAND_INJECTION",
        confidence=RuleConfidence.HIGH_CONFIDENCE,
        score=90,
        reason="Shell chaining detected",
    )

    # 1. BLOCK mode
    engine_block = RiskEngine(mode="BLOCK")
    dec_block = engine_block.evaluate(rule_results=[rule_result], ml_class="COMMAND_INJECTION", ml_confidence=0.9)
    assert dec_block.action == "BLOCK"

    # 2. FLAG_ONLY mode
    engine_flag = RiskEngine(mode="FLAG_ONLY")
    dec_flag = engine_flag.evaluate(rule_results=[rule_result], ml_class="COMMAND_INJECTION", ml_confidence=0.9)
    assert dec_flag.action == "FLAG"
    assert dec_flag.risk_score >= 85  # Score remains high, action downgraded

    # 3. MONITOR mode
    engine_mon = RiskEngine(mode="MONITOR")
    dec_mon = engine_mon.evaluate(rule_results=[rule_result], ml_class="COMMAND_INJECTION", ml_confidence=0.9)
    assert dec_mon.action == "ALLOW"
    assert dec_mon.risk_score >= 85


def test_end_to_end_detector_explainability():
    """
    Verifies that RequestDetector.inspect generates a complete, valid InspectionExplanation.
    """
    raw = RawRequest(
        request_id="req-explain-test",
        client_ip="192.168.1.50",
        method="GET",
        path="/search",
        raw_query="q=%27%20UNION%20SELECT%201,2,3--",
    )
    context = RequestNormalizer.create_context(raw)

    decision, matched_rules, _ = request_detector.inspect(context, request_id="req-explain-test")

    assert decision.action == "BLOCK"
    assert decision.risk_score >= 85
    assert decision.explanation is not None
    assert decision.explanation.request_id == "req-explain-test"
    assert decision.explanation.decision == "BLOCK"
    assert decision.explanation.category == "SQL_INJECTION"
    assert len(decision.explanation.rule_matches) >= 1
    assert decision.explanation.ml_prediction.model_name == "waf_classifier"
    assert decision.explanation.primary_reason is not None
