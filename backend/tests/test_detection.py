"""
Unit tests for Request Normalization and Inspection Pipeline (Phase 2).
"""

from app.detection.preprocessing import (
    RawRequest,
    RequestNormalizer,
    normalize_string,
)
from app.detection.detector import request_detector


def test_single_url_decoding():
    text, depth, null_byte, unicode_anom, trans = RequestNormalizer.normalize_text("admin%20or%201=1")
    assert "admin or 1=1" in text
    assert depth == 1
    assert "url_decode_depth_1" in trans


def test_double_and_nested_url_decoding():
    # %2527 decodes to %27, then to '
    text, depth, null_byte, unicode_anom, trans = RequestNormalizer.normalize_text("%2527%2520OR%25201%253D1")
    assert "' OR 1=1" in text
    assert depth == 2
    assert "url_decode_depth_2" in trans


def test_html_entity_decoding_named_and_hex():
    # Named &lt; and &gt;
    text1, _, _, _, trans1 = RequestNormalizer.normalize_text("&lt;script&gt;alert(1)&lt;/script&gt;")
    assert "<script>alert(1)</script>" in text1
    assert "html_entity_decode" in trans1

    # Hex and decimal entities
    text2, _, _, _, _ = RequestNormalizer.normalize_text("&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;")
    assert "<script>alert(1)</script>" in text2

    text3, _, _, _, _ = RequestNormalizer.normalize_text("&#60;script&#62;alert(1)&#60;/script&#62;")
    assert "<script>alert(1)</script>" in text3


def test_unicode_nfkc_normalization():
    # Fullwidth characters (e.g. ＜ ＞) normalized to standard ASCII < >
    fullwidth_script = "\uff1cscript\uff1ealert(1)\uff1c/script\uff1e"
    text, _, _, has_uni, trans = RequestNormalizer.normalize_text(fullwidth_script)
    assert "<script>alert(1)</script>" in text
    assert has_uni is True
    assert "unicode_nfkc_normalize" in trans


def test_null_byte_injection_detection():
    text, _, has_null, _, trans = RequestNormalizer.normalize_text("sensitive_file.php%00.jpg")
    assert has_null is True
    assert "%00" not in text
    assert "null_byte_removal" in trans


def test_path_canonicalization():
    # Path traversal dots and redundant slashes
    path1 = RequestNormalizer.canonicalize_path("/products/catalog/../../admin/settings")
    assert path1 == "/admin/settings"

    # Redundant multiple slashes
    path2 = RequestNormalizer.canonicalize_path("//api///v1////health")
    assert path2 == "/api/v1/health"

    # Windows-style backslashes
    path3 = RequestNormalizer.canonicalize_path("/files\\..\\..\\windows\\win.ini")
    assert path3 == "/windows/win.ini"


def test_raw_request_preservation_and_immutability():
    raw = RawRequest(
        request_id="test-req-001",
        client_ip="192.168.1.100",
        method="POST",
        path="/search%2f..%2fadmin",
        raw_query="q=%2527%20OR%201=1&tag=sec",
        query_params={"q": ["%2527%20OR%201=1"], "tag": ["sec"]},
        headers={"user-agent": "Mozilla/5.0 &lt;Scanner&gt;"},
        cookies={"session": "safe_sess_id"},
        body_text='{"search": "%3Cscript%3E"}',
    )

    context = RequestNormalizer.create_context(raw)

    # Verify that raw is completely unmodified
    assert context.raw.path == "/search%2f..%2fadmin"
    assert context.raw.query_params["q"] == ["%2527%20OR%201=1"]
    assert context.raw.headers["user-agent"] == "Mozilla/5.0 &lt;Scanner&gt;"
    assert context.raw.body_text == '{"search": "%3Cscript%3E"}'

    # Verify that normalized exposed the attack payloads
    assert context.normalized.canonical_path == "/admin"
    assert "' OR 1=1" in context.normalized.query_params["q"][0]
    assert "Mozilla/5.0 <Scanner>" in context.normalized.headers["user-agent"]
    assert "<script>" in context.normalized.body_text
    assert context.normalized.encoding_depth >= 2


def test_detector_with_inspected_context_blocks_obfuscated_attacks():
    # Double-encoded SQLi in query param
    raw_sqli = RawRequest(
        request_id="sqli-test",
        client_ip="10.0.0.1",
        method="GET",
        path="/items",
        raw_query="id=%2527%2520UNION%2520SELECT%2520null",
        query_params={"id": ["%2527%2520UNION%2520SELECT%2520null"]},
    )
    context_sqli = RequestNormalizer.create_context(raw_sqli)
    decision, matched, _ = request_detector.inspect(context_sqli)

    assert decision.action == "BLOCK"
    assert decision.classification == "SQL_INJECTION"
    assert decision.risk_score >= 70


def test_detector_allows_legitimate_requests_without_false_positives():
    raw_benign = RawRequest(
        request_id="benign-test",
        client_ip="10.0.0.1",
        method="GET",
        path="/products/electronics",
        raw_query="category=laptop&brand=Dell&sort=price_asc",
        query_params={"category": ["laptop"], "brand": ["Dell"], "sort": ["price_asc"]},
        headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    )
    context_benign = RequestNormalizer.create_context(raw_benign)
    decision, matched, _ = request_detector.inspect(context_benign)

    assert decision.action == "ALLOW"
    assert decision.classification == "NORMAL"
    assert decision.risk_score <= 29
    assert len(matched) == 0
