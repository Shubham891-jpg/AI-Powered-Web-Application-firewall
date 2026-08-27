"""
Machine Learning Pipeline & Inference Unit Tests (Phase 4).
Tests artifact loading, inference predictions, confidence outputs,
class mappings, model version metadata, and latency benchmarks.
"""

import time
import pytest
from app.detection.ml.classifier import ml_classifier


def test_model_and_vectorizer_loading():
    """Verifies that the serialized model and vectorizer load cleanly."""
    ml_classifier.load()
    assert ml_classifier.loaded is True
    assert ml_classifier.model is not None
    assert ml_classifier.vectorizer is not None
    assert ml_classifier.model_version == "1.0.0"
    assert ml_classifier.model_name == "waf_classifier"


def test_model_classes():
    """Verifies that all 5 target attack classes exist in the model."""
    classes = list(ml_classifier.model.classes_)
    expected_classes = {
        "NORMAL",
        "SQL_INJECTION",
        "CROSS_SITE_SCRIPTING",
        "COMMAND_INJECTION",
        "PATH_TRAVERSAL",
    }
    assert expected_classes.issubset(set(classes))


def test_prediction_on_normal_traffic():
    """Verifies benign HTTP traffic is classified as NORMAL with high confidence."""
    pred_class, conf = ml_classifier.predict("GET /products?category=electronics&sort=price_asc HTTP/1.1")
    assert pred_class == "NORMAL"
    assert conf >= 0.50


def test_prediction_on_sqli_attack():
    """Verifies SQL injection payload is correctly classified."""
    pred_class, conf = ml_classifier.predict("GET /products?id=1%27%20OR%201=1-- HTTP/1.1")
    assert pred_class == "SQL_INJECTION"
    assert conf >= 0.70


def test_prediction_on_xss_attack():
    """Verifies XSS payload is correctly classified."""
    pred_class, conf = ml_classifier.predict("GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1")
    assert pred_class == "CROSS_SITE_SCRIPTING"
    assert conf >= 0.70


def test_prediction_on_command_injection():
    """Verifies Command Injection payload is correctly classified."""
    pred_class, conf = ml_classifier.predict("GET /lookup?ip=127.0.0.1;%20cat%20/etc/passwd HTTP/1.1")
    assert pred_class == "COMMAND_INJECTION"
    assert conf >= 0.70


def test_prediction_on_path_traversal():
    """Verifies Path Traversal payload is correctly classified."""
    pred_class, conf = ml_classifier.predict("GET /files?filename=../../../../etc/passwd HTTP/1.1")
    assert pred_class == "PATH_TRAVERSAL"
    assert conf >= 0.70


def test_inference_latency_budget():
    """Verifies that inference latency is under 5ms per prediction."""
    sample = "GET /search?q=test HTTP/1.1"
    latencies = []
    for _ in range(50):
        t0 = time.perf_counter()
        ml_classifier.predict(sample)
        latencies.append((time.perf_counter() - t0) * 1000.0)

    avg_latency = sum(latencies) / len(latencies)
    assert avg_latency < 5.0, f"Average latency {avg_latency:.2f}ms exceeded 5ms budget"


def test_metadata_integrity():
    """Verifies model metadata details."""
    info = ml_classifier.get_info()
    assert info["loaded"] is True
    assert info["model_version"] == "1.0.0"
    assert info["accuracy"] is not None
    assert info["accuracy"] >= 0.85
