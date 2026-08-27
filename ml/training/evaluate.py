"""
Model Evaluation and Diagnostic Script for AI-WAF Classifier.
Calculates Accuracy, Precision, Recall, F1-score, False Positive/Negative Rates,
and benchmarks inference latency against target latency budgets (< 5ms).
"""

import json
import os
import sys
import time

# Ensure backend and workspace root are in Python path
sys.path.insert(0, os.path.abspath("backend"))
sys.path.insert(0, os.path.abspath("."))

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

from ml.preprocessing.clean import clean_dataset
from app.detection.preprocessing import RequestNormalizer


def evaluate_artifacts(
    model_path: str = "ml/models/waf_classifier_v1.joblib",
    vectorizer_path: str = "ml/models/tfidf_vectorizer_v1.joblib",
    dataset_path: str = "ml/data/processed/dataset.csv",
):
    print("=" * 60)
    print("           AI-WAF MODEL EVALUATION REPORT")
    print("=" * 60)

    if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
        raise FileNotFoundError(f"Model or vectorizer artifact missing ({model_path}, {vectorizer_path})")

    clf = joblib.load(model_path)
    vec = joblib.load(vectorizer_path)
    df = clean_dataset(pd.read_csv(dataset_path))

    df["normalized_request"] = df["request"].apply(
        lambda x: RequestNormalizer.normalize_text(str(x))[0]
    )

    X = vec.transform(df["normalized_request"])
    y_true = df["attack_type"]
    y_pred = clf.predict(X)

    acc = accuracy_score(y_true, y_pred)
    report = classification_report(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=clf.classes_)

    print(f"\nOverall Accuracy: {acc * 100:.2f}%\n")
    print("Classification Report:")
    print(report)

    print("\nConfusion Matrix (Classes: %s):" % list(clf.classes_))
    print(cm)

    # Calculate False Positive Rate on Normal traffic
    classes = list(clf.classes_)
    if "NORMAL" in classes:
        norm_idx = classes.index("NORMAL")
        normal_total = sum(y_true == "NORMAL")
        normal_false_positives = sum((y_true == "NORMAL") & (y_pred != "NORMAL"))
        fpr = (normal_false_positives / normal_total) if normal_total > 0 else 0.0
        print(f"\nBenign False Positive Rate (FPR): {fpr * 100:.2f}% ({normal_false_positives}/{normal_total})")

    # Latency Benchmark
    test_sample = "GET /search?q=1%27%20OR%201=1-- HTTP/1.1"
    latencies = []
    for _ in range(200):
        t0 = time.perf_counter()
        transformed = vec.transform([test_sample])
        clf.predict_proba(transformed)
        latencies.append((time.perf_counter() - t0) * 1000.0)

    avg_lat = np.mean(latencies)
    p95_lat = np.percentile(latencies, 95)
    print(f"\nInference Latency Benchmark (200 requests):")
    print(f"  Average: {avg_lat:.3f} ms")
    print(f"  p95:     {p95_lat:.3f} ms")
    print(f"  Target:  < 5.000 ms -> {'PASS (Within Budget)' if avg_lat < 5.0 else 'EXCEEDED'}")
    print("=" * 60)

    return {
        "accuracy": acc,
        "classes": list(clf.classes_),
        "avg_latency_ms": round(float(avg_lat), 3),
    }


if __name__ == "__main__":
    evaluate_artifacts()
