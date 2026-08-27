"""
Supervised Model Training Script for AI-WAF.
Fits character n-grams TF-IDF vectorizer and trains baseline Logistic Regression classifier.
Saves model, vectorizer, and metadata artifacts with strict train/test isolation.
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
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

from ml.preprocessing.clean import clean_dataset
from ml.preprocessing.split import split_data
from app.detection.preprocessing import RequestNormalizer


def train_pipeline(
    dataset_path: str = "ml/data/processed/dataset.csv",
    model_output_dir: str = "ml/models",
    version: str = "1.0.0",
    random_state: int = 42,
):
    print(f"[*] Starting AI-WAF Model Training Pipeline (v{version})...")
    start_time = time.time()

    # 1. Load Dataset
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")

    df = pd.read_csv(dataset_path)
    print(f"[+] Loaded {len(df)} records from {dataset_path}")

    # 2. Clean & Deduplicate
    df = clean_dataset(df)
    print(f"[+] Post-cleaning records count: {len(df)}")

    # 3. Apply Same Normalization as Gateway
    print("[*] Normalizing request payloads to eliminate train-serve skew...")
    df["normalized_request"] = df["request"].apply(
        lambda x: RequestNormalizer.normalize_text(str(x))[0]
    )

    # 4. Stratified Train / Test Split (Strictly before vectorizer fitting!)
    train_df, test_df = split_data(df, test_size=0.2, random_state=random_state)
    print(f"[+] Training split: {len(train_df)} samples | Test split: {len(test_df)} samples")

    # 5. Fit Vectorizer ONLY on Training Split
    print("[*] Fitting character n-gram TF-IDF vectorizer on training data...")
    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 5),
        max_features=10000,
        lowercase=True,
    )
    X_train = vectorizer.fit_transform(train_df["normalized_request"])
    y_train = train_df["attack_type"]

    X_test = vectorizer.transform(test_df["normalized_request"])
    y_test = test_df["attack_type"]

    # 6. Train Supervised Classifier (Baseline: Logistic Regression)
    print("[*] Training Logistic Regression classifier with balanced class weights...")
    clf = LogisticRegression(
        C=5.0,
        max_iter=1000,
        class_weight="balanced",
        random_state=random_state,
        solver="lbfgs",
    )
    clf.fit(X_train, y_train)

    # 7. Evaluate Model
    print("[*] Evaluating on held-out test data...")
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=clf.classes_)

    print(f"[+] Test Accuracy: {acc * 100:.2f}%")

    # 8. Benchmark Inference Latency
    sample_text = "GET /search?q=test HTTP/1.1"
    latencies = []
    for _ in range(100):
        t0 = time.perf_counter()
        vec = vectorizer.transform([sample_text])
        clf.predict_proba(vec)
        latencies.append((time.perf_counter() - t0) * 1000.0)
    avg_latency_ms = round(float(np.mean(latencies)), 3)
    p95_latency_ms = round(float(np.percentile(latencies, 95)), 3)
    print(f"[+] Average Inference Latency: {avg_latency_ms} ms (p95: {p95_latency_ms} ms)")

    # 9. Serialize Model Artifacts
    os.makedirs(model_output_dir, exist_ok=True)
    major_ver = version.split(".")[0]
    model_file = os.path.join(model_output_dir, f"waf_classifier_v{major_ver}.joblib")
    vec_file = os.path.join(model_output_dir, f"tfidf_vectorizer_v{major_ver}.joblib")
    meta_file = os.path.join(model_output_dir, f"metadata_v{major_ver}.json")

    joblib.dump(clf, model_file)
    joblib.dump(vectorizer, vec_file)

    metadata = {
        "model_name": "waf_classifier",
        "version": version,
        "algorithm": "LogisticRegression",
        "class_weight": "balanced",
        "vectorizer": "TfidfVectorizer(char, 2-5, max_features=10000)",
        "classes": list(clf.classes_),
        "vocabulary_size": len(vectorizer.vocabulary_),
        "accuracy": round(acc, 4),
        "metrics": report,
        "confusion_matrix": {
            "classes": list(clf.classes_),
            "matrix": cm.tolist(),
        },
        "performance": {
            "avg_latency_ms": avg_latency_ms,
            "p95_latency_ms": p95_latency_ms,
        },
        "training_metadata": {
            "total_samples": len(df),
            "train_samples": len(train_df),
            "test_samples": len(test_df),
            "random_state": random_state,
            "trained_at_unix": time.time(),
        },
    }

    with open(meta_file, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[+] Serialized model: {model_file}")
    print(f"[+] Serialized vectorizer: {vec_file}")
    print(f"[+] Serialized metadata: {meta_file}")
    print(f"[+] Training completed in {time.time() - start_time:.2f}s")
    return metadata


if __name__ == "__main__":
    train_pipeline()
