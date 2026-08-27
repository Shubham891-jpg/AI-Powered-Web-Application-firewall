"""
Supervised Model Training Script.
Fits TF-IDF character n-gram vectorizer and trains baseline Logistic Regression classifier.
Saves model, vectorizer, and metadata artifacts.
"""

import json
import os
import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report


def train_baseline_model(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    model_output_dir: str = "ml/models",
    version: str = "1.0.0",
):
    os.makedirs(model_output_dir, exist_ok=True)

    # 1. Fit Vectorizer ONLY on training data
    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), max_features=10000)
    X_train = vectorizer.fit_transform(train_df["request"])
    y_train = train_df["attack_type"]

    X_test = vectorizer.transform(test_df["request"])
    y_test = test_df["attack_type"]

    # 2. Train Logistic Regression
    clf = LogisticRegression(C=1.0, max_iter=1000, class_weight="balanced", random_state=42)
    clf.fit(X_train, y_train)

    # 3. Evaluate
    y_pred = clf.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=True)

    # 4. Serialize artifacts
    model_path = os.path.join(model_output_dir, f"waf_classifier_v{version.split('.')[0]}.joblib")
    vec_path = os.path.join(model_output_dir, f"tfidf_vectorizer_v{version.split('.')[0]}.joblib")
    meta_path = os.path.join(model_output_dir, f"metadata_v{version.split('.')[0]}.json")

    joblib.dump(clf, model_path)
    joblib.dump(vectorizer, vec_path)

    metadata = {
        "version": version,
        "algorithm": "LogisticRegression",
        "vectorizer": "TfidfVectorizer(char, 2-5)",
        "classes": list(clf.classes_),
        "metrics": report,
    }
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"Model successfully saved to {model_path}")
    return metadata
