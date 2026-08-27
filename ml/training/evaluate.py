"""
Model Evaluation Script for AI-WAF Classifier.
Calculates Accuracy, Precision, Recall, F1-score, and False Positive/Negative Rates.
"""

import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix


def evaluate_model(model_path: str, vectorizer_path: str, test_df: pd.DataFrame):
    clf = joblib.load(model_path)
    vec = joblib.load(vectorizer_path)

    X_test = vec.transform(test_df["request"])
    y_test = test_df["attack_type"]

    y_pred = clf.predict(X_test)
    report = classification_report(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred, labels=clf.classes_)

    print("=== Classification Report ===")
    print(report)
    print("=== Confusion Matrix ===")
    print(cm)
    return report, cm
