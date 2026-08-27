"""
ML Model Loader and Classifier interface for AI-WAF.
Loads serialized models once at application startup.
Never executes training during request paths.
"""

import os
from typing import Any, Optional
from app.config import settings


class WAFClassifier:
    """Local supervised ML classifier for HTTP payload threat classification."""

    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.metadata = None
        self.loaded = False

    def load(self):
        """Loads model and vectorizer from disk if configured."""
        if not settings.ML_ENABLED:
            return

        if os.path.exists(settings.ML_MODEL_PATH) and os.path.exists(settings.ML_VECTORIZER_PATH):
            try:
                import joblib
                self.model = joblib.load(settings.ML_MODEL_PATH)
                self.vectorizer = joblib.load(settings.ML_VECTORIZER_PATH)
                self.loaded = True
            except Exception:
                self.loaded = False

    def predict(self, text: str) -> tuple[str, float]:
        """
        Classifies request payload string.
        Returns: (predicted_class: str, confidence: float)
        """
        if not self.loaded or self.model is None or self.vectorizer is None:
            return "NORMAL", 0.95

        try:
            vector = self.vectorizer.transform([text])
            probs = self.model.predict_proba(vector)[0]
            classes = self.model.classes_
            max_idx = probs.argmax()
            return classes[max_idx], float(probs[max_idx])
        except Exception:
            return "NORMAL", 0.50


# Singleton classifier
ml_classifier = WAFClassifier()
