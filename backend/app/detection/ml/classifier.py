"""
ML Model Loader and Classifier interface for AI-WAF.
Loads serialized models once at application startup.
Never executes training during request paths.
Associates predictions with model and vectorizer version information.
"""

import json
import os
import time
from typing import Any, Optional
from app.config import settings


class WAFClassifier:
    """Local supervised ML classifier for HTTP payload threat classification."""

    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.metadata: dict[str, Any] = {}
        self.loaded = False
        self.model_name = "waf_classifier"
        self.model_version = "1.0.0"
        self.vectorizer_version = "1.0.0"
        self.last_inference_latency_ms: float = 0.0

    def load(self):
        """Loads model, vectorizer, and metadata from disk once at startup."""
        if not settings.ML_ENABLED:
            return

        model_path = settings.ML_MODEL_PATH
        vec_path = settings.ML_VECTORIZER_PATH
        meta_path = settings.ML_METADATA_PATH

        if not os.path.exists(model_path) and os.path.exists(os.path.join("..", model_path)):
            model_path = os.path.join("..", model_path)
            vec_path = os.path.join("..", vec_path)
            meta_path = os.path.join("..", meta_path)

        if os.path.exists(model_path) and os.path.exists(vec_path):
            try:
                import joblib
                self.model = joblib.load(model_path)
                self.vectorizer = joblib.load(vec_path)
                self.loaded = True

                if os.path.exists(meta_path):
                    with open(meta_path, "r", encoding="utf-8") as f:
                        self.metadata = json.load(f)
                        self.model_name = self.metadata.get("model_name", "waf_classifier")
                        self.model_version = self.metadata.get("version", "1.0.0")
                        self.vectorizer_version = self.metadata.get("version", "1.0.0")

                print(f"[+] Loaded ML Model '{self.model_name}' (v{self.model_version}) and TF-IDF vectorizer successfully.")
            except Exception as e:
                print(f"[-] Failed to load ML model: {e}")
                self.loaded = False

    def predict(self, text: str) -> tuple[str, float]:
        """
        Classifies request payload string.
        Returns: (predicted_class: str, confidence: float)
        """
        if not self.loaded or self.model is None or self.vectorizer is None:
            # Fallback baseline when ML is disabled or not loaded
            return "NORMAL", 0.95

        t0 = time.perf_counter()
        try:
            from app.detection.preprocessing import RequestNormalizer
            norm_text = RequestNormalizer.normalize_text(text)[0]
            vector = self.vectorizer.transform([norm_text])
            probs = self.model.predict_proba(vector)[0]
            classes = self.model.classes_
            max_idx = probs.argmax()
            predicted_class = str(classes[max_idx])
            confidence = float(probs[max_idx])
            self.last_inference_latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            return predicted_class, confidence
        except Exception:
            self.last_inference_latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            return "NORMAL", 0.50

    def get_info(self) -> dict[str, Any]:
        """Returns model metadata and health information."""
        return {
            "loaded": self.loaded,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "vectorizer_version": self.vectorizer_version,
            "classes": list(self.model.classes_) if self.model else [],
            "accuracy": self.metadata.get("accuracy", None),
            "performance": self.metadata.get("performance", {}),
        }


# Singleton classifier
ml_classifier = WAFClassifier()
