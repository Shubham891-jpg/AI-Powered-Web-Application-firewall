"""
ML Model loader helper.
"""

from app.detection.ml.classifier import ml_classifier


def initialize_ml_models():
    """Initializes and loads ML models into memory."""
    ml_classifier.load()
