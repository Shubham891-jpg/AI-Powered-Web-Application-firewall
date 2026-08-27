"""
Dataset Normalization Pipeline for ML Pipeline.
"""

from app.detection.preprocessing import normalize_string


def normalize_request_series(series):
    """Normalizes an entire pandas Series of HTTP request payloads."""
    return series.apply(lambda x: normalize_string(str(x)).normalized)
