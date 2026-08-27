"""
ML Vectorizer definitions and utilities.
"""

from sklearn.feature_extraction.text import TfidfVectorizer


def create_baseline_vectorizer(max_features: int = 10000) -> TfidfVectorizer:
    """
    Creates a character n-gram TF-IDF vectorizer per specification:
    TF-IDF + character n-grams (ranges 2-5).
    """
    return TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 5),
        max_features=max_features,
        lowercase=True,
    )
