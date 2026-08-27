"""
Dataset Cleaning Utilities for AI-WAF ML Pipeline.
Removes corrupt records, null payloads, and duplicate requests.
"""

import pandas as pd


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Cleans raw dataset and drops null/duplicate request entries."""
    df = df.dropna(subset=["request", "label"])
    df = df.drop_duplicates(subset=["request"])
    return df
