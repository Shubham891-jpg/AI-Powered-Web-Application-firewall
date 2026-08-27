"""
Stratified Train/Validation/Test Split for ML Dataset.
Avoids data leakage by ensuring all splits are created strictly before vectorizer fitting.
"""

from sklearn.model_selection import train_test_split
import pandas as pd


def split_data(
    df: pd.DataFrame,
    test_size: float = 0.2,
    random_state: int = 42,
):
    """
    Performs stratified train/test split based on attack_type label.
    """
    stratify_target = df["attack_type"] if "attack_type" in df.columns else df["label"]
    train_df, test_df = train_test_split(
        df,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify_target,
    )
    return train_df, test_df
