"""Train the TF-IDF + logistic regression prompt-injection classifier."""

from __future__ import annotations

import json
from pathlib import Path


DATA_PATH = Path("data/training.csv")
MODEL_PATH = Path("models/prompt_injection_model.joblib")
METADATA_PATH = Path("models/prompt_injection_model_metadata.json")
SPLIT_DIR = Path("data/splits")
TRAIN_SPLIT_PATH = SPLIT_DIR / "train.csv"
TEST_SPLIT_PATH = SPLIT_DIR / "test.csv"
RANDOM_SEED = 42
TEST_SIZE = 0.25


def main() -> None:
    try:
        import joblib
        import pandas as pd
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import train_test_split
        from sklearn.pipeline import Pipeline
    except ImportError as exc:
        raise SystemExit(
            "Missing training dependencies. Run `pip install -r requirements.txt` "
            "inside your virtual environment, then rerun `python3 scripts/train.py`."
        ) from exc

    data = pd.read_csv(DATA_PATH)
    required_columns = {"text", "label", "source"}
    missing_columns = required_columns - set(data.columns)
    if missing_columns:
        raise ValueError(f"{DATA_PATH} is missing columns: {sorted(missing_columns)}")

    data = data.dropna(subset=["text", "label"])
    data["text"] = data["text"].astype(str).str.strip()
    data["label"] = data["label"].astype(str).str.strip().str.lower()
    data = data[data["text"] != ""]

    bad_labels = sorted(set(data["label"]) - {"malicious", "benign"})
    if bad_labels:
        raise ValueError(f"Unsupported labels in {DATA_PATH}: {bad_labels}")

    train_df, test_df = train_test_split(
        data,
        test_size=TEST_SIZE,
        random_state=RANDOM_SEED,
        stratify=data["label"],
    )

    pipeline = Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    ngram_range=(1, 2),
                    min_df=1,
                    max_features=5000,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=1000,
                    random_state=RANDOM_SEED,
                ),
            ),
        ]
    )

    pipeline.fit(train_df["text"], train_df["label"])

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    SPLIT_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(pipeline, MODEL_PATH)
    train_df.to_csv(TRAIN_SPLIT_PATH, index=False)
    test_df.to_csv(TEST_SPLIT_PATH, index=False)

    metadata = {
        "model_type": "tfidf_logistic_regression",
        "data_path": str(DATA_PATH),
        "model_path": str(MODEL_PATH),
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "test_size": TEST_SIZE,
        "random_seed": RANDOM_SEED,
        "class_balance": data["label"].value_counts().to_dict(),
        "train_class_balance": train_df["label"].value_counts().to_dict(),
        "test_class_balance": test_df["label"].value_counts().to_dict(),
        "features": {
            "vectorizer": "TfidfVectorizer",
            "ngram_range": [1, 2],
            "max_features": 5000,
        },
        "classifier": {
            "type": "LogisticRegression",
            "class_weight": "balanced",
            "max_iter": 1000,
        },
    }

    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(f"Trained model on {len(train_df)} rows")
    print(f"Held out {len(test_df)} rows for evaluation")
    print(f"Saved model to {MODEL_PATH}")
    print(f"Saved metadata to {METADATA_PATH}")
    print(f"Saved train split to {TRAIN_SPLIT_PATH}")
    print(f"Saved test split to {TEST_SPLIT_PATH}")


if __name__ == "__main__":
    main()
