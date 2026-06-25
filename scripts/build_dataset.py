"""Build the starter training dataset from public seed and custom rows."""

from __future__ import annotations

import csv
import random
from collections import Counter
from pathlib import Path


BASE_PATH = Path("data/base_prompts.csv")
CUSTOM_PATH = Path("data/custom_prompts.csv")
OUTPUT_PATH = Path("data/prompts.csv")

BASE_TOTAL_ROWS = 60
RANDOM_SEED = 42


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as csv_file:
        return list(csv.DictReader(csv_file))


def sample_base_rows(base: list[dict[str, str]]) -> list[dict[str, str]]:
    """Take a stable public sample while preserving all available attacks."""
    rng = random.Random(RANDOM_SEED)
    malicious = [row for row in base if row["label"] == "malicious"]
    benign = [row for row in base if row["label"] == "benign"]

    benign_needed = max(BASE_TOTAL_ROWS - len(malicious), 0)
    benign_sample = rng.sample(benign, k=min(benign_needed, len(benign)))

    return malicious + benign_sample


def main() -> None:
    if not BASE_PATH.exists():
        raise FileNotFoundError(
            f"Missing {BASE_PATH}. Run python3 scripts/download_base_dataset.py first."
        )
    if not CUSTOM_PATH.exists():
        raise FileNotFoundError(f"Missing {CUSTOM_PATH}.")

    base = read_rows(BASE_PATH)
    custom = read_rows(CUSTOM_PATH)

    rng = random.Random(RANDOM_SEED)
    dataset = sample_base_rows(base) + custom
    rng.shuffle(dataset)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=["prompt", "label", "source", "category", "notes"],
        )
        writer.writeheader()
        writer.writerows(dataset)

    counts = Counter(row["label"] for row in dataset)
    print(f"Wrote {len(dataset)} rows to {OUTPUT_PATH}")
    print(f"Label counts: {dict(counts)}")


if __name__ == "__main__":
    main()
