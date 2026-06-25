"""Build data/training.csv from normalized base data plus editable custom rows."""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path


MASTER_PATH = Path("data/master.csv")
CUSTOM_PATH = Path("data/custom_prompts.csv")
OUTPUT_PATH = Path("data/training.csv")
FIELDNAMES = ["text", "label", "source"]
VALID_LABELS = {"malicious", "benign"}


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as csv_file:
        rows = list(csv.DictReader(csv_file))

    missing = set(FIELDNAMES) - set(rows[0].keys() if rows else FIELDNAMES)
    if missing:
        raise ValueError(f"{path} is missing columns: {sorted(missing)}")

    normalized = []
    for row in rows:
        text = (row["text"] or "").strip()
        label = (row["label"] or "").strip().lower()
        source = (row["source"] or path.stem).strip()
        if not text:
            continue
        if label not in VALID_LABELS:
            raise ValueError(f"{path} has unsupported label: {row['label']!r}")
        normalized.append({"text": text, "label": label, "source": source})
    return normalized


def main() -> None:
    rows = read_rows(MASTER_PATH) + read_rows(CUSTOM_PATH)
    seen: set[str] = set()
    deduped = []
    duplicate_count = 0

    for row in rows:
        key = row["text"].casefold()
        if key in seen:
            duplicate_count += 1
            continue
        seen.add(key)
        deduped.append(row)

    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(deduped)

    print(f"Wrote {len(deduped)} rows to {OUTPUT_PATH}")
    print(f"Dropped {duplicate_count} duplicate text rows")
    print(f"Class balance: {dict(Counter(row['label'] for row in deduped))}")
    print(f"Source counts: {dict(Counter(row['source'] for row in deduped))}")


if __name__ == "__main__":
    main()
