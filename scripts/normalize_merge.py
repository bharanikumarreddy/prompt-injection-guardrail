"""Normalize source datasets into data/master.csv.

Stage 1 goal:
- keep one canonical schema for downstream training: text, label, source
- preserve provenance in the source column
- dedupe across source files by normalized prompt text

Stage 2 adds editable custom rows separately, so this script keeps
`data/master.csv` focused on normalized public/base source data.
"""

from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path


SOURCE_FILES = [
    Path("data/base_prompts.csv"),
]
OUTPUT_PATH = Path("data/master.csv")


LABEL_MAP = {
    "0": "benign",
    "false": "benign",
    "benign": "benign",
    "legitimate": "benign",
    "normal": "benign",
    "safe": "benign",
    "1": "malicious",
    "true": "malicious",
    "attack": "malicious",
    "injection": "malicious",
    "jailbreak": "malicious",
    "malicious": "malicious",
}


def normalize_text(text: str) -> str:
    """Collapse whitespace while preserving the readable prompt text."""
    return re.sub(r"\s+", " ", text or "").strip()


def dedupe_key(text: str) -> str:
    """Use a case-insensitive text key for cross-source dedupe."""
    return normalize_text(text).casefold()


def normalize_label(raw_label: str) -> str:
    key = str(raw_label).strip().casefold()
    try:
        return LABEL_MAP[key]
    except KeyError as exc:
        raise ValueError(f"Unsupported label value: {raw_label!r}") from exc


def source_name(path: Path, row: dict[str, str]) -> str:
    """Prefer explicit source metadata, falling back to the file stem."""
    value = (row.get("source") or "").strip()
    return value or path.stem


def read_source(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as csv_file:
        rows = list(csv.DictReader(csv_file))

    normalized_rows = []
    for row in rows:
        text = normalize_text(row.get("prompt") or row.get("text") or "")
        if not text:
            continue

        normalized_rows.append(
            {
                "text": text,
                "label": normalize_label(row["label"]),
                "source": source_name(path, row),
            }
        )

    return normalized_rows


def main() -> None:
    seen: set[str] = set()
    merged: list[dict[str, str]] = []
    duplicate_count = 0

    for path in SOURCE_FILES:
        for row in read_source(path):
            key = dedupe_key(row["text"])
            if key in seen:
                duplicate_count += 1
                continue
            seen.add(key)
            merged.append(row)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["text", "label", "source"])
        writer.writeheader()
        writer.writerows(merged)

    label_counts = Counter(row["label"] for row in merged)
    source_counts = Counter(row["source"] for row in merged)

    print(f"Wrote {len(merged)} rows to {OUTPUT_PATH}")
    print(f"Dropped {duplicate_count} duplicate text rows")
    print(f"Class balance: {dict(label_counts)}")
    print(f"Source counts: {dict(source_counts)}")


if __name__ == "__main__":
    main()
