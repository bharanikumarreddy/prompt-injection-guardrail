"""Download a small public prompt-injection seed dataset.

This keeps dataset provenance visible without adding the HuggingFace
`datasets` package as a runtime dependency for the detector itself.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from urllib.request import urlopen


DATASET_API_URL = (
    "https://datasets-server.huggingface.co/first-rows"
    "?dataset=deepset/prompt-injections&config=default&split=train"
)
OUTPUT_PATH = Path("data/base_prompts.csv")


def normalize_label(value: int) -> str:
    """Map the deepset label convention into this project's labels."""
    return "malicious" if value == 1 else "benign"


def main() -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with urlopen(DATASET_API_URL, timeout=30) as response:
        payload = json.load(response)

    rows = []
    for item in payload["rows"]:
        row = item["row"]
        rows.append(
            {
                "prompt": row["text"],
                "label": normalize_label(row["label"]),
                "source": "deepset/prompt-injections",
                "category": "public_seed",
                "notes": "Downloaded from HuggingFace dataset preview API.",
            }
        )

    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=["prompt", "label", "source", "category", "notes"],
            quoting=csv.QUOTE_ALL,
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
