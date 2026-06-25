"""Combine heuristic and ML signals into one detector verdict."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from prompt_injection_detector.heuristics import HeuristicResult, detect
from prompt_injection_detector.ml import MLResult, predict_prompt


MALICIOUS_ML_THRESHOLD = 0.75
SUSPICIOUS_ML_THRESHOLD = 0.5
STRONG_HEURISTIC_THRESHOLD = 0.9


@dataclass(frozen=True)
class LayerSummary:
    """Compact signal summary for API responses and evaluation."""

    heuristic: dict[str, Any]
    ml: dict[str, Any]


@dataclass(frozen=True)
class CombinedResult:
    """Final detector decision."""

    verdict: str
    confidence: float
    layers: LayerSummary


def check_prompt(prompt: str, model: Any | None = None) -> CombinedResult:
    """Run both detector layers and combine their outputs."""
    heuristic_result = detect(prompt)
    ml_result = predict_prompt(prompt, model=model)
    verdict, confidence = combine_scores(heuristic_result, ml_result)

    return CombinedResult(
        verdict=verdict,
        confidence=confidence,
        layers=LayerSummary(
            heuristic=_heuristic_summary(heuristic_result),
            ml=_ml_summary(ml_result),
        ),
    )


def combine_scores(
    heuristic_result: HeuristicResult,
    ml_result: MLResult,
) -> tuple[str, float]:
    """Convert layer results into malicious / suspicious / benign.

    Decision policy:
    - Strong heuristic hits are malicious even if the ML layer is uncertain.
    - Very high ML probability is malicious even without a rule hit.
    - Medium ML probability or weaker heuristic evidence is suspicious.
    - No meaningful signal is benign.
    """
    heuristic_score = heuristic_result.score
    ml_probability = ml_result.malicious_probability

    if heuristic_score >= STRONG_HEURISTIC_THRESHOLD:
        return "malicious", round(max(heuristic_score, ml_probability), 4)

    if ml_probability >= MALICIOUS_ML_THRESHOLD:
        return "malicious", round(max(heuristic_score, ml_probability), 4)

    if heuristic_result.fired or ml_probability >= SUSPICIOUS_ML_THRESHOLD:
        confidence = max(heuristic_score, ml_probability)
        return "suspicious", round(confidence, 4)

    benign_confidence = 1.0 - max(heuristic_score, ml_probability)
    return "benign", round(benign_confidence, 4)


def to_dict(result: CombinedResult) -> dict[str, Any]:
    """Serialize a combined result for API responses."""
    return asdict(result)


def _heuristic_summary(result: HeuristicResult) -> dict[str, Any]:
    return {
        "fired": result.fired,
        "score": result.score,
        "matches": [
            {
                "rule": match.rule,
                "category": match.category,
                "severity": match.severity,
                "description": match.description,
                "matched_text": match.matched_text,
            }
            for match in result.matches
        ],
    }


def _ml_summary(result: MLResult) -> dict[str, Any]:
    return {
        "fired": result.fired,
        "malicious_probability": result.malicious_probability,
        "predicted_label": result.predicted_label,
    }
