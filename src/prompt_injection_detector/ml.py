"""ML inference helpers for the prompt-injection classifier."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_MODEL_PATH = Path("models/prompt_injection_model.joblib")
MALICIOUS_LABEL = "malicious"


@dataclass(frozen=True)
class MLResult:
    """Classifier result for one prompt."""

    malicious_probability: float
    predicted_label: str
    fired: bool


def load_model(model_path: Path | str = DEFAULT_MODEL_PATH) -> Any:
    """Load the saved scikit-learn pipeline."""
    try:
        import joblib
    except ImportError as exc:
        raise RuntimeError(
            "Missing dependency: joblib. Install dependencies with "
            "`pip install -r requirements.txt`."
        ) from exc

    path = Path(model_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Model artifact not found at {path}. Run `python3 scripts/train.py` first."
        )
    return joblib.load(path)


def predict_prompt(
    prompt: str,
    model: Any | None = None,
    model_path: Path | str = DEFAULT_MODEL_PATH,
    threshold: float = 0.5,
) -> MLResult:
    """Score one prompt with the trained classifier."""
    loaded_model = model if model is not None else load_model(model_path)
    probabilities = loaded_model.predict_proba([prompt or ""])[0]
    classes = list(loaded_model.classes_)

    malicious_index = classes.index(MALICIOUS_LABEL)
    malicious_probability = float(probabilities[malicious_index])
    predicted_label = MALICIOUS_LABEL if malicious_probability >= threshold else "benign"

    return MLResult(
        malicious_probability=round(malicious_probability, 4),
        predicted_label=predicted_label,
        fired=predicted_label == MALICIOUS_LABEL,
    )
