"""FastAPI app for the prompt-injection detector."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from prompt_injection_detector.combiner import check_prompt, to_dict
from prompt_injection_detector.ml import load_model


app = FastAPI(
    title="Prompt Injection Detector",
    description="Layered prompt-injection detector with heuristic and ML signals.",
    version="0.1.0",
)

STATIC_DIR = Path(__file__).parent / "static"
INDEX_PATH = STATIC_DIR / "index.html"

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class CheckRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="Prompt to inspect before LLM use.")


class CheckResponse(BaseModel):
    verdict: str
    confidence: float
    layers: dict[str, Any]


@lru_cache(maxsize=1)
def get_model() -> Any:
    """Load the model once per API process."""
    return load_model()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_PATH.read_text(encoding="utf-8")


@app.post("/check", response_model=CheckResponse)
def check(request: CheckRequest) -> dict[str, Any]:
    try:
        result = check_prompt(request.prompt, model=get_model())
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return to_dict(result)
