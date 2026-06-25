"""Regex and heuristic prompt-injection detector.

This layer is intentionally explainable. It does not try to be clever or
complete; it catches known attack shapes and returns the rule names that fired.
The ML layer will handle softer patterns later.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class HeuristicRule:
    """One explainable detection rule."""

    name: str
    category: str
    severity: str
    description: str
    patterns: tuple[re.Pattern[str], ...]


@dataclass(frozen=True)
class RuleMatch:
    """A rule hit returned to callers."""

    rule: str
    category: str
    severity: str
    description: str
    matched_text: str


@dataclass(frozen=True)
class HeuristicResult:
    """Full heuristic detector result for one prompt."""

    fired: bool
    score: float
    matches: tuple[RuleMatch, ...]


SEVERITY_WEIGHTS = {
    "low": 0.35,
    "medium": 0.65,
    "high": 0.9,
}


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, flags=re.IGNORECASE | re.MULTILINE)


RULES: tuple[HeuristicRule, ...] = (
    HeuristicRule(
        name="ignore_previous_instructions",
        category="instruction_override",
        severity="high",
        description="Attempts to ignore, forget, or override prior instructions.",
        patterns=(
            _compile(r"\b(ignore|disregard|forget|bypass|override)\b.{0,80}\b(previous|prior|above|earlier)\b.{0,40}\b(instructions?|prompts?|messages?|rules?)\b"),
            _compile(r"\b(cancel|drop|discard)\b.{0,60}\b(previous|prior|above|earlier)\b.{0,40}\b(instructions?|rules?|context)\b"),
            _compile(r"\b(new|updated)\s+(task|instructions?|system prompt)\b.{0,80}\b(ignore|forget|disregard|override)\b"),
        ),
    ),
    HeuristicRule(
        name="jailbreak_persona",
        category="jailbreak",
        severity="high",
        description="Uses known jailbreak or unrestricted-persona phrasing.",
        patterns=(
            _compile(r"\b(DAN|developer mode|STAN|AIM|RootGPT)\b"),
            _compile(r"\b(jailbroken|unrestricted|uncensored|unaligned)\b.{0,60}\b(assistant|model|mode|persona)\b"),
            _compile(r"\b(no|without)\b.{0,40}\b(policy|policies|safety|restrictions?|guardrails?|filters?)\b"),
        ),
    ),
    HeuristicRule(
        name="system_prompt_extraction",
        category="prompt_leakage",
        severity="high",
        description="Requests hidden prompts, system messages, policies, or detection rules.",
        patterns=(
            _compile(r"\b(reveal|print|show|display|dump|expose|leak|output)\b.{0,80}\b(system prompt|system message|hidden prompt|developer message|policy|guardrails?)\b"),
            _compile(r"\b(reveal|print|show|display|dump|expose|leak|output)\b.{0,80}\b(detection rules?|regex signatures?|classifier threshold|secret allowlist)\b"),
            _compile(r"\b(full|complete|exact|original)\b.{0,40}\b(prompt text|system prompt|policy text|instructions?)\b"),
        ),
    ),
    HeuristicRule(
        name="role_confusion",
        category="role_confusion",
        severity="high",
        description="Spoofs higher-priority roles such as system, developer, admin, or platform.",
        patterns=(
            _compile(r"\b(system|developer|platform|administrator|admin)\s*:\s*.{0,120}\b(ignore|reveal|override|comply|disable)\b"),
            _compile(r"\b(role\s*=\s*system|role\s*:\s*system|system message|developer instruction)\b"),
            _compile(r"\b(treat|consider)\b.{0,60}\b(user message|this message|analyst note)\b.{0,80}\b(system|developer|higher priority)\b"),
            _compile(r"\b(I am|I'm)\b.{0,40}\b(admin|administrator|developer|security owner|platform owner)\b.{0,80}\b(grant|approve|authorize|override)\b"),
        ),
    ),
    HeuristicRule(
        name="delimiter_injection",
        category="delimiter_injection",
        severity="medium",
        description="Uses delimiters or closing tags to escape prompt sections.",
        patterns=(
            _compile(r"(###|---|\|\|\|).{0,40}\b(end|start|begin|new)\b.{0,60}\b(system|instruction|context|prompt|policy)\b"),
            _compile(r"</\s*(system|instructions?|policy|context|developer)\s*>"),
            _compile(r"```+\s*(system|developer|instructions?|policy)?\s*\n"),
            _compile(r"\b(end|close)\b.{0,40}\b(system|instruction|context|policy)\b.{0,40}\b(block|prompt|section)\b"),
        ),
    ),
    HeuristicRule(
        name="encoded_payload",
        category="obfuscation",
        severity="medium",
        description="Contains encoded or obfuscated payload indicators.",
        patterns=(
            _compile(r"\b(base64|hex encoded|url encoded|rot13|decode this|decoded?|obfuscated|leetspeak|reversed sentence)\b"),
            _compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b"),
            _compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b"),
            _compile(r"(?:%[0-9a-fA-F]{2}){3,}"),
            _compile(r"\b[1!][gq]n[o0]r[e3]\b.{0,40}\b(pr[e3]v[i1]ous|pr[i1]or)\b"),
        ),
    ),
)

BENIGN_DISCUSSION_PATTERNS: tuple[re.Pattern[str], ...] = (
    _compile(r"\b(how|what|why|can you|could you|please)\b.{0,80}\b(test|detect|prevent|protect|resist|triage|explain|summarize|review|classify)\b"),
    _compile(r"\b(build|write|create)\b.{0,50}\b(regex|rule|detector|detection)\b"),
    _compile(r"\b(customer|someone|user|ticket|report)\b.{0,80}\b(pasted|sent|quoted|included|contains?)\b"),
    _compile(r"\b(is that dangerous|dangerous or just noise|how should we triage)\b"),
    _compile(r"\b(detection|detector|research|documentation|class assignment|student|red-team report|false positives?)\b"),
)

SUPPRESSIBLE_RULES = {
    "ignore_previous_instructions",
    "jailbreak_persona",
    "system_prompt_extraction",
    "role_confusion",
    "delimiter_injection",
    "encoded_payload",
}

DIRECT_ATTACK_INTENT_PATTERN = _compile(
    r"\b(reveal|print|show|display|dump|expose|leak|output|disable|override|suppress|auto-close)\b"
    r".{0,100}\b(system prompt|system message|hidden prompt|developer message|policy|detection rules?|regex signatures?|classifier threshold|secret allowlist|alerts?|guardrails?)\b"
)

QUOTED_OR_REVIEW_CONTEXT_PATTERN = _compile(
    r"\b(customer|someone|user|ticket|report|student|class assignment)\b"
    r".{0,100}\b(pasted|sent|quoted|included|contains?|asked|asking|review|triage|classify)\b"
)


def detect(prompt: str) -> HeuristicResult:
    """Run heuristic rules against a prompt."""
    text = prompt or ""
    matches: list[RuleMatch] = []
    benign_discussion = _looks_like_benign_security_discussion(text)

    for rule in RULES:
        for pattern in rule.patterns:
            match = pattern.search(text)
            if not match:
                continue
            if benign_discussion and rule.name in SUPPRESSIBLE_RULES:
                continue
            matches.append(
                RuleMatch(
                    rule=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    description=rule.description,
                    matched_text=match.group(0).strip(),
                )
            )
            break

    score = _score_matches(matches)
    return HeuristicResult(fired=bool(matches), score=score, matches=tuple(matches))


def _score_matches(matches: list[RuleMatch]) -> float:
    """Convert rule hits into a bounded confidence-like score."""
    if not matches:
        return 0.0

    weighted_sum = sum(SEVERITY_WEIGHTS[match.severity] for match in matches)
    return round(min(0.99, weighted_sum), 2)


def matched_rule_names(result: HeuristicResult) -> list[str]:
    """Convenience helper for API responses and reports."""
    return [match.rule for match in result.matches]


def _looks_like_benign_security_discussion(text: str) -> bool:
    """Suppress quoted indicators when the prompt is clearly asking about defense.

    This is intentionally narrow. Direct leak or suppression commands still
    fire unless the prompt is clearly discussing someone else's quoted example.
    """
    if DIRECT_ATTACK_INTENT_PATTERN.search(text):
        return bool(QUOTED_OR_REVIEW_CONTEXT_PATTERN.search(text))
    return any(pattern.search(text) for pattern in BENIGN_DISCUSSION_PATTERNS)
