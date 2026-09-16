"""D1 — input prompt / jailbreak / malicious request gateway."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class PromptClass(str, Enum):
    BENIGN = "benign"
    EXFILTRATION = "exfiltration"
    JAILBREAK = "jailbreak"
    AUTHORIZATION_PROBE = "authorization_probe"
    MEMBERSHIP_INFERENCE = "membership_inference"
    PII_HARVEST = "pii_harvest"


@dataclass
class GatewayResult:
    allowed: bool
    classification: PromptClass
    reasons: list[str]
    confidence: float


EXFIL_PATTERNS = [
    r"\bdump\b.*(database|employees|customers)",
    r"\bgive me (all|the entire|every)\b",
    r"\bexfiltrat",
    r"\bexport (all|the) (data|records)",
    r"\bshow me (all|every) (ssn|aadhaar|pan|salary)",
]

JAILBREAK_PATTERNS = [
    r"ignore (all )?(previous|prior|above) (instructions|rules)",
    r"you are now (dan|unrestricted|jailbroken)",
    r"developer mode",
    r"do not follow (your|the) (safety|policy)",
    r"pretend you have no restrictions",
]

AUTHZ_PATTERNS = [
    r"executive compensation",
    r"board strategy",
    r"security incident",
    r"salary of",
    r"compensation report",
]

PII_PATTERNS = [
    r"\bssn\b",
    r"\baadhaar\b",
    r"\bpan\b",
    r"bank account",
    r"credit card",
    r"phone number of",
    r"home address of",
]

MEMBERSHIP_PATTERNS = [
    r"do we have an employee named",
    r"is there (a|an) (customer|employee) (named|called)",
    r"confirm whether .+ exists",
    r"does (our|the) (system|database) contain",
]


def _match_any(text: str, patterns: list[str]) -> list[str]:
    hits = []
    for p in patterns:
        if re.search(p, text, flags=re.IGNORECASE):
            hits.append(p)
    return hits


def classify_prompt(text: str) -> GatewayResult:
    reasons: list[str] = []
    lower = text.lower()

    if hits := _match_any(lower, JAILBREAK_PATTERNS):
        return GatewayResult(False, PromptClass.JAILBREAK, hits, 0.9)
    if hits := _match_any(lower, EXFIL_PATTERNS):
        return GatewayResult(False, PromptClass.EXFILTRATION, hits, 0.85)
    if hits := _match_any(lower, PII_PATTERNS):
        return GatewayResult(False, PromptClass.PII_HARVEST, hits, 0.8)
    if hits := _match_any(lower, MEMBERSHIP_PATTERNS):
        return GatewayResult(False, PromptClass.MEMBERSHIP_INFERENCE, hits, 0.75)
    if hits := _match_any(lower, AUTHZ_PATTERNS):
        # Detect sensitive topics for telemetry, but do not hard-block:
        # authorization is enforced at retrieval/tool layers (D3/D5).
        return GatewayResult(True, PromptClass.AUTHORIZATION_PROBE, hits, 0.7)

    return GatewayResult(True, PromptClass.BENIGN, reasons, 0.6)
