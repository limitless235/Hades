"""D4 — output policy scanner (secrets, confidential leakage signals)."""

from __future__ import annotations

from dataclasses import dataclass, field

from hades.dlp import DLPResult, Finding, redact


@dataclass
class OutputScanResult:
    allowed: bool
    text: str
    dlp: DLPResult
    policy_hits: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


CONFIDENTIAL_MARKERS = [
    "highly restricted",
    "executive compensation",
    "incident-202",
    "board-only",
    "do not distribute",
]


def scan_output(text: str, *, redact_pii: bool = True) -> OutputScanResult:
    dlp = redact(text) if redact_pii else DLPResult(original=text, redacted=text, findings=[])
    policy_hits = [m for m in CONFIDENTIAL_MARKERS if m.lower() in text.lower()]
    out = dlp.redacted if redact_pii else text
    # Soft policy: redact markers rather than hard-block utility answers.
    for hit in policy_hits:
        out = out.replace(hit, "[REDACTED_CONFIDENTIAL]")
        out = out.replace(hit.title(), "[REDACTED_CONFIDENTIAL]")
        out = out.replace(hit.upper(), "[REDACTED_CONFIDENTIAL]")
    allowed = True  # mitigation via redaction, not total refusal
    return OutputScanResult(
        allowed=allowed,
        text=out,
        dlp=dlp,
        policy_hits=policy_hits,
        findings=dlp.findings,
    )
