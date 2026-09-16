"""D2/D4 — PII / DLP detection, masking, and redaction."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class PIIType(str, Enum):
    SSN = "ssn"
    AADHAAR = "aadhaar"
    PAN = "pan"
    EMAIL = "email"
    PHONE = "phone"
    CREDIT_CARD = "credit_card"
    BANK_ACCOUNT = "bank_account"
    API_KEY = "api_key"
    PASSWORD = "password"
    EMPLOYEE_ID = "employee_id"


@dataclass
class Finding:
    pii_type: PIIType
    value: str
    start: int
    end: int


@dataclass
class DLPResult:
    original: str
    redacted: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def has_pii(self) -> bool:
        return bool(self.findings)


# Patterns intentionally imperfect — lab studies residual leakage under transforms.
PATTERNS: list[tuple[PIIType, re.Pattern[str]]] = [
    (PIIType.SSN, re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    (PIIType.SSN, re.compile(r"\b\d{9}\b")),  # compact SSN
    (PIIType.AADHAAR, re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b")),
    (PIIType.AADHAAR, re.compile(r"\b\d{12}\b")),
    (PIIType.PAN, re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    (PIIType.EMAIL, re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    (PIIType.PHONE, re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
    (PIIType.CREDIT_CARD, re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")),
    (PIIType.BANK_ACCOUNT, re.compile(r"\b(?:acct|account)[#:\s-]*\d{8,17}\b", re.I)),
    (PIIType.API_KEY, re.compile(r"\b(?:sk|ak|api)[_-][A-Za-z0-9]{16,}\b")),
    (PIIType.PASSWORD, re.compile(r"(?i)password\s*[:=]\s*\S+")),
    (PIIType.EMPLOYEE_ID, re.compile(r"\bEMP-\d{4,}\b")),
]

REDACTION_TOKENS = {
    PIIType.SSN: "[REDACTED_SSN]",
    PIIType.AADHAAR: "[REDACTED_AADHAAR]",
    PIIType.PAN: "[REDACTED_PAN]",
    PIIType.EMAIL: "[REDACTED_EMAIL]",
    PIIType.PHONE: "[REDACTED_PHONE]",
    PIIType.CREDIT_CARD: "[REDACTED_CARD]",
    PIIType.BANK_ACCOUNT: "[REDACTED_BANK]",
    PIIType.API_KEY: "[REDACTED_API_KEY]",
    PIIType.PASSWORD: "[REDACTED_PASSWORD]",
    PIIType.EMPLOYEE_ID: "[REDACTED_EMP_ID]",
}


def scan(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for pii_type, pattern in PATTERNS:
        for m in pattern.finditer(text):
            findings.append(
                Finding(pii_type=pii_type, value=m.group(0), start=m.start(), end=m.end())
            )
    # Deduplicate overlapping by start position (keep first).
    findings.sort(key=lambda f: (f.start, -(f.end - f.start)))
    deduped: list[Finding] = []
    last_end = -1
    for f in findings:
        if f.start < last_end:
            continue
        deduped.append(f)
        last_end = f.end
    return deduped


def redact(text: str) -> DLPResult:
    findings = scan(text)
    if not findings:
        return DLPResult(original=text, redacted=text, findings=[])
    # Replace from end to preserve offsets.
    redacted = text
    for f in sorted(findings, key=lambda x: x.start, reverse=True):
        token = REDACTION_TOKENS[f.pii_type]
        redacted = redacted[: f.start] + token + redacted[f.end :]
    return DLPResult(original=text, redacted=redacted, findings=findings)
