"""Threat model for the Hades / Aperture enterprise RAG lab."""

# Security Without Refusal — Threat Model (STRIDE + LLM surfaces)

## Assets

- Synthetic employee PII (SSN, Aadhaar, PAN, salary, bank)
- Customer confidential data
- Executive strategy and compensation
- Security incident details and secrets
- Tool/database access paths
- Telemetry and audit logs

## Actors

| Actor | Capability |
|-------|------------|
| Black-box user | Application UI/API only |
| Gray-box user | Knows RAG exists; crafts retrieval-oriented prompts |
| Red-team operator | Knows defense layers, ACLs, injection surfaces |
| Malicious document author | Plants instructions in corpus |

## Trust boundaries

```text
Internet / User
   │
   ▼
Application (FastAPI)
   ├── Authentication (JWT)
   ├── Authorization / Policy engine
   ├── Input DLP + Prompt gateway
   ▼
RAG Layer
   ├── Vector store (NOT an auth boundary)
   └── Document store metadata (classification, department)
   ▼
Non-refusing LLM (abliterated Qwen 3.5 / mock)
   ▼
Output DLP / policy scanner
   ▼
Tool PEP ──► SQLite / typed APIs
   ▼
Telemetry / SIEM detectors
```

At every boundary ask: what can cross, who controls it, what validates it?

## STRIDE (selected)

| Component | Spoofing | Tampering | Repudiation | Info disclosure | DoS | Elevation |
|-----------|----------|-----------|-------------|-----------------|-----|-----------|
| Auth | Stolen JWT | Token claims edited | Missing audit | Role leakage | Login flood | Role confusion |
| Gateway | N/A | Pattern evasion | N/A | Over-block | Regex cost | Bypass → raw model |
| RAG | Identity spoof | Poisoned docs | Missing retrieval logs | Unauthorized chunks | Huge corpus | ACL skip |
| LLM | N/A | Prompt injection | N/A | Faithful exfil | Huge context | Tool abuse |
| Tools | Forged calls | Raw SQL | Missing tool logs | DB dumps | Heavy queries | Model-decided authz |
| Output | N/A | Encoding transforms | N/A | Residual PII | Scanner cost | N/A |

## LLM-specific threats

- Direct exfiltration prompts
- Authorization bypass via retrieval without ACL
- Indirect prompt injection in retrieved text
- Cross-document contamination
- PII exact / partial / aggregated / reconstructed leakage
- Membership / existence inference
- Tool-layer privilege abuse when authz is delegated to the model

## Security objectives

1. Unauthorized documents never enter model context when retrieval ACL is enabled.
2. Tool authorization is enforced by the PEP, never by model text.
3. DLP reduces residual leakage under common transforms (measure, do not claim perfection).
4. Utility remains usable for authorized tasks (track FPR).
5. Telemetry detects burst restricted access and repeated ACL denials.

## Explicit non-claim

This lab does **not** prove “the LLM is secure.” It measures how far defense-in-depth reduces attack success when model refusal ≈ 0.
