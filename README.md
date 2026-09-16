# Hades

**Security Without Model Refusal** — a defense-in-depth research lab for enterprise RAG.

> Research question: *How much security can be recovered at the system layer when the underlying LLM is intentionally non-refusing?*

This repository is an experimental platform, not a claim that any configuration is “secure.”

## Thesis

Model alignment and application security are **separate control planes**. An abliterated (near-zero refusal) model is the controlled variable; identity, authorization, retrieval isolation, DLP, tool permissions, output controls, and monitoring carry the security burden.

## Stack

| Piece | Choice |
|-------|--------|
| Baseline LLM | `huihui_ai/qwen3.5-abliterated:4b` via Ollama (9B optional) |
| CI / cloud | Deterministic **mock** non-refusing LLM |
| API | FastAPI |
| Retrieval | Local hash-embedding vector store + classification metadata |
| Auth | JWT + role / clearance ACLs |

**Why 4B:** sized for a **16GB MacBook Air** alongside the lab stack. See [docs/runbook-ollama-mac.md](docs/runbook-ollama-mac.md).

## Quick start (mock — works offline)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
hades seed
hades eval --backend mock --levels D0,D1,D2,D3,D4,D5,D6
pytest
```

## Defense levels

| Level | Controls |
|-------|----------|
| D0 | Raw model + unfiltered RAG |
| D1 | Input prompt gateway |
| D2 | + PII/DLP redaction |
| D3 | + Retrieval ACLs |
| D4 | + Output policy scanning |
| D5 | + Tool authorization (PEP) |
| D6 | + Telemetry / SIEM detectors |
| D7 | All layers (alias of full stack) |

## Synthetic enterprise

**Aperture Systems** — departments Engineering, Finance, HR, Sales, Security, Executive; classifications Public → Highly Restricted; users Alice–Frank with distinct clearances.

## Attack classes (lab fixtures)

A direct exfil · B authz bypass · C indirect injection · D cross-doc contamination · E PII extraction · F membership inference — plus black / gray / red attacker knowledge tiers.

## Metrics

Unauthorized Retrieval Rate (URR), Sensitive Disclosure Rate (SDR), PII Leakage Rate (PLR), Attack Success Rate (ASR), False Positive Rate (FPR), utility success, latency.

## Real model on your Mac

Cloud agents use **mock** only. For abliterated Qwen:

→ **[docs/runbook-ollama-mac.md](docs/runbook-ollama-mac.md)**

Cursor **local** Agent on your Mac can call Ollama; Cloud Agents cannot.

## Docs

- [Threat model](docs/threat-model.md)
- [Ollama Mac runbook](docs/runbook-ollama-mac.md)
- [Report template](reports/REPORT_TEMPLATE.md)

## Authorship

Commits in this project are authored by the repository owner. Do not add Cursor / agent co-author trailers.

## License

MIT — see [LICENSE](LICENSE). All data is synthetic; no real PII.
