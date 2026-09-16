# Runbook: Abliterated Qwen 3.5 on Mac (16GB)

This cloud agent verifies Hades with the **mock** backend. Run the real baseline model on your Mac (or via Cursor **local** Agent).

## Why 4B

Primary model: `huihui_ai/qwen3.5-abliterated:4b` (~3.3GB).

On a **16GB MacBook Air**, 9B (~6.6GB) is runnable alone but tight once macOS + Cursor + Hades (Python/vector store) share memory. **4B** is the default for reliable eval matrices. Optional: `:9b` if you close other apps.

## Prerequisites

1. Install [Ollama](https://ollama.com) (native Mac app preferred over Docker on Apple Silicon).
2. Python 3.11+ and a checkout of this repo.
3. From the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Pull the model

```bash
chmod +x scripts/pull_model.sh
./scripts/pull_model.sh
# or:
ollama pull huihui_ai/qwen3.5-abliterated:4b
```

Optional 9B:

```bash
export HADES_OLLAMA_MODEL=huihui_ai/qwen3.5-abliterated:9b
ollama pull "$HADES_OLLAMA_MODEL"
```

## Seed data

```bash
hades seed
# or: python scripts/seed_aperture.py
```

## Refusal probe (baseline)

Confirms the controlled variable (near-zero refusal) before measuring defenses:

```bash
hades refusal-probe --backend ollama
```

## Full eval matrix with Ollama

```bash
export HADES_LLM_BACKEND=ollama
export HADES_OLLAMA_MODEL=huihui_ai/qwen3.5-abliterated:4b
hades eval --backend ollama --levels D0,D1,D2,D3,D4,D5,D6
```

Results: `eval/results/latest.json` and `eval/results/summary.csv`.

## Interactive API

```bash
hades serve --defense-level D3 --backend ollama
# Login
curl -s -X POST localhost:8080/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password"}'
# Chat with Bearer token from login
```

Lab users (password `password`): `alice`, `bob`, `carol`, `dave`, `eve`, `frank`.

## Cursor local Agent

1. Open this repo in Cursor **on your Mac**.
2. Ensure Ollama is running (`ollama serve` / menu bar app).
3. Use **Agent** in the IDE (local), not a Cloud Agent.
4. Ask it to run:

```bash
hades eval --backend ollama --levels D0,D1,D2,D3,D4,D5,D6
```

Local agents can reach `http://127.0.0.1:11434`. Cloud agents cannot.

## Memory tips (16GB)

- Quit browsers / other Electron apps during long evals.
- Keep `HADES` top_k small (default 5).
- Prefer 4B for overnight matrices; use 9B for spot checks.
