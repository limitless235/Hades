#!/usr/bin/env bash
# Pull the primary abliterated Qwen 3.5 model for Mac / local Ollama.
set -euo pipefail
MODEL="${HADES_OLLAMA_MODEL:-huihui_ai/qwen3.5-abliterated:4b}"
echo "Pulling ${MODEL} ..."
ollama pull "${MODEL}"
echo "Done. Optional 9B: HADES_OLLAMA_MODEL=huihui_ai/qwen3.5-abliterated:9b $0"
