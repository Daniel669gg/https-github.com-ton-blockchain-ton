#!/usr/bin/env bash
set -e
[ -f ".venv/bin/activate" ] && source .venv/bin/activate || true
export OPENAI_BASE_URL=${OPENAI_BASE_URL:-http://localhost:11434/v1}
export OPENAI_API_KEY=${OPENAI_API_KEY:-ollama}
python3 ghost_cli.py "$@"
