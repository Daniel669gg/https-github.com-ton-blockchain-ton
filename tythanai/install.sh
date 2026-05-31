#!/usr/bin/env bash
set -e
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║   Ghost Security Platform — Installer v2.2       ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

PYTHON=$(command -v python3 || command -v python)
PY_VER=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "[1/5] Python $PY_VER found at $PYTHON"

if [ ! -d ".venv" ]; then
    echo "[2/5] Creating virtual environment..."
    $PYTHON -m venv .venv
else
    echo "[2/5] Virtual environment already exists"
fi

source .venv/bin/activate

echo "[3/5] Installing core dependencies..."
pip install --upgrade pip -q
pip install fastapi uvicorn[standard] pydantic openai chromadb python-dotenv bandit requests -q

echo "[4/5] Installing optional tools..."
pip install semgrep -q 2>/dev/null && echo "      ✅ semgrep" || echo "      ⚠️  semgrep — install manually: pip install semgrep"

if [ ! -f ".env" ]; then
    cp .env.enterprise.example .env 2>/dev/null || cp .env.ollama.example .env 2>/dev/null || true
    echo "[5/5] Created .env — add your OPENAI_API_KEY"
else
    echo "[5/5] .env already exists"
fi

echo ""
echo "✅ Done! Quick start:"
echo "   source .venv/bin/activate"
echo "   python3 ghost_cli.py scan <path>         # scan project"
echo "   python3 ghost_cli.py ton  <contract.fc>  # TON audit"
echo "   python3 ghost_cli.py server              # web server → :8000/docs"
echo ""
