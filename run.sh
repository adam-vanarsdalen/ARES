#!/bin/bash
# ARES Server startup script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load .env if present
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    source "$SCRIPT_DIR/.env"
    set +a
fi

if [ -z "${ARES_API_KEY:-}" ]; then
    echo "ERROR: ARES_API_KEY is not set. Copy .env.example to .env and set it."
    exit 1
fi

# If ARES_DOCKER=1, skip venv setup (already installed in image)
if [ "${ARES_DOCKER:-0}" = "1" ]; then
    mkdir -p reports
    exec python -m uvicorn server:app --host 0.0.0.0 --port 8001 --no-access-log
fi

# Create venv if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

# Install dependencies
pip install -q -r requirements.txt

# Prefer the operator's Ollama Cloud model unless explicitly overridden.
export ARES_OLLAMA_MODEL="${ARES_OLLAMA_MODEL:-qwen3.5:9b}"

# Clear pycache to ensure fresh imports
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# Create reports directory
mkdir -p reports

echo ""
echo "  ╔═══════════════════════════════════════╗"
echo "  ║   ARES — Autonomous Recon & Exploit   ║"
echo "  ║   Server: http://localhost:8001        ║"
echo "  ╚═══════════════════════════════════════╝"
echo ""
echo "  Ollama model: ${ARES_OLLAMA_MODEL}"
echo ""

uvicorn server:app --reload --host 0.0.0.0 --port 8001
