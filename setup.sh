#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
PY=""
if [ -n "${PYTHON:-}" ]; then
    candidates=("$PYTHON")
else
    candidates=(python3.13 python3.12 python3.11 python3)
fi
for candidate in "${candidates[@]}"; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' >/dev/null 2>&1; then
        PY="$candidate"
        break
    fi
done
if [ -z "$PY" ]; then
    echo 'Python 3.11+ is required. With Homebrew: brew install python@3.13' >&2
    exit 2
fi
if [ ! -d .venv ]; then
    "$PY" -m venv .venv
fi
.venv/bin/python -c 'import sys; assert sys.version_info >= (3, 11), "Existing .venv needs Python 3.11+"'
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pip check
bash verify.sh --require-mcp
printf '\nSetup verified. Start with: bash run.sh "$HOME/Projects/your-project"\n'
