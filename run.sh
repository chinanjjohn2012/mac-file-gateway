#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -eq 0 ]; then
    echo 'Usage: bash run.sh /absolute/path/to/project [--allow-write] [--write-path src] [--backup-retention-days 15] [--allow-exec --exec-path service-c] [--exec-runner service-c=pipenv] [--local-skill-root agent-runtime --local-skill-policy-dir /private/policy] [--exclude PATTERN] [--port 8765]' >&2
    exit 2
fi
ROOT="$1"
shift
case "$ROOT" in
    /*) ;;
    *) ROOT="$PWD/$ROOT" ;;
esac
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
    echo 'Run bash setup.sh first.' >&2
    exit 2
fi
exec .venv/bin/python -m gateway --root "$ROOT" "$@"
