"""Private, bounded subprocess runner for ContextVar static disambiguation."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tokenize

MAX_BYTES = 32 * 1024
MAX_LINES = 1024
MAX_LINE_CHARS = 2048
MAX_TOKENS = 4096
MAX_STMT_TOKENS = 256
MAX_DEPTH = 32
PARSE_TIMEOUT_SECONDS = 0.250
_WORKER = Path(__file__).with_name("contextvar_worker.py")


def _preflight(raw: bytes) -> bool:
    if len(raw) > MAX_BYTES or raw.count(b"\n") + 1 > MAX_LINES:
        return False
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError:
        return False
    if any(len(line) > MAX_LINE_CHARS for line in text.splitlines()):
        return False
    tokens = statement = depth = 0
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            tokens += 1
            if tokens > MAX_TOKENS:
                return False
            if token.type == tokenize.OP:
                if token.string in "([{":
                    depth += 1
                elif token.string in ")]}":
                    depth -= 1
                if depth < 0 or depth > MAX_DEPTH:
                    return False
            if token.type in (tokenize.NEWLINE, tokenize.ENDMARKER):
                statement = 0
            else:
                statement += 1
            if statement > MAX_STMT_TOKENS:
                return False
    except (tokenize.TokenError, IndentationError, RecursionError, ValueError):
        return False
    return True


def proven_lines(raw: bytes) -> tuple[int, ...]:
    """A failed proof is no exemption. Never parse arbitrary sources in-process."""
    if not _preflight(raw):
        return ()
    try:
        # Isolated interpreter, fixed trusted script, no shell, no workspace cwd.
        p = subprocess.run(
            [sys.executable, "-I", "-S", str(_WORKER)],
            input=raw,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=str(_WORKER.parent),
            env={"PYTHONIOENCODING": "utf-8"},
            close_fds=True,
            timeout=PARSE_TIMEOUT_SECONDS,
            check=False,
        )
        if p.returncode != 0 or len(p.stdout) > 16384:
            return ()
        value = json.loads(p.stdout)
        if not isinstance(value, list) or len(value) > 1024:
            return ()
        if any(type(n) is not int or n < 1 or n > MAX_LINES for n in value):
            return ()
        return tuple(sorted(set(value)))
    except (OSError, subprocess.TimeoutExpired, ValueError, RecursionError):
        return ()
