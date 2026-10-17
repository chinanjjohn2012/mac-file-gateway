"""Shared source visibility for file read, search, guarded edits and diffs.

All classification starts from the original UTF-8 text, not an API response.
The policy never replaces or alters committed source bytes.
"""
from __future__ import annotations

import re
from typing import Callable


class SensitiveContentPolicy:
    def __init__(self, protected_paths: tuple[str, ...] = ()):
        # Retain only real absolute paths with stable character boundaries.
        paths = set()
        for raw in protected_paths:
            if type(raw) is not str or not raw.startswith('/') or raw == '/':
                continue
            item = raw.rstrip('/')
            if item:
                paths.add(item)
        # Match a protected directory/path as a complete segment, not a prefix
        # of some unrelated filename (e.g. /repo vs /repository).
        self._paths = tuple(sorted(paths, key=len, reverse=True))
        self._expr = (re.compile(r'(?<![\w./-])(?:' + '|'.join(re.escape(x) for x in self._paths)
                                 + r')(?=$|[/\\\s"\x27:;,)\]}])') if self._paths else None)

    def sensitive_flags(self, text: str) -> list[bool]:
        from .core import _sensitive_line_flags
        flags = _sensitive_line_flags(text)
        if self._expr is not None:
            return [flag or bool(self._expr.search(line))
                    for flag, line in zip(flags, text.splitlines())]
        return flags

    def redact_lines(self, text: str) -> tuple[list[str], int]:
        flags = self.sensitive_flags(text)
        return (["[REDACTED] protected content" if flag else line
                 for line, flag in zip(text.splitlines(), flags)], sum(flags))

    def redacted_diff_lines(self, text: str) -> list[str]:
        flags = self.sensitive_flags(text)
        result = []
        for line, hidden in zip(text.splitlines(keepends=True), flags):
            if hidden:
                terminator = '\r\n' if line.endswith('\r\n') else '\n' if line.endswith('\n') else '\r' if line.endswith('\r') else ''
                result.append('[REDACTED] protected content' + terminator)
            else:
                result.append(line)
        return result

    def visible_runs(self, text: str) -> list[tuple[int, int]]:
        """Return maximal contiguous visible regions by character offsets.

        Hidden content is NEVER queried for an old_text candidate. Queries
        straddling hidden lines cannot match. Lines ending in CRLF/BOM are
        left as-is; writer uses raw source when applying eligible matches.
        """
        flags = self.sensitive_flags(text)
        offset = 0
        start = None
        runs: list[tuple[int, int]] = []
        for line, hidden in zip(text.splitlines(keepends=True), flags):
            end = offset + len(line)
            if hidden:
                if start is not None:
                    runs.append((start, offset))
                    start = None
            elif start is None:
                start = offset
            offset = end
        if start is not None:
            runs.append((start, len(text)))
        if not text:
            runs.append((0, 0))
        return runs

    def visible_matches(self, source: str, old: str) -> list[tuple[int, int]]:
        matches: list[tuple[int, int]] = []
        if not old:
            return matches
        for left, right in self.visible_runs(source):
            offset = left
            while True:
                index = source.find(old, offset, right)
                if index < 0:
                    break
                matches.append((index, index + len(old)))
                offset = index + len(old)
        return matches

    def is_sensitive(self, text: str) -> bool:
        return any(self.sensitive_flags(text))

    def preserves_hidden_lines(self, source: str, updated: str,
                               spans: list[tuple[int, int]], replacement: str) -> bool:
        """Map original hidden lines through the actual edit, not by content.

        A hidden line must remain byte-identical, be a complete line at its
        mapped offset, and still be classified hidden. Equal counts or an
        identical hidden line elsewhere cannot substitute for its provenance.
        Offsets are UTF-8-decoded character offsets, with BOM/CRLF retained.
        """
        previous_end = 0
        for left, right in spans:
            if not 0 <= previous_end <= left < right <= len(source):
                return False
            previous_end = right
        updated_lines: dict[int, tuple[int, str, bool]] = {}
        offset = 0
        for line, hidden in zip(updated.splitlines(keepends=True), self.sensitive_flags(updated)):
            end = offset + len(line)
            updated_lines[offset] = (end, line, hidden)
            offset = end

        offset = displacement = edit_index = 0
        for line, hidden in zip(source.splitlines(keepends=True), self.sensitive_flags(source)):
            end = offset + len(line)
            if hidden:
                while edit_index < len(spans) and spans[edit_index][1] <= offset:
                    left, right = spans[edit_index]
                    displacement += len(replacement) - (right - left)
                    edit_index += 1
                if edit_index < len(spans) and spans[edit_index][0] < end:
                    return False
                expected = (end + displacement, line, True)
                if updated_lines.get(offset + displacement) != expected:
                    return False
            offset = end
        return True

    def new_sensitive_content(self, old: str, new: str) -> bool:
        """Reject newly classified lines, including additional identical ones.

        This multiplicity check is separate from preserves_hidden_lines;
        it does not by itself establish original hidden-line preservation.
        """
        from collections import Counter
        old_hidden = Counter(line for line, hidden in zip(old.splitlines(), self.sensitive_flags(old)) if hidden)
        new_hidden = Counter(line for line, hidden in zip(new.splitlines(), self.sensitive_flags(new)) if hidden)
        return bool(new_hidden - old_hidden)

    def safe_text(self, text: str) -> str:
        return '\n'.join(self.redact_lines(text)[0])
