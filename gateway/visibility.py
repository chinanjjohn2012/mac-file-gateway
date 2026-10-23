"""Shared source visibility for file read, search, guarded edits and diffs.

All classification starts from the original UTF-8 text, not an API response.
The policy never replaces or alters committed source bytes.
"""
from __future__ import annotations

import re
from typing import Callable


def source_lines(text: str, canonical_path: str = '', *, keepends: bool = False) -> list[str]:
    """Same Python physical-line mapping for AST, display, search and edits.

    Legacy non-Python files deliberately keep the old splitlines behavior.
    """
    if canonical_path.endswith((".py", ".pyi")):
        from .python_values import physical_lines
        return physical_lines(text, keepends=keepends)
    return text.splitlines(keepends=keepends)


class SensitiveContentPolicy:
    def __init__(self, protected_paths: tuple[str, ...] = ()):
        # Kept for backwards-compatible callers only. A filesystem path in
        # source text is not a credential, even when its target is private.
        # Filesystem access restrictions are enforced by Gateway separately.
        del protected_paths


    def classify(self, canonical_path: str, raw: bytes) -> tuple[list[bool], tuple[tuple[int, str], ...]]:
        """Path-aware, full-document classification with conservative fallback."""
        if canonical_path.endswith((".py", ".pyi")):
            from .python_values import classify_python
            return classify_python(raw)
        from .core import CREDENTIAL_ASSIGNMENT, CREDENTIAL_URI, TOKEN_VALUE, PRIVATE_KEY_BEGIN
        text = raw.decode("utf-8-sig")
        flags = self.sensitive_flags(text)
        findings: list[tuple[int, str]] = []
        for i, line in enumerate(text.splitlines(), 1):
            if not flags[i - 1]:
                continue
            match = CREDENTIAL_ASSIGNMENT.search(line)
            value = match.group("value").strip() if match else ""
            literal = bool(re.search(
                r"(?i)\b(?:api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|"
                r"password|passwd|token|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
                r"authorization|database[_-]?url|client[_-]?key[_-]?data|"
                r"client[_-]?certificate[_-]?data|certificate[_-]?authority[_-]?data)\b"
                r"[\s\"']*(?::=|:|=)\s*[\"']",
                line,
            ))
            # Structured credential payloads (not ordinary Python local
            # variables) remain protected even if the value is unquoted.
            structured_secret = (
                not canonical_path.endswith((".py", ".pyi"))
                and bool(re.search(
                    r"(?i)\b(?:token|password|passwd|api[_-]?key|secret[_-]?key|client[_-]?secret|" 
                    r"access[_-]?token|refresh[_-]?token|"
                    r"client[_-]?key[_-]?data|client[_-]?certificate[_-]?data|"
                    r"certificate[_-]?authority[_-]?data)\b\s*:\s*\S",
                    line,
                ))
            )
            hard = (
                structured_secret
                or TOKEN_VALUE.search(line) is not None
                or CREDENTIAL_URI.search(line) is not None
                or PRIVATE_KEY_BEGIN.search(line) is not None
                or literal
            )
            findings.append((i, "hard" if hard else "heuristic"))
        return flags, tuple(findings)

    def full_flags(self, canonical_path: str, text: str) -> list[bool]:
        return self.classify(canonical_path, text.encode("utf-8"))[0]

    def sensitive_flags(self, text: str) -> list[bool]:
        from .core import _sensitive_line_flags
        return _sensitive_line_flags(text)

    def redact_lines(self, text: str, canonical_path: str = '') -> tuple[list[str], int]:
        flags = self.full_flags(canonical_path, text) if canonical_path else self.sensitive_flags(text)
        lines = source_lines(text, canonical_path)
        if len(flags) != len(lines):
            flags = [True] * len(lines)
        return (["[REDACTED] protected content" if flag else line
                 for line, flag in zip(lines, flags)], sum(flags))

    def redacted_diff_lines(self, text: str, canonical_path: str = '') -> list[str]:
        flags = self.full_flags(canonical_path, text) if canonical_path else self.sensitive_flags(text)
        lines = source_lines(text, canonical_path, keepends=True)
        if len(flags) != len(lines):
            flags = [True] * len(lines)
        result = []
        for line, hidden in zip(lines, flags):
            if hidden:
                terminator = '\r\n' if line.endswith('\r\n') else '\n' if line.endswith('\n') else '\r' if line.endswith('\r') else ''
                result.append('[REDACTED] protected content' + terminator)
            else:
                result.append(line)
        return result

    def visible_runs(self, text: str, canonical_path: str = '') -> list[tuple[int, int]]:
        """Return maximal contiguous visible regions by character offsets.

        Hidden content is NEVER queried for an old_text candidate. Queries
        straddling hidden lines cannot match. Lines ending in CRLF/BOM are
        left as-is; writer uses raw source when applying eligible matches.
        """
        flags = self.full_flags(canonical_path, text) if canonical_path else self.sensitive_flags(text)
        lines = source_lines(text, canonical_path, keepends=True)
        if len(flags) != len(lines):
            flags = [True] * len(lines)
        offset = 0
        start = None
        runs: list[tuple[int, int]] = []
        for line, hidden in zip(lines, flags):
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

    def visible_matches(self, source: str, old: str, canonical_path: str = '') -> list[tuple[int, int]]:
        matches: list[tuple[int, int]] = []
        if not old:
            return matches
        for left, right in self.visible_runs(source, canonical_path):
            offset = left
            while True:
                index = source.find(old, offset, right)
                if index < 0:
                    break
                matches.append((index, index + len(old)))
                offset = index + len(old)
        return matches

    def is_sensitive(self, text: str, canonical_path: str = '') -> bool:
        return any(self.full_flags(canonical_path, text) if canonical_path else self.sensitive_flags(text))

    def preserves_hidden_lines(self, source: str, updated: str,
                               spans: list[tuple[int, int]], replacement: str, canonical_path: str = '') -> bool:
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
        candidate_lines = source_lines(updated, canonical_path, keepends=True)
        candidate_flags = self.full_flags(canonical_path, updated) if canonical_path else self.sensitive_flags(updated)
        source_split = source_lines(source, canonical_path, keepends=True)
        source_flags = self.full_flags(canonical_path, source) if canonical_path else self.sensitive_flags(source)
        if len(candidate_lines) != len(candidate_flags) or len(source_split) != len(source_flags):
            return False
        for line, hidden in zip(candidate_lines, candidate_flags):
            end = offset + len(line)
            updated_lines[offset] = (end, line, hidden)
            offset = end

        offset = displacement = edit_index = 0
        for line, hidden in zip(source_split, source_flags):
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

    def new_sensitive_content(self, old: str, new: str, canonical_path: str = '') -> bool:
        """Reject newly classified lines, including additional identical ones.

        This multiplicity check is separate from preserves_hidden_lines;
        it does not by itself establish original hidden-line preservation.
        """
        from collections import Counter
        old_hidden = Counter(line for line, hidden in zip(source_lines(old, canonical_path), self.full_flags(canonical_path, old) if canonical_path else self.sensitive_flags(old)) if hidden)
        new_hidden = Counter(line for line, hidden in zip(source_lines(new, canonical_path), self.full_flags(canonical_path, new) if canonical_path else self.sensitive_flags(new)) if hidden)
        return bool(new_hidden - old_hidden)

    def safe_text(self, text: str) -> str:
        return '\n'.join(self.redact_lines(text)[0])
