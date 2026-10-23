"""Bounded, value-oriented classification for Python source files.

Only source bytes and syntax are inspected; scanned project code is never
imported, evaluated or called. Non-Python classification is intentionally
outside this module.
"""
from __future__ import annotations

import ast
import io
import re
import time
import tokenize
from typing import Pattern


MAX_SOURCE_BYTES = 1_048_576
MAX_PHYSICAL_LINES = 120_000
MAX_TOKENS = 200_000
MAX_AST_NODES = 150_000
MAX_AST_DEPTH = 512
MAX_LITERAL_CHARS = 1_048_576
MAX_SCAN_SECONDS = 3.0

_PHYSICAL_NEWLINE = re.compile(r"\r\n|\r|\n")


def physical_lines(text: str, *, keepends: bool = False) -> list[str]:
    """Source line model shared by Python AST, tokens and Gateway visibility.

    Python newlines are CRLF, CR or LF. Unicode NEL/LS/PS, vertical tab
    and form feed do NOT advance ast.lineno; str.splitlines() incorrectly
    counts them as extra lines. Preserve original bytes/characters.
    """
    if not text:
        return []
    result: list[str] = []
    begin = 0
    for match in _PHYSICAL_NEWLINE.finditer(text):
        result.append(text[begin:match.end()] if keepends else text[begin:match.start()])
        begin = match.end()
    if begin < len(text):
        result.append(text[begin:])
    return result


_CREDENTIAL_FIELDS = frozenset({
    "api_key", "access_key", "access_key_id", "secret_key", "client_secret",
    "password", "passwd", "token", "access_token", "refresh_token",
    "auth_token", "authorization", "database_url", "client_key_data",
    "client_certificate_data", "certificate_authority_data",
})

# The cue is recognized only when its named field and an actual literal
# are present; a word such as "password" never carries a finding alone.
_FIELD_CUE = re.compile(
    r"(?i)\b(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s*(?:=|:)\s*(?P<value>.+)"
)


class _ScanUnavailable(Exception):
    """Internal scanner-integrity failure; never return uninspected bytes."""


def _field(name: str) -> bool:
    return re.sub(r"_+", "_", name.casefold().replace("-", "_")) in _CREDENTIAL_FIELDS


def _assignment_target(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return _field(node.id)
    if isinstance(node, ast.Attribute):
        return _field(node.attr)
    if isinstance(node, ast.Subscript):
        return isinstance(node.slice, ast.Constant) and (
            type(node.slice.value) is str and _field(node.slice.value)
        )
    if isinstance(node, (ast.Tuple, ast.List)):
        return any(_assignment_target(child) for child in node.elts)
    return False


def _attribute_chain(node: ast.AST) -> tuple[str, ...] | None:
    names = []
    while isinstance(node, ast.Attribute):
        names.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    names.append(node.id)
    return tuple(reversed(names))


def _env_key_reference(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        chain = _attribute_chain(node.func)
        if chain not in (("os", "getenv"), ("os", "environ", "get")):
            return False
        return (bool(node.args) and len(node.args) == 1
                and not node.keywords and isinstance(node.args[0], ast.Constant)
                and type(node.args[0].value) is str)
    if isinstance(node, ast.Subscript):
        return (_attribute_chain(node.value) == ("os", "environ")
                and isinstance(node.slice, ast.Constant)
                and type(node.slice.value) is str)
    return False


def _value_literal(node: ast.AST, depth: int = 0) -> bool:
    """Is there a nonempty literal contributing to a credential field?

    Ignore ONLY the key position of the three syntactic os environment
    lookups. Dynamic calls with no value literal are not secret evidence.
    """
    if depth > MAX_AST_DEPTH:
        raise _ScanUnavailable
    if isinstance(node, ast.Constant):
        return type(node.value) in (str, bytes) and bool(node.value)
    if _env_key_reference(node):
        return False
    if isinstance(node, ast.Call):
        chain = _attribute_chain(node.func)
        if chain in (("os", "getenv"), ("os", "environ", "get")):
            if node.args and len(node.args) >= 1 and isinstance(node.args[0], ast.Constant) and type(node.args[0].value) is str:
                return (any(_value_literal(item, depth + 1) for item in node.args[1:])
                        or any(_value_literal(k.value, depth + 1) for k in node.keywords))
    if isinstance(node, ast.Subscript) and _attribute_chain(node.value) == ("os", "environ"):
        if isinstance(node.slice, ast.Constant) and type(node.slice.value) is str:
            return False
    return any(_value_literal(child, depth + 1) for child in ast.iter_child_nodes(node))


def _joined_static_literal(node: ast.AST, depth: int = 0) -> str | bytes | None:
    if depth > MAX_AST_DEPTH:
        raise _ScanUnavailable
    if isinstance(node, ast.Constant) and type(node.value) in (str, bytes):
        if len(node.value) > MAX_LITERAL_CHARS:
            raise _ScanUnavailable
        return node.value
    if isinstance(node, ast.JoinedStr):
        # A fully static f-string has the same source value as adjacent
        # string literals, even if no credential-named target is present.
        pieces = []
        size = 0
        for part in node.values:
            if not isinstance(part, ast.Constant) or type(part.value) is not str:
                return None
            size += len(part.value)
            if size > MAX_LITERAL_CHARS:
                raise _ScanUnavailable
            pieces.append(part.value)
        return "".join(pieces)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a = _joined_static_literal(node.left, depth + 1)
        b = _joined_static_literal(node.right, depth + 1)
        if a is None or b is None or type(a) is not type(b):
            return None
        if len(a) + len(b) > MAX_LITERAL_CHARS:
            raise _ScanUnavailable
        return a + b
    return None


def _literal_from_comment(rhs: str) -> str:
    """Classify a lexical comment/docstring field RHS without executing it."""
    # A simple valid expression can reuse AST literal syntax. A truncated
    # quote is an ambiguous cue, not permission to expose unknown material.
    try:
        expression = ast.parse(rhs, mode="eval").body
    except (SyntaxError, ValueError, RecursionError):
        # A docstring may end with the surrounding triple-quote delimiter
        # after an embedded field literal: password = "abc" """. Parse
        # just the FIRST value token, not the enclosing source delimiter.
        try:
            first = next(tokenize.generate_tokens(io.StringIO(rhs).readline))
            if first.type == tokenize.STRING:
                first_value = ast.parse(first.string, mode="eval").body
                if _value_literal(first_value):
                    return "hard"
        except (StopIteration, tokenize.TokenError, SyntaxError, ValueError,
                RecursionError, IndentationError):
            pass
        return "heuristic" if re.search(r"(?i)^\s*[rubf]*['\"]", rhs) else "none"
    return "hard" if _value_literal(expression) else "none"


def _lexical_field_cue(line: str) -> str:
    for match in _FIELD_CUE.finditer(line):
        if not _field(match.group("name")):
            continue
        # This is an explicit field/value pair in a lexical comment or
        # actual docstring, never an arbitrary variable mention.
        kind = _literal_from_comment(match.group("value").strip())
        if kind != "none":
            return kind
    return "none"


def _scan_tokens(text: str, deadline: float) -> tuple[list[tuple[int, str]], int]:
    comments: list[tuple[int, str]] = []
    count = 0
    try:
        for item in tokenize.generate_tokens(io.StringIO(text).readline):
            count += 1
            if count > MAX_TOKENS or (count % 256 == 0 and time.monotonic() >= deadline):
                raise _ScanUnavailable
            if item.type == tokenize.COMMENT:
                comments.append((item.start[0], item.string[1:]))
    except (tokenize.TokenError, IndentationError, UnicodeError, RecursionError, MemoryError):
        raise _ScanUnavailable from None
    return comments, count


def _count_ast_nodes(tree: ast.Module, deadline: float) -> None:
    stack = [(tree, 0)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > MAX_AST_NODES or depth > MAX_AST_DEPTH:
            raise _ScanUnavailable
        if count % 256 == 0 and time.monotonic() >= deadline:
            raise _ScanUnavailable
        stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))


def _unavailable(text: str) -> tuple[list[bool], tuple[tuple[int, str], ...]]:
    # One explicit file-level reason; flags redact all physical source lines.
    return [True] * max(1, len(physical_lines(text))), ((1, "scan_unavailable"),)


def classify_python(
    raw: bytes, protected_expr: Pattern[str] | None = None,
) -> tuple[list[bool], tuple[tuple[int, str], ...]]:
    """Classify one complete Python document, preserving source line numbers.

    Returns per-physical-line flags and (1-based line, severity) findings.
    A scan-integrity failure is represented only by the distinct sentinel
    kind "scan_unavailable", never ordinary heuristic classification.
    """
    from .core import CREDENTIAL_URI, PRIVATE_KEY_BEGIN, PRIVATE_KEY_END, TOKEN_VALUE

    try:
        text = raw.decode("utf-8-sig")
    except (UnicodeDecodeError, UnicodeError):
        return _unavailable("")
    if len(raw) > MAX_SOURCE_BYTES:
        return _unavailable(text)
    lines = physical_lines(text)
    if len(lines) > MAX_PHYSICAL_LINES:
        return _unavailable(text)
    deadline = time.monotonic() + MAX_SCAN_SECONDS
    hard: set[int] = set()
    heuristic: set[int] = set()

    def mark(node: ast.AST, offset: int = 0) -> None:
        first = getattr(node, "lineno", None)
        last = getattr(node, "end_lineno", first)
        if (type(first) is not int or type(last) is not int
                or not 1 <= first <= last
                or first + offset > len(lines) or last + offset > len(lines)):
            raise _ScanUnavailable
        hard.update(range(first + offset, last + offset + 1))

    def line_hard(line: int) -> None:
        if not 1 <= line <= len(lines):
            raise _ScanUnavailable
        hard.add(line)

    # Independent patterns are not dependent on Python variable names or
    # syntactic validity. Keep the original private-key multi-line behavior.
    inside_pem = False
    for number, line in enumerate(lines, 1):
        if PRIVATE_KEY_BEGIN.search(line):
            inside_pem = True
        if (inside_pem or TOKEN_VALUE.search(line) or CREDENTIAL_URI.search(line)
                or (protected_expr is not None and protected_expr.search(line))):
            line_hard(number)
        if inside_pem and PRIVATE_KEY_END.search(line):
            inside_pem = False
        if number % 2048 == 0 and time.monotonic() >= deadline:
            return _unavailable(text)

    try:
        comments, _ = _scan_tokens(text, deadline)
        for comment_index, (lineno, comment) in enumerate(comments):
            if comment_index % 128 == 0 and time.monotonic() >= deadline:
                raise _ScanUnavailable
            value = _lexical_field_cue(comment)
            if value == "hard":
                line_hard(lineno)
            elif value == "heuristic":
                heuristic.add(lineno)
        try:
            tree = ast.parse(text)
        except (SyntaxError, IndentationError):
            tree = None
        except (ValueError, RecursionError, MemoryError):
            raise _ScanUnavailable from None

        if tree is not None:
            _count_ast_nodes(tree, deadline)
            # Find docstrings by syntax: first statement in module/class/function
            # body. Incidental ordinary string literals remain ordinary.
            bodies = [tree.body]
            bodies.extend(
                node.body for node in ast.walk(tree)
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            )
            for body in bodies:
                if (body and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and type(body[0].value.value) is str):
                    # Docstring escaping can hide quoted values in the raw
                    # source representation. Use the safely parsed Constant
                    # value too, marking the whole original docstring span
                    # when the decoded text contains explicit credentials.
                    if any(_lexical_field_cue(part) == "hard"
                           for part in body[0].value.value.splitlines()):
                        mark(body[0])
                    first = max(1, body[0].lineno)
                    last = min(len(lines), body[0].end_lineno or first)
                    for lineno in range(first, last + 1):
                        if (lineno - first) % 128 == 0 and time.monotonic() >= deadline:
                            raise _ScanUnavailable
                        kind = _lexical_field_cue(lines[lineno - 1])
                        if kind == "hard":
                            line_hard(lineno)
                        elif kind == "heuristic":
                            heuristic.add(lineno)

            for node in ast.walk(tree):
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    if any(_assignment_target(target) for target in targets):
                        if node.value is not None and _value_literal(node.value):
                            mark(node)
                elif isinstance(node, ast.Dict):
                    for key, value in zip(node.keys, node.values):
                        if (isinstance(key, ast.Constant) and type(key.value) is str
                                and _field(key.value) and _value_literal(value)):
                            mark(value)
                            mark(key)
                elif isinstance(node, ast.Call):
                    for keyword in node.keywords:
                        if keyword.arg is not None and _field(keyword.arg) and _value_literal(keyword.value):
                            mark(keyword.value)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    args = node.args
                    positional = [*args.posonlyargs, *args.args]
                    for param, default in zip(positional[len(positional) - len(args.defaults):], args.defaults):
                        if _field(param.arg) and _value_literal(default):
                            mark(default)
                    for param, default in zip(args.kwonlyargs, args.kw_defaults):
                        if default is not None and _field(param.arg) and _value_literal(default):
                            mark(default)

                # A known token format is Hard independently of assignment
                # name, even if adjacent literals/Constant+Constant split it.
                if isinstance(node, (ast.Constant, ast.JoinedStr, ast.BinOp)):
                    joined = _joined_static_literal(node)
                    if joined is not None:
                        if type(joined) is bytes:
                            joined = joined.decode("ascii", errors="ignore")
                        if TOKEN_VALUE.search(joined):
                            mark(node)
                if time.monotonic() >= deadline:
                    raise _ScanUnavailable
        else:
            # Complete lexing despite an invalid Python parse: retain visible
            # known keys and obvious quoted field=value pairs. Never treat a
            # bare name with a dynamic RHS as credential evidence.
            for number, line in enumerate(lines, 1):
                if number % 128 == 0 and time.monotonic() >= deadline:
                    raise _ScanUnavailable
                value = _lexical_field_cue(line)
                if value == "hard":
                    line_hard(number)
                elif value == "heuristic":
                    heuristic.add(number)

        if time.monotonic() >= deadline:
            raise _ScanUnavailable
    except (_ScanUnavailable, RecursionError, MemoryError, ValueError):
        return _unavailable(text)

    flags = [False] * len(lines)
    findings: list[tuple[int, str]] = []
    for number in range(1, len(lines) + 1):
        if number in hard:
            flags[number - 1] = True
            findings.append((number, "hard"))
        elif number in heuristic:
            flags[number - 1] = True
            findings.append((number, "heuristic"))
    return flags, tuple(findings)
