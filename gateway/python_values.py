"""Bounded, value-oriented classification for Python source files.

Only source bytes and syntax are inspected; scanned project code is never
imported, evaluated or called. Non-Python classification is intentionally
outside this module.
"""
from __future__ import annotations

import ast
import io
import re
import textwrap
import time
import tokenize
from typing import Callable, Pattern


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

    Subscript selectors are lookup keys/indices, not credential values.
    Literal-bearing containers and other value expressions remain evidence.
    Dynamic calls with no value literal are not secret evidence.
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
    if isinstance(node, ast.Subscript):
        # Inspect the value source, not the selector. This still protects
        # ['literal-secret'][0] and 'literal-secret'[:], while a runtime
        # records['token'] lookup contains no credential-value literal.
        # Independent signature scanning still covers every source literal.
        return _value_literal(node.value, depth + 1)
    return any(_value_literal(child, depth + 1) for child in ast.iter_child_nodes(node))


def _env_reference_name(node: ast.AST) -> str | None:
    if not _env_key_reference(node):
        return None
    if isinstance(node, ast.Subscript):
        return node.slice.value
    assert isinstance(node, ast.Call)
    return node.args[0].value


class _StaticBindings:
    """Conservatively trace literal origins for a Bearer runtime reference.

    Only source syntax is inspected. Unknown runtime values remain unknown;
    no source code is imported, executed, or evaluated.
    """

    def __init__(self, tree: ast.Module, deadline: float):
        self.tree = tree
        self.deadline = deadline
        self.parents: dict[ast.AST, ast.AST] = {}
        self.scopes: dict[ast.AST, ast.AST] = {}
        self.local_names: set[tuple[ast.AST, str]] = set()
        self.global_names: dict[ast.AST, set[str]] = {}
        self.nonlocal_names: dict[ast.AST, set[str]] = {}
        self.uncertain: dict[tuple[ast.AST, str], ast.AST] = {}
        self.env_wildcards: list[tuple[ast.AST, ast.AST]] = []
        self.env_aliases: set[str] = set()
        self.methods: dict[str, list[tuple[ast.AST, ast.AST]]] = {}
        self.functions: dict[str, list[ast.AST]] = {}
        self.definitions: dict[tuple[ast.AST, str, str], list[tuple[ast.AST, ast.AST]]] = {}
        for parent in ast.walk(tree):
            self._check()
            for child in ast.iter_child_nodes(parent):
                self.parents[child] = parent
        for node in ast.walk(tree):
            self._check()
            if isinstance(node, ast.Global):
                self.global_names.setdefault(self._scope(node), set()).update(node.names)
            elif isinstance(node, ast.Nonlocal):
                self.nonlocal_names.setdefault(self._scope(node), set()).update(node.names)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and node.value is not None and _attribute_chain(node.value) == ("os", "environ"):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                self.env_aliases.update(target.id for target in targets if isinstance(target, ast.Name))
        # Aliases are only used to make environment writes more conservative.
        changed = True
        while changed:
            self._check()
            old_size = len(self.env_aliases)
            for node in ast.walk(tree):
                self._check()
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and isinstance(node.value, ast.Name) and node.value.id in self.env_aliases:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    self.env_aliases.update(target.id for target in targets if isinstance(target, ast.Name))
            changed = len(self.env_aliases) != old_size
        for node in ast.walk(tree):
            self._check()
            scope = self._scope(node)
            if isinstance(node, ast.arg):
                self.local_names.add((scope, node.arg))
            elif isinstance(node, ast.Nonlocal):
                for name in node.names:
                    self.local_names.add((scope, name))
                    self.uncertain[(scope, name)] = node
            elif isinstance(node, ast.ExceptHandler) and node.name is not None:
                self.local_names.add((scope, node.name))
                self.uncertain[(scope, node.name)] = node
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                self._bind_target(scope, node.target, node.iter, node.iter)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr, ast.AugAssign)):
                value = node.value
                if value is not None:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        self._bind_target(scope, target, value, node)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                args = node.args
                if not isinstance(node, ast.Lambda):
                    self.functions.setdefault(node.name, []).append(node)
                positional = [*args.posonlyargs, *args.args]
                for param, default in zip(positional[len(positional) - len(args.defaults):], args.defaults):
                    self._record(node, "name", param.arg, default, default)
                for param, default in zip(args.kwonlyargs, args.kw_defaults):
                    if default is not None:
                        self._record(node, "name", param.arg, default, default)
            elif isinstance(node, ast.Return) and node.value is not None:
                if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._record(self._scope(scope), "name", scope.name, node.value, node)
                    self.methods.setdefault(scope.name, []).append((node.value, node))
            elif isinstance(node, ast.Call):
                chain = _attribute_chain(node.func)
                alias_method = (len(chain) == 2 and chain[0] in self.env_aliases) if chain else False
                if (chain in (("os", "putenv"), ("os", "environ", "__setitem__"),
                              ("os", "environ", "setdefault"))
                        or alias_method and chain[-1] in ("__setitem__", "setdefault")) and len(node.args) == 2:
                    key = node.args[0]
                    if isinstance(key, ast.Constant) and type(key.value) is str:
                        self._record(self.tree, "env", key.value, node.args[1], node)
                elif chain == ("os", "environ", "update") or alias_method and chain[-1] == "update":
                    for argument in node.args:
                        self._bind_env_mapping(argument, node)
                    for keyword in node.keywords:
                        if keyword.arg is not None:
                            self._record(self.tree, "env", keyword.arg, keyword.value, node)
                        else:
                            self._bind_env_mapping(keyword.value, node)
        # A call may occur before its definition; connect arguments after indexing.
        for node in ast.walk(tree):
            self._check()
            if not isinstance(node, ast.Call):
                continue
            name = node.func.id if isinstance(node.func, ast.Name) else (node.func.attr if isinstance(node.func, ast.Attribute) else None)
            for func in self.functions.get(name, ()):
                positional = [*func.args.posonlyargs, *func.args.args]
                if isinstance(node.func, ast.Attribute) and positional:
                    positional = positional[1:]
                for param, value in zip(positional, node.args):
                    self._record(func, "name", param.arg, value, node)
                if func.args.vararg is not None:
                    for value in node.args[len(positional):]:
                        self._record(func, "name", func.args.vararg.arg, value, node)
                for keyword in node.keywords:
                    if keyword.arg is not None:
                        self._record(func, "name", keyword.arg, keyword.value, node)
                        if func.args.kwarg is not None:
                            self._record(func, "name", func.args.kwarg.arg, keyword.value, node)
                    else:
                        for param in [*positional, *func.args.kwonlyargs]:
                            self._record(func, "name", param.arg, keyword.value, node)
                        if func.args.kwarg is not None:
                            self._record(func, "name", func.args.kwarg.arg, keyword.value, node)

    def _check(self) -> None:
        if time.monotonic() >= self.deadline:
            raise _ScanUnavailable

    def _scope(self, node: ast.AST) -> ast.AST:
        if node in self.scopes:
            return self.scopes[node]
        parent = self.parents.get(node)
        while parent is not None and not isinstance(parent, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            parent = self.parents.get(parent)
        result = parent or self.tree
        self.scopes[node] = result
        return result

    def _record(self, scope: ast.AST, kind: str, name: str,
                value: ast.AST, owner: ast.AST) -> None:
        if kind == "name":
            if name in self.global_names.get(scope, set()):
                scope = self.tree
            elif name in self.nonlocal_names.get(scope, set()):
                scope = self._scope(scope)
                while (scope, name) not in self.local_names and scope is not self.tree:
                    scope = self._scope(scope)
            self.local_names.add((scope, name))
        self.definitions.setdefault((scope, kind, name), []).append((value, owner))

    def _bind_target(self, scope: ast.AST, target: ast.AST, value: ast.AST, owner: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self._record(scope, "name", target.id, value, owner)
            if isinstance(self.parents.get(owner), ast.ClassDef):
                self._record(self.tree, "attribute", target.id, value, owner)
        elif isinstance(target, ast.Attribute) and _attribute_chain(target) == ("os", "environ"):
            self._bind_env_mapping(value, owner)
        elif isinstance(target, ast.Attribute):
            self._record(self.tree, "attribute", target.attr, value, owner)
        elif isinstance(target, ast.Subscript):
            env = _env_reference_name(target)
            if env is not None:
                self._record(self.tree, "env", env, value, owner)
            elif _attribute_chain(target.value) == ("os", "environ"):
                self.env_wildcards.append((value, owner))
            elif isinstance(target.value, ast.Name) and target.value.id in self.env_aliases:
                if isinstance(target.slice, ast.Constant) and type(target.slice.value) is str:
                    self._record(self.tree, "env", target.slice.value, value, owner)
                else:
                    self.env_wildcards.append((value, owner))
            elif isinstance(target.value, ast.Name):
                self._record(scope, "name", target.value.id, value, owner)
        elif isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, (ast.Tuple, ast.List)) and len(target.elts) == len(value.elts):
                for left, right in zip(target.elts, value.elts):
                    self._bind_target(scope, left, right, owner)
            else:
                for item in target.elts:
                    self._bind_target(scope, item, value, owner)
        elif isinstance(target, ast.Starred):
            self._bind_target(scope, target.value, value, owner)

    def _bind_env_mapping(self, mapping: ast.AST, owner: ast.AST) -> None:
        if isinstance(mapping, ast.Dict):
            for key, value in zip(mapping.keys, mapping.values):
                if isinstance(key, ast.Constant) and type(key.value) is str:
                    self._record(self.tree, "env", key.value, value, owner)
                else:
                    self.env_wildcards.append((value, owner))
        elif (isinstance(mapping, ast.Call) and isinstance(mapping.func, ast.Name)
              and mapping.func.id == "dict"):
            for keyword in mapping.keywords:
                if keyword.arg is not None:
                    self._record(self.tree, "env", keyword.arg, keyword.value, owner)
                else:
                    self.env_wildcards.append((keyword.value, owner))
        else:
            self.env_wildcards.append((mapping, owner))

    def _origins(self, node: ast.AST, scope: ast.AST,
                 seen: set[tuple[ast.AST, str, str]], depth: int = 0) -> set[ast.AST]:
        self._check()
        if depth > MAX_AST_DEPTH:
            raise _ScanUnavailable
        env = _env_reference_name(node)
        if env is not None:
            return self._resolve(self.tree, "env", env, seen, depth + 1)
        if isinstance(node, ast.Name):
            return self._resolve(scope, "name", node.id, seen, depth + 1)
        if isinstance(node, ast.Attribute):
            result = self._resolve(self.tree, "attribute", node.attr, seen, depth + 1)
            result.update(self._origins(node.value, scope, seen, depth + 1))
            return result
        if isinstance(node, ast.Constant):
            if (type(node.value) in (str, bytes) and bool(node.value)
                    or type(node.value) in (int, float, complex, bool)):
                return {node}
            return set()
        if isinstance(node, ast.IfExp):
            children = (node.body, node.orelse)
        elif isinstance(node, ast.Dict):
            children = node.values
        elif isinstance(node, ast.Subscript):
            children = (node.value,)
        elif isinstance(node, ast.Call):
            # A mapping lookup's first string is a key, not its returned value.
            if (isinstance(node.func, ast.Attribute) and node.func.attr == "get"
                    and node.args and isinstance(node.args[0], ast.Constant)
                    and type(node.args[0].value) is str):
                children = (node.func.value, *node.args[1:], *(x.value for x in node.keywords))
            elif isinstance(node.func, ast.Attribute):
                children = (*node.args, *(x.value for x in node.keywords))
            else:
                children = (node.func, *node.args, *(x.value for x in node.keywords))
        else:
            children = ast.iter_child_nodes(node)
        result: set[ast.AST] = set()
        for child in children:
            if child is not None:
                result.update(self._origins(child, scope, seen, depth + 1))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            for value, owner in self.methods.get(node.func.attr, ()):
                origins = self._origins(value, self._scope(owner), seen, depth + 1)
                if origins:
                    result.add(owner)
                    result.update(origins)
        return result

    def _resolve(self, scope: ast.AST, kind: str, name: str,
                 seen: set[tuple[ast.AST, str, str]], depth: int) -> set[ast.AST]:
        self._check()
        if depth > MAX_AST_DEPTH:
            raise _ScanUnavailable
        if kind == "name":
            if name in self.global_names.get(scope, set()):
                scope = self.tree
            else:
                while (scope, name) not in self.local_names and scope is not self.tree:
                    scope = self._scope(scope)
        key = (scope, kind, name)
        if key in seen:
            return set()
        seen.add(key)
        result: set[ast.AST] = set()
        try:
            uncertain = self.uncertain.get((scope, name)) if kind == "name" else None
            if uncertain is not None:
                result.add(uncertain)
            if kind == "name" and name in self.nonlocal_names.get(scope, set()):
                result.update(self._resolve(self._scope(scope), kind, name, seen, depth + 1))
            if kind == "env":
                for value, owner in self.env_wildcards:
                    origins = self._origins(value, self._scope(owner), seen, depth + 1)
                    if origins:
                        result.add(owner)
                        result.update(origins)
            for value, owner in self.definitions.get(key, ()):
                origins = self._origins(value, self._scope(owner), seen, depth + 1)
                if origins:
                    result.add(owner)
                    result.update(origins)
        finally:
            seen.remove(key)
        return result

    def origins(self, value: ast.AST, context: ast.AST) -> set[ast.AST]:
        return self._origins(value, self._scope(context), set())


def _credential_value_has_literal(field: str, node: ast.AST, depth: int = 0,
                                  runtime_allowed: Callable[[ast.AST], bool] | None = None) -> bool:
    """Exclude only the standard Bearer scheme prefix from dynamic auth values."""
    if depth > MAX_AST_DEPTH:
        raise _ScanUnavailable
    runtime_value: ast.AST | None = None
    if field.casefold() == "authorization":
        if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
                and isinstance(node.left, ast.Constant)
                and type(node.left.value) is str and node.left.value == "Bearer "):
            runtime_value = node.right
        elif (isinstance(node, ast.JoinedStr) and len(node.values) == 2
              and isinstance(node.values[0], ast.Constant)
              and type(node.values[0].value) is str and node.values[0].value == "Bearer "
              and isinstance(node.values[1], ast.FormattedValue)
              and node.values[1].conversion == -1 and node.values[1].format_spec is None):
            runtime_value = node.values[1].value
        if runtime_value is not None and runtime_allowed is not None and runtime_allowed(runtime_value):
            return False
    return _value_literal(node, depth + 1)


def _authorization_target(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id.casefold() == "authorization"
    if isinstance(node, ast.Attribute):
        return node.attr.casefold() == "authorization"
    if (isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant)
            and type(node.slice.value) is str):
        return node.slice.value.casefold() == "authorization"
    return False


def _assignment_value_has_literal(target: ast.AST, value: ast.AST, depth: int = 0,
                                  runtime_allowed: Callable[[ast.AST], bool] | None = None) -> bool:
    """Only literals actually bound to a credential target are Hard.

    Tuple/list destructuring must pair corresponding target and source
    positions. Literal values assigned to *unrelated* siblings are never
    evidence for a token/password target; dynamic RHS calls are not
    evaluated or guessed into a static tuple.
    """
    if depth > MAX_AST_DEPTH:
        raise _ScanUnavailable
    if isinstance(target, ast.Starred):
        return _assignment_value_has_literal(target.value, value, depth + 1, runtime_allowed)
    if isinstance(target, (ast.Tuple, ast.List)):
        if not isinstance(value, (ast.Tuple, ast.List)):
            # A single static str/bytes value can itself be unpacked, but
            # opaque runtime results (even with string arguments) cannot
            # associate one unrelated literal with a target position.
            return (isinstance(value, ast.Constant)
                    and type(value.value) in (str, bytes)
                    and bool(value.value) and _assignment_target(target))
        left = target.elts
        right = value.elts
        starred = [i for i, item in enumerate(left) if isinstance(item, ast.Starred)]
        if not starred and len(left) == len(right):
            return any(_assignment_value_has_literal(a, b, depth + 1, runtime_allowed)
                       for a, b in zip(left, right))
        if len(starred) == 1 and len(right) >= len(left) - 1:
            pivot = starred[0]
            suffix = len(left) - pivot - 1
            leading = any(_assignment_value_has_literal(a, b, depth + 1, runtime_allowed)
                          for a, b in zip(left[:pivot], right[:pivot]))
            trailing = any(_assignment_value_has_literal(a, b, depth + 1, runtime_allowed)
                           for a, b in zip(left[pivot + 1:],
                                           right[len(right) - suffix:]))
            middle = any(_assignment_value_has_literal(left[pivot], b, depth + 1, runtime_allowed)
                         for b in right[pivot:len(right) - suffix])
            return leading or trailing or middle
        # The source structure cannot be mapped, so do not infer a
        # credential solely from a string in some unrelated sibling.
        return False
    if _authorization_target(target):
        return _credential_value_has_literal("authorization", value, depth + 1, runtime_allowed)
    return _assignment_target(target) and _value_literal(value, depth + 1)


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


def _scan_tokens(text: str, deadline: float) -> tuple[list[tuple[int, str]], list[tuple[int, int]]]:
    """Tokenize the whole file, recording complete *logical statements*.

    A terminal SyntaxError in another statement must not discard an earlier
    multiline credential assignment. Only tokenization failure is a scanner
    integrity failure; tokens and comments use the same CR/LF line model.
    """
    comments: list[tuple[int, str]] = []
    statements: list[tuple[int, int]] = []
    start: int | None = None
    count = 0
    try:
        # The tokenizer must see CR-only lines just as ast.parse does.
        for item in tokenize.generate_tokens(io.StringIO(text, newline=None).readline):
            count += 1
            if count > MAX_TOKENS or (count % 256 == 0 and time.monotonic() >= deadline):
                raise _ScanUnavailable
            if item.type == tokenize.COMMENT:
                comments.append((item.start[0], item.string[1:]))
            if start is None and item.type not in (
                    tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT,
                    tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER):
                start = item.start[0]
            if item.type == tokenize.NEWLINE and start is not None:
                statements.append((start, item.end[0]))
                start = None
            if item.type == tokenize.ENDMARKER and start is not None:
                statements.append((start, item.start[0]))
                start = None
    except (tokenize.TokenError, IndentationError, UnicodeError, RecursionError, MemoryError):
        raise _ScanUnavailable from None
    return comments, statements

def _count_ast_nodes(tree: ast.Module, deadline: float) -> int:
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
    return count


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

    # Keep the optional legacy parameter for caller compatibility, but a
    # pathname match alone is never credential evidence in V1.
    del protected_expr

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
        if inside_pem or TOKEN_VALUE.search(line) or CREDENTIAL_URI.search(line):
            line_hard(number)
        if inside_pem and PRIVATE_KEY_END.search(line):
            inside_pem = False
        if number % 2048 == 0 and time.monotonic() >= deadline:
            return _unavailable(text)

    try:
        comments, statements = _scan_tokens(text, deadline)
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

        def scan_ast(parsed_tree: ast.Module, *, line_offset: int = 0,
                     allow_bearer_exception: bool = False) -> None:
            bindings: _StaticBindings | None = None
            for node in ast.walk(parsed_tree):
                def runtime_allowed(value: ast.AST) -> bool:
                    nonlocal bindings
                    if not allow_bearer_exception:
                        return False
                    if not isinstance(value, ast.Name) and _env_reference_name(value) is None:
                        return False
                    if bindings is None:
                        bindings = _StaticBindings(parsed_tree, deadline)
                    origins = bindings.origins(value, node)
                    if origins:
                        for origin in origins:
                            mark(origin, line_offset)
                        return False
                    return True

                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    if node.value is not None and any(
                            _assignment_value_has_literal(target, node.value, runtime_allowed=runtime_allowed)
                            for target in targets):
                        mark(node, line_offset)
                elif isinstance(node, ast.Dict):
                    for key, value in zip(node.keys, node.values):
                        if (isinstance(key, ast.Constant) and type(key.value) is str
                                and _field(key.value) and _credential_value_has_literal(key.value, value, runtime_allowed=runtime_allowed)):
                            mark(value, line_offset)
                            mark(key, line_offset)
                elif isinstance(node, ast.Call):
                    for keyword in node.keywords:
                        if keyword.arg is not None and _field(keyword.arg) and _credential_value_has_literal(keyword.arg, keyword.value, runtime_allowed=runtime_allowed):
                            mark(keyword.value, line_offset)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    args = node.args
                    positional = [*args.posonlyargs, *args.args]
                    for param, default in zip(positional[len(positional) - len(args.defaults):], args.defaults):
                        if _field(param.arg) and _credential_value_has_literal(param.arg, default, runtime_allowed=runtime_allowed):
                            mark(default, line_offset)
                    for param, default in zip(args.kwonlyargs, args.kw_defaults):
                        if default is not None and _field(param.arg) and _credential_value_has_literal(param.arg, default, runtime_allowed=runtime_allowed):
                            mark(default, line_offset)

                # A known token format is Hard independently of assignment
                # name, even if adjacent literals/Constant+Constant split it.
                if isinstance(node, (ast.Constant, ast.JoinedStr, ast.BinOp)):
                    joined = _joined_static_literal(node)
                    if joined is not None:
                        if type(joined) is bytes:
                            joined = joined.decode("ascii", errors="ignore")
                        if TOKEN_VALUE.search(joined):
                            mark(node, line_offset)
                if time.monotonic() >= deadline:
                    raise _ScanUnavailable

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

            scan_ast(tree, allow_bearer_exception=True)
        else:
            # Entire-module AST failed but tokenization succeeded. Recover
            # complete logical statements (including multiline RHS literals)
            # without executing source or treating a bare variable name as a
            # credential. The source line offset is carried into Hard flags.
            complete_lines = physical_lines(text, keepends=True)
            ast_budget = MAX_AST_NODES
            for index, (start_line, end_line) in enumerate(statements):
                if index % 128 == 0 and time.monotonic() >= deadline:
                    raise _ScanUnavailable
                if not 1 <= start_line <= end_line <= len(complete_lines):
                    raise _ScanUnavailable
                statement = "".join(complete_lines[start_line - 1:end_line])
                normalized = statement.replace("\r\n", "\n").replace("\r", "\n")
                fragment = textwrap.dedent(normalized)
                try:
                    recovered = ast.parse(fragment)
                except (SyntaxError, IndentationError):
                    recovered = None
                    # A function or class declaration may be valid in isolation
                    # apart from its missing body in this logical-statement
                    # slice. Adding an inert pass parses keyword/defaults.
                    if fragment.rstrip().endswith(":"):
                        try:
                            recovered = ast.parse(fragment + "\n    pass\n")
                        except (SyntaxError, IndentationError):
                            pass
                except (RecursionError, ValueError, MemoryError):
                    raise _ScanUnavailable from None
                if recovered is not None:
                    ast_budget -= _count_ast_nodes(recovered, deadline)
                    if ast_budget < 0:
                        raise _ScanUnavailable
                    # A malformed full module skips the ordinary docstring
                    # pass. Preserve explicit fields in recovered strings.
                    for recovered_node in recovered.body:
                        if (isinstance(recovered_node, ast.Expr)
                                and isinstance(recovered_node.value, ast.Constant)
                                and type(recovered_node.value.value) is str
                                and any(_lexical_field_cue(part) == "hard"
                                        for part in recovered_node.value.value.splitlines())):
                            mark(recovered_node, start_line - 1)
                    scan_ast(recovered, line_offset=start_line - 1)
                else:
                    # Preserve the prior bounded heuristic for an obviously
                    # incomplete quoted RHS. Ordinary name-only dynamic
                    # references still classify as none.
                    clue = _lexical_field_cue(fragment)
                    # A failed AST recovery supplies a statement-level cue,
                    # not an exact physical line. Preserve the entire bounded
                    # tokenizer span: marking only start_line can expose a
                    # literal on a later line through read/search/diff/edit.
                    if clue == "hard":
                        for source_line in range(start_line, end_line + 1):
                            line_hard(source_line)
                    elif clue == "heuristic":
                        heuristic.update(range(start_line, end_line + 1))
                    # If no lexical cue can safely relate a string token
                    # to a named credential field, fail the whole scan rather
                    # than silently accepting uninspected secret material.
                    if clue == "none" and any(_field(match.group("name"))
                                             for match in _FIELD_CUE.finditer(fragment)):
                        try:
                            has_string = any(
                                token.type == tokenize.STRING for token in
                                tokenize.generate_tokens(
                                    io.StringIO(fragment, newline=None).readline
                                )
                            )
                        except (tokenize.TokenError, IndentationError,
                                RecursionError, ValueError):
                            raise _ScanUnavailable from None
                        if has_string:
                            raise _ScanUnavailable
            # Comments were classified during the whole-file lexical pass.
            # No independent per-line RHS shortcut: it cannot understand
            # multiline assignments, dict key/value positions or env keys.

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
