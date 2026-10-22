"""Bounded static proof for ContextVar restoration handles.

This module is executed only by a separately bounded Python worker. It never
imports or executes source code from the selected workspace.
"""
from __future__ import annotations

import ast


def _bound_names(node: ast.AST) -> tuple[str, ...]:
    """Names bound or deleted by explicit *and implicit* Python syntax.

    ast.Name(Store/Del) omits string-valued binders in patterns, except
    handlers, imports, function declarations and type parameters. A binding
    not accounted for here must never be treated as proof of stable identity.
    """
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return (node.id,)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return (node.name,)
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return tuple(alias.asname or alias.name.split(".")[0] for alias in node.names)
    if isinstance(node, ast.arg):
        return (node.arg,)
    if isinstance(node, (ast.MatchAs, ast.MatchStar)):
        return (node.name,) if node.name is not None else ()
    if isinstance(node, ast.MatchMapping):
        return (node.rest,) if node.rest is not None else ()
    if isinstance(node, ast.ExceptHandler):
        return (node.name,) if node.name is not None else ()
    # Python 3.12+ type parameter syntax introduces additional binders.
    type_parameter_types = tuple(
        getattr(ast, attr) for attr in ("TypeVar", "TypeVarTuple", "ParamSpec")
        if hasattr(ast, attr)
    )
    if type_parameter_types and isinstance(node, type_parameter_types):
        return (node.name,)
    return ()


def proven_contextvar_lines(source: str) -> list[int]:
    """Return assignment line numbers with a conservative ContextVar proof."""
    tree = ast.parse(source)
    if sum(1 for _ in ast.walk(tree)) > 8192:
        return []
    # Reject reflective namespace access even when a builtin is passed as a
    # first-class value (e.g. alias = globals), not only when called directly.
    # Module dictionaries and frame-global mappings can rebind the trusted
    # ContextVar object without creating another ast.Name(Store) node.
    # Unprovable binding stability must preserve heuristic redaction.
    reflective_names = frozenset({
        "exec", "eval", "compile", "globals", "locals", "vars",
        "getattr", "setattr", "delattr", "__import__", "__builtins__",
    })
    reflective_attributes = frozenset({
        "exec", "eval", "globals", "locals", "vars", "getattr",
        "setattr", "delattr", "__setattr__", "__delattr__",
        "__dict__", "f_globals", "f_locals",
    })
    if any(
        (isinstance(node, ast.Name) and node.id in reflective_names)
        or (isinstance(node, ast.Attribute) and node.attr in reflective_attributes)
        for node in ast.walk(tree)
    ):
        return []
    # A module import can be stable while its ContextVar constructor member
    # is rebound. Attribute(Store/Del), including annotated/augmented
    # assignment and deletion, is invisible to ast.Name(Store/Del).
    # Reject the *whole* proof in this case, including direct constructor
    # imports which may have occurred after the reassignment.
    if any(
        isinstance(node, ast.Attribute)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node.attr == "ContextVar"
        for node in ast.walk(tree)
    ):
        return []
    module_aliases: set[str] = set()
    constructor_aliases: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "contextvars":
                    module_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "contextvars" and node.level == 0:
            for alias in node.names:
                if alias.name == "ContextVar":
                    constructor_aliases.add(alias.asname or alias.name)
    if not module_aliases and not constructor_aliases:
        return []

    # Collect all name bindings once; this inventory is shared by global
    # import/constructor stability and local set/reset handle checks.
    binding_sites: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):
        for name in _bound_names(node):
            binding_sites.setdefault(name, []).append(node)

    def bindings(name: str) -> list[ast.AST]:
        return binding_sites.get(name, [])

    def constructor(expr: ast.AST) -> bool:
        if not isinstance(expr, ast.Call):
            return False
        func = expr.func
        if isinstance(func, ast.Name) and func.id in constructor_aliases:
            return True
        return (isinstance(func, ast.Attribute) and func.attr == "ContextVar"
                and isinstance(func.value, ast.Name) and func.value.id in module_aliases)

    stable_imports = {name for name in module_aliases | constructor_aliases if len(bindings(name)) == 1}
    vars: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or not constructor(node.value):
            continue
        func = node.value.func
        source_name = func.id if isinstance(func, ast.Name) else func.value.id
        if source_name not in stable_imports:
            continue
        if len(bindings(target.id)) == 1:
            vars.add(target.id)

    approved: list[int] = []
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Only uncomplicated function scopes, with no nested closures, globals,
        # name rebinding, or non-local declarations may earn an exemption.
        subnodes = list(ast.walk(function))
        if any(isinstance(n, (ast.Global, ast.Nonlocal)) for n in subnodes):
            continue
        local_bindings = [name for node in subnodes for name in _bound_names(node)]
        if vars & set(local_bindings):
            continue
        for candidate in subnodes:
            if not isinstance(candidate, ast.Try) or not candidate.finalbody:
                continue
            # Recognize immediate token assignment preceding a try/finally block.
            for block in (function.body, candidate.body):
                if candidate not in block:
                    continue
                position = block.index(candidate)
                if position < 1:
                    continue
                assign = block[position - 1]
                if not isinstance(assign, ast.Assign) or len(assign.targets) != 1:
                    continue
                target = assign.targets[0]
                if not isinstance(target, ast.Name):
                    continue
                token_name = target.id
                value = assign.value
                if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute):
                    continue
                func = value.func
                if func.attr != "set" or not isinstance(func.value, ast.Name) or func.value.id not in vars:
                    continue
                if any(isinstance(arg, (ast.Constant, ast.Starred)) for arg in value.args):
                    continue
                if value.keywords:
                    continue
                # No additional writes/deletes to handle in its function scope.
                if local_bindings.count(token_name) != 1:
                    continue
                # The cleanup must be a direct, unconditional reset call.
                if len(candidate.finalbody) != 1:
                    continue
                reset_statement = candidate.finalbody[0]
                if not isinstance(reset_statement, ast.Expr):
                    continue
                reset = reset_statement.value
                if not (isinstance(reset, ast.Call) and isinstance(reset.func, ast.Attribute)
                        and reset.func.attr == "reset" and isinstance(reset.func.value, ast.Name)
                        and reset.func.value.id == func.value.id and len(reset.args) == 1
                        and not reset.keywords and isinstance(reset.args[0], ast.Name)
                        and reset.args[0].id == token_name):
                    continue
                approved.append(assign.lineno)
    return sorted(set(approved))
