"""Bounded static proof for ContextVar restoration handles.

This module is executed only by a separately bounded Python worker. It never
imports or executes source code from the selected workspace.
"""
from __future__ import annotations

import ast
from collections import Counter


def proven_contextvar_lines(source: str) -> list[int]:
    """Return assignment line numbers with a conservative ContextVar proof."""
    tree = ast.parse(source)
    if sum(1 for _ in ast.walk(tree)) > 8192:
        return []
    # Reject dynamic namespace and reflection operations that defeat local
    # proof of stable module-level object identity.
    unsafe_calls = {"exec", "eval", "globals", "locals", "setattr", "delattr", "__import__"}
    if any(isinstance(n, ast.Call) and (
        isinstance(n.func, ast.Name) and n.func.id in unsafe_calls
        or isinstance(n.func, ast.Attribute) and n.func.attr in {"__setattr__", "__delattr__"}
    ) for n in ast.walk(tree)):
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

    def bindings(name: str) -> list[ast.AST]:
        result = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id == name:
                result.append(node)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name:
                result.append(node)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    target = alias.asname or alias.name.split(".")[0]
                    if target == name:
                        result.append(node)
            elif isinstance(node, ast.arg) and node.arg == name:
                result.append(node)
        return result

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
        locally_assigned = {n.id for n in subnodes
                            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))}
        locally_assigned.update(n.arg for n in subnodes if isinstance(n, ast.arg))
        if vars & locally_assigned:
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
                if sum(isinstance(n, ast.Name) and n.id == token_name
                       and isinstance(n.ctx, (ast.Store, ast.Del)) for n in subnodes) != 1:
                    continue
                if any(isinstance(n, ast.arg) and n.arg == token_name for n in subnodes):
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
