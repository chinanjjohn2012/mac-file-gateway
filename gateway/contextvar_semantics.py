"""Bounded static proof for ContextVar restoration handles.

This module is executed only by a separately bounded Python worker. It never
imports or executes source code from the selected workspace.
"""
from __future__ import annotations

import ast


_TYPE_PARAMETER_CLASSES = tuple(
    getattr(ast, name) for name in ("TypeVar", "TypeVarTuple", "ParamSpec")
    if hasattr(ast, name)
)


def _touches_constructor_member(target: ast.AST) -> bool:
    """Detect writes/deletes to ContextVar itself or objects under it."""
    if isinstance(target, ast.Attribute):
        return target.attr == "ContextVar" or _touches_constructor_member(target.value)
    if isinstance(target, ast.Subscript):
        return _touches_constructor_member(target.value)
    return False


_IMPORT_REGISTRY_MEMBERS = frozenset({
    "modules", "meta_path", "path_hooks", "path_importer_cache",
})
# ImportFrom stores exported attribute names only in ast.alias.name, never
# in ast.Name or ast.Attribute nodes. A module namespace can therefore enter
# scope through an opaque alias without a visible x.__dict__ expression.
# Conservatively reject namespace mappings, including reexports from other
# modules, rather than trying to track an arbitrary alias chain.
_OPAQUE_MODULE_NAMESPACE_EXPORTS = frozenset({"__dict__", "__builtins__"})
_MODULE_PROVENANCE_MUTATIONS = frozenset({
    "__class__", "__getattribute__", "__getattr__",
    "__import__", "__spec__", "__loader__", "__path__", "__package__",
})
_DYNAMIC_IMPORT_OPERATIONS = frozenset({
    "import_module", "reload", "invalidate_caches",
})


def _has_unproven_import_identity(tree: ast.AST) -> bool:
    """Fail closed when source can affect module identity or import resolution.

    A stable import of contextvars does not prove its object remains the
    stdlib module. Module-type mutation, import-cache edits and import hooks
    make constructor provenance dynamic. Opaque registry aliases cannot be
    positively verified without executing source code.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            # Including Load catches cache = sys.modules as well as direct
            # sys.modules["contextvars"] = FakeModule().
            if node.attr in _IMPORT_REGISTRY_MEMBERS:
                return True
            if (isinstance(node.ctx, (ast.Store, ast.Del))
                    and node.attr in _MODULE_PROVENANCE_MUTATIONS):
                return True
            if node.attr in _DYNAMIC_IMPORT_OPERATIONS:
                return True
        elif isinstance(node, ast.ImportFrom):
            # "from contextvars import __dict__ as registry" must not earn
            # ContextVar provenance, even if registry is then passed through
            # other variables or modified via .update(), |=, or subscripts.
            # The same applies to opaque namespace exports from other
            # modules which static parsing cannot identify as unrelated.
            if any(alias.name in _OPAQUE_MODULE_NAMESPACE_EXPORTS
                   for alias in node.names):
                return True
            if node.level == 0 and node.module == "contextvars" and any(
                    alias.name in _MODULE_PROVENANCE_MUTATIONS
                    for alias in node.names):
                return True
            if node.level == 0 and node.module == "sys" and any(
                    alias.name in _IMPORT_REGISTRY_MEMBERS for alias in node.names):
                return True
            if node.level == 0 and node.module in ("importlib", "importlib.util") and any(
                    alias.name in _DYNAMIC_IMPORT_OPERATIONS for alias in node.names):
                return True
        elif isinstance(node, ast.Subscript):
            # The target of an opaque mapping may be a sys.modules alias.
            if (isinstance(node.ctx, (ast.Store, ast.Del))
                    and isinstance(node.slice, ast.Constant)
                    and node.slice.value == "contextvars"):
                return True
    return False


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
    if _TYPE_PARAMETER_CLASSES and isinstance(node, _TYPE_PARAMETER_CLASSES):
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
    # Import names are insufficient proof if the importing module object,
    # sys.modules cache, or an import hook can be changed in this file.
    if _has_unproven_import_identity(tree):
        return []
    # A module import can be stable while its ContextVar constructor member
    # is rebound. Attribute(Store/Del), including annotated/augmented
    # assignment and deletion, is invisible to ast.Name(Store/Del).
    # Reject the *whole* proof in this case, including direct constructor
    # imports which may have occurred after the reassignment.
    if any(
        isinstance(node, (ast.Attribute, ast.Subscript))
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and _touches_constructor_member(node)
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
