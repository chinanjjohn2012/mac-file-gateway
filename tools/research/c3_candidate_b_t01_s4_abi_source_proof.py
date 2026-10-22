"""B03-T01 S4 PARTIAL: read-only Adapter AST + Python/C ABI layout, NO LOAD.

C11 _Static_assert compilation comes only from the frozen reviewed ABI test
translation unit. Python ctypes.Structure instances describe *data layout*
only; no candidate library is opened, linked, imported or invoked. The
reviewed SourceOnlyAdapter is parsed as AST, NEVER imported in this module.
None of these observations is an authoritative S4 FFI or S5 loader gate.
"""
from __future__ import annotations

import ast
import ctypes
import hashlib
import json
from pathlib import Path
import re

import c3_candidate_b_t01_s0_abi_proof as s0

ROOT = s0.ROOT
HEADER = s0.HEADER
ABI_C = s0.ABI_C
SOURCE_ONLY = s0.SOURCE_ONLY
PARENT_S3_HEAD = "9c0bb5b0e83a3d5e57bacd2d55eaff174cb9c8fc"
PARENT_S3_TREE = "ad13b6a5a362874f50dc7ad70778b55c48f7f5c8"
NO_LOAD_ADMISSION = "REVIEW_REQUIRED_NO_LOAD"

# Only uninstantiated, data-only Python type layouts. NO CDLL/PyDLL/dlopen.
class Deadline(ctypes.Structure):
    _fields_ = [
        ("t0_ms", ctypes.c_int64),
        ("outer_budget_ms", ctypes.c_int64),
        ("cleanup_reserve_ms", ctypes.c_int64),
        ("term_grace_ms", ctypes.c_int64),
        ("kill_entry_margin_ms", ctypes.c_int64),
        ("outer_deadline_ms", ctypes.c_int64),
        ("term_cutoff_ms", ctypes.c_int64),
        ("kill_cutoff_ms", ctypes.c_int64),
    ]


class MockInput(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("mode", ctypes.c_uint32),         # reviewed enum, 4-byte C11
        ("phase", ctypes.c_uint32),        # reviewed enum, 4-byte C11
        ("scenario_nonce", ctypes.c_uint64),
        ("scenario_fault_id", ctypes.c_uint32),
        ("attempt_sequence_len", ctypes.c_uint32),
        ("attempt_sequence", ctypes.c_uint32 * 3),
        ("term_fact_mask", ctypes.c_uint64),
        ("kill_fact_mask", ctypes.c_uint64),
        ("now_ms", ctypes.c_int64),
        ("term_sent_at_ms", ctypes.c_int64),
        ("original_policy", Deadline),
        ("attempt_policy", Deadline),
    ]


class MockOutput(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("decision", ctypes.c_uint32),     # reviewed enum, 4-byte C11
        ("scenario_nonce", ctypes.c_uint64),
        ("fake_term_transport_calls", ctypes.c_uint32),
        ("fake_kill_transport_calls", ctypes.c_uint32),
        ("real_group_signal_syscalls", ctypes.c_uint32),
        ("term_attempts", ctypes.c_uint32),
        ("kill_attempts", ctypes.c_uint32),
        ("signals_closed", ctypes.c_uint32),
        ("group_signals_after_close", ctypes.c_uint32),
    ]


TYPES = {
    "uint32_t": ctypes.c_uint32, "uint64_t": ctypes.c_uint64,
    "int64_t": ctypes.c_int64,
    "c3b03_t01_mode_t": ctypes.c_uint32,
    "c3b03_t01_phase_t": ctypes.c_uint32,
    "c3b03_t01_admission_t": ctypes.c_uint32,
    "c3b03_t01_deadline_t": Deadline,
    "c3b03_t01_mock_input_t": MockInput,
    "c3b03_t01_mock_output_t": MockOutput,
}
STRUCTS = {
    "c3b03_t01_deadline_t": Deadline,
    "c3b03_t01_mock_input_t": MockInput,
    "c3b03_t01_mock_output_t": MockOutput,
}
POLICY_FIELDS = tuple(x for x, _ in Deadline._fields_)
BINDING_FIELDS = (
    "scenario_id", "phase_enum", "nonce", "attempt_steps",
    "original_deadline", "attempt_deadline", "now_ms", "term_sent_at_ms",
)


def _byte_sha(path: Path) -> str:
    return s0._sha_regular(path)[0]


def _literal_assignment(tree: ast.Module, key: str) -> object:
    nodes = [
        stmt for stmt in tree.body if isinstance(stmt, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == key
                for target in stmt.targets)
    ]
    if len(nodes) != 1:
        raise ValueError("UNREVIEWED_ADAPTER_ASSIGNMENT:" + key)
    value = nodes[0].value
    if key == "REQUEST_FIELDS":
        if not (isinstance(value, ast.Call) and
                isinstance(value.func, ast.Name) and
                value.func.id == "frozenset" and len(value.args) == 1
                and not value.keywords):
            raise ValueError("UNREVIEWED_REQUEST_FIELDS")
        return frozenset(ast.literal_eval(value.args[0]))
    return ast.literal_eval(value)


def _static_adapter_graph(source: str) -> dict[str, object]:
    """Exact limited AST observation of REVIEW-ONLY adapter, no import/execution."""
    tree = ast.parse(source, filename="<reviewed-source-only-adapter>")
    imports: set[str] = set()
    unsafe_calls = {"__import__", "eval", "exec", "compile", "open",
                    "getattr", "setattr", "delattr"}
    unsafe_attrs = {"CDLL", "PyDLL", "WinDLL", "dlopen", "kill", "killpg",
                    "Popen", "system", "popen", "dlsym"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(item.name.split(".")[0] for item in node.names)
        if isinstance(node, ast.ImportFrom):
            if node.level:
                raise ValueError("ADAPTER_RELATIVE_IMPORT")
            imports.add((node.module or "").split(".")[0])
        if isinstance(node, ast.Call) and (
            (isinstance(node.func, ast.Name) and
             node.func.id in unsafe_calls) or
            (isinstance(node.func, ast.Attribute) and
             node.func.attr in unsafe_attrs)
        ):
            raise ValueError("UNREVIEWED_ADAPTER_CALL")
    if imports != {"__future__", "dataclasses"}:
        raise ValueError("UNREVIEWED_ADAPTER_IMPORTS")
    expected = {
        "REVIEW_ONLY_NO_LOAD": True, "GROUP_SIGNAL_AUTHORIZED": False,
        "C_DISPATCH_IMPLEMENTED": False, "ABI_VERSION": 1,
    }
    if any(_literal_assignment(tree, key) != value
           for key, value in expected.items()):
        raise ValueError("ADAPTER_RUNTIME_AUTHORITY_CHANGED")
    policy = _literal_assignment(tree, "POLICY_FIELD_ORDER")
    if tuple(policy) != POLICY_FIELDS:
        raise ValueError("ADAPTER_POLICY_ABI_FIELD_ORDER")
    request = _literal_assignment(tree, "REQUEST_FIELDS")
    if request != frozenset({
        "abi_version", "mode", "fixture_target", "phase", "fault",
        "nonce", "original_policy", "attempt_policy", "now_ms",
        "term_sent_at_ms", "mock_only", "attempt_sequence",
    }):
        raise ValueError("ADAPTER_REQUEST_SCHEMA_CHANGED")
    binding = [
        n for n in tree.body if isinstance(n, ast.ClassDef)
        and n.name == "SourceBindingPlan"
    ]
    if len(binding) != 1:
        raise ValueError("ADAPTER_SOURCE_BINDING_MISSING")
    fields = tuple(n.target.id for n in binding[0].body
                   if isinstance(n, ast.AnnAssign)
                   and isinstance(n.target, ast.Name))
    if fields != BINDING_FIELDS:
        raise ValueError("ADAPTER_BINDING_FIELDS_CHANGED")
    call = [n for n in tree.body if isinstance(n, ast.FunctionDef)
            and n.name == "native_call"]
    if len(call) != 1:
        raise ValueError("ADAPTER_NATIVE_CALL_CHANGED")
    body = call[0].body
    if len(body) != 2 or not isinstance(body[0], ast.Expr) or not (
        isinstance(body[0].value, ast.Constant) and
        isinstance(body[0].value.value, str)
    ):
        raise ValueError("ADAPTER_CALL_NOT_UNCONDITIONAL_DENY")
    raise_node = body[1]
    if not (isinstance(raise_node, ast.Raise)
            and isinstance(raise_node.exc, ast.Call)
            and isinstance(raise_node.exc.func, ast.Name)
            and raise_node.exc.func.id == "RuntimeError"
            and len(raise_node.exc.args) == 1
            and isinstance(raise_node.exc.args[0], ast.Constant)
            and type(raise_node.exc.args[0].value) is str
            and raise_node.exc.args[0].value.startswith(
                "SOURCE_ONLY_NO_C_LOAD:")):
        raise ValueError("ADAPTER_CALL_NOT_UNCONDITIONAL_DENY")
    return {
        "direct_import_roots": tuple(sorted(imports)),
        "policy_fields": policy, "request_fields": tuple(sorted(request)),
        "binding_fields": fields,
        "native_call_always_denies": True,
        "transitive_stdlib_import_closure_proven": False,
        "future_ffi_adapter_import_graph_proven": False,
    }


def _header_fields(header: str) -> dict[str, tuple[str, ...]]:
    """Parse only the frozen, finite three C struct field lists, not generic C."""
    clean = re.sub(r"/\*[\s\S]*?\*/", "", header)
    chunks = re.findall(
        r"typedef\s+struct\s*\{([\s\S]*?)\}\s*(c3b03_t01_\w+_t)\s*;",
        clean,
    )
    result: dict[str, tuple[str, ...]] = {}
    if len(chunks) != len(STRUCTS):
        raise ValueError("UNREVIEWED_C_STRUCT_COUNT")
    field_re = re.compile(
        r"^\s*(int64_t|uint64_t|uint32_t|c3b03_t01_\w+_t)"
        r"\s+([a-z]\w*)(?:\[(\d+)\])?\s*;\s*$"
    )
    for body, name in chunks:
        if name not in STRUCTS or name in result:
            raise ValueError("UNREVIEWED_C_STRUCT")
        fields = []
        expected_types = dict(STRUCTS[name]._fields_)
        for line in body.splitlines():
            if not line.strip():
                continue
            m = field_re.fullmatch(line)
            if not m:
                raise ValueError("UNREVIEWED_C_FIELD_SYNTAX")
            c_type, field, length = m.groups()
            fields.append(field)
            declared = TYPES.get(c_type)
            actual_type = expected_types.get(field)
            if declared is None or actual_type is None:
                raise ValueError("UNREVIEWED_C_FIELD_TYPE")
            if length is not None:
                if (name, field, length) != (
                    "c3b03_t01_mock_input_t", "attempt_sequence", "3",
                ) or not issubclass(actual_type, ctypes.Array) or (
                    actual_type._type_ is not declared or
                    actual_type._length_ != int(length)
                ):
                    raise ValueError("UNREVIEWED_C_ARRAY")
            elif actual_type is not declared:
                raise ValueError("PYTHON_C_FIELD_TYPE_MISMATCH")
        actual = tuple(field for field, _ in STRUCTS[name]._fields_)
        if tuple(fields) != actual:
            raise ValueError("PYTHON_C_FIELD_ORDER_MISMATCH:" + name)
        result[name] = tuple(fields)
    return result


def _verify_existing_c_assertions(source: str) -> dict[str, object]:
    """Compare every frozen C11 assert with observed Python data layout."""
    statements = re.findall(
        r"^CHECK_(SIZE|ALIGN|OFF|FIELD_SIZE)\(([^)\n]+)\);$",
        source, re.M,
    )
    if len(statements) < 60:
        raise ValueError("INCOMPLETE_C_ABI_ASSERTIONS")
    seen: set[tuple[str, ...]] = set()
    count = {"SIZE": 0, "ALIGN": 0, "OFF": 0, "FIELD_SIZE": 0}
    covered_off: set[tuple[str, str]] = set()
    covered_sizes: set[tuple[str, str]] = set()
    for macro, args in statements:
        parts = tuple(p.strip() for p in args.split(","))
        key = (macro, *parts)
        if key in seen:
            raise ValueError("DUPLICATE_C_ABI_ASSERTION")
        seen.add(key)
        if (macro in ("SIZE", "ALIGN") and len(parts) != 2) or (
            macro in ("OFF", "FIELD_SIZE") and len(parts) != 3
        ):
            raise ValueError("BAD_C_ABI_ASSERTION")
        try:
            typ = TYPES[parts[0]]
            expected = int(parts[-1])
        except (KeyError, ValueError) as exc:
            raise ValueError("UNKNOWN_C_ABI_ASSERTION") from exc
        if macro == "SIZE":
            actual = ctypes.sizeof(typ)
        elif macro == "ALIGN":
            actual = ctypes.alignment(typ)
        else:
            cfield = parts[1]
            if parts[0] not in STRUCTS:
                raise ValueError("UNREVIEWED_C_FIELD_TYPE")
            fields = dict(STRUCTS[parts[0]]._fields_)
            if cfield not in fields:
                raise ValueError("UNKNOWN_C_ABI_FIELD")
            actual = (getattr(typ, cfield).offset if macro == "OFF"
                      else ctypes.sizeof(fields[cfield]))
            (covered_off if macro == "OFF" else covered_sizes).add(
                (parts[0], cfield))
        if actual != expected:
            raise ValueError("PYTHON_C_ABI_LAYOUT_MISMATCH:" +
                             "/".join(parts))
        count[macro] += 1
    full = {(name, field) for name, typ in STRUCTS.items()
            for field, _ctype in typ._fields_}
    if covered_off != full or covered_sizes != full:
        raise ValueError("INCOMPLETE_C_ABI_FIELD_COVERAGE")
    if set(STRUCTS) != {name for name in TYPES if name in STRUCTS}:
        raise ValueError("UNKNOWN_C_ABI_STRUCT")
    return {"assertion_counts": count, "field_count": len(full),
            "sizes": {name: ctypes.sizeof(typ) for name, typ in TYPES.items()},
            "alignments": {name: ctypes.alignment(typ)
                           for name, typ in TYPES.items()},
            "field_offsets": {
                name: {field: getattr(typ, field).offset
                       for field, _ in typ._fields_}
                for name, typ in STRUCTS.items()
            }}


def collect_static_s4_evidence() -> dict[str, object]:
    """Static C11 compile + Python data-only layout; SourceOnly AST, NO C call."""
    manifest = s0.checked_manifest()
    head, tree = s0.current_revision()
    hashes_before = {key: _byte_sha(path) for key, path in (
        ("adapter", SOURCE_ONLY), ("header", HEADER), ("abi", ABI_C),
        ("candidate_source", s0.SOURCE),
    )}
    graph = _static_adapter_graph(SOURCE_ONLY.read_text(encoding="utf-8"))
    structs = _header_fields(HEADER.read_text(encoding="utf-8"))
    layout = _verify_existing_c_assertions(ABI_C.read_text(encoding="utf-8"))
    compiler = s0._compile_abi_once()
    if compiler["compiler_returncode"] != 0 or not (
        compiler["entry_hashed_before_compiler_spawn"]
    ) or not compiler["abi_object_sha256"]:
        raise ValueError("FROZEN_C11_ABI_ASSERT_COMPILE_FAILED")
    if compiler["compiler_entry_sha256_precompile"] != (
        compiler["compiler_entry_sha256_postcompile"]
    ):
        raise ValueError("ABI_COMPILER_ENTRY_DRIFT")
    if any(_byte_sha(path) != hashes_before[key] for key, path in (
        ("adapter", SOURCE_ONLY), ("header", HEADER), ("abi", ABI_C),
        ("candidate_source", s0.SOURCE),
    )):
        raise ValueError("S4_REVIEW_INPUT_CHANGED")
    for key, path in (("adapter", SOURCE_ONLY), ("header", HEADER),
                      ("abi", ABI_C), ("candidate_source", s0.SOURCE)):
        if manifest["./" + path.relative_to(ROOT).as_posix()] != (
            hashes_before[key]
        ):
            raise ValueError("S4_MANIFEST_DRIFT")
    layout_sha = hashlib.sha256(json.dumps(
        layout, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    graph_sha = hashlib.sha256(json.dumps(
        graph, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    return {
        "head": head, "tree": tree,
        "reviewed_s3_parent_head": PARENT_S3_HEAD,
        "reviewed_s3_parent_tree": PARENT_S3_TREE,
        "manifest_sha256": _byte_sha(s0.MANIFEST),
        "reviewed_inputs": hashes_before,
        "real_compiler_entry_sha256_precompile":
            compiler["compiler_entry_sha256_precompile"],
        "real_compiler_entry_sha256_postcompile":
            compiler["compiler_entry_sha256_postcompile"],
        "abi_assertion_object_sha256": compiler["abi_object_sha256"],
        "header_struct_fields": structs,
        "layout": layout,
        "layout_sha256": layout_sha,
        "adapter_source_graph": graph,
        "adapter_source_graph_sha256": graph_sha,
        "real_c11_abi_assertions_compiled_only": True,
        "python_ctypes_data_layout_only": True,
        "candidate_c_compiled": False,
        "candidate_c_executed": False,
        "native_candidate_library_linked": False,
        "native_candidate_library_loaded": False,
        "native_adapter_imported": False,
        "native_dispatches": 0,
        "complete_toolchain_sdk_closure_proven": False,
        "complete_python_ffi_import_graph_proven": False,
        "actual_python_to_c_call_binding_proven": False,
        "loader_inode_custody_proven": False,
        "first_c_load_authorized": False,
        "group_kill_authorized": False,
        "reuse_proven": False, "g2_qualified": False,
        "admission": NO_LOAD_ADMISSION,
    }
