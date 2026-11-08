"""Tracked R006 T1 orchestration harness; never a public execution API."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
import stat

from .core import GatewayError
from .lbe_r006_trusted_bootstrap import (
    D4TrustedBootstrapDenied, fetch_r006_trusted_bootstrap,
)

_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX = 12 * 1024 * 1024
_MARKER = "MFG_R006_REVIEWED_SOURCE_BUNDLE_V1"


class D4R006HarnessDenied(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class D4R006SourceBundle:
    workspace: str
    cwd: str
    argv: tuple[str, ...]
    timeout_seconds: int
    private_root: str
    provisioner_root: str
    staged_manifests: dict[str, tuple[tuple[str, str | None], ...]]
    venv_manifest: tuple[tuple[str, str | None], ...] | None
    expected_source_identities: dict[str, str]
    expected_venv_identity_sha256: str | None
    require_go_p007_stage_source: bool
    expected_venv_record_distributions: tuple[tuple[str, str], ...] | None
    bundle_sha256: str


def _pairs(items):
    out = {}
    for key, value in items:
        if type(key) is not str or key in out:
            raise D4R006HarnessDenied("duplicate/non-string source-bundle key")
        out[key] = value
    return out


def _sha(value, label):
    if type(value) is not str or _SHA64.fullmatch(value) is None:
        raise D4R006HarnessDenied("invalid " + label)
    return value


def _manifest(value, label):
    if type(value) is not list or not 1 <= len(value) <= 24000:
        raise D4R006HarnessDenied("invalid " + label + " manifest")
    result = []
    seen = set()
    for row in value:
        if (type(row) is not list or len(row) != 2
                or type(row[0]) is not str or not row[0]
                or row[0].startswith("/") or ".." in row[0].split("/")
                or "\x00" in row[0] or "\\" in row[0]
                or (row[1] is not None
                    and (type(row[1]) is not str
                         or _SHA64.fullmatch(row[1]) is None))):
            raise D4R006HarnessDenied("invalid " + label + " manifest row")
        key = (row[0], row[1])
        if key in seen:
            raise D4R006HarnessDenied("duplicate " + label + " manifest row")
        seen.add(key)
        result.append(key)
    return tuple(result)


def parse_r006_source_bundle(raw: bytes, expected_sha256: str):
    expected = _sha(expected_sha256, "bundle SHA256")
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX:
        raise D4R006HarnessDenied("source bundle missing/oversized")
    if hashlib.sha256(raw).hexdigest() != expected:
        raise D4R006HarnessDenied("source bundle SHA256 mismatch")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise D4R006HarnessDenied("source bundle JSON malformed") from None
    fields = {
        "marker", "workspace", "cwd", "argv", "timeout_seconds",
        "private_root", "provisioner_root", "staged_manifests",
        "venv_manifest", "expected_source_identities",
        "expected_venv_identity_sha256", "require_go_p007_stage_source",
        "expected_venv_record_distributions",
    }
    if type(data) is not dict or set(data) != fields or data["marker"] != _MARKER:
        raise D4R006HarnessDenied("source bundle schema mismatch")
    if (type(data["workspace"]) is not str
            or re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", data["workspace"]) is None):
        raise D4R006HarnessDenied("invalid workspace")
    cwd = data["cwd"]
    if (type(cwd) is not str or cwd not in {"py-direct","py-pipenv","go-project"}):
        raise D4R006HarnessDenied("invalid product cwd")
    argv = data["argv"]
    if (type(argv) is not list or not 1 <= len(argv) <= 16
            or any(type(x) is not str or not x or "\x00" in x for x in argv)):
        raise D4R006HarnessDenied("invalid argv")
    timeout = data["timeout_seconds"]
    if type(timeout) is not int or not 1 <= timeout <= 120:
        raise D4R006HarnessDenied("invalid timeout")
    roots = []
    for name in ("private_root","provisioner_root"):
        value = data[name]
        if (type(value) is not str or not value.startswith("/")
                or os.path.normpath(value) != value or value.endswith("/")):
            raise D4R006HarnessDenied("invalid " + name)
        roots.append(value)
    if roots[0] == roots[1]:
        raise D4R006HarnessDenied("source roots overlap")

    manifests = data["staged_manifests"]
    if type(manifests) is not dict or not manifests:
        raise D4R006HarnessDenied("staged manifests missing")
    checked = {}
    for kind, rows in manifests.items():
        if type(kind) is not str or kind not in {"bin","lib","go"}:
            raise D4R006HarnessDenied("invalid manifest kind")
        checked[kind] = _manifest(rows, kind)
    ids = data["expected_source_identities"]
    if type(ids) is not dict or set(ids) != set(checked):
        raise D4R006HarnessDenied("source identity kinds mismatch")
    checked_ids = {k:_sha(v, k+" identity") for k,v in ids.items()}
    venv = data["venv_manifest"]
    checked_venv = None if venv is None else _manifest(venv, "venv")
    venv_id = data["expected_venv_identity_sha256"]
    if venv_id is not None:
        venv_id = _sha(venv_id, "venv identity")
    p007 = data["require_go_p007_stage_source"]
    if type(p007) is not bool:
        raise D4R006HarnessDenied("invalid P007 flag")
    dists = data["expected_venv_record_distributions"]
    if dists is not None:
        if (type(dists) is not list
                or any(type(x) is not list or len(x) != 2
                       or any(type(y) is not str or not y for y in x)
                       for x in dists)):
            raise D4R006HarnessDenied("invalid venv distributions")
        dists = tuple((x[0],x[1]) for x in dists)

    if cwd == "go-project":
        good = set(checked)=={"go"} and checked_venv is None and venv_id is None and p007 and dists is None
    elif cwd == "py-pipenv":
        good = set(checked)=={"bin","lib"} and checked_venv is not None and venv_id is not None and not p007 and dists is not None
    else:
        good = set(checked)=={"bin","lib"} and checked_venv is None and venv_id is None and not p007 and dists is None
    if not good:
        raise D4R006HarnessDenied("source bundle role mismatch")

    return D4R006SourceBundle(
        data["workspace"], cwd, tuple(argv), timeout, roots[0], roots[1],
        checked, checked_venv, checked_ids, venv_id, p007, dists, expected)


def load_r006_source_bundle(path: str, expected_sha256: str):
    if type(path) is not str or not path.startswith("/"):
        raise D4R006HarnessDenied("invalid bundle path")
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o600
                or not 0 < st.st_size <= _MAX):
            raise D4R006HarnessDenied("unsafe source-bundle file")
        raw = os.read(fd, _MAX + 1)
        if len(raw) != st.st_size:
            raise D4R006HarnessDenied("source-bundle read mismatch")
        return parse_r006_source_bundle(raw, expected_sha256)
    except OSError:
        raise D4R006HarnessDenied("source bundle unavailable") from None
    finally:
        if fd >= 0:
            os.close(fd)


def prepare_and_install_r006_one_shot(
    service: object, bundle: D4R006SourceBundle, *,
    owner_comment_id: int, g05_receipt_path: str,
):
    """Prepare reviewed source + canonical authority, install; never execute."""
    from .workspaces import WorkspaceService
    if type(service) is not WorkspaceService or type(bundle) is not D4R006SourceBundle:
        raise D4R006HarnessDenied("untrusted harness inputs")
    try:
        prepared = service._prepare_d4_r006_private_attempt(
            bundle.workspace, bundle.cwd, list(bundle.argv),
            private_root=bundle.private_root,
            provisioner_root=bundle.provisioner_root,
            staged_manifests=bundle.staged_manifests,
            venv_manifest=bundle.venv_manifest,
            expected_source_identities=bundle.expected_source_identities,
            expected_venv_identity_sha256=bundle.expected_venv_identity_sha256,
            require_go_p007_stage_source=bundle.require_go_p007_stage_source,
            expected_venv_record_distributions=bundle.expected_venv_record_distributions,
            timeout_seconds=bundle.timeout_seconds)
        bootstrap = fetch_r006_trusted_bootstrap(
            owner_comment_id, g05_receipt_path)
        service._install_d4_r006_one_shot(prepared, bootstrap)
        return prepared
    except (GatewayError, D4TrustedBootstrapDenied):
        raise D4R006HarnessDenied(
            "R006 prepare/bootstrap/install refused") from None
