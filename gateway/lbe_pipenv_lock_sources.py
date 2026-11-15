"""D4 nonexecuting Pipenv lock-to-installed-site source admission.

A pinned Pipfile.lock and a separately approved RECORD distribution list must
agree on exact locked package versions. Neither source can self-attest a wheel
publisher, import graph, selected interpreter, runner, or native permission.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
import stat
import tomllib


class D4PipenvLockDenied(ValueError):
    """Pipfile.lock is missing, mutable, ambiguous or mismatched to site."""


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_VERSION = re.compile(r"[0-9][A-Za-z0-9.+_-]{0,63}\Z")
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_ID = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
       "st_mode", "st_uid", "st_nlink")


@dataclass(frozen=True, slots=True)
class D4PipenvLockSourceObservation:
    lock_sha256: str
    locked_distributions: tuple[tuple[str, str], ...]
    selected_installed_distributions: tuple[tuple[str, str], ...]
    pipfile_sha256: str | None = None
    direct_pipfile_requirements_checked: bool = False
    status: str = "PINNED_LOCK_REQUIREMENTS_MATCH_SELECTED_SITE_NOT_IMPORT_PROOF"
    publisher_attested: bool = False
    actual_loaded_source_graph_proven: bool = False
    native_launch_allowed: bool = False


def _pairs_unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise D4PipenvLockDenied("duplicate Pipfile.lock JSON key")
        result[key] = value
    return result


def _lock_bytes(project_root: str, *, file_name: str = "Pipfile.lock") -> bytes:
    if file_name not in ("Pipfile", "Pipfile.lock"):
        raise D4PipenvLockDenied("unqualified project source file")
    if (type(project_root) is not str or not 2 <= len(project_root) <= 2048
            or not project_root.startswith("/") or "\\" in project_root
            or any(ord(c) < 33 or ord(c) >= 127 for c in project_root)):
        raise D4PipenvLockDenied("invalid absolute project source")
    parts = project_root[1:].split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise D4PipenvLockDenied("noncanonical project root")
    fd = os.open("/", _DIR)
    try:
        for part in parts:
            next_fd = os.open(part, _DIR, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        root = os.fstat(fd)
        if (not stat.S_ISDIR(root.st_mode) or root.st_uid != os.getuid()
                or root.st_mode & 0o022):
            raise D4PipenvLockDenied("Pipenv project root unqualified")
        leaf = os.open(file_name, _FILE, dir_fd=fd)
        try:
            before = os.fstat(leaf)
            if (not stat.S_ISREG(before.st_mode)
                    or before.st_uid != os.getuid()
                    or before.st_mode & 0o022 or before.st_nlink != 1
                    or not 0 < before.st_size <= 1024 * 1024):
                raise D4PipenvLockDenied("Pipenv lock inode unqualified")
            data = bytearray()
            while len(data) < before.st_size:
                chunk = os.read(leaf, min(65536, before.st_size - len(data)))
                if not chunk:
                    raise D4PipenvLockDenied("Pipenv lock truncated")
                data.extend(chunk)
            after = os.fstat(leaf)
            if tuple(getattr(before, k) for k in _ID) != tuple(
                    getattr(after, k) for k in _ID):
                raise D4PipenvLockDenied("Pipenv lock mutated during read")
            return bytes(data)
        finally:
            os.close(leaf)
    except OSError:
        raise D4PipenvLockDenied("Pipenv lock unavailable") from None
    finally:
        os.close(fd)


def _check_pipfile_intent(raw: bytes, lock: dict) -> None:
    """Compare selected direct user requirements with corresponding lock groups.

    This is intentionally limited to fixed simple version declarations; a
    Pipfile with URL, VCS, editable, extras, marker or index overrides is not
    qualified by the safe fixture. Installed transitive/seed packages remain
    separately selected by the real RECORD source inspector.
    """
    try:
        parsed = tomllib.loads(raw.decode("utf-8", "strict"))
    except (UnicodeError, ValueError, TypeError):
        raise D4PipenvLockDenied("unqualified Pipfile TOML") from None
    if type(parsed) is not dict:
        raise D4PipenvLockDenied("Pipfile source declaration missing")
    direct_count = 0
    for section, lock_section in (("packages", "default"),
                                  ("dev-packages", "develop")):
        members = parsed.get(section, {})
        if type(members) is not dict:
            raise D4PipenvLockDenied("Pipfile dependency section invalid")
        expected = lock.get(lock_section, {})
        if type(expected) is not dict:
            raise D4PipenvLockDenied("Pipenv lock section invalid")
        lock_by_name = {}
        for raw_name, spec in expected.items():
            if type(raw_name) is not str or type(spec) is not dict:
                raise D4PipenvLockDenied("Pipenv lock dependency invalid")
            name = re.sub(r"[-_.]+", "-", raw_name).lower()
            if name in lock_by_name:
                raise D4PipenvLockDenied("colliding lock dependency names")
            lock_by_name[name] = spec.get("version")
        seen = set()
        for raw_name, request in members.items():
            if type(raw_name) is not str:
                raise D4PipenvLockDenied("Pipfile package name invalid")
            name = re.sub(r"[-_.]+", "-", raw_name).lower()
            if _NAME.fullmatch(name) is None or name in seen:
                raise D4PipenvLockDenied("ambiguous Pipfile package name")
            seen.add(name)
            if type(request) is dict and set(request) == {"version"}:
                request = request["version"]
            if (type(request) is not str or
                    (request != "*" and
                     (not request.startswith("==") or
                      _VERSION.fullmatch(request[2:]) is None))):
                raise D4PipenvLockDenied("unqualified Pipfile direct package source")
            actual = lock_by_name.get(name)
            if (type(actual) is not str or not actual.startswith("==") or
                    (request != "*" and request != actual)):
                raise D4PipenvLockDenied("Pipfile direct dependency not locked")
            direct_count += 1
    if direct_count == 0:
        raise D4PipenvLockDenied("empty Pipfile cannot qualify locked site")


def inspect_d4_pipenv_lock_sources(
    *, project_root: str, expected_lock_sha256: str,
    expected_distributions: tuple[tuple[str, str], ...],
    expected_pipfile_sha256: str | None = None,
) -> D4PipenvLockSourceObservation:
    """Compare actual nofollow lock bytes against selected RECORD identities.

    An installed seed distribution absent from the project lock is allowed;
    all explicitly locked default/develop dependencies MUST be present in
    the independently selected RECORD list with matching exact versions.
    """
    if (type(expected_lock_sha256) is not str
            or _SHA.fullmatch(expected_lock_sha256) is None
            or expected_lock_sha256 == "0" * 64):
        raise D4PipenvLockDenied("missing pinned lock digest")
    if (type(expected_distributions) is not tuple
            or not 1 <= len(expected_distributions) <= 64
            or any(type(x) is not tuple or len(x) != 2
                   or type(x[0]) is not str or _NAME.fullmatch(x[0]) is None
                   or type(x[1]) is not str or _VERSION.fullmatch(x[1]) is None
                   for x in expected_distributions)
            or tuple(sorted(set(expected_distributions))) != expected_distributions):
        raise D4PipenvLockDenied("invalid independently selected site identities")
    raw = _lock_bytes(project_root)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected_lock_sha256:
        raise D4PipenvLockDenied("Pipenv lock digest differs from source candidate")
    try:
        lock = json.loads(raw.decode("utf-8", "strict"),
                          object_pairs_hook=_pairs_unique)
    except (UnicodeError, ValueError):
        raise D4PipenvLockDenied("invalid or ambiguous Pipfile.lock JSON") from None
    if type(lock) is not dict or type(lock.get("_meta")) is not dict:
        raise D4PipenvLockDenied("Pipfile.lock metadata missing")
    try:
        meta_sha = lock["_meta"]["hash"]["sha256"]
    except (KeyError, TypeError):
        raise D4PipenvLockDenied("Pipfile.lock metadata hash missing") from None
    if type(meta_sha) is not str or _SHA.fullmatch(meta_sha) is None:
        raise D4PipenvLockDenied("Pipfile.lock metadata hash unqualified")
    found: dict[str, str] = {}
    for section in ("default", "develop"):
        rows = lock.get(section, {})
        if type(rows) is not dict:
            raise D4PipenvLockDenied("Pipfile.lock dependency section invalid")
        for raw_name, spec in rows.items():
            if type(raw_name) is not str or type(spec) is not dict:
                raise D4PipenvLockDenied("Pipenv dependency entry invalid")
            name = re.sub(r"[-_.]+", "-", raw_name).lower()
            pinned = spec.get("version")
            if (_NAME.fullmatch(name) is None
                    or type(pinned) is not str or not pinned.startswith("==")
                    or _VERSION.fullmatch(pinned[2:]) is None
                    or set(spec) - {"version", "hashes"}):
                raise D4PipenvLockDenied("Pipenv dependency not an exact source pin")
            hashes = spec.get("hashes", ())
            if (type(hashes) not in (tuple, list)
                    or any(type(v) is not str or not v.startswith("sha256:")
                           or _SHA.fullmatch(v[7:]) is None for v in hashes)):
                raise D4PipenvLockDenied("Pipenv wheel hash declaration invalid")
            version = pinned[2:]
            if name in found and found[name] != version:
                raise D4PipenvLockDenied("conflicting Pipenv package versions")
            found[name] = version
    if not found or any((name, version) not in expected_distributions
                        for name, version in found.items()):
        raise D4PipenvLockDenied("Pipfile.lock dependencies mismatch installed site")
    pipfile_sha256 = None
    if expected_pipfile_sha256 is not None:
        if (type(expected_pipfile_sha256) is not str
                or _SHA.fullmatch(expected_pipfile_sha256) is None
                or expected_pipfile_sha256 == "0" * 64):
            raise D4PipenvLockDenied("unqualified selected Pipfile digest")
        pipfile = _lock_bytes(project_root, file_name="Pipfile")
        pipfile_sha256 = hashlib.sha256(pipfile).hexdigest()
        if pipfile_sha256 != expected_pipfile_sha256:
            raise D4PipenvLockDenied("Pipfile bytes differ from source selection")
        _check_pipfile_intent(pipfile, lock)
    return D4PipenvLockSourceObservation(
        lock_sha256=digest,
        locked_distributions=tuple(sorted(found.items())),
        selected_installed_distributions=expected_distributions,
        pipfile_sha256=pipfile_sha256,
        direct_pipfile_requirements_checked=pipfile_sha256 is not None,
    )
