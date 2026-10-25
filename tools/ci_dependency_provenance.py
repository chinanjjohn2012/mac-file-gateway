#!/usr/bin/env python3
"""Attest exact CI wheel inputs and installed importable bytes (not a cross-run lock).

The wheel source is resolved after early G05.  Only files from a hashed local
wheelhouse may be installed.  The post-install and post-test checks bind the
actual installed package files and critical import roots to that same CI run.
A source-controlled platform lock fixes wheel bytes across runs, but these
checks do not attest publisher signatures or runner-toolchain provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as metadata
import importlib.util
import json
import os
import site
import sysconfig
from pathlib import Path
import re
import stat
import sys
import zipfile


class ProvenanceError(Exception):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def assert_regular(path: Path, label: str) -> None:
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode):
        raise ProvenanceError(f"{label}: file is not an actual regular file: {path}")


def wheel_snapshot(wheelhouse: Path) -> list[dict[str, str]]:
    if not wheelhouse.is_dir() or wheelhouse.is_symlink():
        raise ProvenanceError("wheelhouse must be a real directory")
    entries = sorted(wheelhouse.iterdir())
    if not entries:
        raise ProvenanceError("wheelhouse is empty")
    result = []
    seen = set()
    for wheel in entries:
        assert_regular(wheel, "wheelhouse")
        if wheel.suffix != ".whl":
            raise ProvenanceError("unexpected non-wheel artifact in wheelhouse")
        parts = wheel.name[:-4].split("-")
        if len(parts) not in (5, 6):
            raise ProvenanceError(f"invalid wheel filename: {wheel.name}")
        name, version = canonical(parts[0]), parts[1]
        if not name or not version or name in seen:
            raise ProvenanceError("duplicate or invalid wheel distribution name")
        seen.add(name)
        try:
            with zipfile.ZipFile(wheel) as archive:
                if archive.testzip() is not None:
                    raise ProvenanceError(f"wheel ZIP checksum invalid: {wheel.name}")
                if not any(p.endswith(".dist-info/WHEEL") for p in archive.namelist()):
                    raise ProvenanceError(f"wheel metadata missing: {wheel.name}")
        except zipfile.BadZipFile as exc:
            raise ProvenanceError(f"invalid wheel ZIP: {wheel.name}") from exc
        result.append({"filename": wheel.name, "name": name,
                       "version": version, "sha256": sha256_file(wheel)})
    return result


def save_json(path: Path, value: object) -> None:
    if path.exists() or path.is_symlink():
        raise ProvenanceError("refusing to overwrite a prior attestation record")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict:
    assert_regular(path, "attestation record")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ProvenanceError("malformed attestation record")
    return value


def check_wheels(wheelhouse: Path, wheel_record: Path) -> list[dict[str, str]]:
    record = read_json(wheel_record)
    actual = wheel_snapshot(wheelhouse)
    if record.get("schema") != 1 or record.get("wheels") != actual:
        raise ProvenanceError("wheelhouse differs from the pre-install SHA256 record")
    return actual


def verify_source_lock(wheels: list[dict[str, str]], lock_path: Path) -> None:
    assert_regular(lock_path, "source-controlled wheel lock")
    try:
        actual = lock_path.read_text(encoding="ascii").splitlines()
    except UnicodeError as exc:
        raise ProvenanceError("source-controlled wheel lock must be ASCII") from exc
    expected = [f"{entry['sha256']}  {entry['filename']}" for entry in wheels]
    if actual != expected:
        raise ProvenanceError("wheelhouse differs from source-controlled platform SHA256 lock")
    print("CI_WHEEL_SOURCE_LOCK=PASS count=" + str(len(expected)))



# Close the execution-source gap which wheel RECORD-only hashes cannot see.
# Inspection here uses importlib.metadata with explicit directories and (for
# "preimport") Python -I -S; it never imports an installed third-party package.
_IMPORTABLE_SUFFIXES = frozenset((".py", ".pyi", ".pyc", ".pyo", ".so",
                                  ".pyd", ".dylib", ".dll", ".pth", ".zip", ".egg"))


def scan_site_import_root(root: Path, recorded_files: set[Path]) -> dict:
    """Reject unrecorded importable code, unsafe symlinks and hidden .pth hooks.

    A generated __pycache__ bytecode file is allowed only with a RECORD-listed
    adjacent .py source; its actual bytes are included in the pre/post digest.
    RECORD-listed payloads are still checked by the existing per-dist hashes.
    """
    if not root.is_dir() or root.is_symlink():
        raise ProvenanceError(f"invalid site import root: {root}")
    digest = hashlib.sha256()
    file_count = 0
    pth_count = 0
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            if (current_path / name).is_symlink():
                raise ProvenanceError(f"symlinked import directory: {current_path / name}")
        for name in sorted(filenames):
            path = current_path / name
            if path.suffix.lower() not in _IMPORTABLE_SUFFIXES:
                continue
            assert_regular(path, "site executable source")
            allowed = path in recorded_files
            if not allowed and path.suffix.lower() == ".pyc" and path.parent.name == "__pycache__":
                source = path.parent.parent / (path.name.split(".", 1)[0] + ".py")
                allowed = source in recorded_files and source.is_file()
            if not allowed:
                raise ProvenanceError(f"unrecorded importable source: {path}")
            if path.suffix.lower() == ".pth":
                pth_count += 1
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith(("import ", "import\t")):
                        continue
                    candidate = (root / line).resolve()
                    if candidate.exists() and not candidate.is_relative_to(root):
                        raise ProvenanceError(f".pth adds external import root: {path}")
            relative = path.relative_to(root).as_posix()
            digest.update(relative.encode("utf-8") + b"\0")
            digest.update(sha256_file(path).encode("ascii") + b"\n")
            file_count += 1
    return {"root": str(root), "files": file_count,
            "pth_files": pth_count, "content_sha256": digest.hexdigest()}


def site_import_snapshot() -> dict:
    """Check all active global site roots, including bootstrap packages."""
    raw_roots = [*site.getsitepackages(),
                 sysconfig.get_path("purelib"), sysconfig.get_path("platlib")]
    roots = sorted({Path(s).resolve() for s in raw_roots
                    if s and Path(s).is_dir()}, key=str)
    if not roots:
        raise ProvenanceError("no importable site-packages roots discovered")
    snapshots = []
    for root in roots:
        if root.is_symlink():
            raise ProvenanceError(f"symlinked global site root: {root}")
        recorded: set[Path] = set()
        dist_count = 0
        for dist in metadata.distributions(path=[str(root)]):
            dist_count += 1
            for entry in dist.files or ():
                location = Path(dist.locate_file(entry)).absolute()
                if location.is_relative_to(root):
                    recorded.add(location)
        status = scan_site_import_root(root, recorded)
        status["distributions"] = dist_count
        snapshots.append(status)
    if not sys.flags.no_site:
        # No PYTHONPATH/user-site injection is permitted in this bounded CI.
        if os.environ.get("PYTHONPATH") or os.environ.get("PYTHONNOUSERSITE") != "1":
            raise ProvenanceError("untrusted external Python import search paths enabled")
        stdlib = Path(sysconfig.get_path("stdlib")).resolve()
        for item in sys.path:
            if not item:
                raise ProvenanceError("empty Python import search-path entry")
            path = Path(item)
            if path.is_dir():
                resolved = path.resolve()
                if not resolved.is_relative_to(stdlib) and resolved not in roots:
                    raise ProvenanceError(f"untrusted Python import root: {resolved}")
    result = {"schema": 1, "site_roots": snapshots}
    print("CI_SITE_IMPORT_CLOSURE=PASS count="
          + str(sum(item["files"] for item in snapshots))
          + " roots=" + str(len(snapshots)))
    return result


def installed_snapshot(wheels: list[dict[str, str]]) -> dict:
    installed = []
    roots = {}
    for entry in wheels:
        try:
            dist = metadata.distribution(entry["name"])
        except metadata.PackageNotFoundError as exc:
            raise ProvenanceError(f"resolved wheel missing after install: {entry['name']}") from exc
        version = dist.version
        if version != entry["version"]:
            raise ProvenanceError(f"installed version mismatch: {entry['name']}: {version} != {entry['version']}")
        files = dist.files
        if files is None:
            raise ProvenanceError(f"installed file RECORD missing: {entry['name']}")
        payload = hashlib.sha256()
        count = 0
        for rel in sorted(files, key=str):
            if str(rel).endswith((".pyc", ".pyo")):
                continue
            file = Path(dist.locate_file(rel))
            assert_regular(file, entry["name"])
            digest = sha256_file(file)
            payload.update(str(rel).encode("utf-8") + b"\0" + digest.encode("ascii") + b"\n")
            count += 1
        if count == 0:
            raise ProvenanceError("installed distribution has no attested files")
        installed.append({"name": entry["name"], "version": version,
                          "files": count, "content_sha256": payload.hexdigest()})
    for name in ("mcp", "starlette", "uvicorn", "httpx", "pytest"):
        spec = importlib.util.find_spec(name)
        if spec is None or not spec.origin:
            raise ProvenanceError(f"critical import origin unavailable: {name}")
        origin = Path(spec.origin).resolve(strict=True)
        assert_regular(origin, "critical import root")
        dist = metadata.distribution(name)
        root = Path(dist.locate_file("")).resolve(strict=True)
        if not origin.is_relative_to(root):
            raise ProvenanceError(f"critical import root not under installed distribution: {name}")
        roots[name] = {"origin": str(origin), "origin_sha256": sha256_file(origin)}
    return {"schema": 1, "python": sys.version.split()[0], "executable": sys.executable,
            "installed": installed, "critical_import_roots": roots}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("wheels", "preimport", "installed", "verify"))
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--wheel-record", required=True, type=Path)
    parser.add_argument("--source-lock", required=True, type=Path)
    parser.add_argument("--installed-record", type=Path)
    parser.add_argument("--site-record", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.phase == "wheels":
            wheels = wheel_snapshot(args.wheelhouse)
            verify_source_lock(wheels, args.source_lock)
            save_json(args.wheel_record, {"schema": 1, "wheels": wheels})
            for entry in wheels:
                print(f"CI_WHEEL_SHA256={entry['sha256']} name={entry['filename']}")
            print("CI_WHEELHOUSE=ATTESTED_FOR_THIS_JOB_ONLY; CROSS_RUN_LOCK=SOURCE_SHA256_PINNED")
            return 0
        wheels = check_wheels(args.wheelhouse, args.wheel_record)
        verify_source_lock(wheels, args.source_lock)
        if args.site_record is None:
            raise ProvenanceError("--site-record is required")
        site_snapshot = site_import_snapshot()
        if args.phase == "preimport":
            if not sys.flags.no_site:
                raise ProvenanceError("preimport must use Python -I -S before site hooks")
            save_json(args.site_record, site_snapshot)
            print("CI_PREIMPORT_SITE_SCAN=PASS_NO_THIRD_PARTY_IMPORTS")
            return 0
        if args.installed_record is None:
            raise ProvenanceError("--installed-record is required")
        if site_snapshot != read_json(args.site_record):
            raise ProvenanceError("installed site importable bytes/paths changed since preimport")
        current = installed_snapshot(wheels)
        current["site_import_closure"] = site_snapshot
        if args.phase == "installed":
            save_json(args.installed_record, current)
        elif read_json(args.installed_record) != current:
            raise ProvenanceError("installed dependency bytes/import roots changed during tests")
        for entry in current["installed"]:
            print(f"CI_DIST_SHA256={entry['content_sha256']} name={entry['name']} version={entry['version']} files={entry['files']}")
        for name, value in sorted(current["critical_import_roots"].items()):
            print(f"CI_IMPORT_ROOT={name} path={value['origin']} sha256={value['origin_sha256']}")
        print("CI_EXECUTED_DEPENDENCIES=SOURCE_WHEELS_PINNED_AND_INSTALLED_BYTES_ATTESTED")
        print("CI_INSTALLED_DISTRIBUTION_STATE=" + ("RECORDED" if args.phase == "installed" else "UNCHANGED"))
        return 0
    except (ProvenanceError, OSError, ValueError, KeyError, TypeError, UnicodeError, zipfile.BadZipFile) as exc:
        print("CI_DEPENDENCY_IDENTITY=INCOMPLETE", file=sys.stderr)
        print("CI_DEPENDENCY_REASON=" + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
