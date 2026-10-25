#!/usr/bin/env python3
"""Validate only source-locked wheels and files listed in installed RECORD.

Each wheel must match its platform-specific repository SHA256 lock before any
offline installation.  For every installed wheel distribution, hash *all*
RECORD-listed regular files before tests and compare them after tests.
Files not listed in installed RECORD are outside this verifier's contract:
this does NOT prove that unlisted code is absent or unimportable, or that the
runner/bootstrap/toolchain has independent supply-chain provenance.
Separate G05 tracked-repository admission remains mandatory and unchanged.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as metadata
import json
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


def installed_snapshot(wheels: list[dict[str, str]]) -> dict:
    installed = []
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
            file = Path(dist.locate_file(rel))
            assert_regular(file, entry["name"])
            digest = sha256_file(file)
            payload.update(str(rel).encode("utf-8") + b"\0" + digest.encode("ascii") + b"\n")
            count += 1
        if count == 0:
            raise ProvenanceError("installed distribution has no attested files")
        installed.append({"name": entry["name"], "version": version,
                          "files": count, "content_sha256": payload.hexdigest()})
    return {"schema": 1, "python": sys.version.split()[0], "executable": sys.executable,
            "installed": installed}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("wheels", "installed", "verify"))
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--wheel-record", required=True, type=Path)
    parser.add_argument("--source-lock", required=True, type=Path)
    parser.add_argument("--installed-record", type=Path)
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
        if args.installed_record is None:
            raise ProvenanceError("--installed-record is required")
        current = installed_snapshot(wheels)
        if args.phase == "installed":
            save_json(args.installed_record, current)
        elif read_json(args.installed_record) != current:
            raise ProvenanceError("RECORD-listed installed files changed during tests")
        for entry in current["installed"]:
            print(f"CI_DIST_SHA256={entry['content_sha256']} name={entry['name']} version={entry['version']} files={entry['files']}")
        print("CI_DEPENDENCY_VERIFY_SCOPE=LOCKED_WHEELS_AND_RECORD_FILES_ONLY")
        print("CI_UNLISTED_IMPORTABLE_FILES=NOT_ASSESSED")
        print("CI_EXECUTED_DEPENDENCIES=SOURCE_WHEELS_PINNED_AND_RECORD_FILE_HASHES_CHECKED")
        print("CI_INSTALLED_DISTRIBUTION_STATE=" + ("RECORDED" if args.phase == "installed" else "UNCHANGED"))
        return 0
    except (ProvenanceError, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        print("CI_DEPENDENCY_IDENTITY=INCOMPLETE", file=sys.stderr)
        print("CI_DEPENDENCY_REASON=" + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
