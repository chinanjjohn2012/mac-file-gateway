#!/usr/bin/env python3
"""Additional, scoped R01 Python executed-source evidence; NOT the R004 verifier.

The pre-import site scan MUST run with python -B -I -S after offline wheel
installation and BEFORE the next site-enabled Python invocation. It observes
site-package importable bytes, including RECORD-unlisted files, and detects
potential import-path shadowing without executing any unreviewed file.

It cannot attest Python interpreter/stdlib/runner bootstrap supply-chain
provenance, malicious same-UID races, Native Exec, or production Macs.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import marshal
import os
from pathlib import Path
import stat
import sys
import sysconfig


class EvidenceError(ValueError):
    pass


_SUFFIXES = (".py", ".pyc", ".pyo", ".so", ".pyd", ".dll", ".dylib", ".pth", ".zip", ".egg", ".whl")


def source_like(name: str) -> bool:
    return name.lower().endswith(_SUFFIXES) or ".so." in name.lower()


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def regular(path: Path) -> None:
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode):
        raise EvidenceError("nonregular/symlink executable input: " + str(path))


def under(path: Path, root: Path) -> bool:
    try:
        return path == root or root in path.parents
    except ValueError:
        return False


def default_roots() -> list[Path]:
    paths = sysconfig.get_paths()
    roots = sorted({str(Path(paths[k]).absolute()) for k in ("purelib", "platlib")})
    if not roots:
        raise EvidenceError("no interpreter site-package root")
    return [Path(p) for p in roots]


def read_record(root: Path, file: Path) -> set[str]:
    regular(file)
    rels = set()
    with file.open("r", encoding="utf-8", newline="") as stream:
        for row in csv.reader(stream):
            if not row or not row[0]:
                raise EvidenceError("malformed RECORD in " + str(file))
            path = Path(os.path.abspath(os.path.join(str(root), row[0])))
            if under(path, root):
                name = path.relative_to(root).as_posix()
                if name in rels:
                    raise EvidenceError("duplicate RECORD entry: " + name)
                rels.add(name)
    return rels



def verify_derived_bytecode(pyc: Path, root: Path, recorded: set[str]) -> str:
    """Validate unlisted optimized pyc against its RECORD-listed .py source.

    pip may generate PEP 3147 .opt-1.pyc outside RECORD during install.
    Verify PEP 552 header and recompile approved source without executing it.
    """
    try:
        src = Path(importlib.util.source_from_cache(str(pyc)))
    except (ValueError, OSError) as exc:
        raise EvidenceError("unrecognized RECORD-unlisted bytecode: " + str(pyc)) from exc
    if not under(src, root) or src.relative_to(root).as_posix() not in recorded:
        raise EvidenceError("RECORD-unlisted importable/executable: " + str(pyc.relative_to(root)))
    regular(src)
    payload = pyc.read_bytes()
    code = src.read_bytes()
    if len(payload) < 16 or payload[:4] != importlib.util.MAGIC_NUMBER:
        raise EvidenceError("invalid derived bytecode header: " + str(pyc))
    flags = int.from_bytes(payload[4:8], "little")
    if flags not in (0, 1, 3):
        raise EvidenceError("invalid derived bytecode PEP552 flags")
    if flags & 1:
        if payload[8:16] != importlib.util.source_hash(code):
            raise EvidenceError("derived bytecode source hash mismatch")
    elif (int.from_bytes(payload[8:12], "little") != int(src.stat().st_mtime) & 0xffffffff
          or int.from_bytes(payload[12:16], "little") != len(code) & 0xffffffff):
        raise EvidenceError("derived bytecode source timestamp/size mismatch")
    label = pyc.name
    if ".opt-2.pyc" in label:
        optimize = 2
    elif ".opt-1.pyc" in label:
        optimize = 1
    elif label.endswith(".pyc") and ".opt-" not in label:
        optimize = 0
    else:
        raise EvidenceError("unrecognized derived bytecode optimization")
    try:
        compiled = compile(code, str(src), "exec", dont_inherit=True, optimize=optimize)
    except (SyntaxError, ValueError, TypeError) as exc:
        raise EvidenceError("cannot reproduce derived bytecode") from exc
    if payload[16:] != marshal.dumps(compiled):
        raise EvidenceError("derived bytecode payload differs from recorded source")
    return src.relative_to(root).as_posix()


def scan_root(root: Path) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise EvidenceError("site root missing or symlink: " + str(root))
    root = root.absolute()
    recorded = set()
    dist_records = sorted(root.glob("*.dist-info/RECORD"))
    if not dist_records:
        raise EvidenceError("no installed distribution RECORD: " + str(root))
    for record in dist_records:
        recorded.update(read_record(root, record))
    importable = []
    derived = []
    pths = []
    unknown_non_exec = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs):
            p = Path(base) / name
            if not stat.S_ISDIR(p.lstat().st_mode):
                raise EvidenceError("symlink or non-directory inside site root: " + str(p))
        for name in sorted(files):
            p = Path(base) / name
            regular(p)
            rel = p.relative_to(root).as_posix()
            if not source_like(name):
                if rel not in recorded:
                    unknown_non_exec += 1
                continue
            if rel not in recorded:
                if name.endswith(".pyc"):
                    origin = verify_derived_bytecode(p, root, recorded)
                    derived.append([rel, origin])
                else:
                    raise EvidenceError("RECORD-unlisted importable/executable: " + rel)
            d = digest(p)
            importable.append([rel, d])
            if name.endswith(".pth"):
                pths.append([rel, d])
                for line in p.read_text("utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("import "):
                        continue
                    injected = Path(os.path.abspath(str(root / line)))
                    if injected.exists() and not under(injected, root):
                        raise EvidenceError(".pth injects outside site root: " + rel)
    if not importable:
        raise EvidenceError("site root has no examined importable source")
    return {"path": str(root), "dist_record_count": len(dist_records),
            "importable": importable, "derived_bytecode": derived, "pth": pths,
            "unlisted_nonexecutables": unknown_non_exec}


def site_snapshot(roots: list[Path]) -> dict:
    if not roots or len({str(root.absolute()) for root in roots}) != len(roots):
        raise EvidenceError("no roots or duplicate roots")
    return {"schema": 1, "interpreter": sys.executable,
            "python": sys.version.split()[0], "prefix": sys.prefix,
            "base_prefix": sys.base_prefix,
            "site": [scan_root(p) for p in roots]}


def write_new(file: Path, data: dict) -> None:
    if file.exists() or file.is_symlink():
        raise EvidenceError("refuse overwrite prior R01 evidence")
    if not file.parent.is_dir():
        raise EvidenceError("evidence output parent not found")
    file.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def read_json(file: Path) -> dict:
    regular(file)
    value = json.loads(file.read_text("utf-8"))
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise EvidenceError("bad R01 evidence schema")
    return value


def _classify_root(value: str, repo: Path, site: list[Path]) -> str:
    p = Path(value or str(repo)).absolute()
    if under(p, repo):
        return "HEAD_REPOSITORY_G05"
    if any(under(p, root) for root in site):
        return "INSTALLED_SITE_ROOT"
    paths = sysconfig.get_paths()
    stdlib = Path(paths["stdlib"]).absolute()
    platstdlib = Path(paths["platstdlib"]).absolute()
    if under(p, stdlib) or under(p, platstdlib):
        return "RUNNER_STDLIB_NOT_SOURCE_PINNED"
    if p.name.startswith("python") and p.suffix == ".zip" and under(p.parent, Path(sys.base_prefix).absolute()):
        return "RUNNER_STDLIB_ZIP_NOT_SOURCE_PINNED"
    raise EvidenceError("unexpected actual Python import root: " + str(p))


def verify_runtime(path: Path, repo: Path, snapshot: dict) -> dict:
    data = read_json(path)
    if data.get("executable") != snapshot["interpreter"] or data.get("prefix") != snapshot["prefix"]:
        raise EvidenceError("runtime Python identity differs from pre-import scanner")
    if data.get("user_site_enabled") not in (False, None):
        raise EvidenceError("user site enabled")
    paths = data.get("sys_path")
    if not isinstance(paths, list) or not paths:
        raise EvidenceError("actual Python sys.path not observed")
    roots = [Path(root["path"]) for root in snapshot["site"]]
    observed = []
    for value in paths:
        if not isinstance(value, str):
            raise EvidenceError("invalid sys.path entry")
        observed.append([value, _classify_root(value, repo.absolute(), roots)])
    if not any(category == "INSTALLED_SITE_ROOT" for _, category in observed):
        raise EvidenceError("runtime site root not observed")
    checked_site_modules = 0
    unmatched_test_modules = []
    site_attested = {}
    for root in snapshot["site"]:
        site_attested.update({str(Path(root["path"]) / rel): sha for rel, sha in root["importable"]})
    for entry in data.get("loaded_origins", []):
        if not isinstance(entry, list) or len(entry) != 2:
            raise EvidenceError("bad imported-module origin record")
        name, origin = entry
        if not isinstance(name, str) or not isinstance(origin, str):
            raise EvidenceError("non-string module origin")
        file = Path(origin)
        if not file.is_absolute():
            # Relative entries cannot prove a source identity. Report the gap.
            unmatched_test_modules.append([name, origin])
            continue
        if any(under(file, root) for root in roots):
            expected = site_attested.get(str(file))
            if expected is None:
                raise EvidenceError("actual site-imported module outside RECORD: " + origin)
            regular(file)
            if digest(file) != expected:
                raise EvidenceError("actual site-imported module bytes changed: " + origin)
            checked_site_modules += 1
        else:
            try:
                _classify_root(str(file), repo.absolute(), roots)
            except EvidenceError:
                # Fixtures may import disposable modules outside the app tree;
                # never silently treat these as source-qualified production.
                unmatched_test_modules.append([name, origin])
    return {"observed": observed, "module_count": data.get("module_count", 0),
            "attested_site_module_origins": checked_site_modules,
            "out_of_scope_module_origins": unmatched_test_modules}


def runtime_report() -> dict:
    """Run only AFTER site preflight, under the same CI Python as pytest."""
    import site
    return {"schema": 1, "executable": sys.executable, "prefix": sys.prefix,
            "sys_path": list(sys.path),
            "user_site_enabled": site.ENABLE_USER_SITE,
            "module_count": len(sys.modules)}


def pytest_sessionfinish(session, exitstatus):
    """Optional pytest import-root evidence; no change to test behavior."""
    path = os.environ.get("R01_PYTEST_IMPORT_ROOT_TRACE")
    if path:
        report = runtime_report()
        modules = []
        for name, module in sorted(sys.modules.copy().items()):
            origin = getattr(module, "__file__", None)
            if isinstance(origin, str) and origin:
                modules.append([name, origin])
        report["loaded_origins"] = modules
        write_new(Path(path), report)
        print("R01_ACTUAL_PYTEST_IMPORT_ROOTS_CAPTURED=PASS")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("preimport", "verify", "runtime"))
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--site-root", type=Path, action="append")
    args = parser.parse_args(argv)
    try:
        if args.mode == "runtime":
            if args.runtime is None:
                raise EvidenceError("runtime output required")
            write_new(args.runtime, runtime_report())
            print("R01_RUNTIME_IMPORT_ROOT_OBSERVED=PASS")
            return 0
        if args.snapshot is None:
            raise EvidenceError("snapshot path required")
        if not sys.flags.no_site or not sys.flags.isolated:
            raise EvidenceError("site scanner must run with -I -S before site import")
        roots = args.site_root or default_roots()
        current = site_snapshot(roots)
        if args.mode == "preimport":
            write_new(args.snapshot, current)
        elif current != read_json(args.snapshot):
            raise EvidenceError("site importable file-set or bytes changed after tests")
        print(f"R01_EXACT_INTERPRETER={sys.executable}")
        print("R01_SITE_IMPORTABLE_SOURCE_SET=PASS site_roots=" + str(len(roots))
              + " files=" + str(sum(len(s["importable"]) for s in current["site"])))
        derived_count = sum(len(site["derived_bytecode"]) for site in current["site"])
        if derived_count:
            print("R01_SITE_RECORD_UNLISTED_PYC=REPRODUCIBLY_DERIVED_FROM_RECORDED_SOURCE count="
                  + str(derived_count))
        else:
            print("R01_SITE_UNLISTED_EXECUTABLES=NONE_DETECTED")
        print("R01_SITE_UNVERIFIED_EXECUTABLES=NONE_DETECTED")
        print("R01_RUNNER_BOOTSTRAP_STDLIB_PROVENANCE=NOT_SOURCE_PINNED")
        if args.runtime:
            if args.repo is None:
                raise EvidenceError("repo root required for runtime check")
            observed = verify_runtime(args.runtime, args.repo, current)
            print("R01_ACTUAL_PYTHON_IMPORT_ROOTS=OBSERVED_AND_CLASSIFIED")
            for value, category in observed["observed"]:
                print("R01_IMPORT_ROOT=" + category + " " + value)
            print("R01_ACTUAL_SITE_MODULE_ORIGINS_SHA256_CHECKED="
                  + str(observed["attested_site_module_origins"]))
            print("R01_UNQUALIFIED_TEST_MODULE_ORIGINS="
                  + str(len(observed["out_of_scope_module_origins"])))
            for mod_name, mod_file in observed["out_of_scope_module_origins"][:12]:
                print("R01_OUT_OF_SCOPE_TEST_MODULE=" + mod_name + " " + mod_file)
        return 0
    except (EvidenceError, OSError, TypeError, ValueError, UnicodeError, KeyError) as exc:
        print("R01_EXTERNAL_SOURCE_EVIDENCE=INCOMPLETE " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
