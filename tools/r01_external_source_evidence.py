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
import subprocess
import sys
import sysconfig
import zipfile


class EvidenceError(ValueError):
    pass


_SUFFIXES = (".py", ".pyc", ".pyo", ".so", ".pyd", ".dll", ".dylib", ".pth", ".zip", ".pyz", ".egg", ".whl")
_ARCHIVE_SUFFIXES = (".zip", ".pyz", ".egg", ".whl")


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



def verify_derived_bytecode(pyc: Path, root: Path, recorded: set[str]) -> tuple[str, bool]:
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
        header_matches = payload[8:16] == importlib.util.source_hash(code)
    else:
        header_matches = (int.from_bytes(payload[8:12], "little") == int(src.stat().st_mtime) & 0xffffffff
                          and int.from_bytes(payload[12:16], "little") == len(code) & 0xffffffff)
    # An installer may leave stale invalidation metadata. A different header
    # does not give license to accept unreviewed bytecode: require an EXACT
    # independent recompilation of its executable payload from recorded .py.
    # Record mismatch as an explicit gap; do not claim PEP552 header identity.
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
    return src.relative_to(root).as_posix(), header_matches


def archive_bytes(path: Path) -> bool:
    """Inspect real ZIP central-directory bytes regardless of file suffix.

    CPython zipimport can load ZIP payloads from .pyz and arbitrary names.
    Filename-only checks are insufficient for pre-import source closure.
    """
    try:
        return zipfile.is_zipfile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise EvidenceError("ZIP archive inspection failed: " + str(path)) from exc


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
    imperative_pth = []
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
            # Both recognized archive suffixes AND actual ZIP magic matter:
            # a bare .asset/noextension ZIP is importable after a .pth injection.
            is_zip = archive_bytes(p)
            if name.lower().endswith(_ARCHIVE_SUFFIXES) and not is_zip:
                # Keep the original negative contract: an unlisted would-be
                # archive fails as UNLISTED even when its ZIP bytes are corrupt.
                if rel not in recorded:
                    raise EvidenceError("RECORD-unlisted importable/executable: " + rel)
                raise EvidenceError("invalid ZIP archive: " + rel)
            if not source_like(name) and not is_zip:
                if rel not in recorded:
                    unknown_non_exec += 1
                continue
            if rel not in recorded:
                if name.endswith(".pyc"):
                    origin, header_matches = verify_derived_bytecode(p, root, recorded)
                    derived.append([rel, origin, header_matches])
                else:
                    raise EvidenceError("RECORD-unlisted importable/executable: " + rel)
            d = digest(p)
            importable.append([rel, d])
            if name.endswith(".pth"):
                pths.append([rel, d])
                for line_number, line in enumerate(p.read_text("utf-8").splitlines(), 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith(("import ", "import\t")):
                        # CPython site.py executes these directives at startup.
                        # A passive end-of-session census cannot prove their
                        # effects if imported files are later removed.
                        imperative_pth.append([rel, line_number,
                                               hashlib.sha256(line.encode("utf-8")).hexdigest()])
                        continue
                    injected = Path(os.path.abspath(str(root / line)))
                    if injected.exists():
                        if not under(injected, root):
                            raise EvidenceError(".pth injects outside site root: " + rel)
                        if injected.is_file() or injected.is_symlink():
                            regular(injected)
                            if archive_bytes(injected):
                                # The complete scan covers these bytes too.
                                # A .pth path cannot justify unlisted ZIP input.
                                relative = injected.relative_to(root).as_posix()
                                if relative not in recorded:
                                    raise EvidenceError("RECORD-unlisted importable/executable: " + relative)
                            elif injected.name.lower().endswith(_ARCHIVE_SUFFIXES):
                                raise EvidenceError("invalid ZIP archive in .pth: " + rel)
    if not importable:
        raise EvidenceError("site root has no examined importable source")
    return {"path": str(root), "dist_record_count": len(dist_records),
            "importable": importable, "derived_bytecode": derived, "pth": pths,
            "imperative_pth": imperative_pth,
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


def _require_canonical_path(path: Path) -> Path:
    """Reject lexical parent escapes, symlinks and other aliases to trusted roots."""
    raw = str(path)
    if any(part == ".." for part in path.parts):
        raise EvidenceError("noncanonical Python import path: " + raw)
    absolute = path.absolute()
    resolved = path.resolve(strict=False)
    if absolute != resolved:
        raise EvidenceError("noncanonical/symlink Python import path: " + raw)
    return resolved


def _read_git_head_manifest(repo: Path) -> dict[str, str]:
    """Compare local manifest to immutable committed HEAD content, not self-report."""
    root = _require_canonical_path(repo)
    if not root.is_dir():
        raise EvidenceError("missing HEAD repository: " + str(root))
    manifest = root / "MANIFEST.sha256"
    if manifest.is_symlink() or not manifest.is_file():
        raise EvidenceError("missing or unsafe HEAD G05 MANIFEST: " + str(manifest))
    regular(manifest)

    def git(*args: str) -> bytes:
        # Git read-only object queries, not shell and never any repo write.
        # Do not inherit caller-controlled Git overrides into source identity.
        clean_env = {key: value for key, value in os.environ.items()
                     if not key.startswith("GIT_")}
        try:
            completed = subprocess.run(["git", "-C", str(root), *args],
                                       capture_output=True, timeout=15, check=False,
                                       env=clean_env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EvidenceError("immutable HEAD source query unavailable") from exc
        if completed.returncode != 0:
            raise EvidenceError("immutable HEAD source query failed: " +
                                " ".join(args))
        return completed.stdout

    actual_root = _require_canonical_path(Path(git("rev-parse", "--show-toplevel").decode("utf-8").strip()))
    if actual_root != root:
        raise EvidenceError("HEAD source root differs from repository checkout")
    head = git("rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    if len(head) != 40 or any(ch not in "0123456789abcdef" for ch in head):
        raise EvidenceError("invalid immutable Git HEAD identity")
    expected = os.environ.get("G05_EXPECTED_HEAD")
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if expected and workspace and Path(workspace).resolve(strict=False) == root and head != expected:
        raise EvidenceError("HEAD source SHA differs from G05 expected checkout")
    immutable = git("show", head + ":MANIFEST.sha256")
    if manifest.read_bytes() != immutable:
        raise EvidenceError("working MANIFEST differs from immutable Git HEAD source")
    hashes = {}
    try:
        lines = immutable.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise EvidenceError("invalid immutable Git HEAD manifest encoding") from exc
    for line in lines:
        if len(line) < 69 or line[64:68] != "  ./":
            raise EvidenceError("invalid immutable HEAD MANIFEST line")
        rel, expected_hash = line[68:], line[:64]
        if (not rel or rel in hashes or any(ch not in "0123456789abcdef"
                                             for ch in expected_hash)
                or Path(rel).is_absolute() or ".." in Path(rel).parts):
            raise EvidenceError("invalid immutable HEAD MANIFEST entry")
        hashes[rel] = expected_hash
    if not hashes:
        raise EvidenceError("empty immutable HEAD MANIFEST")
    return hashes


def _repo_attested_file(path: Path, repo: Path,
                        hashes: dict[str, str] | None = None) -> Path:
    """Require real source bytes matching the immutable HEAD MANIFEST."""
    root = _require_canonical_path(repo)
    source = _require_canonical_path(path)
    if not under(source, root):
        raise EvidenceError("unattested HEAD module outside tracked root: " + str(path))
    if hashes is None:
        hashes = _read_git_head_manifest(root)
    for candidate in (source, *source.parents):
        if not under(candidate, root):
            break
        if candidate.is_file():
            regular(candidate)
            rel = candidate.relative_to(root).as_posix()
            if rel not in hashes:
                raise EvidenceError("unattested HEAD module not in immutable MANIFEST: " + rel)
            if digest(candidate) != hashes[rel]:
                raise EvidenceError("changed HEAD module source bytes: " + rel)
            if candidate != source and not archive_bytes(candidate):
                raise EvidenceError("HEAD module origin traverses non-ZIP file: " + rel)
            return candidate
    raise EvidenceError("unattested HEAD module source: " + str(path))


def _classify_root(value: str, repo: Path, site: list[Path]) -> str:
    p = _require_canonical_path(Path(value or str(repo)))
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


def site_attested_file(path: Path, roots: list[Path],
                       hashes: dict[str, str]) -> Path | None:
    """Resolve the real, hashed source for site files or ZIP member paths.

    A module __file__ or sys.path may contain archive.pyz/pkg/module.py,
    while the ZIP file itself is the independently hashed importable input.
    """
    path = _require_canonical_path(path)
    for root in roots:
        if not under(path, root):
            continue
        for candidate in (path, *path.parents):
            if not under(candidate, root):
                break
            if candidate.is_symlink():
                raise EvidenceError("symlink in site source path: " + str(candidate))
            if candidate.is_file():
                regular(candidate)
                expected = hashes.get(str(candidate))
                if expected is None:
                    raise EvidenceError("unattested site import source: " + str(candidate))
                if digest(candidate) != expected:
                    raise EvidenceError("changed site import source bytes: " + str(candidate))
                if candidate != path and not archive_bytes(candidate):
                    raise EvidenceError("module origin traverses non-ZIP file: " + str(candidate))
                return candidate
        return None
    return None


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
    repo = _require_canonical_path(repo)
    imperative = [
        [rel, line_number] for site in snapshot["site"]
        for rel, line_number, _digest in site.get("imperative_pth", [])
    ]
    if imperative:
        raise EvidenceError("unqualified imperative .pth startup execution: " +
                            repr(imperative[:8]))
    repo_hashes = None

    def head_hashes() -> dict[str, str]:
        nonlocal repo_hashes
        if repo_hashes is None:
            repo_hashes = _read_git_head_manifest(repo)
        return repo_hashes

    site_attested = {}
    for root in snapshot["site"]:
        site_attested.update({str(Path(root["path"]) / rel): sha for rel, sha in root["importable"]})
    observed = []
    for value in paths:
        if not isinstance(value, str):
            raise EvidenceError("invalid sys.path entry")
        category = _classify_root(value, repo.absolute(), roots)
        if category == "INSTALLED_SITE_ROOT":
            location = _require_canonical_path(Path(value or str(repo)))
            source = site_attested_file(location, roots, site_attested)
            if source is None:
                if location.is_symlink() or not location.is_dir():
                    raise EvidenceError("unattested site import root: " + str(location))
            elif not archive_bytes(source):
                raise EvidenceError("non-ZIP file in Python sys.path: " + str(location))
        elif category == "HEAD_REPOSITORY_G05":
            location = _require_canonical_path(Path(value or str(repo)))
            if location == repo:
                if not location.is_dir():
                    raise EvidenceError("missing HEAD repository import root: " + str(location))
            elif location.is_dir():
                # An arbitrary post-G05 generated directory cannot become a
                # trusted import root merely by sharing the checkout prefix.
                relative = location.relative_to(repo).as_posix() + "/"
                if not any(name.startswith(relative) for name in head_hashes()):
                    raise EvidenceError("unattested HEAD directory import root: " + str(location))
            elif location.is_file():
                candidate = _repo_attested_file(location, repo, head_hashes())
                if not archive_bytes(candidate):
                    raise EvidenceError("non-ZIP HEAD file in Python sys.path: " + str(location))
            else:
                # Includes a ZIP executed during startup then unlinked, and
                # a generated path removed while the old sys.path survived.
                raise EvidenceError("missing or unattested HEAD import root: " + str(location))
        observed.append([value, category])
    if not any(category == "INSTALLED_SITE_ROOT" for _, category in observed):
        raise EvidenceError("runtime site root not observed")
    checked_site_modules = 0
    unmatched_test_modules = []
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
        try:
            _require_canonical_path(file)
            category = _classify_root(str(file), repo.absolute(), roots)
            if category == "INSTALLED_SITE_ROOT":
                if site_attested_file(file, roots, site_attested) is None:
                    raise EvidenceError("actual site-imported module outside attested inputs: " + origin)
                checked_site_modules += 1
            elif category == "HEAD_REPOSITORY_G05":
                _repo_attested_file(file, repo, head_hashes())
        except EvidenceError:
            # External fixtures, lexical escapes and untracked/changed HEAD
            # inputs are NEVER silently upgraded to verified source identity.
            unmatched_test_modules.append([name, origin])
    if unmatched_test_modules:
        raise EvidenceError("unattested or noncanonical loaded module origins: "
                            + repr(unmatched_test_modules[:4]))
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
        imperative_count = sum(len(site.get("imperative_pth", [])) for site in current["site"])
        print("R01_IMPERATIVE_PTH_STARTUP_EFFECTS=" +
              ("NOT_ATTESTED count=" + str(imperative_count)
               if imperative_count else "NONE_OBSERVED"))
        print("R01_SITE_IMPORTABLE_SOURCE_SET=PASS site_roots=" + str(len(roots))
              + " files=" + str(sum(len(s["importable"]) for s in current["site"])))
        derived_count = sum(len(site["derived_bytecode"]) for site in current["site"])
        if derived_count:
            print("R01_SITE_RECORD_UNLISTED_PYC=REPRODUCIBLY_DERIVED_FROM_RECORDED_SOURCE count="
                  + str(derived_count))
            stale = sum(1 for site in current["site"] for row in site["derived_bytecode"] if not row[2])
            print("R01_PYC_INVALIDATION_HEADER_MISMATCH=OBSERVED_COUNT_" + str(stale))
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
