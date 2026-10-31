#!/usr/bin/env python3
"""PR101 P005: nine SHA-pinned Wheel BASE dependency metadata closure only.

Uses the six owner-authorized P002 wheels, two inherited R004 (packaging,
certifi), and the P001 primary Pipenv wheel as SOURCE bytes only. Only the
already source-attested packaging 26.3 parser may be imported. Never install,
import, invoke or execute the Pipenv distribution or the Go toolchain.
"""
from __future__ import annotations

import argparse
from email.parser import Parser
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib import request
from urllib.parse import urlsplit
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.lbe_pipenv_p002_metadata import _unique_pairs, read_lock
from tools.lbe_pipenv_p003_wheel_bytes import (
    ByteQualificationError, NoRedirect, _audit_wheel,
    _download_wheel, _official_wheel_url,
)
from tools.lbe_pipenv_p004_import_probe import verify_installed
from tools.lbe_t1_source_qualifier import (
    PIPENV_NAME, PIPENV_SHA256, inspect_pipenv_wheel,
)

PROFILE = "PR101-PIPENV-P005-BASE-RUNTIME-DECLARED-MARKER-GRAPH-20261030"
MAX_JSON = 2000000
MAX_METADATA = 524288
MAX_GRAPH_REQS = 512
EXPECTED = {
    "pipenv": ("2026.10.4", PIPENV_NAME, PIPENV_SHA256),
    "certifi": (
        "2026.10.23", "certifi-2026.10.23-py3-none-any.whl",
        "e9b54de76e530bb6cf0ccd036787103acb58fd42ba930ea8bf948ddbaa2f61d1",
    ),
    "packaging": (
        "26.3", "packaging-26.3-py3-none-any.whl",
        "d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c",
    ),
    "distlib": (
        "0.4.4", "distlib-0.4.4-py2.py3-none-any.whl",
        "cf09d55b1e85a89576b036aeb71550bfd68320f3f21761ca329eadadad918638",
    ),
    "filelock": (
        "4.2.4", "filelock-4.2.4-py3-none-any.whl",
        "301241438c57936ef93f4243a94f2559022268bfcf9b375a9a72eb0f8db8358e",
    ),
    "platformdirs": (
        "4.11.10", "platformdirs-4.11.10-py3-none-any.whl",
        "973c4c082b964958c71588448488d2b14fb253893dfbdb82325a14c84e540e8f",
    ),
    "python-discovery": (
        "1.6.1", "python_discovery-1.6.1-py3-none-any.whl",
        "d43fcdef879fe795352bd13ccf8d185ba5a9f86f36cfcd00529f596e737442b3",
    ),
    "setuptools": (
        "84.2.1", "setuptools-84.2.1-py3-none-any.whl",
        "ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2",
    ),
    "virtualenv": (
        "21.15.0", "virtualenv-21.15.0-py3-none-any.whl",
        "013eb9c340466186ac8923ce920ae05becfa1390fdf3565b7eae0d191a2f4a2e",
    ),
}
ADDITIONAL_SOURCE_ONLY = ("pipenv", "certifi")
NEW_SIX = frozenset(EXPECTED) - {"pipenv", "certifi", "packaging"}


class P005Error(ValueError):
    """The metadata-based runtime graph is not qualified."""


def _checked_root(root: Path) -> None:
    if (not root.is_absolute() or not root.is_dir()
            or root.is_symlink() or root.resolve(strict=True) != root
            or os.environ.get("RUNNER_TEMP") != str(root)):
        raise P005Error("disposable runner scratch identity invalid")


def _pypi_wheel_source(name: str, root: Path) -> tuple[Path, dict]:
    """Download only the two separately preapproved exact original source Wheels."""
    version, filename, digest = EXPECTED[name]
    source = f"https://pypi.org/pypi/{name}/{version}/json"
    opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(
                request.Request(source,
                                headers={"User-Agent": "mfg-p005-source-only/1"}),
                timeout=40) as res:
            if res.geturl() != source or res.status != 200:
                raise P005Error("PyPI release metadata redirect/source mismatch")
            raw = res.read(MAX_JSON + 1)
        if not 0 < len(raw) <= MAX_JSON:
            raise P005Error("PyPI release metadata size invalid")
        metadata = json.loads(raw.decode("utf-8", "strict"),
                              object_pairs_hook=_unique_pairs)
        if not isinstance(metadata, dict):
            raise P005Error("PyPI release metadata shape invalid")
        info, urls = metadata.get("info"), metadata.get("urls")
        if (not isinstance(info, dict) or
                re.sub(r"[-_.]+", "-", info.get("name", "").lower()) != name or
                info.get("version") != version or not isinstance(urls, list)):
            raise P005Error("PyPI release name/version mismatch")
        candidates = [w for w in urls if isinstance(w, dict) and
                      w.get("filename") == filename and
                      w.get("packagetype") == "bdist_wheel"]
        if len(candidates) != 1:
            raise P005Error("ambiguous pinned source Wheel")
        wheel = candidates[0]
        if (wheel.get("yanked") is not False or
                not isinstance(wheel.get("digests"), dict) or
                wheel["digests"].get("sha256") != digest or
                type(wheel.get("size")) is not int or
                not 0 < wheel["size"] <= 12000000):
            raise P005Error("pinned source wheel digest/size/yanked mismatch")
        url = wheel.get("url")
        _official_wheel_url(url, filename)
        dest = root / "lbe-p005-primary-source-only" / filename
        _download_wheel(url, dest, wheel["size"], digest)
        if name == "pipenv":
            inspected = inspect_pipenv_wheel(dest, digest, wheel["size"])
            if inspected["status"] != "WHEEL_BYTES_AND_RECORD_VERIFIED":
                raise P005Error("pinned Pipenv byte/RECORD qualification missing")
        else:
            inspected = _audit_wheel(dest, {"name": name, "version": version,
                                             "filename": filename, "sha256": digest},
                                     wheel["size"])
            if not inspected.get("bytes_verified"):
                raise P005Error("certifi original-lock byte/RECORD failed")
        return dest, {"name": name, "sha256": digest, "byte_record": "PASS"}
    except (OSError, ValueError, UnicodeError, request.URLError) as exc:
        if isinstance(exc, P005Error):
            raise
        raise P005Error("approved source-only PyPI acquisition rejected") from exc


def _wheel_metadata(path: Path, name: str, version: str,
                    digest: str) -> dict:
    """Read metadata from exact SHA-pinned already audited ZIP (no Python import)."""
    if (not path.is_file() or path.is_symlink() or
            hashlib.sha256(path.read_bytes()).hexdigest() != digest):
        raise P005Error("source wheel hash/path changed before METADATA read")
    filename = EXPECTED[name][1]
    if path.name != filename:
        raise P005Error("source wheel filename does not match immutable identity")
    prefix = filename.split("-")[0] + "-" + version + ".dist-info/"
    try:
        with zipfile.ZipFile(path) as z:
            info = z.getinfo(prefix + "METADATA")
            if info.file_size > MAX_METADATA or info.file_size <= 0:
                raise P005Error("source METADATA size invalid")
            message = Parser().parsestr(
                z.read(info).decode("utf-8", "strict"))
        names = message.get_all("Name") or []
        versions = message.get_all("Version") or []
        if (len(names) != 1 or len(versions) != 1 or
                re.sub(r"[-_.]+", "-", names[0].lower()) != name or
                versions[0] != version):
            raise P005Error("source METADATA identity mismatch")
        reqs = message.get_all("Requires-Dist") or []
        if (len(reqs) > MAX_GRAPH_REQS or
                any(not isinstance(x, str) or len(x) > 1024 for x in reqs)):
            raise P005Error("oversize Requirements declaration")
        python_reqs = message.get_all("Requires-Python") or []
        if len(python_reqs) > 1:
            raise P005Error("ambiguous Requires-Python declaration")
        return {
            "name": name, "version": version,
            "requires_dist": reqs,
            "requires_python": python_reqs[0] if python_reqs else None,
        }
    except (OSError, KeyError, UnicodeError, zipfile.BadZipFile) as exc:
        raise P005Error("source wheel METADATA cannot be read") from exc


def evaluate_base_graph(metadata: dict, environment: dict) -> dict:
    """Evaluate base (extra='') runtime requirements on exact CPython3.13 Darwin.

    This is NOT source-code security review, extra activation, real Pipenv
    virtualenv creation, or proof that missing Requires-Python is compatible.
    """
    from packaging.requirements import Requirement
    from packaging.specifiers import SpecifierSet
    from packaging.utils import canonicalize_name

    if (set(metadata) != set(EXPECTED) or
            environment.get("python_version") != "3.13" or
            environment.get("sys_platform") != "darwin" or
            environment.get("platform_machine") != "arm64" or
            environment.get("implementation_name") != "cpython" or
            environment.get("extra") != ""):
        raise P005Error("runtime graph platform/identity scope changed")
    versions = {k: EXPECTED[k][0] for k in EXPECTED}
    unknown_python = []
    for name, meta in metadata.items():
        if (not isinstance(meta, dict) or
                meta.get("name") != name or meta.get("version") != versions[name]):
            raise P005Error("runtime graph source distribution identity changed")
        py = meta.get("requires_python")
        if py is None or py == "":
            unknown_python.append(name)
        else:
            try:
                if environment["python_full_version"] not in SpecifierSet(py):
                    raise P005Error("Python version outside declared compatibility: " + name)
            except (ValueError, TypeError) as exc:
                if isinstance(exc, P005Error):
                    raise
                raise P005Error("invalid Requires-Python metadata") from exc
    active = []
    ignored = []
    visited = set()
    queued = ["pipenv"]
    while queued:
        name = queued.pop(0)
        if name in visited:
            continue
        visited.add(name)
        reqs = metadata[name].get("requires_dist")
        if not isinstance(reqs, list) or len(reqs) > MAX_GRAPH_REQS:
            raise P005Error("invalid runtime requirements collection")
        for raw in reqs:
            if not isinstance(raw, str) or len(raw) > 1024:
                raise P005Error("malformed requirement string")
            try:
                parsed = Requirement(raw)
            except (ValueError, TypeError) as exc:
                raise P005Error("invalid Requires-Dist syntax") from exc
            if parsed.url:
                raise P005Error("unapproved direct-URL requirement")
            try:
                enabled = (parsed.marker is None or
                           parsed.marker.evaluate(environment=environment))
            except (ValueError, TypeError) as exc:
                raise P005Error("requirement marker could not be evaluated") from exc
            if not enabled:
                ignored.append({"parent": name, "raw": raw,
                                "reason": "inactive_base_extra_or_environment_marker"})
                continue
            target = canonicalize_name(parsed.name)
            if parsed.extras:
                raise P005Error("base dependency unexpectedly activates unknown extra")
            if target not in versions:
                raise P005Error("unlocked active runtime dependency: " + target)
            if versions[target] not in parsed.specifier:
                raise P005Error("pinned dependency does not satisfy specifier: " +
                                name + " -> " + target)
            active.append({"from": name, "to": target, "constraint": str(parsed.specifier),
                           "version": versions[target]})
            queued.append(target)
        if len(visited) > len(EXPECTED) or len(active) > 256:
            raise P005Error("unexpected runtime graph explosion")
    if visited != set(EXPECTED):
        raise P005Error("pinned runtime graph has unreachable/extra distributions")
    return {
        "base_requires_dist_marker_graph": "SATISFIED_FOR_EXPLICIT_EXTRAS_EMPTY",
        "runtime_distributions": sorted(visited),
        "active_requirements": active,
        "inactive_optional_or_platform_requirements": ignored,
        "python_requires_undeclared": sorted(unknown_python),
        "python313_full_compatibility": (
            "NOT_PROVEN" if unknown_python else "DECLARED_METADATA_MATCHED_ONLY"
        ),
        "independent_external_security_review": "NOT_ISSUED",
        "full_Pipenv_native_T1": "NOT_RUN",
        "complete_optional_extra_graph": "NOT_QUALIFIED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner-temp", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        root = args.runner_temp
        _checked_root(root)
        rows = read_lock(args.lock)
        if ({r["name"] for r in rows} != NEW_SIX or
                any((r["version"], r["filename"], r["sha256"]) != EXPECTED[r["name"]]
                    for r in rows)):
            raise P005Error("P002 six candidates differ from audited source identity")
        site = root / "lbe-p004-private-site"
        seven = {k: v[0] for k, v in EXPECTED.items() if k not in (
            "pipenv", "certifi")}
        verify_installed(site, seven)
        # Only the original R004 packaging 26.3 may be imported for parsing.
        sys.path.insert(0, str(site))
        from packaging import __file__ as packaging_origin
        from packaging.markers import default_environment
        if (packaging_origin is None or
                not Path(packaging_origin).resolve(strict=True).is_relative_to(site)):
            raise P005Error("marker parser import not from attested private root")
        env = default_environment()
        env["extra"] = ""
        if not (sys.version_info[:2] == (3, 13) and
                sys.platform == "darwin" and
                env["platform_machine"] == "arm64"):
            raise P005Error("P005 must run only on hosted macOS15 ARM64 Python3.13")
        source = root / "lbe-p005-primary-source-only"
        if source.exists() or source.is_symlink():
            raise P005Error("source-only staging directory already exists")
        source.mkdir(mode=0o700)
        source_proofs = []
        paths = {}
        for name in ADDITIONAL_SOURCE_ONLY:
            paths[name], proof = _pypi_wheel_source(name, root)
            source_proofs.append(proof)
        all_evidence = json.loads(
            (root / "lbe-p003-wheel-byte-evidence.json").read_text("utf-8"))
        if all_evidence.get("wheel_count") != 6:
            raise P005Error("P003 six-Wheel actual SHA report missing")
        six_report = {r.get("distribution"): r for r in all_evidence["entries"]}
        if set(six_report) != NEW_SIX:
            raise P005Error("P003 actual source wheel identities changed")
        for name in NEW_SIX:
            row = six_report[name]
            if (row.get("actual_sha256") != EXPECTED[name][2] or
                    row.get("bytes_verified") is not True):
                raise P005Error("P003 candidate actual SHA proof changed")
            path = root / "lbe-p003-six-wheel-bytes" / EXPECTED[name][1]
            _audit_wheel(path, {"name": name, "version": EXPECTED[name][0],
                                 "filename": EXPECTED[name][1],
                                 "sha256": EXPECTED[name][2]}, path.stat().st_size)
            paths[name] = path
        packaging_path = root / "lbe-p004-packaging" / EXPECTED["packaging"][1]
        _audit_wheel(packaging_path, {"name": "packaging", "version": "26.3",
                                     "filename": EXPECTED["packaging"][1],
                                     "sha256": EXPECTED["packaging"][2]},
                     packaging_path.stat().st_size)
        paths["packaging"] = packaging_path
        metadata = {name: _wheel_metadata(path, name, EXPECTED[name][0],
                                           EXPECTED[name][2])
                    for name, path in paths.items()}
        graph = evaluate_base_graph(metadata, env)
        out = root / "lbe-p005-base-graph-source-evidence.json"
        if out.exists() or out.is_symlink():
            raise P005Error("P005 source graph evidence cannot be overwritten")
        payload = {
            "profile": PROFILE, "only_source_downloads": list(ADDITIONAL_SOURCE_ONLY),
            "pinned_primary_source": source_proofs,
            "status": graph["base_requires_dist_marker_graph"],
            "graph": graph,
            "complete_runtime_approval": False,
            "executed_Go_Pipenv": False,
        }
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, indent=2)
            stream.write("\n")
    except (OSError, ValueError, ImportError, UnicodeError,
            zipfile.BadZipFile, json.JSONDecodeError) as exc:
        print("LBE_P005_RUNTIME_GRAPH=BLOCKED: " + str(exc), file=sys.stderr)
        return 2
    print("LBE_P005_RUNTIME_BASE_MARKER_GRAPH=PASS distributions=9")
    print("LBE_P005_ACTIVE_REQUIREMENT_EDGES=" +
          str(len(graph["active_requirements"])))
    print("LBE_P005_INACTIVE_OPTIONAL_MARKER_REQUIREMENTS=" +
          str(len(graph["inactive_optional_or_platform_requirements"])))
    print("LBE_P005_REQUIRES_PYTHON_UNDECLARED=" +
          ",".join(graph["python_requires_undeclared"]))
    print("LBE_P005_RUNTIME_GRAPH_COMPATIBILITY=" +
          graph["python313_full_compatibility"])
    print("LBE_P005_FULL_GO_PIPENV_NATIVE=NOT_RUN")
    print("LBE_P005_INDEPENDENT_B_C_SOURCE_REVIEW=NOT_ISSUED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
