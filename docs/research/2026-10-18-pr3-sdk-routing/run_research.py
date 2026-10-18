"""Reproduce the PR3 research in a new directory outside every Git checkout.

Reads an existing, hash-verified MCP 1.30.0 install; never edits site-packages.
The original matrix/build/runner files are copied unchanged into that directory.
This is an opt-in research command, not a Gateway startup or dependency hook.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
BASELINE = "b82a4755a7713c2584dbb538088e59e1214ff293"
ORIGINAL = "bea279ba402b95c1bb3f3c2566db39c972ac76355b80719fb3b8fc356319b29f"
CANDIDATE = "6b9fef82b68c070c6f66f9181ac91221832655c1abd80d3a7afe498ed5a5a3ef"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_sdk(source: Path, manifest: dict[str, str]) -> None:
    # Only source/typing files are in the fixed manifest; ignore generated caches.
    actual = {p.relative_to(source).as_posix(): digest(p)
              for p in source.rglob("*")
              if p.is_file() and "__pycache__" not in p.parts
              and (p.suffix == ".py" or p.name == "py.typed")}
    if actual != manifest:
        raise RuntimeError("SDK source differs from the recorded MCP 1.30.0 source; STOP")


def run_stage(root: Path, name: str, argv: list[str], env: dict[str, str]) -> int:
    with (root / f"{name}.stdout.log").open("xb") as stdout:
        with (root / f"{name}.stderr.log").open("xb") as stderr:
            process = subprocess.run(argv, cwd=root, env=env, stdout=stdout,
                                     stderr=stderr, timeout=150, check=False)
    (root / f"{name}.command.json").write_text(json.dumps({
        "argv": argv, "cwd": str(root), "env": env, "exit_code": process.returncode,
    }, indent=2) + "\n", encoding="utf-8")
    if process.returncode:
        raise RuntimeError(f"{name} failed; inspect its preserved logs outside the checkout")
    return process.returncode


def summarized(result: dict, expected_rows: list[dict]) -> dict:
    rows = result["cases"]
    if [row["case"] for row in rows] != [row["case"] for row in expected_rows]:
        raise RuntimeError("Matrix cases changed or are missing; STOP")
    for row, expected in zip(rows, expected_rows):
        if "harness_or_mechanism_exception" in row:
            raise RuntimeError(f"Fixture/mechanism exception in {row['case']}; not a safety PASS")
        if row.get("passed") is not expected.get("passed") or row.get("not_run") != expected.get("not_run"):
            raise RuntimeError(f"Unexpected outcome in {row['case']}; STOP")
    expected_hash = ORIGINAL if result["mode"] == "original" else CANDIDATE
    if (result["SDK_version"] != "1.30.0" or result["SDK_file_sha256"] != expected_hash
            or result["Popen_attempts"] != 0 or result["Gateway_started"]
            or result["listener_started"]):
        raise RuntimeError("Source/runtime boundary check failed; STOP")
    return {
        "SDK_file_sha256": result["SDK_file_sha256"], "exit_code": 0,
        "Popen_attempts": 0, "listener_started": False, "Gateway_started": False,
        "cases": [{key: value for key, value in row.items()
                   if key in ("case", "passed", "not_run")} for row in rows],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="new directory outside every Git checkout; raw logs stay private here")
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    if any((ancestor / ".git").exists() for ancestor in (output, *output.parents)):
        parser.error("--output must be outside every Git checkout")
    if output.exists() or not output.parent.is_dir():
        parser.error("--output must not exist and its parent directory must exist")
    dist = importlib.metadata.distribution("mcp")
    if dist.version != "1.30.0":
        parser.error("requires MCP 1.30.0; install it only in a disposable research venv")
    sdk = Path(dist.locate_file("mcp")).resolve()
    manifest = json.loads((HERE / "SDK_SOURCE_SHA256.json").read_text(encoding="utf-8"))
    verify_sdk(sdk, manifest)
    output.mkdir()
    for name in ("home", "tmp", "evidence"):
        (output / name).mkdir()
    for name in ("sdk_asgi_matrix.py", "build_throwaway_candidate.py", "run_matrix.py", "SDK-LICENSE.txt"):
        shutil.copyfile(HERE / name, output / name)
    for mode in ("original", "candidate"):
        for relative in manifest:
            destination = output / f"sdk-{mode}" / "mcp" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(sdk / relative, destination)
    # No caller credentials, proxy settings, Gateway configuration or Python hooks.
    env = {
        "PATH": str(Path(sys.executable).parent) + os.pathsep + os.defpath,
        "HOME": str(output / "home"), "TMPDIR": str(output / "tmp"),
        "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    versions = {name: importlib.metadata.version(name)
                for name in ("mcp", "starlette", "anyio", "httpx", "uvicorn")}
    (output / "provenance.json").write_text(json.dumps({
        "utc": datetime.now(timezone.utc).isoformat(), "python": sys.version,
        "platform": platform.platform(), "versions": versions,
        "sdk_source": str(sdk), "review_baseline": BASELINE,
        "script_sha256": {name: digest(HERE / name) for name in (
            "run_research.py", "sdk_asgi_matrix.py", "build_throwaway_candidate.py", "run_matrix.py")},
    }, indent=2) + "\n", encoding="utf-8")
    try:
        run_stage(output, "build", [sys.executable, "-B", str(output / "build_throwaway_candidate.py")], env)
        if digest(output / "sdk-candidate/mcp/server/streamable_http.py") != CANDIDATE:
            raise RuntimeError("Candidate source hash differs; STOP")
        if (output / "evidence/throwaway-sdk-candidate.diff").read_bytes() != (
                HERE / "patches/mcp-1.30.0-routing-prototype.patch").read_bytes():
            raise RuntimeError("Generated patch differs from the review patch; STOP")
        for relative, expected in manifest.items():
            if relative != "server/streamable_http.py" and digest(output / "sdk-candidate/mcp" / relative) != expected:
                raise RuntimeError("Unexpected additional SDK candidate change; STOP")
        expected = json.loads((HERE / "results/recorded-research-summary.json").read_text(encoding="utf-8"))
        summary = {"kind": "public-script reproduction; research only; Phase 2 remains BLOCK",
                   "review_baseline": BASELINE, "versions": versions,
                   "python": platform.python_version(), "platform": platform.platform(),
                   "matrix_sha256": digest(HERE / "sdk_asgi_matrix.py"), "runs": {}}
        for mode in ("original", "candidate"):
            run_stage(output, mode, [sys.executable, "-B", str(output / "run_matrix.py"), mode, "publication"], env)
            result = json.loads((output / f"evidence/runs/{mode}-publication/result.json").read_text())
            summary["runs"][mode] = summarized(result, expected["runs"][mode]["cases"])
        # Whitelist summary contains no local paths, tokens, session IDs or raw replies.
        (output / "PUBLIC_SUMMARY.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    finally:
        verify_sdk(sdk, manifest)
        verify_sdk(output / "sdk-original/mcp", manifest)
    print("Reproduction matched: original 5 positives / 9 counterexamples / 1 policy N/A; candidate 15/15.")
    print("Phase 2 remains BLOCK. Raw logs are private in the requested output directory.")
    print("PUBLIC_SUMMARY.json is the path-free summary; review it before sharing.")


if __name__ == "__main__":
    main()
