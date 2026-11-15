"""R006 current-run + fresh-current-checkout identity gate (SAFE T0).

A stored G05 receipt is only a locator/witness. Canonical admission also
rechecks the exact current checkout bytes/Manifest/ignored+untracked state,
authenticates the current GitHub Run and the exact in-progress Job via public
GitHub APIs, and binds all of them to the verified owner grant. No REST/MCP
request bytes or ordinary environment flag can mint execution authority.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import urllib.error
import urllib.request

from .lbe_owner_grant import D4VerifiedOwnerGrant

_REPO = "chinanjjohn2012/mac-file-gateway"
_PR = 114
_RECEIPT_MARKER = "MFG_G05_R006_RECEIPT_V1"
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_JOB = re.compile(r"[A-Za-z0-9_.-]{1,120}\Z")
_MAX_RECEIPT = 4096
_MAX_RESPONSE = 512 * 1024
_TOKEN = object()


class D4R006RuntimeIdentityDenied(ValueError):
    """Current checkout/run identity is absent, stale or mismatched."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class D4VerifiedRuntimeIdentity:
    """Verifier-produced current run identity; not directly constructible."""

    __slots__ = ("_base_sha", "_head_sha", "_head_tree", "_manifest_sha256",
                 "_run_id", "_run_attempt", "_job_id", "_checkout_root", "_pid")

    def __init__(self, token, *, base_sha, head_sha, head_tree,
                 manifest_sha256, run_id, run_attempt, job_id,
                 checkout_root):
        if token is not _TOKEN:
            raise D4R006RuntimeIdentityDenied(
                "runtime identity cannot be directly constructed")
        self._base_sha = base_sha
        self._head_sha = head_sha
        self._head_tree = head_tree
        self._manifest_sha256 = manifest_sha256
        self._run_id = run_id
        self._run_attempt = run_attempt
        self._job_id = job_id
        self._checkout_root = checkout_root
        self._pid = os.getpid()

    @property
    def base_sha(self): return self._base_sha
    @property
    def head_sha(self): return self._head_sha
    @property
    def head_tree(self): return self._head_tree
    @property
    def manifest_sha256(self): return self._manifest_sha256
    @property
    def run_id(self): return self._run_id
    @property
    def run_attempt(self): return self._run_attempt
    @property
    def job_id(self): return self._job_id
    @property
    def checkout_root(self): return self._checkout_root

    def check_grant(self, grant: object) -> None:
        if os.getpid() != self._pid or type(grant) is not D4VerifiedOwnerGrant:
            raise D4R006RuntimeIdentityDenied("runtime identity process/grant changed")
        a = grant.attempt
        if (a.base_sha != self._base_sha or a.head_sha != self._head_sha
                or a.head_tree != self._head_tree
                or a.manifest_sha256 != self._manifest_sha256
                or a.run_id != self._run_id
                or a.run_attempt != self._run_attempt):
            raise D4R006RuntimeIdentityDenied(
                "owner grant does not bind current checkout/run")


def _strict_json(raw: bytes, max_size: int, label: str):
    if type(raw) is not bytes or not 0 < len(raw) <= max_size:
        raise D4R006RuntimeIdentityDenied("invalid " + label + " bytes")
    def pairs(items):
        out = {}
        for key, value in items:
            if type(key) is not str or key in out:
                raise D4R006RuntimeIdentityDenied(
                    "duplicate/non-string " + label + " field")
            out[key] = value
        return out
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise D4R006RuntimeIdentityDenied("malformed " + label + " JSON") from None


def _receipt(value: bytes) -> dict[str, object]:
    receipt = _strict_json(value, _MAX_RECEIPT, "G05 receipt")
    fields = {
        "marker", "repo", "pr", "head_sha", "head_tree", "manifest_sha256",
        "run_id", "run_attempt", "job_name", "checkout_root",
        "checkout_identity", "checkout_credentials_clean",
    }
    if type(receipt) is not dict or set(receipt) != fields:
        raise D4R006RuntimeIdentityDenied("G05 receipt schema mismatch")
    identity = receipt["checkout_identity"]
    if (receipt["marker"] != _RECEIPT_MARKER or receipt["repo"] != _REPO
            or receipt["pr"] != _PR
            or type(receipt["head_sha"]) is not str
            or _SHA40.fullmatch(receipt["head_sha"]) is None
            or type(receipt["head_tree"]) is not str
            or _SHA40.fullmatch(receipt["head_tree"]) is None
            or type(receipt["manifest_sha256"]) is not str
            or _SHA64.fullmatch(receipt["manifest_sha256"]) is None
            or type(receipt["run_id"]) is not int or receipt["run_id"] <= 0
            or type(receipt["run_attempt"]) is not int
            or receipt["run_attempt"] <= 0
            or type(receipt["job_name"]) is not str
            or _JOB.fullmatch(receipt["job_name"]) is None
            or type(receipt["checkout_root"]) is not str
            or not receipt["checkout_root"].startswith("/")
            or type(identity) is not list or len(identity) != 6
            or any(type(x) is not int for x in identity)
            or receipt["checkout_credentials_clean"] is not True):
        raise D4R006RuntimeIdentityDenied("invalid G05 receipt identity")
    return receipt


def _git(root: Path, *argv: str, allow_missing: bool = False) -> bytes:
    executable = "/usr/bin/git" if Path("/usr/bin/git").is_file() else "git"
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    result = subprocess.run(
        [executable, *argv], cwd=root, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=30,
    )
    allowed = (0, 1) if allow_missing else (0,)
    if result.returncode not in allowed:
        raise D4R006RuntimeIdentityDenied(
            "current checkout Git admission unavailable")
    return result.stdout


def _nul_paths(raw: bytes) -> set[str]:
    if raw and not raw.endswith(b"\0"):
        raise D4R006RuntimeIdentityDenied("current checkout Git output malformed")
    try:
        values = [x.decode("utf-8", "strict") for x in raw.split(b"\0") if x]
    except UnicodeDecodeError:
        raise D4R006RuntimeIdentityDenied("current checkout path is non-UTF8") from None
    if len(values) != len(set(values)):
        raise D4R006RuntimeIdentityDenied("current checkout path list duplicated")
    return set(values)


def _checkout_identity(root: Path) -> list[int]:
    st = root.lstat()
    if not stat.S_ISDIR(st.st_mode) or root.is_symlink():
        raise D4R006RuntimeIdentityDenied("current checkout root is unsafe")
    return [st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_ctime_ns]


def _verify_local_checkout_credentials(root: Path) -> None:
    rows = _git(
        root, "config", "--local", "--get-regexp",
        r"^(credential\..*|http\..*\.extraheader)$", allow_missing=True)
    if rows:
        raise D4R006RuntimeIdentityDenied(
            "current checkout persisted credentials are present")
    remotes = _git(
        root, "config", "--local", "--get-regexp",
        r"^remote\..*\.url$", allow_missing=True)
    for row in remotes.decode("utf-8", "replace").splitlines():
        _key, _sep, value = row.partition(" ")
        lower = value.lower()
        if ((lower.startswith("https://") or lower.startswith("http://"))
                and "@" in value.split("/", 3)[2]):
            raise D4R006RuntimeIdentityDenied(
                "current checkout remote URL embeds credentials")


def _fresh_checkout_receipt(
    stored: dict[str, object], *, environ=None,
) -> bytes:
    """Re-run current checkout admission using only trusted local primitives."""
    env = os.environ if environ is None else environ
    root = Path(stored["checkout_root"])
    before_identity = _checkout_identity(root)
    if before_identity != stored["checkout_identity"]:
        raise D4R006RuntimeIdentityDenied("checkout root identity changed")

    if _git(root, "config", "--local", "--bool", "core.filemode").strip() != b"true":
        raise D4R006RuntimeIdentityDenied("current checkout core.filemode unsafe")
    head = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    tree = _git(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    if head != stored["head_sha"] or tree != stored["head_tree"]:
        raise D4R006RuntimeIdentityDenied("current checkout Head/Tree changed")
    if _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all"):
        raise D4R006RuntimeIdentityDenied(
            "current checkout tracked/untracked state changed")
    other = _nul_paths(
        _git(root, "ls-files", "--others", "--exclude-standard", "-z"))
    ignored = _nul_paths(
        _git(root, "ls-files", "--others", "--ignored", "--exclude-standard", "-z"))
    if other or ignored:
        raise D4R006RuntimeIdentityDenied(
            "current checkout contains untracked/ignored inputs")
    tracked = _nul_paths(_git(root, "ls-files", "--cached", "-z"))
    flags = _nul_paths(_git(root, "ls-files", "-v", "-z"))
    if flags != {"H " + path for path in tracked}:
        raise D4R006RuntimeIdentityDenied("current checkout index flags changed")

    manifest = root / "MANIFEST.sha256"
    if manifest.is_symlink() or not manifest.is_file():
        raise D4R006RuntimeIdentityDenied("current Manifest is not regular")
    try:
        raw_manifest = manifest.read_bytes()
        lines = raw_manifest.decode("ascii").splitlines()
    except (OSError, UnicodeError):
        raise D4R006RuntimeIdentityDenied("current Manifest unreadable") from None
    if hashlib.sha256(raw_manifest).hexdigest() != stored["manifest_sha256"]:
        raise D4R006RuntimeIdentityDenied("current Manifest digest changed")
    listed = []
    for row in lines:
        if "  ./" not in row:
            raise D4R006RuntimeIdentityDenied("current Manifest row malformed")
        digest, name = row.split("  ./", 1)
        if _SHA64.fullmatch(digest) is None or not name:
            raise D4R006RuntimeIdentityDenied("current Manifest row invalid")
        parts = Path(name).parts
        if Path(name).is_absolute() or any(x in ("", ".", "..") for x in parts):
            raise D4R006RuntimeIdentityDenied("current Manifest path unsafe")
        path = root / name
        if path.is_symlink():
            raise D4R006RuntimeIdentityDenied("current Manifest path is symlink")
        try:
            st = path.stat()
            data = path.read_bytes()
        except OSError:
            raise D4R006RuntimeIdentityDenied("current Manifest path unavailable") from None
        if not stat.S_ISREG(st.st_mode) or hashlib.sha256(data).hexdigest() != digest:
            raise D4R006RuntimeIdentityDenied("current tracked source digest changed")
        listed.append(name)
    if listed != sorted(set(listed)):
        raise D4R006RuntimeIdentityDenied("current Manifest ordering invalid")
    if set(listed) != tracked - {"MANIFEST.sha256"}:
        raise D4R006RuntimeIdentityDenied("current Manifest file set changed")
    _verify_local_checkout_credentials(root)
    after_identity = _checkout_identity(root)
    if before_identity != after_identity:
        raise D4R006RuntimeIdentityDenied("checkout root changed during fresh G05")

    expected_env = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": _REPO,
        "GITHUB_RUN_ID": str(stored["run_id"]),
        "GITHUB_RUN_ATTEMPT": str(stored["run_attempt"]),
        "GITHUB_JOB": stored["job_name"],
        "G05_EXPECTED_HEAD": stored["head_sha"],
    }
    if any(env.get(k) != v for k, v in expected_env.items()):
        raise D4R006RuntimeIdentityDenied("fresh G05 run/job context changed")
    fresh = {
        "marker": _RECEIPT_MARKER, "repo": _REPO, "pr": _PR,
        "head_sha": head, "head_tree": tree,
        "manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
        "run_id": stored["run_id"], "run_attempt": stored["run_attempt"],
        "job_name": stored["job_name"], "checkout_root": str(root.resolve()),
        "checkout_identity": after_identity, "checkout_credentials_clean": True,
    }
    return (json.dumps(
        fresh, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ) + "\n").encode("ascii")


def _verify_run_and_job(
    receipt: dict[str, object], run_api_bytes: bytes, jobs_api_bytes: bytes,
    *, base_sha: str, head_sha: str, run_id: int, run_attempt: int,
) -> int:
    run = _strict_json(run_api_bytes, _MAX_RESPONSE, "GitHub run")
    if type(run) is not dict:
        raise D4R006RuntimeIdentityDenied("GitHub run is not an object")
    if (run.get("id") != run_id or run.get("run_attempt") != run_attempt
            or run.get("event") != "pull_request"
            or run.get("head_sha") != head_sha
            or run.get("status") != "in_progress"
            or run.get("conclusion") is not None
            or type(run.get("repository")) is not dict
            or run["repository"].get("full_name") != _REPO
            or type(run.get("head_repository")) is not dict
            or run["head_repository"].get("full_name") != _REPO):
        raise D4R006RuntimeIdentityDenied("GitHub run identity/status mismatch")
    prs = run.get("pull_requests")
    if type(prs) is not list or len(prs) != 1 or type(prs[0]) is not dict:
        raise D4R006RuntimeIdentityDenied("GitHub run PR binding missing")
    item = prs[0]
    if (item.get("number") != _PR or type(item.get("head")) is not dict
            or type(item.get("base")) is not dict
            or item["head"].get("sha") != head_sha
            or item["base"].get("sha") != base_sha):
        raise D4R006RuntimeIdentityDenied("GitHub run Base/Head/PR mismatch")

    payload = _strict_json(jobs_api_bytes, _MAX_RESPONSE, "GitHub jobs")
    if (type(payload) is not dict or type(payload.get("jobs")) is not list
            or len(payload["jobs"]) > 100):
        raise D4R006RuntimeIdentityDenied("GitHub jobs response malformed")
    matches = [
        job for job in payload["jobs"]
        if type(job) is dict and job.get("name") == receipt["job_name"]
    ]
    if len(matches) != 1:
        raise D4R006RuntimeIdentityDenied("exact current GitHub job not found")
    job = matches[0]
    if (type(job.get("id")) is not int or job["id"] <= 0
            or job.get("run_id") != run_id
            or job.get("run_attempt") != run_attempt
            or job.get("head_sha") != head_sha
            or job.get("status") != "in_progress"
            or job.get("conclusion") is not None):
        raise D4R006RuntimeIdentityDenied("GitHub job identity/status mismatch")
    return job["id"]


def verify_r006_runtime_identity_t0(
    grant: object, receipt_bytes: bytes, run_api_bytes: bytes,
    jobs_api_bytes: bytes, fresh_receipt_bytes: bytes, *, environ=None,
) -> D4VerifiedRuntimeIdentity:
    """Bind owner grant to exact current run/job AND freshly rechecked checkout."""
    if type(grant) is not D4VerifiedOwnerGrant:
        raise D4R006RuntimeIdentityDenied("owner grant must be verified first")
    receipt = _receipt(receipt_bytes)
    fresh = _receipt(fresh_receipt_bytes)
    if fresh != receipt:
        raise D4R006RuntimeIdentityDenied("stored G05 receipt is stale/current checkout differs")
    a = grant.attempt
    if (receipt["head_sha"] != a.head_sha
            or receipt["head_tree"] != a.head_tree
            or receipt["manifest_sha256"] != a.manifest_sha256
            or receipt["run_id"] != a.run_id
            or receipt["run_attempt"] != a.run_attempt):
        raise D4R006RuntimeIdentityDenied("G05 receipt does not match owner grant")
    job_id = _verify_run_and_job(
        receipt, run_api_bytes, jobs_api_bytes,
        base_sha=a.base_sha, head_sha=a.head_sha,
        run_id=a.run_id, run_attempt=a.run_attempt)

    env = os.environ if environ is None else environ
    expected = {
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": _REPO, "GITHUB_RUN_ID": str(a.run_id),
        "GITHUB_RUN_ATTEMPT": str(a.run_attempt),
        "GITHUB_JOB": receipt["job_name"], "G05_EXPECTED_HEAD": a.head_sha,
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
    }
    if any(type(env.get(k)) is not str or env.get(k) != v
           for k, v in expected.items()):
        raise D4R006RuntimeIdentityDenied("local GitHub runner claims mismatch")
    return D4VerifiedRuntimeIdentity(
        _TOKEN, base_sha=a.base_sha, head_sha=a.head_sha,
        head_tree=a.head_tree, manifest_sha256=a.manifest_sha256,
        run_id=a.run_id, run_attempt=a.run_attempt, job_id=job_id,
        checkout_root=receipt["checkout_root"])


def _read_receipt(path: str) -> bytes:
    if type(path) is not str or not path.startswith("/") or len(path) > 1024:
        raise D4R006RuntimeIdentityDenied("invalid G05 receipt path")
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or not 0 < before.st_size <= _MAX_RECEIPT):
            raise D4R006RuntimeIdentityDenied("unsafe G05 receipt file")
        data = os.read(fd, _MAX_RECEIPT + 1)
        after = os.fstat(fd)
        if (len(data) != before.st_size
                or (before.st_dev, before.st_ino, before.st_size,
                    before.st_mtime_ns, before.st_ctime_ns, before.st_mode)
                != (after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns, after.st_mode)):
            raise D4R006RuntimeIdentityDenied("G05 receipt changed while reading")
        return data
    except OSError:
        raise D4R006RuntimeIdentityDenied("G05 receipt unavailable") from None
    finally:
        if fd >= 0:
            os.close(fd)


def _fetch_json(opener, url: str, label: str) -> bytes:
    request = urllib.request.Request(
        url, method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "mac-file-gateway-r007-runtime-identity/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with opener.open(request, timeout=5) as response:
            if getattr(response, "status", None) != 200 or response.geturl() != url:
                raise D4R006RuntimeIdentityDenied(label + " HTTP identity mismatch")
            if not response.headers.get("Content-Type", "").lower().startswith(
                    "application/json"):
                raise D4R006RuntimeIdentityDenied(label + " is not JSON")
            link = response.headers.get("Link", "")
            if 'rel="next"' in link:
                raise D4R006RuntimeIdentityDenied(label + " is paginated")
            data = response.read(_MAX_RESPONSE + 1)
            if not 0 < len(data) <= _MAX_RESPONSE:
                raise D4R006RuntimeIdentityDenied(label + " response oversized")
            return data
    except (OSError, urllib.error.URLError, urllib.error.HTTPError):
        raise D4R006RuntimeIdentityDenied(label + " transport unavailable") from None


def fetch_verified_r006_runtime_identity(
    grant: object, receipt_path: str,
) -> D4VerifiedRuntimeIdentity:
    """Canonical current-run GitHub API + fresh checkout re-admission."""
    if type(grant) is not D4VerifiedOwnerGrant:
        raise D4R006RuntimeIdentityDenied("unverified owner grant")
    receipt_bytes = _read_receipt(receipt_path)
    receipt = _receipt(receipt_bytes)
    fresh = _fresh_checkout_receipt(receipt, environ=os.environ)
    run_id = grant.attempt.run_id
    run_url = f"https://api.github.com/repos/{_REPO}/actions/runs/{run_id}"
    jobs_url = (
        f"https://api.github.com/repos/{_REPO}/actions/runs/{run_id}/jobs"
        "?filter=latest&per_page=100")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _NoRedirect(),
    )
    run = _fetch_json(opener, run_url, "GitHub run")
    jobs = _fetch_json(opener, jobs_url, "GitHub jobs")
    return verify_r006_runtime_identity_t0(
        grant, receipt_bytes, run, jobs, fresh, environ=os.environ)
