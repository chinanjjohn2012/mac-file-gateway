# Audit 窗口放行 Hard 行 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 有效 Audit 在到期前放行范围内新引入的 Hard 行，并让读、搜索、diff、替换和整文件写入看到这些原文。

**Architecture:** `SensitiveAudit.allows(path)` 已经表示「这个路径现在落在有效窗口内」。写入侧在拒绝 Hard 之前先问它；显示侧用同一个答案清掉 Hard 和 heuristic 的显示标记。`classify` 的种类不变。`scan_unavailable` 仍在这两步之前整文件失败。

**Tech Stack:** Python 3、现有 Gateway / pytest。测试命令用仓库里的 `.venv/bin/python -m pytest`。

## Global Constraints

- 不新增参数。命令行仍是 `--sensitive-content-audit-path` 与 `--sensitive-content-audit-until`。`gateway.json` 仍是 `sensitive_content.mode = "audit"`、`paths`、`expires_at`。
- 按行哈希批准保留，只服务于没有落在有效 Audit 范围内的路径。
- `scan_unavailable` 仍整文件拒绝，读、搜索、diff 仍整文件打码。
- Audit 不扩大写范围，不影响其他工作区。
- 到期同时看 UTC 和启动时算出的 monotonic 截止时间。时钟回拨不延长。
- `/info` 和 `/workspaces` 里的 `sensitive_content.read_redaction_enabled` 保持 `true`。
- 范围内的 Hard 行不进入批准暂存，不向 stderr 打 token。
- 靠 Audit 放行的写入，在原子安装前再查一次 Audit。此时到期则不写文件。
- 现有 warning 文案保持不变：`Temporary heuristic write audit active; inspect content locally.`
- 分类结果仍是 Hard 或 heuristic。

---

## 文件

- 修改 `gateway/visibility.py`：`display_flags` 在有效 Audit 路径上显示 Hard 和 heuristic 行。
- 修改 `gateway/core.py`：把 `sensitive_audit.allows` 传给显示策略。
- 修改 `gateway/writer.py`：有效 Audit 放行 Hard 写入，整文件覆盖改看显示标记，安装前复查。
- 修改 `gateway/__main__.py`：两个参数的帮助文本。
- 修改 `docs/SENSITIVE_CONTENT_POLICY.md`：第 4 节和第 4.1 节。
- 修改 `tests/test_sensitive_content_v3.py`、`tests/test_sensitive_content_regression.py`。
- 测试新增放在 `tests/test_sensitive_content_regression.py`。不新建模块。

### Task 1: 有效 Audit 路径上的原文显示

**Files:**
- Modify: `gateway/visibility.py:81-170`
- Modify: `gateway/core.py:292-294`
- Test: `tests/test_sensitive_content_regression.py`

**Interfaces:**
- Consumes: `SensitiveAudit.allows(canonical_path: str) -> bool`
- Produces: `SensitiveContentPolicy.__init__(..., *, line_visible=None, path_visible: Callable[[str], bool] | None = None)`。`path_visible` 为真时，该路径上的 Hard 与 heuristic 行不打码。`scan_unavailable` 仍整文件打码。

- [ ] **Step 1: Write the failing test**

在 `tests/test_sensitive_content_regression.py` 末尾追加：

```python
def test_active_audit_shows_hard_and_heuristic_lines_until_expiry(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "other").mkdir()
    until = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    gateway = Gateway(
        root, allow_write=True, write_paths=("src", "other"),
        sensitive_content_audit_paths=("src",),
        sensitive_content_audit_until=until,
    )
    hard = "password = 'hardcoded-secret'\n"
    heuristic = 'token = f"{runtime}" +\n'
    (root / "src" / "hard.py").write_text(hard)
    (root / "src" / "soft.py").write_text(heuristic)
    (root / "other" / "hard.py").write_text(hard)
    try:
        assert gateway.info()["write_policy"]["sensitive_content"]["read_redaction_enabled"] is True
        shown = gateway.read_file("src/hard.py")
        assert shown["redacted_lines"] == 0
        assert "hardcoded-secret" in shown["content"]
        _flags, findings = gateway._visibility.classify("src/hard.py", hard.encode())
        assert any(kind == "hard" for _number, kind in findings)
        assert "runtime" in gateway.read_file("src/soft.py")["content"]
        assert gateway.search_files("hardcoded-secret", file_glob="hard.py")["matches"]
        hidden = gateway.read_file("other/hard.py")
        assert "hardcoded-secret" not in hidden["content"]
        assert hidden["redacted_lines"] == 1
        gateway.sensitive_audit.deadline = 0.0
        expired = gateway.read_file("src/hard.py")
        assert "hardcoded-secret" not in expired["content"]
        assert expired["redacted_lines"] == 1
    finally:
        gateway.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_sensitive_content_regression.py::test_active_audit_shows_hard_and_heuristic_lines_until_expiry -q --tb=short`

Expected: FAIL，因为 `hardcoded-secret` 仍被打码，不在 `src/hard.py` 的读取结果里。

- [ ] **Step 3: Write minimal implementation**

`gateway/visibility.py` 的构造函数改为：

```python
def __init__(self, protected_paths: tuple[str, ...] = (), *,
             line_visible: Callable[[str, str], bool] | None = None,
             path_visible: Callable[[str], bool] | None = None):
    del protected_paths
    self._line_visible = line_visible or (lambda _path, _line: False)
    self._path_visible = path_visible or (lambda _path: False)
```

`display_flags` 换成：

```python
def display_flags(self, canonical_path: str, text: str) -> list[bool]:
    """Classification flags with Audit-scoped or granted lines left visible.

    Findings stay Hard or heuristic. scan_unavailable is never revealed.
    A grant reveals only its exact Hard line. An active Audit path reveals
    every Hard and heuristic line in that file.
    """
    if not canonical_path:
        return self.sensitive_flags(text)
    flags, findings = self.classify(canonical_path, text.encode("utf-8"))
    lines = source_lines(text, canonical_path)
    if any(kind == "scan_unavailable" for _, kind in findings) or len(flags) != len(lines):
        return [True] * max(1, len(lines))
    audit = self._path_visible(canonical_path)
    revealed: set[int] = set()
    for number, kind in findings:
        if not 1 <= number <= len(lines):
            continue
        if audit and kind in {"hard", "heuristic"}:
            revealed.add(number)
        elif kind == "hard" and self._line_visible(canonical_path, lines[number - 1]):
            revealed.add(number)
    if not revealed:
        return flags
    return [False if index + 1 in revealed else flag for index, flag in enumerate(flags)]
```

`gateway/core.py` 装配显示策略时加上：

```python
self._visibility = SensitiveContentPolicy(
    self._protected_content_paths,
    line_visible=self.sensitive_grants.line_visible,
    path_visible=self.sensitive_audit.allows,
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_sensitive_content_regression.py::test_active_audit_shows_hard_and_heuristic_lines_until_expiry tests/test_sensitive_content_status.py tests/test_sensitive_content_v3.py::test_v3_scan_integrity_failure_is_file_level_and_not_audit_bypass -q --tb=short`

Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add gateway/visibility.py gateway/core.py tests/test_sensitive_content_regression.py
git commit -m "$(cat <<'EOF'
Show Hard and heuristic lines inside an active audit path.

Expiry and paths outside the audit keep redaction, and scan failures stay fully hidden.
EOF
)"
```

### Task 2: 有效 Audit 放行 Hard 写入

**Files:**
- Modify: `gateway/writer.py:128-167` 和 `gateway/writer.py:247-256`
- Modify: `tests/test_sensitive_content_v3.py:129-150`
- Modify: `tests/test_sensitive_content_regression.py:214-237`、`347-372`
- Test: `tests/test_sensitive_content_regression.py`

**Interfaces:**
- Consumes: `SensitiveAudit.allows(canonical_path: str) -> bool`，Task 1 的 `display_flags`
- Produces: `_reject_candidate` 在路径被有效 Audit 覆盖时不拒绝新引入的 Hard 行，并在这种放行时返回 `True`，让现有安装前复查生效。整文件覆盖改用 `display_flags`。

- [ ] **Step 1: Write the failing test**

在 `tests/test_sensitive_content_regression.py` 末尾追加：

```python
def test_active_audit_writes_hard_lines_without_a_pending_grant(tmp_path, capsys):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "other").mkdir()
    until = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    gateway = Gateway(
        root, allow_write=True, write_paths=("src", "other"),
        sensitive_content_audit_paths=("src",),
        sensitive_content_audit_until=until,
    )
    hard = "password = 'hardcoded-secret'\n"
    try:
        preview = gateway.create_file("src/secret.py", hard)
        assert preview["applied"] is False
        assert "hardcoded-secret" in preview["diff"]
        assert preview["warnings"] == ["Temporary heuristic write audit active; inspect content locally."]
        applied = gateway.create_file("src/secret.py", hard, dry_run=False)
        assert applied["applied"] is True
        assert "sensitive approval" not in capsys.readouterr().err
        read = gateway.read_file("src/secret.py")
        replaced = gateway.replace_text(
            "src/secret.py", "hardcoded-secret", "other-secret",
            read["file_sha256"], dry_run=False,
        )
        assert replaced["applied"] is True
        assert "other-secret" in gateway.read_file("src/secret.py")["content"]
        current = gateway.read_file("src/secret.py")
        overwritten = gateway.write_file(
            "src/secret.py", "password = 'third-secret'\n", current["file_sha256"], dry_run=False,
        )
        assert overwritten["applied"] is True
        with pytest.raises(GatewayError) as outside:
            gateway.create_file("other/secret.py", hard, dry_run=False)
        assert outside.value.details["rule_id"] == "CREDENTIAL_HARD"
        assert not (root / "other" / "secret.py").exists()
        gateway.sensitive_audit.deadline = 0.0
        with pytest.raises(GatewayError) as expired:
            gateway.create_file("src/next.py", hard, dry_run=False)
        assert expired.value.details["rule_id"] == "CREDENTIAL_HARD"
        assert not (root / "src" / "next.py").exists()
    finally:
        gateway.close()


def test_hard_literal_without_audit_stays_rejected_and_redacted(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    hard = "password = 'hardcoded-secret'\n"
    try:
        with pytest.raises(GatewayError) as blocked:
            gateway.create_file("secret.py", hard, dry_run=False)
        assert blocked.value.details["rule_id"] == "CREDENTIAL_HARD"
        assert not (root / "secret.py").exists()
        (root / "secret.py").write_text(hard)
        assert "hardcoded-secret" not in gateway.read_file("secret.py")["content"]
    finally:
        gateway.close()


def test_hard_write_is_rejected_when_audit_expires_before_install(tmp_path, monkeypatch):
    from gateway import write_storage
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    until = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    gateway = Gateway(root, allow_write=True, write_paths=("src",),
                      sensitive_content_audit_paths=("src",),
                      sensitive_content_audit_until=until)
    original_install = write_storage.install_file

    def expire_before_install(parent, name, raw, mode, verify, *, create):
        gateway.sensitive_audit.deadline = 0.0
        return original_install(parent, name, raw, mode, verify, create=create)

    try:
        monkeypatch.setattr(write_storage, "install_file", expire_before_install)
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("src/secret.py", "password = 'hardcoded-secret'\n", dry_run=False)
        assert exc.value.code == "sensitive_content"
        assert not (root / "src" / "secret.py").exists()
    finally:
        gateway.close()
```

把 `test_bearer_exception_keeps_literal_and_other_credential_fields_hard` 里 Audit 已打开时的拒绝断言换成写入成功、读回原文，并保留分类仍是 Hard：

```python
preview = gateway.create_file("candidate.py", source)
assert preview["applied"] is False
assert not (root / "candidate.py").exists()
applied = gateway.create_file("candidate.py", source, dry_run=False)
assert applied["applied"] is True
read = gateway.read_file("candidate.py")
assert read["redacted_lines"] == 0
assert source.strip() in read["content"]
_flags, findings = gateway._visibility.classify("candidate.py", source.encode())
assert any(kind == "hard" for _number, kind in findings)
```

`test_audit_heuristic_only_scoped_and_hard_secrets_rejected` 中 `src/ordinary.py` 的 `pytest.raises` 换成：

```python
gateway.create_file("src/ordinary.py", "password = 'hardcoded-secret'\n", dry_run=False)
assert "hardcoded-secret" in gateway.read_file("src/ordinary.py")["content"]
```

`other/b.py` 的拒绝断言不动。

`test_http_contextvar_cycle_and_temporary_audit` 末尾换成：

```python
hard = client.post("/create", json={"path": "src/hard.py",
                                    "content": "password = 'hardcoded'\n",
                                    "dry_run": False})
assert hard.status_code == 200
read_hard = client.get("/read", params={"path": "src/hard.py"})
assert "password = 'hardcoded'" in read_hard.json()["content"]
```

`test_audit_does_not_allow_structured_kubernetes_credentials` 的拒绝断言换成：

```python
applied = gateway.create_file("src/cluster.yaml", payload, dry_run=False)
assert applied["applied"] is True
assert payload.strip() in gateway.read_file("src/cluster.yaml")["content"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_sensitive_content_regression.py::test_active_audit_writes_hard_lines_without_a_pending_grant tests/test_sensitive_content_regression.py::test_hard_write_is_rejected_when_audit_expires_before_install -q --tb=short`

Expected: FAIL，`create_file` 抛出 `CREDENTIAL_HARD`。

- [ ] **Step 3: Write minimal implementation**

`gateway/writer.py` 的 `_reject_candidate` 在算出 `introduced` 之后改成：

```python
introduced = self._introduced(canonical, raw, previous, source, candidate)
audit_covers = self.gateway.sensitive_audit.allows(canonical)
ungranted = [
    (number, text) for number, text, kind in introduced
    if kind == "hard" and not audit_covers
    and not self.gateway.sensitive_grants.line_visible(canonical, text)
]
if ungranted:
    pending_id, token = self.gateway.pending.remember(
        workspace=self.gateway.workspace_name, path=canonical, lines=ungranted,
    )
    announce_pending(pending_id, token)
    raise GatewayError("sensitive_content",
        "Credential-like content is not accepted by this gateway's write policy.",
        details={
            "rule_id": "CREDENTIAL_HARD",
            "line": ungranted[0][0],
            "severity": "hard",
            "pending_id": pending_id,
            "lines": [{"line": number, "line_sha256": line_sha256(text)} for number, text in ungranted],
        })
heuristic = [number for number, _text, kind in introduced if kind == "heuristic"]
if heuristic and not audit_covers:
    raise GatewayError("sensitive_content",
        "Credential-like content is not accepted by this gateway's write policy.",
        details={"rule_id": "CREDENTIAL_ASSIGNMENT", "line": heuristic[0], "severity": "heuristic"})
return audit_covers and any(kind in {"hard", "heuristic"} for _number, _text, kind in introduced)
```

整文件覆盖那一段，把分类标记换成显示标记：

```python
source_text = snapshot.raw.decode("utf-8-sig")
source_has_sensitive = any(self.gateway._visibility.display_flags(canonical, source_text))
if operation == "write" and source_has_sensitive:
    raise GatewayError("sensitive_content", "This source contains redacted data and cannot be whole-file overwritten through the gateway.")
```

上面的 `scan_unavailable` 检查继续使用 `source_classification`，不要删。

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
.venv/bin/python -m pytest tests/test_sensitive_content_regression.py tests/test_sensitive_content_v3.py tests/test_sensitive_grants.py tests/test_sensitive_content_status.py tests/test_write_http.py -q --tb=line
```

Expected: PASS。没有 Audit 的 Hard 用例仍然拒绝。`test_v3_scan_integrity_failure_is_file_level_and_not_audit_bypass` 和 `test_audit_expiry_during_install_prevents_commit` 保持通过。

- [ ] **Step 5: Commit**

```bash
git add gateway/writer.py tests/test_sensitive_content_v3.py tests/test_sensitive_content_regression.py
git commit -m "$(cat <<'EOF'
Admit Hard lines while a sensitive-content audit is active.

The same expiry check runs before install, and paths outside the audit stay rejected.
EOF
)"
```

### Task 3: 政策与命令帮助

**Files:**
- Modify: `docs/SENSITIVE_CONTENT_POLICY.md:144-168`
- Modify: `gateway/__main__.py:27-30`

**Interfaces:**
- Consumes: Task 2 的写入和显示行为
- Produces: 文档与帮助文本和该行为一致

- [ ] **Step 1: Update the policy**

第 4 节最后两句换成：

```markdown
Audit admits new heuristic and Hard findings inside its path until expiry,
and read, search, and diff show those lines. It cannot admit
`scan_unavailable`. Redaction outside the path, after expiry, and for
`scan_unavailable` stays active. File and path denial and all other write
permissions remain active.
```

第 4.1 节删掉 “Heuristic Audit cannot grant Hard lines.” 在 “`scan_unavailable` cannot be granted.” 后面写成：

```markdown
An active Audit admits Hard lines inside its path without a line-hash
grant. Outside that path, and after Audit expiry, an exact line-hash
grant is still required. A grant cannot admit `scan_unavailable`.
```

- [ ] **Step 2: Update the command help**

`gateway/__main__.py` 两处帮助改为：

```python
help="Temporary audit path that admits heuristic and Hard lines ('.' for this workspace); repeatable; requires --allow-write and --sensitive-content-audit-until"
```

```python
help="Temporary audit absolute UTC expiry for heuristic and Hard lines; must be in the future"
```

- [ ] **Step 3: Check the wording**

Run: `.venv/bin/python -m gateway --help`

Expected: 帮助里出现 `admits heuristic and Hard lines`，并且不再出现 `Temporary heuristic write audit path`。

- [ ] **Step 4: Commit**

```bash
git add docs/SENSITIVE_CONTENT_POLICY.md gateway/__main__.py
git commit -m "$(cat <<'EOF'
Document that an active audit admits and reveals Hard lines.

The command help matches the path and expiry flags operators already use.
EOF
)"
```
