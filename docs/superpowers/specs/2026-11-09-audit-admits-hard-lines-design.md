# Audit 窗口放行 Hard 行并可读

目标：已经配置的临时 Audit 在到期前，除了 heuristic，也放行范围内的 Hard 行，并且读、搜索、diff 能看到这些原文。不新增参数，不改分类。

## 已经确定

- 对话框方案不做。
- 配置入口不变。命令行仍是 `--sensitive-content-audit-path` 与 `--sensitive-content-audit-until`。`gateway.json` 仍是工作区 `sensitive_content.mode = "audit"`、`paths`、`expires_at`。
- 按行哈希批准保留，只服务于没有落在有效 Audit 范围内的路径。
- `scan_unavailable` 仍整文件拒绝，读、搜索、diff 仍整文件打码。
- Audit 不扩大写范围，不影响其他工作区。
- 到期同时看 UTC 和启动时算出的 monotonic 截止时间。时钟回拨不延长。
- `/info` 和 `/workspaces` 里的 `sensitive_content.read_redaction_enabled` 保持 `true`。打码仍然生效：范围外、到期后，以及 `scan_unavailable`。

## 写入

文件路径落在有效 Audit 内时，本次新引入的 Hard 行和 heuristic 行都允许写入。预览和正式写入都通过。分类结果仍是 Hard 或 heuristic。

路径不在范围内，或 Audit 已到期时，Hard 行继续走现有规则：未批准的是 `CREDENTIAL_HARD`，已有按行批准的原文可以写入。heuristic 行在范围外或到期后仍是 `CREDENTIAL_ASSIGNMENT`。

一次写入只要靠有效 Audit 才被放行，无论放行的是 Hard 还是 heuristic，都在原子安装前再查一次 Audit。此时已经到期则拒绝，不写文件。现有 warning 文案保持不变：`Temporary heuristic write audit active; inspect content locally.`

范围内的 Hard 行不进入批准暂存，不向 stderr 打 token。

## 读取

有效 Audit 覆盖的路径上，Hard 行和 heuristic 行在读、搜索、diff 中显示原文。同一显示结果用于替换和整文件写入：这些行不再算隐藏行，预览里的 diff 也包含原文。`classify` 的发现种类不变。

范围外的 Hard 行仍只按已有的行哈希批准显示。范围外的 heuristic 行继续打码。`scan_unavailable` 不因为 Audit 显示任何原文。

Audit 到期后，范围内的 Hard 行和 heuristic 行恢复打码。磁盘上已写下的文件不删除。

## 文档

`docs/SENSITIVE_CONTENT_POLICY.md` 第 4 节改为：有效 Audit 放行范围内新引入的 heuristic 和 Hard，并在读、搜索、diff 显示这两类原文。保留「不能放行 `scan_unavailable`」和「不能扩大写范围」。第 4.1 节写明：有效 Audit 范围内的 Hard 行由 Audit 放行；行哈希批准仍只用于范围外或到期后的 Hard 行，并且仍然不能放行 `scan_unavailable`。删掉「Audit 不能放行 Hard」这句。

命令行帮助里把 “Temporary heuristic write audit” 改成说明该窗口也放行 Hard 行。

## 测试

这些现有预期要改，因为它们断言「开着 Audit 仍然拒绝 Hard」：

- `tests/test_sensitive_content_v3.py` 的 `test_bearer_exception_keeps_literal_and_other_credential_fields_hard`：Audit 覆盖 `.` 时，预览和正式写入成功，读和搜索能看到字面量。`classify` 对这些字面量的发现仍是 Hard。
- `tests/test_sensitive_content_regression.py` 的 `test_audit_heuristic_only_scoped_and_hard_secrets_rejected`：`src` 下的 `password = 'hardcoded-secret'` 写入成功且能读回。`other/` 下的 heuristic 行仍然拒绝。
- 同文件 `test_http_contextvar_cycle_and_temporary_audit`：`src/hard.py` 的正式写入返回 200，读回能看到 `password = 'hardcoded'`。
- 同文件 `test_audit_does_not_allow_structured_kubernetes_credentials`：这些载荷在 `src` 的有效 Audit 下写入成功且能读回。

新增或并入现有测试：

- 没有 Audit 时，上述 Hard 字面量仍是 `CREDENTIAL_HARD`，读回仍打码。
- Audit 到期后，范围内新的 Hard 写入被拒绝；已经写在磁盘上的 Hard 行恢复打码。
- 原子安装前 Audit 到期时，Hard 写入不落盘。现有 heuristic 的安装前到期测试保持通过。
- `scan_unavailable` 在有效 Audit 下仍拒绝且整文件打码。`test_v3_scan_integrity_failure_is_file_level_and_not_audit_bypass` 保持原预期。
- `read_redaction_enabled` 的状态断言保持 `true`。
- 有效 Audit 范围内的 Hard 写入不产生 `pending_id`，stderr 不出现 `sensitive approval`。

不改没有打开 Audit 的 Hard 分类用例，包括 `test_lookup_change_preserves_hard_literal_protection`。
