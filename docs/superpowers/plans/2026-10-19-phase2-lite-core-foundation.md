# Phase 2 Lite Core Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付 A1/A2/A3 的配置声明、共享参数验证、Workspace 授权及纯内存任务状态机；不连接真实 Multi exec、OS 信号或 MCP 执行工具。

**Architecture:** 配置声明与运行时能力分离；WorkspaceService 是唯一业务授权入口。不可变 ExecutionRequest 经已签收的 CommandRunner 参数校验得到仅供规划的 ExecutionIntent；ExecRegistry 管理内部 ticket、1/Workspace 与 4/global 配额及模拟生命周期。所有生产入口继续拒绝执行激活，不提供模拟后端配置开关。

**Tech Stack:** 现有 Python 标准库、dataclasses、threading、pytest、Starlette/现有测试基础设施；官方 `mcp==1.30.0` 保持不变。没有新增产品依赖。

**Spec:** `docs/superpowers/specs/2026-10-19-phase2-lite-parallel-gates-design.md`，PR #11 固定 `ca1a17cc943b2f5b7f5cf43d9d77211fe090de40`；继承其中引用的 PR #8 Lite 规格。项目方已于本会话批准书面规格并同意编写计划；尚未提供 PR #11 独立设计复审通过的结论。本计划为待审实施草案，不把用户审批冒充 G0 的完整独立签收。

## Global Constraints

- 本轮范围仅 A1/A2/A3，达到 **G1 核心纯逻辑候选**，不是完整 Phase 2 Lite 实现计划。C1/G2、B1/G3、A4/B2/G4、G5 各有后续工作包；本轮不重跑 Q0、不修改其判定器。
- 默认执行关闭；`schema_version:1`；必须显式 workspace、exec.enabled 与非空 paths；根目录仅可由显式 `paths:["."]` 授权。runners 为可选路径映射，未指定时保留现有“scope 内最近 Pipfile，否则 direct”的后续运行语义；本轮不声称已验证 Pipfile 的原生执行身份。
- 每 Workspace 同时 1 个、全局 4 个已接纳任务；满额立即拒绝、不排队。服务端执行超时默认 60 秒、范围 1–300 秒；TERM grace 2 秒、独立 drain 2 秒、每输出流 48,000 字符是后续真实 Supervisor 的冻结值，本轮模型不得冒称实现了 OS 终止或输出回收。
- 不提供远程 job/query/recovery、跨 POST 取消、跨请求去重；断线不等于已启动命令结束。每次接纳至多一次 Popen attempt；本轮新 Multi 路径的真实 Popen/信号调用必须始终为零。
- 新增纯逻辑保持 Python 3.11+ 可导入、可测试；macOS 真实 Multi exec 仍须 Python 3.13+ 及已批准的 cwd/PGID 机制。不得提高 Legacy/file-only 的最低版本。
- 官方 SDK 不修改；不限制合法 JSON-RPC ID、不吞 SDK 通知、不将已知风险或 Q0 取证成功写成 SDK 资格 PASS。Task 2 CLOSED 保持原范围，不重新评审同一已签收修复来拖延本轮工作。
- 原有 Legacy 测试可在临时可信项目启动真实子进程；“Popen=0”针对本轮新增 Multi 核心路径，不能错误地给整套回归打全局补丁、使原真实执行测试失真。
- 项目代码执行不是 OS sandbox；目录声明和模拟 ticket 不提供 actual cwd、PGID 或凭据隔离资格。仅在独立候选分支实施；不更改运行实例、业务配置、Tunnel、release/ms1 或已安装 SDK。

## Review Focus

1. **声明被误当成能力：** 解析 exec.enabled=true 后，CLI、直接 app/MCP factory 或动态 invoke 意外启用执行；Task 1/4 必须覆盖所有入口并证明零派发/零 Popen。
2. **请求快照被改变：** 调用者修改 argv、同前缀目录 service/service-extra、拿 A 的准备结果交给 B；Task 2 检查不可变副本、组件级 scope 与重新授权。
3. **取消等待者提前释放资源：** HTTP waiter 离开、重复完成、服务关闭与接纳竞争，不能提前释放 slot 或 root；Task 3/4 用事件屏障证明唯一 owner 和释放一次。
4. **配额串行化文件 API：** 1/Workspace、4/global 达限时不得排队；其他 Workspace 文件操作仍能完成；Task 3/4 检查并发真实逻辑，禁止靠 sleep 通过。
5. **修复继承只是口头成立：** 计划分支包含文档不代表包含 PR #10；Task 1 固定代码基线，Task 2/4 重用原 validator 与回归，禁止复制出第二套 Go/pytest 解析器。

---

## 范围、基线与文件结构

### 两个不同的基线

本计划文档基于 PR #11 的 `ca1a17cc943b2f5b7f5cf43d9d77211fe090de40`，以保持设计差异独立。**未来代码工作区必须从已签收的 PR #10 提交 `cd345b0cb46f48b70c6e4478ae4d7d97269c5894` 建立隔离分支**，不从缺少修复的文档分支直接开发，不合并或移动 PR #10 的已签收头部。需在执行账本记录代码 BASE、批准后的计划 SHA、两个规格文件的固定来源；把批准的计划/规格原样放进该候选工作区后重建 Manifest。此举不等于批准合并 PR #10 到 release/ms1。

已核对的实现锚点（均为 PR #10 固定 SHA）：
- `gateway/workspaces_config.py`：WorkspaceSettings/GatewaySettings、parse_workspace_config/read_workspace_config；目前 exec 与 local_skills 只接受 enabled=false。
- `gateway/workspaces.py`：WorkspaceService.require/invoke/_operation/close；每个实际 Gateway 固定 allow_exec=False，文件 worker 的生命周期受 Condition 管理。
- `gateway/executor.py`：_clean_argv/_validate_command 已包含 D1/D2/R1；_MAX_ARGV=64、单项最多 1024 字符、总计最多 8192 字符。源 blob `4ce838f053cf3174d00c178a5a2d1440e56077d0`。
- `gateway/multi_fields.py`：_PHASE2 继续阻止 Multi run_command 和 Skills；不得移除该屏障。
- `gateway/multi_cli.py`、`gateway/http_multi.py`、`gateway/mcp_multi.py`：生产组装入口，必须各自检查未取得执行能力的配置。

| 文件 | 本轮职责 |
| --- | --- |
| 新增 gateway/exec_contracts.py | 不可变请求、规划结果、终态值对象；严格输入验证调用现有 validator |
| 新增 gateway/exec_policy.py | 不可变 WorkspaceExecSettings、exec 子配置解析、组件级 scope/runner 声明匹配及激活拒绝 |
| 新增 gateway/exec_registry.py | 无 SDK/无 subprocess 的 ticket/配额/生命周期内核 |
| 修改 gateway/workspaces_config.py | 将 exec 声明解析为类型；local_skills 仍严格关闭 |
| 修改 gateway/workspaces.py | 内部准备/模拟接纳、统一授权、关闭等待；文件 invoke 白名单不扩大 |
| 修改 gateway/multi_cli.py、gateway/http_multi.py、gateway/mcp_multi.py | 对 exec-enabled 声明的生产组装硬拒绝；不新增执行路由/工具 |
| 新增 tests/test_exec_core_policy.py、test_exec_core_prepare.py、test_exec_core_registry.py、test_exec_core_boundary.py | 四项任务各自的正反控 |
| 新增 tests/exec_core_helpers.py | 测试专用模拟 owner/屏障、计数器，不能进入产品模块 |
| 修改 docs/PROGRESS.md、MANIFEST.sha256 | 候选范围与真实验收边界；清单一致性 |

**不修改：** gateway/executor.py 的已签收语法实现、Legacy REST/MCP 行为、multi_fields 的执行禁止集合、requirements、run.sh/setup.sh 的产品配置及运行中的 Gateway。若确需超出此范围，先提出最小差异并重新评审，不在本计划中顺手重构。

### 关键设计细化（本计划提议，待评审后冻结）

- 将“配置语法可解析”和“可创建生产监听器”分离。内部 parse_workspace_config 可表示 exec.enabled=true；read_workspace_config 及生产 app/MCP/CLI 组装必须通过 assert_exec_runtime_unavailable，并对任何 enabled=true 抛 PrivateFileError。函数没有 allow_unsafe、测试模式或环境变量旁路。
- WorkspaceService 可在无监听器的内部测试中用已解析声明构建，但其所有 ctx.gateway 继续 allow_exec=False；任何 invoke 非文件操作一律先拒绝，不能通过 getattr 触及 run_command 或新增内部方法。
- ExecutionIntent 只证明语法和声明授权，不含可执行句柄/可用 OS 身份；runtime_ready 恒为 false。Pipfile 的实际发现、FD 租约和 cwd 执行身份留给 C1/A4，不能从“配置 runner=pipenv”推导其已安全可运行。
- SDK 无关的纯逻辑开发无需等待旧完整 SDK 合同变成 PASS。真实执行/真实 MCP 接入仍分别受 G2/G3 约束。

### Task 1: 类型化 exec 声明与不可绕过的运行时激活屏障

**Files:** 新增 gateway/exec_policy.py、tests/test_exec_core_policy.py；修改 workspaces_config.py、multi_cli.py、http_multi.py、mcp_multi.py；如现有测试直接断言 parser 必须拒绝 enabled=true，拆为“纯解析成功”与“生产入口拒绝”，保留原负控的零激活目的。

**Interfaces:**
- `WorkspaceExecSettings(enabled: bool = False, paths: tuple[str, ...] = (), runners: tuple[tuple[str, str], ...] = ())`，frozen dataclass。
- `parse_exec_policy(value: object) -> WorkspaceExecSettings`；只接受 dict，键为 enabled/paths/runners；runners 是 JSON `{relative_path: "direct"|"pipenv"}` 映射，默认空映射。
- WorkspaceSettings 末尾新增 `execution: WorkspaceExecSettings`，使用默认值保留既有位置参数构造兼容性。
- `assert_exec_runtime_unavailable(settings: GatewaySettings) -> None`：本阶段任何 Workspace 的 execution.enabled 为 true 就抛 PrivateFileError；不导入 SDK、不打开 FD、不启动进程。

- [ ] **Step 1 — 建立隔离代码工作区并核对继承。** 从上述 cd345b0 固定 BASE 创建新分支；确认 executor blob 和原 tests/test_phase2_argv.py 存在。用 `PATH="$PWD/.venv/bin:$PATH" bash verify.sh --require-mcp` 保存基线结果；依赖只装独立 venv。原 Mac 的 1656 和 Linux 的 1648 是历史基线，不强求新环境得到相同数量；失败/skip 逐条说明。
- [ ] **Step 2 — 写 RED。** test_exec_defaults_disabled 保证缺失字段为 false/空 tuple；test_enabled_requires_explicit_scope 覆盖 true+缺省或空 paths；test_root_scope_requires_literal_dot；test_invalid_policy_fields 拒绝 bool/int 混用、未知键、重复路径、非规范路径、绝对路径、父目录及无效 runner；test_runner_map_cannot_escape_scope 保证 service 与 service-extra 不混淆。路径列表沿用现有上限128、单项UTF-8最多2048字节；runners 最多128项。disabled 时非空 paths/runners 拒绝。
- [ ] **Step 3 — 验证 RED。** `PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest -q tests/test_exec_core_policy.py`；新模块缺失/新声明尚不可解析的失败必须先出现，不能删原启动负控来获得通过。
- [ ] **Step 4 — 实现类型与屏障。** 复用现有相对路径校验规则；路径组件匹配 runner scope。read_workspace_config 解析后立即运行屏障；run_multi 在 service 建立前也检查；create_multi_app/build_multi_mcp 在注册任何 route/tool 前检查。local_skills 原规则不变。内部 Service 本身没有真实 exec 能力，不能据其能接受声明推导生产激活成功。
- [ ] **Step 5 — GREEN 与提交。** 新测加 test_every_public_factory_rejects_enabled_policy：直接工厂、CLI --check、CLI HTTP-only/MCP、read_workspace_config 全拒绝；监听器/SDK组装/业务 Popen 计数为0，错误不回显私有根路径。执行本文件和完整 pytest，更新 Manifest，提交 `feat(core): model exec policy without enabling runtime`。

### Task 2: 不可变请求、共享参数校验与 Service 内部准备

**Files:** 新增 gateway/exec_contracts.py、tests/test_exec_core_prepare.py；修改 gateway/workspaces.py。不修改 executor.py 的已签收解析器。

**Interfaces:**
- `ExecutionRequest(workspace: str, cwd: str, argv: tuple[str, ...], timeout_seconds: int, dry_run: bool)`，frozen；`parse_execution_request(payload: object) -> ExecutionRequest`。
- 仅允许 workspace/cwd/argv/timeout_seconds/dry_run；workspace、argv 必填；cwd 默认 "."、timeout 60、dry_run true。字段严格类型，不把 bool 当 int。argv 先调用现有 `_clean_argv(list)` 与 `_validate_command(list)`，再冻结 tuple；增加对输入字符串可编码 UTF-8 的显式检查，不改变 Legacy validator。
- `ExecutionIntent(request: ExecutionRequest, scope: str, runner_hint: str, runner_project_hint: str | None, runtime_ready: bool = False)`，frozen；runner_hint 为 direct/pipenv/auto，auto 不代表已完成 Pipfile 搜索。
- `WorkspaceService.prepare_execution(payload: object) -> ExecutionIntent` 为仅内部的只读规划方法；沿用 get 的 workspace 错误码及生命周期锁，在 Service 内检查 execution.enabled、cwd 组件级 scope、Gateway 的 blocked/excluded/hidden 策略。执行声明关闭抛 exec_disabled，越界抛 exec_scope。
- `WorkspaceService.invoke` 只接受原 _READ|_WRITE，检查必须发生在 getattr 之前；prepare_execution 不经该动态入口公开。

- [ ] **Step 1 — 写 RED。** test_request_defaults_and_exact_types：timeout 1/300 成功，0/301/True 失败；缺 workspace 不选默认；未知字段失败。test_request_snapshot_is_immutable 修改原 argv list 后快照不变。test_service_denies_other_workspace_and_prefix_scope 覆盖 A授权/B关闭、service-extra、../、绝对路径；沿用已有 runtime/control-plane root 隔离正反控。
- [ ] **Step 2 — 加共享修复负控。** test_prepare_reuses_signed_validator：参数化此前 Task 2 的 Go hook/-C/-pgo/诊断 flags、pytest @argfile/addopts/INI 环境引用/路径别名；拒绝码与 Legacy 共用语法一致。正控保留 cache/log 含空格、引用列表、pgo auto/off。测试把 CommandRunner.run 和业务 Popen 设为“调用即失败”守卫，证明准备路径不借 dry_run 去调用可执行 runner。
- [ ] **Step 3 — 运行 RED。** `.venv/bin/python -m pytest -q tests/test_exec_core_prepare.py`；确认失败来自未实现请求/准备契约，而不是真实 SDK 导入或外部环境。
- [ ] **Step 4 — 实现内部准备。** 在实际同步规划 worker 内取得现有 _operation 生命周期租约，检查策略后返回不可变 intent；扩展 require 只识别明确的内部 prepare_execution 操作，不放开任意名字。默认/显式 runner 只给规划提示；不创建 enabled=True 的 CommandRunner，不持有伪造 cwd/PGID 句柄，不访问另一个 Workspace 的 Pipfile。intent 返回后不继续持有 root lease，因此以后 spawn 必须重新授权和取得 G2 证明的原生租约。
- [ ] **Step 5 — GREEN 与提交。** test_internal_prepare_never_advertises_exec 检查 info/list_workspaces 中 exec 仍 false；test_invoke_cannot_call_internal_or_run_command 检查旁路被拒。运行新测试、原 tests/test_phase2_argv.py、完整 pytest（设置 venv PATH），更新 Manifest；提交 `feat(core): prepare immutable authorized execution intent`。

### Task 3: 仅内存的配额、单 owner ticket 与生命周期

**Files:** 新增 gateway/exec_registry.py、tests/test_exec_core_registry.py、tests/exec_core_helpers.py。

**Interfaces:**
- `ExecRegistry(*, clock: Callable[[], float] = time.monotonic)`，配额固定1/Workspace、4/global，不提供用户可配超额值。
- `reserve(intent: ExecutionIntent) -> ExecutionLease`：只接受 dry_run=false 的已准备意图；内核仅管理名额，不是第二个授权源。生产调用点必须由 Task 4 的 Service 重新准备。满额抛 GatewayError("exec_busy", ...)，关闭后抛 service_closing。
- `ExecutionLease` 为内部不透明身份，含只读 ticket_id 与 workspace；写状态需要 registry 签发的对象身份，不能仅用外部字符串ID修改。不得序列化为远程接口或利用 __del__/HTTP上下文退出自动释放。
- `record_attempt(lease) -> None`、`record_started(lease) -> None`、`request_stop(lease, reason: Literal["timeout","shutdown"]) -> None`、`finish(lease, outcome: ExecutionOutcome) -> None`、`begin_close() -> None`、`wait_idle() -> None`、`snapshot() -> RegistrySnapshot`。
- `ExecutionOutcome(exit_code: int | None, timed_out: bool, error_code: str | None)` 与 RegistrySnapshot（active_total、各 workspace 计数、closing）为只读值；结果只交给 owner，不在 registry 内无限保存终态。

**状态契约：** RESERVED→STARTING（record_attempt最多一次）→RUNNING→STOPPING→FINISHED；RESERVED 可无启动直接 FINISHED；STARTING 可因启动失败 FINISHED。finish 后删除活动记录并释放一次；重复同一 lease 的 finish 幂等，其他 registry/伪造/过期身份不能改动新任务。完成前不得复用 ticket ID。record_started 才开始模拟执行时钟；调用方可用注入的单调时钟推进超时，registry 不启动定时线程、不发信号、不调用 waitpid。真实 spawn 开始点与 OS timer 的耦合留 A4 冻结。

- [ ] **Step 1 — 写配额 RED。** test_one_per_workspace_and_four_global：A二次接纳失败，第五个不同Workspace失败；完成一个后新接纳成功；失败不能增加计数。test_dry_run_never_reserves；test_concurrent_reserve_is_atomic 用 barrier 证明同Workspace两个竞争者只有一个成功，而非检查一次顺序调用。
- [ ] **Step 2 — 写 owner RED。** test_duplicate_finish_does_not_release_successor、test_foreign_lease_cannot_release、test_attempt_recorded_at_most_once、test_waiter_cancel_does_not_finish_owner。以 threading.Event 协调测试 owner，不用随意 sleep。test_timeout_requests_stop_without_pretending_reaped 检查到期进入 STOPPING 但仍占 slot，owner 真正 finish 才清空。
- [ ] **Step 3 — 验证 RED。** `.venv/bin/python -m pytest -q tests/test_exec_core_registry.py`；缺少 registry 时必须失败。以后故意把 finish 改为重复减计数或在 waiter取消时释放，相关测试必须能失败。
- [ ] **Step 4 — 实现纯内核。** Condition 内原子检查全局/Workspace配额和 closing；不在锁内调用任何外部 callback/文件I/O。增加 `mark_expired() -> tuple[str, ...]`，把到期RUNNING记录转为STOPPING并返回ticket_id给将来的owner调度器；没有 backend 时只是状态变化，不伪装超时已杀死进程。身份拒绝使用 invalid_argument，非法状态迁移使用 exec_state；begin_close 先停接纳，所有活动任务只能由其 owner 完成。
- [ ] **Step 5 — GREEN 与提交。** test_close_vs_reserve_has_single_order、test_finished_records_do_not_grow、test_original_quota_is_preserved_after_all_failure_paths 全通过；新模块 import 守卫验证不导入 mcp/subprocess/ctypes、不调用 os.kill/killpg/fork/exec/posix_spawn。运行完整 pytest、更新 Manifest，提交 `feat(core): add owner-bound execution admission model`。明确模拟attempt计数不是原生 Popen资格。

### Task 4: Service 生命周期汇合、生产入口否定测试与交付

**Files:** 修改 gateway/workspaces.py；新增 tests/test_exec_core_boundary.py；修改 docs/PROGRESS.md、MANIFEST.sha256。其他文件仅在 Task 1/2 已明确范围内修正。

**Interfaces:**
- `WorkspaceService._reserve_execution(payload: object) -> ExecutionLease` 为内部接缝，不注册工具/路由：在 Service 生命周期内重新 prepare/require，拒绝传入裸 ExecutionIntent 作为授权凭据，检查closing后调用 registry.reserve；不调度 worker。
- `WorkspaceService.close()` 保留文件操作 drain 顺序；先拒绝新文件/规划/模拟接纳，再等待活动文件worker与模拟owner完成，最后关闭 Gateway、pinned_root、inventory。锁顺序固定 Service lifecycle→Registry；Registry 不回调Service，等待时不得持有另一方锁。close重复调用安全。
- 本轮不存在生产 worker，也不存在调用 _reserve_execution 的 REST/MCP路径。测试专用owner只放 tests/exec_core_helpers.py；不添加可从配置选择的 fake backend。

- [ ] **Step 1 — 写关闭与隔离 RED。** test_service_close_waits_for_owner_and_file_worker：事件控制两个独立完成，提前取消等待者不得关闭root；test_busy_exec_does_not_block_other_workspace_file_read；test_reserve_reauthorizes_payload_and_rejects_borrowed_intent；test_close_never_admits_after_closing。
- [ ] **Step 2 — 写全入口 RED。** enabled=true 声明的 CLI、app、MCP factory 必须按 Task1屏障拒绝；enabled=false 的正常服务继续无 /run 路由、tools/list 不含run_command，伪造tools/call不能绕 multi_fields._PHASE2。Service.invoke("run_command")及invoke("prepare_execution")均拒绝；每个 ctx.gateway.exec 仍关闭。所有拒绝断言真实业务 Popen尝试为0，别把错误的 mock 返回当成功。
- [ ] **Step 3 — 运行 RED 后接入生命周期。** `.venv/bin/python -m pytest -q tests/test_exec_core_boundary.py`；再最小实现上述内部接缝，保持真实权限与执行能力解耦。不得为让测试通过而把生产能力检查改成平台伪造、环境变量开关或测试专用参数。
- [ ] **Step 4 — GREEN 及完整回归。** 设置 `PATH="$PWD/.venv/bin:$PATH"`，运行所有 tests/test_exec_core_*.py 及整套 `.venv/bin/python -m pytest -q -rs`。重新生成完整 tracked-file Manifest 后运行 `bash verify.sh --require-mcp` 和 `git diff --check`。保留 pytest、HTTP smoke、Manifest、退出码、平台与完整依赖版本；smoke 的 mcp_verified=false 不能被写成MCP产品验收。
- [ ] **Step 5 — 提交与独立复审。** docs/PROGRESS.md 只标 G1候选结果，不标实际执行PASS；提交 `feat(core): integrate inert service lifecycle and activation guards`。另一个LLM/验收人员审查固定BASE..HEAD与全部新增入口、owner/配额时序、继承修复证据；作者自检不得冒充独立复审。修订后按新固定SHA回归，未经批准不合并。

## Manifest、测试命令与交付记录

Manifest 必须枚举全部 tracked files（排除自身），按路径字节序排序，逐项使用标准库 hashlib.sha256；不得只替换几条预期行、不核对新增/遗漏。可在未来实施提交中执行：

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
import hashlib, subprocess
paths = sorted(p for p in subprocess.check_output(['git', 'ls-files', '-z']).split(b'\0') if p and p != b'MANIFEST.sha256')
rows = [hashlib.sha256(Path(p.decode()).read_bytes()).hexdigest() + '  ./' + p.decode() for p in paths]
Path('MANIFEST.sha256').write_text('\n'.join(rows) + '\n', encoding='utf-8')
PY
```

先 `git add` 本任务明确文件让其成为 tracked，再生成清单、加入 Manifest、运行完整验证后提交。不要把临时日志/测试数据库、SDK源码副本或原生私有证据加入Git。每个任务账本记录 `BASE / 测试名 / RED实际失败 / GREEN实际结果 / 完整回归 / 偏离规格裁决 / commit`，而非填入预想的测试数量。

## 后续分轨工作及不会被本计划放行的内容

| 工作包 | 本轮产物如何交给后续工作 | 开始真实集成前的条件 |
| --- | --- | --- |
| C1/G2 原生机制 | ExecutionIntent仅提供意图，不提供cwd/PGID资格；另立原生正常启动/race/单reaper资格计划 | 同一机制direct/pipenv正控、cwd/Pipfile身份、PGID复用与后代回收、独立签收；不复活失败的/dev/fd路线 |
| B1/G3 MCP受限合同 | 核心不依赖SDK helper；独立盘点8个未知emitter，限定应用调用链 | 正式受限规格、所有可达自动/错误消息正确、合法ID/GET/断连/清理、独立证明与书面批准；不以旧Q0重复复现阻挡A1–A3 |
| A4/G4 真实Supervisor/REST | 用已审ExecutionRequest/Intent/Registry接缝，但必须重新授权和持有原生租约 | G2通过；把模拟时间/状态换成真实Popen/唯一owner，不把模拟计数当OS保证 |
| B2/G4 MCP集成 | 未来adapter只调用同一Service；不从MCP requestId派生进程身份 | G2/G3与核心验收通过后单独计划，不能本轮移除_PHASE2屏障 |
| G5 发布 | 合格固定版本、更新清单、原生与客户端证据交接 | 单独合并/部署/启用授权；Task2已签收不等于PR10已发布 |

## 覆盖对照与当前交付边界

规格 §1/§3/§5 的 A1/A2/A3、G1 由 Task1–4 覆盖；§2 的声明授权、参数验证、1/4配额、一次attempt、无远程去重对应上述测试。§2/§4/§5 中的原生期限、实际信号/reap/drain、输出限制和完整MCP语义仅作为冻结后续合同，并未在本计划实现；对应 C1/A4/B1/B2/G2–G4。§6 的固定提交、隐私与继承覆盖在任务基线和交付记录。由此，任何G1通过都不能被总结成M01–M15-L全部PASS。

**写作时状态：** 只形成计划；没有实施上述新模块、运行新测试、合并任何PR或安装SDK。项目方已同意PR11书面规格，独立设计复审及本实施计划审批仍须如实记录。建议沿用“本会话逐任务实施＋其他LLM独立复审”的协作方式；本计划经审阅、相关独立设计阻断项关闭并明确授权后，先执行Task1，不再回到旧Q0资格循环。
