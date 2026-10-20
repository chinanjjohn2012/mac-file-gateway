# Phase 2 Lite：核心开发与 MCP 受限合同并行推进（架构变更草案）

**状态：DRAFT — 待用户审阅书面规格、独立安全/架构复审；不构成产品实施、合并、部署或启用授权。**  
**日期：2026-10-19。**  
**依赖设计：** [PR #8](https://github.com/chinanjjohn2012/mac-file-gateway/pull/8)，固定设计提交 `a46ab54d2814afcb5932dae27799ec258be9e354`，仍为 CONDITIONAL / Draft。  
**Q0 证据：** [PR #9](https://github.com/chinanjjohn2012/mac-file-gateway/pull/9)，固定计划提交 `64e50fc17ec9c1251ab8b4c4e1df85794f2815bb`；用户运行的原生 macOS V3 研究证据采集成功，但官方原版 SDK 协议合同仍 FAIL/BLOCK。  
**共享安全修复：** [PR #10](https://github.com/chinanjjohn2012/mac-file-gateway/pull/10)，固定提交 `cd345b0cb46f48b70c6e4478ae4d7d97269c5894`，D1/D2/R1 的 Task 2 已由项目方确认完成独立签收、状态 CLOSED，PR 仍 Draft/未合并。

## 1. 决策及成功标准

项目方于 2026-10-19 同意的**方向**是：保留**未修改的官方 MCP SDK 1.30.0**，不因其已知问题阻止其他不依赖 SDK 语义的代码开发；同时需要为 MCP 产品接入**独立证明并明确批准**新的受限协议合同。方向同意不等于本书面规格已批准，更不等于自动接受 SDK 所有风险或批准产品上线。

三个方案的取舍：

| 方案 | 优势 | 风险/结论 |
| --- | --- | --- |
| 全项目等待 SDK 完整合同通过 | 单一阻断点简单 | 无关的授权和服务逻辑也停工；不采用 |
| 忽略或静默接受 SDK 缺陷继续接入 | 速度快 | 无法证明结果/错误归属或清理正确；禁止 |
| **分轨开发，分层资格，最终汇合** | 核心代码可独立验收，协议风险不被掩盖 | 增加依赖与证据管理；**本次建议** |

**成功标准：** 允许独立完成并审查核心服务/授权/解析代码；不通过或绕过相关机制资格的组件不得被连成真实可启用的 Multi exec；协议范围、OS 身份、真实进程生命周期和最终发布资格分别证明。

## 2. 冻结的安全与兼容边界

1. 保留 PR #8 已明确的 **运行正确、停止正确、结果正确**，以及 M01–M15-L 中不因协议受限而可豁免的安全要求。
2. 首版 Multi exec 默认关闭，必须显式 `workspace`、`exec.enabled=true`、授权 `paths` 与 `runners`；禁止把缺失 `workspace` 自动回退到 Legacy root。显式 `paths:["."]` 才能授权根目录。
3. 命令仍经已审查的 **CommandRunner** D1/D2/R1 校验；不提供任意 shell、未授权的外部路径/环境变量或跨请求内部执行重试。每次已接纳的真实调用 `Popen_attempts<=1`，拒绝、dry-run、spawn 前放弃为零。
4. **不承诺 OS sandbox**；执行可信项目代码仍有 Gateway OS 账户权限。路径检查不能替代 actual cwd 身份证明；PGID 数值不能替代可证明的进程组身份锚点。
5. 服务端真实执行期限为 1–300 秒、默认 60；每 Workspace 一个、全局四个执行 permit；TERM grace 2 秒及独立 drain 预算 2 秒、每流最多 48,000 字符的输出限制与脱敏维持 PR #8 口径。
6. 无远程 job/query/recovery 或跨 POST 取消；HTTP/Tunnel 断连后的已启动命令仍由服务端唯一 owner 管理，直到真实终止、超时或服务关闭。结果可能丢失，新的独立请求可再次执行；绝不虚称 exactly-once。
7. Legacy/file-only Python 3.11+ 兼容性不变；新 Multi exec 的 macOS 原生资格仍要求 Python 3.13+。不修改官方 SDK `mcp==1.30.0`、SDK `site-packages`、SDK Wheel、全局猴子补丁或在线运行配置。

## 3. 代码依赖拆分与可开展范围

下述“可以开发”指**在独立分支、测试优先、默认关闭、不能误启用的候选代码开发**；正式产品集成、合并和启用需要对应后续门槛，不从本次方向同意自动取得授权。

| 工作包 | 可开展工作 | 阻断/禁止 |
| --- | --- | --- |
| **A1 Workspace 纯配置和授权** | Schema v1 扩展、显式授权、Workspace ID、scope、runner/Pipfile 关联、fail-closed 校验、纯单元/HTTP 负控 | 不得在配置缺失/错误时派发命令；不得自动使 exec 可用 |
| **A2 命令入口共享验证** | 按 PR #10 已签收修复复用 `CommandRunner`；合法 argv、Legacy regression、dry-run/admission 单一语义 | PR #10 尚未合并至 `release/ms1`；不能以源分支的 PASS 宣称其他分支自动继承 |
| **A3 Service/任务状态机** | `ExecutionRequest`、一次性内部 ticket、配额、错误码、状态迁移、结果模型、纯模拟 supervisor 单元测试 | 未取得原生身份资格前，不能连接真实 `Popen` / OS 信号控制 |
| **C1 macOS 实行资格（独立）** | 隔离无业务凭据原生实验：actual cwd 正常 direct/pipenv 启动、rename/recreate race、Pipfile 归属、进程组身份/复用及真实子孙进程回收 | 旧 `/dev/fd/<fd>` 在原生 Mac `ENOTDIR`，不是正控；不得以字符串 cwd、全局 chdir、preexec_fn 或裸 `killpg(pgid)` 代替 |
| **A4 ExecSupervisor + REST** | 在 C1 对所选机制获独立资格后，实现唯一进程 owner、超时、TERM/KILL、drain、FD/root pin/permit、服务关闭；REST `/run` 与 Service 一体化验证 | C1 未通过时只可测试模拟状态机和 REST 拒绝路径；不得开启真实执行。REST 单独发布需另行发布授权 |
| **B1 原版 SDK 受限合同** | 构建“应用不使用请求关联日志/进度”的候选 profile、完备静态/动态可达性证据、错误/自动消息盘点、合法 ID/GET/背压复验 | 不能删除旧四项失败负控、屏蔽 SDK 消息、收窄合法 JSON-RPC ID、仅凭最终 JSON 宣称 SDK 资格 |
| **B2 MCP 产品接入** | 仅在受限 profile 经独立证明并由项目方书面批准后，才实现 MCP `run_command` 与 Service 的产品集成 | 在 B1 资格或 C1 必要 OS 机制未获批前不得连入实际可执行路径 |

**建议隔离接口：** `WorkspaceService.require(workspace, operation, cwd, ...)` 作为唯一授权入口；REST/MCP 只负责严谨参数验证与结果适配，传入同一内部 `ExecutionRequest`；`ExecSupervisor` 是唯一实际 Popen/信号/reap/reader/permit 持有人。内部 ticket 与 JSON-RPC request ID 分离，不持久化成远程 job。接口具体签名由后续获批实现计划冻结，现阶段不可把示意签名当作已实现 API。

## 4. MCP 受限协议 profile（候选，不是已经合格的官方 SDK）

**候选范围：** 原版官方 `mcp==1.30.0`、`stateless_http=True`、`json_response=True`，通过标准 MCP 初始化、工具枚举和同步工具调用返回最终成功/失败结果；Gateway 的 Lite 应用工具**不调用** `Context.info`、`Context.report_progress`，不主动提供请求关联 logging/progress、elicitation/sampling、动态工具变更或远程 job/recovery。

**该限制只约束应用使用的可选能力，不能用来修改线上的合法协议域。** 整数 `0`、空字符串 `""`、整数 `71`、字符串 `"71"`、字符串 `"_GET_stream"` 等合法请求 ID 的正确响应/并发隔离与 GET/SSE 命名空间仍须证明；不得修改 SDK 数据结构、过滤请求或吞掉 SDK 自动产生的消息。

**现有失败必须保留：** `CTX_EMPTY`、`PROGRESS_EMPTY`、`RAW_EMPTY`、`RAW_ZERO` 是原版官方 SDK 在**原完整合同**下已复现的协议反例；macOS V3 `--diagnose=0` 是取证成功，`--qualify=2`、`FAIL_BLOCK_ORIGINAL_SDK / STOP_PRODUCT` 才是现有合同结论，不得被新 profile 的独立结论覆盖。

**受限 profile 资格证据：**
- 对 Q0 `unknown_reachable_emitters=8` 的**每一项**列出源码位置、触发条件、Lite 工具调用链、静态可达性、动态覆盖、是否 SDK 自动产生及最终裁决。对应用不可达的宣称必须有正反证据；`UNKNOWN`、`NOT_RUN` 不得视为 PASS。
- 真实原版 FastMCP→Session→Streamable HTTP→ASGI，验证初始化、tool success、tool error、参数拒绝、未知工具、执行超时映射、取消前后、并发请求、GET/SSE、发送失败、自然断线和资源清理；不能用仅成功 HTTP body 替代 actual related metadata/route owner 检查。
- **仅当所有 profile 范围内可达路径均不产生需要正确关联而 SDK 无法正确处理的通知，或确证产生的消息在官方原版 SDK 上具有正确归属/投递时，才可提出受限合同资格 PASS 的候选。** 一旦真实路径仍产出无法正确投递的关联消息，继续 BLOCK，不能自行吞弃。
- 保留 4 项完整合同失败为独立持续回归；记录原合同 `FAIL/BLOCK` 与新受限合同 `QUALIFICATION PASS/FAIL` 为两个不混淆的判定。
- 完成真实 ChatGPT Web → 认证 Tunnel → Gateway 的合成任务兼容性验证（需单独明确授权），包括 ID/GET/重试/断线行为及信息脱敏；旧研究中的目标客户端可达性 UNKNOWN 不能靠推断关闭。

## 5. 并行工作流的汇合门槛

| Gate | 必须获得的证据/签收 | 通过之前允许的工作 |
| --- | --- | --- |
| **G0 规格** | 本书面规格经项目方审批；独立安全/架构复审无阻断项，再制定可执行实施计划 | 仅隔离设计/评审 |
| **G1 核心纯逻辑** | A1/A2/A3 的 RED→GREEN、Legacy/Multi fail-closed 回归，固定提交/Manifest；Task 2 的审查版确实被候选分支继承 | 静态/模拟，不允许真实 Multi Popen |
| **G2 OS 资格** | 同一 macOS 机制的真实正常 direct/pipenv/cwd 正控、目录替换竞态、PGID 不误杀、子孙回收、独立复审与明确批准 | 未通过时 ExecSupervisor 真实 spawn/stop 一律 STOP |
| **G3 MCP 受限合同** | Q0 完整旧缺陷证据保留，8 个 emitter 均裁决，所有限定范围可达路径/合法 ID/错误/GET/断线清理证据，独立复审和用户**书面批准替代合同** | 未通过时 MCP 产品 adapter 仅可设计/隔离测试，不得接入可执行服务 |
| **G4 联合功能** | REST、MCP 同一 Service 严格授权/资源计数，真实 worker 生命周期、SIGINT/SIGTERM、M01–M15-L 原生和目标客户端强制项逐项 PASS；CI/Manifest/隐私审计 | 任何缺失/skip/NOT_RUN 的强制项不能算功能 PASS |
| **G5 发布** | 独立安全/架构最终评审及项目方单独批准 merge、deploy、enable | 保持 Draft、默认 exec=false，不更改现有 Gateway/Tunnel |

**不允许“风险已记录所以自动解除 G3”。** 即使 G3 不通过，A1/A2/A3 的纯逻辑开发可以继续；G2 未通过，真实 supervisor 集成不能继续。REST 如需独立发布，还需另立 OS/REST 专项完整验收和发布授权，不能借用这次 MCP 受限合同的审批。

## 6. Git/版本与验证证据管理

- [PR #8](https://github.com/chinanjjohn2012/mac-file-gateway/pull/8) 保留原 Lite 设计及其历史 CONDITIONAL 状态；本文件是在 PR #8 头部设计之上**提出**的增量路线，**没有修改原文件的历史判断**。设计批准后，须明确标注仅 M10-L 的应用 profile 部分被新合同替代，其他约束保持。
- [PR #9](https://github.com/chinanjjohn2012/mac-file-gateway/pull/9) 的计划 PASS、官方 SDK 原合同 FAIL/BLOCK 与 Q0 macOS V3 研究结果均不改写；若新的 profile 需要研究脚本/判定器，使用独立研究 PR、不同合格名称和原始证据保留策略。
- [PR #10](https://github.com/chinanjjohn2012/mac-file-gateway/pull/10) Task 2 CLOSED 仅证明其**固定提交**已签收，不证明 `release/ms1` 已具备修复；后续工作分支必须明确建立依赖（独立审查后的合并或可验证的移植），不得同时混入未审查的源码漂移。
- 所有开发在独立候选分支；先新测试的可达反例，再最小修复，再完整回归与独立复审。区分 Linux CI、原生 macOS、SDK ASGI、真实 Web/Tunnel。不得用 Linux 模拟代替真实 native/客户端证据。
- 公开 PR 仅放脱敏摘要、测试代码及校验哈希；原始请求内容、凭据、host 路径、业务项目标识、绝对 home 路径和完整私有日志留在批准的本机证据目录。
- SDK 1.30.0 本身即使被列为 Known Issues / Accepted Risk 候选，也**不构成**该受限 profile 已通过资格的证据。对原合同失败的接受范围与新产品实际可达行为必须由独立评审和项目方分别裁定。

## 7. 书面规格评审重点与暂行状态

请独立审查：A1/A2/A3 的开发边界是否真的不依赖 SDK/OS 身份；模拟 owner 结果能否错误被路由到真实 Popen；受限应用配置是否忽略 SDK 自动/错误关联消息；是否暗中削减合法 JSON-RPC ID；是否保持 GET/backpressure/cancel/cleanup 的正确归属；G2 cwd/PGID 正控是否遗漏；PR #10 的修复是否在候选分支确实存在；G0–G5 是否形成可复现的 fail-closed 发布门禁。发现问题请固定文件、行号、反例、优先级及最小关闭条件。

**当前状态（截至本草案）：** Task 2 = CLOSED（未合并）；Q0 原始研究证据已采集、官方完整合同 = FAIL/BLOCK；8 个自动/关联发送入口可达性未全部定论；macOS actual cwd/PGID 未完成合格证明；受限 profile 资格 = NOT QUALIFIED；Multi exec 功能与启用 = BLOCK。**本草案不批准任何可执行代码开发、合并、部署或启用，待 G0 书面审批后进入下一步详细实施计划。**
