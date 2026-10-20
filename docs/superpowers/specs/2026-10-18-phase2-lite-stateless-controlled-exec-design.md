# Phase 2 Lite：官方 MCP 1.30.0 + Stateless 同步受控执行（设计规格）

**状态：设计草案，待用户书面审阅及独立安全／架构评审；不是产品实施、合并或启用授权。**
**日期：2026-10-18。**
**基线：** chinanjjohn2012/mac-file-gateway 的 release/ms1，固定提交 e32cb5124bbd8b08a79c75b4940799e041dd1295。
**历史材料：** 原 Phase 2 设计 PR #5 固定 a51f31d9ccee9c9ba46f0a53dd669b836b970fdf；PR3 研究 PR #6 固定 20521da9fb83e4053a7f5fb16699ee48a373f95b；修订候选 PR #7 固定 eee0d8e1d5fbc86d131ca32712d5033e8c941589。三份历史材料均保留，不视为此 Lite 规格的独立批准。
**决策：** 用户已选择「执行命令、返回结果、服务端超时终止」，优先保留官方未修改 MCP SDK 1.30.0；并接受客户端或 Tunnel 断线后已启动命令继续运行至正常结束、服务端超时或服务关闭，结果可能无法送达，独立重试可能重复执行。

## 1. 目标、非目标与批准边界

### 1.1 首版三个不变目标

1. **运行正确**：显式 Workspace 授权，实际 cwd 与 runner/Pipfile 绑定，白名单 argv，只有 apply 启动命令；有效命令必须能在原生 macOS 正常成功运行。
2. **停止正确**：**服务端**执行超时、Gateway 关闭（SIGINT/SIGTERM）时，安全停止受管理进程并回收真实 worker、FD、输出 reader、目录租约和 permit；绝不向复用的外部 PGID 发送信号。
3. **结果正确**：一条成功送达的同步调用返回其自身的 exit_code、timed_out、stdout、stderr 和截断信息；每次服务端接纳至多一次 Popen；断线后不伪造成功或假定客户端收到了结果。

首版不是异步任务系统：没有远程 job_id、查询/恢复输出端点、增量进度订阅或跨请求取消 API。不保证结果持久化、跨 HTTP 请求去重、断线后的结果补发；不为兼容业务隐式重试。文件 API、已有单根 Legacy exec / Skills 及其既有配置应保持行为兼容。**不引入 OS sandbox**：执行可信代码仍具备 Gateway 所在 OS 账户的权限；API 的 write=false 不会阻止被执行代码修改文件。

### 1.2 两种不同的取消语义

- **不提供的产品功能**：客户端发起的 MCP notifications/cancelled、HTTP 断连或另一个 POST **不能**按“远程停止指定正在运行的命令”解释；不持有会话级 requestId→ticket 映射，不提供跨 POST 取消。
- **必须提供的安全功能**：服务端执行计时器、Gateway 关闭、启动失败与内部资源异常的安全停止和回收。
- 断连**发生在实际启动之前**时，允许 admission 拒绝／放弃本次启动（Popen=0）；**已实际启动**后，HTTP task 被取消不等于命令结束。真实 worker 的停止权和超时责任只由服务端 supervisor 持有。
- 若用户按“停止”而客户端断开，命令仍可能执行，直到上述服务端终态；必须在工具说明中直白声明。

### 1.3 原 Phase 2 合同如何适用

本规格拟**替代**原 PR #5 对 Multi exec 的 stateful MCP、跨 POST 取消、会话 seen-ID ledger 及其绑定到执行 ticket 的要求；并重新定义 M06、M10、M14。原 D1/D2/R1、actual cwd、原生 PGID、防误杀、进程组后代回收、双输出 drain、shutdown、资源配额、M01–M05/M07–M09/M11–M13/M15 安全目标**全部保留**。历史 PASS/BLOCK 证据保留来源与原适用范围，不因 Lite 决策被重新归类。**本规格未经评审批准前，不覆盖旧方案，也不自动解除任何 BLOCK。**

## 2. 现有实现与决定的技术路线

在固定 release/ms1 基线上：
- requirements.txt 固定官方 mcp==1.30.0；gateway/mcp_multi.py 使用 FastMCP、stateless_http=True、json_response=True，现有 Multi 只有文件工具。
- gateway/workspaces_config.py 显式拒绝 Multi exec.enabled=true；gateway/workspaces.py 为每个 Workspace 建立 allow_exec=False 的 Gateway，WorkspaceService.require 只支持文件读写。
- Legacy 的 gateway/executor.py 已有 argv 白名单、direct/pipenv、dry_run、同步 Popen、60 秒默认/300 秒上限、输出过滤与基础超时；但**不能**直接把既有进程组数值 kill、路径检查/argv 解析搬到 Multi 当作已合格实现。
- gateway/http_multi.py 已有 REST 和 SDK 共用服务的模式；gateway/multi_admission.py 的严格 JSON/请求体入口、gateway/http.py 的 Boundary 可复用，但执行端点尚不存在。
- 原方案已记录的 D1/P1、D2/P2、R1/P2、LC1(/dev/fd 正常启动失败)、PGID identity、SIGTERM 及同步 worker 生命周期是**未完成门槛**。

**选择：A1。** 保持官方 SDK 源码和依赖声明不变，通过 Gateway WorkspaceService + 独立 ExecSupervisor 实现执行生命周期。MCP 工具和 REST 都直接调用同一个服务入口，**不**由 MCP 通过 loopback HTTP 再调用 REST；后者会增加请求身份和超时边界。SDK 仅作协议接入，永远不能作为真实进程的唯一生命周期 owner。研究候选 mcp 1.30.0+mfg.1 不进入 Lite 产品依赖。

~~~
ChatGPT Web → 私有 Tunnel → Boundary / StrictPostAdmission
                                  ↓
                      官方 MCP 1.30.0 (stateless JSON)
                        或 同进程 REST /run
                                  ↓
                  严格参数 → WorkspaceService.require
                                  ↓
                 接纳/permit → 共享 CommandRunner
                                  ↓
                      sole-owner ExecSupervisor
                                  ↓
                   固定 cwd / runner → Popen
                                  ↓
               服务端计时 + 原生身份安全停止
                                  ↓
                 同步结果（连接仍在才可送达）
~~~

## 3. 执行入口、身份和授权

拟新增 REST POST /run 和 MCP run_command；接口为 workspace（必填）、cwd（Workspace 内相对路径，默认 "."）、argv（必填非空字符串数组）、timeout_seconds（默认 60，范围 1–300 的整数）、dry_run（默认 true，严格 bool）。拒绝未知字段、错误类型、数字越界、JSON 重复键、非法 Unicode 和请求体超限；任何拒绝都不得启动业务。

**授权顺序**：Host/Origin/可选本机 Bearer + 私有 Tunnel 认证边界 → StrictPostAdmission/合法 JSON-RPC 包 → 真实参数检查 → WorkspaceService.require(exec) → argv/目录/runner/配额 → 真实 spawn。被拒绝的请求必须 dispatch=0、Popen_attempts=0。MCP ToolError 在应用错误时保留机器可识别的 code；REST 对应原计划状态码。MCP 的 wire request ID 只用于本 HTTP 请求的协议响应，不作为 OS 进程、Workspace、授权或跨请求去重身份；工具函数的 Service 许可检查不可被 MCP/REST 绕过。

- 显式配置每个 Workspace 的 exec.enabled=false 默认，启用需非空、显式 paths；路径 "." **只在配置显式提供时**允许，禁止缺省授予整个 root。
- Workspace ID 必须显式传递，不能根据 cwd/path 猜、不能回退默认 root，也不能从 A 的 Pipfile 继承 B 的 runner 配置。
- 同一 Workspace 最多一个执行任务，Gateway 全局最多四个；超额**立即拒绝、不排队**。GET 文件 API 和其他 Workspace 文件操作不应因长执行被全局锁阻塞。
- 首版继续共用 CommandRunner 的允许命令：pytest、python -m pytest、python -m compileall、项目内相对 .py、go test、go vet；shell=False，stdin=DEVNULL；pipenv 使用 pipenv run 而非交互 pipenv shell。
- D1/D2/R1 的 Go hook、pytest addopts/@argsfile、提取值路径选项、短选项簇必须先修复并验证，且在 Legacy/Multi 中同样生效。未经批准不得扩展任意 shell、系统程序、远程外部路径或 command/env 参数。

现有 Boundary 的 GATEWAY_TOKEN 是可选的本机设置，不可把 SDK 的 Mcp-Session-Id 或仅仅持有任意 JSON-RPC ID 当作授权；远程暴露必须持续由已授权的私有 Tunnel 管理。业务错误、输出和调试日志不得泄漏根路径、环境变量或凭据。

## 4. Stateless MCP 合同与不可忽略的原版 SDK 风险

保持 FastMCP 的 stateless_http=True、json_response=True，复用现有 /mcp 入口、单 POST 单 JSON-RPC 对象的严格包装；文件工具与 exec 工具共存，且客户端初始化、tools/list、tools/call 必须通过目标 ChatGPT/Tunnel 兼容性测试。**Stateless 是待验证的规避方向，不是对官方 MCP 1.30.0 的无条件安全证明。**

此前 PR3 在原版 1.30.0 的持久 Session 复现 int 71 与 str "71" 路由别名、0/空 ID 关联消息丢失、GET 控制域碰撞、派发前取消清理遗漏；PR #7 对修订候选的限定机制 PASS **不可以**替代原版 SDK 的 Lite 资格。必须在官方未修补 SDK 的实际 ASGI/HTTP 路径独立验证：

1. 同时进行的多个独立 POST（例如 int 71/str "71"）使用真实 request/response/related-message，全部保留正确的调用归属、原始 wire ID 与类型；不能通过全部拒绝来伪造成功。
2. 同一个 POST 进入/返回的协议行为完整正确；单 POST 内的实际关联消息、progress、响应及 SDK 错误都不错误进入独立 GET/SSE 通道。0、空字符串和 "_GET_stream" 在支持的合法位置要作正反控。
3. 按 SDK 支持的模式验证 GET、初始化、协议版本、重连、Mcp-Session-Id（如由 SDK 返回）、DELETE、stateless 无跨请求状态的真实性质和客户端兼容；若 GET SSE 不提供或返回 405，必须证明协议允许、SDK 行为正确且目标客户端兼容，不能单凭假设禁用。
4. 真实 zero-buffer 背压、ASGI task 取消、HTTP 断连、发送失败、自然结束、清理竞态及重复请求下，transport/stream/worker 资源回到基线；被取消的派发前请求不产生业务执行。先复现旧 F2 反例，再观察是否受 stateless 隔离影响；不要以进程退出时 OS 回收代替服务期间的 leak 检测。
5. 客户端的 notifications/cancelled **不作为执行停止合同**，但不得因此误取消其他业务、误关响应路由或篡改结果。不得隐藏实际协议问题、改变合法 ID 域或跳过相关测试来让原版 SDK 通过。
6. 目标链路单独取证 ChatGPT Web → Tunnel → Gateway 的实际 ID、传输 POST/GET、请求持续时间、断开重试与错误结构；只收集合成负载和脱敏协议记录，不读取真实项目秘密。

**资格判定：**上述合法支持行为、请求隔离和资源清理全部可证明时，方可标记「官方 SDK 1.30.0 / Stateless / Phase 2 Lite 的传输机制资格 PASS」。任何 P1/P2 相关未关闭复现、主要路径未执行/跳过或客户端不兼容均 FAIL/BLOCK；回到方案设计而不是偷偷打补丁、减少合法 ID 类型或跳过测试。无跨请求主动取消意味着不需要为 exec 设计持久会话 seen-ID ledger，但同一请求的正确性和失败安全不豁免。

## 5. 同步执行状态与断线后的严格语义

服务端 WorkspaceService 在 admission 时签发**内部一次性 execution ticket**；它只用于一个受管理任务的状态、quota/FD/worker 关联，不暴露为远程 job API，也不以 JSON-RPC ID 作为身份。每个 ticket 的 Popen_attempts≤1。STARTING/RUNNING/STOPPING/FINISHED 由唯一 ExecSupervisor owner 改变。工作线程从接纳开始独立于 HTTP waiter，服务端生命周期负责它直到真实完成和资源回收。

- deny、dry_run 和**尚未实际启动前被安全撤销**：Popen_attempts=0，marker=0，permit 释放。
- 确实调用 Popen 但启动报错：attempts=1，业务 marker=0，返回失败并释放租约；不可内部重试 Popen。
- 已启动后客户端/Tunnel 断开：服务端**不把 disconnect 当作取消命令**，仍执行直到自然终止、服务端到期或服务关闭；不允许 ASGI CancelScope/线程池等待的取消破坏真实 worker 管理。不保证还能送达结果。
- HTTP 响应失败或结果送达未知：当前 ticket 不内部重试；用户/客户端的**下一次新 HTTP 请求**是独立接纳，可能再次执行相同 argv（若前请求占用配额则可先被 busy 拒绝）。**不**承诺跨请求 exactly-once、幂等执行或去重。
- 非零 exit code 是已执行程序的结果而非网关启动失败；超时必须标明 timed_out=true 和未自然退出的 exit_code 语义，不得伪报程序成功退出。
- 不对客户端提供 ticket 查询或结果重放。断线后可在服务端内存中保留监控所需的有限状态，但结果可在真实完成和日志安全处理后丢弃；不持久化原始 stdout/stderr 到公开工件。

**同步响应字段**保持 cwd、requested_argv、effective_argv、runner、runner_project、dry_run、executed、exit_code、timed_out、stdout、stderr、stdout_truncated、stderr_truncated、content_trust、workspace，并可在经评审后添加不泄漏本机路径的安全字段。stdout 与 stderr 分开截断至每条流最多 48,000 字符，并保留 best-effort 凭据脱敏和明确“输出不可信”标记。

## 6. 服务端超时、cwd、PGID 和资源回收

默认 timeout_seconds=60，允许 1–300。仅由 Gateway monotonic 时钟计时；在申请配额后真实 spawn 的执行窗口开始计时，且不把等待客户端送达结果计入命令的额外执行机会。**HTTP/Tunnel 超时与服务端超时不是同一个时钟**。即使实际目标客户端早于 300 秒断开，服务端仍按已接受的时长履行停止；产品不得保证客户端能收到 300 秒结果，必须用合成端到端实验记录实际等待上限。

- 保留原计划的原生 macOS actual-cwd 防竞态资格：同一候选必须**正常启动** direct 与 pipenv 子进程，观察真实 cwd dev/ino 和 Pipfile 归属，并在重命名／替换竞态下安全拒绝。旧 /dev/fd/<fd> 候选在 macOS Python 3.14.7 的正常情形出现 ENOTDIR，已判失败；**不得**回退到只靠字符串路径检查、全进程 chdir、不安全 preexec_fn 或把所有正常启动拒绝当作 PASS。
- 保留原计划原生 PGID 身份锚点证明：leader 先退出而后代仍存活、最后成员退出竞态、PGID 数值复用、TERM→KILL 期间停止、重定向/继承管道、超时 drain，不能误向第三方 group 发信号。WNOWAIT 是候选而非必须实现；不合格则 Supervisor 功能不能进入可启用状态。
- 正常到期后的策略依原合同：有安全组身份时发 TERM，约 2 秒后仍存活时安全 KILL；受管理 output drain 约 2 秒预算，保留 partial/truncated 信号并回收 reader、permit 与 root FD 租约。若识别不到安全信号锚点，必须 fail-closed，并通过隔离实验确定可提供的停止保障；不能冒险使用原数字 PID/PGID。
- 每 Workspace 一个、Gateway 全局四个 permit 由实际任务持有，**不是**由 HTTP waiter 持有；所有正常、拒绝、超时、启动失败、disconnect、SIGINT/SIGTERM 关闭路径都只能释放一次。
- WorkspaceService.close() 先停止新 admission，再按安全 identity 停止和等待所有实际 worker，最后关闭 Workspace root pins。SIGINT 与 SIGTERM 都必须经真实 Uvicorn/ASGI 生命周期验收，不得仅依赖外层 finally。关闭时的安全终止是客户端断线继续运行原则的显式例外。
- 资源期限超出可信停止能力、进程组身份不可证明、输出子进程逃组等原已记录的边界，须如实记录未验收或设计接受的限制，不能宣称任意后代/恶意代码可被 OS 级隔离。

Multi exec 的原生最低资格仍是 **macOS + Python 3.13+**；Legacy/file-only 可继续使用 Python 3.11+。新配置必须在不支持的原生环境中启动前拒绝 exec-enabled 模式，不影响旧配置、文件模式和单根模式。

## 7. 错误、用户预期和工具文档

- 拒绝、超额、执行失败、超时、非零程序退出、传输断开须有可区分结果；REST 的 HTTP 状态和 MCP ToolError 的机器码分别回归，工具错误不得映射成成功的 command result。
- 明确 dry_run 默认 true，正式执行需要 dry_run=false；MCP annotations 为 readOnlyHint=false、destructiveHint=true、idempotentHint=false、openWorldHint=true，防止客户端将 exec 自动解释为只读或幂等。
- 文档醒目标注：「客户端停止或网络断开不等于命令停止；重新请求可能再次执行；结果可能丢失；工具不能执行远程取消/查询。请仅运行可信项目命令，必要时先 dry-run。」
- 单次结果不含公开 ticket/OS PID、秘密环境及绝对私有根目录；审计可留精简计数和哈希，不留含凭据的原始命令输出到公开 Git。
- 禁止 SDK 全局 monkeypatch、site-packages 修改、替换 SDK wheel、显式状态持久 Session、私设远程 cancel/job API，除非另立规格和新的批准。

## 8. M01–M15：沿用编号的 Lite 强制验收映射

| ID | 新版处理与必须证明的内容 |
| --- | --- |
| M01 | **保留**：旧配置 exec=false；新配置只有显式授权才可执行；不兼容 Python 时新功能 fail-closed，旧 Legacy/file-only 正常。 |
| M02 | **保留**：workspace/scope/B off/缺省 ID 禁止执行，Service/REST/MCP 三层都有 deny=0 Popen 正控。 |
| M03 | **保留**：D1/D2/R1 Go/pytest 解析及路径间接执行阻断，safe 命令、direct/pipenv 与 Legacy 回归。 |
| M04 | **保留**：Host/Origin/Bearer（适用时）、raw/decoded 大小、重复键、非法字段、MCP body 均 reject-before-dispatch。 |
| M05 | **保留**：正常 direct/pipenv cwd 身份启动正控（不能只测失败），目录竞态安全拒绝，真实命令与 dry_run Popen=0。 |
| M06-L | **替换远程取消部分**：single admission Popen≤1、spawn 前安全拒绝/关闭、Popen 报错与 reader 异常回收；**没有**跨 POST cancel-to-ticket。 |
| M07 | **保留**：1/Workspace、4/Gateway；busy=409（REST）且立即无排队；其他 Workspace 文件读取不阻塞。 |
| M08 | **保留**：leader=0 但原 group 后代存活时不提前 FINISHED，安全回收后代。 |
| M09 | **保留**：escaped pipe writer/输出无 EOF 等场景 drain 预算及有限结果和资源回收。 |
| M10-L | **替换 Stateful 资格**：**官方原版 1.30.0** Stateless 的真实 SDK ASGI、独立 POST typed-ID/related 信息/GET 命名空间、HTTP 断连/背压/取消清理、客户端兼容、无跨请求 cancel 的可验证行为；所有正反控不得静默跳过。 |
| M11 | **保留**：PGID identity 锚点、复用时零误信号、合法 TERM/KILL、reap 与 FD 后置关闭。 |
| M12 | **保留**：SIGINT 和 SIGTERM，idle/spawn/running/drain/close 真实服务关闭生命周期。 |
| M13 | **保留**：stdout/stderr/无效 UTF-8/输出截断/凭据日志/FD/permit 的上下限与释放。 |
| M14-L | **修订**：每个**服务端独立接纳** Popen≤1；丢响应后不会内部重试，但新请求可合法再次启动；不可宣称 exactly-once；必须实测掉线后的 worker 持续管理与最终回收。 |
| M15 | **保留并扩展**：Phase 1 F1–F7/N1、Legacy exec/Skills、官方原版 MCP 模式、完整原生任务、真实 Tunnel/ChatGPT 合成端到端、CI/Manifest 独立标注 PASS/FAIL/NOT RUN。 |

核心 M10-L、M05、M08、M11、M12、M14-L 等需要原生或实际客户端证据；任何强制项 NOT RUN/skip 都不能作为完整功能资格 PASS。历史 PR #7 的三项 P2 + P3 限定研究关闭结论依旧有效，但不把它们当作 M10-L 对原版 SDK 的通过证据。

## 9. 资格顺序和 STOP 边界（不是实施授权）

- **资格 A（先行、隔离、原版 SDK）：**真实 SDK 1.30.0 Stateless ASGI 正反控 + 真实 ChatGPT/Tunnel 兼容和断连传播可观察性；机制失败则此 Lite 路线 STOP，不能开始有风险的 SDK-依赖接入。真实客户端调查须只用合成任务，且在另行授权后执行。
- **资格 B（独立共享安全修复）：**Task 2 D1/D2/R1 可单独提交并独立评审，不因 SDK 资格失败而停止；Legacy 行为正控必须保留。
- **资格 C（独立原生可行性）：**actual cwd 正常启动 + race 及 PGID 不误杀各自证据；任何一项失败阻断 Supervisor 及后续 Multi exec，不阻断资格 B。
- **产品开发阶段（待另行批准）**：Workspace config/admission → sole-owner ExecSupervisor → REST/MCP 适配 → 服务关闭 → 全量回归。Task 4 的前提仍是共享校验、cwd 和 PGID 安全资格。技能执行不在 Lite 范围内。
- **交付门槛**：真正独立安全＋架构复审，原生 macOS M01–M15-L 无强制跳过，Linux CI、Manifest、安全日志审计，真实 Web/Tunnel 合成验证，完整从申请到真实 worker 关闭的结果闭环。最后仍需单独批准合并、部署和启用。

## 10. 评审要求、证据与当前状态

请独立审查：与原 Phase 2 的每一处**放宽**是否确为用户选择 A 所必要，是否削弱不应削弱的 OS 进程安全；原版 stateless 是否真规避已复现路由问题或只是转移清理风险；断线后 worker/permit/timer 归属；错误与超时是否混淆客户端/服务端；M01–M15-L 是否有漏项；Legacy 和文件工具是否兼容。对每项提出固定 commit、源码行号、反例、优先级、关闭条件与所属阻断范围。没有证据的客户端可达性应写 UNKNOWN，不能推断发生频率。

本提交目标是**规格与独立评审入口**，不是执行新的 SDK probe、运行真实 Gateway、产品实现或安装修改 SDK。各层状态必须区分：本规格待书面批准；SDK 1.30.0 Lite/Stateless 机制资格 BLOCK（未验）；cwd/PGID 执行资格 BLOCK（未验）；Multi exec 代码与 Phase 2 Lite 功能资格 BLOCK；合并／部署／启用未授权。保留 PR #5–#7 的历史审计记录，后续获准后再决定如何在原实施计划中标注「由 Lite 替代」，不得默默改写已受审 SHA。
