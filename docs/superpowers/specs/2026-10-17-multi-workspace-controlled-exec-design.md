# Multi-Workspace Phase 2：Controlled Exec 设计规格（评审稿）

**日期：**2026-10-17
**当前状态：**2026-10-17 独立设计评审为 **BLOCK（D1/P1、D2–D5/P2）**。本稿补充合同但**未修复共享执行器代码**，尚待重新独立复审与用户审批，非实施/启用/合并/部署授权。
**基线：**`release/ms1` — `e32cb5124bbd8b08a79c75b4940799e041dd1295`（Phase 1 已通过 PR #3 合并）。
**现有参考：**`docs/CONTROLLED_EXEC.md`、`docs/PHASE1_LOCAL_TRUST_BOUNDARY.md`、`gateway/executor.py`、`gateway/workspaces.py`、`gateway/multi_cli.py`。

## 1. 用户已确认的决策

Phase 2 采用 **方案 A：复用现有单根 `CommandRunner` 并加入 Multi-Workspace 独立授权和进程生命周期管理**。不引入独立 OS 用户、容器、虚拟机或操作系统沙箱。

两类边界必须严格区分：

- **Gateway API 的执行入口授权：**只允许从显式选中的、已启用 exec 的 Workspace 内，在其允许的 cwd/scope 下启动白名单命令；不同 Workspace 的工具授权配置独立。
- **不承诺进程的 OS 沙箱：**`pytest`、Python 脚本和 `go test` 都能运行可信项目代码；进程拥有 Gateway 所在 OS 账户的文件与网络权限，可能访问其他 Workspace 或其他本机路径。`write.enabled=false` 只禁用 Gateway 文件修改 API，不能禁止这些受信任的子进程改写文件。

接受 Phase 1 的可信本机 OS 用户/进程威胁模型：不重新添加 UID、POSIX mode 或 ACL 启动准入。绝不能把 Multi-Workspace 称作恶意本机账户或恶意代码之间的隔离沙箱。

## 2. 目的与非目标

目的：在不破坏 Phase 1 文件工具和单根 Legacy 模式的情况下，为 Multi 模式添加按 Workspace 启用的 `run_command`；继续支持 Python、pytest、Go test/vet 与 pipenv，真实管理超时、取消、服务停止和子进程资源回收。

命令白名单与单根模式一致：`pytest ...`、`python -m pytest ...`、`python -m compileall ...`、`python relative/script.py ...`、`go test ...`、`go vet ...`。保持 `subprocess.Popen(shell=False)`，stdin 为 DEVNULL，不启用交互式 `pipenv shell`。

**复用约束：**共享 `CommandRunner` 的 Go hook 同义参数和 pytest/Go 路径型选项缺陷须先修复并通过 Legacy 负控；具体可测合同见 §12（D1/D2）。`shell=False` 不能阻止 Go 启动外部工具；仅凭逐 token 斜线切分也无法正确验证带路径值的命令选项。对任意受信任脚本的自定义参数，不宣称 OS 沙箱级路径限制。

本期不支持：通用 Shell/PTY、任意命令、`python -c`、任意环境变量透传、持久任务队列、后台任务、远程 Job 查询与取消 API、实时流式终端、Local Skill Bridge、动态策略热更新、远程主机执行、OS 级多租户沙箱、自动切换生产 Gateway。默认关闭 Phase 2。

## 3. 基线代码与预期改动边界

已经核对的 `release/ms1`：

1. `gateway/workspaces_config.py`：`exec.enabled` 目前仅允许 false；`WorkspaceSettings` 尚无 exec scope/runner 字段。
2. `gateway/workspaces.py`：每个 Workspace 自有 `Gateway`、root FD 和文件授权，当前构造时硬性 `allow_exec=False`；`WorkspaceService` 的同步 worker 租约防止提前关闭 root FD，但不具备命令级取消监督。
3. `gateway/multi_fields.py`：`_PHASE2` 同时拒绝 `run_command` 与四个 Local Skill 工具。未来只能单独开放 `run_command`，其余仍拒绝。
4. `gateway/http_multi.py`、`gateway/mcp_multi.py`：Multi 模式目前均不暴露 exec 路由和工具；它们已经拥有共享的严格 JSON/admission 和必填 Workspace 约束。
5. `gateway/executor.py`：已有命令白名单、相对 cwd、pipenv 自动选择、执行期限 1–300 秒、`Popen(start_new_session=True)`、进程组超时 kill 与有界输出；尚无跨请求进程 Supervisor。
6. `gateway/multi_cli.py`：当前 `uvicorn.run(...timeout_graceful_shutdown=10)`。已知历史观察：**SIGTERM 可能直接退出而不触发 CLI close**。Phase 2 不能依靠 Phase 1 的 SIGINT 结果证明 SIGTERM 安全。

计划只改与上述组件直接相关的配置、Workspace 进程协作、REST/MCP 协议适配及必要生命周期集成；保持 Legacy 的调用形式、默认值和 HTTP/MCP 表面不变。

## 4. 设计配置契约

建议继续使用 `schema_version: 1` 并以可选键扩展 `exec`；Phase 1 的原始 JSON 配置在新版本中原样有效，旧版本读到新启用的执行配置仍 fail-closed。

```json
{
  "schema_version": 1,
  "server": {"port": 8765, "transport": "http"},
  "workspaces": {
    "project-a": {
      "root": "/absolute/path/to/trusted-project-a",
      "read": {"enabled": true},
      "write": {"enabled": false},
      "exec": {
        "enabled": true,
        "paths": ["service"],
        "runners": {"service": "pipenv"}
      },
      "local_skills": {"enabled": false}
    },
    "project-b": {
      "root": "/absolute/path/to/project-b",
      "exec": {"enabled": false},
      "local_skills": {"enabled": false}
    }
  }
}
```

契约：只有 `exec.enabled=true` 且 `paths` 显式非空时允许执行；无 exec 即关闭，关闭时非空 paths/runners 视为矛盾配置并拒绝。`paths` 是非重复、规范的 Workspace 相对目录，不能绕过已有 `Gateway` 的禁止路径和 symlink/no-follow 规则；`"."` 表示**明确授予整个 root 作为启动 cwd 的范围**，推荐优先使用更窄的目录。`runners` 为 scope 内相对路径到 `direct|pipenv` 的字典，缺省时延续“仅在匹配 scope 以内向上查找普通 Pipfile；找到用 pipenv，否则 direct”的 Legacy 行为。

`exec.enabled` 与 `write.enabled` 互不隐式授予：允许只读文件 API 的 Workspace 单独开启 exec，但文档/能力说明必须明确执行的可信代码可以自行写盘。Local Skills 始终保持 `enabled=false`，其参数即便出现在配置中也不能使之运行。

未知字段、重复 JSON 键、非布尔 enabled、错误 paths/runners 类型、无授权的 runner 目录、非规范路径等必须在 `--check` 阶段失败且不启动监听器或任何子进程。配置保持本机私有，并继续受 Phase 1 控制面/活动代码目录保护。

## 5. REST 和 MCP 协议契约

复用 REST `POST /run`；Multi MCP 新增工具 `run_command`。两个入口使用同一参数集合和业务授权，不允许隐式 Workspace：

```json
{
  "workspace": "project-a",
  "cwd": "service",
  "argv": ["python", "-m", "pytest", "-q"],
  "timeout_seconds": 60,
  "dry_run": true
}
```

- `workspace`、`cwd`、`argv` 必填；`timeout_seconds` 整数 1–300（默认 60）；`dry_run` 严格布尔（默认 true）；argv 继续遵守 Legacy 的长度/类型/禁止参数规则。拒绝 Pydantic 类型强转、重复字段、未知参数、非标准 JSON 常量和无效 Unicode。
- `dry_run=true` 必须走完整 Workspace/cwd/runner/script 校验，但进程创建数量必须为 0。返回 Legacy 的 `requested_argv`、`effective_argv`、`runner`、`runner_project`、`executed=false` 等字段，加 `workspace`；不返回绝对 root、Token、配置路径。
- 实际执行返回 Legacy 格式的有限 `stdout/stderr`、`exit_code`、`timed_out`、`executed` 和 `content_trust=untrusted_command_output`，每流最大 48,000 字符、凭据行脱敏仅为 best-effort。失败的命令退出码仍是正常响应字段，不是 HTTP 500。
- 当所有 Workspace exec 均关闭时，Multi 模式 `tools/list` 不出现 `run_command`，REST `/run` 不注册；一旦至少一个启用，接口可被发现，但每次仍通过选中 Workspace 的权限校验，不能以“工具可见”代替授权。
- `list_workspaces` 仅返回各 ID 的 exec 布尔能力，不展示绝对 root、完整配置或 runner 内部文件。MCP 注解应是 `readOnlyHint=false`、`destructiveHint=true`、`idempotentHint=false`、`openWorldHint=true`。
- 统一的请求链必须保持 `Boundary (Host/Origin/Bearer) → StrictPostAdmission → strict arguments → WorkspaceService.require → CommandRunner`；必须对 Multi REST 与 MCP SDK 两个入口进行原始参数负控。
- 预期拒绝码：无/未知 Workspace 分别 400/404；exec disabled、exec scope 外或禁止命令 403；并发容量耗尽 409；服务关闭 503；runner 不可用 503；启动失败 500；未认证请求 401。固定错误码不得泄露本机目录和环境变量。

## 6. Workspace 授权与路径身份

`WorkspaceService` 是服务端最终授权点；REST/MCP 验证只是外层拒绝。每次真实启动前需检查配置中的 `exec.enabled`、请求 Workspace ID、相对 cwd 属于显式 scope、实际根目录 pinned identity/安全的目录分量、所选 runner 的有效作用域。不得从 path 推断 Workspace、回退至默认 root、跨 root 修改 cwd 或借另一个 Workspace 的 Pipfile。

已有 `Gateway.run_command` 及 `CommandRunner` 应被复用，而不是复制一个权限更弱的 Multi 执行器。已配置好的 `Gateway` 可以在仅启用 exec 而未启用文件写的 Workspace 中运行；权限声明应显示 exec=true、write=false，但明确这是 Gateway API 两种能力的区别，不能宣称 OS 只读。

运行可信测试代码和 Python 脚本意味着 argv 白名单不是对其副作用的约束。项目中的不可信脚本、特殊 pytest 插件和 Go 测试可越出工作目录操作宿主机；这一点纳入风险声明，不用虚假的“跨 Workspace 进程沙箱”验收测试替代。

## 7. 执行监督、超时与取消

> **独立复审补充：**本节为总体原则；§12 的 D3/D4 终态、drain、容量和 PGID 所有权合同是额外强制条件。直接子进程退出 ≠ 受监管作业完成，输出截断上限 ≠ drain 时间上限。

第一版保持同步请求/结果（不发布可查询的 job ID，也不提供显式 `cancel_command`）；取消源仅包括**实际观察到**的请求取消/连接断开、超时、Gateway 关闭。网络/隧道未传播断开事件时不保证即时取消，但真实命令仍应受最大 300 秒 timeout 管束。

增加内部 `ExecSupervisor`（作为复用 `CommandRunner` 的协作对象，而非独立 OS Worker 服务），登记 `STARTING/RUNNING/STOPPING/FINISHED`、执行进程与 process group、取消标志、同步 worker FD 租约。拟议资源上限：每个 Workspace **1** 个活跃执行、单 Gateway **4** 个；超额立即 `busy` 拒绝，不排队，不占用文件读写的全局互斥锁，A 的长任务不阻塞 B 的文件操作。

要求：

1. 先登记执行租约及状态，再启动进程；取消与 `Popen` 交界的前后竞态都必须安全：已取消不能漏启动，已启动必须被跟踪和回收。
2. 子进程采用 `shell=False`、`stdin=DEVNULL`、`start_new_session=True`。在超时、已观察到的取消或服务关闭时，向进程组发送 SIGTERM，给予有界宽限（**建议 2 秒**），再用 SIGKILL 兜底，并 `wait()` 回收直接子进程；不能只停止 await 而留下子进程。
3. stdout/stderr 同时持续 drain，限制缓冲与输出长度，异常/超时亦须关闭管道和完成 reader 清理。必须先完成子进程终态和资源回收，最后释放持有 Workspace root FD 的同步 worker 租约。
4. `WorkspaceService.close` 拒绝新文件与 exec 调用，通知 supervisor 停止活跃执行，等待真实工作线程及子进程收尾，**最后**关闭 Gateway 和 pin FD。不得使用强制超时关闭仍由 worker 使用的 FD。
5. SIGINT **和 SIGTERM** 都必须经真实监听器验证进入上述关闭路径；单靠 `uvicorn.run(...timeout_graceful_shutdown=10)` 或 SIGINT 的旧验收不能覆盖 SIGTERM。验证关闭并发、取消发生在 spawn 前/后、读写 worker 与 exec 共享关闭状态、真实进程组及 FD 泄漏。
6. 非恶意的受信任项目代码可自行 `setsid` 逃离启动进程组，因此不承诺杀死所有退出原进程组的后代；强制 SIGKILL、断电、任意不可中断内核 I/O 也不属于“有界优雅关闭”的保证。
7. 超时继续使用 `executed=true`、`timed_out=true`、`exit_code=null` 等 Legacy 语义。若取消发生且响应仍能交付，Multi 可添加 `cancelled` 字段；实际断线时可能无法送达结果，但内部清理必须完成。Legacy 输出字段的意义不得改变。

**设计风险门槛：**如果独立审查认为传输断开不可靠、用户必须主动远端取消，需先更新本设计并明确取消 API/认证/状态机，而不是未经批准偷偷扩展持久后台任务。

## 8. 日志、凭据与错误策略

命令环境继续采用小型白名单，不继承 `GATEWAY_TOKEN`、`VIRTUAL_ENV` 或任意自定义敏感环境变量；Pipenv 仅设置明确的 `PIPENV_PIPFILE` 与必要选项。日志可记 Workspace ID、命令类别、状态、耗时、超时/取消、容量命中，但不得打印 Token、完整 argv、stdout/stderr 原文或配置/项目绝对路径。

执行结果中的 stdout/stderr **可能包含机密数据**，原有 best-effort 文本脱敏不是通用 DLP；通过 Tunnel 提供 exec 必须由管理员只对可信项目显式授权。Gateway 不得因鉴权错误、解析错误或**同一已接纳请求的内部重试/异常恢复**重复启动实际命令。跨独立请求的重试不提供 exactly-once，见 §12 D5。

## 9. 强制验收矩阵

> 原有测试类别仍适用；§12 中 M01–M15 的状态/计数/负控断言是本次 BLOCK 复审要求的附加验收门槛。原有 CI、Manifest 或基线探针均不能替代尚未实现的 Phase 2 REST/MCP 动态验收。

| 范围 | 必测项 |
| --- | --- |
| 配置兼容 | 原 Phase 1 JSON 保持可用、exec 默认关闭；enabled 无 scopes、非规范路径、非法 runner/字段/类型、重复 JSON 键必须在监听前拒绝；Legacy 单根 CLI 无回归。 |
| 授权负控 | Workspace 缺失/不存在/未授权，越界 cwd、symlink、被保护目录、非法 argv、`--pdb`、`python -c`、Shell/跨项目路径均在 `Popen` 前拒绝；通过模拟 Popen 计数证明无副作用。 |
| 协议负控 | REST/MCP 严格一致；Host/Origin/Bearer 401/403、无效 MIME、重复参数、Unicode、非有限数、未知字段、过大 payload；Tools 列表仅按授权暴露 exec，Skills 仍不存在。 |
| 实际执行 | 合法 Python/pytest/Go/pipenv、dry-run、失败退出码、超时、输出限额/敏感行标记、进程启动错误；响应均绑定正确 Workspace。 |
| 并发取消 | 1/Workspace 与全局 4 的限额，同根并发冲突、异根并行、取消前/后 Popen 竞态、输出线程错误、真实进程组/FD/线程回收。 |
| 生命周期 | 真实 macOS 监听器接收 SIGINT 与 **SIGTERM**，取消活跃任务并等待真实 worker，避免泄漏或提前关闭 FD；测试断连能被观察到和未能观察到的区别。 |
| 完整回归 | Phase 1 F1–F7/N1 的既有回归、文件读写/备份/旧 Legacy exec+Skill、原生 macOS 全量、REST/MCP live smoke、GitHub Actions、Manifest SHA 校验。 |

只要出现未授权启动、越权 Workspace 入口、**受监管进程**残留、受监管进程取消失效、SIGTERM 不进入清理路径、Local Skill Bridge 被顺带启用、无法通过原生 macOS 安全回归、或者任何独立复审的 P0/P1 阻断项，则**不得合并 Phase 2**。

## 10. 实施顺序、发布与回退（尚非实施授权）

必须先在共享 `CommandRunner` 中安排 D1/D2 的语义修复和 Legacy 负控，再允许 Multi exec 的实际启动入口；D3/D4 监督器、可中断 drain 与 D5 至多一次内部启动是另外的独立实施/验收任务。**本轮仅修订设计、不实现这些修复。**

用户批准本规格后，才起草可审阅的详细实施计划。计划应按“先失败测试，后配置解析、授权路由、执行监督、REST/MCP 表面、真实 macOS 回归”拆分，功能分支不修改运行中的 Gateway。独立安全/架构审查与用户最终合并批准是另外的门槛。

保持 `exec.enabled=false` 为默认，Phase 2 程序合并不自动修改私有配置/Tunnel/部署。回退可在受控维护窗口关闭 exec 授权、`--check` 后切换回文件模式；不需要改变 Phase 1 的 Workspace 数据或备份。

## 11. 本稿需审阅的细节

**已确认：**复用方案 A、可信本机进程、无 OS 沙箱、显式 Workspace exec 授权、Legacy 兼容、Local Skill Bridge 不在 Phase 2。

**拟议、需随文批准后才能冻结：**继续扩展 `schema_version:1`、`paths:["."]` 的明确语义、1/Workspace 与 4/进程的并发限额、2 秒终止宽限、Phase 2 首版不提供远端主动取消 API。以上给出了可执行测试合同，但**用户当前的“接受”仅批准方案 A 的隔离边界，不代表这些细项已自动获批**。

用户审阅并批准本文件后，下一步才调用实施计划工作流。此时不得修改功能源码、启用 Multi exec、执行真实命令或调整生产 Gateway。
## 12. 2026-10-17 独立 BLOCK 复审补充合同（规范性）

**原受审设计 Commit：**`23a579df7dcacae4490e492a557fe8460f369bfa`，Tree `11d2a185c75a28972a8757623eda5a77a2999e7e`。独立报告判定 1 项 P1（D1）、4 项 P2（D2–D5），设计不能冻结。本节细化前文而不改变已确认的方案 A、可信本机项目及**无 OS 沙箱**边界。本节修订**不等于**共享执行器漏洞修复或 Phase 2 功能验收。

### D1 / P1 — Go 外部工具 hook 等价选项（实现仍 OPEN）

复用共享 `CommandRunner` 之前，必须按 Go 实际解析语义规范化 flag 名：单横线与双横线、`flag=value` 与 `flag value`、参数位置变体。至少对 `exec`、`toolexec`、`vettool` 等可指定外部命令的 hook 全部拒绝。当前只检查 `-exec` 等单横线前缀会放行等价形式，直接 `Popen(shell=False)` 不能限制 Go 之后启动的程序。不得把“可信项目代码可读写宿主机”当作放行**远程 argv hook** 的理由。

**关闭条件：**修改 Legacy/Multi 共用解析器；所有 hook 等价写法在 dry-run 和 apply 均于 `Popen` 前拒绝，`Popen` 计数严格为 0；原生合成 Go marker 不能被触发；合法 `go test`/`go vet` 及常用非 hook 参数继续可用。未完成代码修复前，此项保持 **OPEN / P1 阻断**。

### D2 / P2 — 提取路径型选项值后校验（实现仍 OPEN）

不能仅对整个 argv token 的斜线切分来校验 `..`/绝对路径；选项名前缀会隐藏真实路径。对**明确支持的命令和已知携带路径的选项**，必须先按各 CLI 文法分离 option 与 path value，再对真实值应用相对路径、无父目录、无宿主绝对路径和允许 scope 规则。首批必测 pytest `-cVALUE`、`-c VALUE`、`--config-file=VALUE`、`--config-file VALUE`，以及 Go `-modfile=VALUE`、`-modfile VALUE` 等受支持等价形式；明确验证外部兄弟配置和绝对配置被拒绝，项目内合法配置仍允许。自定义可信 Python 脚本未识别的自由参数仍为非沙箱风险，不应声称都能静态约束。

**关闭条件：**Legacy 与 Multi 共享安全修复；非法形式 dry-run/apply 的 `Popen=0`，并以独立合成 pytest 配置读取、Go 模块参数反例及正常控制用例验收。

### D3 / P2 — 正常 leader 退出不能立即 FINISHED

独立的内部作业 ticket 拥有 `STARTING/RUNNING/STOPPING/FINISHED`、进程组、可取消信号权限、同步 worker root FD 租约和 permit。前三个状态均占执行名额。即使 leader `wait` 返回 0，原进程组可能仍有受监管后代且继续持有 reader 管道；须检查并终止/收尾该**原进程组**，不可直接释放名额。可以保留 leader 的 `exit_code=0`、`timed_out=false`，将清理结果另记为 `group_cleanup`，不误报原命令失败。

只有当直接子进程已 `wait`、所监管原组完成结束/清理、输出读端已按 D4 合同回收、实际 worker 租约释放后，才能进入 `FINISHED` 并释放计数。取消/延迟计时器从终态起撤销信号权限，不能用已经失去所有权的数字 PGID 误杀后来的复用进程；使用假系统调用和代际 ticket 验证，不在真实机上误杀无关进程。自建 `setsid` 的逃组后代不在“必须杀尽”的范围，但其继承管道必须由本服务安全处理。

### D4 / P2 — 可中断输出读取、独立 drain 截止时间

原始组清理、主进程 `wait` 和每流 48k 字符留存限制均不保证管道 EOF。逃组后代可能继续持有 stdout/stderr 写端，阻塞式 `BufferedReader.read` 及跨线程 `close` 均不可作为可靠的停止方案。采用**单一 FD owner**负责读取与关闭：例如 `os.set_blocking(fd, False)` 加 `selectors.DefaultSelector`/有限 poll 与显式停止通知；其它线程只能通知 owner，不能跨线程关闭正在阻塞读取的同一 FD。实现可以选择等价可证明机制，但必须有独立测试。

**时限草案（待审批）：**进程 TERM 宽限 2 秒后升级 KILL；输出 drain **另设最多 2 秒**，即使没有 EOF 也结束本服务读端并回收 reader/FD/permit。两种预算分开计时；`timeout_graceful_shutdown=10` 不是这些阶段安全收尾的证据。超过 drain 预算保留已经捕获的部分输出，并明确 `drain_incomplete` 或相应 `stdout_truncated`/`stderr_truncated` 标记。强制 KILL、断电或任意不可中断内核 I/O 不承诺绝对收尾时限，但可控合成管道与线程应满足预算。逃组 helper 的生命由测试自身管理，不得以其仍存活判定“受监管原组残留”。

### D5 / P2 — 选择“单次服务端接纳至多一次启动”（待用户批准）

**建议采用评审选项 A，避免首版引入幂等键和持久 Job 系统：**同一个服务端已接纳的 REST/MCP 请求内部有一个唯一 ticket，整个服务处理链中最多一次真实 `Popen` 尝试。授权失败、解析失败、失败重试或异常恢复不能在同 ticket 内再次启动，尤其禁止捕获执行器异常后无意重新调用。

**不承诺跨独立请求去重或 exactly-once。** 若命令产生副作用但 HTTP/MCP 响应丢失，调用者不知道它是否完成；把同样五个参数重新发送（即使同 MCP request ID）是**新的执行请求**，可以再次产生副作用。`idempotentHint=false` 仅提示非幂等性，不是服务端去重保护。合成副作用 marker 负控：同一 ticket 内异常/处理重入至多 1 个 marker；丢弃第一次响应后独立重传可以有第 2 个 marker；主动再次执行也合法。此选择须经用户在正式设计审批时确认。

### 资源、路径与 SIGTERM 交接条件（独立复审 I3–I8）

- `_cwd()` 当前只是暂时打开 no-follow FD，交给 `Popen(cwd=...)` 时未必保持目录 pin；执行授权应保持根与实际 cwd 身份在最后校验→启动交接期间有效，并验证子进程真正工作的 Workspace/cwd；不可在多线程 macOS 用不安全的 `preexec_fn` 偷渡。
- Exec 的名额在提交到耗时同步线程池前通过 `WorkspaceService/ExecSupervisor` 原子 admission 取得；同一 Workspace 拟 1 个、全局拟 4 个。名额满时业务服务立即 busy 而不是先排队；已取消的等待者不得晚启动。长期 exec 不能耗尽 Phase 1 文件 API 的 worker，也不能持有全局文件锁。
- 请求取消必须分别验证 asyncio Task.cancel、AnyIO CancelScope、MCP SDK 取消通知与 REST 实际可观察断连；AnyIO 屏蔽等待者取消不等于同步 worker 终止。不能观察到的网络中断，只保证最长执行期限。
- SIGINT 与 **SIGTERM** 均须通过原生 macOS **真实 Gateway** 活跃任务测试，证明关闭路径抵达、停止接受新请求、受监管进程组停止、实际 worker 收尾、root FD 最后关闭；现有 `uvicorn.run` 的 SIGTERM 最小监听器负控仍是待解决风险。

### M01–M15 强制验收断言（细化 `9）

- **M01 配置：**旧配置到新代码正常且 exec 关闭；新 enabled 配置到旧代码 fail-closed；非法配置 listener=0/Popen=0。
- **M02 授权：**A 开启 B 关闭，Service 直接、REST、MCP 三路 B 均 Popen=0；无 Workspace 不回退；Skills 未启用。
- **M03 CLI 语义：**D1 hook 与 D2 路径值每一种等价写法均拒绝且 Popen=0，原生 Go/pytest 合成 marker 和合法控制通过。
- **M04 协议：**Host/Origin/Bearer、MIME、重复键、非法 Unicode/非有限数、未知字段及超限 payload 都在 dispatch/Popen 前拒绝，REST/MCP 各自错误封装正确。
- **M05 合法行为：**direct、pipenv、Python、pytest、Go、dry-run=零进程、非零退出、缺失 runner、cwd/输出绑定正确。
- **M06 启动竞态：**ticket→permit→授权→Popen→handle 注册→drain→终态各屏障取消/异常，单 owner 清理且计数、FD 恢复。
- **M07 容量：**STARTING/RUNNING/STOPPING 均占额度，超额立即 busy 不排队；A 长 exec 不阻塞 B 文件读写；取消等待者绝不再启动。
- **M08 正常结束：**leader 0 退出、原组后代持管道和重定向管道两种，组清理后 FINISHED，旧 exit_code 不改变，FD/permit 为 0。
- **M09 逃组持管道：**stderr 单独持有、stdout/stderr 共同持有，drain 预算内回收自身 reader/FD，helper 测试后安全清理。
- **M10 超时取消：**TERM 被忽略后 KILL；Task.cancel、CancelScope、MCP cancel、REST 可观察/不可观察断连分别验收。
- **M11 生命周期身份：**重复 close/cancel、leader 提前退出、旧 PGID 信号、FD 数字复用的模拟均不得错杀或跨 Workspace 误用。
- **M12 真实监听器：**macOS SIGINT/SIGTERM 的 idle/spawn/active/drain/并发 close，验证顺序与实际 worker/FD 收尾。
- **M13 输出与凭据：**合成敏感变量不继承/泄漏，stdout/stderr 巨量/无效 UTF-8、reader 错误，输出有界且错误无绝对路径。
- **M14 重试：**有副作用 marker 后丢弃响应；同一 ticket 至多启动一次，外部独立重传可产生第二次副作用并被明确记录。
- **M15 完整回归：**Phase 1 F1–F7/N1、文件/备份、Legacy exec/Skill、macOS 全量、REST/MCP live smoke、CI 与 Manifest 分别给结果；旧 CI 不替代未实现的功能验收。

### 处置状态及保留的批准门槛

| Finding | 本稿处置 | 不可提前宣称的结论 |
| --- | --- | --- |
| D1 / P1 | 明确 Go 同义 hook 共享执行器前置修复与 Popen=0。 | **代码仍存在基线漏洞；OPEN / 阻断。** |
| D2 / P2 | 明确路径型选项值提取、正反控制与 Legacy/Multi 复测。 | **代码尚未修复；OPEN。** |
| D3 / P2 | 明确正常 leader 退出后的组清理/终态/PGID 回收。 | 未完成真实 Supervisor 实现及验证。 |
| D4 / P2 | 明确单 owner 非阻塞 drain、期限、部分输出。 | 未完成真实管道/关闭验证。 |
| D5 / P2 | 推荐单 ticket 至多一次；跨独立请求不保证去重。 | **需用户批准该合同；没有跨请求幂等保证。** |

本次仅保留外部独立复审的编号、风险与逻辑结论；不将报告中含本机私有路径的证据 ZIP、日志或任何真实配置发布到公开仓库。规格须先通过新的独立设计复审并获用户批准，之后才可编写详细实施计划；D1/D2 代码修复和 D3/D4 原生验收又是另行的合并门槛。**本次文字修订不是设计 PASS，更不是 Phase 2 功能 PASS。**
