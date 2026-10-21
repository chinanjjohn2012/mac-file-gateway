# Mac File Gateway — Git CLI V1 逐文件实施计划

Status: **A–F 分批独立 Standards / Spec 复审 PASS（无未关闭 P0/P1/P2）；F Linux CI、用户提供的 macOS 原生验证、真实 ChatGPT Web → Secure MCP Tunnel Git E2E 均 PASS；2.5.0 单次集成发布仍待独立定向复审与运营审批，最终合并、Tag、部署及生产 Git 启用未批准**  
Date: 2026-10-21  
Authoritative design: docs/GIT_CLI_V1_DESIGN.md @ e32de7b896a3231fd9e60ac5798ea94b482c5e07  
Design review: **Standards PASS / Spec PASS，P0=0、P1=0、P2=0**（用户提供的独立定向复审结果）  
Pre-Git runtime baseline: release/ms1 @ ba8634f24cdc26904d1c80951df7173e429240c7, MCP Python SDK 2.3.0  
Implementation base: the approved design commit above. This plan is subordinate to the design and is **not implementation evidence**.

### 2026-10-21 实施与测试验收记录（不等于发布授权）

- F 固定测试基线：`b0bfe1f6b9e2ebfc79db01b716bd2074bd19fb56`（Git CLI V1 T15/T16 原 P2 已由独立定向复审关闭；Standards / Spec PASS）。
- F Linux [Actions #39543099172](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39543099172)：`1109 passed, 8 skipped`，真实 Git/MCP Smoke 与 Manifest 157 项 PASS。
- 用户在隔离的 macOS 临时仓库报告：`1117 passed, 1 warning`，MCP/stdio/Git Hook 断连 Smoke PASS、`Release manifest: OK`、退出码 0。这是用户提交的本机日志，不冒充本助手远程 macOS 执行。
- 真实 ChatGPT Web → Secure MCP Tunnel → 测试 Gateway 实测：工具发现、A/B 独立授权、Git Preview/Apply、非幂等 Commit、断连后的 Hook 完成（用户观察提交数 2 → 3）及重连后的 `run_git(status)` PASS；见 [PR #31 E2E 记录](https://github.com/chinanjjohn2012/mac-file-gateway/pull/31#issuecomment-6311418279)。
- **2.5.0 集成发布收尾**仅调整版本/文档/断言/Manifest；真实生产发布与 Git 高权限启用仍须运营者在新增集成 PR 的独立复审、完整 CI 后明确批准。源码所含 Git 执行权限默认关闭。

## 0. 目标与不可改变的契约

目标：增加受服务端总开关及 Workspace 级命令名单控制的 Git CLI，提供结构化 run_git 而非任意 argv，允许在 Workspace 子目录运行原生 Git，并允许 Git 向上发现父级 Repository 及修改整个实际仓库。

不可改变：

- 服务端 server.git.enabled 缺省 false；每 Workspace 的 git.allowed_commands 缺省空，需已实现 Schema 才能授权。Legacy 需显式 --allow-git + --git-command。
- 每次 Multi 请求显式 workspace；命令、options、paths、cwd 只走严格 Schema 和同一业务服务，不复用普通 run_command 的执行权限。
- cwd 和客户端**明确提供的本地路径参数**限制在选定 Workspace 内；Git 真实仓库可位于父级，Git 产生的跨 Workspace 文件、Hook/Filter/Remote 副作用明确允许。这里不是文件系统沙箱。
- V1 不支持 checkout、clone 以及其它未实施的 Git 命令；不接受任意 argv、Git 全局选项、额外 flags、Revision/pathspec 表达式注入。
- Git 自己决定 .gitignore、Index、工作树、Hook、Credential Helper、Remote 的语义；不把现有文件 API hidden/exclude/redaction/backup 规则套在 Git 效果与输出上。
- 同一 common Git dir 的 Gateway Git 操作保守串行；独立仓库可并行。首次 git rev-parse 前持久化每调用 DISCOVERING，仓库内任一 Git 子进程前持久化 RUNNING；清理不确定后失败关闭，重启遗留记录不得自动解封。
- Worker 租约从实际同步工作线程取得至其资源释放为止；HTTP 断连不等于取消，结果丢失时不自动重试写命令。保留 SDK 2.3.0 双协议。
- Multi-Workspace **stdio 仍然不支持**：测试 Multi HTTP 适配两版协议及 Legacy HTTP/stdio 两版协议，同时测试现有 --config --transport stdio 被拒绝；本任务不为 Multi 增加 stdio。

**实施止损原则：** 若代码现实与已通过的设计冲突、发现无法满足的原生 Git 行为或需要增加新的高权限接口，先停止相应文件实施并提交证据回到设计复审，不以自行放宽输入或权限解决。

## 1. 现有代码锚点（已核对）

| 文件 | 当前情况 | 计划切入点 |
|---|---|---|
| gateway/workspaces_config.py | 严格 schema_version=1；server 仅 port/transport；Workspace 仅 read/write/exec/local_skills | 扩展 Git 配置，不改变已有字段 |
| gateway/workspaces.py | WorkspaceService._operation/require 只接受文件操作；service.close 等待实际 Worker | 新建 Git 专属授权与同步 Worker 租约；共享 Git 协调器 |
| gateway/multi_fields.py | 前置 SDK 参数的精确类型/字段检查；Multi 的通用 workspace 注入 | 增加 run_git 及嵌套 options/paths 严格校验 |
| gateway/private_fs.py | pinned FD 打开私有路径；拒绝 symlink/非普通控制文件；本地账户视为可信 | 复用校验原则，不弱化现有读逻辑；Git 私有状态单独写协议 |
| gateway/core.py | Gateway 初始化 Writer/CommandRunner；close 直接关闭 root_fd；现有 _parts/_directory 专属于文件规则 | Legacy 专属 Git Worker 生命周期和 opt-in；File API 保持不变 |
| gateway/executor.py | 单独的 pytest/Python/go allowlist；超时后 KILL、流读取 | **不扩张**到 Git；只参考现有实现与测试经验 |
| gateway/mcp_adapter.py | SDK 2.3 MCPServer + StrictLegacyMCP.call_tool；run_in_threadpool | Legacy 独立 run_git 注册、strict context/call_tool |
| gateway/mcp_multi.py | SDK 2.3 MCPServer；Write tools 按 any_write 注册；无执行工具 | Multi 有效 Git 权限非空才注册 run_git |
| gateway/http.py | Legacy POST /run 特判；统一 Boundary；按服务启用调整 body budget | 增加专用 POST /git/run，不用 /run |
| gateway/http_multi.py | GET/POST 文件表及 StrictPostAdmission；write_endpoint 调 service.invoke | 新增 Git 独立路由/调 service.invoke_git |
| gateway/__main__.py | --config 与 Legacy 权限参数互斥；只建立 Gateway/Skill | 新增显式 Legacy Git flags，不改变多模式选择 |
| gateway/multi_cli.py | 构建 WorkspaceService；提示“Execution disabled in Phase 1” | 显式显示 Git 特权和仍禁用的通用 Exec/Skills |
| gateway/multi_admission.py | 全 Multi POST 的 8MiB、重复 JSON Key、复杂度门禁 | 原则上不改，新增路由复用 |
| gateway/mcp_transport.py | 双协议及 stateless JSON；subscriptions=False | 原则上不改，做协议回归 |
| verify.sh / GitHub Actions | compileall、pytest、REST/MCP smoke、Manifest 强一致 | 在 Git 实现完成后补独立 Git smoke/崩溃测试 |
| MANIFEST.sha256 | 当前设计 HEAD 校验条目 133 项 | 每次可交付提交更新，最终用 verify.sh + Actions 验证 |

## 2. 任务分组、依赖顺序与每个文件的修改

### P0 — 构建纯策略与输入门禁（没有 Git 执行能力）

#### T01 — 新增 gateway/git_policy.py

职责：**纯数据与纯编译**，不启动任何 Git、不读取磁盘 Git 配置，也不访问网络。

修改：
1. 声明 10 个 V1 命令：status、diff、log、branch、switch、add、commit、fetch、pull、push；checkout/clone/其它命令必须在配置及调用层拒绝。
2. 定义每个 command 的精确 options schema：必填、默认值、严格类型、枚举、整数范围、互斥和仅适用的 paths；拒绝未知字段与原始 argv/extra_args。
3. 纯内存校验 branch/ref、remote 名称、message、expected_remote_oid 的字段类别；明确区分 lexical validation（Preview）和锁内状态核验（Apply）。
4. 将固定 Schema 编译为唯一 Git argv（无 shell）。switch 固定 --no-guess；push 用 refs/heads/<branch>:refs/heads/<branch>，绝不生成裸 +main；force-with-lease 仅允许精确目标 ref 和显式旧 OID。
5. 路径操作使用服务器生成的 -- 和 literal pathspec 序列；输出不存在让客户端插入新 Git option 的通道。
6. Preview 只返回选定 Workspace-relative cwd、结构化命令、规范化 argv 及 repository_checked=false / remote_checked=false / branch_checked=false / execute_started=false，不调用 git --version、rev-parse 或其它 Git。
7. 错误码统一按 Git 专属命名：git_disabled / git_command_not_allowed / git_option_invalid / git_path_blocked 等，且错误消息不回显敏感原值。

新增 tests/test_git_policy.py，验证：
- 逐命令正确/错误 options、缺省、互斥、unknown、null、bool 与 int 混淆、过长/控制字符。
- branch="+main" 只出现在服务端拼接的完整 refspec；无 lease 的非快进 push 无强制标记，错误 lease 不会降级为强推。
- checkout、clone 和其它未实现命令始终拒绝；无 paths 命令传 paths 被拒绝。
- Preview 对 Git 执行接口的 spy 调用数绝对为零。

完成门禁：仅单元测试；业务 Git 仍无法从外部调用。

#### T02 — 修改 gateway/workspaces_config.py

修改：
1. GatewaySettings 增加全局 Git enabled；WorkspaceSettings 增加 immutable allowed_commands。
2. strict server.git={"enabled": bool}，缺省 false；Workspace.git={"allowed_commands": [...]}，缺省空数组。
3. 只允许 T01 已实现 Schema 的 Git 命令，验证无重复、合法字符串、上限，未知字段和与总开关矛盾的配置 fail-closed。
4. 不放宽原 root、read、write、exec、local_skills、hidden_paths 的现有严格验证，不要求 Git 仓库根在 Workspace 内。
5. 私有 Git 状态的持久位置在 Workspace 外，必须稳定跨进程重启。Multi 优先从受保护 config_dir 派生专用 state 子目录；Legacy 使用稳定的按项目隔离的本机私有状态路径。**不无意新增客户端可改写的 state_dir 参数**；若安全实现需要新增外部配置字段，应先复审。
6. state 目录与 Workspace / 活跃运行代码目录不得相交；初始化要在启动运行监听前 fail-closed，不能靠动态请求阶段才发现状态目录不可读。

修改 tests/test_phase1_workspaces_config.py；新增 tests/test_git_config.py。

完成门禁：旧 Multi 示例完全兼容；Git 缺省禁用；exec/local_skills 仍按 Phase 1 拒绝；非法 Git 配置在启动前被拒绝。

#### T03 — 修改 gateway/multi_fields.py

修改：
1. 新增 run_git 入口的精确顶层 required/optional 字段和类型：command 必填；cwd 默认 "."，options 默认 {}，paths 默认 []，timeout_seconds 默认 120，dry_run 默认 true；Multi 的 workspace 仍必填。
2. 在 SDK/Pydantic 可能做值转换之前严格检查嵌套 options、paths 的类型、长度、边界；真正授权和 Schema 校验仍在 GitService 同步 Worker 内重复执行。
3. run_git 不是通用 run_command，也不能被 _PHASE2 误禁用；无需把 Phase 1 的 Exec / Skill 开关改开。
4. Legacy signature 不需要 workspace；Multi 永远需要合法 workspace，错误码保持一致。

修改 tests/test_phase1_multi_fields.py 和新增 tests/test_git_fields.py。

完成门禁：MCP/REST 的非法输入在任何 Git 进程启动之前拒绝；重复 Key 继续由已有 REST/Multi admission 处理。

### P1 — 目录身份、仓库状态与同步进程（尚不开放外部入口）

#### T04 — 新增 gateway/git_repository.py：路径与仓库身份

修改：
1. 以已授权 Workspace 根 FD/身份为起点检查 cwd 和每个显式本地路径；拒绝绝对、..、symlink 祖先/叶节点跳出、缺失父级、混淆式 pathspec 和跨 Workspace 路径。仅对 Git 入参做路径验证，不调用 Gateway._allowed 去套文件扩展名/隐藏规则。
2. 在服务器固定、已清理的 Git 环境下运行内部有界 rev-parse，读取 Git 实际 worktree、gitdir、common-dir，允许仓库根位于 Workspace 父级；无仓库时以明确状态失败。
3. 以 common Git dir 稳定物理身份构造共享协调键，而不是简单的相同字符串；同仓库 linked worktree 应指向同一键。
4. 创建仓库独占锁注册表：V1 同仓库所有 Git 调用（读/写）串行、不同仓库可并行；等待锁最多 10 秒并受总预算限制。不得持有 WorkspaceService._lifecycle 条件锁等待仓库锁。
5. 获取锁后再次核验仓库身份；发生替换返回 git_repository_changed，不静默换锁或改查另一仓库。
6. 若此文件过大，可在独立复审后将仅与持久运行记录相关的实现拆成 gateway/git_state.py；优先遵守已通过设计的三模块结构，不为抽象增加无意义文件。

新增 tests/test_git_repository.py：父级仓库、共享 common-dir、linked worktree、symlink、真实路径身份、无仓库、有界锁、独立仓库并行、身份突变。

完成门禁：仓库身份发现和锁独立可测，但任何首次 discovery 不允许跳过 T05 的持久前置意图。

#### T05 — gateway/git_repository.py：持久活动记录、隔离与恢复启动门禁

这是**本实施计划最高优先级失败关闭任务**，必须先于任何可公开执行的 Git 入口完成。

修改：
1. 在 Workspace 外的服务端私有状态目录保存 per-invocation DISCOVERING / per-repository RUNNING / QUARANTINED 等活动记录；记录使用稳定调用 ID、common-dir 身份、必要的时间和可用的 PID/PGID 启动身份证据，不包含凭据或原始 Git 输出。
2. 使用受控 FD 打开与 no-follow 路径检查，持久提交经过临时文件、fsync、rename、父目录 fsync；持久失败不准执行 Git。除非本机已接受的信任模型另有要求，不新增 POSIX UID/ACL 权限门禁；仍必须防止 Gateway File API 对私有状态读写。
3. **从第一次 Git 进程启动前**获得短期服务端级准入门并同步落盘独立 DISCOVERING。首次 rev-parse 启动前必须已有持久记录；若无法落盘，Git 进程启动数为 0。
4. Discovery 主进程/受控子进程完整 wait/reap/drain 后才删除本次 DISCOVERING 并同步目录；多个正常并发 discovery 记录不相互覆盖/误删。若尚不能归属 Repository 的子进程清理未确认，保留记录并进入 GLOBAL_QUARANTINED。
5. 在 discovery 彻底清理、记录已同步删除且**没有未回收子进程**之后，可等仓库锁；拿到锁后先检查本仓库隔离状态，持久化仓库级 RUNNING 后才能启动任何后续内部核验或业务 Git。运行期间保持 RUNNING。
6. 短期服务端级门协调“检查 GLOBAL_QUARANTINED + 持久化意图 + 启动进程”和“宣告全局隔离”；不要在 Git 命令执行期间或等待仓库锁时持有全局门，不与 WorkspaceService 生命周期互斥锁形成反向锁序。
7. **清理无法确认**时（包括超时且无法确认清理），在**同仓库锁内**转换 QUARANTINED 并尝试持久提交，再释放锁；其他 Workspace/linked worktree 即使排队也不得启动业务 Git。超时但进程及资源完全回收时按第 8 条清理，不能误隔离。隔离写入失败也不得删除原持久 RUNNING，当前实例全局 fail-closed，按设计 §7.2 的可信持久化故障模型处理。
8. 成功或 Git 业务失败但进程完全清理后，移除对应 RUNNING、持久 fsync、回到 READY；非零 Git exit_code 本身不是隔离条件。
9. 进程启动时先扫描残留 DISCOVERING/GLOBAL_QUARANTINED/RUNNING/QUARANTINED 状态，保证**启动扫描完成之前不能启动任何 Git 进程**。无法读取、无法归属或状态损坏时 Git 全局失败关闭。
10. V1 不提供 Web/MCP/REST reset 或自动解封任务；离线恢复只能在 Gateway 停用后由管理员核实进程及 PID 重用风险、按明确本机流程清除记录再重启。记录的 TTL 不构成恢复资格。
11. **2026-10-21 已批准的存储故障边界：** 不能删除仍可能有未回收受控 Git 进程的持久记录；确认完全回收后，若 unlink 已生效、目录 fsync 失败且全局标记也无法写入，本实例必须失败关闭，但重启后无残留记录不要求凭空维持永久隔离。重启后的下一次 Git 必须先重新持久提交活动意图，写入失败零启动；有残留记录仍须隔离。详见设计 §7.2。

新增 tests/test_git_state.py 和 tests/test_git_recovery.py。

必须故障注入：
- 落盘 write/fsync/rename/dir-fsync 任意失败 → 首次 git 子进程启动数 0。
- 首次 discovery 已启动，Gateway 被强杀、异常处理尚未运行 → 重启全局拒绝；离线管理员恢复后才放行。
- 两个 discovery 并行的调用 ID/记录互不覆盖；完整清理后互不阻塞。
- DISCOVERING 删除后、RUNNING 写入前模拟强杀 → 无未回收进程；RUNNING 写入后、锁内 Git 启动前强杀 → 重启该仓库隔离。
- 清理不确定先隔离后解锁，其他 Workspace 和 linked worktree 零业务 Git 启动；独立仓库仍可执行（GLOBAL_QUARANTINED 除外）。
- 状态读取损坏、活动标记清理失败及目录不可用 → 本实例 fail-closed。
- 已启动/可能启动且清理未知，即使隔离覆盖和全局标记补写失败，原已同步的 DISCOVERING/RUNNING 仍保留，重启继续隔离。
- 已确认所有 Git 进程和资源回收：分别注入 unlink 前失败、unlink 后目录 fsync 失败、全局隔离标记无法写入，核对本实例拒绝、重启按真实残留记录处理；若无记录，新的 Popen 前必须先持久提交新意图，故障注入使其失败则启动数为零。测试文件 tests/test_git_storage_failure_boundary.py。

完成门禁：以上隔离、强杀与重启行为须先有本地可重复自动化证据；禁止先对 Web/MCP 开放 apply。

#### T06 — 新增 gateway/git_cli.py：受控执行器与时间预算

修改：
1. Git Binary 只能由服务端可信安装位置决定，不能由调用方控制。使用 subprocess.Popen([git_binary,*compiled_argv], shell=False, stdin=DEVNULL, stdout/stderr=PIPE, start_new_session=True)。
2. Git 子进程环境从允许列表构造，不透传父进程全部 os.environ；保留服务端批准的 HOME/USER/LOGNAME/PATH/TMPDIR/LANG/LC_*/SSH_AUTH_SOCK，固定 GIT_TERMINAL_PROMPT=0；拒绝 GIT_DIR、GIT_WORK_TREE、GIT_COMMON_DIR、GIT_INDEX_FILE、GIT_OBJECT_DIRECTORY、GIT_CONFIG_*、GIT_SSH_COMMAND 和其它未经列入 allowlist 的 GIT_* 污染。
3. 仓库发现、ref/remote 校验与业务命令统一 Git Binary、工作目录、环境；允许磁盘上的原生配置、Hook、Filter 和 Helper 运行。
4. timeout_seconds 为从实际同步 Worker 准入开始的**单一端到端预算**，默认 120、范围 10..900；发现最多 5 秒、仓库锁等待最多 10 秒，都受总 deadline 和 5 秒清理预留限制；不能为下一阶段重新授予一整段 timeout。
5. 并发持续读取 stdout/stderr、限制捕获总字节/响应总字符；超限报告截断/错误，禁止声称输出完整。机器消费结果与人可读结果需区别，原生 Git 输出不得套 File API redaction；日志禁止原始输出/秘钥/远端含密码 URL。
6. 到期先 TERM Git 进程组，最多 2 秒再 KILL，必须有限期 wait/reap 和 drain；清理结果不确定立即转到 T05 的隔离逻辑，不能在仍可能运行时把 Repo 标记 READY。
7. 断连不取消已准入同步 Worker；不自动重试非幂等 Git。明确 execute_started、exit_code、timed_out、output_truncated、cleanup_status、repository_checked 等返回字段。
8. 准入与执行串接时先 T05 服务端级 DISCOVERING，再发现，获取仓库锁后 T05 RUNNING，再做锁内检查与业务 Git；不提供任何能绕过 T05 的裸 subprocess helper。

新增 tests/test_git_cli.py 和 tests/test_git_lifecycle.py。

完成门禁：真实临时 Git 仓库能够运行核心 10 种受支持 Schema（分阶段逐个启用），清理/环境/输出上限测试通过；不打开外部适配器入口。

### P2 — 服务层与 Legacy/Multi 接入

#### T07 — 修改 gateway/workspaces.py

修改：
1. WorkspaceService 共享一份 GitRepositoryCoordinator/GitCLIExecutor，**不能为每个 Workspace 各建独立仓库锁**。
2. 增加 require_git 与独立 invoke_git；检查 server.git.enabled、目标 Workspace.allowed_commands、已实现 Schema，不调用 File-only require('run_git') / service.invoke('run_git')。
3. 从实际同步 Worker 执行线程取得 WorkspaceService 活动租约；shutdown 设置 closing 后拒绝新请求、等待已准入真实 Worker 释放租约，不能提前关闭 Workspace root FD。
4. 生命周期锁不能包住慢 I/O、记录 fsync、仓库锁等待或 Git 子进程；同仓库状态锁与短期全局准入门遵守 T05 锁序。
5. info/list_workspaces 暴露 sanitized Git enabled、可用命令、必要的“Git 可修改父级仓库”警示；不暴露完整磁盘路径。现有 read_only 的 File API 定义不变。

修改 tests/test_phase1_workspaces.py；新增 tests/test_git_workspaces.py。

完成门禁：Workspace B 有权 pull 影响 Workspace A 的同仓库文件为**允许**；A 直接调用未授权 pull 被拒绝；服务端 disabled 时所有 Workspace 拒绝；运行中 close 等待同步 Worker。

#### T08 — 修改 gateway/core.py

修改：
1. Legacy 增加 Git 显式 enable 与 allowed_commands 注入，默认全部 disabled；GitService 使用独立于 CommandRunner 的运行器和状态目录。
2. 为 Legacy Git 实际同步 Worker 建立独立活动租约与 close/drain 协调；当前 Gateway.close() 直接关闭 FD，不能用于未排空的 Git 任务。
3. 保持原文件 API、Writer、受控 Exec 的行为与签名，避免对 _checked/_allowed 增加 Git 例外。
4. gateway.info 附加 Git capability、允许命令和高权限警示，但不输出绝对 workspace/private state 位置；生命周期 close 保持幂等。

新增 tests/test_git_legacy.py；修改 tests/test_core.py 的覆盖范围（必要时）。

完成门禁：Legacy 不启用 Git 时工具不可见且已有读取/受控 Exec 不变；启用后独立权限生效；close 不在 Git Worker 使用期间关闭 root FD。

#### T09 — 修改 gateway/__main__.py 与 gateway/multi_cli.py

gateway/__main__.py：
- 添加 --allow-git 和可重复 --git-command NAME，显式 opt-in，未启用时传命令名单报 CLI 错；与 --config 模式严格互斥。
- 将 Git 配置传入 Legacy Gateway，非自动继承 --allow-exec 或 --allow-write；CLI --check 输出 sanitized Git Policy、初始化状态可用性，不能执行 Git discovery。
- 保持 --transport stdio Legacy、--http-only、--local-skill-* 等旧参数逻辑，新增字段不能导致其他模式静默切换。

gateway/multi_cli.py：
- 从多 Workspace 私有配置构建 Git 服务及隔离状态启动扫描；检查失败按服务端 Git fail-closed（根据设计区分 Git enabled 与 File API 是否仍可提供服务）。
- 日志更新为“通用 Exec 与 Local Skills 禁用；Git CLI 仅在显式授权时启用”，不能再无条件写“全部 Execution disabled”。
- 保持 --config --transport stdio 拒绝；同一进程 + HTTP MCP 现有架构不变。

修改 tests/test_cli.py、tests/test_exec_cli.py、tests/test_phase1_review_cli.py；新增 tests/test_git_cli_args.py。

完成门禁：CLI 配置与实际工具发现匹配；未启用 Git 时启动输出和原有能力无回归。

### P3 — REST/MCP 适配（在引擎门禁完成后才暴露）

#### T10 — 修改 gateway/mcp_multi.py 与 gateway/mcp_adapter.py

- 两侧在**有效 Git 权限非空**时注册一个 run_git 工具；Multi signature 必有 workspace，Legacy 无 workspace。两者使用完全相同的 GitService.run/调用顺序，不复制授权逻辑。
- 在 StrictWorkspaceMCP / StrictLegacyMCP.call_tool 的 SDK 2.3.0 前置 validate_tool_arguments 中检查顶层参数，然后在同步服务边界再次校验嵌套 Schema/Workspace 授权。
- run_in_threadpool 放真实同步执行，Context 继续传递给父 MCPServer；Git ToolAnnotations 固定 readOnlyHint=false、destructiveHint=true、idempotentHint=false、openWorldHint=true。
- 工具说明清晰指出父级 Repository、Git 原生 Hook/Filter/Remote 副作用，Preview 缺省无 Git 启动，远端执行失败不能自动重试。
- SDK 继续 subscriptions=False；不恢复 FastMCP，Multi 不新增 stdio 启动模式。

新增 tests/test_git_mcp.py；扩充 tests/test_mcp_sdk_v2.py、tests/test_phase1_multi_mcp.py、tests/test_mcp.py、tests/test_mcp_exec.py。

完成门禁：两种 MCP 协议 × Legacy HTTP/stdio 与 Multi HTTP 的实际工具注册、误参拒绝、Context/结构化返回一致；Multi stdio 继续被 CLI 拒绝。

#### T11 — 修改 gateway/http.py 与 gateway/http_multi.py

- Legacy 增加单独 POST /git/run，必须在现有 /run 与 write.enabled 判断之外授权；该能力由 Git enable 控制。
- Multi 增加 POST /git/run，明确 workspace 必填，复用 StrictPostAdmission、Boundary、Host/Origin/Token、不重复解析规则。
- 两模式对 route/query/body/missing/duplicate/invalid nested options/unsupported command 一律在业务线程中再校验权限，不能靠前端 HTTP 校验代替实际 Worker 授权。
- 使用受控请求体预算；不要为了 Git 消息体扩大整个服务的读取上限。报错映射：git_disabled/command_not_allowed=403，git_repository_quarantined/git_busy=409 或可解释的 503，cleanup_incomplete=503，其它参数 400/路径 403；将最终状态码表冻结在测试中。
- JSON 响应的 dry_run/execute_started/cleanup_status 与 MCP 相同；敏感远端与私有记录路径不出现在错误 details 中。
- 现有 read/write/create/delete 路由、MCP 传输安全边界不改变。

新增 tests/test_git_http.py；扩充 tests/test_phase1_multi_http.py、tests/test_command_http.py、tests/test_http.py、tests/test_phase1_admission.py。

完成门禁：REST 与 MCP 在同一配置和调用下行为一致；全局关闭、Workspace 未授权、Git 隔离和非法参数在 Git Popen 之前阻断。

### P4 — 故障注入、真实 Git、发布文档与 CI

#### T12 — 新增 tests/test_git_integration.py

使用 TemporaryDirectory、临时 parent Git Repo、两个 sibling Workspace、linked worktree 与本地 bare Remote；测试仅在临时目录执行，不触及真实用户仓库、SSH Token 或业务远程：

- Workspace 的 cwd 是父仓库子目录；pull --ff-only 更新 Workspace 外兄弟目录（**允许**）。
- .gitignore / nested ignore / info exclude 均按 Git 原生应用；匹配 ignore 的已跟踪文件仍可能由 pull 更新。
- git add -A 无 paths 作用于整个 parent Repo；带 literal paths 时不能用 :(top) / symlink / ../ 指定 Workspace 外的本地路径。
- 同仓库两个 Workspace 不同命令权限，但写锁共用；真实 linked worktree common-dir 共锁；独立仓库可并发。
- 本地 Git Hook/Filter 允许执行并可能修改 Workspace 外文件；这是**设计允许的行为**，不能做成隐式阻断项。
- switch --no-guess 在只有远程同名分支时失败；checkout/clone 始终拒绝；push +main 是准确分支引用，不能意外强推；错误 force-with-lease 不改远端。
- Git 失败但清理完全、超时但确认清理完成，与 cleanup 未确认的后续准入差异；Git 环境污染不影响仓库与 Index。
- Preview 对任何命令（包括没有 Git 仓库）均不启动 git。

完成门禁：行为符合设计已接受范围；每项验证前后使用临时 Repo 内容/Index/SHA 可断言，不把命令成功当作完整隔离证明。

#### T13 — 新增 tests/test_git_fault_injection.py 与 tests/smoke_git_cli.py

Fault injection：
1. 私有记录首次落盘写入、fsync、rename、目录 fsync 失败 → git 子进程零启动，响应失败且无隐式放行。
2. 首次 DISCOVERING 记录已落盘并启动 rev-parse 后，强制 SIGKILL Gateway 测试进程（独立子进程，不杀测试控制者）；重启扫描后全局拒绝新业务 Git，管理员离线清理状态后可恢复。
3. DISCOVERING 清理与 RUNNING 创建的移交空档强杀；确认此前没有残留进程。RUNNING 已落盘后强杀，重启隔离该仓库。
4. 清理未确认时先隔离后释放仓库锁，另一个 Workspace/linked worktree 等待者一律禁止进入；独立 Repo 未被全局隔离时可继续。
5. 断连后的真实同步 Worker 仍受截止期限约束；Gateway.close 不释放其仍使用的 FD；持续 stdout/stderr drain、大输出上限、TERM/KILL、reap、不重试。
6. 离线恢复要以测试管理员身份、真实进程已清理为条件；不在 HTTP/MCP 暴露 reset。

Smoke：
- 独立临时 HTTP 监听，Git 显式启用；Legacy 与 Multi 各走有效工具和安全拒绝路径。
- 不使用真实 GitHub、真实 Tunnel 凭据、真实 SSH 远端或内部项目路径。
- macOS 上单独运行故障注入和 Git 行为测试，记录 OS/Git/Python/SDK 版本。

完成门禁：强杀重启/离线恢复、死锁、超时/资源释放均可重复，不能只由 mock 结果替代真实进程证据。

#### T14 — 修改 tests/smoke_mcp_live.py、tests/smoke_mcp_stdio.py、tests/smoke_mcp_disconnect.py

- smoke_mcp_live：增加启用 Git 后 Legacy/Multi 的双协议 discovery、tools/call、严格入参和 Preview/Apply；继续保留未启用时工具不可见的负例。
- smoke_mcp_stdio：Legacy stdio 两协议验证 Git；Multi stdio 仍不支持且应保持 CLI 拒绝，不新增 Multi stdio server。
- smoke_mcp_disconnect：独立临时子进程 Git 命令验证已开始后断连仍有界、结果未知不重试；验证超时中不能提前释放根 FD。
- 不把现有 REST-only smoke_live 的 mcp_verified=false 当作 Git MCP 已验收。

完成门禁：真实 MCP client/session 而非仅 tool registry spy；versions 2025-11-25 与 2026-07-28 一致。

#### T15 — 修改 README.md、README.zh-CN.md、samples/gateway.example.json、BUILD_INFO.json

- 仅在实际 Git 功能已实装且可验收之后，增加配置/CLI/API 说明，写清服务端总开关、Workspace 级 allowed_commands、Legacy flags、dry_run 与已支持命令列表。
- 说明 Repo 根可在 Workspace 外，Git 原生 Hook/Filter/Remote 权限、Git 输出可包含普通 File API 看不到的内容、Git 没有 File API 备份，也不能把 read_only=true 当作 Git 写入禁止。
- 文档应说明隔离时 git_repository_quarantined 和管理员离线恢复；**不提供远程解除隔离功能**，不建议盲目重启解决不确定状态。
- 样例只用中性占位目录和 Remote，绝不包含业务内部项目名、主机名、秘密或本机用户名。
- BUILD_INFO / 版本字段按仓库原发布约定更新，而不是凭空宣称已经发版。

完成门禁：英文/中文 README、示例与真实参数 schema 完全一致，全部文档只公开已经实现的能力。

#### T16 — 修改 verify.sh、.github/workflows/controlled-exec-tests.yml、MANIFEST.sha256

- verify.sh --require-mcp 增加 Git 临时 Repo smoke，保留现有 compileall、完整 pytest、REST/MCP/stdio/断连 smoke。
- GitHub Actions 运行可自动重复的临时仓库 Git 和故障注入测试，保证无外网、无需云端凭据；平台差异测试在 macOS 专项报告注明，不能把 Linux CI 冒充 Mac 验收。
- Release manifest 列出所有新增/修改且被 Git 跟踪的文件，并验证排序与哈希；使用 bash verify.sh --require-mcp 和 Actions 的独立 manifest 检查。
- 本文档对应的 plan-only PR 也需更新 Manifest，但该校验只证明规划文件一致，不证明任何实现测试已运行。

完成门禁：完整测试与 Manifest 双重绿灯、macOS 原生测试、真实 Tunnel 环境连接验证、独立安全/架构与 Spec-to-code 审查全部完成后才讨论代码 PR 合并。

## 3. 建议提交/评审批次及依赖门禁

| 批次 | 主要文件 | 必须通过才进入下一批的证据 |
|---|---|---|
| A — 纯规则 | git_policy.py、workspaces_config.py、multi_fields.py、对应测试 | 完全无 Git 执行路径，配置/参数 fail-closed，旧配置兼容 |
| B — 先保安全引擎 | git_repository.py、git_cli.py、相关状态/路径/超时测试 | DISCOVERING 前置持久化、仓库锁、QUARANTINED/重启/离线恢复及超时回收全部可重复 |
| C — 服务集成 | workspaces.py、core.py、__main__.py、multi_cli.py、相关测试 | 两模式同一权限与共享协调器，关闭等 Worker，Multi file-only 权限无回归 |
| D — 网络适配 | mcp_multi.py、mcp_adapter.py、http_multi.py、http.py、对应测试 | SDK v2 两协议、严格入参、REST/MCP 行为一致；无任意执行器绕过 |
| E — 真实端到端 | test_git_integration.py、test_git_fault_injection.py、smoke_git_cli.py、现有 MCP smoke | 临时 Git parent Repo + linked worktree + bare remote、强杀重启、故障隔离/恢复 |
| F — 文档发布 | README、样例、BUILD_INFO、verify.sh、Actions、MANIFEST | 本机回归、Actions、真实 macOS 和 Tunnel 验收、独立审查 |

**禁止拆开交付的原子组：**

- 首次 discovery Popen 必须与 DISCOVERING 前置落盘一起交付，不能先启动 Git 再补持久记录。
- 业务 Git Popen 必须与仓库 RUNNING 标记、同仓库锁、QUARANTINED 隔离一起交付。
- Workspace Git 授权校验必须进入真实 Worker（在 MCP/REST 校验之外），不能只依赖 tool discovery。
- Git 执行器的 deadline / drain / reap 与关闭租约必须一起交付，不能先提供无上限 Popen 再补测试。
- Git CLI 不可通过普通 run_command、Local Skills 或文件操作 API 权限间接启用。

## 4. 逐文件完成定义与计划复审问题

每个文件合并时需提供：
1. 最小 diff，说明其权限/生命周期边界的输入、输出及依赖。
2. 对应单元测试名称、执行命令、pass/fail 结果；复杂步骤包含可重复临时目录 fixture。
3. 执行前/后的 Git 是否可能启动；可能启动时明确受哪个 DISCOVERING 或 RUNNING 持久记录保护。
4. 异常、超时、HTTP 断连、Gateway 关闭和强杀后恢复的状态及 Worker FD 生命周期。
5. 未实现的命令/参数保持拒绝，且无需宽松 fallback。
6. 对用户已接受的 Git 原生跨 Workspace 影响保留准确描述。

独立逐文件实施计划复审应输出 Standards PASS/FAIL、Spec PASS/FAIL，逐个列出 P0/P1/P2 及最小修复，并重点回答：

- T04/T05/T06 的真实进程启动点是否都被持久活动意图覆盖，服务端级 Gate 与仓库锁的获取顺序是否可能死锁？
- 同一 WorkspaceService 共享仓库锁但 Legacy 有独立生命周期时，是否仍满足当前 close/drain 与 FD 持有契约？
- Git 命令的纯 Schema、cwd/paths identity 校验、锁内 Git 运行时校验与实际 argv 是否有可绕过的双解释或 TOCTOU？
- T10/T11 的 REST/MCP 严格参数门禁是否可以被错误的 top-level/nested options 值绕过？
- V1 的回归矩阵是否覆盖强杀首次 discovery、重启残留记录、正常并发发现、移交空档、离线恢复这五项关键验收？
- 是否错把 Multi stdio 当作现有支持模式，或错把 Linux CI / 设计 Spec PASS 视为 macOS 产品验收？

**本计划保留历史设计和审查问题；实际 A–F 分批代码证据参见相应 PR。2.5.0 独立发布集成 PR 尚须新 Head 的 CI、版本/Manifest 定向独立复审及运营者明确授权，才能合并、打 Tag 或部署；不得因计划状态而自动开放 Git。**
