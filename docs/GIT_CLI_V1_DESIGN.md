# Mac File Gateway — Git CLI V1 设计与独立评审规格

状态：**DRAFT / 待独立 Standards 与 Spec 评审**  
日期：2026-10-20  
代码基线：release/ms1 @ ba8634f24cdc26904d1c80951df7173e429240c7  
MCP Python SDK：2.3.0  
范围：**仅设计，不代表已经实现、测试、发布或启用 Git 能力**

## 1. 用户已确认的设计决策

1. 服务端总开关 server.git.enabled 控制 Git CLI 是否启用，默认 false。
2. 每个 Workspace 通过 git.allowed_commands 独立指定允许的 Git 子命令；没有明确授权则不能执行。
3. Git 接口采用结构化参数：run_git(workspace, cwd, command, options, paths, timeout_seconds, dry_run)。客户端不得直接提交任意 argv。
4. cwd 和客户端显式传入的本地文件/目录路径必须在其指定 Workspace 内；所有路径都由 Gateway 校验和拼装。
5. Git 从 cwd 原生向上发现仓库。仓库根目录可以在 Workspace 的父目录，不额外要求仓库根目录位于 Workspace 内。
6. Git 执行已授权命令时可修改整个实际仓库，包括 Workspace 外的文件；不受 Gateway 普通文件 API 读写路径、隐藏文件、文件类型、备份或敏感内容规则限制。
7. .gitignore、子目录 .gitignore、.git/info/exclude 和用户全局 ignore 由 Git 自身处理；Gateway 不重新实现。忽略规则不保证已跟踪文件免于 pull 等操作的更新。
8. 多 Workspace 需要独立命令授权；如多个 Workspace 共享同一仓库，需要按实际 Git 仓库身份协调并发操作。
9. Git 原生 Hook、Filter、Credential Helper、配置及远程操作可能访问 Workspace 外部或执行其他程序。这属于用户接受的高权限 Git 模型，并非 OS 沙箱。
10. 现有普通 File API、受控 run_command、Local Skill Bridge、Multi-Workspace Phase 1 路径边界及 MCP SDK 2.3.0 传输契约均保持原样。

### 1.1 核心场景

~~~text
parent-repo/                       # 实际 Git 仓库根目录
├── .git/
├── project-a/
├── workspace/                     # Gateway 已授权 Workspace 根目录
│   └── project-b/
└── project-c/
~~~

客户端请求 workspace=workspace、cwd=project-b、command=pull、options={ff_only:true}。
Gateway 验证 cwd 在 Workspace 内后，以 workspace/project-b 为进程工作目录启动 Git；Git 自动向上找到 parent-repo/.git。
pull 可能更新 parent-repo 中的 project-a、project-c 和上层文件。这是**允许行为**，不得阻止或强制回滚。

客户端显式传入 cwd=../project-c 或 paths=[../project-c/secret.txt] 时必须在执行前拒绝。

## 2. 权限边界：限制调用入口，不限制 Git 效果

### 2.1 Gateway 必须保证

- 每次 Multi-Workspace 调用显式提供合法 Workspace ID，无自动选择或回退。
- 由服务端总开关、目标 Workspace 命令列表和已实现的命令 Schema 三重条件决定能否执行。
- 对每一个**定义为本地路径**的结构化参数，验证其不能指向 Workspace 外部。
- 不接受客户端的任意 Git 全局参数、额外 flags、argv 或自定义命令片段。
- 不因使用 Git 而对普通文件 API 放宽 .git、隐藏文件或 Workspace 访问限制。
- Git 执行受服务器端运行时限、并发额度、输出预算与进程生命周期管理。

### 2.2 不保证、且明确接受

- Git 进程本身可以通过父级仓库发现、Git 配置、Hook、Filter、外部 Helper、Remote 等机制读写 Workspace 外的文件或访问网络。
- 一个 Workspace 的 Git 写操作可以更改另一个 Workspace 的文件，甚至后者禁止该子命令。
- 无 paths 的 Git 命令可以按 Git 语义作用于整个父级仓库，例如 git add -A（无 pathspec）可暂存整个工作树的变化。
- Gateway 不对 Git 最终修改的文件逐个审批或创建普通 File API 备份。
- Gateway 普通 File API 的 read_only=true 只描述 File API；Git 启用后不能解释为整个本地磁盘只读。
- Git 输出可能显示 Workspace 外部或 File API 不允许直接读取的仓库文件信息。Git 输出不再套用 File API 文件范围过滤。
- 仅对结构化 API 的显式本地路径提供范围保证；第三方 Hook/Filter 对任意字符串的特殊解释不属于这个保证。
- 同一 OS 用户运行的其他 Git、IDE 或进程不参与 Gateway 的仓库执行锁；不是跨进程 OS 隔离。
- Git 命令白名单不能消除 Hook/Filter 等本机程序执行能力，不能宣称为安全沙箱。

## 3. 服务端及 Workspace 配置

Multi-Workspace 私有 gateway.json 按现有严格 schema_version=1 增量扩展：

~~~json
{
  "schema_version": 1,
  "server": {
    "port": 8765,
    "transport": "http",
    "git": {"enabled": true}
  },
  "workspaces": {
    "workspace-a": {
      "root": "/absolute/example/parent-repo/project-a",
      "read": {"enabled": true},
      "write": {"enabled": false},
      "exec": {"enabled": false},
      "local_skills": {"enabled": false},
      "git": {"allowed_commands": ["status", "diff", "log"]}
    },
    "workspace-b": {
      "root": "/absolute/example/parent-repo/project-b",
      "read": {"enabled": true},
      "write": {"enabled": false},
      "exec": {"enabled": false},
      "local_skills": {"enabled": false},
      "git": {
        "allowed_commands": [
          "status", "diff", "log", "add", "commit", "pull", "push"
        ]
      }
    }
  }
}
~~~

约束：

- server.git.enabled：严格布尔，缺省 false。
- workspaces.*.git.allowed_commands：标准 Git 子命令名的无重复数组，缺省空数组；不接受未实现 Schema 的命令名。
- 有效授权 = server.git.enabled 且 command 属于本 Workspace allowed_commands 且 Schema 已实现。
- 不以 read/write/exec 的启用情况间接推导 Git 权限；Multi-Workspace 仍不开放通用执行器及 Local Skills。
- 未配置 Git 的旧文件继续合法，实际 Git 权限为空。
- 私有配置、运行根目录、不同 Workspace 配置根目录的既有安全校验继续生效，但**不要**把这些校验错误延伸到 Git 自动发现的父级仓库。
- 不允许 Web/MCP 修改这个授权配置，也不允许客户端提交独立的 Repository Root。

Legacy 模式通过 --allow-git 及可重复 --git-command NAME 单独 opt-in，等价于一个隐式 Workspace；仍使用同一执行器与参数规则，但工具签名省略 workspace 字段。--config 与 Legacy 权限参数继续互斥。

gateway_info 和 list_workspaces 可以公开 Git 是否启用、允许的命令，但不公开 Workspace 根目录绝对路径。原 read_only 字段语义不变，同时明确新增的高权限 Git 可能修改文件。

## 4. MCP / REST 统一接口

建议唯一业务工具为 run_git；Multi-Workspace 请求示例：

~~~json
{
  "workspace": "workspace-b",
  "cwd": ".",
  "command": "pull",
  "options": {
    "remote": "origin",
    "branch": "main",
    "ff_only": true
  },
  "paths": [],
  "timeout_seconds": 120,
  "dry_run": true
}
~~~

- workspace：Multi 必填；Legacy 不出现。
- cwd：相对所选 Workspace 根目录的现有目录，默认 "."；不接受客户端原始 -C。
- command：固定已实现的 Git 内建子命令枚举，并校验 Workspace 权限。
- options：只允许该子命令已声明的字段与类型；无 raw_argv、extra_args、flags 等通道。
- paths：用于有本地路径操作数的子命令；相对已校验 cwd，且每项必须在 Workspace 内。默认 []。
- timeout_seconds：严格整数，建议默认 120，上限 900 秒（需 macOS 生命周期验收后冻结）。
- dry_run：严格布尔，默认 true，仅预览规范化后的命令和相对 cwd，不启动 Git；false 真正执行。
- 未知字段、重复或无效 JSON、错误类型、NUL、控制字符、不支持的参数及尺寸超限必须拒绝。
- MCP 注解：readOnlyHint=false、destructiveHint=true、idempotentHint=false、openWorldHint=true。
- REST 建议 POST /git/run；Legacy/Multi 的 REST 与 MCP 最终进入同一 GitService 和参数编译器。
- 返回 workspace、command、是否 preview、退出码、受限 stdout/stderr、超时和截断状态；仅返回脱敏的仓库身份信息。
- 无响应不代表未执行；不得对 commit/pull/push 自动重试。

## 5. 每个子命令的结构化 Schema

**命令名允许并不意味着可以传全部 Git 参数。** 只有已实现并测试的参数形式才能执行。初版候选：

| 子命令 | 允许的结构化参数 | 显式本地路径 | 说明 |
|---|---|---|---|
| status | short:bool, branch:bool | 可选 paths | 不传 paths 时可查询父级完整仓库 |
| diff | cached:bool, stat:bool | 可选 paths | 不接受任意 revision、--no-index 或输出文件 |
| log | limit:int(1..50), oneline:bool | 无 | 暂不接受任意 rev:path、format |
| branch | action:list/create/delete, name, 受控 start_point | 无 | 分支名、引用名需要专用验证 |
| switch | name, create:bool | 无 | 可切换整个父级仓库的工作树 |
| checkout | branch | 无 | 初版仅分支切换，不开放 checkout 文件模式 |
| add | all:bool, update:bool | 可选 paths | 无路径的 -A/-u 可以覆盖父级完整仓库 |
| commit | message:str, amend:bool | 无 | Hook 可运行；默认由 Git 决定提交范围 |
| fetch | remote:已配置名称, prune:bool | 无 | Remote 配置的间接路径和网络访问允许 |
| pull | remote:已配置名称, branch:受控 ref, ff_only:bool | 无 | 允许父级仓库整体更新 |
| push | remote:已配置名称, branch:受控 ref, force_with_lease:bool | 无 | 可能影响远程仓库 |
| clone | url:远程 URI, destination:本地目标目录 | destination 必须在 Workspace 内 | 初版不支持本地路径源及 --separate-git-dir |

实施前必须冻结同一命令的互斥选项、必选字段、默认值、Ref 校验、Remote 名称存在性和 argv 生成顺序。若单个 Schema 暂时不能安全明确实现，就从实际 V1 可配置命令中移除，不能退回任意 argv。

restore、reset、clean、rm、config、remote、rebase、merge、worktree、submodule、apply、archive、show 等其他命令需独立 Schema 和测试后才能作为后续功能开放。不存在 "高级模式" 绕过结构化参数检查。

### 5.1 Remote 与 Revision

- fetch/pull/push 的 remote 只能是 Git 已配置且名称经过验证的 Remote；不允许本轮客户端直接指定本地路径或任意 URL。
- 已配置 Remote 可能本身指向 Workspace 外本地仓库，这是 Git 配置的**间接行为**，按用户需求允许。
- clone.url 是远程 URL，而非本地路径；初版候选仅严格支持 https:// 和 ssh://，不支持 local path 或 scp 风格简写（后续评审可扩展）。
- Revision/Ref 单独定义类型，不能接受任意 Git Revision 表达式；明确拒绝 REV:PATH、以 - 开头的值、Pathspec Magic 和选项注入。
- Git Hook 可能重新解释 Commit Message、Branch Name 等数据：Gateway 无法限制自定义 Hook 对这些文本的处理，作为高权限 Git 风险记录。

## 6. 显式路径参数的范围保证

**本节限制的是 API 的显式本地路径，而不是 Git 进程最终可访问的文件。**

1. cwd 相对 Workspace Root 解析。拒绝绝对路径、..、~、不规范分隔、NUL、控制字符。
2. 使用既有已验证的固定根目录 / no-follow 校验思路检查实际目录祖先，禁止通过符号链接把 cwd 转到 Workspace 外。
3. paths 相对 cwd，不能使用任何能定位 Workspace 外的词法形式；对已存在项及其祖先检查实际目录身份；对尚不存在的目标，检查所有已存在父级。
4. 路径参数只在该子命令专用的路径字段提供。由服务端生成 -- 分隔及 literal Pathspec 语义，不能接受客户端传 :(top)、:(glob)、include/exclude magic 或 --pathspec-from-file。
5. 客户端不支持原始 Git 全局选项 -C、-c、--config-env、--git-dir、--work-tree、--exec-path、--bare；Gateway 内部生成的固定参数另行审查。
6. 不接受未建模的文件/可执行路径选项，如 --output、-F、--template、--reference、--separate-git-dir、--upload-pack、--receive-pack。
7. 没有显式路径的命令照 Git 原生语义运行。git add -A 不带 paths 时仍允许作用到父级整个仓库。
8. 这是**受信任本地 OS 用户模型下**的服务端 API 参数范围控制，不宣称对恶意本地进程并发篡改文件或 Hook 间接解释提供 OS 沙箱级保证。

## 7. Git 仓库识别与多 Workspace 协调

- Gateway 按请求选择 workspace 和 cwd，Git 自行向上查找最近的仓库；不要拒绝位于 Workspace 父级的 Repository。
- 使用固定内部 git rev-parse 调用获取 worktree root、gitdir、common Git dir 等用于协调的信息，不对客户端提供任意 rev-parse argv。
- 对发现的同一 common Git dir 采用稳定身份键（例如规范化目录的 dev/inode），使不同 Workspace 发起到同一个父级仓库的 Git 调用落在同一协调锁。
- V1 可以保守串行化同仓库全部 Git 请求；至少所有可能修改仓库状态的操作必须串行化。等待锁不得一直持有 WorkspaceService 的全局条件互斥锁。
- 单独的 git clone 尚无目标 Repository：使用已校验的 Workspace 内 destination 协调，并在创建完成后再识别新仓库。
- Worktree 模式若共用 common Git dir，可以保守串行化，避免把两个共享 Common Dir 的工作树误当成无关仓库。
- 只协调 Gateway 自身发起的 Git 调用。普通 shell/IDE 自行执行的 Git 不参与此锁，不能宣称全仓库原子一致性。
- 可以返回安全的 repo identity / repo_is_ancestor 标记，但不要在 capability 列表中公开绝对路径。

## 8. Runner、SDK 2.3 与运行生命周期

- 专用 GitCLIExecutor 负责构造固定 Git executable + 结构化参数形成的 argv，以 shell=False 运行；不经过旧受控 executor 的 pytest/python/go allowlist，不自动使用 Pipenv。
- Git executable 由服务端确定，不能由客户端选择；保留 Git 正常运行必要的 HOME、SSH Agent、Credential Helper 上下文。
- 不把 Gateway Token、Tunnel 密钥和 Gateway 私有控制凭据作为 Git 子进程环境变量继承；日志不打印环境、原始带凭据的 URL、Commit Message 和无限制 stdout/stderr。
- 不提供交互式 TTY；V1 不接受任意 stdin 文本。非交互式操作需要明确失败语义。
- 超时、输出预算、进程组结束和 reap 必须经过实际 macOS 测试；不能保证任意故意脱离进程组的 Hook 子孙进程都可被终止。
- Multi-Workspace 的执行须获取 WorkspaceService._operation 同步 Worker 生命期租约；不能在操作结束前释放所依赖 FD。
- 对 Legacy 需确保 Gateway.close 不会提前释放运行中的 Git 所需资源，不改变原 run_command/Local Skill 的既有契约。
- 沿用 MCP SDK 2.3.0 的 MCPServer、Context 转发、gateway/mcp_transport.py、双协议 2025-11-25 / 2026-07-28、subscriptions=False 和现有 Host/Origin/Token 校验。
- HTTP 断连**不能被当作取消已开始的 Git 操作**；执行由服务端明确超时终止，响应丢失意味着调用者结果未知，不自动重试写操作。
- Legacy MCP 原始 JSON 重复 Key 的遗留差异须评审与测试，但不得把现有历史限制误称为新增 Git 漏洞。

## 9. 修改范围（实现阶段，不属于本设计 PR）

建议新增：
- gateway/git_cli.py — Git 请求编译与运行器（足够小时不必继续拆分）。
- gateway/git_policy.py — 每个命令的 Schema、授权验证。
- gateway/git_repository.py — 父级仓库发现、共享仓库协调标识。

建议修改：
- gateway/workspaces_config.py、gateway/workspaces.py：私有权限配置、Workspace 路由、实际 Worker 租约。
- gateway/multi_fields.py：run_git 严格签名和嵌套 options 验证。
- gateway/mcp_multi.py、gateway/mcp_adapter.py：SDK v2 MCPServer 工具注册。
- gateway/http_multi.py、gateway/http.py：REST 接口。
- gateway/core.py、gateway/__main__.py：Legacy 启用、信息和关闭过程。
- gateway/multi_cli.py：启用 Git 后正确表述执行能力。
- README.md、README.zh-CN.md、samples/gateway.example.json、BUILD_INFO.json、MANIFEST.sha256：**仅在代码实际实现时**同步更新。

原则上不改 gateway/executor.py、gateway/local_skills/*、gateway/mcp_transport.py、gateway/write_storage.py、gateway/multi_admission.py，除非评审证明必要。

## 10. 测试与验收矩阵

| 分类 | 必须验证 |
|---|---|
| 启用与授权 | 默认 Git 禁用；server enabled + Workspace allowlist 双门禁；未知命令与缺失 Schema 拒绝；Legacy/Multi 行为一致 |
| Workspace 绑定 | 多 Workspace 明确指定；跨 Workspace ID 不能回退；cwd 选取正确 |
| 显式路径 | 正常子路径允许；../、绝对路径、symlink 跳出、Pathspec Magic、REV:PATH、隐式路径参数拒绝 |
| 命令 Schema | 每个支持命令正常执行；未知 options、参数类型错误、互斥选项、Git 全局参数及 raw argv 均拒绝 |
| 父级仓库 | 在子目录 Workspace pull 更新父级仓库其他兄弟目录；不阻断、不回滚 |
| Git 原生行为 | .gitignore 原生规则；tracked 文件 pull 更新；Hook/Filter 执行及外部副作用按设计允许 |
| 共享仓库 | 两个 Workspace 不同命令权限、相同仓库身份、协调锁正确且不死锁 |
| 网络和 clone | Remote 名称限制；clone 目标路径限制；外部本地 Git Remote 经既有配置间接访问允许 |
| 生命周期 | dry_run 不执行；输出上限；超时与进程回收；Gateway 关闭等待/终止；HTTP 断连状态未知不自动重试 |
| 协议 | 2025-11-25 和 2026-07-28 真实 MCP HTTP/stdio，Tool discovery 与严格入参，subscriptions 关闭 |
| 回归 | File API、普通 Exec、Local Skills、Workspace 配置、隐私与备份功能不被改变 |

实现完成后必须运行 bash verify.sh --require-mcp、真实 macOS Git/MCP/Tunnel smoke、完整 pytest 回归、GitHub Actions、Release Manifest 一致性校验和独立代码安全评审。仅设计文档 PR 不能声称实现测试通过。

## 11. 分阶段交付与独立评审

1. **设计 PR（本次）：** 冻结上述用户决定、配置/接口、命令 Schema 和接受的非沙箱边界；独立 Standards 与 Spec 评审，不修改运行代码。
2. **实现 PR A：** 参数编译器、双层授权、Workspace/Legacy 接入、最小命令子集及测试。只暴露已经完成 Schema 的命令。
3. **实现 PR B：** 同仓库身份协调、父级仓库整体同步及 Git Hook/Filter 的真实 macOS 验收；必要时合并到 A，但验收门禁不省略。
4. **发布门禁：** 完整回归、MCP SDK 2.3.0 双协议、真实 Tunnel、Manifest、独立审查、运营者明确同意后再合并 release/ms1。

独立评审必须回答：
- 每个计划开放的 Git 命令是否还有被遗漏的显式本地路径入口？
- 结构化 API 是否真正排除了任意 Git 全局参数、路径 Magic 与 Revision 路径混用？
- 父级 Repository 更新 Workspace 外文件是否与用户决定一致，是否在文档中明确披露？
- 每个 Workspace 独立命令权限与共享 Repository 写锁能否正确共存？
- Git Hook/Filter、已有 Remote 的间接越界行为是否被正确标注为接受风险，而不是错误描述成可被阻止？
- SDK 2.3.0 的取消/断连/关闭与本机 Git 进程收尾是否自洽？
- 哪些命令 Schema 应推迟实施以避免不完整解析？

评审输出：Standards PASS/FAIL、Spec PASS/FAIL、P0/P1/P2 问题（附代码/设计位置、触发前提、证据、修复建议）、建议补充的测试和进入代码实施计划的条件。

## 12. 依据

- 本仓库 gateway/workspaces.py、gateway/workspaces_config.py、gateway/multi_fields.py、gateway/mcp_adapter.py、gateway/mcp_multi.py、gateway/mcp_transport.py。
- docs/PHASE1_LOCAL_TRUST_BOUNDARY.md。
- docs/MCP_SDK_V2_MIGRATION.md。
- Git 官方： https://git-scm.com/docs/git 、https://git-scm.com/docs/gitglossary 、https://git-scm.com/docs/git-add 、https://git-scm.com/docs/gitignore 、https://git-scm.com/docs/githooks 。
