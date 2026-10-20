# Mac File Gateway — Git CLI V1 设计与独立评审规格

状态：**DRAFT / Standards PASS；Spec FAIL（上一轮问题已关闭，本轮新增 P2 设计修订待定向复审）**  
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
8. 多 Workspace 需要独立命令授权；如多个 Workspace 共享同一仓库，需要按实际 Git 仓库身份协调并发操作。V1 延后 checkout 和 clone，避免双模式参数歧义和创建中仓库的锁窗口。
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
- timeout_seconds：严格整数，建议默认 120 秒，允许范围 10..900 秒。至少预留 5 秒用于进程终止和回收；低于 10 秒直接拒绝。
- dry_run：严格布尔，默认 true。仅在纯内存中做严格 Schema、权限、显式路径验证并编译预览；**不启动任何 Git 进程，包含内部 rev-parse/check-ref-format/show-ref**，也不取得仓库锁。预览必须返回 repository_checked=false、branch_checked=false、remote_checked=false、execute_started=false。执行分支才进行仓库、Remote 与引用存在性检查；预览不是成功承诺。
- 未知字段、重复或无效 JSON、错误类型、NUL、控制字符、不支持的参数及尺寸超限必须拒绝。
- MCP 注解：readOnlyHint=false、destructiveHint=true、idempotentHint=false、openWorldHint=true。
- REST 建议 POST /git/run；Legacy/Multi 的 REST 与 MCP 最终进入同一 GitService 和参数编译器。
- 返回 workspace、command、是否 preview、退出码、受限 stdout/stderr、超时和截断状态；仅返回脱敏的仓库身份信息。
- 无响应不代表未执行；不得对 commit/pull/push 自动重试。

## 5. V1 命令 Schema（执行前冻结）

**V1 仅支持 status、diff、log、branch、switch、add、commit、fetch、pull、push。checkout、clone 不属于 V1，配置或调用均应拒绝。** 每个 Git 参数由服务端严格结构化编译，不存在 raw argv、任意额外选项或 Git 全局参数透传。未完成本节全部约束和测试的命令不能进入可配置命令列表。

所有 options 为严格对象；除下面列出的字段外任何键均拒绝，布尔字段不接受 0/1 或字符串代替；路径参数未定义的命令必须 paths=[]；错误和互斥参数必须在启动业务 Git 前拒绝。

| 子命令 | options 字段与固定默认值 | paths | 精确 argv 模板（省略 false 对应的可选 flag） |
|---|---|---|---|
| status | short=false, branch=false | 可选 | git status [--short] [--branch] [-- <literal-paths>] |
| diff | cached=false, stat=false | 可选 | git diff [--cached] [--stat] [-- <literal-paths>] |
| log | limit=20（1..50）, oneline=false | 必须 [] | git log --max-count=N [--oneline] |
| branch | action 必填且为 list/create/delete；create/delete 必填 name，list 必须不提供 name | 必须 [] | git branch --list；git branch -- <name>；git branch -d -- <name> |
| switch | name 必填, create=false | 必须 [] | git switch --no-guess <name>；新建时 git switch --no-guess --no-track -c <name> HEAD |
| add | all=false, update=false；两者不得同时 true；都为 false 时必须提供非空 paths | 可选 | git add [-A 或 -u] [-- <literal-paths>] |
| commit | message 必填且非空, amend=false | 必须 [] | git commit [--amend] -m <message> |
| fetch | remote 必填且为已配置 Remote 名称, prune=false | 必须 [] | git fetch [--prune] <remote> |
| pull | remote 必填，branch 必填，ff_only=true 且 V1 不允许 false | 必须 [] | git pull --ff-only <remote> refs/heads/<branch> |
| push | remote 必填，branch 必填，force_with_lease=false，expected_remote_oid 只在 force_with_lease=true 时必填 | 必须 [] | 普通：git push <remote> refs/heads/<branch>:refs/heads/<branch>；lease：git push --force-with-lease=refs/heads/<branch>:<expected_remote_oid> <remote> refs/heads/<branch>:refs/heads/<branch> |

冻结约束：

1. **checkout 延后。** git checkout <name> 在同名本地分支不存在但 tracked 文件存在时可能退化为文件恢复。V1 只用 git switch 执行分支切换。对任何 checkout 配置与请求直接拒绝，不执行。
2. **switch 默认禁用猜测。** create=false 在仓库独占锁内查验 refs/heads/<name> 为真实存在的本地分支，然后运行 --no-guess；不得从远程同名分支自动创建。create=true 在锁内确认目标不存在且 HEAD 有效，只能从 HEAD 以 -c 新建且明确 --no-track；禁止 -C、--force、--detach、--discard-changes、隐式重置。
3. **push 完整 refspec。** 不能把用户 branch 值原样用作 refspec；名称只可嵌入服务端拼接的 refs/heads/<name>:refs/heads/<name>，并在锁内确认源本地分支存在。branch="+main" 必须准确指向名为 +main 的分支，绝不能得到裸 +main 强制推送。不能通过任何输入形成前导 +、--force 或任意额外 refspec。
4. **精确 lease。** force_with_lease=false 禁止提供 expected_remote_oid；force_with_lease=true 则 expected_remote_oid 必须是匹配该仓库对象格式的完整旧 Commit OID（SHA-1 40 位或 SHA-256 64 位，运行时核验），只允许 --force-with-lease=refs/heads/<branch>:<expected_remote_oid>。显式旧 OID 与远端不一致必须由 Git 拒绝；禁止无 expected 值的 --force-with-lease 变体与普通 --force。
5. **分支名与 Remote 名分开验证。** 纯词法预检用于 Dry-run，运行时在仓库锁内用固定 Git ref 检查，拒绝任意 Revision 表达式、REV:PATH、选项注入、缩写强制标记。Git check-ref-format --branch 通过不代表值可直接作 refspec，必须由编译器包裹完整 ref。
6. **branch action 冻结。** list 禁止 name 和任何 paths；create 只从当前 HEAD，V1 不接受 start_point；delete 仅 -d（不可 -D 强删）；create/delete 必须 name。
7. **fetch/pull/push Remote** 只能从 Git 已配置 Remote 名称选择，不能由本轮客户端提供本地目录、Remote URL、额外 refspec 或 SSH 命令；已配置 Remote 本身指向 Workspace 外的地址属于已接受的间接行为。pull.branch 与 push.branch 分别用受控本地 Branch 名语法，编译完整 refs/heads/<branch>。
8. **add 互斥。** all 和 update 不能同为 true；二者均 false 且 paths 为空报错。无 paths 的 git add -A / -u 按 Git 原生语义可覆盖整个父级仓库，这是用户已接受行为。
9. Commit Message 可由 Hook 进一步解释，Git Remote 和 Hook/Filter 可能执行其他程序；这是有意接受的高权限 Git 语义，而非参数白名单可提供的 OS 隔离。

### 5.1 预览与实际执行

- Dry-run（默认）只执行纯服务端 JSON/Schema/Workspace 路径校验和内存 argv 编译；任何 git rev-parse、git remote、git check-ref-format、git show-ref 均不得启动。输出注明未执行仓库、Remote 或 Branch 的运行时验证。
- Apply 在实际同步 Worker 中重新执行授权与路径验证，执行有界仓库发现，获取同仓库锁，在锁内重查仓库身份及 Remote/Branch 前置条件，再启动业务 Git。
- 预览与执行之间的 Git 状态、Remote、Branch 或文件均可能变化；预览不是已获得一次性执行许可，也不能保证未来 Git 操作成功。

### 5.2 后续命令

**V1 明确延后 checkout 和 clone。** 其他 restore、reset、clean、rm、config、remote、rebase、merge、worktree、submodule、apply、archive、show、cherry-pick 等亦不能通过通用 argv 执行。

- checkout 后续独立解决分支/文件模式歧义，不能只依赖 check-ref-format --branch。
- clone 后续须在其全部创建/checkout/错误清理期间保留目标目录及其子目录的独占预留，并与后来发现的仓库锁协调，防止 .git 出现但 clone 未结束时第二请求进入。

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

## 7. Git 仓库发现和同仓库执行锁

- Git 按所选 Workspace + 已校验 cwd 向上发现父级仓库。父级 Repository 不要求位于 Workspace 内。
- V1 不允许 clone，因此取消旧方案中目标目录创建期的锁转换；实现 PR 不需提前设计双锁。
- dry_run=true 时**完全跳过 Git 仓库发现、前置 Ref/Remote 校验及仓库锁**。
- Apply 在活动同步 Worker 中用固定 Git argv 和与业务命令相同的受控环境执行有界 git rev-parse，获得 worktree root、gitdir 和 common Git dir；无需将用户输入传给原始 Git 参数。
- 使用实际 common Git dir 的规范化目录身份（例如 st_dev/st_ino）作为 Gateway 内部统一仓库锁键，保证多个 Workspace 访问同一个父级仓库及 linked worktree 时协调为同一把锁；独立仓库保持并行能力。
- **V1 同仓库的全部 Git 命令保守串行化。** 等待锁有上限并可能返回 git_busy；不能在等待或执行过程中持有 WorkspaceService 的全局生命周期 mutex。申请 Workspace 同步 Worker 租约在等待锁之前；关闭时拒绝新的租约。
- 在获得锁后重新识别并校验 Git 仓库身份，发生变化报 git_repository_changed，不能静默换用另一仓库或在两把仓库锁之间执行。**业务 Git 启动前必须在同一锁内检查该仓库是否处于失败关闭状态。**
- 释放顺序：执行命令及其有界清理/输出 drain → 锁内确认清理完成并清除活动标记，**或先原子隔离该仓库** → 释放仓库锁 → 释放 Workspace 操作租约 → 允许关闭关联 FD。finally 释放锁绝不意味着清除隔离，细节见 §7.1。
- 只能协调 Gateway 发起的进程，不能阻止终端、IDE、其他 Gateway 实例的 Git 操作；既有本地 OS 信任边界不变。
- 错误/能力列表不泄漏绝对仓库根路径；Git 本身有界 stdout/stderr 仍可能返回父级仓库内容，这是已接受的特权能力。

### 7.1 清理不确定时的失败关闭准入（第二轮复审新增 P2）

**隔离状态及原子性。** 按实际 common Git dir 身份为每个 Repository 维护由同一执行锁保护的状态：READY（可执行）、RUNNING（受控 Git 正在执行）和 QUARANTINED（清理未确认，禁止后续执行）。不同 Workspace 与真实 linked worktree 共用同一状态对象。请求 B 在取得仓库锁以后、启动任何**业务 Git**前，必须检查状态与持久活动记录：若为 QUARANTINED 或发现未确认活动记录，则返回 git_repository_quarantined，业务 Git 启动计数必须为零。状态检查、RUNNING 准入和业务执行不可拆到两次锁获取之间；独立仓库仍可并行。

**崩溃/重启不自动清除。** 为使重启不绕过隔离，服务端在 Workspace 外的私有状态目录维持每仓库的持久活动记录。仅在启用 Git 时配置和初始化该目录。锁内首次启动可能残留的 Git 子进程前，必须用写临时文件、fsync、原子 rename 和目录 fsync 的方式持久写入 RUNNING 记录；记录包含 common-dir 稳定身份、调用 ID、时间，启动后尽可能追加 PID/PGID 与进程启动身份（只用于受信任管理员离线核验）。记录无法可靠写入时禁止启动 Git。仓库发现前的内部 Git 子进程若清理不确定、尚无可靠仓库身份，必须持久记录**服务端级 Git 失败关闭状态**；后续任何业务 Git 均被拒绝，而不能随意把故障指给某个 Workspace。

**锁内终态转换：**

1. **完全收尾（成功或业务失败均适用）：** 已确认受控主进程及其进程组清理、wait/reap、stdout/stderr drain 完成，且该同步 Worker 已不再使用相关执行资源。安全删除并同步活动标记，回到 READY，最后释放仓库锁，后续请求正常准入。Git 非零退出码不构成隔离条件。
2. **清理未确认：** 超时、断连、关闭或异常路径中，如果无法确认受控执行已清理，必须**在持有仓库锁期间**把内存状态转为 QUARANTINED，原子持久化隔离标记，再释放仓库锁并有界返回 git_cleanup_incomplete。已存在的 RUNNING 记录不得提前删除；若隔离更新失败，RUNNING 残留记录也必须在后续请求及下次启动被解释为 QUARANTINED，同时将本实例 Git 功能整体置为失败关闭。
3. **状态清理失败：** 即使子进程已完全退出，删除活动记录/同步持久状态失败仍不得标记 READY；保持隔离并返回明确错误。最后的 finally 仅释放仓库锁和已经结束的同步 Worker 租约，不可抹去隔离状态。

**恢复条件。** V1 不提供 Web/MCP/REST reset 操作，不引入后台监控线程，不以 TTL 到期、git status 成功、Gateway 重启、HTTP 连接关闭或一个独立仓库成功执行作为解封证据。启动时所有残存的 RUNNING/QUARANTINED 标记都按隔离解释。只有受信任的**本地管理员在 Gateway 停止并禁止新 Git 调用后**，根据 PID/PGID、进程启动身份及实际受控进程组/子进程状况确认原执行已经结束或彻底回收，才能通过离线私有状态恢复流程清除对应标记并重新启用 Git。PID 可重用，不能只凭 PID 数字；若无法证明清理完成，则保持隔离。标记目录不能安全读取、存在无法归属的活动记录或身份对应关系不可信时，服务端 Git 功能整体失败关闭，不能自动忽略。

**边界不扩张。** 上述规则仅控制 Gateway 自己的 Git 后续准入和受控进程，不禁止终端/IDE 的 Git，也不试图捕捉主动脱离进程组的第三方 Hook/Filter/Credential Helper；后者仍属用户已接受的非沙箱风险。该机制不对普通 File API、受控 Exec 或 Local Skill 增加 Git 权限。

## 8. Runner 环境、端到端预算与 MCP SDK 2.3

### 8.1 冻结进程环境

- Git Binary 由可信服务端配置选定，禁止客户端指定可执行文件、原始 argv、PATH 或任意 GIT_*。固定 shell=False，不经过原 executor 的 pytest/python/go 命令白名单，也不使用 Pipenv。
- 从**允许列表**构造子进程环境，不直接继承整个 os.environ。显式保留必要的 HOME、USER、LOGNAME、经服务端控制的 PATH、TMPDIR、LANG/LC_*、SSH_AUTH_SOCK，以支持 Git 全局配置、SSH Agent、macOS Keychain 及正常 Credential Helper。
- 清理父环境中的 GIT_DIR、GIT_WORK_TREE、GIT_COMMON_DIR、GIT_INDEX_FILE、GIT_OBJECT_DIRECTORY、GIT_ALTERNATE_OBJECT_DIRECTORIES、GIT_CONFIG_*、GIT_CEILING_DIRECTORIES、GIT_DISCOVERY_ACROSS_FILESYSTEM、GIT_EXEC_PATH、GIT_PREFIX、GIT_SSH、GIT_SSH_COMMAND、GIT_ASKPASS 等可能重定向仓库、Index、配置、对象库、Helper 或命令的变量；Git 内部需要的固定选项必须由 Gateway 唯一生成。
- 仓库发现、锁内 Ref/Remote 校验、业务 Git 命令必须使用相同 Git Binary 和环境策略，确保检查与执行针对同一仓库与 Index。正常磁盘 Git config、Hook、Filter 和 Remote 仍然生效，不把环境清理误写成禁止 Git 扩展。
- 非交互式使用 stdin=DEVNULL 和 GIT_TERMINAL_PROMPT=0；V1 不提供任意 stdin_text/PTY。Gateway Token、Tunnel 凭据和私有策略密钥不得继承到子进程，日志不打印环境、Commit Message、远端凭据或原始 Git 输出。
- stderr/stdout 是不可信且可能含 Workspace 外路径与秘密的 Git 数据。对调用方提供有界响应但不能保证零信息泄漏；日志只记录非敏感操作标识及状态。

### 8.2 精确生命周期

- timeout_seconds 是**从同步 Worker 被准入开始**计算的单个端到端总预算，建议默认 120 秒、有效范围 10..900 秒。预算包括仓库发现、锁等待、锁内检查、Git 执行、stdout/stderr drain、超时终止和 reap，不得为每阶段重新给满 timeout。
- 仓库发现最多 5 秒；仓库锁等待最多 10 秒，二者均取与（总截止期限减去 5 秒清理预留之后）的剩余时间较小值；无法在限定时间内取得锁返回 git_busy。业务 Git 不得在清理预留时间不足时启动。
- 预留最后 5 秒用于进程清理：终止时向进程组发 TERM，最多 2 秒；未退出则发 KILL，剩余时间用于并发 drain/reap；若无法确认主进程及受控子进程已清理，**先在仓库执行锁内持久隔离（§7.1），再有界返回 git_cleanup_incomplete**，不能声称成功。对故意脱离进程组或无法杀死的内核态进程不作绝对保证。
- stdout/stderr 必须持续并发读取，限制原始字节及最终响应字节；超过上限应标明被截断或明确返回失败，不允许对不完整机器输出给出成功/完整语义。
- 已进入 closing 时拒绝新调用；已准入 Git 请求可在连接断开后继续受总超时限制。Gateway 不得在同步 Worker 尚在使用目录 FD 时释放该 FD。**实际同步 Worker 仍在运行时不得释放租约或关闭 FD；受控 Git 清理未确认时，应先持久隔离仓库，再释放执行锁及已经结束的 Worker 租约。** finally 不得将 QUARANTINED 自动复位为 READY。
- 在 SDK 2.3.0 的 stateless JSON 传输中，HTTP 断连并不等于取消执行，也不保证 exactly-once。commit、pull、push 响应丢失属于结果未知，禁止自动重试。

### 8.3 MCP 与前置验证

- 沿用现有 MCPServer、Context、gateway/mcp_transport.py、subscriptions=False、Host/Origin/Token、2025-11-25 / 2026-07-28 双协议；不能恢复 FastMCP 或自实现 JSON-RPC。
- Multi-Workspace 使用已有 StrictPostAdmission；Legacy 原始 JSON 重复键是旧版遗留风险，须明确测试，但不是本次新增的权限授权源。
- dry_run=true 返回 execute_started=false、repository_checked=false、branch_checked=false、remote_checked=false，且实际不调用 Git；dry_run=false 在锁内执行所有需要仓库状态的校验，并区分发现失败、业务命令未启动、业务命令启动后失败、超时、清理未完成。

## 9. 修改范围（实现阶段，不属于本设计 PR）

建议新增：
- gateway/git_cli.py — Git 请求编译与运行器（足够小时不必继续拆分）。
- gateway/git_policy.py — 每个命令的 Schema、授权验证。
- gateway/git_repository.py — 父级仓库发现、共享仓库协调标识、锁内失败关闭状态及持久执行记录；私有状态目录不属于 File API，且 V1 不新增后台任务。

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
| 命令 Schema | 逐命令必填项、默认值、互斥项和 argv；未知 options、错误类型、不支持 paths、checkout/clone 和原始 Git argv 必须拒绝 |
| 父级仓库 | 在子目录 Workspace pull 更新父级仓库其他兄弟目录；不阻断、不回滚 |
| Git 原生行为 | .gitignore 原生规则；tracked 文件 pull 更新；Hook/Filter 执行及外部副作用按设计允许 |
| 共享仓库 | 两个 Workspace 的共享父级仓库同一把锁，linked worktree 共用 common-dir 锁，独立仓库并行；锁等待不持有生命周期互斥锁 |
| 清理未确认的隔离准入 | A 清理未确认先隔离后解锁，B 同仓库/不同 Workspace 或 linked worktree 不得启动业务 Git；独立仓库不受影响；持久隔离重启后仍有效，管理员核实后才能离线恢复 |
| 网络和延后功能 | Remote 名称限制；clone/checkout 直接拒绝；已配置的外部本地 Git Remote 作为间接行为允许 |
| 生命周期 | dry_run 连 rev-parse 都不启动；单一端到端预算覆盖锁/发现/drain/reap；超时 TERM/KILL 和同步 Worker 资源回收，断连状态未知不自动重试 |
| 环境和输出 | 污染 GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE/GIT_COMMON_DIR 不可重定向仓库/Index；保留认证环境，Gateway Token 不继承，stdout/stderr 持续 drain | 
| 协议 | 2025-11-25 和 2026-07-28 × HTTP/stdio × Legacy/Multi，严格参数、Context 和 subscriptions 关闭 |
| 回归 | File API、普通 Exec、Local Skills、Workspace 配置、隐私与备份功能不被改变 |

新增复审要求的**精确回归断言**：临时仓库同时存在 tracked 文件 victim、却没有 victim 分支时，checkout 及相关配置拒绝且文件的未暂存内容不变；switch 在仅有远程同名分支时 --no-guess 必须失败，在新建分支时不猜测远程；branch="+main" 的 push 只定位 refs/heads/+main，普通 push 不得非快进强推，lease 旧 OID 不匹配远端必须拒绝；继承 GIT_DIR、GIT_WORK_TREE、GIT_INDEX_FILE、GIT_COMMON_DIR 污染时仍定位正确仓库/Index；Dry-run 不启动任何 Git 子进程；路径覆盖绝对、..、symlink 祖先/叶节点、缺失叶、Pathspec Magic、REV:PATH 和特殊文件名 literal 行为；同仓库锁在真实 linked worktree 下共享，独立仓库可并行；锁等待、断连、超时、关闭及 output drain/reap 有清晰状态。

新增 P2 必须验证的**可断言场景**：

1. 注入 A 的 git_cleanup_incomplete；A 必须先在同仓库锁内转为 QUARANTINED 并保留持久标记，再释放锁；另一 Workspace B 和相同 common-dir 的真实 linked worktree 调用均返回 git_repository_quarantined，业务 Git 进程启动数为零。
2. 将 B 挂在 A 的仓库锁等待队列，A 完成隔离再解锁：B 不得在状态检查与 Popen 之间跨越锁或启动 Git；活动记录写入失败必须拒绝启动，隔离更新失败必须整体失败关闭，禁止放行。
3. 后续重启载入残留 RUNNING/QUARANTINED 标记、超时、断连和 closing 不得自动放行；只有本机管理员已确认受控主进程/进程组及相关子进程均退出，并通过离线私有状态流程清理标记后方可恢复。
4. 成功和业务 Git 非零失败但**清理确认完成**的路径均清除活动记录、释放锁并允许下一请求；独立仓库在另一仓库隔离期间仍可运行。
5. 已准入同步 Worker 在断连、截止期限或关闭时不得提前释放仍使用中的根 FD 与执行租约；不可在仍有受控 Worker 活动时关闭目录身份。仓库发现身份未确定却清理失败时触发服务端 Git 全局失败关闭。

实现完成后必须运行 bash verify.sh --require-mcp、真实 macOS Git/MCP/Tunnel smoke、完整 pytest 回归、GitHub Actions、Release Manifest 一致性校验和独立代码安全评审。仅设计文档 PR 不能声称实现测试通过.

## 11. 分阶段交付与独立评审

1. **设计 PR（本次）：** 冻结上述用户决定、配置/接口、命令 Schema 和接受的非沙箱边界；独立 Standards 与 Spec 评审，不修改运行代码。
2. **实现 PR A：** 参数编译器、双层授权、Workspace/Legacy 接入、最小命令子集及测试。只暴露已经完成 Schema 的命令。
3. **实现 PR B：** 父级仓库整体同步、真实 Git Hook/Filter、macOS 及 MCP 生命周期验收；**同仓库身份协调需随 PR A 首批可执行 Git 能力一同交付**，不能延后到 B。checkout 与 clone 不在 V1。
4. **发布门禁：** 修订版设计独立 Standards/Spec 复审 PASS 后才能进入逐文件实施计划；实现后进行完整回归、MCP SDK 2.3.0 双协议、真实 Tunnel、Manifest、独立代码审查与运营者批准，再合并 release/ms1。

独立评审必须回答：
- 每个计划开放的 Git 命令是否还有被遗漏的显式本地路径入口？
- 结构化 API 是否真正排除了任意 Git 全局参数、路径 Magic 与 Revision 路径混用？
- 父级 Repository 更新 Workspace 外文件是否与用户决定一致，是否在文档中明确披露？
- 每个 Workspace 独立命令权限与共享 Repository 写锁能否正确共存？
- Git Hook/Filter、已有 Remote 的间接越界行为是否被正确标注为接受风险，而不是错误描述成可被阻止？
- SDK 2.3.0 的取消/断连/关闭与本机 Git 进程收尾是否自洽？
- 哪些命令 Schema 应推迟实施以避免不完整解析？

评审输出：Standards PASS/FAIL、Spec PASS/FAIL、P0/P1/P2 问题（附代码/设计位置、触发前提、证据、修复建议）、建议补充的测试和进入代码实施计划的条件。

## 12. 独立复审反馈的设计修订记录

本轮依据 PR #15 Base ba8634f → Head 64e1305 的独立评审（Standards PASS，Spec FAIL，P1×2、P2×1）：
- P1 checkout 可能退化为文件恢复：V1 延后 checkout，仅通过带 --no-guess 的 switch 切换分支。
- P1 push branch="+main" 可能触发强推：完整 refs/heads/<branch>:refs/heads/<branch>，force-with-lease 必须显式指定目标与旧 OID。
- P2 clone 创建期目标锁/仓库锁衔接缺口：V1 延后 clone。
- 原 P2 后续约束：冻结逐命令 Schema、Git 环境清理、预览零 Git 运行、锁等待与总超时/输出 drain/reap 顺序。
- 第二轮复审 Base ba8634f → Head 4660d05：Standards PASS、Spec FAIL，上一轮三个问题已关闭；新增 P2 是 Git 清理未确认后释放锁前未隔离仓库，导致新请求可能与残留执行重叠。
- 本次定向补充 §7.1、§8.2、§9 和 §10：状态隔离/持久活动标记、锁内原子转换、离线恢复、跨 Workspace/linked worktree 准入和失败关闭验收；**修订仍待独立定向复审，不代表实现测试通过。**

## 13. 依据

- 本仓库 gateway/workspaces.py、gateway/workspaces_config.py、gateway/multi_fields.py、gateway/mcp_adapter.py、gateway/mcp_multi.py、gateway/mcp_transport.py。
- docs/PHASE1_LOCAL_TRUST_BOUNDARY.md。
- docs/MCP_SDK_V2_MIGRATION.md。
- Git 官方： https://git-scm.com/docs/git 、https://git-scm.com/docs/gitglossary 、https://git-scm.com/docs/git-add 、https://git-scm.com/docs/gitignore 、https://git-scm.com/docs/githooks 。
