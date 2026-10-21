# Mac File Gateway 2.4.0

让网页版 ChatGPT 通过 **本地网关 + OpenAI Secure MCP Tunnel** 安全访问 macOS 上的项目文件，并按需启用文件修改、受控命令执行和 Local Skill Bridge。

这套方案不要求使用桌面版 Work/Codex，也不需要把项目同步到云盘。Mac File Gateway 只监听本机 loopback 地址；需要从网页版 ChatGPT 调用时，再通过 Secure MCP Tunnel 连接私有 MCP 服务。

---

## 一、下载代码

项目仓库：

https://github.com/chinanjjohn2012/mac-file-gateway/tree/release/ms1

正式部署仍以已经批准发布的 `release/ms1` 为准。**Git CLI V1 目前是独立开发候选能力**（PR #19 / #23 / #25 / #27 及后续 F 批次），不代表 `release/ms1` 或 2.4.0 已发布 Git 执行权限。其代码与测试基于官方 MCP Python SDK 2.3.0；正式合并、发布以及真实 Tunnel 接入仍需通过独立门禁。

### 已包含的主要代码

```text
mac-file-gateway/
├── gateway/
│   ├── core.py                  # 项目访问、目录浏览、读取、搜索和基础安全策略
│   ├── directories.py           # 创建目录
│   ├── writer.py                # 创建文件、更新文件、精确文本替换
│   ├── write_storage.py         # 写锁、备份、原子提交
│   ├── file_ops.py              # 删除、移动、重命名
│   ├── executor.py              # 受控 run_command
│   ├── mcp_adapter.py           # 单工作区 MCP 工具注册
│   ├── mcp_multi.py             # 多工作区 MCP 工具注册
│   ├── mcp_transport.py         # MCP SDK v2 HTTP 传输配置
│   ├── http.py                  # 本地 HTTP / MCP 服务
│   └── local_skills/
│       ├── bridge.py            # Local Skill Bridge 入口
│       ├── config.py            # 运行时审计 policy / hash 校验
│       ├── registry.py          # Skill 注册、依赖和可用性
│       ├── runs.py              # SkillRun
│       ├── paths.py             # Skill 路径规范化
│       ├── reader.py            # SKILL.md / references / schemas 读取
│       ├── args.py              # Skill 参数校验
│       ├── sql_policy.py        # SQL 只读策略
│       ├── sql_scope.py         # realtime 查询时间范围控制
│       ├── hooks.py             # 现有 Hook 自检和运行
│       ├── executor.py          # 白名单 Skill script 执行
│       └── sanitize.py          # Skill 输出脱敏
├── tests/
│   ├── fixtures/
│   │   └── skill-rejections.json
│   └── ...
├── samples/local-skill-policy/   # 虚构配置示例，不作为运行时默认配置
├── tools/
│   ├── collect_local_skill_policy.py
│   └── check_local_skill_bridge.py
├── docs/
│   ├── CONTROLLED_EXEC.md
│   ├── 2026-10-01-local-skill-bridge.md
│   ├── LOCAL_SKILL_BRIDGE_IMPLEMENTATION_PLAN.md
│   └── PHASE0_LOCAL_SKILL_AUDIT.md
├── setup.sh
├── run.sh
├── verify.sh
└── tunnel.sh
```

### MCP 工具清单

Mac File Gateway 按启动参数决定暴露哪些工具，不会默认打开全部能力。

#### 基础读取：4 个

始终提供：

- `gateway_info`
- `list_files`
- `read_file`
- `search_files`

#### 文件写入：额外 10 个

启用 `--allow-write` 后增加：

- `create_directory`
- `delete_directory`（只删除空目录）
- `create_file`
- `write_file`
- `replace_text`
- `delete_file`
- `remove_file`
- `unlink`
- `rename`
- `move`

其中 `remove_file`、`unlink` 是 `delete_file` 的别名，`move` 和 `rename` 使用相同的受控移动语义。

#### 受控命令：额外 1 个

启用 `--allow-exec` 并指定至少一个 `--exec-path` 后增加：

- `run_command`

它不是通用终端，不接受 shell command string。

当前允许的主要命令形状：

- `pytest ...`
- `python -m pytest ...`
- `python -m compileall ...`
- `python relative_script.py ...`
- `go test ...`
- `go vet ...`

不会通过 `/bin/sh -c` 执行，不支持管道、重定向、command substitution、任意 executable 或 `python -c`。

#### Local Skill Bridge：额外 4 个

配置 `--local-skill-root` 后增加：

- `local_skill_info`
- `begin_local_skill`
- `read_skill_file`
- `run_skill_script`

`release/ms1` 已接通这四个工具和专用 Skill script 执行路径。`run_skill_script` 没有 `dry_run`：通过策略检查后会实际执行白名单脚本。是否可用以 `local_skill_info` 返回的 Bridge / Skill 状态为准；安全初始化失败时仍提供诊断信息，但拒绝 begin/read/run。

Local Skill Bridge 与 `--allow-exec` 是两套独立能力。启用 Local Skill Bridge **不需要**启用 `run_command`。

如果同时启用读取、写入、受控命令和 Local Skill Bridge，最多会暴露 **19 个 MCP 工具**；开发候选版额外获得独立 Git 授权后，Legacy 最多 **20 个**。Multi 仍不提供普通 `run_command` 和 Local Skill Bridge。

#### Git CLI V1：额外 1 个（候选、默认关闭）

只有服务端和命令名单**分别显式授权**且 Git 服务可用时，才会注册：

- `run_git`（REST：`POST /git/run`）。

Legacy 必须同时使用 `--allow-git` 和至少一个 `--git-command NAME`；Multi 需要私有配置中的 `server.git.enabled=true` 及对应 Workspace 的 `git.allowed_commands` 非空。Multi 请求必须明确给出 `workspace`，无默认 Workspace。这个工具不继承文件写权限、普通 `run_command` 或 Local Skill Bridge 的权限；Multi stdio 仍不支持。

支持的十个命令为：`status`、`diff`、`log`、`branch`、`switch`、`add`、`commit`、`fetch`、`pull`、`push`。不支持 `checkout`、`clone`、任意 argv、Git 全局 flags 或 shell。所有调用默认 `dry_run=true`，预览**完全不启动 Git，包括 `rev-parse`**。详细授权、API 形状和不可撤销的 Git 副作用见下方“Git CLI V1”章节。

### 预览、安全保护和限制

**修改预览：** `create_file`、`write_file`、`replace_text`、`create_directory`、删除/移动操作以及 `run_command` 默认采用预览模式。文件写入和受控命令只有明确使用实际执行参数后才会真正执行。

**访问范围：** 所有文件路径都以启动时选择的项目根目录为基准。可以通过 `--write-path` 和 `--exec-path` 进一步缩小写入及命令执行范围。

**版本保护：** 修改、删除或移动已有文件时使用 `read_file` 返回的 `file_sha256` 做版本校验。源文件在读取后发生变化会返回冲突，不会直接覆盖。

**文件备份：** 更新或删除已有文件前保存原始内容到：

```text
.gateway-backups/
```

每次真正修改或删除已有文件且需要创建备份时，Gateway 会先清理创建时间**超过 15 × 24 小时**的完整备份对（`.bak` 和 `.json`）；预览和无变化的写入不会清理。时间以备份名称的 UTC 时间为准，不依赖 mtime。保留期可通过 `--backup-retention-days N` 设置（1–3650，默认 15）。不完整或异常的备份对留给本地人工检查。清理后仍超过 **10000 份备份或 5120 MiB**，需要备份的写入会返回 `backup_full`；不会提前删除未过期备份。采用机制 A：没有后台/定时清理。

**文件访问限制：**

- 单文件最大 **1 MiB**
- 单次读取最多 **300 行**
- 搜索单次最多返回 **100 条结果**
- 只处理允许范围内的 UTF-8 代码和文本文件
- 默认屏蔽隐藏文件/目录；可用 `--allow-hidden-path` 精确授权某个隐藏目录及其子项（可重复，默认不授权）
- 即使授权也拒绝 `.git`、`.env`、`.ssh`、`.venv`、`.gateway-backups` 等敏感路径；仍拒绝依赖目录、数据库和密钥文件
- 拒绝路径越界、符号链接和多链接普通文件
- `*kubeconfig*` 文件默认拒绝访问
- credential-like 内容会做 best-effort 脱敏

**受控命令不是 OS sandbox。** 项目中的测试或脚本一旦被允许执行，仍然拥有启动 Gateway 的 macOS 用户权限，因此 `--exec-path` 应尽量收窄，只允许可信项目。

---

## 二、在 Mac 上安装并启动

### 1. 安装依赖

假设代码放在：

```text
~/Downloads/mac-file-gateway
```

执行：

```bash
cd "$HOME/Downloads/mac-file-gateway"
bash setup.sh
```

需要 **Python 3.11 或更新版本**。

Gateway 自身通过 `requirements.txt` / `requirements-dev.txt` 和项目 `.venv` 管理依赖，当前升级分支固定使用 **`mcp==2.3.0`**，并兼容 MCP `2025-11-25` 与 `2026-07-28` 两种协议。Gateway 仓库本身没有 `Pipfile` 或 `Pipfile.lock`；目标项目中的 Pipfile 仅用于判断受控命令是否需要通过 `pipenv run` 执行，无需为 Gateway 的 SDK 升级修改。

如果没有合适版本，可以使用 Homebrew，例如：

```bash
brew install python@3.13
```

`setup.sh` 会：

1. 创建或复用项目自己的 `.venv`
2. 安装开发依赖
3. 运行 `pip check`
4. 检查官方 MCP SDK
5. 运行 `compileall`
6. 运行完整 pytest
7. 运行 REST-only HTTP、真实 MCP HTTP（双协议）、MCP stdio（双协议）和受控命令断连/超时 smoke test
8. 核验 `MANIFEST.sha256`

安装和验证过程不会修改你准备让 ChatGPT 操作的目标项目。

### 2. 只读启动

最小启动方式：

```bash
bash run.sh "/path/to/project"
```

此时只能读取、浏览和搜索项目。

### 3. 启用文件修改

```bash
bash run.sh "/path/to/project" \
  --allow-write
```

如果只想允许修改特定目录：

```bash
bash run.sh "/path/to/project" \
  --allow-write \
  --write-path service-c \
  --write-path service-a
```

`--write-path` 不会扩大读取权限，只会进一步缩小可修改范围。

### 4. 允许特定隐藏目录的读写和空目录删除

例如，需要让 Web 管理 `service-a/.scratch` 隐藏目录中的文件及子文件夹：

```bash
bash run.sh "/path/to/project" \
  --allow-write \
  --allow-hidden-path service-a/.scratch \
  --write-path service-a/.scratch
```

授权项必须是项目内的**精确隐藏目录路径**，不能使用 glob；可以重复指定。只设置 `--allow-hidden-path` 开放读取，不开放写入；创建、修改、删除还必须有 `--allow-write` 和对应写入范围。删除空文件夹使用 `delete_directory`（REST：`POST /rmdir`），默认先预览；非空目录必须先逐个删除允许范围内的文件，再删除空目录。不提供递归目录删除。隐藏目录中的文件仍需符合文件类型、敏感名称和哈希校验等原有安全策略。

### 5. 启用受控测试/命令执行

例如：

```bash
bash run.sh "/path/to/project" \
  --allow-write \
  --allow-exec \
  --exec-path service-c \
  --exec-path service-b \
  --exec-path service-a
```

如果某个项目使用 Pipenv，可以显式配置：

```bash
bash run.sh "/path/to/project" \
  --allow-exec \
  --exec-path service-c \
  --exec-runner service-c=pipenv
```

这样在 `service-c` 下执行 pytest 时，Gateway 会使用类似：

```text
pipenv run pytest ...
```

如果没有显式配置 `--exec-runner`，Gateway 会在当前允许的 exec scope 内，从执行目录向上查找最近的 `Pipfile`；找到后自动使用 `pipenv run`，否则使用 direct runner。

不需要维护交互式 `pipenv shell`。

### 6. 启用 Local Skill Bridge

以下是通用示例；将 `agent-runtime` 换为你的实际项目相对路径。真实 policy 放在本机配置目录：

```bash
bash run.sh "/path/to/project" \
  --local-skill-root agent-runtime \
  --local-skill-policy-dir "$HOME/.config/mac-file-gateway/local-skill-policy"
```

Local Skill Bridge 不要求 `--allow-exec`。

如果希望文件修改、项目测试和 Skill 都可用，可以组合：

```bash
bash run.sh "/path/to/project" \
  --allow-write \
  --allow-exec \
  --exec-path service-c \
  --exec-path service-b \
  --exec-path service-a \
  --local-skill-root agent-runtime \
  --local-skill-policy-dir "$HOME/.config/mac-file-gateway/local-skill-policy"
```

### 7. 额外排除文件

例如：

```bash
bash run.sh "/path/to/project" \
  --exclude 'config/*' \
  --exclude '*.json'
```

### 8. 本地地址

默认监听：

```text
http://127.0.0.1:8765
```

MCP：

```text
http://127.0.0.1:8765/mcp
```

保持这个终端窗口运行。按 `Ctrl+C` 停止 Gateway。

### 9. 本地健康检查

另开一个终端：

```bash
curl --noproxy '*' -fsS http://127.0.0.1:8765/health
```

正常情况下返回类似：

```json
{
  "status": "ok",
  "read_only": true,
  "mcp_enabled": true
}
```

这里的 `read_only` **只表示 File API 文件写入是否启用**，不表示 Git 必定只读。候选版中启用 `run_git` 后，即使 `read_only=true`，获授权的 `add`、`commit`、`pull` 等仍可按原生 Git 语义修改文件或仓库。

也可以直接检查当前 Gateway 配置：

```bash
.venv/bin/python -m gateway \
  --root "/path/to/project" \
  --local-skill-root agent-runtime \
  --local-skill-policy-dir "$HOME/.config/mac-file-gateway/local-skill-policy" \
  --check
```

`gateway_info` 当前版本应为：

```text
2.4.0
```

### 10. Local Skill Bridge 真实树检查

合并或发布前，可以验证真实 `project/agent-runtime`：

```bash
.venv/bin/python tools/check_local_skill_bridge.py \
  "/path/to/project" \
  --local-skill-root agent-runtime \
  --local-skill-policy-dir "$HOME/.config/mac-file-gateway/local-skill-policy"
```

检查内容包括：

- runtime audit policy hash 是否匹配
- `hooks.json` 和所有已启用 Hook 是否匹配审计 hash
- Hook startup self-test 是否通过
- Skill dependency 是否可用
- Entry Skill 集合是否符合 runtime policy
- 禁用/延期 Skill 是否没有被暴露

这个检查 **不会执行真实 MySQL、ClickHouse、Prometheus、DigitalOcean、Linode 或 trace service 查询脚本**。

---

### Git CLI V1（独立候选分支，未纳入发布版）

**默认不授权 Git**。先在可丢弃的本地测试仓库验证，确认独立复审和原生 macOS 验收结论；不要因为本节存在，就在生产 Gateway 或 Tunnel 上提前开启高权限 Git。开发版本功能与 `2.4.0` 已发布功能必须区分。

#### Legacy：单 Workspace 显式授权

```bash
bash run.sh "/path/to/project" \
  --allow-git \
  --git-command status \
  --git-command diff
```

`--allow-git` 没有 `--git-command`，或只有 `--git-command` 而缺少 `--allow-git`，启动都会拒绝。重复或非法命令名也被拒绝。示例仅授权读取 Git 状态和 diff；若单独授权 `add`、`commit`、`pull` 或 `push`，需要明确接受其写入、Hook/Filter、Remote 副作用。该权限与 `--allow-write`、`--allow-exec` 相互独立，`--check` 不进行 Git discovery 或启动 Git 子进程。

#### Multi：全局开关与 Workspace 双重授权

复制 [`samples/gateway.example.json`](./samples/gateway.example.json) 至项目范围**之外**受保护的私有配置目录后，按需修改：

```json
{
  "schema_version": 1,
  "server": {"port": 8765, "transport": "http", "git": {"enabled": true}},
  "workspaces": {
    "project-a": {
      "root": "/absolute/path/to/project-a",
      "git": {"allowed_commands": ["status", "diff"]}
    },
    "project-b": {
      "root": "/absolute/path/to/project-b",
      "git": {"allowed_commands": []}
    }
  }
}
```

此为 Git 最小授权片段；完整私有配置可保留示例中的受控读取/写入字段。`server.git.enabled` 默认为 `false`；各 Workspace 的 `allowed_commands` 默认为空。**project-b 无 Git 权限**。授权名单只接受已实现的十个命令且不得重复。仅通过 `--config /private/path/gateway.json` 启动 Multi HTTP 模式；不得与 Legacy `--root`、`--allow-git`、`--git-command` 混用，也不提供 Multi stdio。

#### 结构化 API 与字段

Legacy MCP `run_git(command, cwd=".", options={}, paths=[], timeout_seconds=120, dry_run=true)`；Multi 在前面额外要求 `workspace`。两种模式的 REST 地址相同：`POST /git/run`，Multi JSON Body 必须有 `workspace`，Legacy JSON 不接受该字段。

```json
{"workspace":"project-a","command":"status","cwd":".","options":{"short":true},"paths":[],"timeout_seconds":120,"dry_run":true}
```

上例是 **Multi** 的纯预览。真正执行需要显式 `"dry_run": false`。Legacy 应删除 `workspace` 字段。两者均使用受控 JSON 参数，不是任意 Git argv；`options` 必须是对象、`paths` 必须是数组，可省略但**不能为 null**。显式本地 `cwd` 和 `paths` 限定在选中的 Workspace 中且拒绝 `..`、绝对路径和 symlink；无 paths 的 `git add -A`、`pull` 以及 Git Hook 等**仍可影响整个父仓库**。Git 仓库根目录可以位于 Workspace 根的父级，这不是 OS sandbox。

| 命令 | 可用的 `options` | 语义限制 |
|---|---|---|
| `status` | `short`、`branch` | 原生状态，可选显式 paths |
| `diff` | `cached`、`stat` | 原生 diff，可选显式 paths |
| `log` | `limit`（1–50）、`oneline` | 默认最多 20 条 |
| `branch` | `action`（list/create/delete）、`name` | 创建或删除需要 name |
| `switch` | `name`、`create` | 固定 `--no-guess`，不会隐式创建远端同名分支 |
| `add` | `all`、`update` | 互斥；两者都未启用时须提供 paths |
| `commit` | `message`、`amend` | message 必填；可能运行 Hook |
| `fetch` | `remote`、`prune` | remote 必须是已配置的名字，不接受 URL |
| `pull` | `remote`、`branch`、`ff_only` | 固定 fast-forward-only，默认 `ff_only=true` |
| `push` | `remote`、`branch`、`force_with_lease`、`expected_remote_oid` | 不允许隐式强推，lease 需明确的旧 OID |

`timeout_seconds` 为 **10–900 秒**（默认 120），覆盖发现仓库、等待同仓库锁、检查、执行以及清理。Git REST 请求独立受 65,536 字节 Body 上限限制。执行结果包含 `execute_started`、`repository_checked`、`remote_checked`、`branch_checked`、`exit_code`、`timed_out`、`output_truncated`、`cleanup_status` 等字段；不把退出码非零直接当成进程清理失败，也不会将截断结果声称为完整输出。

#### 高权限边界、断连与离线恢复

- **Git 不使用 File API 的 hidden/exclude/redaction/backup 规则**。Git 的原生输出可能包含其他 Workspace 内的路径或秘密；Hook、Filter、Credential Helper、Remote 能以当前 macOS 用户权限访问工作区外的内容并启动程序。File API 的 `read_only=true` **不禁止 Git 写入**；Git 修改不生成 `.gateway-backups`。
- `dry_run=true` 是唯一不启动 Git 的预览路径；`dry_run=false` 经服务端及 Workspace 双重授权进入同步 Worker，先持久化 `DISCOVERING` / `RUNNING` 再 Popen。业务 Git 在同一 common-dir 串行；其他本机终端或 IDE 不受这把锁协调。
- **客户端断连或超时不证明业务取消**。尤其 `commit`、`pull`、`push` 的响应丢失表示结果未知，不要自动重试；应在安全恢复或人工确认后再决定下一步。
- Git 清理不确定、遗留活动记录或持久状态异常会隔离相关仓库或整个 Git 服务，可能返回 `git_repository_quarantined`、`git_global_quarantined`、`git_cleanup_incomplete`、`git_state_unavailable`。**没有 MCP/REST 重置隔离的接口**；不可通过反复重启、TTL 或另外一个 Workspace 的 `status` 自动解封。
- 管理员必须先停止 Gateway、禁止新 Git 调用，并独立确认相关主进程、受控子进程及进程组都结束，再根据本地私有状态离线处理遗留标记。PID 可能重用，不应仅凭 PID 数字作清理证明。若无法确认则保持隔离。Git 进程已完整收尾后的状态删除同步失败仍按已批准的 §7.2 故障模型处理，不承诺任意硬件故障下永久持久标记。

## 三、让网页版 ChatGPT 连接到 Mac

### 1. 准备 Tunnel 权限

连接路线需要：

- ChatGPT 账号或工作区允许使用 **Developer mode**
- OpenAI Platform 中存在可用的 Secure MCP Tunnel
- Tunnel 与正确的 ChatGPT 工作区关联
- 运行 Tunnel Client 的身份拥有对应权限
- 一个可供 Tunnel Client 使用的 runtime API key

Tunnel 权限与 ChatGPT 订阅本身是两套概念，不能只根据订阅类型判断是否已经具备。

Platform 设置入口：

```text
https://platform.openai.com/settings/organization/tunnels
https://platform.openai.com/settings/organization/api-keys
```

### 2. 安装 Tunnel Client

OpenAI Tunnel Client 可以通过 Homebrew 安装：

```bash
brew install openai/tools/tunnel-client
```

### 3. 启动本地 Gateway

第一个终端：

```bash
cd "$HOME/Downloads/mac-file-gateway"

bash run.sh "/path/to/project" \
  --allow-write \
  --allow-exec \
  --exec-path service-c \
  --exec-path service-b \
  --exec-path service-a \
  --local-skill-root agent-runtime \
  --local-skill-policy-dir "$HOME/.config/mac-file-gateway/local-skill-policy"
```

### 4. 启动 Secure MCP Tunnel

第二个终端：

```bash
cd "$HOME/Downloads/mac-file-gateway"
bash tunnel.sh
```

`tunnel.sh` 会先检查：

```text
http://127.0.0.1:8765/health
```

确认本地 MCP 已启用，然后提示输入：

```text
Tunnel ID
tunnel_********************************

OpenAI Platform runtime API key
sk-***
```

API key 输入时不会显示。

脚本不会把 runtime API key 写入项目文件；它会通过环境变量传给 `tunnel-client run`。

需要同时保持：

```text
终端 1：Mac File Gateway
终端 2：Secure MCP Tunnel
```

都处于运行状态。

不要把 runtime API key、kubeconfig token 或其他凭据发送到聊天中。

### 5. 在 ChatGPT 中创建自定义 App

ChatGPT 当前通过 **Apps / 自定义 MCP App** 管理这类连接，不再使用旧的 “Plugins → 添加 MCP 连接” 流程。

先确认工作区允许 Developer mode。根据套餐和角色，入口通常在：

```text
Settings
  → Apps
  → Advanced settings
  → Developer mode
```

管理员/所有者也可以从：

```text
Workspace settings
  → Apps
  → Create
```

创建自定义 App。Enterprise / Edu 工作区还可能需要管理员先在 `Permissions & Roles → Connected Data` 中授予 Developer mode 权限。

创建 **Mac File Gateway** App 时，使用当前工作区提供的 Secure MCP Tunnel 连接方式，选择已有 Tunnel 或填写对应 `tunnel_id`，然后执行工具扫描（Scan Tools）并创建 App。创建完成后，开发中的 App 会出现在 `Settings → Apps → Enabled Apps`，通常带有 `Dev` 标记。

在聊天中需要访问本地 Gateway 时，从工具菜单选择 **Mac File Gateway**，或在支持的界面中 @mention 该 App。App 的选择作用于当前消息；后续消息如果需要再次读取本地数据或执行工具，应再次选择或引用该 App。

当前包含 write / modify actions 的完整 MCP 主要面向 ChatGPT Business、Enterprise 和 Edu；Pro 的自定义 MCP 目前限 read / fetch。具体 UI 和权限仍可能随产品更新而变化。

OpenAI 官方说明：

https://help.openai.com/en/articles/12584461-developer-mode-and-full-mcp-connectors-in-chatgpt

**到这里才表示网页版 ChatGPT 已经可以调用你的 Mac Gateway。**

---

## 四、连接成功后怎么用

### 1. 浏览和分析代码

例如：

> 使用 Mac File Gateway，先列出项目目录，再搜索 Python 文件里与 click tracking 有关的代码。读取相关文件并给出行号，分析点击统计逻辑，不修改任何文件。

也可以指定文件：

> 读取 service-a 中和 OpenRTB click tracking 有关的代码，解释数据是怎么流转的。

所有文件路径都使用**相对于启动时项目根目录的路径**，不用把完整 Mac 路径发给 ChatGPT。

### 2. 创建文件或目录

例如：

> 在项目根目录创建 gateway_demo.txt，内容是 hello。先给出预览，不要实际写入。

确认后再说：

> 按刚才的预览创建这个文件。

### 3. 修改已有文件

例如：

> 读取 service-c 中指定文件，把超时时间从 3 秒改成 5 秒。先展示 diff，不修改其他位置。

Gateway 会使用 `file_sha256` 做版本检查。

如果文件已经被 Cursor、IDE 或其他进程修改，会返回 conflict，需要重新读取后再操作。

### 4. 删除、移动和重命名

当前版本已经支持文件级：

- 删除
- 移动
- 重命名

例如：

> 读取 src/old.py 后，把它移动到 src/archive/old.py。先预览，不覆盖已有文件。

可删除空目录（`delete_directory`，默认预览），不支持递归删除非空目录。

### 5. 执行项目测试

如果启动时启用了 `--allow-exec`：

> 在 service-c 里运行 pytest，只运行 tests/test_xxx.py。

或者：

> 在 service-a 执行 go test ./...。

Gateway 不会打开交互式 shell，而是通过受控 argv 直接启动允许的命令。

### 6. 使用 Local Skill Bridge

实际 Entry Skill 名称、脚本和依赖由本地真实 policy 决定，通过 `local_skill_info` 查看。公开 `samples/local-skill-policy/` 仅展示虚构的数据库、指标、云查询等配置；不会自动加载，也不代表已审计的生产能力。

可以直接描述业务任务，例如：

> 使用可用的本地数据库 Skill 检查指定表结构，然后执行只读查询。

Local Skill Bridge 会先通过 `begin_local_skill` 建立一个受控 SkillRun，然后只允许读取已审计的 Skill 文件和显式依赖，并只执行 runtime policy 白名单中的脚本。

---

## 五、Local Skill Bridge v1 安全边界

### 数据库只读

v1 中 MySQL / ClickHouse 查询由 Gateway 的 SQL Policy Gate 先检查。

允许的是只读查询，例如：

- `SELECT`
- `WITH ... SELECT`
- `DESC`
- `DESCRIBE`
- 部分受控 `SHOW`
- 普通 `EXPLAIN`

写操作、系统敏感 schema、外部 ClickHouse table function 等会被拒绝。

### realtime 查询范围

对于已审计的 `*_realtime` 表，Gateway 要求查询范围能够被确定证明为 **不超过 2 小时**。

不确定、动态表达式、JOIN/UNION/CTE/subquery 等 realtime 查询形式会 fail closed。

### Skill script 不是通用 shell

`run_skill_script`：

- 只能执行 runtime policy 中显式 allowlist 的 Skill script
- argv 逐项校验
- DB script 先经过 SQL Policy
- 再经过现有 Hook
- stdin 关闭
- timeout 受限
- 输出大小受限并脱敏
- cwd 使用独立 artifact 目录

它不能用来运行任意 shell command。

### Audit freshness

Skill、Hook 或 `hooks.json` 的审计文件发生变化后：

- 单个 Skill hash 变化：对应 Skill 变为 unavailable
- dependency unavailable：依赖它的 Entry Skill 同步 unavailable
- `hooks.json` 或 Hook script hash 变化：整个 Local Skill Bridge fail closed

修改 `agent-runtime/skills` 后，需要重新审计并更新 runtime policy，而不是自动信任新内容。

---

### 本地 policy 与更新流程

真实配置使用两份文件：`skill-compatibility.json` 和 `hook-selftests.json`。默认目录为 `~/.config/mac-file-gateway/local-skill-policy/`，也可由本地启动者用 `--local-skill-policy-dir` 指定。目录必须位于 Gateway 项目范围之外；Web/MCP 无法指定或修改该目录。配置缺失、标为 draft 或校验失败时，Bridge 保持 disabled，不会回退到 sample。

每个有脚本的 Skill 必须显式声明 `kind`，可选 `shell`、`mysql`、`clickhouse`、`prometheus`、`cloud-api`、`trace`；无脚本的 Skill 使用 `instructions`。执行策略根据 kind 选择，业务 Skill 名称无需写入代码。云查询还需 `command_script_sections` 映射每个脚本至已有的参数策略；`agent_dir_env` 指定已审计脚本所需的目录环境变量。具体配置属于本地审计基线。

先备份当前两份真实 JSON，再更新公开代码。两份 JSON 作为一套版本保存；迁移只增加显式策略类型，不刷新已有证据 hash 或改变白名单。目录权限建议 0700，文件权限 0600。

Skill 或 Hook 改动后，采集新的证据 draft：

```bash
.venv/bin/python tools/collect_local_skill_policy.py /path/to/project \
  --local-skill-root agent-runtime \
  --local-skill-policy-dir "$HOME/.config/mac-file-gateway/local-skill-policy" \
  --output-dir "$HOME/.config/mac-file-gateway/local-skill-policy-draft-20261002"
```

输出目录必须是新目录且在项目范围外。工具保留权限配置，只采集已列入证据的文件 hash 变化；不执行 Hook 或查询脚本，也不自动添加新 Skill、白名单、时间列映射或 Hook 用例。`changes.json` 是本地审计变更清单。

审核代码、依赖和权限以及新增/移除的 Hook 后，再将 draft 两份 JSON 的 `review_status` 改为 `approved`。用上面的真实树检查命令验证该 draft 目录；检查会执行 Hook 自检，不执行查询脚本。检查通过后，把启动参数切换到这一整套配置并重启 Gateway。保留旧目录作为本地回滚版本。

## 六、备份和使用边界

文件写入产生的备份位于：

```text
.gateway-backups/
```

这是本地未加密的原始文件内容。

建议将：

```text
.gateway-backups/
.gateway-tmp-*
```

加入目标项目的 `.gitignore` 或本地 Git exclude，避免提交。

Gateway 不提供远程删除/恢复备份的接口，需要在 Mac 本地处理。

### 并发修改

Gateway 使用项目级 advisory lock 协调多个 Gateway 写入，但普通 IDE、Cursor、Git 或其他本地程序不会参与这个锁。

因此仍建议避免多个工具同时修改同一个文件。

文件更新、删除、移动会在提交前再次校验源文件状态；发现变化会拒绝继续。

### macOS 文件元数据

Gateway 主要面向普通代码和 UTF-8 文本文件。

它会保留普通 POSIX 权限位，但不保证保留所有 macOS：

- extended attributes
- ACL
- resource forks

因此不适合通过 Gateway 修改需要完整 macOS 文件元数据语义的文件。

---

## 七、常用检查命令

开发候选版本的本地验证（MCP SDK import、compileall、pytest、REST HTTP、真实 MCP HTTP / stdio 双协议、Git Legacy/Multi、Git Hook 断连 Smoke 和 `MANIFEST.sha256` 一致性）：

```bash
bash verify.sh --require-mcp
```

`verify.sh` 会在 Git 工作树中按已跟踪文件重新计算发布清单；文件内容、文件集合或 `MANIFEST.sha256` 任一发生漂移都会失败。GitHub Actions 也会检查同一发布清单。

其中 REST-only 的 `tests/smoke_live.py` 输出 `mcp_verified: false` 是预期行为（它以 `--http-only` 启动）；独立的 `tests/smoke_mcp_live.py` 成功后才输出 `mcp_verified: true`，`tests/smoke_mcp_stdio.py` 验证真实 stdio 子进程交互并输出 `stdio_verified: true`。新增的 `tests/smoke_mcp_disconnect.py` 使用临时项目验证现代 MCP 的受控执行中断连、超时及**一次真实 Git commit Hook 在断连后继续完成**；`tests/smoke_git_cli.py` 单独覆盖 Legacy/Multi Git MCP 双协议及授权后的预览/应用。Gateway 已禁用未使用的 `subscriptions/listen` 长连接接口。断连后的执行与重试契约详见 `docs/MCP_SDK_V2_MIGRATION.md`；断连不表示已启动的操作被撤销。

只检查启动策略：

```bash
.venv/bin/python -m gateway \
  --root "/path/to/project" \
  --local-skill-root agent-runtime \
  --local-skill-policy-dir "$HOME/.config/mac-file-gateway/local-skill-policy" \
  --check
```

验证真实 Local Skill Tree：

```bash
.venv/bin/python tools/check_local_skill_bridge.py \
  "/path/to/project" \
  --local-skill-root agent-runtime \
  --local-skill-policy-dir "$HOME/.config/mac-file-gateway/local-skill-policy"
```

查看本地服务：

```bash
curl --noproxy '*' -fsS http://127.0.0.1:8765/health
```

停止服务：

```text
Ctrl+C
```

---

## 八、相关文档

- `docs/MCP_SDK_V2_MIGRATION.md`：SDK 2.3.0 迁移范围、保留契约、验证和回滚
- `docs/CONTROLLED_EXEC.md`：受控项目命令执行规则
- `docs/2026-10-01-local-skill-bridge.md`：Local Skill Bridge v1 冻结规格
- `docs/LOCAL_SKILL_BRIDGE_IMPLEMENTATION_PLAN.md`：实现计划
- `docs/PHASE0_LOCAL_SKILL_AUDIT.md`：Phase 0 compatibility audit
- `samples/local-skill-policy/skill-compatibility.json`：虚构的配置格式示例
- `tests/fixtures/skill-rejections.json`：必须允许/拒绝的策略测试向量
- `samples/local-skill-policy/hook-selftests.json`：虚构的 Hook 自检格式示例


---

## Multi-Workspace Phase 1 + Git CLI V1 (development candidate; not yet released)

The optional `--config` mode selects **multiple explicitly named local project roots** using one Gateway HTTP process and one MCP tunnel. This mode is under implementation and is not included in the published `release/ms1` deployment until tests and security review pass. Do not use the draft branch for production access.

Configuration stays **private and local**, never in the public Git repository. Start from [samples/gateway.example.json](./samples/gateway.example.json), substitute your own absolute project directories, then place the final file at `~/.config/mac-file-gateway/gateway.json`. On a personal Mac, a `0700` config directory and `0600` JSON file are **recommended but not enforced**. Phase 1 trusts local OS accounts and does not use ownership, POSIX mode or extended ACLs as startup admission gates. Symlinks, multiply-linked config files, unexpected file types, ambiguous JSON, control-plane/Workspace overlaps and API authorization errors are still rejected. See [Phase 1 local trust boundary amendment](./docs/PHASE1_LOCAL_TRUST_BOUNDARY.md) for the accepted local-user risk.

```bash
mkdir -p "$HOME/.config/mac-file-gateway"
chmod 700 "$HOME/.config/mac-file-gateway"
chmod 600 "$HOME/.config/mac-file-gateway/gateway.json"

# Phase-1 validation: no listeners and no file writes.
bash run.sh --config "$HOME/.config/mac-file-gateway/gateway.json" --check

# Run after validation.
bash run.sh --config "$HOME/.config/mac-file-gateway/gateway.json"
```

In Multi mode, `list_workspaces` enumerates **IDs only**, and every file tool requires an explicit `workspace` argument. REST `GET /workspaces` lists the same IDs; REST GET file methods use `workspace` in the query, and POST mutations require it in the JSON body. There is no implicit default or cross-workspace move/rename. Per-root permissions, backups and locks are independent. A writable Workspace cannot modify a read-only Workspace through file tools.

**Multi restriction:** Multi mode retains the original file APIs and does **not** expose general `run_command` or Local Skill Bridge. Separately authorized Git CLI V1 is a distinct reviewed capability: `server.git.enabled=true` AND a nonempty per-Workspace `git.allowed_commands` list are required before `run_git` / `POST /git/run` can execute. The default sample grants neither. Multi stdio remains unsupported. Existing Legacy root/HTTP/stdio remain available; never mix `--config` with Legacy root/write/exec/Git flags. See the Chinese Git CLI V1 section above for the exact API contract.

The Multi HTTP listener validates every POST before invoking REST or the MCP SDK. Only one JSON media type (optionally `charset=UTF-8`) is accepted; duplicate JSON keys, unknown tool arguments, excessive decoded data and unsupported multi-mode methods fail closed. This mode assumes a trusted local OS environment: Workspace boundaries are remote API capability routing, not OS-level multi-tenant sandboxing. Other local accounts with write access to configuration, runtime code, or source files can change Gateway behavior; that risk is outside the Phase 1 threat model.

Recognized credentials and configured protected paths are hidden consistently from file reads, search results and diff previews. This is **best-effort content protection**, not general DLP. Whole-file overwrite of sources containing hidden lines is refused; exact replacement can target only visible source spans and never reconstruct a redacted display as source content. Backup retention remains 15 UTC days / 10,000 backups / 5,120 MiB **per root**, with opportunistic pruning during actual writes.

To revert, stop the Multi listener and start the previous positional-root command. Existing files and backups need no conversion.

### Git CLI V1 — English summary (draft feature, not a published release)

- **Default denial:** Legacy requires both `--allow-git` and repeatable `--git-command NAME`. Multi requires `server.git.enabled: true` and a nonempty per-Workspace `git.allowed_commands`. A Multi `run_git` call must specify `workspace`; Legacy does not accept that field. General Exec/Local Skills grants do not enable Git.
- **Interface:** MCP `run_git` or `POST /git/run` uses `command`, `cwd` (default "."), `options` (object), `paths` (array), `timeout_seconds` (10–900, default 120) and `dry_run` (default true). These options/paths can be omitted, but explicit JSON null is invalid. The REST endpoint has a separate 65,536-byte body cap.
- **Allowed Git commands:** `status`, `diff`, `log`, `branch`, `switch`, `add`, `commit`, `fetch`, `pull`, `push`. No raw argv, `checkout`, `clone`, or arbitrary shell. Apply requires `dry_run=false`; preview launches **zero** Git subprocesses, including repository discovery.
- **Repository privilege is broader than File API:** The actual repository can be an ancestor of the Workspace. Explicit local cwd/paths stay Workspace-contained, but native Git `pull`, `add -A`, hooks, filters, remote/credential helpers can change files outside the chosen Workspace. File `read_only`, hidden/exclude/redaction rules and backup guarantees **do not apply** to Git effects/output. Git is **not an OS sandbox**.
- **Crash/disconnect:** A disconnected or timed-out MCP client may not know whether a non-idempotent Git operation finished. Never automatically retry `commit`, `pull` or `push`. Durable `DISCOVERING`/`RUNNING` intent is required before Git Popen; uncertain cleanup triggers persistent quarantine. There is **no** Web/MCP/REST quarantine reset. Only a trusted local administrator, after Gateway shutdown and independent evidence that the affected main process/group/children have exited, may perform offline recovery. Repeated restart is not a recovery method.
- **Status:** This is a reviewed development candidate from separate Git CLI draft PRs. Published `release/ms1` and the existing `2.4.0` release are **not** declared Git-enabled by this documentation. Native macOS test success does not replace real Secure MCP Tunnel end-to-end validation or release approval.
