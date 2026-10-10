# Mac File Gateway 2.4.0

让网页版 ChatGPT 通过 **本地网关 + OpenAI Secure MCP Tunnel** 安全访问 macOS 上的项目文件，并按需启用文件修改、受控命令执行和 Local Skill Bridge。

这套方案不要求使用桌面版 Work/Codex，也不需要把项目同步到云盘。Mac File Gateway 只监听本机 loopback 地址；需要从网页版 ChatGPT 调用时，再通过 Secure MCP Tunnel 连接私有 MCP 服务。

---

## 一、下载代码

项目仓库：

https://github.com/chinanjjohn2012/mac-file-gateway/tree/release/ms1

建议直接使用 `release/ms1`。

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
│   ├── mcp_adapter.py           # MCP 工具注册
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

#### 文件写入：额外 9 个

启用 `--allow-write` 后增加：

- `create_directory`
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

如果同时启用读取、写入、受控命令和 Local Skill Bridge，最多会暴露 **18 个 MCP 工具**。

### 预览、安全保护和限制

**修改预览：** `create_file`、`write_file`、`replace_text`、`create_directory`、删除/移动操作以及 `run_command` 默认采用预览模式。文件写入和受控命令只有明确使用实际执行参数后才会真正执行。

**访问范围：** 所有文件路径都以启动时选择的项目根目录为基准。可以通过 `--write-path` 和 `--exec-path` 进一步缩小写入及命令执行范围。

**版本保护：** 修改、删除或移动已有文件时使用 `read_file` 返回的 `file_sha256` 做版本校验。源文件在读取后发生变化会返回冲突，不会直接覆盖。

**文件备份：** 更新或删除已有文件前保存原始内容到：

```text
.gateway-backups/
```

备份不会自动删除。达到 **2000 个备份文件或 256 MiB** 后，需要先在本地整理旧备份，新的需要备份的写入才会继续。

**文件访问限制：**

- 单文件最大 **1 MiB**
- 单次读取最多 **300 行**
- 搜索单次最多返回 **100 条结果**
- 只处理允许范围内的 UTF-8 代码和文本文件
- 默认屏蔽隐藏文件/目录、依赖目录、数据库文件、密钥文件等
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
7. 运行本地 HTTP smoke test

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

### 4. 启用受控测试/命令执行

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

### 5. 启用 Local Skill Bridge

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

### 6. 额外排除文件

例如：

```bash
bash run.sh "/path/to/project" \
  --exclude 'config/*' \
  --exclude '*.json'
```

### 7. 本地地址

默认监听：

```text
http://127.0.0.1:8765
```

MCP：

```text
http://127.0.0.1:8765/mcp
```

保持这个终端窗口运行。按 `Ctrl+C` 停止 Gateway。

### 8. 本地健康检查

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

这里的 `read_only` 只表示文件写入是否启用。

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

### 9. Local Skill Bridge 真实树检查

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

目录删除不开放。

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

代码级本地验证（MCP import、compileall、pytest、HTTP smoke 和 `MANIFEST.sha256` 一致性）：

```bash
bash verify.sh --require-mcp
```

`verify.sh` 会在 Git 工作树中按已跟踪文件重新计算发布清单；文件内容、文件集合或 `MANIFEST.sha256` 任一发生漂移都会失败。`release/ms1` 的 GitHub Actions 使用同一发布清单作为门禁。

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

- `docs/CONTROLLED_EXEC.md`：受控项目命令执行规则
- `docs/2026-10-01-local-skill-bridge.md`：Local Skill Bridge v1 冻结规格
- `docs/LOCAL_SKILL_BRIDGE_IMPLEMENTATION_PLAN.md`：实现计划
- `docs/PHASE0_LOCAL_SKILL_AUDIT.md`：Phase 0 compatibility audit
- `samples/local-skill-policy/skill-compatibility.json`：虚构的配置格式示例
- `tests/fixtures/skill-rejections.json`：必须允许/拒绝的策略测试向量
- `samples/local-skill-policy/hook-selftests.json`：虚构的 Hook 自检格式示例
