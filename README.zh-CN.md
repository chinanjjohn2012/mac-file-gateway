# Mac File Gateway 2.5.0

中文主文档已经合并到 [README.md](./README.md)，请以主 README 为当前版本说明、安装步骤、安全边界和 ChatGPT Apps / Secure MCP Tunnel 连接流程的唯一维护入口。

此文件保留用于兼容旧链接，避免再维护一份容易与主 README 漂移的重复文档。

2.5.0 源码主要包含：

- 受控文件读写、目录创建、删除、移动和重命名；
- 受控 `run_command`，支持 pytest、Python 检查和 Go test/vet；
- Local Skill Bridge：`local_skill_info`、`begin_local_skill`、`read_skill_file`、`run_skill_script`；
- 项目外真实 Local Skill policy、审计 hash 和 fail-closed 初始化；
- `MANIFEST.sha256` 发布清单一致性校验。
- Git CLI V1（2.5.0 源码，默认关闭）：Legacy 需要 `--allow-git` 与 `--git-command`；Multi 需要服务端 `server.git.enabled` 和每个 Workspace 的 `git.allowed_commands`，默认关闭。
- 只有经过明确授权，才会注册 `run_git`（REST：`POST /git/run`），默认 `dry_run=true`；其权限、父仓库范围和断连风险详见主 README 新增的 Git CLI 小节。

**版本与发布边界：** 本文档描述包含 Git CLI V1 的 2.5.0 源码，不代表已创建 GitHub Release、完成生产部署或批准生产 Git。Git 依然默认关闭，必须经过运营者单独授权才能启用。

完整说明见 [README.md](./README.md)。
