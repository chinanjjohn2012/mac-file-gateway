# Mac File Gateway 2.4.0

中文主文档已经合并到 [README.md](./README.md)，请以主 README 为当前版本说明、安装步骤、安全边界和 ChatGPT Apps / Secure MCP Tunnel 连接流程的唯一维护入口。

此文件保留用于兼容旧链接，避免再维护一份容易与主 README 漂移的重复文档。

2.4.0 主要包含：

- 受控文件读写、目录创建、删除、移动和重命名；
- 受控 `run_command`，支持 pytest、Python 检查和 Go test/vet；
- Local Skill Bridge：`local_skill_info`、`begin_local_skill`、`read_skill_file`、`run_skill_script`；
- 项目外真实 Local Skill policy、审计 hash 和 fail-closed 初始化；
- `MANIFEST.sha256` 发布清单一致性校验。

完整说明见 [README.md](./README.md)。
