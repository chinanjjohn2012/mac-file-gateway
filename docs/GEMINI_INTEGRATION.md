# Gemini Web 双端口本地 MCP 连接（开发分支）

> 功能状态：本地 OAuth/MCP 适配代码与自动化测试已提供；Google Gemini Web 真实账号联调及 macOS Tunnel 验收仍必须单独完成。不要把本地测试视作生产发布批准。

## 设计和边界

- **8765**：现有 `mac-file-gateway`，ChatGPT Web 使用原 `tunnel.sh`。配置和工作区文件均留在用户 Mac。
- **8766**：新增 Gemini OAuth/MCP Adapter（**独立辅助进程，不是另一套文件服务**），通过本机 Streamable HTTP 调用 `127.0.0.1:8765/mcp`。
- Gemini HTTPS Tunnel 只映射到 8766；Tunnel 不是认证机制，8766 必须完成 OAuth 才能调用工具。
- ChatGPT 与 Gemini 可以并行连接；两边最终复用 Gateway 的写入预览、锁、SHA-256 校验与备份。若一侧写入同一源文件，另一侧的过期哈希修改必须拒绝。
- 单工作区支持 4 个读取工具及 10 个文件操作工具（本地开启写权限后才注册）；多工作区另有 `list_workspaces`。Gemini 首版 **不支持** Git、受控 Exec 和 Local Skill 桥接工具。
- 本地部署不等于零数据传输：通过 `read_file` 返回的内容会经 Gemini 云端处理。

## 0. 前提

- Python 3.11+；现有 `release/ms1` 的依赖已安装（项目当前固定 `mcp==2.3.0`）。
- macOS 安装 `cloudflared`（建议 Named Tunnel 和固定 HTTPS 域名）。**不要求公网 IP、路由器端口映射或云主机**。
- Gemini Custom Apps 当前要求美国个人账号、18 岁以上、Keep Activity 开启且英文界面；以 [Google 帮助中心](https://support.google.com/gemini/answer/17209137) 为准。
- 本地操作员可访问 Mac 的终端，并保管 OAuth 客户端密钥和私有状态数据库。

## 1. 启动已有 Gateway

只读调试：

```bash
bash run.sh /absolute/path/to/demo-project --port 8765
```

完整文件写入（**仅测试目录**；`--allow-write` 必须由 Mac 本地操作员开启）：

```bash
bash run.sh /absolute/path/to/demo-project --port 8765 \
  --allow-write --write-path .
```

多工作区使用已有 `bash run.sh --config /private/gateway.json`。不要为了 Gemini 修改既有 `GATEWAY_TOKEN`、Host/Origin 检查或 `tunnel.sh`，也不要把 8765 监听改为 `0.0.0.0`。

## 2. 创建 Gemini 私有客户端

准备一个 DNS 已指向 Cloudflare Named Tunnel 的 HTTPS 域名，例如 `https://gemini-mcp.example.com`。

```bash
python -m gateway.gemini_adapter init \
  --config "$HOME/.config/mac-file-gateway/gemini.json" \
  --public-url https://gemini-mcp.example.com
```

多工作区启动时使用 `--workspace project-a --workspace project-b` 显式指定 Gemini 最多可访问的工作区。默认不批准任何多工作区名称；单工作区无需 `--workspace`。

`init` 只创建一次，拒绝覆盖原文件。生成的配置文件和 SQLite 状态数据库必须只对当前 OS 用户可读（0600，父目录 0700）。`init` 输出的 Client ID/Secret 不要复制到版本库或聊天记录。

**重要：必须预先登记精确的 Google OAuth 回调 URL。** 确认 Google Custom Apps 对该应用实际分配的回调 URL 后，将完整 URL 加入私有 `gemini.json` 文件的 `redirect_uris` 数组。不能使用通配符，也不要猜测回调地址。没有明确登记的回调将被拒绝，必须在 Gemini Developer Mode 验证。

校验配置（不显示密钥）：

```bash
python -m gateway.gemini_adapter check \
  --config "$HOME/.config/mac-file-gateway/gemini.json"
```

启动独立辅助进程：

```bash
python -m gateway.gemini_adapter serve \
  --config "$HOME/.config/mac-file-gateway/gemini.json"
```

服务仅监听 `127.0.0.1:8766`，`/health` 仅供本地运维检查，**不要映射到公网**。

## 3. 启动专用 Gemini Tunnel

参考 [`samples/gemini-cloudflared.yml`](../samples/gemini-cloudflared.yml) 创建个人的私有 Cloudflare Tunnel 配置。替换 `TUNNEL_UUID`、凭据路径和 HTTPS hostname。

关键约束：

1. **只允许** `/mcp`、官方 OAuth 元数据和 `/oauth/authorize`、`/oauth/continue`、`/oauth/token`、`/oauth/revoke`；最后必须用 `http_status:404` 兜底。
2. 目标只可以是 `http://127.0.0.1:8766`，必须设置 `originRequest.httpHostHeader: 127.0.0.1:8766` 以匹配本地 Host 保护。
3. 公网不许转发 `/health`、8765 的 `/read`、`/write`、`/mcp` 或 Git/Exec REST 路由。
4. 外网流量必须走 TLS；不能删除 `Origin`、OAuth Bearer 或服务端工具权限校验来规避客户端错误。

启动：

```bash
bash tunnel-gemini.sh /private/path/to/gemini-cloudflared.yml
```

`cloudflared` 和 Gemini Adapter 是两个独立本地进程，可以与 ChatGPT 的 `tunnel.sh` 并行运行。

## 4. Gemini Web 添加 Custom App

在 [Gemini Connected Apps](https://gemini.google.com/apps) 的 Custom apps 中输入：

```text
https://gemini-mcp.example.com/mcp
```

Adapter 暂不提供 Dynamic Client Registration。根据 Google 的 Custom Apps 说明，展开 Advanced features，手动填写 `init` 产生的 Client ID/Secret。Authorization Server Metadata 和 Protected Resource Metadata 可通过以下 HTTPS 路径发现：

```text
/.well-known/oauth-authorization-server
/.well-known/oauth-protected-resource
```

OAuth 使用 Authorization Code + PKCE S256，令牌持久化存储并允许撤销。首次授权会显示一个请求 ID（浏览器本身不能批准）。**在 Mac 终端亲自检查待批请求：**

```bash
python -m gateway.gemini_adapter pending \
  --config "$HOME/.config/mac-file-gateway/gemini.json"
```

确认请求所列的 Client、回调域名、scope 以及 Workspace，执行：

```bash
python -m gateway.gemini_adapter approve REQUEST_ID \
  --config "$HOME/.config/mac-file-gateway/gemini.json"
```

如需授予更窄权限，可指定多个 `--scope`，例如仅 `--scope files:read`；或指定多个 `--workspace`。审批不能扩大请求原有范围。

回浏览器点击 **Continue after local approval**；授权码只能使用一次且要求 PKCE 验证。随后可在 Gemini 中输入 `@Mac File Gateway`。

## 5. 允许写入与安全确认

OAuth scope 有 `files:read`、`files:write`、`files:delete`，并受 Gateway 本地写入策略限制。Gateway 未设置 `--allow-write` 时，即使已批准 OAuth 写权限，也不会提供文件写入能力。

Gemini 对修改操作会在 UI 中进行确认（须在真实 Developer Mode 复验）；Adapter 另外将非只读工具统一标记为 `destructiveHint=True`。**OAuth 授权、Gemini 确认及 Gateway 的 `dry_run` 各自是独立机制。**

操作步骤仍建议先调用 `dry_run=true` 预览，再经过用户确认使用 `dry_run=false` 执行。需修改已有文件时必须传入 `read_file` 返回的 `file_sha256`；过期文件必须重新读取，不能自动重试不确定结果的非幂等写入。

## 6. 断开连接 / 回滚

停止 Gemini Tunnel 和 8766 Adapter 不会主动关闭 8765 或现有 ChatGPT Tunnel。

紧急撤销所有已签发 Token：

```bash
python -m gateway.gemini_adapter revoke-all \
  --config "$HOME/.config/mac-file-gateway/gemini.json"
```

仅有 OAuth Token 可能被泄漏时，应该先 `revoke-all`，停止 Gemini Tunnel，重新创建客户端密钥（保留备份并按审核流程手工轮换）。切勿删除 Gateway 文件备份或在应急过程中关闭 8765 的安全策略。

## 7. 开发与发布门禁

本地自动化测试：

```bash
python -m pytest -q tests/test_gemini_adapter.py
bash verify.sh --require-mcp
```

`verify.sh` 需要已安装项目 `.venv` 和官方 MCP SDK。变更 Release Manifest 时必须更新 `MANIFEST.sha256`。

真实验收还需要：在 macOS 真机上同时运行两个 Tunnel，使用 [Gemini Developer Mode](https://gemini.google.com/devmode) 完成 OAuth、tools/list、read_file、create_file、replace_text、delete_file、move、确认卡、安全拒绝和断连测试；同时验证 ChatGPT 原有读写。**没有这些证据不能声明已完成线上接入。**

官方参考：[Gemini Custom Apps](https://support.google.com/gemini/answer/17209137)、[Connected Apps MCP](https://developers.google.com/connected-apps/mcp)、[OAuth 实现](https://developers.google.com/connected-apps/mcp/oauth)。
