# Microsoft Dev Tunnel + Gemini Web（开发分支）

> 代码适配与自动化测试不代表微软 Tunnel 或 Google Gemini 真实账户已联通。真实联调前不使用生产 Workspace，不合并或部署到 release/ms1。

## 1. 架构与安全约束

ChatGPT Web -> 原 OpenAI Secure MCP Tunnel -> 127.0.0.1:8765/mcp

Gemini Web -> Microsoft Dev Tunnel HTTPS -> 127.0.0.1:8766/mcp -> 127.0.0.1:8765/mcp

仅一个文件处理核心，不新增端口、不修改 OpenAI 的 tunnel.sh。Cloudflare 配置仍默认可用，Dev Tunnel 配置显式选择 tunnel_type=devtunnel。

Dev Tunnels 在微软服务端终止 HTTPS 并重写请求头；它转发的是端口，不是 Cloudflare 式路径白名单。8766 的 Dev Tunnel 模式仅允许 MCP、OAuth discovery（含 /mcp 资源路径）以及 authorize、continue、token、revoke。/health 在该模式下连本地请求也返回 404；所有未列明路径及变体拒绝。Host 只接受本地 loopback 或配置中的精确公开域名（不信任 X-Forwarded-* 作为身份）；OAuth 认证和现有 scope/Workspace 校验继续执行。

公网网络层允许匿名连接并不授权 MCP 调用。永远不要把 8765 或其他本地服务加入该 Tunnel。使用独立、持久、单端口 Tunnel，限制匿名 ACL 期限。启动脚本不创建 Tunnel、不改变 ACL，也不自动续期。不要在托管期间从另一终端或工具修改其端口/ACL。CLI 预检只是启动前的核对，不是云端 ACL 或并发配置修改的强制隔离。

## 2. 安装和创建专用 Tunnel

在 Mac 安装：

~~~bash
brew install --cask devtunnel
devtunnel user login
devtunnel --version
~~~

创建独立 Tunnel，初始保持私有。记录 CLI 返回的实际 Tunnel ID；如果包含区域后缀，使用完整 ID。

~~~bash
devtunnel create
devtunnel port create TUNNEL_ID -p 8766 --protocol http
devtunnel port list TUNNEL_ID
devtunnel port show TUNNEL_ID -p 8766
~~~

确认唯一端口为 8766、协议为 http。获取该端口的实际 HTTPS URL，例如 https://abc123-8766.usw2.devtunnels.ms 。如果必须先 host 才能得到 URL，可在 Tunnel 仍私有、Adapter 未运行且确认没有其他服务占用 8766 时临时执行 devtunnel host TUNNEL_ID，记录地址后 Ctrl-C。不要猜测域名或使用 inspection URL。

地址可能因隧道到期、重建、区域变化而改变。改变公开 origin 时应撤销旧授权、创建新的私有客户端配置和独立状态库并重新连接 Gemini，不要直接复用旧令牌数据库。

## 3. 启动本地 Gateway 与 Gemini Adapter

从 feature/gemini-dual-port 的安装目录运行 setup.sh（如果尚未安装依赖）。使用无敏感数据的测试 Workspace，先复用现有 8765 进程；如未启动：

~~~bash
bash run.sh /absolute/path/to/demo-project --port 8765 \
  --allow-write --write-path .
~~~

确认已有 ChatGPT 使用原 tunnel.sh；不要再启动第二个 Gateway，不要更改原 GATEWAY_TOKEN/Host/Origin 保护。

首次建立新的私有客户端配置（使用实际 HTTPS origin，不含末尾 / 或 /mcp）：

~~~bash
CONFIG="$HOME/.config/mac-file-gateway/gemini-devtunnel/gemini.json"
PUBLIC_URL="https://abc123-8766.usw2.devtunnels.ms"
.venv/bin/python -m gateway.gemini_adapter init \
  --config "$CONFIG" --public-url "$PUBLIC_URL" \
  --tunnel-type devtunnel
~~~

输出的 Client ID/Secret 仅供本机操作员填入 Gemini，不要复制进聊天、仓库或 Tunnel 日志。多工作区使用一个或多个 --workspace 参数。配置文件 0600，所在专用目录 0700。首次实际 OAuth 前确认并登记完整 Google 回调地址至 redirect_uris；禁止通配符或猜测回调。

~~~bash
.venv/bin/python -m gateway.gemini_adapter check --config "$CONFIG"
.venv/bin/python -m gateway.gemini_adapter serve --config "$CONFIG"
~~~

另一个终端中：

~~~bash
CONFIG="$HOME/.config/mac-file-gateway/gemini-devtunnel/gemini.json"
bash tunnel-gemini-dev.sh TUNNEL_ID --config "$CONFIG" --check-only
bash tunnel-gemini-dev.sh TUNNEL_ID --config "$CONFIG"
~~~

预检检查 CLI JSON 中唯一端口为 HTTP 8766（如果 CLI 返回 forwarding URI，也校验公开 origin）；随后在本地验证 OAuth discovery、未经认证的 MCP 401 和路径隔离，才执行 host。CLI JSON 格式不兼容时 fail closed，不直接绕过预检。如果命令返回的公网 HTTPS 地址与配置不同，停止 Tunnel，修正配置并重新授权。

## 4. 允许 Gemini 云端访问并进行公网无凭据探测

只有在本地预检、安全评审和专用测试 Workspace 均已就绪后，由 Mac 操作员主动设置限时匿名 ACL。仅允许端口 8766，不使用全 Tunnel 的匿名权限：

~~~bash
devtunnel access create TUNNEL_ID --port 8766 --anonymous --expiration 4h
devtunnel access list TUNNEL_ID --port 8766
~~~

必须保持 Adapter 的 OAuth 认证。然后运行（不会上传任何文件或 OAuth Token）：

~~~bash
CONFIG="$HOME/.config/mac-file-gateway/gemini-devtunnel/gemini.json"
bash tunnel-gemini-dev.sh TUNNEL_ID --config "$CONFIG" --probe-public
~~~

公网探测不自动跳转；OAuth metadata 必须返回 200 且 issuer/resource 精确匹配，未认证 MCP GET/POST 必须返回 401 且含 WWW-Authenticate challenge，/health、/read、/write、/git/run、/mcp/、/oauth/admin 均必须返回 404。探测失败即停止 Tunnel 并撤销匿名 ACL，不得通过关闭 OAuth、扩大 Host 白名单或公开 8765 来修复。

Microsoft 的防钓鱼提示页面可能出现在首次 HTML 浏览器访问；真实用户应阅读提示再自行继续。API 探测使用 Accept: application/json，不依赖浏览器登录 Cookie。不要要求 Gemini 注入绕过提示或 Microsoft 认证的特殊 Header，也不要把 Microsoft Tunnel Token 当作 Gemini OAuth Token。

### 独立 curl 检查脚本（不需要 Dev Tunnel CLI）

在 Gateway 安装目录运行，默认读取 ~/.config/mac-file-gateway/gemini-devtunnel/gemini.json：

~~~bash
# 只检查本地 8766（默认）
bash test-gemini-dev.sh

# Tunnel 已启动后，只检查公网 HTTPS
bash test-gemini-dev.sh --public

# 同时检查本地和公网
bash test-gemini-dev.sh --both

# 使用自定义配置
bash test-gemini-dev.sh --both --config "$CONFIG"
~~~

脚本底层执行实际 curl 请求，复用现有 OAuth metadata、401 challenge 与 404 路由隔离检查；逐条输出 HTTP 状态和每个目标的 PASS/FAIL。不会读取或修改工作区文件，不发送 OAuth Client Secret、Token 或 Cookie，不跟随重定向，不关闭 TLS 证书验证，不修改 Tunnel ACL。公网探测遇到 Microsoft 登录或 HTML 提示页面时按失败处理。

退出码：0 为选定目标全部通过，1 为 HTTP/网络/安全检查失败，2 为配置或依赖错误。先通过本地检查，再启用受限公网访问并运行公网检查。所有检查通过也不代表 Gemini 的真实 OAuth 和读写已验收。

## 5. 连接 Gemini Web

打开 https://gemini.google.com/devmode ，Create new -> MCP Server URL 填写实际 PUBLIC_URL/mcp。Additional settings 中填写预注册的 Client ID/Secret。若 Google 分配的回调地址尚未登记，先确认真实地址后按原 Gemini 安装文档的 exact redirect_uris 方式配置并重启 Adapter。

在本地 CLI 检查 pending 请求，核对 client、回调、scope、Workspace 后审批：

~~~bash
.venv/bin/python -m gateway.gemini_adapter pending --config "$CONFIG"
.venv/bin/python -m gateway.gemini_adapter approve REQUEST_ID --config "$CONFIG"
~~~

回浏览器 Continue after local approval。写入需 Gateway 允许写、Gemini OAuth scope 授权和实际用户确认；先 dry_run=true 预览，更新现有文件需 file_sha256。首轮联调使用无敏感数据的临时目录；Git、Exec、Local Skill 不向 Gemini 暴露。

## 6. 真机验收及关闭

记录 Dev Tunnel CLI 版本、实际公网 origin、OAuth discovery、401 challenge、404 隔离、Gemini 授权和工具清单，再在同一个测试 Workspace 验证两个 Web 端的读写和陈旧 SHA 冲突。真实浏览器确认卡与断连后未知执行结果仍需验证；非幂等写入不能自动重试。

停止时 Ctrl-C 结束 Dev Tunnel host，并关闭 8766 Adapter；在本地撤销 Gemini Token：

~~~bash
.venv/bin/python -m gateway.gemini_adapter revoke-all --config "$CONFIG"
~~~

通过 devtunnel access list/delete（见 CLI --help）撤销该端口的匿名 ACE，或在确认此专用 Tunnel 不再需要时删除该 Tunnel。不要删除其他 Tunnel，不停止 8765/ChatGPT 连接。

参考：
- https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands
- https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/security
- https://developers.google.com/connected-apps/mcp/dev-mode/usage
- [Gemini OAuth 与文件操作说明](GEMINI_INTEGRATION.md)
