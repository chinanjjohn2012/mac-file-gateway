# Gemini Web 双端口接入实施计划（基于 release/ms1）

> 状态：设计/开发计划，尚未实施或通过真实 Gemini 联调  
> 日期：2026-11-12  
> 基线分支：release/ms1  
> 基线提交：c6b9b903ddbd3777374113d38b63127d2918986a  
> 工作分支：feature/gemini-dual-port  
> 原则：先审查和测试，后实现；不在 release/ms1 直接开发，不改变现有 ChatGPT 默认行为。

## 1. 确定的需求与非目标

### 1.1 目标

- mac-file-gateway **仍仅部署在用户 Mac 本地**，不迁移文件或 Gateway 到云服务器。
- 保留一个现有 Gateway 核心进程（127.0.0.1:8765）以及 OpenAI Secure MCP Tunnel。
- 新增**独立 Gemini Adapter 辅助进程**（127.0.0.1:8766），配独立 HTTPS Tunnel 和 OAuth 认证；8766 不是第二套文件 Gateway。
- ChatGPT Web 和 Gemini Web 同时连接、互不干扰；两者可同时读取同一工作区。
- Gemini 最终提供现有文件工具的**完整读写能力**：4 个基础读取工具、10 个受控文件/目录写入工具（单工作区；多工作区另含 list_workspaces）。读写始终受 Gateway 既有权限配置约束，默认无写权限；需要本地显式开启。
- 继续复用 Gateway 的相对路径限制、隐藏/敏感文件保护、SHA-256 版本校验、写入预览、写锁、原子写入和备份。
- Gemini 的 OAuth、身份、Workspace 和工具权限在 8766 独立执行；未经授权的请求在到达 8765 之前被拒绝。

### 1.2 本期非目标

- 不把 Gateway 从 127.0.0.1 改为 0.0.0.0；不直接在公网暴露 8765。
- 不修改现有 tunnel.sh 的默认行为，不要求 ChatGPT 使用 Gemini OAuth。
- 不把整个目标项目复制到 Google Drive 或其他云存储。
- 不在首期给 Gemini 开放 run_command、run_git、run_skill_script、Local Skill Bridge 或通用 REST 接口；它们需单独安全评审。
- 不将“Gemini UI 可能弹出的确认卡”视为唯一服务端授权机制。
- 不把仅通过 CI/Mock 的测试视为真实 Gemini 或真实 macOS 通过验收。

## 2. 基线事实与现有边界

- gateway/__main__.py：Legacy 默认 HTTP 端口 8765；Multi 由配置选端口；监听 127.0.0.1。
- gateway/mcp_transport.py：官方 MCP SDK 2.3.0，Streamable HTTP 路径 /mcp，stateless_http=True、json_response=True，含 Host/Origin/DNS rebinding 防护。
- gateway/http.py：Boundary 限制 Host、Origin、Sec-Fetch-Site、请求体和可选 GATEWAY_TOKEN；明确不是公网认证系统。
- gateway/mcp_adapter.py 与 gateway/mcp_multi.py：SDK 工具注册、严格参数校验、分离读写能力和 Workspace 参数；单工作区还可按需暴露 Exec/Git/Local Skill，但 Gemini 首期不得转发。
- gateway/write_storage.py、gateway/writer.py、gateway/file_ops.py：现有文件修改、锁、SHA-256 冲突和备份逻辑，计划不重写。
- gateway/sensitive_grants.py：本地操作员可授权特定敏感内容，远程 MCP/REST 不能签发此类授权；Gemini Adapter 必须保留该边界。
- tunnel.sh：现有 OpenAI 专属 Tunnel；与 Gemini 新 Tunnel 分开。
- tests/test_mcp_sdk_v2.py、tests/test_mcp_write.py、tests/test_phase1_multi_mcp.py、tests/smoke_mcp_live.py、tests/smoke_mcp_disconnect.py：作为协议、并发、写入和断连的回归基线。

注意：仓库存在历史设计文档及不同 PR 状态描述，规划依据以此处固定的 release/ms1 提交上的**实际代码**为准，运行环境是否已部署需另行验证。

## 3. 目标架构与数据流

ChatGPT Web -> OpenAI Secure MCP Tunnel -> 127.0.0.1:8765/mcp
Gemini Web -> 独立公网 HTTPS Tunnel -> 127.0.0.1:8766/mcp (OAuth 验证与工具授权)
                                                |
                                                | 可信本机 MCP 客户端
                                                v
                                      127.0.0.1:8765/mcp
                                                |
                                      既有 Gateway / Workspace / 本地文件

- 两个监听端口都只绑定 loopback；公网入口只对应 8766，公网无法访问 8765 的 REST/MCP。
- 8766 只把**通过 OAuth 和工具/Workspace 授权的 MCP 请求**转发至 8765；禁止未认证透明反向代理。
- 8766 到 8765 通过官方 MCP 客户端或经审查的规范内转发实现，内部请求生成正确的 localhost Host/Origin，不依赖公网 Host 绕过 8765 检查。
- 不把外部 Authorization Bearer、X-Forwarded-*、Cookie 或用户可控身份头原样传给 8765。
- 8765 现有 ChatGPT 私有 Tunnel 在未设置 GATEWAY_TOKEN 的部署中工作；**不得**为了 Gemini 在该共享端口强制新全局 Bearer Token。
- 8766 与 8765 处于同一 Mac，但属于不同进程。关闭 8766 或它的 Tunnel 不关闭 8765。
- 默认不开启 Gemini 公网入口；认证、路由和权限测试全部通过后再启用。
- Tunnel 只是网络通道，不提供等价于 OAuth 的身份认证。文件内容被读出后会传给 Gemini，不能宣称“数据从不离开 Mac”。

## 4. Gemini 端点与认证方案

### 4.1 对外 HTTPS 端点（均映射到本地 8766）

- /mcp：Streamable HTTP；所有受保护 MCP 调用强制 Bearer 鉴权。
- /.well-known/oauth-protected-resource：RFC 9728，发布受保护资源及 authorization_servers。
- /.well-known/oauth-authorization-server：OAuth Authorization Server Metadata（RFC 8414）；签发授权元数据。
- /oauth/authorize：Authorization Code + PKCE S256，用户登录/本机操作员批准。
- /oauth/token：授权码交换及 Refresh Token 流程。
- /oauth/revoke：断开连接、令牌撤销。
- /health：只在 loopback 上供运维检测；不得作为无鉴权公网诊断端点。

OAuth 需要兼容 Google Custom Apps 的配置方式。首期选择**静态预注册 Client ID / Secret（高级设置）**，避免不受控 DCR；只有官方实际接入证明必须使用 DCR 时才增设严格限制的注册端点。发现文档不得错误声明未实现的 registration_endpoint。

### 4.2 安全协议细节

- 未认证访问 /mcp 返回 401 和规范 WWW-Authenticate（指向 Protected Resource Metadata）。
- 严格校验 authorization code 的一次性、TTL、client_id、redirect_uri、PKCE S256、state/CSRF 绑定。
- OAuth redirect_uri 只允许经过注册、验证的 Google 回调 URI；不能仅检查一个宽泛域名后允许任意重定向。
- 通过本地 Mac 操作员的可信确认/配对流程签发授权；远程请求不能因知道 Tunnel URL 就自动取得权限。
- Access Token 校验主体、签发者、目标资源/audience、scope、有效期、撤销状态；无效和过期令牌必须拒绝。
- Refresh Token 方案先验证 Google 的持久连接要求，结合过期、撤销、丢失设备和密钥保护设计；不能发放无法撤销的长期无限期令牌。
- 秘钥保存在 Mac Keychain 或本机 0600 受保护配置中；日志、URL、错误信息、MCP 响应不得泄漏令牌、授权码、私有绝对路径或文件内容。
- 授权端点需考虑速率限制、爆破、拒绝服务、CSRF、响应缓存禁用和审计。令牌验证失败时 fail closed。
- 不信任外部 Origin、Host、X-Forwarded-For 等身份暗示；Tunnel 入口限定路由和方法，禁止直接向公网公布 8765 或 8766 的内部管理路由。
- 不主动添加开放的 CORS 通配规则；实际 Google 客户端要求以抓包/Developer Mode 实测为准。
- Google 账号先决条件（美国、18 岁以上、个人账号、Keep Activity、英文功能）由使用说明列出，不作为 Gateway 的身份证据。

## 5. 平台权限、工具映射与文件写入

### 5.1 作用域矩阵

- files:read：gateway_info、list_workspaces（Multi）、list_files、read_file、search_files。
- files:write：create_directory、create_file、write_file、replace_text、rename、move。
- files:delete：delete_file、remove_file、unlink、delete_directory。
- 作用域是 Gemini Token 权限与 Gateway 本地配置的**交集**；任何一侧拒绝都不得执行。
- 对 Multi，每个文件调用必须包含有效 workspace ID，且属于 OAuth 主体授权 Workspace 集合；不允许缺省 Workspace 或跨 Workspace 移动。
- /mcp 的 tools/list 只返回当前授权允许的工具；tools/call 即使绕过列表直接按名字请求，也必须再次校验权限和参数。
- 未列入首期白名单的任何工具，包括 run_git、run_command 和 Local Skill，默认拒绝且不可通过客户端参数开启。

### 5.2 完整读写目标与执行门禁

- Gemini 需要与 ChatGPT 达成**文件类功能对等**，只读仅用于 P1 的技术验证。
- 现有 Gateway 仍需要本地开启 --allow-write/Workspace write policy；Gemini 不得自行提升服务端权限。
- 写操作保持 dry_run=True 默认预览；真正 apply（dry_run=False）必须经过用户明确授权，验证 Gemini 确认流程，并由服务端执行对应 scope/工作区/路径/版本校验。预览本身不等于授权。
- 对删除及其他破坏性操作，验证确认语义；如 Gemini 无法可靠提供确认信号，增加本地一次性操作员确认机制后才允许正式 apply。
- 保持旧文件 file_sha256 约束与备份语义；不能因代理、网络重试或并发导致静默覆盖。
- 连接断开后的已启动操作结果可能未知，不得自动重试非幂等的 apply。
- Gemini 读取任何本地文件内容都意味着内容可能经 Google 云端处理；必须在用户说明中提示边界。

## 6. 任务拆分（每阶段必须达成验收门禁）

| 阶段 | 预计工作量 | 关键任务 | 产物与门禁 |
| --- | ---: | --- | --- |
| P0 基线冻结 | 1–2 人日 | 固定 ms1 SHA、清点 8765 工具和安全边界、跑 CI/macOS 回归、确认环境依赖 | baseline 验证记录；无 8765 行为变化 |
| P1 双端口 MCP 骨架 | 2–3 人日 | 新增 8766 可禁用服务；实现到 8765 的受控 MCP 客户端/工具转发；测试两代 MCP 协议 | 本地可发现和调用只读工具；未授权公网路径不可用 |
| P2 OAuth 与 Tunnel | 4–8 人日 | OAuth 发现、PKCE、静态客户端配置、Token/Refresh/撤销、本地批准、独立 Named Tunnel | 401/403、OAuth 正反例、安全联调通过；无认证访问绝不读文件 |
| P3 完整文件读写 | 3–5 人日 | 映射现有 10 个写入工具、tools/list 过滤与 tools/call 二次校验、Multi Workspace、确认/预览/冲突处理 | Gemini 可创建、修改、删除、移动，且越权与并发失败安全 |
| P4 双平台隔离 | 2–3 人日 | ChatGPT 原 Tunnel 回归、两条 Tunnel 并行、断连/重启/超时/请求限制及敏感授权边界 | 关闭一条连接不影响另一条；敏感内容不会越界 |
| P5 真机验收与发布 | 3–5 人日 | Mac 上运行、Gemini Developer Mode 真正连接、文档、CI、安全复审和回滚演练 | 真实双平台文件读写与发布清单签字 |

粗估 **15–26 人日**，不是承诺交付时间。OAuth 细节、Gemini 的实时协议行为和真实 macOS/Tunnel 环境是主要不确定项。任一阶段未过门禁不得直接扩权进入下一阶段。

## 7. 预期改动目录与约束

预期新建（具体命名在 P1 设计评审后锁定）：

- gateway/gemini_adapter/__init__.py
- gateway/gemini_adapter/__main__.py
- gateway/gemini_adapter/app.py：独立 8766 ASGI 入口与允许路由。
- gateway/gemini_adapter/oauth.py：OAuth 发现、授权、Token 及撤销。
- gateway/gemini_adapter/authorization.py：访问令牌、scope、Workspace、工具 allowlist。
- gateway/gemini_adapter/mcp_proxy.py：SDK MCP 上游连接与调用转发。
- gateway/gemini_adapter/config.py：私有连接配置与校验。
- tunnel-gemini.sh：Gemini Tunnel 健康检查、启动和关闭，不更改 tunnel.sh。
- tests/test_gemini_oauth.py、tests/test_gemini_mcp.py、tests/test_gemini_write.py、tests/test_dual_platform.py。
- docs/GEMINI_INTEGRATION.md：Mac 安装、用户配对、权限、断连和恢复。

原则上不修改 gateway/http.py、gateway/mcp_transport.py、gateway/core.py、gateway/writer.py、gateway/write_storage.py、gateway/file_ops.py。若发现必要改动，须提交最小范围设计说明、独立回归测试及回滚依据，不得为 Gemini 关闭 8765 Host/Origin/路径安全保护。

## 8. 测试矩阵

### 8.1 功能

- 8765 原服务单独运行正常；8766 独立启动/停止；两者同时在线。
- Gemini MCP 协议握手、工具发现、参数校验、SDK 2025-11-25 和 2026-07-28 兼容性。
- 单工作区与多工作区：list/search/read；create/replace/write/delete/move/rmdir；预览与真正 apply。
- 两平台同时读；相同文件并发修改；陈旧 file_sha256 冲突；丢失响应后的非幂等请求不自动重试。
- 网关重启时 Adapter 正确报告 503/不可用；Gemini Tunnel 重启不影响 ChatGPT；ChatGPT Tunnel 重启不影响 Gemini。

### 8.2 安全

- 未带令牌、错误 Token、过期 Token、撤销 Token、错误 audience/issuer、缺少 scope、越权 Workspace、直接 tools/call 绕过 tools/list。
- OAuth redirect_uri/PKCE/authorization code replay/CSRF/登录配对、Refresh 和撤销。
- 路由黑名单：公网 /read、/write、/git/run、/run、8765/mcp 均不可到达；不能借助代理访问 localhost 以外目标。
- Host、Origin、DNS rebinding、X-Forwarded-*/伪造身份、重复 JSON 字段、超大 body、恶意类型、文件路径越界、符号链接、秘密内容脱敏与本机敏感授权不会泄漏。
- Gemini 端不能发起 run_command、run_git、run_skill_script，即使 8765 已启用。
- 无公网无认证 PoC 连到真实项目；所有测试使用临时 fixture 或明确授权的测试 Workspace。

### 8.3 发布基线

- 在固定依赖的隔离开发环境执行 bash verify.sh --require-mcp、完整 pytest，以及真实 HTTP/stdio/断连 smoke tests。
- 保留原 ChatGPT Web 真机端到端读/写/预览流程的测试记录。
- Gemini Developer Mode 记录真实 OAuth、tools/list、tools/call、确认与文件写入证据；不把模拟工具输出当成云端认证成功。
- 代码审查、威胁建模、依赖安全、权限最小化、日志脱敏和 macOS 真机运行通过后才能准备发布。

## 9. 风险、待验证项及处理

1. **Gemini OAuth 发现与客户端注册的实际行为**：先按官方 RFC 9728 + RFC 8414 + Authorization Code/PKCE 实现；用真实 Gemini Developer Mode 验证，若要求 DCR 再独立评审，不能默认开放注册。
2. **Google 写操作确认不等于服务端批准**：进行真实 UI 行为验证，必要时加本机操作员一次性批准，不能仅根据 destructiveHint 自动允许 apply。
3. **现有 8765 不要求 Bearer 的兼容性**：不得为 Gemini 强迫修改原 tunnel.sh 或原 Gateway 的 GATEWAY_TOKEN；公网仅连接有独立 OAuth 门禁的 8766。
4. **SDK/代理兼容性**：优先复用 SDK，不手写不完整的 MCP 协议；保留初始化、错误、注解、结构化返回值的语义。差异需补协议测试。
5. **多工作区与权限**：8766 提供的服务端权限只能比 8765 更窄，不能更宽；启动时能力/配置不一致要 fail closed。
6. **高风险工具与连接中断**：首期不开放脚本、Git、Exec；未来另立评审，并采用明确的不自动重试策略。
7. **私有数据传输**：文件驻留 Mac，但工具结果通过公网传到 Gemini；避免把“本地部署”误写成“零数据出端”。
8. **发布安全**：不要为了排查错误临时开放 0.0.0.0 或无认证公开 /mcp；使用受保护开发环境与测试目录。

## 10. 开发节奏、分支与回滚

- 仅以此固定 ms1 SHA 为初始开发基线；有后续 ms1 变更时显式审查并选择性合并，不自动覆盖正在开发的 Adapter。
- 先交付本计划供审阅；计划确认后再按 P0→P5 分批开发和提交，每阶段提供代码 diff、测试证据和未解决问题。
- 现有 8765 和 tunnel.sh 为稳定兼容基线。Gemini 功能默认禁用。
- 回滚 Gemini 时先撤销 Token、停止 Gemini Tunnel、关闭 8766，**不停止 8765**；确认 ChatGPT 继续可用。
- 任何触及 8765 既有关键入口的改动都需单独发布门禁和回滚演练，不允许直接合并到 release/ms1。

## 11. 官方参考

- Gemini Custom Apps: https://support.google.com/gemini/answer/17209137
- Connected Apps MCP guide: https://developers.google.com/connected-apps/mcp
- OAuth guide: https://developers.google.com/connected-apps/mcp/oauth
- Gemini Developer Mode: https://developers.google.com/connected-apps/mcp/dev-mode
- Google registration troubleshooting: https://developers.google.com/connected-apps/gpc/troubleshooting
- Cloudflare Tunnel: https://developers.cloudflare.com/tunnel/get-started/
