# PR3 SDK 路由机制研究草案

2026-10-18 Asia/Shanghai。基线 `b82a4755a7713c2584dbb538088e59e1214ff293`，tree `04db26fc8181d34cfa8f2e6b2e677d8c910e6b94`。

本文件是隔离 spike 的设计建议，不修改已冻结的仓库计划或规格，也不批准源码实施、依赖发布、合并、部署或 Multi exec。PR3 及 Phase2 功能资格保持 BLOCK。候选只存在于 `sdk-candidate/`；已安装 SDK 与 Gateway 保持原样。

## 问题与选择

原 MCP1.30.0 在 `streamable_http.py:599–605` 先以 `str(id)` 写 `_request_streams`，再于609行送入 server read stream，最后才到 `BaseSession._receive_loop` 的 responder 注册。响应与 related-message 路由也字符串化。单独 seen-ID 集合无法消除合法整数71与字符串"71"的别名，且 `_GET_stream` 与独立 GET 共用命名空间。

| 选择 | 修复边界与代价 | 本轮建议 |
| --- | --- | --- |
| A SDK 首次路由处建立类型保真、分域的索引 | 单一传输层统一分配/查找/关闭；保留原 wire ID，需控制 SDK 版本和源码变更 | 优先；本轮在真实SDK源码副本中验证 |
| B SDK适配层持有复合键并替代传输路由 | 须证明 factory/session/GET 扩展点完整；不能只是 handler 或 read-stream 包装 | 可选，不在本轮实现 |
| C 限制混合 ID | 收窄合法协议输入，影响客户兼容，未获批准 | 不采用 |
| D 上层 seen-ID 或事后响应检查 | 无法恢复被覆盖的通道，也不能防止错误清理 | 不采用 |

推荐 A 的逻辑修复边界。生产交付可考虑经审计的 SDK 发布或受控 fork，并固定代码版本/哈希；具体依赖交付方式尚未批准。本轮不修改 site-packages，不把原型复制进 Gateway，不采用运行时全局 monkeypatch 作为产品方案。

## 标识合同

保留三个域：外部 `wire_id: int | str`、内部请求路由键、内部 GET 路由键。会话实例是外围命名空间，不能跨会话共享 seen/route 状态。

试验编码：

```text
K(71)         = rpc:i:71
K("71")       = rpc:s:"71"
K("_GET_stream") = rpc:s:"_GET_stream"
GET control   = _GET_stream
```

整数取十进制；字符串使用带引号、ASCII转义的规范JSON编码。`type(x) is int/str`，不把 bool/float 当整数。两个前缀与 GET 控制域分开，因此不会因客户字符串模仿前缀而碰撞。wire JSON 从不重写；response.id、cancel.requestId 和 responder 保持客户原类型和值。

每个请求的首次 route 写入、response/related 路由、公开 `close_sse_stream(wire_id)` 与内部 route-close 都使用一致的边界转换。`close_standalone_sse_stream()` 明确关闭 GET 域，不能把它作为客户 ID 传给同一转换函数。内部存储键不公开为远程 job/cancel API。

## 准入、取消与生命周期

1. 此机制必须位于既有强制认证边界之后；Mcp-Session-Id 本身不是授权。由 SDK manager 验证 session 与已提供的 credential owner，由 transport 验证 Host/Origin/MIME/session/protocol 等。只有通过这些检查的客户到服务端 request 才进入 ledger。SDK可缺省的 user 不能被误当作强制认证；Gateway Boundary 的实际认证上下文如何接入仍需产品集成验证。
2. 同一 transport/会话的 typed seen-ID 终身保留。查重、检查容量、添加墓碑、首次 route 注册之间无 `await`，以该 transport 的单一事件循环为 owner。若未来跨线程/循环，必须重新设计同步，不能以 GIL 代替证明。
3. 并发/完成后的重复请求、包括 initialize 已使用的 ID，都在首次 route 写入及 responder/业务派发前拒绝。不能覆盖旧 entry，不通过业务工具返回伪成功。试验用 HTTP409 常量 JSON；生产错误合同仍须客户端兼容验收。
4. ledger 不处理 notification 或客户对服务端请求的 response。合法 cancellation 继续让原 SDK 根据 typed wire ID 定位 responder；两种 ID 的原始值、响应路径与清理路径一致。
5. cap 满时拒绝新 request，但继续允许取消/DELETE 等控制消息；不驱逐活会话墓碑。试验默认1024、专门用例设3，均不是已批准产品值。retire 后 SDK 不再承认该 session，才可清空历史；新session可合法复用旧数字ID。
6. GET 在首次异步响应前同步注册并捕获 entry；内层 sender、外层 ASGI 异常和 finally 都只能清理该 owner。router 在 `await send` 前捕获 entry，发送失败后也须 compare-remove。只屏蔽内存流关闭所需的取消窗口。GET 重连可能复用控制键，旧 GET cleanup 不得删除新 GET。这里的路由 owner 不是进程 PGID 身份锚点，不解除 Task1 门槛。

## 可执行验证范围

`sdk_asgi_matrix.py` 对原 SDK 副本与候选副本运行相同真实 SDK FastMCP→session manager→HTTP transport→responder→tool 路径。认证仅使用夹具自造 credential，由真实 SDK auth middleware/owner检查处理。没有网络监听、Gateway、WorkspaceService、子进程 worker、业务脚本或数据库。

矩阵覆盖整数/字符串正控、混合响应归属及 A 结束时 B 通道、双向取消、并发/完成后重复ID、跨session同ID、GET与客户`_GET_stream`、旧GET清理屏障、cap/owner/retire、新session与stateless兼容、合法ID域。观察 transport 写入、responder登记、工具派发、原entry身份及真实HTTP结果，不只检查 Popen=0。

原型明确只研究 **JSON POST response + 独立 GET，EventStore=None**，与当前 Gateway 的传输设置对应。SSE POST、EventStore/恢复/旧事件数据不是本轮通过范围；候选构造时对这些未资格模式受控拒绝，不能把这种研究限定静默带入产品。实际 Gateway 客户端、业务错误、取消到同步 worker 的衔接、真实 listener 仍是独立验收。

最终15个case的具体结果、首轮夹具观测缺口、两个异常路径先失败再修订的证据见 `REVIEW_REPORT.md`。显式DELETE退役已测；idle TTL、并发双GET准入压力、全部自然断连时序及未认证HTTP边界不属于本轮已验收项。

## STOP 与交接

候选矩阵结果只回答机制可行性。真实 SDK/adapter 不能保持完整合法 ID 域、认证/session顺序或路由 ownership，继续 STOP。采用替代 SDK 或增加模式，需要重新固定版本/哈希并验收。

生产实施前仍须批准 SDK 修复交付边界、精确的错误/容量/session合同，完成独立源码与真实客户端评审，再更新正式计划的 Task5/M10。cwd 替代、PGID/WNOWAIT、D1/D2/R1、真实取消/双信号/FD与permit、M01–M15全部未因此关闭。Task2 仍仅在独立授权后推进。
