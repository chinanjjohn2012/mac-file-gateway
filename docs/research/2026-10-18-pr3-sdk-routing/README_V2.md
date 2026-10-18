# PR3 SDK 路由机制：F1/F2/F3 隔离候选 v2（未获产品资格）

**本目录只用于独立复现与修订机制实验。当前 SDK 候选资格及 Phase 2 均保持 BLOCK。**

版本边界：历史原材料固定 `7a72acb86c404f1853e51b2d7addb344d4613d28`；独立评审识别 PR6-F1/F2/F3 三项 P2（详见私有证据包）。v2 在历史文件旁**新增**工具、探针和补丁；不修改原版 SDK、安装环境、既有探针、历史报告或历史矩阵及摘要。新的 Git SHA 需由发布后核实并锁定，不能使用旧提交作为 v2 证据。

## v2 对应的修订

- **PR6-F1 / typed related ID**：一次性 SDK 副本中的 `mcp/server/fastmcp/server.py` 四个内部 helper 传入原始 `request_context.request_id`；保留向外展示字符串的 `Context.request_id` 属性；`mcp/shared/session.py` 使用 `is not None`，区分 `0`、`""` 与缺失的 `None`。Transport 继续用 v1 的无碰撞内部路由键。
- **PR6-F2 / 派发前取消**：一次性 SDK 副本的 JSON POST 分支把**首次可中断的 `writer.send`** 放入 `try/finally`，按已捕获的 route entry 所有权清理，关闭两个 memory-stream 端点，保留 session-wide seen-ID 历史。内部 worker 和 OS FD/permit 仍未验收。
- **PR6-F3 / 失败证据**：`run_matrix_v2.py` 在启动 subprocess 前以独占方式创建 stdout/stderr 日志；无论超时、正常非零退出或启动失败，`command.json` 在 finally 保留 argv、时间、结果、超时标识、源码哈希。超时按失败（124）返回，启动失败按 125 返回；不会生成伪造的成功矩阵结果。

新增 `build_throwaway_candidate_v2.py` 必须作用于**完全匹配官方 MCP 1.30.0** 并已通过历史 `build_throwaway_candidate.py` 构建的临时 SDK 副本；生成的三文件 patch 必须与 `patches/mcp-1.30.0-routing-v2-prototype.patch` 逐字节一致。正式产品不得直接使用这些实验包。

## 复跑入口

在**仓库外的新建一次性 Python 虚拟环境**安装官方 MCP `1.30.0` 及真实依赖；不改动正在运行的 Gateway SDK。运行：

```bash
python -B docs/research/2026-10-18-pr3-sdk-routing/run_research_v2.py \
  --output /tmp/pr3-v2-private-evidence-new
python -m pytest docs/research/2026-10-18-pr3-sdk-routing/tests/test_runner_v2.py -q
```

`--output` 必须是尚不存在的路径，且不得位于 Git checkout 内。复跑脚本核对全部111份官方 SDK 源码、历史 v1 补丁与哈希、v2 三文件哈希与完整补丁、原15项矩阵及 F1/F2 的新增真实 FastMCP/ASGI 探针。原版矩阵须保留原有 5 项正控/9 项反例/1 项不适用的范围判定；v2 候选须保留原15项正反控并通过新增用例。任何脚本、来源、case 状态变化均 STOP。

运行后只有 `PUBLIC_V2_SUMMARY.json` 适合作为**经人工复核后的初步公开摘要**；`record-*`、`sdk-*`、`evidence/`、`provenance.json` 以及真实机器路径均为私有数据，不得提交公开 Git。`run_matrix_v2` 只应测试合成 SDK 负载；不得复用为远程通用命令执行器。

## 新增验证断言

- FastMCP `ctx.info` 与 `ctx.report_progress`：同会话 int `71` 和 str `"71"` 并发，A/B 的关联事件只进入其对应的内部 request stream，两个最终 HTTP 结果正确。旧 FastMCP `Context.request_id` 兼容行为不变。
- 底层 `send_log_message`: ID `71`、整数 `0`、空字符串 `""` 的路由保持类型和值；仅 `None` 允许作为 unsolicited GET。
- JSON POST 实际零缓冲背压下取消 ASGI 请求：被取消请求没有派发，route 删除且**两端 memory stream 关闭**，其他请求仍正常；seen-ID 不因 route cleanup 被删除。
- F3：stdout/stderr 已产生后超时、正常非零、启动失败都保存 `command.json` 与流日志；失败始终以非零结果交付。
- v1 的15项矩阵及合法 ID/GET、取消与 owner 清理等合同不退化。

## 证据及未关闭门槛

2026-10-18 在隔离 Linux x86_64/Python 3.13 环境曾得到原15例候选 15/15、新增 F1/F2 探针通过、F3 回归 3/3；**该次环境缺少官方 `httpx-sse` 与 `sse-starlette`，使用了临时测试导入/GET 适配。它不等价于官方完整依赖，更不构成 macOS native 机制资格或独立复审 PASS。** 这些适配文件不包含在此发布文件中。必须在独立 macOS arm64、Python 3.14.7、官方安装的 MCP/HTTPX SSE/sse-starlette 等完整依赖下重跑上述入口，固定版本与源码哈希。

仍未解决 SDK 正式交付方式、会话 ID/ledger 字节预算及生命周期、409/429 合同、SSE POST/EventStore、全部自然断连、实际客户端兼容、Gateway 认证/session-ticket 绑定、同步 worker 取消、FD/permit、SIGINT/SIGTERM、actual cwd 和 PGID 原生资格。D1/D2/R1 共享校验未因 SDK 实验改变。Task 2 可另行授权独立进行；没有授权 Multi exec/Local Skill Bridge 启用、合并或部署。
