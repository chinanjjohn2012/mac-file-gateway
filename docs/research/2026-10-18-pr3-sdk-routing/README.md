# PR3 SDK 路由机制：独立报告、草案与探针

这些文件供独立评审，不接入 Gateway，也不是可合并的 SDK 产品修复。机制建议为 **CONDITIONAL**；**PR3 和 Phase 2 功能资格保持 BLOCK**。Multi exec 与 Local Skill Bridge 不因本材料启用。

## 阅读顺序与固定版本

1. [原固定版本独立复审报告](BASELINE_REVIEW.md)：LC1/PR2 台账与 PR3/P2 的失败链、位置和最小修订。
2. [后续独立研究报告](REVIEW_REPORT.md)：原 SDK 反例、候选结果、失败证据演进和边界。
3. [机制设计草案](PR3_DESIGN_RESEARCH.md)：方案 A/B/C/D、typed ID、GET 域、准入与 owner 清理合同。
4. [完整实验补丁](patches/mcp-1.30.0-routing-prototype.patch) 与 [构建器](build_throwaway_candidate.py)。
5. [真实 SDK ASGI 矩阵](sdk_asgi_matrix.py)、[公开复跑入口](run_research.py)、[历史结果摘要](results/recorded-research-summary.json) 和 [发布前复跑摘要](results/publication-rerun-summary.json)。原始三用例反例脚本保留于 [history](history/sdk_typed_id_routing_probe.py)。

需要交给另一位评审者时，可同时提供本 PR 的固定 commit 和 [独立评审请求草案](REVIEW_REQUEST.md)。

| 标识 | 固定值与含义 |
| --- | --- |
| 原独立审查/研究的 Gateway 基线 | `b82a4755a7713c2584dbb538088e59e1214ff293` |
| 基线 tree | `04db26fc8181d34cfa8f2e6b2e677d8c910e6b94` |
| Phase 1 基线 | `e32cb5124bbd8b08a79c75b4940799e041dd1295` |
| 本研究材料分支的起点 | `553a221240ed5f1678c949c29fe150305fd95d28`，PR #5 设计分支的发布起点；不是本报告新审查通过的版本 |
| SDK | MCP `1.30.0`；[111 个源码/typing 文件的 SHA-256](SDK_SOURCE_SHA256.json) |
| 原版 `server/streamable_http.py` SHA-256 | `bea279ba402b95c1bb3f3c2566db39c972ac76355b80719fb3b8fc356319b29f` |
| 最终一次性候选文件 SHA-256 | `6b9fef82b68c070c6f66f9181ac91221832655c1abd80d3a7afe498ed5a5a3ef` |

本 PR 只新增研究材料并更新仓库文件清单。正式计划、规格、Gateway 源码、依赖和 CI 行为均不随此研究材料改变。原始报告、所有失败轮次和完整证据包继续私有保留，没有被公开副本覆盖。

## 已观察到什么

MCP 1.30.0 的 transport 在业务 responder 注册前使用 `str(id)` 写路由。合法整数 `71` 和字符串 `"71"` 会别名；客户 ID `"_GET_stream"` 还会与独立 GET 通道相撞。只增加业务层 seen-ID 集合不能修复这些碰撞。

候选在 SDK 源码副本内使用类型保真、分域路由键，保持 wire ID 原值/类型；在首次路由写入前拒绝重复，并让异步 cleanup 和发送失败路径只处理自己的 entry。它只研究 **JSON POST response + 独立 GET、EventStore=None、单事件循环 owner**。

最终相同的 15 个 ASGI case：原版 5 个正控满足、9 个目标安全断言不满足、1 个仅候选策略不适用；候选 15/15 满足。原版命令退出 0 表示预期反例已复现，不是安全 PASS。没有 Gateway listener、WorkspaceService、真实执行器或业务数据参与；SDK 内部 `Popen_attempts=0` 只是探针范围约束，不是 Controlled Exec 验收。

GET 清理的两条异常路径先在早期候选失败，再于最终候选通过。旧 GET cleanup、ASGI send 异常和 memory-stream 关闭错误用真实 SDK 加受控屏障验证；没有宣称所有自然断连或任意调度均通过。

## 在仓库外复跑

使用独立研究 venv；不要修改运行中的 Gateway venv，也不要向 site-packages 应用补丁。原研究环境为 macOS 26.6.2 / Darwin 25.6.0 arm64、Python 3.14.7；MCP 1.30.0、Starlette 0.52.1、AnyIO 4.15.1、httpx 0.28.1、Uvicorn 0.54.0。其他版本/平台的结果必须单独记录，不能继承原生 macOS 结论。

在仓库根目录执行下面的合成研究命令。整个研究目录和输出都创建于系统临时目录中，不启用 Gateway 或网络监听：

```bash
RESEARCH_TMP="$(mktemp -d)"
python3.14 -m venv "$RESEARCH_TMP/venv"
"$RESEARCH_TMP/venv/bin/python" -m pip install \
  'mcp==1.30.0' 'starlette==0.52.1' 'anyio==4.15.1' \
  'httpx==0.28.1' 'uvicorn==0.54.0'
"$RESEARCH_TMP/venv/bin/python" -B \
  docs/research/2026-10-18-pr3-sdk-routing/run_research.py \
  --output "$RESEARCH_TMP/run"
```

这些命令使用虚构认证身份、固定 ASGI 地址和内存工具，外层只启动本次 Python 探针进程。`run_research.py` 要求输出目录全新、位于任何 Git checkout 之外；从当前解释器的安装位置只读复制 SDK 并核对全部源文件。版本或哈希不符即 STOP，不自动修改依赖或降级断言。运行时清除调用者的凭据、代理、Gateway 环境变量和 Python hooks。

入口把原研究的三个 Python 文件逐字节复制到外部目录，再构建副本并按相同输入运行原版与候选。它额外检查完整预期结果集、无夹具异常、候选仅变更一个文件、补丁/hash 一致和原安装未变。导入失败、连接失败、全部拒绝或缺少正控都不能得到通过。

输出包含各阶段命令、退出码、完整日志和详细 JSON；这些文件可能含本机路径，应保持私有。只有白名单 `PUBLIC_SUMMARY.json` 是无路径摘要，分享前仍需检查。`results/` 中的公开 JSON 明确区分历史研究结果与本次发布复跑结果。

## 仍未验收的产品门槛

- SDK 修复的发行/fork/适配边界、正式错误码和 seen-ID 容量政策尚未批准；候选默认 1024、测试设 3、HTTP 409/429 都是研究参数。
- 候选主动拒绝 SSE POST 和 EventStore；不能把这些研究限制静默带入产品。重放、idle TTL、并发双 GET 压力、全部自然断连和客户端兼容仍未验收。
- 夹具只验证 SDK 的合成认证/session owner；实际 Gateway 强制认证上下文和 REST/MCP 接入尚未验证。
- actual cwd 原子交接、PGID/WNOWAIT 身份锚点、D1/P1、D2/P2、R1、同步 worker 取消、SIGINT/SIGTERM、FD/permit 与 M01–M15 仍是独立硬门槛。Task 2 没有在此开始。
- 真实 Gateway MCP/客户端、进程执行和完整 Phase 2 独立验收不能由此矩阵、Manifest 或普通 CI 替代。

## 公开材料与原证据的关系

`sdk_asgi_matrix.py`、`build_throwaway_candidate.py`、`run_matrix.py` 和实验 patch 均与原研究最终文件一致。新增的 `run_research.py` 只提供外部目录准备、来源检查和结果核对；不改变触发步骤。报告公开版仅脱敏本机路径、调整材料链接，并注明后续发布授权。SDK 全量副本、原始日志、私有证据 ZIP 和真实配置不进入仓库。

MCP 衍生补丁/片段遵循随附的 [MIT 许可](SDK-LICENSE.txt)。协议依据：[MCP 2025-11-25 基础消息合同](https://modelcontextprotocol.io/specification/2025-11-25/basic#requests)、[Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)。实现结论由固定 SDK 源码副本及实际 ASGI 结果支持，不依赖其他模型的结论。
