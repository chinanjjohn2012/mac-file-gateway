# Mac File Gateway Phase 2 — LC1 / PR2 定向实施计划复审

> b82a475 固定版本的历史独立报告（公开脱敏副本）。保留当时的已执行/源码推导边界；后续真实 GET、取消与候选机制实验见 [研究报告](REVIEW_REPORT.md)，不倒写历史结论。原日志与完整证据包保持私有。
日期：2026-10-18 Asia/Shanghai
固定版本：b82a4755a7713c2584dbb538088e59e1214ff293
总体结论：BLOCK。Standards 无新增问题；Spec 新增 PR3 / P2 一项。新增 P0=0、P1=0、P2=1、P3=0。

本稿已正确关闭 LC1 的“全部失败也可资格通过”计划漏洞，并补齐原 PR2 的同会话重复 ID／D5 重试语义。继续 BLOCK 的新原因是 MCP 1.30.0 更早的传输路由状态及合法 ID 的别名碰撞：pre-_in_flight seen-ID 守卫本身仍不足够。无需重写方案 A 或七任务架构，但需补充 SDK ingress 资格门槛和 M10。

1. 版本、环境与边界

New commit：b82a4755a7713c2584dbb538088e59e1214ff293
New tree：04db26fc8181d34cfa8f2e6b2e677d8c910e6b94
Old plan：4bae2fe0073a84cf46b58d57a23a2643f79196cb / tree 6d8df81605982dac934034f4d9e1665e0af39fdc
原冻结规格：a7a3f87772ad13545facff48620db68f12ac8ef3 / tree 32570eac352d1571481d8e9b4f42e3806392b495
Phase1 base：e32cb5124bbd8b08a79c75b4940799e041dd1295 / tree cbd826312cc83300e4a5e85f64c7746d8ac90e7f
实际采用新提交的规格 D5 澄清，与原冻结规格逐差异比较，没有静默混用。

隔离根：仓库外的临时目录（本机路径已脱敏）
source、old-source、frozen-source、baseline-source 为固定 Git blob 提取的四份隔离快照；独立 review.git 只作对象读取，不是运行 Gateway 的目录。
完整读取 old→new diff，逐段读取新计划、变动的 D5、相关旧合同，以及 MCP manager/transport/receive-loop 的完整相关函数，复核项目 MCP/HTTP 适配。源码文件、测试、Shell、依赖在新旧／冻结／基线共同路径逐 SHA 校验一致。仅计划、规格、Manifest 三文件变化，37 additions / 23 deletions。

四快照共513文件全部匹配 Git blob，原 Manifest 128/128/127/126 条均完整且哈希一致，没有重生成。old/frozen/base→new diff --check 均退出0。无适用 AGENTS/CLAUDE/CONTRIBUTING/CODING_STANDARDS/issue-tracker 文件；固定规格由用户直接提供，不依赖其它仓库 issue-tracker 或外部 setup。
实际环境：macOS26.6.2 Build25G83，Darwin25.6.0 arm64；Python3.14.7；MCP1.30.0、Starlette0.52.1、AnyIO4.15.1、Uvicorn0.54.0、httpx0.28.1、pytest9.1.1。解释器只读复用现有 .venv，未安装或改写依赖；实际导入 gateway.executor 为本次 source/gateway/executor.py。
2026-10-18 00:21:38+08:00 的只读核验：PR#5 OPEN/Draft，head=b82a475…，base=e32cb51…，与固定受审对象一致。

原研究阶段记录的真实仓库审前／后 HEAD 与 status 一致，未读取原有未跟踪文件。没有修改真实源码、配置、索引、分支或 PR，也没有提交、推送、合并、部署或重启。本机 checkout 状态细节仅保存在私有证据中。
前包 MFG_PHASE2_PLAN_REREVIEW_2026-10-18_4bae2fe.zip 的 SHA256 重新核对为1de7fdfe71662fbe46204281a06a22eae5b1d75b90db435ece1f622b4dfab2b6，原样保留；只复制经校验的旧报告／结果到 evidence/prior-evidence，并明确为历史证据。本轮没有重跑旧 cwd 和 ID-reuse 探针，未把历史实验写成本轮新执行。

2. 原发现关闭台账

| 项目 | 计划合同 | 机制／代码实际状态 | 位置 |
| ---- | -------- | ---------------- | ---- |
| LC1 / P2 | CLOSED：同候选正常成功 AND 竞态安全，不再只有 OR；always-failing 必须 FAIL | 旧 /dev/fd 候选在已测 macOS/Python 组合 FAIL；替代机制未获批、未资格 | 计划17/41/47–53/114–118/125/183 |
| 原 PR2 / P2 | 同会话整生命周期唯一 ID、登记前拒绝重复、历史不驱逐、D5 合法重试规则 CLOSED | seen-ID guard 未实现；更早 SDK 路由边界仍有新 PR3，故 IP3 不能功能关闭 | 计划57–63/139–144/188/192；规格196 |
| IP1 / IP4 / IP5 | 保持计划层面 CLOSED | 不等于代码或 M01–M15 实测通过 | 计划15/30/41/45/156/173–195 |
| D1 / P1、D2 / P2、R1 | 既有待实施安全修复要求保留 | 共享 CommandRunner 代码未变、未修复；不重复计为本轮新发现 | 计划18/92–103 |
| PGID / WNOWAIT | 资格门槛保留 | 未做原生资格证明；不准数字 PGID 无锚点信号 | 计划16–17/80–90/127–131 |

LC1 关闭的是资格判定的计划缺陷，不是“找到可运行 launcher”。原 PR2 关闭的是非法重复 ID 与迟到 wire cancel 的身份合同，不是“SDK ingress 已能保证所有合法请求的响应路由”。IP2/IP3 的实施阻断状态继续保留。

3. PR3 / P2 — SDK 首次传输状态写入与合法 ID 路由碰撞未纳入资格合同

位置：计划57/59/139/142–143行，及 M10第188行；相关已批准语义：规格D5第196行、合法 MCP 协议 ID 保真与 Legacy/file tools 兼容。
分类：本轮新识别的实施计划／SDK 资格缺口；根因是既有 MCP1.30.0 传输实现，非本提交新增生产漏洞。当前项目 gateway/mcp_multi.py:39、gateway/mcp_adapter.py:47 仍 stateless_http=True；没有实施计划中的 stateful Multi exec 路径。本轮未证明现有 Gateway 新越权。

固定实际 SDK 源码：
- mcp/server/streamable_http.py:599 将请求 ID 转成 str，602–605写 _request_streams；609才送入 server read stream。
- mcp/shared/session.py:365–375 稍后才创建 responder 并写 _in_flight，键保留原始类型。
- streamable_http.py:1063/1076 在 message_router 同样把响应／related ID 转成 str；404–416按该键清理。
- streamable_http.py:63 的 GET_STREAM_KEY="_GET_stream"；743–761使用同一 _request_streams 管理独立 GET 通道。
完整相关函数与文件哈希在私有证据 SDK-complete-functions.txt / audit-result.json；公开版另提供 SDK_SOURCE_SHA256.json。

失败链A（本轮真实 SDK 已复现）：
同一个有状态会话中，A 的整数 ID71 和 B 的字符串 ID"71" 都合法、未重复，保留类型的 seen-ID 集合会同时允许。SDK 却将两者变成同一个 "71" 路由键，B覆盖A的响应通道。A先完成时，其整数ID71／A结果进入B的HTTP响应；A等待不到自己的结果。这个问题即使 seen-ID 守卫放在整个传输层之前，单靠“重复ID拒绝”也不能解决，因为两个ID本来不同。

本轮合成 ASGI 结果：
| Case | 请求 ID | 实际观察 |
| ---- | ------- | -------- |
| integer-positive | 71、72 | 两个请求均取得自己的 ID 类型和结果 |
| string-positive | "71"、"72" | 两个请求均取得自己的 ID 类型和结果 |
| mixed-type-alias | 71、"71" | B得到整数71和A的served_label；A的HTTP waiter在夹具2秒上限取消 |
探针按事件屏障确保 A/B 都已开始，然后先释放A；不是靠偶然调度或一次未碰撞观察。两个工具最终都释放，SDK lifespan 正常退出。Popen=0、监听器=0、Gateway=0，只有合成标签，没有真实数据。没有实现或测试项目 seen-ID guard；typed_guard_would_admit_both 是类型保真键的显式对照。

失败链B（仅源码推导，本轮未执行带 guard 的该实验）：
一个在 read-stream/receive-loop 前放置的守卫满足文字上的“before _in_flight”，但完全重复请求早已在传输层替换 _request_streams；即使第二请求 dispatch=0，原 HTTP 通道也可受损。计划当前断言“原 responder 不变”没有覆盖更早的原响应通道。

失败链C（仅源码推导）：
合法字符串 ID"_GET_stream" 与 SDK 内部 GET 通道 sentinel 共用键；JSON response 模式仍有 GET handler。该值与活跃 GET 通道共存可能覆盖通道或使清理作用于另一通道。本轮没有运行真实 GET/SSE 共存实验，不把它标为已复现。

影响／评级：合法请求结果错投、ID类型不符及响应挂起；新引入 stateful 集成不能只凭数值 ID／pre-responder 守卫通过资格。不是已证明的跨凭据泄漏、未授权启动、FD丢失或错误 PGID 信号，评级 P2。取消与清理也必须在同一无碰撞身份模型下验证，但本轮混合ID探针未发送取消，不能称错取消已复现。

与现有 STOP 的关系：本稿正确要求 SDK hook 不可行即 STOP，但判据主要是 pre-responder、session correlation 和数值ID71/72。一个太晚的 hook，或一个虽早但只做 typed seen-ID 的 hook，仍可能通过这些指定用例；必须把具体的“首次 ID 索引状态写入前”及完整合法 ID 域路由加入资格，而不是把抽象 STOP 当作已验证。

最小计划修订（不要求本轮改代码或重写架构）：
1) 把 SDK feasibility 的准入边界推进到认证／有效 session 已确认之后、首次写入 ID 索引传输状态之前，至少早于 _request_streams 与 _in_flight。重复拒绝不能替换/关闭原 HTTP response stream、responder 或 ticket。
2) 明确在所选 SDK/adapter 下，请求、响应、related消息、取消与清理使用无碰撞的会话身份，并保持外部合法 ID 的值与类型。内部 GET sentinel 与客户 ID 必须隔离。若当前SDK或扩展机制做不到，STOP并回设计/owner审阅；不能静默 stringify 两种外部 ID、把合法混合 ID 当成重复、收窄支持类型或改依赖后继续宣称本固定机制通过。若选择新的协议限制或SDK适配，需要明确契约与客户兼容评审。
3) 把这些断言补入 Task5 Step2 和 M10，并在 Task3/4 请求身份定型之前完成隔离 SDK ingress 可行性证明。完整 Supervisor/native/live 集成证据仍在后续完成；不形成“先完整 Task4 才能研究 hook”的循环。

必须新增测试／预期：
- 并发71/"71"均成功，response.id精确保留类型且各自结果对应；整数、字符串正控同时保留，不能靠禁用全部派发让测试通过。
- 活跃GET与ID"_GET_stream"的POST共存，路由不互相覆盖；请求完成/取消清理不得关闭GET或另一个请求。
- 并发完全重复ID拒绝发生在首个transport写入前，重复的SDK registration=0/dispatch=0/Popen=0；原 response stream/responder身份不变，原请求仍正常完成。
- 同session的typed IDs取消精确作用于目标；旧内部回调、跨session同ID、会话终止、容量上限仍隔离；每次业务收尾回收permit/lease。
- 以上在真实固定SDK先做隔离正反控，再走真实Gateway MCP listener与必需客户端。若未运行、仅mock或任一合法ID路由失败，SDK qualification=FAIL，不能凭原数值用例放行。

阻断范围：阻断计划的 SDK ingress 资格合同冻结、Task3/4有关请求身份接口定型与Task5集成/暴露、最终功能合并；不阻断独立 Task2 修复、Task1 test-only PGID研究、Task3 静态配置与另行批准的隔离机制研究。

复跑命令（复制脚本到新的可写证据目录后，选择相同依赖解释器）：
<独立研究解释器> -B <全新仓库外副本>/sdk_typed_id_routing_probe.py
脚本会以exclusive创建结果JSON，不能在原证据目录重跑覆盖。准确argv、最小合成环境、退出码0见 evidence/probe-command.json，完整stdout/stderr各有独立文件。退出0表示“正控正常且反例复现”，不是 SDK/Phase2 功能PASS。

4. 七任务与最小依赖顺序

| Task | 本轮合同完整性 | 依赖与测试 | 允许边界（都仍需单独实施授权） |
| ---- | -------------- | ---------- | ---------------------------- |
| T1 PGID proof | 未改变，资格门槛清楚 | 最小test-only probe，无须完整T4 | 可独立研究；尚未native PASS |
| T2 shared safety | 未改变，D1/D2/R1矩阵保留 | 与PGID/cwd失败解耦，Legacy正控仍必需 | 可独立优先修复 |
| T3 config/admission/cwd | LC1合同已闭合 | 同机制成功正控前置；现无获批替代；身份定型还受PR3约束 | 静态部分可做，native handoff继续STOP |
| T4 Supervisor | 原owner/预算/lease合同保留 | T1 qualified+T2 reviewed+T3 cwd qualified；身份需SDK feasibility | 当前native接入STOP |
| T5 REST/MCP | 原PR2规则补齐，PR3仍缺 | hook须早于transport写入；补合法typed/sentinel域测试 | ingress研究可先行，集成/暴露STOP |
| T6 signals/retry | 未改变，D5澄清同步 | 真实双信号/worker收尾/0或1次尝试 | 仅前置合格后集成 |
| T7 evidence | M05前移、M10/M14同步 | 保留各自平台与mandatory skip阻断 | 不得用当前CI填作未来功能通过 |

最小顺序：T2优先独立；T1与T3静态/获批test-only机制研究并行；SDK ingress原型资格可作为T5的前置子步骤提前完成；T1+T2+T3 native与SDK请求身份资格合格之后再进入T4/T5生产耦合，然后T6、T7。没有要求把Task2等待在失败cwd/PGID之后，也没有授权启动实施。

5. 实际验证、CI与缺口

本轮实际执行：
- 拉取固定Git对象到新隔离裸库，提取四快照，513个blob/原Manifest/三组diff --check验证通过；原仓库head/status一致；前包SHA与CRC正确。
- 一次真实MCP1.30.0有状态ASGI三case探针：2个正控正常、1个合法混合ID反例成立。命令退出0；Popen被fixture禁止且计数0，不存在HTTP监听端口。
- 固定SDK相关完整函数和版本／文件哈希检查；项目MCP/HTTP相关调用链只读检查。
- GitHub PR/Actions只读核实及完整公开CI日志保存。

CI#39048314711：head=b82a475…，completed/success，Ubuntu24.04.5/Python3.13.16；822 passed、8 skipped；Manifest与语法步骤success；REST smoke real_http_listener=PASS、mcp_verified=false。该-q日志没有逐条skip原因，本轮未推测。以上是已有基线回归证据，不含未来Phase2执行器或stateful准入功能。

本轮未执行：完整本地pytest/verify.sh；新的原生cwd launcher资格；Task1 WNOWAIT/PGID；Gateway REST/MCP exec、真实取消/双信号/客户端迁移；_GET_stream动态共存；实际guard在晚hook的重复ID实验；业务DB/Skill/项目脚本。对后两条SDK失败链只给源码推导。旧cwd和非法重复ID结果来自前包，已核验保留但没有本轮重跑。

硬门槛保持：可用且获批的atomic cwd handoff；原生PGID唯一owner/信号排空再reap；D1/P1及D2/R1；真实取消与FD/permit收尾；SIGINT/SIGTERM；PR3无碰撞SDK ingress/响应/取消/清理；真实MCP与既有客户；M01–M15独立验收与Legacy/Phase1回归。一个机制或文档通过不代表代码实现、上线或任一后续动作获批。

6. 分轴独立报告

## Standards
独立生命周期副审：Standards PASS，生命周期计划质量 CONDITIONAL，新增发现0；认可LC1与原PR2合同补齐，保留native资格STOP。完整原文保存在私有证据 evidence/standards-agent.md。该副审未运行探针，未被主审的SDK反例结论引导。

## Spec
独立Spec/security副审：新增1项P2，SDK传输层键碰撞及前置边界须收紧；静态独立核对，未运行探针。完整报告保存在私有证据 evidence/spec-agent.md。主报告将该新问题编号PR3，与原PR2非法重复ID问题分开；不合并严重度、不重复计数。主审自行复现合法typed-ID反例并核实官方协议。

接受风险不变：可信本机用户/进程/项目代码、无OS沙箱、合法独立请求重试不去重、逃组后代边界、不可观察断连以timeout限制；不恢复UID/POSIX/ACL启动准入，也不启用Local Skill。

结论仍BLOCK：LC1和原PR2修订接受，新增PR3/P2须先补计划资格合同。所有证据只保存在被审快照外部；未改受审文件和原Manifest，未提交、推送、合并、部署或重启Gateway。本报告不授予实施或生产启用许可。

文件校验：
计划 SHA256 6495cede79e725cbfda7c2e60dbb3ed9f599de3302e4ccbf1b137d7fd4027e08
规格 SHA256 cc98c93c0fe226e63f8b8d31516b83e330a7ef6a9c5cc641fcd9c763bff4a3aa
计划总行数 199

公开复跑入口与来源说明见 [README](README.md)。原最小 typed-ID 探针逐字节保留为 [history/sdk_typed_id_routing_probe.py](history/sdk_typed_id_routing_probe.py)；先复制到全新仓库外目录再运行，结果采用 exclusive 创建。该历史探针不含 GET、取消或候选修复，不能替代后续完整矩阵。
