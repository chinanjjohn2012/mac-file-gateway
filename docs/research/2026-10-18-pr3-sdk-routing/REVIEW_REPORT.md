# PR3 SDK 路由机制研究与独立探针报告

> 公开脱敏副本。以下结果来自原研究阶段；本次另行获准发布报告、草案和探针，不代表获准实施产品修复。原始日志与完整失败证据继续保存在私有证据包。
日期：2026-10-18 Asia/Shanghai
固定 Gateway 基线：b82a4755a7713c2584dbb538088e59e1214ff293
Tree：04db26fc8181d34cfa8f2e6b2e677d8c910e6b94

总体处置：维持 BLOCK，不关闭 PR3 或 Phase2 生产资格。
机制建议：CONDITIONAL，优先 A（SDK首次路由写入处采用类型保真、分域索引），保留原 wire ID；同时要有早期重复准入和每条异步清理路径的 owner 检查。seen-ID 不是路由修复的替代品。

1. 实际范围

原研究使用仓库外的隔离临时目录；本机绝对路径已从公开副本移除。
source/是b82a475固定Git快照，129文件及原Manifest未改。sdk-original/是已安装MCP1.30.0的111文件源码副本；sdk-candidate/仅改一个streamable_http.py用于可丢弃研究。已安装SDK、真实仓库及原有配置/索引/分支未被本次修改；原研究阶段未操作PR，也没有提交/推送/合并/部署/重启/安装依赖，也未启用Multi exec、Skill、业务脚本或数据库。
本轮探针使用真实FastMCP、SDK auth/session manager、HTTP transport、responder及合成工具；没有Gateway、WorkspaceService或同步子进程worker。HTTP通过ASGI调用，无网络监听。每轮SDK内部Popen计数0；外层只是本次启动并已结束的Python探针进程。
环境：Darwin 25.6.0 arm64；macOS26.6.2 Build25G83；Python3.14.7；MCP1.30.0、Starlette0.52.1、AnyIO4.15.1、httpx0.28.1、Uvicorn0.54.0。probe-command中的HOME/TMPDIR均为合成目录；认证仅为夹具自造身份，不读取真实凭据。
封装前PR只读查询head=553a221240ed5f1678c949c29fe150305fd95d28，已不同于固定基线；新Head未审。本研究始终固定b82a475，不跟随或混用外部更新。

2. 源码事实与设计边界

原SDK streamable_http.py:599–605 将ID字符串化并写_request_streams，609才送入server read stream；BaseSession._receive_loop:365–375稍后注册responder。router:1063/1076也字符串化，GET_STREAM_KEY在63行并与请求路由共用字典。
选择A：SDK路由层统一使用内部K(int71)=rpc:i:71、K(str71)=rpc:s:"71"；GET仍为独立控制域_GET_stream。wire消息、responder和cancel的ID不改。SDKmanager验证session/已提供credential owner后，先作typed ID终身查重与容量检查，再同步保留墓碑及首次路由，期间无await。
公开close_sse_stream(raw wire ID)与内部route-close分开。GET在首次异步响应前捕获entry；内层、外层异常、finally和router发送异常都只关闭/compare-remove自己的entry。只对内存流关闭屏蔽取消，不代表同步worker或进程清理已验收。
详见PR3_DESIGN_RESEARCH.md的A/B/C/D比较、标识域、准入/取消/retire合同和STOP。

3. 最终相同输入对照（15个case，不是pytest数量）

| 真实SDK ASGI case | 原SDK original-v3 | 临时候选 candidate-v4 |
| --- | --- | --- |
| integer_positive | PASS | PASS |
| string_positive | PASS | PASS |
| mixed_ID_response_and_cleanup | 目标断言失败 | PASS |
| mixed_cancel_integer | 目标断言失败 | PASS |
| mixed_cancel_string | 目标断言失败 | PASS |
| concurrent_duplicate_before_any_route_write | 目标断言失败 | PASS |
| completed_and_initialize_ID_reuse | 目标断言失败 | PASS |
| cross_session_same_ID_cancel_owned | PASS | PASS |
| GET_and_reserved_spelling_coexist | 目标断言失败 | PASS |
| late_GET_cleanup_cannot_delete_successor | 目标断言失败 | PASS |
| GET_outer_ASGI_send_exception_is_owned | 目标断言失败 | PASS |
| router_old_closed_send_cannot_remove_successor | 目标断言失败 | PASS |
| seen_cap_owner_and_session_retirement | NOT RUN: Unmodified SDK has no seen-ID policy/cap; candidate-only policy test | PASS |
| stateless_independent_same_ID_compat | PASS | PASS |
| legal_ID_domain_roundtrips | PASS | PASS |

原SDK：5项满足断言、9项目标断言失败、1项NOT RUN。命令退出0表示预期反例和正控均被观察到，不是原SDK安全PASS。
唯一NOT RUN原因：原SDK没有本研究的seen-ID策略/每会话cap，该项只对候选政策进行验证；不得把它算成原SDK通过。
最终临时候选：15/15满足机制断言、命令退出0，无skipped。SDK来源文件明确指向隔离副本，非原安装路径。

已复现：合法混合ID错投/丢失；整数取消的错误响应进入字符串请求通道；重复请求同时覆盖原route与responder；客户ID_GET_stream破坏独立GET通知；受控迟到GET cleanup删除后继；旧ASGI send异常清理和真实memory-stream send关闭错误均可删除后继。
取消目标区分：原SDKBaseSession对typed responder的选择本身没有在本轮被证明错取消另一个工具；失败来自响应/清理链。不得把响应错投扩大成跨凭据泄漏、未授权执行或错误PGID信号。
候选双向取消都要求目标实际收到cancel、另一工具不取消、各HTTP响应ID类型与内容正确；不是只验证202。重复负控要求route写入0、responder登记0、工具派发0，并要求原请求继续成功，因此不能靠禁用全部执行取得PASS。

4. 证据演进与非假阳性检查

v1重连清理夹具未确保旧cleanup真正执行，可能在取消中跳过；其代码/原始结果保留，但该case不作为资格证据。
v2增加shielded屏障和old_cleanup_actually_executed断言，原SDK该case失败、初始候选通过。此人为控制顺序不是所有自然断连均已通过。
双轴独立检查又发现初始候选遗漏外层GET异常和router await-send后的pop。先补真实ASGI异常/真实内存流关闭错误探针：candidate-v3为13满足、2失败，退出1；源码与日志全部保留。
随后仅修订临时候选的owner传递/比较，candidate-v4同样15输入全部通过。两条错误路径要求实际抛错/传播、后继entry身份保留、后继通知可达；不是仅检查异常被吞掉。原SDK同一最终脚本仍失败。
所有轮次的精确argv、环境、退出码、完整stdout/stderr和JSON在evidence/runs；源码版本对应关系及哈希见final-audit.json。没有删失败步骤、弱化断言或把修订后实验当作b82a475源码通过。

5. 可复跑材料（公开版）

入口及环境说明：README.md；设计：PR3_DESIGN_RESEARCH.md。
主探针 sdk_asgi_matrix.py、构建器 build_throwaway_candidate.py 和单轮运行器 run_matrix.py 保持原研究文件逐字节一致，没有删除触发步骤或弱化断言。
run_research.py 是公开封装：从调用解释器的 MCP1.30.0 安装位置复制源码到仓库外全新目录，核对全部111个源文件哈希，生成一次性候选，运行同一原版/候选矩阵，并要求原版9个反例和5个正控符合预期、候选15项通过且无夹具异常。
SDK_SOURCE_SHA256.json 固定原版111文件；patches/mcp-1.30.0-routing-prototype.patch 是完整单文件候选差异；SDK-LICENSE.txt 保留 MCP MIT 许可。无需把 SDK 全量源码或 Gateway 快照另行提交到仓库。
results/recorded-research-summary.json 是原研究最终矩阵的白名单脱敏摘要；新的发布复跑结果另外保留，不能冒充原始日志。
完整私有包继续保留原SDK/候选副本、历史源码与夹具、所有失败轮次、精确argv/环境/完整日志及旧审查原件。公开副本不包含这些原始文件，也没有覆盖它们。
这个diff不是可直接合并的生产修复：含_probe_*研究参数、未批准cap/409/429政策和未资格模式主动拒绝；不得直接应用到正在运行的SDK或Gateway。

6. 独立分轴复核

## Standards
初审未发现引入的编码标准缺陷，但指出两条既有SDK异步owner遗漏；见下方保留的独立复核摘要，完整初审在私有证据包。修订后复核确认两条已按设计覆盖，未发现当前研究差异的新actionable问题；完整复核在私有证据包。副审只读，未代替主审执行探针。

## Spec
初审P2指出同样的GET异常owner合同不完整；完整初审在私有证据包。新探针先失败再通过后，复核未发现当前限定方案的新actionable Spec问题；完整复核在私有证据包。不是把同一个风险按两轴重复计成新的生产漏洞。

7. 不关闭的门槛

本轮仅JSON POST response + 独立GET + EventStore=None + 单事件循环owner。SSE POST/EventStore/重放未测且候选主动拒绝；这些研究限制不能静默成为产品协议限制。未测试全部自然断连/任意故障调度、并发双GET压力、idle TTL、Python3.11/3.13、真实SDK客户端及Gateway listener。session退役只验证了显式DELETE/旧SID拒绝/新session复用ID。
夹具建立了合成认证身份并验证错误owner404，但没有把Gateway Boundary实际认证上下文接入此候选；正式实现必须保留强制Bearer/Host/Origin等入口边界，不能只信session header。cap1024（专门用例设3）及409/429均为研究值，需产品合同决定。
没有验证同步worker、Root FD/permit、PGID/WNOWAIT、SIGINT/SIGTERM、原子cwd、新执行器、真实客户迁移。既有D1/P1、D2/P2、R1未修复，Task2没有借本研究启动。原822 passed/8 skipped和mcp_verified=false属于历史基线CI，本轮未重跑CI/verify或宣称功能验收。

结论：支持将A作为待审批的SDK修复边界继续推进；需要明确SDK补丁/fork交付方式、正式错误/容量/session合同，再独立审查实际产品变更。PR3与Phase2生产资格维持BLOCK，Multi exec保持禁用。原资料和全部失败证据保留，产品源码实施、合并或部署仍未获授权；本次发布授权只覆盖研究材料。

哈希：原SDK文件bea279ba402b95c1bb3f3c2566db39c972ac76355b80719fb3b8fc356319b29f；早期候选7e92aaf5c1fe0ec1dffcedb28d2ac744254731efb8f5d11ff9fe8c8976670dfd；最终研究候选6b9fef82b68c070c6f66f9181ac91221832655c1abd80d3a7afe498ed5a5a3ef。

公开版来源说明：原报告仅移除本机路径、调整可复跑入口和私有证据引用，并明确发布授权与产品实施授权的边界。源码事实、原始15项结果、夹具缺口、失败轮次和未完成门槛保持原意。
