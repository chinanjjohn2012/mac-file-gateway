# Mac File Gateway F1 — 发布、回滚与安全验收计划（设计稿）

**状态：** PLAN_ONLY / NO_GO / NOT_EXECUTED。仅作设计与审查，不允许执行 Merge、Release/Tag、Deploy、真实 Gateway/Tunnel 操作、生产配置修改、正向 Exec Apply、Native C/C3、未知 PID/PGID 信号或 UNKNOWN/quarantine 自动清理。任何真实环境操作必须另行授权。

**候选依据（核验日 2026-10-25）：**
- GitHub Draft PR #72（完整 F1 整栈），目标 `release/ms1` Base `2f163eeb83fc2f984354dc6d231a614dca5aa9af`，Head `ea7989800ba1f1e759739d5bf3a700c1691801a6`，Tree `c45a94a0c288b491bb5c44082f6aab88dfb42bf6`；72 commits / 48 paths，未合并。
- 原生两角色独立 Review：PR #72 Standards 与 Spec r001、`FULL`、各 `ROLE_FULL_SCOPE_PASS`、P0–P2=0，`INTEGRATION_STATUS: NOT_TESTED`；它们不是发布审批。
- Linux Actions #40160131270：`1472 passed, 8 skipped, 1 warning`；GitHub-hosted macOS ARM64 Actions #40160131466：两组 `4 passed + 46 passed`，各 1 warning。证据仅覆盖相应快照及隔离测试。
- 运行时、README、`BUILD_INFO.json` 仍使用 `2.5.0` 字样；这不是新的 F1 发布版本决策。
- 权威合同：`docs/MULTI_WORKSPACE_EXEC_RECOVERY_D0_DESIGN.md` 的 F1 §0、`docs/MULTI_WORKSPACE_EXEC_PRODUCTION_FIRST_IMPLEMENTATION_PLAN.md`、`docs/MULTI_WORKSPACE_EXEC_F1_RELEASE_CANDIDATE.md`，以 PR #72 固定 Head 为准。
- 此计划与《GitHub PR R01/R10 远端已提交快照等效解释（待批准）》相互独立；后者批准前不得当作生效门禁。

## 1. 发布边界与明确非目标

**本次只考虑 F1 deny-only，不发布真实命令执行能力。**

- Multi 的 `server.exec.enabled` 与 Workspace `exec.enabled` 均默认 `false`；明确双重授权只允许校验过的 `dry_run=true` Preview。
- `dry_run=false` 必须在 Exec Runner/Popen 和任何临时 PREPARED 之前拒绝：健康无证明 → `exec_cleanup_proof_required`（REST 503、MCP 稳定结构化错误）；已隔离 → `exec_quarantined`；不可用 → `exec_state_unavailable`；未授权 → `exec_disabled`。
- 独立的 File Write、Git CLI 只能在各自权限授予情况下执行；不得因 Exec 隔离而误禁合法 Git/File，也不得把 Git 权限反向借给 Exec。
- 不提供 F3 全后代清理证明；不运行旧 macOS 正向 Exec/进程组测试；不启用 Private Bridge / test-only grant；不把 Mac/Tunnel 生产验收当作 GitHub Runner 结果。
- 没有独立版本号、安装包、部署对象、用户环境变更、合并策略授权之前，不得声称 F1 已发布。

## 2. 逐关门禁（任何一项失败 = NO_GO）

| Gate | 验收条件 | 当前状态与关闭责任 |
| --- | --- | --- |
| GOV-01 — R01/R10 | 已批准版本的 GitHub 远端等效解释已同步 A/B/C；现有 PR 的 R01 证据缺口须独立处理，R10 条件逐项成立 | **PENDING**；用户批准规范 + B/C 各自必要补充验证，不改原 Review |
| SRC-01 — 最终源码 | 固定 Base/Head/Tree、完整 Diff 和 Blob、207 个跟踪文件 Manifest；任何版本、发布文档或安全代码改动形成新快照并按影响重审 | PR #72 当前 72 commits/48 paths 有角色级双 PASS；**最终发布快照仍待确定** |
| CI-01 — 正反例 | 最终 SHA 的 Linux 及 macOS ARM64 实测、原始 Job/log、合法 Preview/Git/File 成功、非法 Exec/越权拒绝、OWNER/UNKNOWN 并发/恢复、SKIP 处理记录 | 既有 GitHub 限定范围验证通过；不是生产升级/回滚 |
| SEC-01 — 测试专用模块 | 独立核对测试专用 Grant/Private Listener 对普通 REST/MCP/CLI/配置/动态导入均不可达；不得只依靠静态文本扫描 | **待形成可审安全证据**；不自动启用或删除历史模块 |
| SEC-02 — 持久状态与排他锁 | 同一私有 `exec-state` 状态根及 `owner.lock` 排他所有权；未知/损坏记录必须 fail closed，不能删除或清零以获得启动 | 生产升级/降级兼容尚未验证 |
| OPS-01 — 版本与制品 | 用户选定新版本号、制品 SHA-256、安装/配置路径、依赖版本、运行入口、环境权限、保留回退制品 | **PENDING**；不能把 2.5.0 文本当作新发布批准 |
| OPS-02 — 可逆性 | 在**另行授权的可丢弃环境**完成升级→异常→回退演练：Git/File、隔离状态、排他锁均满足第 4/5 节，不使用真实 Exec Apply | **NOT_TESTED** |
| OPS-03 — 审批与授权 | 维护者明确选择最终合并策略、运行环境、批准人、停机窗口、回滚责任人及 RTO/RPO；⟂ 不把 GitHub mergeable=true 当成审批 | **PENDING**；当前 release/ms1 未观察到分支保护 |
| E2E-01 — 真实环境 | 如目标交付包括用户 Mac/Tunnel，需获单独授权并验收真实安装/连接/权限/恢复；未授权时不能列为已测试 | **NOT_TESTED** |
| FINAL-01 — 放行决策 | R01/R10、代码 B/C、隔离+必要环境验收、运营/回滚演练全部达到**所批准发布范围**，且用户明确授权合并/发布 | **NO_GO**；本计划不执行任何动作 |

符号说明：表中的 “当前状态” 是按固定 PR #72 已读证据形成的**设计判断**，不是新 CI、生产 E2E 或独立 B/C 结论。

## 3. 发布前准备：只列操作，不在本轮执行

**P0 — 定义制品与责任人。** 确认正式版本号（待用户选择，不预填 2.5.1/2.6.0）、打包产物来源与 SHA-256、发布目标主机、功能 Flag 原值、合法 File/Git 范围、Runtime/SDK 版本、停机窗口、升级人和回滚人。整理允许执行的精确命令清单，单独批准；计划文本不是执行授权。

**P1 — 固定候选与审批。** 重新读取 `release/ms1`、PR #72 和任何候选 Head/Base/Tree、全部合并前 Diff、B/C SHA-bound Review 与原始 CI。若使用 squash/rebase/merge 导致有效 Tree/Base/依赖改变，重新核对及必要重新复审。没有分支保护时，应有明确人工双人门禁与禁止直接推送/force-push 的运营承诺。

**P2 — 可丢弃 staging 预检（须另行授权）。** 在隔离 macOS ARM64 环境运行安装、配置解析、预览、拒绝、Git/File 两向权限、owner-lock 争用、UNKNOWN/损坏记录冷启动、取消/断连、服务关闭等待和回退试验。只能使用可丢弃 Workspace、Git repo 和私有状态根；**不运行正向 Exec Apply，不尝试 Native C 或未知 PID/PGID 信号**。保存每一项原始日志和受审二进制/配置哈希。

**P3 — 生产执行审查（须再次授权）。** 仅在用户批准部署目标/窗口/权限后，按已验收 Runbook 进行；当前不执行。

## 4. 关键状态兼容与数据保护合同

从源码读取的已知边界：

- Multi 配置的 `schema_version=1`，server/Workspace Exec 默认关闭，且只有双开关允许暴露受控 Preview；老版本未必认识全部新字段。**不能在未经验证的旧版本中沿用新配置并推断安全。**
- `WorkspaceService` 在网络接收请求之前创建 `ExecStateStore`（配置根下 `exec-state`），持有 FD-pinned 私有状态目录和 `owner.lock`；锁需具备正确所有者、权限和排他 `flock`，直到服务关闭。
- `ExecStateStore` 的记录 `schema_version=1`；未完成 `PREPARED/RUNNING/UNKNOWN`、外来临时记录、坏记录和残留 Group-only RETIRED 均须保守隔离（依实现的严格启动扫描）；任何状态错误不能退化成内存默认健康。
- 独立 `git-state` 包含 discovery/运行中/隔离持久状态；Git 有独立命令/仓库授权、进程及恢复边界，不能仅靠 File API 状态判断。
- File Write 还涉及现有备份数据、原始文件和敏感内容策略；升级/回退不得覆盖用户文件或清理审计证据。
- **owner.lock 不是普通可以随意复制覆盖的文件。** 运行时复制/替换它会改变 inode/排他锁语义；离线快照必须保留权限与取证记录，不能把复制后的锁看作等价锁。安全的恢复步骤需要在隔离环境验证。

**状态不确定时默认动作是停止 Exec（以及有必要时停止整个 Gateway），保留持久记录与现场，等待受权离线调查；不自动重试、清理、解封或重新申请所有权。**

## 5. 拟议升级与回滚 Runbook（仅作将来授权用）

| 序号 | 未来受权操作者应做什么 | 通过条件与禁止 |
| --- | --- | --- |
| S0 | 记录当前版本、二进制/代码树、配置源、私有状态根、Workspace 根、Git 仓库与权限、进程/监听/Tunnel 清单 | 不得采集并公开私钥/API Key 内容；有未知活跃 Exec/Git 或 owner-lock 争用即停止 |
| S1 | 暂停外部入站及新写入；在明确审批的维护窗口内停止当前 Gateway/相关连接，等待实际同步 Worker 和 Git cleanup 完成 | 不能只凭 HTTP 断连认定子进程已退出；不发未经授权的 PID/PGID 信号；不能同时启两个实例 |
| S2 | **在进程已停止、锁所有权已核对后**，由授权管理员制作只读、受保护的配置/`exec-state`/`git-state`/用户文件及备份目录一致性快照，记录文件元数据/哈希/可恢复性 | 保留全部 UNKNOWN/PREPARED/损坏原始证据；不得删除状态记录、替换活动 `owner.lock` 或将状态根拷到同时运行的实例 |
| S3 | 验证新制品与签收快照/签名/哈希相符，安全替换可执行代码，保留最小权限及原配置；只启动一个实例 | 新版本必须默认 deny-only，拒绝 `dry_run=false` 前不得发起 Exec Popen 或产生 PREPARED |
| S4 | 在**已批准测试范围**进行只读健康/状态检查、合法 Preview、非法 Exec 拒绝、授权及越权 File/Git、UNKNOWN/不可用优先级；核对日志、错误码、配置显示和新实例锁排他性 | 仅在明示授权的可丢弃目标进行实际 File/Git apply；生产不自动进行破坏性探针或用户 Tunnel 测试 |
| S5 | 若升级异常，保持停止入站、记录取证快照，选择经预先验收的回退制品；先证明它对持久 Exec/Git 状态与双开关合同的兼容性，**逐项清点 Legacy `--allow-exec`、`--local-skill-root` / `run_skill_script`、独立 Git CLI 的执行入口与授权** | 旧版忽略 `exec-state` 或不能保证 deny-only 时，不得仅因关闭 `--allow-exec` 就视为没有子进程执行入口：`--local-skill-root` 可以独立注册允许执行脚本的 `run_skill_script`；必须证明无意外可执行入口、合法保留的独立 Skill/Git 能力仅限明确批准范围，并在可丢弃环境完成负向/正向验证。任何未知/意外入口或状态不兼容 → NO_GO、保持维护/停机，不能“盲回滚” |
| S6 | 在经批准的离线环境恢复旧制品/兼容配置，保留新版本留下的状态/锁原始证据，不自动恢复/清除 Quarantine；单实例重启并按负向合同验收 | 不做自动降级状态格式、自动 unquarantine、重新发送 commit/pull/push 或启动 Exec；任意状态不明 → NO_GO |
| S7 | 将最终结果记入变更记录：源码 SHA、二进制哈希、状态哈希、入站恢复、验收结论、用户授权、回滚时机及未覆盖项 | 未得到独立运营批准，不允许标记“发布/回滚完成” |

**回退决策分叉：**
- A：旧制品已在可丢弃环境证明能拒绝 Exec，兼容或安全隔离新持久状态、Git/File 范围正确、排他锁完好 → 才能在另行批准的运维计划中执行。
- B：旧制品不会读取新状态，或存在丢失/覆盖 `owner.lock`、UNKNOWN、Git 状态和工作区数据的风险 → **禁止自动回退**，保持服务停机/隔离，按离线事故恢复程序处理。

README 里“停止 Multi listener 并启动旧 Legacy 命令”的一般性提示**不足以证明本次 F1 持久状态回滚安全**。旧 Legacy Exec 若在其独立授权下可能正向执行，则回退时必须确保不会无意恢复 Exec grants；**Legacy Local Skill Bridge 的 `--local-skill-root` / `run_skill_script` 有独立执行授权，不随 `--allow-exec=false` 自动失效**，回退前还必须审计并明确允许或拒绝该入口及相邻 Git CLI 能力。

## 6. 必须签收的测试矩阵（先设计，未来单独批准执行）

| ID | 合法成功/正向 | 非法拒绝/反向 | 环境与证据要求 |
| --- | --- | --- | --- |
| T01 快照 | 固定制品、配置、Manifest/Tree 一致 | 任意 Head/Base/Tree/制品哈希漂移直接阻断 | GitHub 原始 CI + staging 制品证据 |
| T02 Exec Preview | 双开关授权 + 健康状态返回合法 `dry_run=true` 预览 | 无证明 `dry_run=false` REST 503 / MCP 结构化错误，无 Runner/PREPARED | 真 127.0.0.1 REST/MCP SDK + 私有状态见证 |
| T03 错误优先级 | 正常只读 File/status 可用 | `exec_disabled`、`exec_quarantined`、`exec_state_unavailable` 区分正确，不泄露敏感细节 | 隔离可丢弃状态目录、真实协议入口 |
| T04 File/Git 隔离 | 同服务授权 File Write 与真实 Git `dry_run=false` 在 Exec 拒绝/UNKNOWN 下成功 | 越权 File/Git 和 Exec 复用权限必须拒绝 | 真实可丢弃 Git repo + File API；禁止真实远端 Push |
| T05 启动/锁 | 健康私有 owner-lock 单实例持有，正常关闭后独占可复用 | 双实例争用、unsafe symlink/path、坏权限/损坏记录 fail closed | 真实私有 FS；禁止在用户主机未知进程上做强制信号 |
| T06 恢复/重启 | 健康状态正常重启，合法 Preview 与 File/Git 保持 | `PREPARED/UNKNOWN`、中断临时文件、损坏 JSON、锁不可用不得变为健康 Exec | 可丢弃目录 + 原始状态哈希；不清理 UNKNOWN |
| T07 取消/耗时 | 允许的同步 Preview 正常完成，服务关闭等待租约结束 | 断连/取消不得提前释放租约或重试非幂等 Git/Exec | 真实 SDK/REST + 必要的离线并发反例 |
| T08 升级回退 | 经过批准的新版→旧版隔离演练可恢复健康 File/Git/状态与单实例 | 旧版不认识新状态或曾隔离时不得恢复实际 Exec、清空证据或双进程共持锁 | 未来另行授权的 disposable macOS 升降级演练 |
| T09 配置/兼容 | 显式 File/Git scope、默认关闭状态，以及经**独立授权**保留的 Legacy Local Skill 脚本范围保持一致 | 除缺失/非法权限、旧版不认识字段或版本不匹配外，重点验证关闭 `--allow-exec` 时 `--local-skill-root` 是否仍注册 `run_skill_script` 并可启动子进程；未经批准的脚本/Exec/Git 入口必须拒绝，不能把合法授权的独立能力误判成 Exec 证明 | 未来另行批准的可丢弃旧版本配置/真实 CLI/HTTP/MCP 反例；不连用户平台、不执行未知本机子进程 |
| T10 真机/Tunnel | 仅在将来**另行授权**后按真实连接合同进行 | 重连不产生重放/权限扩大；无权限则不执行 | 用户 Mac/Tunnel；当前 `NOT_TESTED` |

**风险分级执行：** 优先复用 PR #72 精确 SHA 的 GitHub Actions 证据；仅在代码、Base、关键依赖、原生平台或危险边界改变时补充有必要的新测试。涉及子进程信号、真实用户数据、生产迁移/回退的实验**不能**因 R01/R10 或 B/C 复审需要而扩大授权。

## 7. 回滚停止条件、职责与文档包

**立即停止/NO_GO：** 启动时既有 UNKNOWN 被清除或被视为健康；Exec Apply 正向执行；任何非预期 Exec Popen/PREPARED；双实例并存；私有状态/所有权锁无法可信复核；文件/仓库改动超范围；回退会失去状态兼容性；敏感内容或凭证泄露；原始 CI/验收快照不匹配；未授权真实平台操作。

**角色：**
- A：拟订与实施受权范围内的方案、复核原始证据、编写只读候选交接和修复；不代签 B/C。
- B：独立 Standards 检查完整性、运行时边界、准入与回滚安全合同。
- C：独立 Spec 检查 F1 deny-only、合法能力与恢复规格。
- 用户/授权运营人员：批准版本、变更/停机窗口、RTO/RPO、生产目标、真正执行人、回滚决策与合并/部署授权。

**发布证据包最低清单：** 版本/包哈希、Source Head/Base/Tree/Manifest、B/C 绑定审查、CI Run/Job/Log、SKIP/风险清单、签收矩阵、私有状态保留与回滚演练报告、运行配置和受影响 Workspace 边界摘要（不包含机密）、运营许可和部署/回滚记录。

**目前缺失：** 明确版本号、变更窗口/RTO/RPO、真实目标、旧版状态格式兼容性独立证据、可丢弃完整升级/回退演练、真实用户 Mac/Tunnel E2E（如纳入发布范围）、最终用户合并/部署批准。当前结论**NO_GO**。

## 8. 本计划与 PR #72 的关系

此计划使用 PR #72 的既有 SHA-bound 证据作为**输入**，不会修改 PR #72 或 B/C 已提交 Review；该计划本身尚未进行独立 B/C 设计复审和任何升级/回退操作。若本计划进入真实发布流程，必须先固定新的发行候选及适用规范版本，再重新完成必要的代码、运维和真实环境审查。任何 GitHub 文档 PR 的通过都不是 Merge 或 Release 授权。
