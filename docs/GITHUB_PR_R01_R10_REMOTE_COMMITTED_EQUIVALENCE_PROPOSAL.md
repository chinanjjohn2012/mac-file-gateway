# GitHub PR — R01/R10 远端已提交快照等效解释（待批准）

**版本：** GH-R01R10-REMOTE-1.0-PROPOSAL  
**状态：** PROPOSED / NOT_EFFECTIVE。此文本是可复用的补充解释草案，**尚未修改**《独立代码复审规则 V1.0》或《GitHub Review Handoff V1.0》的权威原文；必须由用户明确批准并同步 A/B/C 项目的权威规则来源后生效。不得用此草案追认任何既有 FULL PASS。  
**适用：** GitHub PR 中已提交、已推送、固定 SHA 的代码复审。Bitbucket 本地工作树、未提交修改、仅有聊天粘贴的代码及非 GitHub PR 场景不自动适用。  
**权威依据：** 《独立代码复审规则 V1.0》R01–R10；《GitHub Review Handoff V1.0》§2–§7。两者与此草案不一致时，**现行权威规则优先**。

## 1. 精确解释，不降低验收门槛

R01 固定 HEAD、工作树状态和 Manifest，且特别要求**对未提交代码**建立完整 Manifest / 等效文件哈希。对于 `GITHUB_COMMITTED_ONLY` 范围，受审对象是 GitHub 中指定 `HEAD_SHA` 指向的 Git Tree 和其完整文件集合，而不是开发者 Mac 的任意目录。可用远端 Tree、Blob、全量文件 SHA-256、完整 Diff 和隔离 CI 检出证明**该已提交快照**的代码身份与完整性；审查者必须明确注明 `DEVELOPER_LOCAL_WORKTREE: NOT_OBSERVED`。

这不是对本地未提交工作树的等效证明。不得写“本地无未提交修改”“已查本机隐藏目录”或“整个开发工作树完整”之类无法从 GitHub 得出的结论。

## 2. 快照模式及拒绝条件

| 模式 | 审查对象 | R01 所需证据 | 允许的表述 |
| --- | --- | --- | --- |
| `GITHUB_COMMITTED_ONLY` | 已推送 Git Commit Tree，明确排除未提交内容 | 第 3 节 G01–G08 全部核验 | “远端已提交快照完整性 PASS” |
| `LOCAL_WORKTREE` | 包括 staged、unstaged、untracked 或本地隐藏路径文件 | 本地分支/HEAD、真实工作树清单、Manifest/哈希、前后快照一致性 | 经直接本地证据核验后按实际范围声明 |
| `MIXED_OR_UNKNOWN` | 工作运行依赖未固定的本地文件、生成源码、外部子模块/制品或不完整 GitHub 对象 | 补齐全部外部代码/制品的可核验版本及完整性，否则 `REVIEW_INCOMPLETE` | 不得宣称整体完整代码通过 |

`GITHUB_COMMITTED_ONLY` 不允许把尚未推送的修复、未纳入受审 Tree 的测试、任意外部下载的源码或聊天中的代码算作已审内容。Git LFS、子模块、构建时生成/下载并参与行为的代码，须独立固定提交/对象和哈希，**只有指针文件并不够**。

## 3. G01–G08：GitHub R01 远端证据组合（全部必需）

**G01 — 身份和冻结。** 读取 GitHub API 当前 Repo、PR、Head/Base 分支及完整 SHA、任务编号、轮次、审查范围、状态；取得原生 Git Commit 的 Tree SHA。开始与结束时再次读取，确认 Head/Base/有效 Diff 未变。

**G02 — 实际全部源码。** 基于固定 Base...Head 获取未截断的完整文件增删/重命名/类型差异及必要 Blob；分页、大小上限或权限导致不能覆盖全部受审文件则标为不完整，不能靠 PR 标题、A 说明或仅 1 页 diff 替代。

**G03 — Git Tree/Blob 闭合。** Git Tree 完整树对象能够解析为受审源码；对比全量 Git 跟踪文件集合和所需内容哈希。仓库若维护 `MANIFEST.sha256`，独立校验路径唯一、排序、数量、文件 SHA-256 与实际内容一致，并显式说明 Manifest 自身不作自引用哈希；不得忽略追踪的高风险文件。

**G04 — 真实 CI 代码同一性。** 读取原始 Workflow Run、Job 和日志，记录触发事件、被检出 Commit、Tree、OS/架构、运行命令、退出码、PASS/FAIL/SKIP。若 PR Job 使用 GitHub 合成 Merge Commit，必须核对其两个真实 Parent（Base、Head）以及 Merge Tree 与受审 Head Tree 一致；仅 Run 关联 Head SHA 而不能证明实际检出代码时不得无条件复用。

**G05 — 隔离工作树。** 在真正运行测试的 GitHub 托管或受控一次性环境中，核验检出前的跟踪文件无差异、非预期未跟踪/忽略源码不能参与行为、构建/测试使用的生成源码和依赖可追踪。该“干净工作树”仅属于 CI 隔离工作区，不属于开发者本机。测试之后产生的预期制品须与代码身份核验分开记录。

**G06 — 运行环境与安全门禁。** 测试需要的架构/SDK/权限/隔离边界必须由原始日志直接证明；未授权的真实平台、Native C、进程组实验不得为了取得 R01/R10 PASS 而执行。Mock、Linux、macOS、真实 HTTP/Tunnel/生产依次明确区分。

**G07 — 两角色独立且绑定同一快照。** B 与 C 分别直接读取权威规则、源码/合同、原始证据；原生 GitHub Review 的 `commit_id` 以及正文 Base/Head/Tree/轮次/范围相同，且为本角色独立结论。只写 `REVIEW_COMPLETE` 或 `TARGETED_REVIEW_PASS` 不能转换为整个 `FULL_CODE_REVIEW_PASS`。

**G08 — 漂移和缺证拒绝。** Head、Base、Git Tree、实际 Diff、文件源身份或测试环境发生实质变化，都要确定影响并形成新的绑定证据和 Review；尤其 Base 前进后不能仅因 Head SHA 不变就沿用旧 PASS。任何必需证据缺失，输出 `REVIEW_INCOMPLETE` / `BLOCKED`，不得作乐观推断。

建议在 A 交接及 B/C Review 增补以下字段（**补充字段，不取代现有 GH_HANDOFF_V1 必需字段**）：

`EVIDENCE_MODE: GITHUB_COMMITTED_ONLY | LOCAL_WORKTREE | MIXED_OR_UNKNOWN`  
`REMOTE_SNAPSHOT_VERIFIED: YES | NO`  
`CI_CHECKOUT_TREE_VERIFIED: YES | NO | NOT_APPLICABLE_WITH_REASON`  
`DEVELOPER_LOCAL_WORKTREE: NOT_OBSERVED | DIRECTLY_VERIFIED`  
`EXTERNAL_SOURCE_OR_ARTIFACT_GAPS: NONE | <逐项列举>`  
`R01_GATE: PASS_REMOTE_COMMITTED_ONLY | INCOMPLETE | NOT_APPLICABLE`

## 4. R10 原样保留：角色级 PASS 仍不等于总体放行

满足 G01–G08 只能使 R01 **远端已提交快照证据**达到相应范围，不自动满足 R10。R10 仍逐项要求：

1. Standards 与 Spec 两份独立、当前快照的足够范围代码 Review；A 不代签。
2. 完整权威合同矩阵：新功能、既有合法成功、非法拒绝、边界、异常、失败、取消、恢复、并发、跨适用模式及相邻影响面；独立主动反例。
3. 真实协议/SDK/平台调用链与 Mock 结果分开；原始 CI 和 skipped/未运行项明确记录。
4. P0–P2 无未关闭阻断，且不存在妨碍完整代码验收的未覆盖风险。
5. 独立的 R10 汇总检查明确 `R10_STATUS: ELIGIBLE | BLOCKED | INCOMPLETE`。只有全部条件成立，才可以在**已提交代码范围**作完整代码验收判定；不得由 A 单人将 B/C 角色 PASS 改写为整体签收。

`INTEGRATION_STATUS` **独立判定**。真实生产升级、Tunnel、回滚、F3 正向 Exec 等未测项目仍是未测；R10 与任何 GitHub CI GREEN 均不自动产生 `INTEGRATION_PASS`、合并/部署授权。

## 5. 不适用、失败与防绕过

- PR 的审查目标实际依赖本机未提交文件，或 GitHub 只包含一部分实现 → 必须使用 `LOCAL_WORKTREE`/混合模式并核验真实源；不能“切模式”规避失败。
- CI 中执行的 Merge Tree 不等于受审 Head Tree，或外部制品未锁定 → 远端证据不完整。
- PR 只有固定 Head、Base 发生变化，或 rebase/squash/merge 产生新 Tree → 必须重新比较及评估必要的重审范围。
- 工作流自行打印“PASS”，但原始 Job、真实测试、SDK 路径或权限不支持结论 → 不成立。
- 用户 Mac、私有生产配置、Git 仓库外进程/文件、实际 Gateway/Tunnel 无直接证据 → 标为 NOT_TESTED，不得因 GitHub checkout 干净而宣布其已验收。
- 不通过下调 R03–R10、删除红色反例、隐藏 skipped、修改 B/C Review、强行清理 UNKNOWN 或未经授权的系统实验取得 PASS。

## 6. 批准、生效与历史 PR 过渡

1. 用户核对并明确**批准本文件中的 GITHUB_COMMITTED_ONLY 解释**。在此之前它只是一份草案。
2. 将已批准且带版本号的文本加入《独立代码复审规则 V1.0》的正式补充页，同时更新/引用《GitHub Review Handoff V1.0》，并同步三个独立 Project 的权威资料来源。不能只在 A 聊天中生效。
3. B/C 以后每轮实际读取该新版本，并独立记录采用的证据模式、未覆盖项、CI checkout 和 Tree；本地/Bitbucket 规则保持不变。
4. **既有 Review 不修改、不回溯重判。** 例如 PR #72 当前 B/C ROLE_FULL_SCOPE_PASS 仍只绑定 Head `ea7989800ba1f1e759739d5bf3a700c1691801a6`、Base `2f163eeb83fc2f984354dc6d231a614dca5aa9af`。若希望使用新解释关闭其 R01 缺口，应由 B/C 在同一未漂移快照下各自补充独立的证据确认，并另外检查完整 R10；A 不得自行追认整体 FULL PASS。
5. 本解释**不授权**任何 PR 合并、代码改写、发布、部署、用户 Gateway/Tunnel 操作或真实 Exec/F3。

**验收本规则本身的完成标志：** 用户批准确切版本 + 三 Project 权威资料同步 + 新轮次审查能够按 G01–G08 无歧义复现；只提交本草案 Draft PR 并不等于生效。
