# GitHub Review Handoff V2.0 — A/B/C PR 状态机

`PROTOCOL_ID: GHRH-2.0`  

## 1. 职责、事实来源和短命令

- A / DEVELOPER：授权范围内开发、测试、提交与 PR 交接；读取 B/C 结果、统一修复和进度协调；不得代替签收。
- B / STANDARDS_REVIEWER：独立 Standards 审查、只读源码与合同、发布自己的 SHA 绑定 COMMENT Review；不得读取/继承 C 的 Review。
- C / SPEC_REVIEWER：独立 Spec 逐合同审查、发布自己的 SHA 绑定 COMMENT Review；不得读取/继承 B 的 Review。
- 三聊天共用同一通用核心规则、同一版本 GitHub Handoff 和证据适配；各角色只需本角色职责文件，公共规则统一维护且版本一致。
- GitHub PR 是**动态交接唯一权威来源**。资料空间/Project 来源只保存静态规则。没有自动唤醒三个聊天，也不能凭消息缺失推断对方正在执行。
- A `下一步`：只读检查指定 PR 的代码/Head/Base、原始证据、A 交接及双 Review，输出下一角色；绝不开发。
- A `继续开发`：先审查最新角色结论、冻结及安全门禁后按授权开发/修复/提交/发布新交接。
- B/C `继续`：针对明确定义的当前 PR 和同一轮次独立审查与发 Review。

## 2. 确定任务与快照

一个审查轮次必须声明：
~~~text
REPO: owner/repo
PR: #N
TASK_ID: <本任务>
REVIEW_ROUND: rNNN
REVIEW_TARGET: <明确代码/合同目标>
CONTRACT_SCOPE: <权威合同范围>
REVIEW_SCOPE: FIX | TARGETED | FULL
BASE_SHA: <完整 SHA>
HEAD_SHA: <完整 SHA>
HEAD_TREE: <完整 SHA>
RULESET_ID: ICR-V2.0
AUTHORITY_REFS: <权威文档固定 ref 与版本>
EVIDENCE_PROFILE_ID: ETP-V2.0
EXTERNAL_INPUTS: <所需受控外部代码/配置/制品>
~~~
若任务不明确，禁止擅自取“最新 PR”开始写操作。
开始/结束均核对 Base/Head/实际变更；Base 变化必须重新评估有效差异、合同范围和 CI 证据，旧 PASS 不自动继承。
A 冻结审查快照之后，不应继续修改该轮受审代码；重新提交必须进入新轮次。未经批准不得合并、部署、生产发布或扩大原生安全实验。

## 3. 动态交接格式

PR Body 保存稳定目标、合同与安全门禁。A 的轮次交接通过 PR Conversation 评论：
~~~text
GH_HANDOFF_V2 READY_FOR_REVIEW
ROLE: DEVELOPER
REPO: owner/repo
PR: #N
TASK_ID: <任务>
REVIEW_ROUND: rNNN
REVIEW_TARGET: <范围>
CONTRACT_SCOPE: <范围>
BASE_SHA: <SHA>
HEAD_SHA: <SHA>
HEAD_TREE: <SHA>
RULESET_ID: ICR-V2.0
EVIDENCE_PROFILE_ID: ETP-V2.0
AUTHORITY_REFS: <文件及固定 ref>
REVIEW_SCOPE: FIX | TARGETED | FULL
REQUESTED_REVIEWS: STANDARDS, SPEC
CHANGES: <变更摘要与修复编号>
ORIGINAL_EVIDENCE: <原始 CI/日志/证据索引或缺证说明>
KNOWN_GAPS: <未验证项及影响>
SECURITY_GATES: <未授权事项>
~~~
修复后首行 `GH_HANDOFF_V2 FIX_READY` 并带上一轮 Head、两份旧 Review URL、问题关闭情况和回归证据；旧 Comment/Review 不修改、不回写。
交接评论仅供定位，不能替代 B/C 直接核验。

## 4. 独立 Review 的公共字段

B/C 各自使用原生 GitHub `COMMENT` Review，尽可能显式传 `commit_id = REVIEWED_HEAD_SHA`，正文首行为 `GH_HANDOFF_V2 STANDARDS_REVIEW` 或 `GH_HANDOFF_V2 SPEC_REVIEW`：
~~~text
ROLE: STANDARDS_REVIEWER | SPEC_REVIEWER
REPO: owner/repo
PR: #N
TASK_ID: <任务>
REVIEW_ROUND: rNNN
REVIEW_TARGET: <范围>
CONTRACT_SCOPE: <范围>
REVIEWED_BASE_SHA: <SHA>
REVIEWED_HEAD_SHA: <SHA>
REVIEWED_TREE_SHA: <SHA>
RULESET_ID: ICR-V2.0
EVIDENCE_PROFILE_ID: ETP-V2.0
AUTHORITY_REFS: <权威合同固定 ref>
REVIEW_PROGRESS: REVIEW_COMPLETE | REVIEW_INCOMPLETE | SNAPSHOT_CHANGED
EVIDENCE_STATUS: SUFFICIENT | INSUFFICIENT | NOT_ASSESSED
VERDICT: PASS | FAIL | BLOCKED | CONDITIONAL | NOT_ISSUED
REVIEW_SCOPE: FIX | TARGETED | FULL
REVIEW_LEVEL: FIX_PASS | TARGETED_REVIEW_PASS | ROLE_FULL_SCOPE_PASS | NONE
INTEGRATION_STATUS: PASS | FAIL | NOT_TESTED
FINDINGS: <P0-P3、原始证据和关闭条件>
GAPS: <NOT_RUN、缺证和残余风险>
~~~
报告正文还须写明独立反例、正反/边界/异常验证、原始代码与测试身份、审查前后稳定性。
PR Conversation 评论若无法原生 SHA 绑定，必须说明降级性质；不能伪装成 GitHub 原生提交绑定 Review。
同一账户的两个角色是逻辑独立会话，不是独立人类或账户。若合同要求独立人员，必须另外满足。

## 5. A 的状态机和“下一步”只读查询

A 按实际 PR 最新 Head/Base/Tree、权威合同版本、原始执行证据、A 交接和 B/C **各自同一轮次** Review 判定：
- `DEVELOPING`：无当前有效冻结交接 → A 开发或补齐合法证据。
- `READY_FOR_REVIEW`：交接完整、无 B/C 有效结果 → 通知 B/C 各自 `继续`。
- `STANDARDS_DONE` / `SPEC_DONE`：仅一方完成 → 指向另一方 `继续`。
- `BOTH_COMPLETE_WITH_BLOCKERS`：存在 P0–P2 / FAIL / BLOCKED → A 整理修复任务；新提交新轮次双复审。
- `BOTH_ROLE_PASS`：两个足够范围的角色级 PASS → A 核查 R10 与额外门禁，但不能代替签署 FULL。
- `SNAPSHOT_CHANGED`：Head/Base/有效差异/依赖/合同身份有未处理漂移 → 暂停旧 PASS，核验新快照。
- `EVIDENCE_BLOCKED`：不能读取规则、代码、必要证据或权限不足 → 报告确切缺口，不虚写 PASS。
所有查询输出 `REPO, PR, TASK_ID, REVIEW_ROUND, BASE_SHA, HEAD_SHA, REVIEW_TARGET, RULESET_ID, DEVELOPER, STANDARDS_REVIEWER, SPEC_REVIEWER, BLOCKERS, NEXT_ROLE, NEXT_COMMAND`。
**任何单人角色结果、FIX/TARGETED PASS 或 `REVIEW_COMPLETE` 都不是 `FULL_CODE_REVIEW_PASS`。**

## 6. V2.0 协议生效门禁

- 本协议只用于明确指定采用 V2.0 的新审查轮次；交接和独立 Review 统一使用 `GH_HANDOFF_V2`。不得以无版本信息的评论、角色自述或先前结论自动填补缺失的 `EVIDENCE_STATUS` 或证明当前 PASS。
- 必须记录精确批准的规则版本、合同版本、快照身份与开始适用的轮次。只有 B/C 对同一固定规范文件快照独立复审、用户批准，且 A/B/C 三个 Project 来源都能完整读取并核验一致后，才可以声明 `EFFECTIVE_FOR_NEW_ROUNDS`。
- 本协议不授权任何 PR 合并、部署、发布、产品安全门禁变更或高风险实验。无证据不得宣称签收或集成通过。
