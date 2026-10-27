# V2.0 三角色独立复审规范 — r003 固定来源候选包

**STATUS: DRAFT / NOT_APPROVED / NOT_EFFECTIVE。** 用户授权 A 修复 [PR #75](https://github.com/chinanjjohn2012/mac-file-gateway/pull/75) 的候选规范版本差异、提交新轮次交 B/C 独立设计复审；**这项开发授权不等于正式批准或切换规则**。旧 r001/r002 Review 和产品 PR 的受审 Head 保持不变。

## 规范分层和候选文件身份

| GitHub 候选路径 | 基准来源及精确内容身份 | 验证状态 |
| --- | --- | --- |
| `INDEPENDENT_CODE_REVIEW_RULES_V2_CANDIDATE.md` | A Project `GITHUB_INDEPENDENT_CODE_REVIEW_RULES_V2.0.md`；SHA256 `9bece5bf9c74e1fc899d6fcb09a067d4793b8ba3a61f6efc2c54eba2898cae3b`；Git Blob `feb442029c6220e52b2916a3900a7083bb652561` | **逐字节一致**；ICR-V2.0，R01–R10 + 报告、禁止、启用 |
| `GITHUB_REVIEW_HANDOFF_V2_CANDIDATE.md` | A Project `GITHUB_REVIEW_HANDOFF_V2.0.md`；SHA256 `b01cdc055bb35e586019781710229dadc4ca6ed80b6f97b2e0605db78965eef0`；Git Blob `710ff3db2c106309b577ab5bdda5ece60c65e821` | **逐字节一致**；GHRH-2.0 / A/B/C 状态机 |
| `EVIDENCE_AND_TEST_PROFILES_V2_CANDIDATE.md` | A Project `GITHUB_EVIDENCE_AND_TEST_PROFILES_V2.0.md`；SHA256 `36402e54a3b5515eed649a6cad4402cc5d41c86fe5fee36fa93d1e70f5b1e0e5`；Git Blob `2a38933ae76fcbefd7a49d4d48a3ba120cd87c6c` | **逐字节一致**；ETP-V2.0 / E1–E8、T0–T3、Head/Merge 实证 |
| `ROLE_A_DEVELOPER_V2_CANDIDATE.md` | A Project `GITHUB_ROLE_A_DEVELOPER_V2.0.md`；SHA256 `9655c6406fdf21a42739b9b670513309b417dd44fbd68f6a85e89be93d2d6dec`；Git Blob `780b788e6c92249cd5456bc66d9a83f89cc65f40` | **逐字节一致**；A 开发/冻结/交接 |
| `ROLE_B_STANDARDS_V2_CANDIDATE.md` | A 根据 B r002 直接指出的全文阅读/降级评论门禁修订；候选 Git Blob `c5249b443de99a4b4ef6c50ecd8ddf37fe20b387` | **B Project 实际 Role 文件字节不可由 A 直接读取：待 B 本人同版核验** |
| `ROLE_C_SPEC_V2_CANDIDATE.md` | A 根据 C r002 直接指出的完整 R01–R10、报告、禁止/边界、无法全文读取须阻断等要求修订；候选 Git Blob `437eb9df09954decbc1b34d585bf97b10e8adcb6` | **C Project 实际 Role 文件字节不可由 A 直接读取：待 C 本人同版核验** |
| `MIGRATION_ACCEPTANCE_V2_CANDIDATE.md` | V1/G01–G08 兼容、S1–S14 风险矩阵、B/C 设计审查、版本同步、T0 状态模拟和生效门禁 | 新 r003 复审范围；不是生效记录 |

文件名仍保留 `_CANDIDATE` 方便 GitHub 审查，**不得**因此更改上表四份逐字节规范正文里的正式版本 ID；实际生效状态由外层 README、审批记录和指定新轮次决定。规范正文自述的启用条件必须先真实满足，不能因复制到候选目录或 CI GREEN 自动成为权威。

## 本轮聚焦关闭的旧 r002 缺口

- **B/C P2 — R03**：候选误写“**不同比例的运行模式**”。现 Core 与 Project 确认逐字节一致，强制按实际适用的**不同执行模式**覆盖。
- **B/C P2 — R08**：原 RED 等效替代缺少“**已独立核验的等效原始失败证据**”门禁；现 Core 正文按上传版精确对齐，不接受开发者叙述代替原始 RED。
- **B/C P2/P3 — ETP §4**：明确按 Head/Merge 两种实际执行身份、父提交、依赖/配置差异判定 Head 是否必须独立重测；不以合成 Merge GREEN 冒充全部 Head PASS。
- **B/C P2 — 身份/角色**：恢复各角色适用的全文阅读、缺章阻断、原生绑定/降级标注，形成可复核 Git Blob 与 Project 来源同版核验任务。A 已验证四份 A Project 文件，**未完成 B/C 各自 Project 来源同步**。

## 生效与安全门禁

1. 本 PR 只申请 B 和 C 在同一固定 Base/Head/Tree 上分别出具 V2.0 **TARGETED 规则设计复审**；Review 必须清楚标为候选，不是已启用的产品流程。
2. 设计审查完成、所有 P0–P2 阻断独立关闭后，仍须用户**批准精确文件版本、Git Head/Tree、起用的新轮次**；不得自动视为通过。
3. A/B/C 三个 Project 必须分别实际全文读取公共三份规范及本角色职责，报告精确内容身份及差异；直到三方独立确认，`PROJECT_SOURCE_SYNC=NOT_VERIFIED`、`EFFECTIVE_FOR_NEW_ROUNDS=NO`。
4. 迁移验收 `MIGRATION_ACCEPTANCE_V2_CANDIDATE.md` 至少执行一次可检索的 T0 只读/内存演练；测试证据须真实记录运行代码/输出。T0 模拟通过只覆盖迁移逻辑样例，不等于 Project 数据真实同步。
5. 现行/历史 V1/G01–G08 记录和旧 Review 不改写、不自动追认；所有 Head/Base/合同漂移须重评。生产系统、安全合同、P0–P2、R01/R10、集成门禁均不因治理批准而放宽。
6. **治理与产品代码复审分别跟踪。** 已知规范审批或跨 Project 来源同步差异不得在每个产品 PR 被重复计算为新的产品代码 P2；单独标 `EXTERNAL_PROCESS_GATE`，且如实际阻止该轮完整 R01/R10 放行仍如实标 `R10_STATUS: BLOCKED`。只有真实触发版本或证据适用性变化时重新核验对应治理门禁。
7. 此候选不授权合并、发布、部署、生产配置、权限提升、真实 Native/T2/T3、自动解封、任意旧 PASS 追认或 A 代签 B/C。

**NEXT_ROLE：B Standards、C Spec 各自独立设计复审；批准和 Project 同步均待后续独立验证。**
