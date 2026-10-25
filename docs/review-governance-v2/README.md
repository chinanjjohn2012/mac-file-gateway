# 三角色独立代码复审与 GitHub Handoff V2.0 — 设计候选包

**状态：DRAFT / NOT_EFFECTIVE / NOT_APPROVED。** 本目录只包含新架构提案与验收用例；未修改任何已有权威 V1.0 规则、PR Review 或安全权限。
**定位：** 为 A / DEVELOPER、B / STANDARDS_REVIEWER、C / SPEC_REVIEWER 提供跨技术栈、跨仓库可复用的独立复审与 GitHub PR 交接体系。

## 目录

| 文件 | 责任 |
| --- | --- |
| `INDEPENDENT_CODE_REVIEW_RULES_V2_CANDIDATE.md` | 技术无关 R01–R10，规定**证明什么** |
| `GITHUB_REVIEW_HANDOFF_V2_CANDIDATE.md` | A/B/C 状态机、PR 快照、交接和 Review，规定**怎么协作** |
| `EVIDENCE_AND_TEST_PROFILES_V2_CANDIDATE.md` | 不同受审对象、CI/本地/制品、测试风险、证据复用，规定**怎么证明** |
| `ROLE_A_DEVELOPER_V2_CANDIDATE.md` | A 的开发/冻结/交接/只读协调职责 |
| `ROLE_B_STANDARDS_V2_CANDIDATE.md` | B 的独立 Standards 检查与 Review |
| `ROLE_C_SPEC_V2_CANDIDATE.md` | C 的独立逐合同 Spec 检查与 Review |
| `MIGRATION_ACCEPTANCE_V2_CANDIDATE.md` | 与 V1/G01–G08 的兼容、生效前门禁和验收反例 |

## 强制边界

1. 这是**拟议 V2.0**，不得作为当前已批准 V1.0 / GH-R01R10-REMOTE-1.0 的替代要求签发 PASS。
2. 原《独立代码复审规则 V1.0》R01–R10、《GitHub Review Handoff V1.0》和已批准的 G01–G08 继续有效，直到明确批准、B/C 独立复审和 A/B/C 三个 Project 同版来源验证完成。
3. 对使用现有 `GITHUB_COMMITTED_ONLY` 解释的在途评审，仍按已批准的 G01–G08 执行；**V2 提案中合成 Merge Tree 的分离建模不构成即时豁免**。
4. 不修改 PR #72/#73 等旧 Head、历史 Review、规则原始 Git Blob；旧 PASS 不追认。
5. 不授权合并、发布、部署、破坏性原生测试、生产操作或任何平台行为扩大。
6. 三角色是独立会话与独立判断要求；不声称在相同 GitHub 登录下具备独立账户身份或独立人类评审者资格。

## 核心抽象

- **Review Target**：明确的代码/制品集合与所需合同范围，`FULL` 只相对于该声明的目标，不等于整个仓库。
- **Snapshot**：代码身份、外部输入、有效差异、合同/规则版本与前后稳定性。
- **Evidence Profile**：依据目标与风险选择可复核的证明链；不能以“可选”规避合同所需真实测试。
- **Three dimensions**：`REVIEW_PROGRESS` / `EVIDENCE_STATUS` / `VERDICT` 分开，`REVIEW_COMPLETE` 不等于 `PASS`。
- **Role sign-off**：B/C 分别发表有范围的结果；A 检查完整性与阻断，不代签整体 FULL。

## 进入生效前需要的程序

- B / Standards 与 C / Spec 对**同一固定新 PR Head/Base/规则版本**分别进行独立、至少定向的规范设计复审。
- 修复阻断问题并重新产生固定快照和双独立 Review。
- 用户明确批准**确定的文档版本与 Git 提交身份**。
- 三个 Project 均实际读取同一版本；通过 `MIGRATION_ACCEPTANCE_V2_CANDIDATE.md` 的关键验收反例。
- 明确记录 `EFFECTIVE_FOR_NEW_ROUNDS`；旧审查按其历史规则处理，历史 PASS 不自动升级。
