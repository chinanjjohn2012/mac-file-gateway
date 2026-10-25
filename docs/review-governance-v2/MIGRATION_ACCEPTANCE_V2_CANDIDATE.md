# V2.0 迁移、独立复审与验收反例 — 候选

STATUS: DRAFT / NOT_EFFECTIVE

## A. 迁移不可变规则

1. 保留现行《独立代码复审规则 V1.0》、《GitHub Review Handoff V1.0》、已批准 GitHub G01–G08 原文和 PR #72/#73 旧审查的精确 Head/Base/Tree/Review。
2. 本 PR 只提出新规范；A 不代替 B/C 发表任何独立 Review，不使用旧 r002 的 PASS 冒充新设计 PASS。
3. 经过 B/C 在固定 V2 候选 Head 上独立复审、问题修订后再次双审、用户明确批准和 A/B/C Project Sources 同版本全文读取核验后，才对新轮次生效。
4. 新旧标记共存：旧 GH_HANDOFF_V1 记录只作为历史读入，不自动升级到 V2 或填补缺失 EVIDENCE_STATUS。
5. 针对所有使用 GH-R01R10-REMOTE-1.0 的现有远端代码评审，G01–G08 原批准约束依旧生效；新 E1–E8 不能覆盖 G04 的合成 Merge Tree 限制。

## B. 必测状态机反例（只读模拟/隔离演练）

| 用例 | 预期 |
| --- | --- |
| 同一 Head/Base/Tree、只有 B 完成 | NEXT_ROLE=C，不能提前整体 PASS |
| 两份都是 TARGETED_REVIEW_PASS | 不得推断 FULL_CODE_REVIEW_PASS |
| B/C 在不同 Head 或不同合同版本上 PASS | 不得拼接；SNAPSHOT_CHANGED 或 BLOCKED |
| Base 前进但 Head 不变 | 重评有效差异和影响，不自动继承 PASS |
| 任一关键源码/外部构建输入身份无法取得 | EVIDENCE_STATUS=INSUFFICIENT，阻断超范围 PASS |
| 评审已检查完毕，必要原生测试 NOT_RUN | REVIEW_COMPLETE + INSUFFICIENT + BLOCKED，而非机械 REVIEW_INCOMPLETE |
| 明确发现 P1 合同失败 | REVIEW_COMPLETE + FAIL；不能因为测试未全部执行推迟缺陷结论 |
| CI 被测的是合成 Merge Tree 而非 Head Tree | 记录真实测试对象与证明范围；**仅作 V2 提议验证**，不豁免当前 G04 |
| HEAD 内容匹配，但 ignored 文件参与 import/shadow | 执行源完整性失败，不得远端快照 PASS |
| GitHub PR 资料不包含本地未提交修复 | 不得宣称已审本机工作树或全部源码 |
| B/C 使用同一 GitHub 用户 | 只认逻辑会话/分析独立，不声称账户/人员独立 |
| A 用户输入“下一步” | 只能只读输出状态，不执行写入 |
| 没有明确授权的危险/生产测试 | NOT_RUN + 风险影响，不以 PASS 强制要求执行 |
| 旧 V1 Review 与 V2 新规则并存 | 保持历史结果、版本与适用范围，不自动追认 |

## C. 正式评审门禁

- 请 B 在此 Draft PR 的**当前 Head/Base**执行独立 Standards 规则设计复审；请 C 独立执行 Spec 逐合同设计复审。两人必须各自读取实际文档 Diff、源规则和权威约束，不互相采信结论。
- 重点审核：V2 的 FULL 范围定义、B/C 独立性真实程度、G04/G05 兼容、证据不足与 REVIEW_COMPLETE 分离、T2/T3 安全实验、版本切换与旧 Review 不追认。
- 结果仅可为绑定 SHA 的设计/规则定向 Review，**不是生产代码 FULL 或真实集成 PASS**。
- 修复后新 SHA/new round 重审，直到问题关闭；不得直接改写冻结的旧受审 Head。
- 经用户明确批准版本及三 Project 来源同步验收后再单独记录生效事实；批准本规则不自动允许合并、部署、发布或扩大高风险实验。

## D. 发布前清单

- [ ] 文档正确分层，R01–R10 不出现项目特有的强制 API/SDK/DB 名。
- [ ] A/B/C 三角色保持原有日常命令及独立权限。
- [ ] 旧 V1/G01–G08 严格执行直到切换批准并生效。
- [ ] 新规则已由 B/C 独立评审且所有阻断关闭。
- [ ] 批准精确版本与快照身份，记录迁移时点。
- [ ] 三个 Project 均实际读取一致的完整规则、交接和证据适配版本。
- [ ] 通过至少一次不修改产品代码的只读/隔离模拟验收；旧 Review 不追认。
