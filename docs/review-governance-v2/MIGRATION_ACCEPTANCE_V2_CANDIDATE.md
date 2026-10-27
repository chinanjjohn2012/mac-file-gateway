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

## E. 固定规范字节与独立来源同步（r003 修复候选）

- **本 PR 仍是拟议规则的设计复审，不是规则正式启用。** GitHub 候选路径内的 Core/Handoff/ETP/A Role 采用 A Project 实际全文读取的 V2.0 文件**逐字节副本**；路径名包含 `_CANDIDATE` 不改变文件内部的规范 ID，也不因文件已提交而宣布生效。各文件 SHA256、Git Blob 和来源读取身份在本目录 README 记录。
- B/C Role 的 r003 候选文本保留并补强每轮强制全文读取（R01–R10 + 报告 + 禁止 + 版本适用边界）、只读独立取证、原生 COMMENT Review 与证据缺口阻断。A 无法从自己的 Project 直接证明 B/C Project 实际挂载的 Role 文件字节；**必须由 B 和 C 分别直接全文读取各自 Project Source，报告真实 SHA256/内容差异并独立评价**。在这些核验前 `THREE_PROJECT_SYNC=NOT_VERIFIED`。
- 候选文件和三个 Project 的最终权威文件如果字节/义务仍不同，不得冒称同一已批准规范；如需变更候选 Head 或 Project 权威来源，必须新快照重新核验与必要独立复审。任何用户批准必须绑定明确 Base/Head/Tree、规范 Git Blob/sha256 和首次适用的新轮次。
- A/B/C 同一 GitHub 登录名不是人类/账号独立；独立评审由各自直接取证与自己的原生 Review 体现。不读取或代写别的角色结论。

## F. 规范启用隔离和可复核的 T0 状态演练

- 针对本目录的变更，B/C 复审目标为 **V2.0 规范设计与迁移**；普通产品 PR 只针对当前适用规则验证产品合同、完整源码、原始执行身份与安全授权。**旧治理批准/来源同步问题不应在每个产品 PR 作为新的产品 P0–P2 重复统计**，应单独登记 `EXTERNAL_PROCESS_GATE` 并链接治理复审记录。若该流程门禁实际影响 R01/R10 的当前资格，仍要诚实标记相应 `EVIDENCE_STATUS`/`R10_STATUS`，不得虚构整体 PASS。
- 完成 B/C 独立设计复审且无阻断、用户明确批准精确文本、各 Project 同版全文读取及必要迁移 T0 验证以后，才允许为**未来明确指定的新轮次**记录 `EFFECTIVE_FOR_NEW_ROUNDS`。旧 `GH_HANDOFF_V1`、V1 Review 和产品 PR 不追认 V2 PASS；真实环境/生产/Native/T2/T3 仍需独立授权。
- 有效性演练至少验证：仅 B 通过时下一角色 C；两项 TARGETED 不产生 FULL；Head/Base/Tree 或合同错配不拼接 PASS；Base 漂移不继承旧 PASS；用户批准但未完成 Project 同步不生效；来源/运行输入不足与必要测试 NOT_RUN 如实阻断；角色审查完成却发现 P1 得到 FAIL 而不是 INCOMPLETE；产品缺陷与独立治理门禁分离；Merge 与 Head 证据分别标识；无任何情形获得自动合并、发布或原生执行许可。
- 所有 T0 演练只使用不触达生产的内存输入、可审计源码和隔离仓库快照。运行结果只能证明**迁移规则模拟器**的受测组合，不代表真实 A/B/C Project 已同步、不代表真实 GitHub 后端状态机、Native/生产资格或集成 PASS。
