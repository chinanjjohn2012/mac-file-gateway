# Phase 2 Lite C3 Candidate B — B-02 Controller Survives TERM：隔离设计及原生验收门禁

**Status：DESIGN ONLY / INDEPENDENT STANDARDS–SPEC REVIEW PENDING；B-02 原生实验尚未执行；G2 BLOCK。**

**固定实现基线：** [PR #29 B-01](https://github.com/chinanjjohn2012/mac-file-gateway/pull/29)，Head `f84d2d2abdec76dd7e0f34cb19d78250433b8087`，独立 Standards/Spec 代码复审 PASS/PASS（仅限 B-01）。[PR #28 设计](https://github.com/chinanjjohn2012/mac-file-gateway/pull/28) 已独立复审通过，仍为 Draft。此分支只新增本设计文档与 `MANIFEST.sha256`，不修改上述已通过复审的代码或生产 Gateway。

**本阶段要回答的问题：** 在 macOS ARM64 的全新、测试独占进程组里，Owner 是否能在保持合法、未回收 Anchor 身份期间，向该组**仅发送一次 SIGTERM**，让按已验证配置恢复默认 TERM 处置的 Worker 因 TERM 退出，同时让组外 Controller 继续存活并通过合法直接父进程 `waitpid` 观察 `WIFSIGNALED && WTERMSIG == SIGTERM`？保持 Worker 退出证据与清理证据独立，不能把 `TERM_SENT`、EOF、`143` 或 Controller 自报字符串当作 Worker 终态。

## 1. 范围、禁止事项和前提

1. **B-02 只允许合成 TERM 研究。** 本阶段不得执行 `SIGKILL` / `kill(-PGID,SIGKILL)`，也不得实现 B-03 Forced Group KILL；B-03 必须独立设计、RED、原生和代码复审。禁止接收任意宿主 PID/PGID、可执行程序、命令、真实 Workspace、数据库或用户路径；仅由当前 Runner 创建的私有 `0700` 临时根目录及受控、固定枚举模式。
2. **先恢复 B-01 证据。** 同一真实 Darwin 构建中，重新验证 Owner 是 Anchor/Controller 的唯一直接父进程与 waiter、Controller 是 Worker 的唯一父进程与 waiter、Worker 在工作门打开前真实加入 Anchor PGID，三者 Session 关系由内核证明。B-01 的既有 PASS 不能替代 B-02 每次实验的预条件。
3. **升级一个已知 P3 为 B-02 前置门禁：** 在发送 TERM 前，Owner 必须独立证明 Controller 处于自己的进程组，`getpgid(controller_pid) == controller_pid`，而不只是不属于 Anchor 组；失去 `POSIX_SPAWN_SETPGROUP` 的变异构建必须被拒绝。PR #29 的另一条 P3（对组 Join Spawn 失败返回 errno 分类）保持后续 B-01 证据加固，不直接当作 TERM 研究资格。
4. **单一 Owner 授权：** 只能由 Native Owner 发出一次 `kill(-anchor_pgid,SIGTERM)`。组身份必须在唯一 Owner 串行状态机中保持至关闭信号资格，禁止第二 waiter 提前回收 Anchor，失去身份、身份未确认、`ECHILD` 或已超时时不得进入任何组信号系统调用。发送前校验已知直接 Anchor 身份、`getpgid`、`getsid`、内核 PPID/PGID、状态、总预算；在真正 syscall **之前**计入组信号尝试（成功与失败分开），所有组信号入口都经过单一门禁。
5. **信号处置必须显式验证：** Anchor 的 TERM 生存策略在合成 Helper 里明确设为忽略 TERM 并于 READY 前由 `sigaction` 核验；Controller 在目标组外且其 PGID=其 PID；Worker 经 `POSIX_SPAWN_SETSIGDEF`/`SETSIGMASK`、`posix_spawnattr_setsigdefault`/`setsigmask` 恢复 TERM 默认且解除屏蔽，在 Worker READY 中通过 `sigaction`/`sigprocmask` 自检。原生负控故意遗漏上述恢复时，须先证明相应继承的 IGNORE 或 BLOCK 前置条件确实存在，不能用一个成功的默认状态当成有意义负控。
6. **执行门与因果顺序：** 保持 B-01 Worker READY → Controller 核实 → Owner 独立核实并授予 → Controller 放行 Worker gate。在 Worker 已进入明确的合成“仍存活、等待 TERM”状态并发回 *ARMED* 证据、Controller/Owner 真实再次核验组关系之前，不得发送 SIGTERM。禁止以固定 `sleep()` 代替 ARM/信号的事件屏障；必须区分 Worker 自行退出、超时与真正 `waitpid` 观察的 SIGTERM。
7. **单一单调截止时间：** 一个 Outer Deadline 覆盖 Controller/Worker 握手、ARMED、TERM、接收可信 Worker `waitpid` 结果、Controller/Anchor 合作收尾及 FD 关闭。TERM 发送函数内部再次检查截止时间。检查到 syscall 之间的抢占窗口不是内核原子授权证明；不据此宣称 G2 或 PID/PGID 重用安全。
8. **失败清理：** Worker/Anchor/Controller 必须有私有合作退出 gate 和独立的合成自退出上限（上限必须落在验证总预算内且留出真实回收时间），不能靠 Actions 收尾来强杀孤儿。TERM 被忽略/被屏蔽的负控不得以发组 KILL 补救；只可在合法自有控制通道下合作退出或在预算内自退出，并由各自合法父进程观察结果。Owner 不得在失去身份后尝试数字 PGID/直接 PID 补发信号。超预算、IPC 异常、Waiter 失败、无法证明清理完成均为 `BLOCK/UNRESOLVED`，不输出成功。
9. **双轴证据：** `worker_result = OBSERVED_SIGNAL(SIGTERM) | OBSERVED_EXIT(code) | UNKNOWN`，仅 Controller 对合法直接 Worker 的 `waitpid` 有权确定；`cleanup = VERIFIED | UNRESOLVED` 由 Native Owner 独立判断 Anchor/Controller 已确实回收、Worker 可信结束、受管 FD 关闭及已知合成资源无遗留。若 Controller 提前退出或私有完成消息丢失，强制 Worker result `UNKNOWN`，不得从 EOF、状态字符串或仅发送 TERM 推断。
10. **研究输出限定：** Runner 只公开枚举 `mode/result/reason`、布尔证据、相对耗时与非敏感检查摘要；实际 PID/PGID、IPC 字节、绝对临时路径及进程信息留在测试私有文件（不作为公开 Actions artifact）。严禁把组信号入口做成对用户输入的任意 PID/PGID 接口。

## 2. 原生实验与可证伪负控

| 测试编号 | 实验与真实前置条件 | 应得证据与拒绝条件 |
| --- | --- | --- |
| B02-T01 `term-positive` | 新建 Anchor leader 真实保持未回收，明确忽略 TERM；组外 Controller PGID=自身 PID；Worker 与 Anchor 同 SID/PGID，已真正 ARMED 且 TERM 默认且未屏蔽 | Owner 资格/期限检查后仅一次 `SIGTERM` 组信号尝试，且真实 syscall 成功；Controller 在信号后仍在组外存活，真实 `waitpid` 得到 `WIFSIGNALED && WTERMSIG(SIGTERM)`；Worker/Anchor/Controller 在预算内由合法父进程收尾，两个结果轴分别记录 |
| B02-T02 `missing-sigdef` | Controller 在 Spawn Worker 前确实有 TERM=IGNORE 继承状态，故意省略 `SETSIGDEF` 的特定配置；Worker 在 READY 时证实仍忽略 TERM | 同一正向发信号路径后 Worker 不得错误报告被 TERM 杀死；必须合作退出/自退出，返回预期 BLOCK，且所有受管进程完成收尾 |
| B02-T03 `missing-sigmask` | Controller 在 Spawn Worker 前真的阻塞 TERM，故意省略 `SETSIGMASK`，Worker READY 证实继承阻塞状态 | TERM 不能冒充已观察 SIGTERM 终态；独立核查等待结果与有界清理，预期 BLOCK |
| B02-T04 `controller-group-regression` | 故意移除 Controller 独立组 Spawn flag，验证其 PGID≠其 PID 的真实状态；同时仍可能在 Anchor 组外 | Owner 必须在发组 TERM 前拒绝，`group_attempts=0`、`worker_gate_opened=0`，且不能因 Controller 尚在组外而误 PASS |
| B02-T05 `anchor-lost-before-term` | 以事件屏障使 Anchor 先真实退出/被独占回收，Owner 再进入发送资格检查 | 严格 `SAFE_REFUSAL`，`group_attempts=0`，不得沿用旧数字 PGID |
| B02-T06 `deadline-before-term` | 单调预算在资格检查/发送前被测试控制的调度闸耗尽 | 发信号函数内再次拒绝，`group_attempts=0`，负控仍有界收尾；不能先发 TERM 再返回 BLOCK |
| B02-T07 `canary-isolation` | 新建另一独立且可观测的合成 Canary PGID，整个 TERM 时段存活 | 目标 Worker 得到合法 TERM 观察且 Canary 在观察窗内仍存活；任何异常组目标/Canary 退出将结果 BLOCK；不得把它说成已证明任意宿主组绝不会被误杀 |
| B02-T08 `controller-result-lost` | Worker 真实信号结果可能存在，但 Controller 在向 Owner 发送完整合法结果前因测试故障退出/断管 | Owner 不能从 `TERM_SENT` 或 stdout EOF 合成 `OBSERVED_SIGNAL`；结果 `UNKNOWN`，清理轴独立标记；不完整即 BLOCK |

**独立 Mutation 门禁（至少两项）：** 一项移除 Worker TERM 默认恢复，使 B02-T01 无法通过；另一项移除 Controller `POSIX_SPAWN_SETPGROUP` 或 Owner 的 `getpgid(controller)==controller` 检查，使 B02-T04 必须捕获误放行。不得将仅靠源码字符串扫描的失败计为完成原生 Mutation。所有变异仅在临时合成二进制进行，不修改固定研究基线。

## 3. 状态机、信号所有权与失败终态

```text
B01_IDENTITY_HELD -> WORKER_GATED -> WORKER_ARMED
    -> TERM_ELIGIBLE -> TERM_ATTEMPTED -> SIGNALS_CLOSED
    -> WORKER_WAITED_OR_UNKNOWN -> ANCHOR_CONTROLLER_REAPED
    -> CLEANUP_VERIFIED | UNRESOLVED

任一身份/Session/PGID/期限/IPC 违反
    -> SAFE_REFUSAL（未发送） | BLOCK（已尝试或不能证明）
    -> SIGNALS_CLOSED -> BOUNDED_CLEANUP -> UNRESOLVED（证据不足）
```

- `TERM_ATTEMPTED` 是 syscall **调用意图**；`TERM_SENT` 是 syscall 确认成功的动作；`OBSERVED_SIGNAL(SIGTERM)` 只能来自 Controller `waitpid`；`CLEANUP_VERIFIED` 需要由 Owner 汇总两条父子关系的合法回收证据，四者不可互相替代。
- 原生 Worker 在 TERM 前应有明确仍存活的合成 ARM 门，且不能在 ARM 后马上自行退出；研究时钟窗口须与自退出上限严格分隔。用户态 `getpgid` 检查到内核 `kill(-pgid)` **并非原子操作**，设计不把此机制推广为真实运行的身份许可。
- 信号资格在释放 Anchor/关闭组身份窗口之前必须先关闭；每条清理路径都保留独立受管 FD/IPC ownership 和终态，不能以“已发送 TERM”代替清理已完成。

## 4. 实施阶段和严格验收

1. **B02-D0（此 PR，设计冻结）：** 仅创建本文及 Manifest；固定 SHA 让另一审查方独立进行 Standards/Spec 设计复审。必须重点审查真实自有组 TERM 范围、Anchor 忽略 TERM 后持有身份、Controller 独立组前置证明、双轴结果、不重复或越权组信号、失效/超时的清理证据。**在独立设计 PASS 前不添加信号实验或 C 实现**。
2. **B02-R1（独立 RED）：** 独立实现分支新增 `tests/test_c3_candidate_b_term.py` 和 `.github/workflows/c3-candidate-b-term-native.yml`。至少 B02-T01～T06 的源/Runner 契约必须先以 *缺少实现* 而失败；negative `sigdef/sigmask` 的前置证据、Controller PG leader、发送前截止和 Anchor 身份失效必须有可证伪断言。RED 不冒充 Darwin 实际竞态或违规发信号。
3. **B02-R2（隔离原生最小候选）：** 只增加独立 C/Driver 合成机制（例如 `tools/research/c3_candidate_b_term.c`、`tools/research/run_c3_candidate_b_term.py`），不得把 TERM 支持合并进 Gateway/PR #29 的 B-01 Helper；所有实际信号只对本轮创建并持有合法身份的测试专有组。分阶段扩到 T07/T08，任一异常 BLOCK，不允许用宽松容错跳过预期对抗案例。
4. **B02-R3（原生复测）：** GitHub-hosted `macos-15` ARM64 + Python 3.13/3.14 真实组 TERM，以及独立合成 Worker 的实际退出 `waitpid`。同 SHA 完成 Linux 全量 pytest、HTTP/MCP smoke、compileall、shell 和 Manifest。Job 日志分别报告每个前置条件、是否真正调用组 TERM、是否回收 Worker、是否收尾，无遗留合成进程被 Actions 强制终止。
5. **B02-R4（独立代码签收）：** 固定 Head/Base/Git Tree；另一审查方阅读真实 C/Python/Tests/工作流及原生 Job 日志，逐项评定 Standards/Spec 与 P0/P1/P2，必要时定向 RED→GREEN。只有 B-02 独立 PASS 才能标为研究闭环，不能自动放行 B-03。
6. **B03-D0（未来单独设计）：** B-02 闭环后，再以独立 Draft PR 研究 `TERM-resistant Worker → 组 KILL → Controller waitpid`、KILL 是最后组信号、Controller 失联时 `UNKNOWN`、已失去 Anchor 的安全拒绝和资源收尾。B03 自己的设计/RED/原生/代码复审不可省略。

## 5. 禁止扩大本阶段结论

B-01 的独立代码 PASS 仅建立跨父进程组 Join 在受控 Darwin 上有原生正向证据，**不使 `kill(-pgid)` 在数值 PGID 重用下获得内核原子授权**。B-02 即使将来通过，也只能说明特定合成 Owner/Anchor/Controller/Worker 的 TERM 结果观察：不能证明通用进程树回收、生产级 IPC 身份、stdout/stderr 完整 drain、真实 Direct/Pipenv 和 shutdown/Permit/Lease。所有未知、失败或不完整的结果都要可见并留在 BLOCK。

**当前状态：** `B02_DESIGN_AWAITING_REVIEW`；`B02_NATIVE_NOT_RUN`；`B03_NOT_AUTHORIZED`；`reuse_proven=false`；`g2_qualified=false`。PR 保持 Draft、绝不合并或重启 Gateway；真实 ExecSupervisor、REST/MCP Multi exec、G2/G3/G4/G5 和发布启用继续 BLOCK。
