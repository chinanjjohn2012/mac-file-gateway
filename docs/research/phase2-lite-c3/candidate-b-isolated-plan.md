# Phase 2 Lite C3 — Candidate B 组外 Controller / 独立 Anchor 隔离研究计划

**Status: DESIGN/IMPLEMENTATION PLAN ONLY — NEEDS INDEPENDENT STANDARDS / SPEC REVIEW BEFORE B-NATIVE IMPLEMENTATION. G2 BLOCK.**
**基线：** PR #22 固定设计提交 `a7cd33d2b6f4cbe48b5db41b8f0a3f51a44e109e`；Candidate B 独立研究分支从此提交派生。
**关联但不继承资格：** PR #24 Candidate A 原生原型（未独立签收）；PR #26 C3-05/06/13 在 `51634d73c49aef85ed965b108fac481cc61f7c29` 经外部独立复审 Standards/Spec PASS、P2×3 CLOSED，仅限其自身隔离研究。
**MCP SDK 基线：** 官方 Python SDK 2.3.0。本文不更改 Gateway 产品代码、SDK、Workspace、Pipfile 或执行配置。

## 1. 研究问题与非目标

核心问题：在真实 Darwin ARM64 中，能否让 Native Owner 唯一持有并回收一个常驻进程组 Anchor，同时让**组外** Controller 成为 Worker 的合法直接父进程，使 Worker 在执行业务测试逻辑**之前**加入 Anchor PGID，且在 TERM/KILL 后由 Controller 真实 `waitpid` 获得 Worker 状态？

这属于**合成研究**：全部进程由本测试创建、位于私有临时目录，不能提供现有 host PID/PGID、任意执行文件、命令、项目路径或真实业务输入。任何合成成功都不能证明 PID/PGID 重用免疫、`getpgid`→`kill(-pgid)` 原子授权、任意后代树回收或 G2。

父子关系及唯一回收所有权（不得简化为 Owner 直接回收 Worker）：

```text
GitHub-hosted macOS test runner (仅启动隔离 Native Owner helper)
└── Native Owner [唯一负 PGID 信号授权者；唯一 Anchor/Controller waiter]
    ├── Anchor [Owner 直接子进程、Worker 进程组 Leader；整个信号窗口保持未回收]
    └── Controller Relay [Owner 直接子进程、不同 PGID、与 Anchor 同 Session]
        └── Worker [Controller 唯一直接子进程；在启动测试逻辑前加入 Anchor PGID]
            └── 已知合成后代（只用于明确的特定实验）
```

注意：Anchor 的实际 `TERM` 处置必须在原生实验中**显式配置并核验**，不能假设默认存活；Candidate B 的设想是它在 TERM 后仍维持组身份，KILL 是最后的合法组信号。Controller 必须在组外存活并尝试回收 Worker，但不能保证其永远可用。

## 2. 不可放宽的身份、安全与状态契约

1. **统一 Owner：** `ANCHOR_HELD → RUNNING → TERM_SENT → SIGNALS_CLOSED → REAPED/CLOSED` 由同一个 Native Owner 串行管理。Anchor 与 Controller 仅由 Owner `waitpid`；Worker 仅由 Controller `waitpid`。每次组信号前须验证 Owner 独占关系、存活且未回收的 Anchor、PGID、Session、截止时间和状态；在身份丢失、`ECHILD` 或任何歧义下零后续组信号并标记 `UNRESOLVED/QUARANTINED`。
2. **进程组绑定：** Owner 为 Anchor 使用 `POSIX_SPAWN_SETPGROUP` 建立新 PGID；Controller 由 Owner 另建独立进程组，保持与 Anchor 同 Session。Controller 为 Worker 调用 Darwin `posix_spawnattr_setpgroup(anchor_pgid)`，必须检查 API 返回值以及实际 `getpgid/getpid/getsid`。Worker 在控制 gate 释放前只做受控握手、不可运行业务测试逻辑。
3. **跨父级 join 的真实性：** 不得用 Worker 执行后的 `setpgid()` 或 `sleep()` 模拟“执行前加入”。Worker 的真实 PGID/Session、Controller 的真实 PGID/Session、Worker 的合法父进程、Anchor 的 Leader 身份均由独立观察证明。目标不存在、Session 不同、身份不匹配或 join 失败时绝不 release gate，不报告成功。
4. **信号处置：** Worker 显式通过 `posix_spawnattr_setsigdefault` 和 `setsigmask` 恢复 SIGTERM 默认处置与未阻塞状态，校验对应 `POSIX_SPAWN_SETSIGDEF/SETSIGMASK` flags；Anchor 的 TERM 策略显式冻结。缺少恢复配置的负控必须先确认初始继承了可观测的被忽略/阻塞 TERM，否则该负控无效。
5. **正确信号结果：** TERM 与最后一次 KILL 是 Owner 的*动作记录*；`OBSERVED_EXIT(code)` / `OBSERVED_SIGNAL(signum)` 只能来自 Controller 对其直接 Worker 的成功 `waitpid`。Controller 死亡、IPC 丢失或未获得可验证状态时结果必须 `UNKNOWN`，绝不将 `KILL_SENT`、EOF 或 stdout 文本写成 Worker 状态。
6. **双轴状态：** `worker_result = OBSERVED_EXIT | OBSERVED_SIGNAL | UNKNOWN` 与 `cleanup = VERIFIED | UNRESOLVED` 独立记录。Worker 状态已观察也不能推出同组后代都退出；Anchor/Controller FD、已知后代及双流 drain 必须分别获得证据。任意存活脱组后代不能标记 `VERIFIED`。
7. **控制消息来源：** Owner↔Controller 使用私有专有 IPC，Owner 验证唯一合法写端（含显式关闭 Worker/后代继承写端），`FD_CLOEXEC` 加 `spawn file-actions` 关闭，不能仅靠 ticket 字段证明来源。`RELAY_READY/WORKER_SPAWNED/WORKER_REAPED/FINAL/UNRESOLVED` 是严格版本化、固定尺寸/有界长度、序号递增的消息；伪造 stdout、重复/乱序、漏写端、早 EOF 均不得形成观察到的成功终态。
8. **目录、时限和资源：** 合成目录为私有 0700 + marker、Owner 持有目录 FD，使用 `posix_spawn_file_actions_addfchdir_np`；所有阶段使用一个单调外层预算，包含 gate、TERM grace、KILL、双流 drain、合法 wait 和关闭。`EINTR/ECHILD/ESRCH/EPIPE`、取消、失败清理都不能造成无界等待或向失效 PID/PGID 补发信号。

## 3. 分层、可证伪的原生验证矩阵（先 RED，后候选实现）

| 研究 ID | 观察前提和正向案例 | 同路径负控和拒绝条件 | 必须收集的证据 |
| --- | --- | --- | --- |
| B-01 — Cross-parent group join | Owner 持有 Anchor，组外 Controller 成为 Worker 父进程；Worker 执行前加入 Anchor PGID | Anchor PGID 不存在、不同 Session、spawn group join 返回错误、Workload 早于 gate 执行 | Anchor/Controller/Worker 的真实父子关系、PGID、Session；gate 是否释放；Worker 确认由 Controller `waitpid` |
| B-02 — Controller survives TERM | Anchor 保持有效身份；Worker 默认响应 TERM；Controller 在组外仍活着 | 故意继承被忽略/阻塞 SIGTERM、缺少 `SETSIGDEF`/`SETSIGMASK`；Anchor 提前退出 | Owner 唯一 TERM 调用；Worker 真实 `WIFSIGNALED/WTERMSIG`；Controller 收到可信结果 |
| B-03 — Forced group KILL | TERM-resistant Worker 实际进入组；Owner 在有效 Anchor 下最后一次 KILL；Controller 成功 reap Worker | Controller 在 KILL 前后死亡、Worker 脱组、假 `KILL_SENT=OBSERVED_SIGNAL` | KILL 是最后组信号；Controller 是唯一 Worker waiter；若观察缺失则 `UNKNOWN`；清理独立记录 |
| B-04 — Anchor identity lost | Anchor 真实退出但尚未回收，以及已回收两种有序阶段 | 旧 PGID 仍在缓存、第二 waiter 提前回收、`ECHILD` | 资格丢失后组信号尝试计数为零；`QUARANTINED`，不重用数字 PGID |
| B-05 — IPC origin/terminal | 合法 Controller 私有 FD 传完整 `WORKER_REAPED` 后唯一 `FINAL` | Worker stdout 伪造、写 FD 泄漏、错 ticket/seq、重复终态、损坏/截断、前置 `FINAL` | IPC 源、继承 FD 检查、合法 wait 证据、单一 Owner 终态 |
| B-06 — Bounded shutdown | EOF/取消发生在 Anchor、Controller、Worker 不同阶段 | 中途 SIGPIPE、控制 pipe 关闭、EINTR、deadline 前后 TERM/KILL、完成消息缺失 | 总预算、已知子进程合法回收、FD 关闭、无失效 PGID 信号，失败仍 BLOCK |
| B-07 — Output/descendants | 已知合成后代持有 stdout/stderr；Worker 自己已退出 | 后代关流但仍活着；脱组 `setsid` 的合成负控 | 不能仅凭 EOF 声称后代全退；已知后代独立见证、两流 drain 状态与独立 cleanup 结果 |

**第一原生里程碑仅 B-01（跨父级 join + 真实 wait + 三项负控）**：若这一组在目标 macOS 失败，后续 B-02/B-03 的 SIGTERM/SIGKILL 研究不得假装已具备可行架构；保留 `BLOCK` 和原始证据，复审技术路线。其余场景分阶段实施，不要一次性把“完整 G2”加入本 PR。

## 4. 执行顺序、冻结产出和最小文件范围

1. **B-D0 文档冻结（本 PR）：** 只新增此计划及 Manifest；提交设计独立 Standards/Spec 复审。审查时验证 B 的组外 Controller、Worker 亲缘关系、实际跨父级 join 先于 workload、组身份丢失停止信号以及结果真假契约是否一致。没有独立设计 PASS 不提交原生运行候选。
2. **B-R1 合约 RED（后续独立实现分支）：** 新增 `tests/test_c3_candidate_b_join.py` 和单独的 macOS ARM64 工作流。测试应要求真实 B-01 join、可靠 Controller Worker `waitpid`、跨 Session/缺失组/错误 Parent gate 拒绝；没有 C Helper 时 RED 必须因缺失实现而失败，不能将其称为内核竞态重现。
3. **B-R2 原生最小候选：** 仅新增 `tools/research/c3_candidate_b_anchor.c`、`tools/research/run_c3_candidate_b.py`，可增独立 test-only worker，禁止 Gateway 产品代码。使用固定枚举 mode 和测试独占私有根，根目录由 Runner 创建且没有用户传入 existing PID/PGID 的入口。
4. **B-R3 原生双版本：** 在 hosted `macos-15` ARM64 Python 3.13/3.14 中运行真实 C join 和 wait；同 SHA 执行 Linux pytest 全量、HTTP/MCP smoke、compileall、shell 校验、Manifest。一切公共日志仅可显示 enums/bools/相对耗时，不输出真实 PID、根路径、控制帧或负载字节。
5. **B-R4 独立源码/日志复审：** 固定 Head、Base、Git Tree 和原始 Actions Job 日志；Standards/Spec 单独 PASS 后方可关闭 B-01 隔离研究。其它 B-02…B-07 继续独立 RED→原生→复审，不由 B-01 的 PASS 自动放行。

## 5. 对比 Candidate A 所需且尚缺的证据

| 判断维度 | Candidate A 当前有界观察 | Candidate B 必须新增证明 |
| --- | --- | --- |
| 组领导者/权限 | Relay 为直接 Parent/PG Leader；部分 A 合成实验成功，但 PR #24 代码仍待独立复审 | Owner 持有 Anchor 和组外 Controller；真实 B Worker 跨 Parent 加组可行性 |
| KILL 后 Worker 状态 | Relay 被 KILL 可能丧失合法 Worker wait，结果 `UNKNOWN` | Controller 组外存活并在 KILL 后尝试 `waitpid`，不保证成功 |
| PID/PGID 重用 | PR #26 C3-05/06/13 仅 `reuse_proven=0` | 不继承 PR #26 G2 资格；B 的持有 Anchor 仍需独立 XNU 证明 |
| IPC/后代/关闭 | A 当前限定合成路径，不能证明所有后代 | B 独立验证 Control FD 非继承、真 Worker 父子关系、两流/子孙边界及 deadline |

**最终门禁：** Candidate B 当前只能列为 `DESIGN_CANDIDATE_NOT_NATIVE_PROVEN`；C3 B-01 原生未执行、全部真实 PGID 重用性质未证明。PR 保持 Draft；G2、真实 ExecSupervisor、REST/MCP Multi exec、G3 MCP SDK 2.3.0 协议资格、G4/G5 发布均 BLOCK。不得重启 Gateway、合并研究 PR 或操作真实 Workspace/生产进程。
