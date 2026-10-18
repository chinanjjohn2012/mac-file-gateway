# Phase 2 Lite Q0 Isolated SDK Qualification — Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **This is an isolated research-probe plan, NOT a Phase 2 product implementation plan.** Implementation of the probes, even in a disposable environment, still requires separate human approval.

**Goal:** Reproduce and classify Q0's known original-SDK falsey-related-ID failure, exhaustively assess reachability for the proposed Lite application contract, and produce an independently reviewable GO/STOP decision **without modifying MCP 1.30.0 or enabling Multi exec**.

**Architecture:** Pin and verify the official SDK in a disposable macOS venv. Run a versioned, synthetic FastMCP→Session→Streamable HTTP ASGI probe and a separate source-to-call-site emission inventory; compare machine-readable evidence with a fail-closed decision gate. Keep raw logs out of Git; only an independently scrubbed summary and the probe code may become public.

**Tech Stack:** macOS arm64, Python 3.14.7 for evidence parity, official `mcp==1.30.0`, AnyIO, HTTPX ASGI, Starlette, pytest, SHA-256 and JSON. Reference the independent review's official-package wheel and full transitive dependency inventory; never reuse a Gateway runtime venv.

**Spec:** `docs/superpowers/specs/2026-10-18-phase2-lite-stateless-controlled-exec-design.md` at fixed PR #8 head `a46ab54d2814afcb5932dae27799ec258be9e354`, `release/ms1` base `e32cb5124bbd8b08a79c75b4940799e041dd1295`.

**Status:** PLAN FOR REVIEW; PR #8 design CONDITIONAL; official SDK 1.30.0 Stateless M10-L related-message subcase **KNOWN FAIL/BLOCK**, other M10-L cases incomplete; Phase 2 Lite product **BLOCK**. This plan does not grant permission to run real Gateway, attach ChatGPT/Tunnel, amend the protocol contract, merge or deploy.

## Global Constraints

- **No SDK modification:** never edit installed `site-packages`, build `mcp 1.30.0+mfg.1`, swap SDK source, monkeypatch production, rewrite wire JSON-RPC IDs or silently reject valid IDs. Probe wrappers may record inputs/outputs only and must delegate to official implementation unchanged.
- **No product execution:** do not touch `gateway/`, `requirements.txt`, `setup.sh`, `run.sh`, `verify.sh`, Workspace config, product tests or SDK installed in Gateway; all synthetic tests must assert **Popen=0** and use no real project code/credentials.
- **Official SDK source map:** read the 111-file upstream SHA map at PR #7 fixed `eee0d8e1d5fbc86d131ca32712d5033e8c941589`, file `docs/research/2026-10-18-pr3-sdk-routing/SDK_SOURCE_SHA256.json`, as a *reference only*; never import PR #7's patched SDK candidate as original SDK qualification evidence.
- **Fixed evidence:** independent PR #8 review dated 2026-10-18 verified macOS arm64 / Python 3.14.7 / original MCP wheel SHA-256 `666edb5009503e1047c9d60346a756f94b261f05cc2625f23d41c728ffc484d0`; its private ZIP SHA-256 is `e2aca2635349e322c0e85ff120ed9dcd0479c1fd3fc857c414af87dbd8603cb0`. Preserve its report and baseline observations; do not paste its host paths or raw logs into public Git.
- **Observed baseline, not extrapolation:** independent POSTs with IDs integer `71` and string `"71"` routed correctly in the narrow test. `CTX_EMPTY`, `RAW_ZERO`, `RAW_EMPTY` and `PROGRESS_EMPTY` lost related metadata and targeted nonexistent `_GET_stream`; final JSON still succeeded. SDK ASGI task cancellation cancelled its tool coroutine. Client reachability remains UNKNOWN.
- **Q0 is not a re-test-to-PASS exercise:** while the reviewed contractual set still includes correct related-message delivery for legal IDs, those four reproducible counterexamples mean **FAIL/BLOCK**. A diagnostic script exiting 0 means evidence collected, never SDK qualification PASS.
- **Scope and authorization:** only after user approval of this research plan may an engineer write/run the isolated probes. Q1–Q3 below are *conditional future plans* with their own gates; no real Tunnel/ChatGPT interaction without separate explicit permission.
- **No hidden skips:** every mandatory Q0 item gets PASS, FAIL, BLOCKED, NOT_RUN or INVALID_PROBE with reason; SKIP/UNKNOWN cannot be promoted to PASS. Independent review may preserve earlier valid evidence, but must never swap PR #7 patched-candidate PASS for original SDK qualification.

## Review Focus

These five possible false-positive paths must each have a test in the owner task:

1. A legal falsey ID produces correct final HTTP JSON but no related notification → **Task 2:** qualify using transport metadata/stream ownership, not HTTP body alone.
2. Context converts integer 0 into string "0", while raw Session 0 is discarded → **Task 2:** distinguish high-level and raw APIs and assert their exact observed types.
3. The Lite tool never explicitly calls `ctx.info`, but SDK error/automatic paths still produce a related notification → **Task 3:** map and dynamically exercise error, progress-token and SDK-generated paths; classify anything unknown as BLOCKED.
4. Instrumentation changes scheduling or SDK behavior and hides the original bug → **Task 2:** uninstrumented and delegating-observer runs must have matching user-visible responses and identical failure class; no routing fixes.
5. An unverified wheel, mismatched source or private raw logs are accidentally promoted as public evidence → **Task 1 and Task 4:** fail on provenance drift and scrub-before-publication.

---

## Fixed inputs and deliverables

The plan is limited to **Q0**. Source facts:

| Item | Fixed observation / boundary |
| --- | --- |
| Reviewed Lite spec | PR #8 `a46ab54d2814afcb5932dae27799ec258be9e354`, design CONDITIONAL, no new design P0/P1/P2/P3 |
| Official SDK | `mcp==1.30.0`, verified upstream wheel SHA-256 stated above; no fork |
| Existing falsey site | `mcp/shared/session.py:333` truthiness, with `mcp/server/streamable_http.py:1055–1099` GET fallback |
| Four negative cases | `CTX_EMPTY`, `RAW_ZERO`, `RAW_EMPTY`, `PROGRESS_EMPTY`: related metadata becomes None; final JSON correct |
| Two contrasting cases | `CTX_ZERO` and `PROGRESS_ZERO` use FastMCP's string `"0"` and must not be misreported as proof for raw integer 0 |
| GET | Stateless has real GET 200 SSE; DELETE 405 in the reviewed setup; no assumption that GET is absent |
| Runtime | No real Gateway, real Tunnel, actual worker, cwd, PGID, FD or process termination qualification |

**Future research-only files (do not create them during plan authoring):**

- Create: `docs/research/phase2-lite-q0/README.md` — provenance, exact commands, evidence policy and red/green interpretation.
- Create: `docs/research/phase2-lite-q0/verify_official_sdk.py` — deterministic wheel/source/version/dependency verification.
- Create: `docs/research/phase2-lite-q0/probe_related.py` — real official FastMCP/Session/HTTP ASGI positive and negative synthetic cases, with **delegating** instrumentation.
- Create: `docs/research/phase2-lite-q0/inventory_emissions.py` — source call graph and runtime emission coverage classification.
- Create: `docs/research/phase2-lite-q0/decide_q0.py` — JSON decision gate and sanitized summary generator.
- Create: `docs/research/phase2-lite-q0/tests/test_provenance.py`, `test_related_cases.py`, `test_emission_inventory.py` and `test_decision_gate.py`.
- Private outside-repo artifacts: `provenance.json`, `case-results.json`, `emissions.json`, full logs and environment/pip inventory, `Q0_DECISION_PRIVATE.json`. A manually reviewed `PUBLIC_Q0_SUMMARY.md` may be exported without paths, tokens, raw requests or local account details.
- Update `MANIFEST.sha256` **only if/when** the research-only code is subsequently reviewed and committed. Original PR #8 and PR #7 source must remain untouched.

### Task 1: Provenance and Fail-Closed Environment Gate

**Files:** Create `verify_official_sdk.py`, `tests/test_provenance.py` and a concise `README.md` under `docs/research/phase2-lite-q0/`.

**Interfaces:**
- Produce `verify_official_sdk.verify(venv_python: str, wheel_path: str, output: str) -> dict[str, object]`.
- Return at least `source_commit`, `sdk_version`, `wheel_sha256`, `source_verified`, `dependency_versions`, `platform`, `python_version` and `qualification_eligible`.
- Emit a private JSON record even on failure; any source mismatch ⇒ `qualification_eligible=false` and no downstream probe.

- [ ] **Step 1: Add provenance tests** `test_pinned_official_wheel`, `test_wrong_wheel_hash_fails`, `test_missing_sse_dependency_fails`, `test_wrong_python_or_platform_is_not_native_qualified`. Assert wheel digest equals `666edb5009503e1047c9d60346a756f94b261f05cc2625f23d41c728ffc484d0`, package metadata is `1.30.0`, installed source matches all official manifest entries, and importing `httpx_sse` and `sse_starlette` succeeds. No partial import shim.
- [ ] **Step 2: Run tests against bad fixtures first**. Command: `$Q0_VENV/bin/python -m pytest -q docs/research/phase2-lite-q0/tests/test_provenance.py`. Expected: explicit invalid fixture rejected; tests PASS when fail-closed rules are enforced (before implementation, missing function must first fail).
- [ ] **Step 3: Implement the minimal verifier**. Do not install into Gateway's `.venv`. In a new disposable venv, freeze the complete environment; reference reviewer versions for parity (Python 3.14.7, Starlette 0.52.1, AnyIO 4.15.1, Uvicorn 0.54.0, HTTPX 0.28.1, httpx-sse 0.4.3, sse-starlette 3.5.0, Pydantic 2.13.5). Any version variation is a *new experiment* and must be labeled separately.
- [ ] **Step 4: Re-run tests and record exact sources**. Assert PASS for negative fixture detection and official source verification; record raw stdout/stderr only under a new, user-authorized private output root, never the Git checkout.
- [ ] **Step 5: Review and commit research files only** (after separate approval): one small commit with no SDK source or product files.

### Task 2: Q0 Falsey-Related-ID Red/Green Qualification Probe

**Files:** Create `probe_related.py` and `tests/test_related_cases.py`.

**Interfaces:**
- Produce `probe_related.run_cases() -> list[dict[str, object]]`; each record has `case_id`, `wire_id_type`, `wire_id_value`, `emitter_api`, `related_metadata_type`, `related_metadata_value`, `route_owner`, `delivered_to_request_stream`, `get_fallback_observed`, `http_status`, `final_response_id_matches` and `protocol_contract_pass`.
- Provide distinct command modes `--diagnose` (0 only if observations are complete) and `--qualify` (nonzero whenever a mandatory protocol case fails or probe is invalid). Do not equate diagnostic success to qualification PASS.
- Import official SDK only from the verified isolated venv. Record real FastMCP→Session→transport→HTTPX ASGI behavior, not a mock protocol implementation. Intercept `Popen` with a test guard that fails if called.

- [ ] **Step 1: Write negative tests**:
  - `test_ctx_empty_routes_to_real_request`: empty string request, `ctx.info`, assert actual related metadata preserves empty ID and request-stream delivery; **expected FAIL on original 1.30.0**.
  - `test_progress_empty_routes_to_real_request`: same for `ctx.report_progress`; **expected FAIL**.
  - `test_raw_zero_and_empty_keep_related_metadata`: direct Session log API for IDs integer 0 and empty string; **expected FAIL**.
  - `test_http_success_does_not_promote_missing_related_to_pass`: even HTTP 200, correct wire type/value and correct final tool output must leave `protocol_contract_pass=false` if related metadata/stream lost.
  - `test_distinct_typed_71_post_results`, `test_fastmcp_zero_contrast`, `test_get_not_assumed_absent`: retain working 71/"71" per-POST response and related-message positives, distinguish high-level "0" vs raw 0, and confirm GET route behavior.
  - `test_observer_does_not_mutate_transport`: observer/delegate and uninstrumented control produce the same failure class; all route mutations are made by upstream SDK only.
  The contract test must assert internal routing, not only the HTTP result. Representative intended assertion (RED under official SDK):

  ~~~python
  row = by_case["CTX_EMPTY"]
  assert row["final_response_id_matches"] is True
  assert row["related_metadata_value"] == ""
  assert row["delivered_to_request_stream"] is True
  ~~~

- [ ] **Step 2: Run RED against official original SDK**. Expected: the first four **contract** tests fail on the known defect; observational provenance and positive controls pass. If negative tests unexpectedly pass, STOP and check test validity and source/fixture parity before asserting any fix.
- [ ] **Step 3: Implement the minimal diagnostic collector** in `probe_related.py`. It must report the expected broken SDK behavior faithfully. **Do not fix or work around the SDK**. Distinguish `observed_matches_independent_review=true` from `protocol_contract_pass=false`.
- [ ] **Step 4: Add gate tests** `test_qualify_fails_when_known_falsey_case_fails` and `test_diagnostic_collected_evidence_does_not_mean_qualified`. Expected: `--qualify` exits nonzero (recommend 2) and machine summary states `Q0=FAIL/BLOCK` while original SDK reproduces the four negatives; `--diagnose` may exit 0 if collection itself was valid.
- [ ] **Step 5: Repeat clean, instrumented and uninstrumented runs**. Confirm the same wire IDs, real transport owner, stream delivery and final responses; preserve counterexample and positive-control raw evidence privately. Do not start products, listeners or real work.
- [ ] **Step 6: Review and commit research-only probe changes** after separate approval; no SDK replacement or acceptance-criteria edits.

### Task 3: Reachability and “No Related Messages” Feasibility Inventory

**Files:** Create `inventory_emissions.py` and `tests/test_emission_inventory.py`.

**Interfaces:**
- Produce `inventory_emissions.scan(source_root: str, gateway_root: str, dynamic_probe: str) -> dict[str, object]` with `emitters[]`. Each entry has `source_file`, `callable`, `message_kind`, `trigger`, `reachable_via_lite`, `reachability_evidence`, `sdk_generated`, `app_controlled` and `coverage_status`.
- Analyze exact official `mcp` and current pinned Gateway code; no general SDK rewrite. The inventory is evidence of all known outgoing paths, not an assertion that dynamic code cannot exist.

- [ ] **Step 1: Add inventory tests** `test_ctx_log_and_progress_are_in_inventory`, `test_lowlevel_send_log_message_is_in_inventory`, `test_sdk_generated_error_and_progress_token_paths_are_classified`, `test_unknown_emitter_blocks_scope_claim` and `test_no_related_scope_requires_dynamic_evidence`.
- [ ] **Step 2: Fail the tests before implementing inventory**; the missing scanner and unknown-emitter negative must be observable.
- [ ] **Step 3: Inspect call sites and build graph** around `Context.request_id`, `Context.info`, `Context.report_progress`, `ServerSession.send_log_message`, `ServerMessageMetadata`, request/related metadata, GET fallback, errors, progress tokens and any discovered server-initiated message path. For every “not reachable from Lite” claim, name exact gateway registration and SDK code path, not an absence-of-log assertion.
- [ ] **Step 4: Exercise the classification with synthetic FastMCP tools** including success, tool error, cancellation before dispatch and after dispatch, initialization, tools/list, tool result and explicit Context helper calls. Observe whether SDK generates related messages without application `ctx.info/progress` calls; no Popen permitted. A path not dynamically exercised must stay `NOT_RUN` or `UNKNOWN`.
- [ ] **Step 5: Re-run inventory tests** and export `emissions.json` with explicit UNKNOWN counts and counterexamples. Any unclassified reachable or plausible SDK-generated emitter blocks a blanket no-related-message claim.
- [ ] **Step 6: Independent review** of the actual SDK API and transport source inventory before treating this as an architectural input; research-only commit if authorized.

### Task 4: Q0 Decision Gate and Public/Private Handoff

**Files:** Create `decide_q0.py`, `tests/test_decision_gate.py`; extend research `README.md`.

**Interfaces:**
- Produce `decide_q0.decide(provenance: dict[str, object], cases: list[dict[str, object]], inventory: dict[str, object], contract: str) -> dict[str, object]`.
- Return `current_contract_status` and `next_action` from only:
  - `FAIL_BLOCK_ORIGINAL_SDK` / `STOP_PRODUCT` — any mandatory legal-ID related notification fails under the existing PR #8 contract (current expected outcome).
  - `LIMITED_SCOPE_DESIGN_CHANGE_REQUIRED` / `REQUEST_EXPLICIT_SPEC_APPROVAL` — only if a candidate no-related-message application scope is evidenced across relevant SDK automatic/error paths, but it **does not qualify the existing contract**.
  - `PASS_FULL_CONTRACT` / `PROCEED_TO_Q1_PLANNING` — only if *all* specified legal-ID, Context, raw Session and ownership cases satisfy the original protocol contract with official unmodified SDK and full independent review.
  - `INVALID_OR_NOT_RUN` / `REPAIR_PROBE_ONLY` — environment/source/check failure or missing mandatory evidence.
- Never infer `PASS_FULL_CONTRACT` from absence of client logs, a client that happens to use only integers, final JSON correctness, or a manually excluded emitter.

- [ ] **Step 1: Write failure-closed decision tests**:
  - `test_four_known_falsey_failures_force_stop`: valid provenance + four known failures ⇒ `FAIL_BLOCK_ORIGINAL_SDK`, exit nonzero.
  - `test_json_success_never_overrides_related_loss`: HTTP 200 + related loss ⇒ STOP.
  - `test_unknown_emission_path_cannot_be_silently_excluded`: UNKNOWN ⇒ `INVALID_OR_NOT_RUN` or STOP, not PASS.
  - `test_limited_scope_cannot_upgrade_existing_contract`: fully evidenced app-only scope ⇒ `LIMITED_SCOPE_DESIGN_CHANGE_REQUIRED`, **not** SDK PASS.
  - `test_invalid_wheel_or_missing_probe_blocks`: fail provenance or skip ⇒ `INVALID_OR_NOT_RUN`.
  - `test_full_pass_requires_complete_independent_evidence`: all cases truly pass + reviewed coverage ⇒ only then a candidate PASS; review is still required before product.
- [ ] **Step 2: Run RED** with deliberately inconsistent synthetic evidence (e.g. diagnostic exit 0 but SDK protocol FAIL). Expect prior or absent gate to mishandle it, then fix gate only, never change evidence.
- [ ] **Step 3: Implement the pure decision function**, validate required fields and stable severity order, ensure public summary can be generated only from approved redacted fields.
- [ ] **Step 4: Run GREEN tests** with both broken original SDK fixture and synthetic all-good fixture. **Real original SDK is expected to remain FAIL/BLOCK**; green tests mean the decision algorithm correctly refuses it, not SDK qualification PASS.
- [ ] **Step 5: Produce the fixed-version handoff**: `Q0_DECISION_PRIVATE.json`, full private run logs, `PUBLIC_Q0_SUMMARY.md`, full commands, exact source/dependency hashes, failing/positive cases and a next-step choice. Strip paths, usernames, secrets, local tunnel keys and raw request bodies before any public commit.
- [ ] **Step 6: Ask for human + independent architectural review**. Do not silently edit PR #8's approved/conditional spec or PR #7 historical evidence.

## Conditional next phases — separate plans only after Q0 resolution

| Phase | Future isolated question | Entry condition | Exit / STOP |
| --- | --- | --- | --- |
| Q1: SDK transport cleanup | Real zero-buffer F2 backpressure, send failure, GET/SSE/DELETE, natural HTTP disconnect, both memory-stream endpoints, lingering tasks while listener stays alive | Existing protocol Q0 passes **or** newly reviewed and explicitly approved constrained contract | Any original SDK cleanup/cross-request corruption ⇒ FAIL/BLOCK; no Gateway exec |
| Q2: service-owner model | Detached **synthetic** Service/Supervisor survives SDK ASGI cancellation and owns ticket, timeout, permit and worker lifecycle | Q0 decision permits continued Lite research; separate approved model/probe plan | Early FD/permit release, double spawn, lost timer or improper shutdown ⇒ BLOCK; model PASS does not qualify native cwd/PGID |
| Q3: real client compatibility | Synthetic tools only; ChatGPT Web/Tunnel IDs, POST/GET/SSE, request lifespan, disconnect/retry and max synchronous wait | User's **separate** authorization to use live client/tunnel + Q0/Q1 appropriate gate | Incompatibility or unauthorized provenance ⇒ STOP; no real business command |
| Native task independent of Q0 | macOS cwd/Pipfile valid spawn/race, PGID safe identity/reap, SIGTERM drain | Separate product-mechanism spec and human authorization; Q0 not its permission source | Any normal-start failure, wrong signal or leaked lease ⇒ BLOCK |

Q0 known failure may render later SDK-dependent stages unnecessary. A reviewer may approve *independent informational investigation* while Q0 is FAIL, but results must not be used to declare Phase 2 Lite eligible.

## Final verification checklist and execution handoff

- [ ] Fixed source/SDK provenance and review ZIP SHA proven; no private paths in public files.
- [ ] Four known failures **reproduced or transparently marked changed evidence**; zero skipped mandatory Q0 checks.
- [ ] HTTP success is explicitly separate from related-message qualification; no test rewrites the wire ID or upstream transport.
- [ ] Static/dynamic inventory names every known emission path or preserves UNKNOWN; no silent scope reduction.
- [ ] Qualification gate returns nonzero and `FAIL/BLOCK` when legal-ID route remains broken; limited-scope alternative requires a **new** approved design.
- [ ] Independent reviewer verifies full raw evidence and public summary before any implementation proposal.
- [ ] PR #8 remains Draft; SDK product qualification, cwd/PGID native qualification and Phase 2 Lite remain BLOCK; no Gateway code, SDK fork, real client or business command executed by this plan.

**Review requested:** confirm the tasks, exact stop rules and evidence policy before granting permission to implement *isolated research probes only*. Even approval to execute those probes is not authorization to merge, deploy, enable Multi exec or rewrite official SDK.
