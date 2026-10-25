# F1 deny-only product migration traceability

**Review base:** approved F0 design PR #69, Head `4110fac4edf2027703f4ce830a4d46718de4804d`, Tree `e3b911d921f7a6fd812bca92450eb759f2a61805`.

**Historical source:** `tests/test_multi_exec_product.py` at this exact immutable F0 Head, plus original GitHub Action #40123817169 (1468 passed / 8 skipped / 1 warning). Those older positive subprocess results remain discoverable as historical evidence, **not F1 passing behavior**. This table is the explicit contract-by-contract F1 rewrite justification required by D0 §0.3 and the F0/F1 implementation plan. Do not skip old tests and call them GREEN.

| Historical test/contract | F1 retained executable coverage | Future F3 positive-real-Exec obligation |
|---|---|---|
| configuration two opt-ins / bad scopes | existing `test_config_requires_two_gates_and_canonical_scopes`, `test_global_off_defaults_to_no_exec` unchanged | none |
| per-Workspace preview and real child stdout / exit code | `test_exec_preview_and_proof_deny_are_workspace_scoped` and `test_f1_physical_no_prep_or_runner_and_proof_before_busy` test legal preview, missing-proof reject, disabled workspace | actual child stdout/exit code; only after independent native full-tree proof |
| REST invalid typed requests, legal preview, real child apply | `test_rest_explicit_routing_and_types` and `test_f1_real_rest_sdk_mcp_and_status_policy` cover real REST, 503 and no intent | REST positive child apply after F3 proof |
| same-Workspace lease / close waits | `test_worker_lease_blocks_same_workspace_and_close_waits` now exercises a safe synchronous preview Worker | actual spawned-child lifecycle and full descendants after F3 |
| official SDK MCP registry and real child stdout | `test_mcp_registry_and_grants` plus `test_f1_real_rest_sdk_mcp_and_status_policy` validate legal preview and structured machine-readable denial | real MCP child output after F3 |
| five different Workspaces / four leased slots | `test_global_four_slots_reject_fifth_until_one_releases` now exercises 4 concurrent preview workers plus proof-before-busy | four real children, durability and cleanup after F3 |
| CLI opt-in status | `test_cli_reports_actual_exec_state` now requires truthful enabled-preview vs denied-apply text; `test_f1_real_rest_sdk_mcp_and_status_policy` tests honest `available=false` | positive Exec status only after F3 proof |
| REST ASGI disconnect with actual Python child | `test_asgi_rest_disconnect_keeps_sync_preview_worker_until_exit` uses a deterministic blocked preview through real Starlette/ASGI; no child spawned | actual child/disconnected and descendant cleanup require F3 native tests |
| cancelled MCP waiter and leased Worker | `test_cancelled_mcp_tool_waiter_does_not_release_sync_worker` uses deterministic blocked preview in real SDK tool path | actual child after F3 |
| independent Git, File grants, UNKNOWN/quarantine | `test_f1_same_service_real_git_and_file_write_survive_exec_quarantine` uses **real authorized Git apply subprocess** and real File Write apply in the same Exec-enabled service even after UNKNOWN/quarantine | no Exec spawn; Git has a distinct approved executor |

**Cross-checks:** `gateway/workspaces.py` enforces no-proof denial before busy/runner/physical PREPARED; `gateway/http_multi.py` and `gateway/mcp_multi.py` route through that same synchronous worker, HTTP 503 and MCP isError+structuredContent.error; `gateway/http.py` maps errors. The approved B1-B1-A `_IntentWitness` is reused for physical write/open/link/rename/unlink observation; test-only witness scope does not imply a kernel audit or a production OS sandbox.

**F1 safety limit:** never launch a positive Exec child, use a Private Bridge/test-grant or claim descendant cleanup. Historical macOS positive child lifecycle `tests/smoke_multi_exec_macos.py` remains in Git history as F3 evidence; it must not be silently reclassified as an F1 pass. No macOS ARM64/native, Tunnel, merge, deployment, process group signals, or automatic unquarantine are authorized by this F1 implementation.
