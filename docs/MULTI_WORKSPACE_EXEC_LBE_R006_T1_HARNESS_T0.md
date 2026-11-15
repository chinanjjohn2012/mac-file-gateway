# R006 tracked T1 harness - SAFE SOURCE/T0 candidate

The candidate now contains the tracked orchestration source a future authorized
PRODUCT_T1 job will use, so no ad-hoc execution script needs to be added after
B/C freeze.

The harness accepts only a private one-link 0600 canonical source-bundle JSON
whose complete bytes match an independently supplied SHA256. It does not
download, discover or approve source. Existing WorkspaceService code performs
the deep Go P007, Pipenv RECORD, staged-runtime and first-party rechecks.

Order is fixed: reviewed source bundle -> service-owned prepared attempt ->
canonical direct-owner + current B/C FULL + G05/live-run bootstrap -> one
private one-shot installed into the shared invoke_exec gate. The harness never
calls invoke_exec, REST, MCP or Popen.

Real T1 still requires a separately reviewed qualification bundle and digest,
current frozen-head B/C FULL reviews, a direct repository-owner exact run
grant, and explicit user T1 authorization. PRODUCT_T1 remains NOT_RUN.
