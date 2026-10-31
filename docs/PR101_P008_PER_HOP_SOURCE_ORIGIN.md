# PR #101 — P008 pre-contact HTTPS redirect origin hardening

TASK_ID: MULTI-EXEC-LBE-V1-CONSOLIDATED-20261030
PROPOSAL_ID: PR101-P008-SOURCE-REDIRECT-PER-HOP-20261031
ROLE: A DEVELOPER (NOT independent Standards/Spec reviewer)
REVIEW_SCOPE: TARGETED source-only B101-SRC-P3-01 original B Standards review
ORIGINAL_TARGETED_REVIEW: B PRR_kwDOU5v3IM8AAAABVLLvLA at earlier HEAD 7b94a54543db48af4760490f2bc6c70823d7cf2a
REVIEW_TARGET: P001 exact official Go 1.27.3 archive, Pipenv 2026.10.4 PyPI release JSON and exact pinned main Wheel, NO other external artifact
RULES: ICR-V2.0/GHRH-2.0/ETP-V2.0, confirm current effective source identity/round separately
FIX_HEAD: dynamic GitHub PR #101 after commit and current original CI, not this documentation

## Finding, scope and negative case

The original P001 source-only CI used curl --location plus a **final effective URL** host check. That rejects an unapproved final origin but might contact a forbidden intermediate HTTPS host in an approved-host -> forbidden-host -> approved-host redirection chain BEFORE checking final origin. The fixed source SHA rejects replaced bytes but cannot retroactively prevent that outbound network contact.

Replace the three P001 source-only fetches with the standard-library source-only P008 fetcher, using a redirect handler that DOES NOT automatically follow redirects. Before each HTTP request, including a redirected request, validate an exact HTTPS scheme, approved host+path and source kind with no credentials, unusual port, query, fragment, percent-escaped bypass, dot components or control characters. After receiving a redirect (up to three hops), reject an out-of-scope Location **before opening the connection**. Reject loops, auto-follow, malformed metadata, oversize or absent source. Do not change the downloaded source names, target versions, hash locks, install, compiler execution or runtime.

Known approved source URI families:
- Go: https://go.dev/dl/go1.27.3.darwin-arm64.tar.gz to its exact official https://dl.google.com/go/go1.27.3.darwin-arm64.tar.gz or exact official https://storage.googleapis.com/golang/go1.27.3.darwin-arm64.tar.gz only (if a redirect chain uses a different path, FAIL_CLOSED, do not silently broaden).
- Pipenv release JSON: exactly https://pypi.org/pypi/pipenv/2026.10.4/json.
- Pipenv main Wheel: only exact source-pinned filename ending pipenv-2026.10.4-py3-none-any.whl at https://files.pythonhosted.org/packages/.../ on an explicitly validated package URL from official JSON.
- Complete real Go compressed SHA256 dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2, exact compressed size 68196737.
- Complete actual Pipenv main Wheel SHA256 308125623e4d08dfe32936f7259a9ed33c5480baa2c9a291a1ff8a9328eeeb1f, with existing P001 additional Wheel RECORD check following fetch.

A standalone offline standard-library fake opener tests the positive approved metadata path; approved redirect to a synthetic nonmatching archive must fail on SHA; approved -> evil.example.org -> approved, spoof host, unexpected path/port/scheme, metadata-to-wheel redirect, redirect loop, wrong auto redirect, missing/evasive destination and source overwrite must all fail before unauthorized open. The fake opener has zero external networking; real download still occurs ONLY on permitted hosted disposable macOS CI and is byte-locked by the unchanged P001 source attestation and Go P007 stage.

## Explicit remaining gaps

This is network-origin policy hardening only. It is not an assessment of the full original Go compiler/stdlib, Pipenv benchmarks, independent publisher attestation or all nine Wheel source code. It does not authorize or execute Go test/vet/build, Pipenv run/venv, T2/T3, OS signals, user Mac/Tunnel or production. The C P1/P2 targeted fixes remain A candidates until separately reviewed on new Head; B original external source full security BLOCKED. All source SHA/ZIP/RECORD, Manifest and ETP identity must be checked against original GitHub CI **on the new Head**; earlier successes cannot be inherited. A does not publish either B or C's independent PASS. R10 and full integration still BLOCKED.
