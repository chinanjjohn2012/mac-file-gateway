# R006 owner grant trusted-bootstrap source candidate

The new bootstrap has two separate responsibilities:

1. Future separately authorized network fetch: build the exact public GitHub
   issue-comment API URL from a numeric comment id, use HTTPS system trust,
   disable ambient proxies, send no authorization/secret header, reject
   redirects/non-200/non-JSON/oversized responses, then apply the strict
   repository-owner grant parser.
2. Pure T0 runtime binding: compare the verified grant to the exact internally
   checked LBE plan, fixed macOS selected-source observation, Base/Head/Tree,
   Manifest, GitHub Run ID/Attempt and expiry.

No normal product path invokes the network fetch yet. CI replaces the opener
with a fake and performs no external request. No F1 exception, Popen, native
PRODUCT_T1, T2/T3 or production action is enabled.
