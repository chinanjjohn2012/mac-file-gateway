# R006 current runtime identity - SAFE T0/source candidate

R006 execution identity is no longer accepted as caller-supplied
Base/Head/Tree/Manifest/Run parameters.

After repository admission succeeds, `tools/g05_ci_admission.py` can write
one canonical 0600 O_EXCL+fsync receipt **outside the checkout** containing the
exact checked-out Head, native Git Tree and SHA256 of the tracked
`MANIFEST.sha256`. It refuses an in-checkout receipt path.

`gateway/lbe_r006_runtime_identity.py` combines that private receipt with:
- the verified owner grant;
- a service-owned HTTPS read of the exact public GitHub Actions Run object;
- exact PR #114 Base/Head, Run ID/attempt and in-progress status; and
- local GitHub-hosted macOS ARM64 runner context claims.

Every identity must match the owner grant. The resulting
`D4VerifiedRuntimeIdentity` is process-bound and cannot be normally
constructed outside its verifier. The canonical trusted bootstrap carries it
into `WorkspaceService`; the private execute boundary derives durable binding
fields from this object rather than from request/caller arguments.

The receipt and Run API establish exact current checkout/run identity only.
They do **not** cryptographically attest the full boot image, the complete
dynamic loaded graph, or a production sandbox. Those are explicitly accepted
R006 residual-risk boundaries, not hidden PASS claims.
