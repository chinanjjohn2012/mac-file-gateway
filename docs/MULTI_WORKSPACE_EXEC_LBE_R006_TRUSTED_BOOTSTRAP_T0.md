# R006 canonical trusted bootstrap bundle - SAFE T0/source candidate

Future private native admission must not accept arbitrary parser-produced owner
grant and review objects supplied by a caller. The canonical bootstrap performs
the service-owned public GitHub owner-comment fetch first, then the current
r006 B/C FULL review-list fetch, verifies their exact snapshot relationship and
returns one process-bound bundle.

The current product has no public route to this bootstrap. Unit tests replace
both fetchers and perform no network request. A later private execute path may
accept only this bundle, then still must bind the current plan/recipe, fixed
macOS selected-source profile and durable nonce before Worker reservation.

This is not an exact T1 approval and does not enable public Exec or Popen.
