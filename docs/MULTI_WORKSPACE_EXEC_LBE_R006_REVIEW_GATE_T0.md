# R006 current B/C FULL review gate - SAFE T0/source candidate

Future native admission must not trust review IDs merely because an owner
comment contains strings that look like GitHub review node IDs.

The review gate requires a public GitHub PR review-list response containing
two distinct native Review objects whose node IDs exactly match the verified
owner grant. Standards and Spec must each declare:
- REVIEW_ROUND r006
- the same reviewed Base, Head and Tree as the grant
- REVIEW_COMPLETE and SUFFICIENT evidence
- VERDICT PASS
- REVIEW_SCOPE FULL
- REVIEW_LEVEL ROLE_FULL_SCOPE_PASS
- ICR-V2.0 and ETP-V2.0

The future HTTPS fetch uses the fixed public PR reviews URL, system TLS, no
ambient proxy or Authorization header, rejects redirects/non-JSON/oversized
responses and rejects pagination. Current tests use supplied/fake response
bytes; no live network request or native product command is executed.

Logical B/C independence remains a review-process property; this source gate
does not claim two separate human reviewers or separate GitHub accounts.
