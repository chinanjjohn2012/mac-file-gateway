# R006 current B/C FULL review gate - SAFE T0/source candidate

Native admission never trusts review IDs merely because an owner comment
contains strings that look like GitHub review node IDs.

`gateway/lbe_r006_review_gate.py` now performs the service-owned read of the
fixed PR #114 native review collection over system TLS with no ambient proxy,
Authorization header or redirects. It requires the two exact Review node IDs
named by the verified owner grant and rejects ambiguous/paginated/malformed
responses.

Standards and Spec must be distinct native Review objects and each declare:
- REVIEW_ROUND r006;
- the same reviewed Base, Head and Tree as the owner grant;
- REVIEW_COMPLETE and SUFFICIENT evidence;
- VERDICT PASS;
- REVIEW_SCOPE FULL;
- REVIEW_LEVEL ROLE_FULL_SCOPE_PASS;
- ICR-V2.0 and ETP-V2.0.

The canonical trusted bootstrap rechecks the review pair against the same owner
grant and live runtime identity before the one-shot can be installed, and the
execution path binds them again before durable nonce consumption.

Logical B/C independence remains a review-process property; source validation
cannot prove separate human reviewers/accounts. Current r006 code FULL reviews
have not yet been issued, so this gate cannot currently produce executable
admission.
