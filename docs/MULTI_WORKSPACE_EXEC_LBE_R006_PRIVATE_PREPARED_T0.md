# R006 private prepared-attempt flow - SAFE T0/source candidate

The private product flow is intentionally split into two stages.

1. **Prepare**: the service stages and rechecks the existing first-party,
   operator, Mach-O and private dylib sources, observes the fixed macOS
   selected-source profile, and returns one in-process D4R006PreparedAttempt.
   It holds only a lifecycle lease and does not reserve an executable slot.
   The owner can see the exact product recipe fingerprint before approving it.
2. **Execute candidate**: the same prepared object is burned once. The service
   rechecks eligibility, binds an exact verified owner grant to the same plan,
   recipe, Head/Tree/Manifest, GitHub run/attempt and fixed host profile,
   durably consumes the nonce, then reserves the Worker slot. Only then can
   the private R006 Runner boundary be constructed.

No REST/MCP/config/public invoke_exec path calls either private method.
A failed binding burns the in-memory prepared candidate; a successfully
consumed nonce is never released. Tests replace the native launch method with
a no-child witness or fake Popen. Real PRODUCT_T1 remains NOT_RUN and needs a
separate exact owner run authorization plus current B/C code review.
