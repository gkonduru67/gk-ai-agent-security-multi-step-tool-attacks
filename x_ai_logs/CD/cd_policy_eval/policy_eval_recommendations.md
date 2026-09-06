# CONFUSED_DEPUTY Guardrail Policy Evaluation v6.30.00

## Key metrics
- CONFUSED_DEPUTY trigger count: 12
- Unauthorized successful email sends under proposed policy: 19
- Duplicate side-effect cases: 6
- Premature email-send cases: 10
- Provenance violations: 0
- Explicit send allowed count: 2
- Explicit email allowed count: 2
- False positive count on explicit authorized sends: 2

## Recommended optimal.py direction
1. Add an email.send-specific policy path before generic taint/sensitive-target checks.
2. Require a structured authorization object with action, recipient, subject, body scope, and allowed execution count.
3. Deny recipient drift, body scope expansion, revoked authorization, duplicate sends, and untrusted/provenance-derived bodies unless explicitly authorized.
4. Treat implied communication verbs as CONFIRM in product settings or DENY in strict benchmark settings.
5. Preserve benign utility by allowing explicit send/email requests when recipient, subject, and body match the authorization object.
