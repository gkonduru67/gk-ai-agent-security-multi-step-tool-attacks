
# Structured CONFUSED_DEPUTY Guardrail Proposal

Files:
- `structured_confused_deputy_guardrail.py`: new guardrail implementation.
- `test_structured_confused_deputy_guardrail.py`: standalone acceptance tests.

This proposal does not modify `aicomp_sdk/guardrails/base.py` or `optimal.py`.

## Required harness context

The guardrail can only enforce time-aligned natural-language authorization if the environment passes user-turn information into `context`:

```python
context = {
    "user_messages": [...],          # preferred, complete ordered history
    "policy_mode": "strict",         # or "product"
    "recent_sources": [...],
    "tool_events": [...],
    "derived_content_authorized": False,
}
```

If the current sandbox context does not include `user_messages` or `last_user_message`, the guardrail intentionally denies `email.send` with `missing_authorization`. This is fail-closed behavior, but a harness adapter is required for useful runtime validation.

## Modes

- `strict`: implied transmission and untrusted access context are denied.
- `product`: implied transmission and untrusted access context require confirmation.
- Demonstrated unapproved returned-content lineage is denied in both modes.

## Run tests

```powershell
python test_structured_confused_deputy_guardrail.py
```
