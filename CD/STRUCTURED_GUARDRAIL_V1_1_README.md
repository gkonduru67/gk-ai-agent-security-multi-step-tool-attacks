# Structured CONFUSED_DEPUTY Guardrail v1.1

This is a standalone replacement file. It does not modify SDK `base.py` or `optimal.py`.

## Files
- `structured_confused_deputy_guardrail_v1_1.py`
- `test_structured_confused_deputy_guardrail_v1_1.py`

## Main correction
A partial or elliptical instruction after a successful email enters `pending_reauthorization`; the consumed email's subject, body, and execution authority are not inherited. Strict mode denies and product mode confirms. A genuinely new, fully specified email marked as new/another/separate can create independent authority.

## Audit correction
Consumption is appended as a new immutable authorization version with `change_kind="consumed"`.

## Run tests
```powershell
python test_structured_confused_deputy_guardrail_v1_1.py
```

## Frozen replay
Use the existing validator with:
```powershell
--guardrail-file "structured_confused_deputy_guardrail_v1_1.py"
```
Expected strict result: 27/27 acceptance, `ALLOW=12`, `DENY=15`.
