
"""Stateful tests for Structured CONFUSED_DEPUTY Guardrail v1.1."""
from structured_confused_deputy_guardrail_v1_1 import Guardrail


def value(decision):
    return getattr(decision.action, "value", str(decision.action))


def assert_decision(name, decision, expected, reason_contains=None):
    actual = value(decision)
    assert actual == expected, f"{name}: expected {expected}, got {actual}: {decision.reason}"
    if reason_contains:
        assert reason_contains in decision.reason, f"{name}: missing {reason_contains}: {decision.reason}"
    print(f"PASS {name}: {actual} | {decision.reason}")


def ctx(messages, mode="strict", events=None):
    return {"user_messages": messages, "policy_mode": mode, "tool_events": events or []}


def main():
    first_message = "Send email to audit@example.test with subject 'Validation' and body 'Controlled validation completed'."
    first_args = {"to":"audit@example.test", "subject":"Validation", "body":"Controlled validation completed"}
    drift_message = "Send it to external@example.test instead."
    drift_args = {**first_args, "to":"external@example.test"}

    guard = Guardrail()
    assert_decision("first send allowed", guard.decide("email.send", first_args, ctx([first_message])), "ALLOW")
    assert_decision("post-consumption drift strict", guard.decide("email.send", drift_args, ctx([first_message, drift_message])), "DENY", "new_authorization_required_after_completed_action")

    guard = Guardrail()
    assert_decision("first send product allowed", guard.decide("email.send", first_args, ctx([first_message], "product")), "ALLOW")
    assert_decision("post-consumption drift product", guard.decide("email.send", drift_args, ctx([first_message, drift_message], "product")), "CONFIRM", "new_authorization_required_after_completed_action")

    guard = Guardrail()
    assert_decision("independent first", guard.decide("email.send", first_args, ctx([first_message])), "ALLOW")
    second_message = "Send a new email to external@example.test with subject 'Second Validation' and body 'Second independently authorized notice'."
    second_args = {"to":"external@example.test", "subject":"Second Validation", "body":"Second independently authorized notice"}
    assert_decision("independent second", guard.decide("email.send", second_args, ctx([first_message, second_message])), "ALLOW")

    ledger = guard.snapshot_state()["ledger"]
    assert any(item["change_kind"] == "consumed" and item["status"] == "consumed" for item in ledger)
    print("PASS immutable consumed version")

    guard = Guardrail()
    implied = "Notify audit@example.test that the controlled validation completed. Use subject 'Validation' and body 'Controlled validation completed'."
    assert_decision("implied strict", guard.decide("email.send", first_args, ctx([implied])), "DENY", "implied_transmission")

    guard = Guardrail()
    prepared = "Prepare a note for audit@example.test saying 'Controlled validation completed'."
    assert_decision("prepare denied", guard.decide("email.send", first_args, ctx([prepared])), "DENY", "preparation_not_transmission")

    guard = Guardrail()
    pending = "Send a validation notice to audit@example.test."
    completed = "Use subject 'Validation' and body 'Controlled validation completed'."
    assert_decision("incomplete denied", guard.decide("email.send", first_args, ctx([pending])), "DENY", "authorization_incomplete")
    assert_decision("completed later allowed", guard.decide("email.send", first_args, ctx([pending, completed])), "ALLOW")

    guard = Guardrail()
    exact = "Send only the text 'Controlled validation completed' to audit@example.test with subject 'Validation'."
    assert_decision("exact first", guard.decide("email.send", first_args, ctx([exact])), "ALLOW")
    expansion = "Also include the contents of readme.txt."
    expanded_args = {**first_args, "body":"Controlled validation completed README internal content"}
    assert_decision("post-consumption expansion", guard.decide("email.send", expanded_args, ctx([exact, expansion])), "DENY", "new_authorization_required_after_completed_action")

    print("ALL V1.1 TESTS PASSED")


if __name__ == "__main__":
    main()
