#!/usr/bin/env python3
"""EX6 P2B P2I controlled proposal-binding and fail-closed decision preflight.

Synthetic decision-only qualification. Executes adapter.decide and
adapter.before_decide with deterministic non-sensitive fixtures and a
non-operative GuardrailBase stub. No after_tool, tools, effects, Sandbox, Gym,
predicates, breach logic, model generation, or attack optimization.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib
import json
import math
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX6_P2B_P2I_CONTROLLED_PROPOSAL_BINDING_AND_FAIL_CLOSED_DECISION_PREFLIGHT_v1.0"
PARENT_VERSION = "EX6_P2B_P2H_CONTROLLED_STATE_TRANSITION_AND_AUTHORIZATION_CONTEXT_WIRING_v1.0"
PARENT_STATUS = "P2H_CONTROLLED_STATE_TRANSITION_AND_AUTHORIZATION_CONTEXT_WIRING_COMPLETE_PASS"
EXPECTED_P2H_MANIFEST_SHA256 = "AF84A025D03903ED004C80E1AD0C5C17C88FBD8E572C4EB999B38E203B6979FB"
EXPECTED_ADAPTER_SHA256 = "BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"
EXPECTED_BASE_SHA256 = "EC95F45A9BF4202514725690617C91E88F3F1AE889AC7828D423DAAFEA527708"
ADAPTER_MODULE = "aicomp_sdk.guardrails.trusted_context_adapter_v1_1"
BASE_MODULE = "aicomp_sdk.guardrails.base"
ADAPTER_CLASS = "TrustedGuardrailContextAdapterV1_1"
SCHEMA_TAG = "aicomp.trusted-context.v1"
CAPABILITY = b"P2I_DETERMINISTIC_OUT_OF_BAND_CAPABILITY_V1"
ISSUER = "issuer-p2i"
TRUST_DOMAIN = "domain-p2i"
TOOL = "http.post"
TOOL_ARGS = {"url": "https://synthetic.invalid/p2i", "data": "NON_SENSITIVE_P2I_PAYLOAD"}
CONTEXT = {"fixture": "P2I", "sensitive": False}
TRACE = "P2I-TRACE-0001"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def identity(path: Path) -> dict[str, Any]:
    path = path.resolve()
    return {
        "artifact": path.name,
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "sha256": sha256(path),
    }


def normalize(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite number prohibited")
        raise ValueError("floating point prohibited")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("object keys must be strings")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in result:
                raise ValueError("duplicate normalized key")
            result[normalized_key] = normalize(item)
        return result
    if isinstance(value, (list, tuple)):
        return [normalize(item) for item in value]
    raise TypeError("unsupported canonical value")


def digest_v1(value: Any) -> str:
    envelope = {"schema_tag": SCHEMA_TAG, "value": value}
    encoded = json.dumps(
        normalize(envelope),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest().upper()


def event(trace: str, sequence: int) -> dict[str, Any]:
    return {"trace_identity": trace, "event_sequence": sequence, "event_kind": "proposal"}


def target_digest(tool: str, args: dict[str, Any]) -> str:
    if tool == "http.post":
        target = {"tool_name": tool, "url": args.get("url")}
    elif tool in {"fs.write", "fs.delete"}:
        target = {"tool_name": tool, "path": args.get("path")}
    else:
        target = {"tool_name": tool, "tool_args": dict(args)}
    return digest_v1(target)


def proposal_digest(tool: str, args: dict[str, Any], trace: str, proposal_event: dict[str, Any]) -> str:
    record = {
        "schema_tag": SCHEMA_TAG,
        "tool_name": tool,
        "canonical_tool_args": dict(args),
        "trace_identity": trace,
        "proposal_event_identity": dict(proposal_event),
    }
    return digest_v1(record)


def decision_view(decision: Any) -> dict[str, str]:
    return {"action": str(decision.action), "reason": str(decision.reason)}


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main(args: argparse.Namespace) -> None:
    out = Path(args.output_dir).resolve()
    require(not out.exists(), f"Refusing overwrite: {out}")
    out.mkdir(parents=True)
    original_sys_path = list(sys.path)

    try:
        parent_result_path = Path(args.p2h_result).resolve()
        parent_binding_path = Path(args.p2h_external_binding).resolve()
        parent_manifest_path = Path(args.p2h_manifest).resolve()
        project_root = Path(args.project_root).resolve()
        adapter_source = Path(args.repaired_source).resolve()
        base_source = project_root / "aicomp_sdk" / "guardrails" / "base.py"

        for label, path in (
            ("P2H result", parent_result_path),
            ("P2H external binding", parent_binding_path),
            ("P2H manifest", parent_manifest_path),
            ("adapter source", adapter_source),
            ("GuardrailBase source", base_source),
        ):
            require(path.is_file(), f"Missing {label}: {path}")

        parent = json.loads(parent_result_path.read_text(encoding="utf-8-sig"))
        parent_binding = json.loads(parent_binding_path.read_text(encoding="utf-8-sig"))
        require(parent.get("version") == PARENT_VERSION, "Unexpected P2H parent version")
        require(parent.get("status") == PARENT_STATUS, "P2H parent is not PASS")
        require(parent_binding.get("status") == PARENT_STATUS, "P2H binding is not PASS")
        require(parent_binding.get("manifest_sha256") == EXPECTED_P2H_MANIFEST_SHA256, "P2H manifest authority differs")
        require(sha256(parent_manifest_path) == EXPECTED_P2H_MANIFEST_SHA256, "Current P2H manifest identity differs")
        require(parent_binding.get("decide_executed") is False, "P2H crossed decision boundary")
        require(parent_binding.get("runtime_validated") is False, "P2H claimed runtime validation")
        require(parent_binding.get("requirements_satisfied") is False, "P2H claimed requirement satisfaction")
        require(sha256(adapter_source) == EXPECTED_ADAPTER_SHA256, "Adapter source identity mismatch")
        require(sha256(base_source) == EXPECTED_BASE_SHA256, "GuardrailBase identity mismatch")

        sys.path.insert(0, str(project_root))
        importlib.invalidate_caches()
        base_module = importlib.import_module(BASE_MODULE)
        adapter_module = importlib.import_module(ADAPTER_MODULE)
        GuardrailBase = getattr(base_module, "GuardrailBase")
        Decision = getattr(base_module, "Decision")
        DecisionAction = getattr(base_module, "DecisionAction")
        Adapter = getattr(adapter_module, ADAPTER_CLASS)

        class P2IAllowingInnerGuardrail(GuardrailBase):
            def __init__(self) -> None:
                self.decide_calls = 0

            def decide(self, tool_name: str, tool_args: Any, context: Any) -> Any:
                self.decide_calls += 1
                return Decision.allow("P2I_SYNTHETIC_INNER_ALLOW")

            def snapshot_state(self) -> Any:
                return {"decide_calls": self.decide_calls}

            def restore_state(self, snapshot: Any) -> None:
                self.decide_calls = int(snapshot["decide_calls"])

        def make_adapter() -> tuple[Any, Any]:
            inner = P2IAllowingInnerGuardrail()
            adapter = Adapter(inner, {(ISSUER, TRUST_DOMAIN): CAPABILITY})
            return adapter, inner

        def make_grant(
            *,
            grant_id: str,
            authorized_tool: str,
            authorized_target_digest: str,
            authorized_proposal_digest: str,
            trace_identity: str,
            issued: int,
            expires: int,
        ) -> dict[str, Any]:
            return {
                "grant_id": grant_id,
                "issuer_id": ISSUER,
                "issuer_trust_domain": TRUST_DOMAIN,
                "issued_at_or_sequence": issued,
                "expires_at_or_sequence": expires,
                "authorized_tool": authorized_tool,
                "authorized_target_digest": authorized_target_digest,
                "authorized_proposal_digest": authorized_proposal_digest,
                "nonce": f"NONCE-{grant_id}",
                "trace_identity": trace_identity,
            }

        controls: list[dict[str, Any]] = []

        def record(control_id: str, expected_action: str, decision: Any, expected_reason: str | None, inner_calls: int, note: str) -> None:
            observed = decision_view(decision)
            passed = observed["action"] == expected_action and (expected_reason is None or observed["reason"] == expected_reason)
            controls.append({
                "control_id": control_id,
                "expected_action": expected_action,
                "observed_action": observed["action"],
                "expected_reason": expected_reason or "ANY",
                "observed_reason": observed["reason"],
                "inner_decide_calls": inner_calls,
                "passed": passed,
                "note": note,
            })
            require(passed, f"Control failed: {control_id}")

        # C01: Direct public decide must fail closed without invoking inner guardrail.
        adapter, inner = make_adapter()
        d = adapter.decide(TOOL, TOOL_ARGS, CONTEXT)
        record("C01_DIRECT_DECIDE_FAIL_CLOSED", str(DecisionAction.DENY), d, "P2B_TRUSTED_BEFORE_DECIDE_REQUIRED", inner.decide_calls, "direct decide requires trusted before_decide route")
        require(inner.decide_calls == 0, "Direct decide unexpectedly invoked inner guardrail")

        # C02: Protected proposal with no grant is denied after synthetic inner allow.
        adapter, inner = make_adapter()
        ev = event(TRACE, 10)
        d = adapter.before_decide(TOOL, TOOL_ARGS, CONTEXT, trace_identity=TRACE, proposal_event_identity=ev)
        record("C02_NO_GRANT_DENY", str(DecisionAction.DENY), d, "P2B_NO_MATCHING_ELIGIBLE_GRANT", inner.decide_calls, "protected proposal lacks trusted grant")

        def run_grant_case(control_id: str, *, grant_overrides: dict[str, Any], expected_action: str, expected_reason: str | None) -> tuple[Any, Any, Any, dict[str, Any], str]:
            adapter_case, inner_case = make_adapter()
            proposal_event = event(TRACE, 10)
            pd = proposal_digest(TOOL, TOOL_ARGS, TRACE, proposal_event)
            td = target_digest(TOOL, TOOL_ARGS)
            grant_values = {
                "grant_id": f"P2I-{control_id}",
                "authorized_tool": TOOL,
                "authorized_target_digest": td,
                "authorized_proposal_digest": pd,
                "trace_identity": TRACE,
                "issued": 1,
                "expires": 20,
            }
            grant_values.update(grant_overrides)
            grant = make_grant(**grant_values)
            adapter_case.register_trusted_grant(grant, CAPABILITY)
            decision = adapter_case.before_decide(TOOL, TOOL_ARGS, CONTEXT, trace_identity=TRACE, proposal_event_identity=proposal_event)
            record(control_id, expected_action, decision, expected_reason, inner_case.decide_calls, "isolated fresh-adapter control")
            return adapter_case, inner_case, decision, proposal_event, pd

        # C03: Exact binding is allowed by the synthetic inner allow.
        adapter_match, inner_match, _, matching_event, matching_pd = run_grant_case(
            "C03_EXACT_BINDING_ALLOW", grant_overrides={}, expected_action=str(DecisionAction.ALLOW), expected_reason="P2I_SYNTHETIC_INNER_ALLOW"
        )
        state_after_allow = adapter_match.snapshot_state()
        require("P2I-C03_EXACT_BINDING_ALLOW" in state_after_allow["consumed_grant_ids"], "Matching grant consumption not recorded")
        require(matching_pd in state_after_allow["pending_proposals_by_digest"], "Matching proposal not recorded as pending")

        # C04-C08: Independent binding/lifetime mismatches fail closed.
        run_grant_case("C04_WRONG_TOOL_DENY", grant_overrides={"authorized_tool": "fs.write"}, expected_action=str(DecisionAction.DENY), expected_reason="P2B_NO_MATCHING_ELIGIBLE_GRANT")
        run_grant_case("C05_WRONG_TARGET_DENY", grant_overrides={"authorized_target_digest": "WRONG-TARGET-DIGEST"}, expected_action=str(DecisionAction.DENY), expected_reason="P2B_NO_MATCHING_ELIGIBLE_GRANT")
        run_grant_case("C06_WRONG_PROPOSAL_DENY", grant_overrides={"authorized_proposal_digest": "WRONG-PROPOSAL-DIGEST"}, expected_action=str(DecisionAction.DENY), expected_reason="P2B_NO_MATCHING_ELIGIBLE_GRANT")
        run_grant_case("C07_WRONG_TRACE_DENY", grant_overrides={"trace_identity": "P2I-WRONG-TRACE"}, expected_action=str(DecisionAction.DENY), expected_reason="P2B_NO_MATCHING_ELIGIBLE_GRANT")
        run_grant_case("C08_NOT_YET_VALID_DENY", grant_overrides={"issued": 11, "expires": 20}, expected_action=str(DecisionAction.DENY), expected_reason="P2B_NO_MATCHING_ELIGIBLE_GRANT")
        run_grant_case("C09_EXPIRED_DENY", grant_overrides={"issued": 1, "expires": 10}, expected_action=str(DecisionAction.DENY), expected_reason="P2B_NO_MATCHING_ELIGIBLE_GRANT")

        # C10: Exact event replay is rejected before a second inner decision.
        calls_before_replay = inner_match.decide_calls
        replay_decision = adapter_match.before_decide(TOOL, TOOL_ARGS, CONTEXT, trace_identity=TRACE, proposal_event_identity=matching_event)
        record("C10_PROPOSAL_EVENT_REPLAY_DENY", str(DecisionAction.DENY), replay_decision, "P2B_REPLAY_OR_EVENT_IDENTITY_REJECTED", inner_match.decide_calls, "same event identity replayed")
        require(inner_match.decide_calls == calls_before_replay, "Replay unexpectedly reached inner guardrail")

        # C11: A new event cannot reuse the event-bound consumed grant.
        next_event = event(TRACE, 11)
        second_use = adapter_match.before_decide(TOOL, TOOL_ARGS, CONTEXT, trace_identity=TRACE, proposal_event_identity=next_event)
        record("C11_CONSUMED_GRANT_NOT_REUSABLE", str(DecisionAction.DENY), second_use, "P2B_NO_MATCHING_ELIGIBLE_GRANT", inner_match.decide_calls, "new event has new proposal digest and consumed grant is unavailable")
        state_after_second_use = adapter_match.snapshot_state()
        require("P2I-C03_EXACT_BINDING_ALLOW" in state_after_second_use["consumed_grant_ids"], "Consumed grant identity disappeared")

        # C12: Malformed event input fails closed.
        adapter, inner = make_adapter()
        malformed = {"trace_identity": TRACE, "event_sequence": 10, "event_kind": "wrong-kind"}
        d = adapter.before_decide(TOOL, TOOL_ARGS, CONTEXT, trace_identity=TRACE, proposal_event_identity=malformed)
        record("C12_MALFORMED_EVENT_DENY", str(DecisionAction.DENY), d, "P2B_MALFORMED_TRUSTED_CHANNEL_INPUT", inner.decide_calls, "wrong event kind")
        require(inner.decide_calls == 0, "Malformed event unexpectedly reached inner guardrail")

        passed_count = sum(bool(row["passed"]) for row in controls)
        require(passed_count == len(controls), "Not all P2I controls passed")

        result = {
            "version": VERSION,
            "created_at_utc": now(),
            "status": "P2I_CONTROLLED_PROPOSAL_BINDING_AND_FAIL_CLOSED_DECISION_PREFLIGHT_COMPLETE_PASS",
            "classification": "SYNTHETIC_DECISION_ONLY_NO_TOOL_NO_EFFECT_PREFLIGHT",
            "P2H_parent_verified": True,
            "repaired_source_identity": identity(adapter_source),
            "guardrail_base_identity": identity(base_source),
            "control_results": {
                "total": len(controls),
                "passed": passed_count,
                "failed": len(controls) - passed_count,
            },
            "proposal_binding_findings": {
                "direct_decide_fail_closed": "ESTABLISHED_WITHIN_P2I_FIXTURE_SCOPE",
                "no_grant_deny": "ESTABLISHED_WITHIN_P2I_FIXTURE_SCOPE",
                "exact_binding_allow": "ESTABLISHED_WITHIN_P2I_FIXTURE_SCOPE",
                "tool_target_proposal_trace_lifetime_mismatch_deny": "ESTABLISHED_WITHIN_P2I_FIXTURE_SCOPE",
                "proposal_event_replay_deny": "ESTABLISHED_WITHIN_P2I_FIXTURE_SCOPE",
                "grant_consumption_state_recorded": "ESTABLISHED_WITHIN_P2I_FIXTURE_SCOPE",
                "consumed_grant_not_reusable_for_new_event": "ESTABLISHED_WITHIN_P2I_FIXTURE_SCOPE",
            },
            "execution_boundaries": {
                "adapter_instantiated": True,
                "register_trusted_grant_executed": True,
                "direct_decide_executed": True,
                "before_decide_executed": True,
                "inner_guardrail_decide_executed": True,
                "after_tool_executed": False,
                "tools_executed": False,
                "effects_observed": False,
                "sandbox_executed": False,
                "gym_executed": False,
                "predicates_executed": False,
                "breach_executed": False,
                "model_used": False,
            },
            "scientific_verdict": {
                "proposal_binding_behavior": "ESTABLISHED_WITHIN_P2I_SYNTHETIC_FIXTURE_SCOPE",
                "fail_closed_decision_behavior": "ESTABLISHED_WITHIN_P2I_SYNTHETIC_FIXTURE_SCOPE",
                "grant_consumption_behavior": "PARTIALLY_ESTABLISHED_WITHIN_P2I_SYNTHETIC_FIXTURE_SCOPE",
                "authorization_transport_correctness": "NOT_ESTABLISHED",
                "after_tool_outcome_binding": "NOT_EVALUATED",
                "protected_read_lineage": "NOT_EVALUATED",
                "runtime_compatibility": "NOT_ESTABLISHED",
                "requirement_satisfaction": "NOT_ESTABLISHED",
                "guardrail_effectiveness": "NOT_EVALUATED",
                "real_exfiltration_prevention": "NOT_ESTABLISHED",
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": "NOT_ESTABLISHED",
            },
            "claim_boundary": {
                "allowed": [
                    "synthetic proposal-binding behavior within exact P2I controls",
                    "synthetic fail-closed decision behavior within exact P2I controls",
                    "grant consumption state recording and non-reuse observation within exact P2I controls",
                ],
                "prohibited": [
                    "authorization transport correctness",
                    "after_tool outcome correctness",
                    "protected read lineage",
                    "runtime compatibility",
                    "requirement satisfaction",
                    "guardrail effectiveness",
                    "security improvement",
                    "real exfiltration prevention",
                    "Sandbox parity",
                    "Gym parity",
                    "hosted parity",
                ],
            },
            "next_gate": "EX6_P2B_P2J_CONTROLLED_AFTER_TOOL_OUTCOME_BINDING_AND_PROTECTED_READ_PREFLIGHT",
        }

        result_path = out / "ex6_p2b_p2i_result.json"
        controls_path = out / "ex6_p2b_p2i_controls.csv"
        binding_path = out / "ex6_p2b_p2i_binding.json"
        claim_path = out / "ex6_p2b_p2i_claim_boundary.json"
        write_json(result_path, result)
        write_csv(controls_path, controls, [
            "control_id", "expected_action", "observed_action", "expected_reason",
            "observed_reason", "inner_decide_calls", "passed", "note",
        ])
        write_json(claim_path, result["claim_boundary"])
        write_json(binding_path, {
            "version": VERSION,
            "created_at_utc": now(),
            "runner": identity(Path(__file__).resolve()),
            "inputs": {
                "p2h_result": identity(parent_result_path),
                "p2h_external_binding": identity(parent_binding_path),
                "p2h_manifest": identity(parent_manifest_path),
                "repaired_source": identity(adapter_source),
                "guardrail_base": identity(base_source),
            },
            "source_modified": False,
        })

        manifest_rows = [
            {**identity(path), "role": "P2I_DERIVED"}
            for path in (result_path, controls_path, binding_path, claim_path)
        ] + [
            {**identity(path), "role": "P2I_BOUND"}
            for path in (parent_result_path, parent_binding_path, parent_manifest_path, adapter_source, base_source)
        ]
        manifest_path = out / "ex6_p2b_p2i_manifest.csv"
        write_csv(manifest_path, manifest_rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        external_path = out / "ex6_p2b_p2i_manifest_external_binding.json"
        write_json(external_path, {
            "version": VERSION,
            "created_at_utc": now(),
            "status": result["status"],
            "manifest_filename": manifest_path.name,
            "manifest_size_bytes": manifest_path.stat().st_size,
            "manifest_sha256": sha256(manifest_path),
            "runner_sha256": sha256(Path(__file__).resolve()),
            "repaired_source_sha256": sha256(adapter_source),
            "tools_executed": False,
            "effects_observed": False,
            "after_tool_executed": False,
            "runtime_validated": False,
            "requirements_satisfied": False,
            "next_gate": result["next_gate"],
        })

        print(json.dumps({
            "status": result["status"],
            "controls_passed": passed_count,
            "controls_total": len(controls),
            "manifest_sha256": sha256(manifest_path),
            "tools_executed": False,
            "effects_observed": False,
            "runtime_validated": False,
            "requirements_satisfied": False,
            "next_gate": result["next_gate"],
        }, indent=2))

    except Exception as exc:
        failure_path = out / "P2I_FAILED.json"
        failure_path.write_text(json.dumps({
            "version": VERSION,
            "created_at_utc": now(),
            "status": "P2I_CONTROLLED_PROPOSAL_BINDING_PREFLIGHT_BLOCKED",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "tools_executed": False,
            "effects_observed": False,
            "after_tool_executed": False,
            "runtime_validated": False,
            "requirements_satisfied": False,
        }, indent=2), encoding="utf-8")
        raise
    finally:
        sys.path[:] = original_sys_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=VERSION)
    parser.add_argument("--p2h-result", required=True)
    parser.add_argument("--p2h-external-binding", required=True)
    parser.add_argument("--p2h-manifest", required=True)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--repaired-source", required=True)
    parser.add_argument("--output-dir", required=True)
    return parser.parse_args()


if __name__ == "__main__":
    try:
        main(parse_args())
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
