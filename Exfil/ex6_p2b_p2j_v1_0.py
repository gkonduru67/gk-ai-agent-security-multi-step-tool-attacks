#!/usr/bin/env python3
"""EX6 P2B P2J controlled after_tool outcome-binding preflight.

Uses synthetic in-memory proposal/outcome fixtures only. No tool, external
effect, Sandbox, Gym, model, breach, or evaluator execution occurs.

Important boundary: positive protected-read qualification is deliberately
DEFERRED because trusted_context_adapter_v1_1.py calls the official
is_protected_secret_path predicate for a successful fs.read. This P2J gate
preserves the current predicate-execution prohibition. It qualifies outcome
binding and the negative unsuccessful-read non-recording path only.
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
from typing import Any, Callable

VERSION = "EX6_P2B_P2J_CONTROLLED_AFTER_TOOL_OUTCOME_BINDING_AND_PROTECTED_READ_PREFLIGHT_v1.0"
PARENT_VERSION = "EX6_P2B_P2I_R1_REPLAY_CLASSIFICATION_CONTRACT_RECONCILIATION_v1.0"
PARENT_STATUS = "P2I_R1_REPLAY_CLASSIFICATION_CONTRACT_RECONCILIATION_COMPLETE_PASS"
EXPECTED_PARENT_MANIFEST_SHA256 = "16CA2A4DE648C7AA1B242931AB35192D6B712BD230D527F5991E6A3EC18C34AC"
EXPECTED_PARENT_RUNNER_SHA256 = "38256C1B3725F5E97096F70F0C1626368835FFD8D411B8EED4DB950C99B35BFE"
EXPECTED_ADAPTER_SHA256 = "BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"
EXPECTED_BASE_SHA256 = "EC95F45A9BF4202514725690617C91E88F3F1AE889AC7828D423DAAFEA527708"
ADAPTER_MODULE = "aicomp_sdk.guardrails.trusted_context_adapter_v1_1"
BASE_MODULE = "aicomp_sdk.guardrails.base"
ADAPTER_CLASS = "TrustedGuardrailContextAdapterV1_1"
SCHEMA_TAG = "aicomp.trusted-context.v1"
CAPABILITY = b"P2J_DETERMINISTIC_OUT_OF_BAND_CAPABILITY_V1"
ISSUER = "issuer-p2j"
DOMAIN = "domain-p2j"
CONTEXT = {"fixture": "P2J", "sensitive": False}


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
    data = json.dumps(
        normalize(envelope),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest().upper()


def proposal_event(trace: str, sequence: int) -> dict[str, Any]:
    return {"trace_identity": trace, "event_sequence": sequence, "event_kind": "proposal"}


def outcome_event(trace: str, sequence: int, kind: str = "outcome") -> dict[str, Any]:
    return {"trace_identity": trace, "event_sequence": sequence, "event_kind": kind}


def proposal_digest(tool_name: str, tool_args: dict[str, Any], trace: str, event: dict[str, Any]) -> str:
    return digest_v1({
        "schema_tag": SCHEMA_TAG,
        "tool_name": tool_name,
        "canonical_tool_args": dict(tool_args),
        "trace_identity": trace,
        "proposal_event_identity": dict(event),
    })


def safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"type": "bytes", "sha256": hashlib.sha256(value).hexdigest().upper(), "length": len(value)}
    if isinstance(value, dict):
        return {str(key): safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [safe(item) for item in value]
    if isinstance(value, set):
        return sorted(safe(item) for item in value)
    return value


def state_digest(adapter: Any) -> str:
    encoded = json.dumps(safe(adapter.snapshot_state()), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest().upper()


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
    output_dir = Path(args.output_dir).resolve()
    require(not output_dir.exists(), f"Refusing overwrite: {output_dir}")
    output_dir.mkdir(parents=True)
    original_sys_path = list(sys.path)
    observations: list[dict[str, Any]] = []

    try:
        parent_result_path = Path(args.p2i_r1_result).resolve()
        parent_binding_path = Path(args.p2i_r1_external_binding).resolve()
        parent_manifest_path = Path(args.p2i_r1_manifest).resolve()
        project_root = Path(args.project_root).resolve()
        adapter_source = Path(args.repaired_source).resolve()
        base_source = project_root / "aicomp_sdk" / "guardrails" / "base.py"

        for label, path in (
            ("P2I-R1 result", parent_result_path),
            ("P2I-R1 external binding", parent_binding_path),
            ("P2I-R1 manifest", parent_manifest_path),
            ("adapter source", adapter_source),
            ("GuardrailBase source", base_source),
        ):
            require(path.is_file(), f"Missing {label}: {path}")

        parent = json.loads(parent_result_path.read_text(encoding="utf-8-sig"))
        parent_binding = json.loads(parent_binding_path.read_text(encoding="utf-8-sig"))
        require(parent.get("version") == PARENT_VERSION, "Unexpected P2I-R1 version")
        require(parent.get("status") == PARENT_STATUS, "P2I-R1 parent is not PASS")
        require(parent.get("controls", {}).get("action_passed") == 12, "P2I-R1 action controls differ")
        require(parent_binding.get("status") == PARENT_STATUS, "P2I-R1 external binding is not PASS")
        require(parent_binding.get("manifest_sha256") == EXPECTED_PARENT_MANIFEST_SHA256, "P2I-R1 manifest authority differs")
        require(parent_binding.get("runner_sha256") == EXPECTED_PARENT_RUNNER_SHA256, "P2I-R1 runner authority differs")
        require(sha256(parent_manifest_path) == EXPECTED_PARENT_MANIFEST_SHA256, "Current P2I-R1 manifest identity differs")
        require(parent_binding.get("tools_executed") is False, "P2I-R1 crossed tool boundary")
        require(parent_binding.get("effects_observed") is False, "P2I-R1 crossed effect boundary")
        require(parent_binding.get("runtime_validated") is False, "P2I-R1 claimed runtime validation")
        require(parent_binding.get("requirements_satisfied") is False, "P2I-R1 claimed requirement satisfaction")
        require(sha256(adapter_source) == EXPECTED_ADAPTER_SHA256, "Adapter source identity mismatch")
        require(sha256(base_source) == EXPECTED_BASE_SHA256, "GuardrailBase source identity mismatch")

        sys.path.insert(0, str(project_root))
        importlib.invalidate_caches()
        base_module = importlib.import_module(BASE_MODULE)
        adapter_module = importlib.import_module(ADAPTER_MODULE)
        GuardrailBase = getattr(base_module, "GuardrailBase")
        Decision = getattr(base_module, "Decision")
        DecisionAction = getattr(base_module, "DecisionAction")
        Adapter = getattr(adapter_module, ADAPTER_CLASS)

        class P2JInnerGuardrail(GuardrailBase):
            def __init__(self) -> None:
                self.calls = 0

            def decide(self, tool_name: str, tool_args: Any, context: Any) -> Any:
                self.calls += 1
                return Decision.allow("P2J_SYNTHETIC_INNER_ALLOW")

            def snapshot_state(self) -> Any:
                return {"calls": self.calls}

            def restore_state(self, snapshot: Any) -> None:
                self.calls = int(snapshot["calls"])

        def fresh() -> tuple[Any, Any]:
            inner = P2JInnerGuardrail()
            return Adapter(inner, {(ISSUER, DOMAIN): CAPABILITY}), inner

        def prepare_pending(tool_name: str, tool_args: dict[str, Any], trace: str, proposal_sequence: int) -> tuple[Any, Any, str, str, dict[str, Any]]:
            adapter, inner = fresh()
            event = proposal_event(trace, proposal_sequence)
            decision = adapter.before_decide(
                tool_name,
                tool_args,
                CONTEXT,
                trace_identity=trace,
                proposal_event_identity=event,
            )
            require(str(decision.action) == str(DecisionAction.ALLOW), "Synthetic proposal was not allowed")
            pd = proposal_digest(tool_name, tool_args, trace, event)
            ad = digest_v1(dict(tool_args))
            snapshot = adapter.snapshot_state()
            require(pd in snapshot["pending_proposals_by_digest"], "Pending proposal absent after before_decide")
            return adapter, inner, pd, ad, event

        def observe(
            control_id: str,
            adapter: Any,
            inner: Any,
            invoke: Callable[[], None],
            expected_exception_contains: str,
            expect_pending_before: bool,
            expected_pending_after: bool,
            proposal_digest_value: str,
            expect_read_delta: int,
            note: str,
        ) -> None:
            before_snapshot = adapter.snapshot_state()
            before_digest = state_digest(adapter)
            pending_before = proposal_digest_value in before_snapshot["pending_proposals_by_digest"]
            reads_before = len(before_snapshot["protected_read_records"])
            calls_before = inner.calls
            exception_type = ""
            exception_text = ""
            try:
                invoke()
            except Exception as exc:
                exception_type = type(exc).__name__
                exception_text = str(exc)
            after_snapshot = adapter.snapshot_state()
            after_digest = state_digest(adapter)
            pending_after = proposal_digest_value in after_snapshot["pending_proposals_by_digest"]
            reads_after = len(after_snapshot["protected_read_records"])
            calls_after = inner.calls
            exception_pass = (
                (expected_exception_contains == "" and exception_text == "")
                or (expected_exception_contains != "" and expected_exception_contains in exception_text)
            )
            passed = (
                exception_pass
                and pending_before == expect_pending_before
                and pending_after == expected_pending_after
                and reads_after - reads_before == expect_read_delta
                and calls_after == calls_before
            )
            observations.append({
                "control_id": control_id,
                "expected_exception_contains": expected_exception_contains or "NONE",
                "observed_exception_type": exception_type or "NONE",
                "observed_exception": exception_text or "NONE",
                "exception_pass": exception_pass,
                "pending_before": pending_before,
                "expected_pending_before": expect_pending_before,
                "pending_after": pending_after,
                "expected_pending_after": expected_pending_after,
                "protected_read_count_before": reads_before,
                "protected_read_count_after": reads_after,
                "protected_read_delta": reads_after - reads_before,
                "expected_protected_read_delta": expect_read_delta,
                "inner_calls_before": calls_before,
                "inner_calls_after": calls_after,
                "state_digest_before": before_digest,
                "state_digest_after": after_digest,
                "state_changed": before_digest != after_digest,
                "passed": passed,
                "note": note,
            })

        # C01 valid non-read outcome binds and retires pending proposal.
        trace = "P2J-TRACE-C01"
        tool = "synthetic.lookup"
        tool_args = {"key": "P2J-C01"}
        adapter, inner, pd, ad, _ = prepare_pending(tool, tool_args, trace, 10)
        observe(
            "C01_VALID_OUTCOME_RETIRES_PENDING",
            adapter,
            inner,
            lambda: adapter.after_tool(
                proposal_digest=pd,
                event_identity=outcome_event(trace, 11),
                trace_identity=trace,
                tool_name=tool,
                tool_args_digest=ad,
                trusted_tool_outcome={"success": True, "completion_sequence": 11},
            ),
            "", True, False, pd, 0,
            "successful synthetic non-read outcome",
        )

        # C02-C07 independent mismatches fail closed and preserve pending state.
        mismatch_cases = [
            ("C02_UNKNOWN_PROPOSAL", "WRONG-PROPOSAL", None, None, None, {"success": True, "completion_sequence": 11}, "P2B_REPLAY_OR_EVENT_IDENTITY_REJECTED"),
            ("C03_WRONG_TRACE", None, "P2J-WRONG-TRACE", None, None, {"success": True, "completion_sequence": 11}, "P2B_REPLAY_OR_EVENT_IDENTITY_REJECTED"),
            ("C04_WRONG_TOOL", None, None, "synthetic.wrong", None, {"success": True, "completion_sequence": 11}, "P2B_MALFORMED_TRUSTED_CHANNEL_INPUT"),
            ("C05_WRONG_ARGS_DIGEST", None, None, None, "WRONG-ARGS-DIGEST", {"success": True, "completion_sequence": 11}, "P2B_MALFORMED_TRUSTED_CHANNEL_INPUT"),
            ("C06_INVALID_SUCCESS_TYPE", None, None, None, None, {"success": "true", "completion_sequence": 11}, "P2B_MALFORMED_TRUSTED_CHANNEL_INPUT"),
            ("C07_COMPLETION_SEQUENCE_MISMATCH", None, None, None, None, {"success": True, "completion_sequence": 12}, "P2B_MALFORMED_TRUSTED_CHANNEL_INPUT"),
        ]
        for cid, pd_override, trace_override, tool_override, ad_override, outcome, expected_error in mismatch_cases:
            trace = f"P2J-TRACE-{cid}"
            tool = "synthetic.lookup"
            tool_args = {"key": cid}
            adapter, inner, pd, ad, _ = prepare_pending(tool, tool_args, trace, 10)
            observe(
                cid,
                adapter,
                inner,
                lambda adapter=adapter, pd=pd, ad=ad, trace=trace, tool=tool, cid=cid, pd_override=pd_override, trace_override=trace_override, tool_override=tool_override, ad_override=ad_override, outcome=outcome: adapter.after_tool(
                    proposal_digest=pd_override or pd,
                    event_identity=outcome_event(trace, 11),
                    trace_identity=trace_override or trace,
                    tool_name=tool_override or tool,
                    tool_args_digest=ad_override or ad,
                    trusted_tool_outcome=outcome,
                ),
                expected_error, True, True, pd, 0,
                "mismatch must preserve pending proposal",
            )

        # C08 wrong event kind is rejected and pending remains.
        trace = "P2J-TRACE-C08"
        tool = "synthetic.lookup"
        tool_args = {"key": "C08"}
        adapter, inner, pd, ad, _ = prepare_pending(tool, tool_args, trace, 10)
        observe(
            "C08_WRONG_OUTCOME_EVENT_KIND",
            adapter,
            inner,
            lambda: adapter.after_tool(
                proposal_digest=pd,
                event_identity=outcome_event(trace, 11, kind="proposal"),
                trace_identity=trace,
                tool_name=tool,
                tool_args_digest=ad,
                trusted_tool_outcome={"success": True, "completion_sequence": 11},
            ),
            "invalid event identity", True, True, pd, 0,
            "event-kind schema rejection",
        )

        # C09 unsuccessful fs.read outcome retires pending and records no protected read.
        trace = "P2J-TRACE-C09"
        tool = "fs.read"
        tool_args = {"path": "/synthetic/non-sensitive/p2j.txt"}
        adapter, inner, pd, ad, _ = prepare_pending(tool, tool_args, trace, 10)
        observe(
            "C09_UNSUCCESSFUL_READ_NO_RECORD",
            adapter,
            inner,
            lambda: adapter.after_tool(
                proposal_digest=pd,
                event_identity=outcome_event(trace, 11),
                trace_identity=trace,
                tool_name=tool,
                tool_args_digest=ad,
                trusted_tool_outcome={"success": False, "completion_sequence": 11},
            ),
            "", True, False, pd, 0,
            "unsuccessful read must not invoke protected-read qualification",
        )

        # C10 repeat acknowledgement after a successful retirement is rejected.
        trace = "P2J-TRACE-C10"
        tool = "synthetic.lookup"
        tool_args = {"key": "C10"}
        adapter, inner, pd, ad, _ = prepare_pending(tool, tool_args, trace, 10)
        adapter.after_tool(
            proposal_digest=pd,
            event_identity=outcome_event(trace, 11),
            trace_identity=trace,
            tool_name=tool,
            tool_args_digest=ad,
            trusted_tool_outcome={"success": True, "completion_sequence": 11},
        )
        observe(
            "C10_REPEATED_ACKNOWLEDGEMENT_REJECTED",
            adapter,
            inner,
            lambda: adapter.after_tool(
                proposal_digest=pd,
                event_identity=outcome_event(trace, 11),
                trace_identity=trace,
                tool_name=tool,
                tool_args_digest=ad,
                trusted_tool_outcome={"success": True, "completion_sequence": 11},
            ),
            "P2B_REPLAY_OR_EVENT_IDENTITY_REJECTED", False, False, pd, 0,
            "pending proposal was already retired",
        )

        passed_count = sum(bool(row["passed"]) for row in observations)
        failed_ids = [row["control_id"] for row in observations if not row["passed"]]
        status = (
            "P2J_CONTROLLED_AFTER_TOOL_OUTCOME_BINDING_PREFLIGHT_COMPLETE_PASS"
            if not failed_ids
            else "P2J_OUTCOME_BINDING_PREFLIGHT_COMPLETE_WITH_GAPS"
        )
        next_gate = (
            "EX6_P2B_P2K_PROTECTED_READ_PREDICATE_BOUNDARY_PREFLIGHT"
            if not failed_ids
            else "EX6_P2B_P2J_R1_OUTCOME_BINDING_RECONCILIATION"
        )

        result = {
            "version": VERSION,
            "created_at_utc": now(),
            "status": status,
            "classification": "SYNTHETIC_AFTER_TOOL_NO_TOOL_NO_EFFECT_PREFLIGHT",
            "P2I_R1_parent_verified": True,
            "repaired_source_identity": identity(adapter_source),
            "guardrail_base_identity": identity(base_source),
            "controls": {
                "total": len(observations),
                "passed": passed_count,
                "failed": len(failed_ids),
                "failed_ids": failed_ids,
            },
            "protected_read_boundary": {
                "unsuccessful_read_non_recording": "EVALUATED",
                "successful_protected_read_qualification": "DEFERRED_PREDICATE_EXECUTION_PROHIBITED",
                "official_predicate_executed": False,
            },
            "execution_boundaries": {
                "adapter_instantiated": True,
                "before_decide_executed": True,
                "after_tool_executed": True,
                "inner_guardrail_decide_executed": True,
                "tools_executed": False,
                "effects_observed": False,
                "sandbox_executed": False,
                "gym_executed": False,
                "predicates_executed": False,
                "breach_executed": False,
                "models_used": False,
            },
            "scientific_verdict": {
                "after_tool_outcome_binding": "ESTABLISHED_WITHIN_P2J_SYNTHETIC_FIXTURE_SCOPE" if not failed_ids else "GAPS_IDENTIFIED",
                "pending_proposal_retirement": "ESTABLISHED_WITHIN_P2J_SYNTHETIC_FIXTURE_SCOPE" if not failed_ids else "GAPS_IDENTIFIED",
                "mismatched_outcome_fail_closed": "ESTABLISHED_WITHIN_P2J_SYNTHETIC_FIXTURE_SCOPE" if not failed_ids else "GAPS_IDENTIFIED",
                "unsuccessful_read_non_recording": "ESTABLISHED_WITHIN_P2J_SYNTHETIC_FIXTURE_SCOPE" if not failed_ids else "GAPS_IDENTIFIED",
                "successful_protected_read_recording": "NOT_EVALUATED",
                "protected_read_lineage": "NOT_ESTABLISHED",
                "authorization_transport_correctness": "NOT_ESTABLISHED",
                "runtime_compatibility": "NOT_ESTABLISHED",
                "requirement_satisfaction": "NOT_ESTABLISHED",
                "guardrail_effectiveness": "NOT_EVALUATED",
                "real_exfiltration_prevention": "NOT_ESTABLISHED",
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": "NOT_ESTABLISHED",
            },
            "claim_boundary": {
                "allowed": [
                    "synthetic after_tool outcome-binding behavior within exact P2J controls",
                    "pending-proposal preservation or retirement within exact P2J controls",
                    "unsuccessful fs.read non-recording within exact P2J fixture",
                ],
                "prohibited": [
                    "successful protected-read qualification",
                    "protected-read lineage",
                    "authorization transport correctness",
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
            "next_gate": next_gate,
        }

        result_path = output_dir / "ex6_p2b_p2j_result.json"
        controls_path = output_dir / "ex6_p2b_p2j_controls.csv"
        binding_path = output_dir / "ex6_p2b_p2j_binding.json"
        claim_path = output_dir / "ex6_p2b_p2j_claim_boundary.json"
        write_json(result_path, result)
        write_csv(controls_path, observations, [
            "control_id", "expected_exception_contains", "observed_exception_type",
            "observed_exception", "exception_pass", "pending_before",
            "expected_pending_before", "pending_after", "expected_pending_after",
            "protected_read_count_before", "protected_read_count_after",
            "protected_read_delta", "expected_protected_read_delta",
            "inner_calls_before", "inner_calls_after", "state_digest_before",
            "state_digest_after", "state_changed", "passed", "note",
        ])
        write_json(claim_path, result["claim_boundary"])
        write_json(binding_path, {
            "version": VERSION,
            "created_at_utc": now(),
            "runner": identity(Path(__file__).resolve()),
            "inputs": {
                "p2i_r1_result": identity(parent_result_path),
                "p2i_r1_external_binding": identity(parent_binding_path),
                "p2i_r1_manifest": identity(parent_manifest_path),
                "repaired_source": identity(adapter_source),
                "guardrail_base": identity(base_source),
            },
            "source_modified": False,
        })

        manifest_rows = [
            {**identity(path), "role": "P2J_DERIVED"}
            for path in (result_path, controls_path, binding_path, claim_path)
        ] + [
            {**identity(path), "role": "P2J_BOUND"}
            for path in (parent_result_path, parent_binding_path, parent_manifest_path, adapter_source, base_source)
        ]
        manifest_path = output_dir / "ex6_p2b_p2j_manifest.csv"
        write_csv(manifest_path, manifest_rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        external_path = output_dir / "ex6_p2b_p2j_manifest_external_binding.json"
        write_json(external_path, {
            "version": VERSION,
            "created_at_utc": now(),
            "status": status,
            "manifest_filename": manifest_path.name,
            "manifest_size_bytes": manifest_path.stat().st_size,
            "manifest_sha256": sha256(manifest_path),
            "runner_sha256": sha256(Path(__file__).resolve()),
            "repaired_source_sha256": sha256(adapter_source),
            "after_tool_executed": True,
            "tools_executed": False,
            "effects_observed": False,
            "predicates_executed": False,
            "runtime_validated": False,
            "requirements_satisfied": False,
            "next_gate": next_gate,
        })

        print(json.dumps({
            "status": status,
            "controls_passed": passed_count,
            "controls_total": len(observations),
            "failed_ids": failed_ids,
            "successful_protected_read_qualification": "DEFERRED_PREDICATE_EXECUTION_PROHIBITED",
            "manifest_sha256": sha256(manifest_path),
            "tools_executed": False,
            "effects_observed": False,
            "predicates_executed": False,
            "runtime_validated": False,
            "next_gate": next_gate,
        }, indent=2))

    except Exception as exc:
        failure_path = output_dir / "P2J_FAILED.json"
        failure_path.write_text(json.dumps({
            "version": VERSION,
            "created_at_utc": now(),
            "status": "P2J_PREFLIGHT_BLOCKED",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "observations_frozen": observations,
            "tools_executed": False,
            "effects_observed": False,
            "predicates_executed": False,
            "runtime_validated": False,
            "requirements_satisfied": False,
        }, indent=2), encoding="utf-8")
        raise
    finally:
        sys.path[:] = original_sys_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=VERSION)
    parser.add_argument("--p2i-r1-result", required=True)
    parser.add_argument("--p2i-r1-external-binding", required=True)
    parser.add_argument("--p2i-r1-manifest", required=True)
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
