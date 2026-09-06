#!/usr/bin/env python3
"""P2O-E bridge import and direct synthetic integration qualification.

E1 imports the generated bridge through the SDK package namespace, confirms
resolution of the frozen packaged SandboxEnv, inspects inheritance and the
bridge constructor, but does not instantiate TrustedBridgeSandboxV1 or
SandboxEnv.

E2 directly exercises TrustedOutcomeTransportV1 with a synthetic recording
adapter and synthetic values only. It checks one acknowledgement per tested
call, value-free outcome metadata, deterministic digest fields, sequence
consumption, duplicate-consumption rejection, and fail-closed adapter-error
behavior. It does not execute fs.read, any tool, HTTP, Sandbox, Gym,
predicates, breach logic, models, protected fixture reads, real secrets, or
external effects.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib
import inspect
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX6_P2B_P2O_E_BRIDGE_IMPORT_AND_SYNTHETIC_INTEGRATION_QUALIFICATION_v1.0"
PARENT_VERSION = "EX6_P2B_P2O_D_CONTROLLED_IMPORT_AND_PURE_UNIT_QUALIFICATION_v1.0"
PARENT_STATUS = "P2O_D_CONTROLLED_IMPORT_AND_PURE_UNIT_QUALIFICATION_COMPLETE_PASS"
PARENT_MANIFEST_SHA = "1C821051495BF7F9E9C2D85633705FC620F559B3A48ED378C4B9362570A502E8"
PARENT_RUNNER_SHA = "BD6AE232A817304BAF1EA30F066CA651D788CF6EC91D6CE05CA7835041E8AC52"

TRANSPORT_REL = "aicomp_sdk/core/env/trusted_outcome_transport_v1.py"
TRANSPORT_SHA = "5C7F7D16A37896959C6F4CC769E5F72A6E5E534EE140BA5CAF2FB70661102CE1"
PATH_REL = "aicomp_sdk/core/tools/fs_trusted_result_v1.py"
PATH_SHA = "EF6EC29952194AC83A741CCFAF3FCE41DD64D2D6BEE5501A8273209CD3C21F8F"
BRIDGE_REL = "aicomp_sdk/core/env/sandbox_trusted_bridge_v1.py"
BRIDGE_SHA = "3EE9BBB1E65949795A5639D12C55D81D8D0645357260DFC5A91DB1E9710288B6"
SANDBOX_REL = "aicomp_sdk/core/env/sandbox.py"
SANDBOX_SHA = "B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0"
PROTECTED = {
    SANDBOX_REL: SANDBOX_SHA,
    "aicomp_sdk/core/predicates.py": "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37",
    "aicomp_sdk/core/tools/fs.py": "4B8C54032ED807CE4C35BAB403EE622141881158E10F600A4B6D329E6D6F95B8",
    "aicomp_sdk/guardrails/optimal.py": "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED",
    "aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py": "BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99",
}
BRIDGE_MODULE = "aicomp_sdk.core.env.sandbox_trusted_bridge_v1"
TRANSPORT_MODULE = "aicomp_sdk.core.env.trusted_outcome_transport_v1"
SANDBOX_MODULE = "aicomp_sdk.core.env.sandbox"
EXPECTED_OUTCOME_KEYS = {
    "success",
    "completion_sequence",
    "canonical_source_path",
    "raw_output_sha256",
    "protected_value_sha256_or_bound_digest",
}
PROHIBITED_OUTCOME_KEYS = {
    "raw_value",
    "value",
    "content",
    "post_hook_output",
    "secret",
    "payload",
}


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


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)


def add(
    rows: list[dict[str, Any]],
    check_id: str,
    execution_layer: str,
    passed: bool,
    observed: Any,
    expected: Any,
    failure_layer: str,
) -> None:
    rows.append(
        {
            "check_id": check_id,
            "execution_layer": execution_layer,
            "passed": bool(passed),
            "observed": str(observed),
            "expected": str(expected),
            "failure_layer": failure_layer,
        }
    )


class RecordingAdapter:
    """Synthetic adapter. Stores only the outcome metadata supplied to it."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def after_tool(self, outcome: dict[str, object]) -> None:
        self.calls.append(dict(outcome))


class RaisingAdapter:
    """Synthetic adapter error control."""

    def __init__(self) -> None:
        self.call_count = 0

    def after_tool(self, outcome: dict[str, object]) -> None:
        self.call_count += 1
        raise RuntimeError("synthetic adapter rejection")


def clear_target_modules() -> None:
    for name in [BRIDGE_MODULE, TRANSPORT_MODULE]:
        sys.modules.pop(name, None)


def main(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir).resolve()
    require(not output_dir.exists(), f"Refusing overwrite: {output_dir}")
    output_dir.mkdir(parents=True)

    checks: list[dict[str, Any]] = []
    e1_rows: list[dict[str, Any]] = []
    e2_rows: list[dict[str, Any]] = []
    imported_modules: list[str] = []

    try:
        project = Path(args.project_root).resolve()
        require(project.is_dir(), f"Missing project root: {project}")

        inputs = {
            "result": Path(args.p2o_d_result).resolve(),
            "checks": Path(args.p2o_d_checks).resolve(),
            "d1_imports": Path(args.p2o_d_d1_imports).resolve(),
            "d2_units": Path(args.p2o_d_d2_units).resolve(),
            "claim_boundary": Path(args.p2o_d_claim_boundary).resolve(),
            "binding": Path(args.p2o_d_binding).resolve(),
            "external_binding": Path(args.p2o_d_external_binding).resolve(),
            "manifest": Path(args.p2o_d_manifest).resolve(),
            "runner": Path(args.p2o_d_runner).resolve(),
        }
        for label, path in inputs.items():
            require(path.is_file(), f"Missing P2O-D {label}: {path}")

        parent_result = json.loads(inputs["result"].read_text(encoding="utf-8-sig"))
        parent_external = json.loads(
            inputs["external_binding"].read_text(encoding="utf-8-sig")
        )
        require(
            parent_result.get("version") == PARENT_VERSION
            and parent_result.get("status") == PARENT_STATUS,
            "P2O-D parent differs",
        )
        require(
            parent_result.get("checks")
            == {"failed": 0, "failed_ids": [], "passed": 28, "total": 28},
            "P2O-D check summary differs",
        )
        require(
            sha256(inputs["manifest"]) == PARENT_MANIFEST_SHA
            and parent_external.get("manifest_sha256") == PARENT_MANIFEST_SHA,
            "P2O-D manifest differs",
        )
        require(
            sha256(inputs["runner"]) == PARENT_RUNNER_SHA
            and parent_external.get("runner_sha256") == PARENT_RUNNER_SHA,
            "P2O-D runner differs",
        )
        require(
            parent_external.get("bridge_import_and_synthetic_integration_gate_eligible")
            is True
            and parent_external.get("controlled_actual_fs_read_eligible") is False,
            "P2O-D eligibility boundary differs",
        )

        transport_path = project / TRANSPORT_REL
        path_helper_path = project / PATH_REL
        bridge_path = project / BRIDGE_REL
        sandbox_path = project / SANDBOX_REL
        for path, expected, label in [
            (transport_path, TRANSPORT_SHA, "transport"),
            (path_helper_path, PATH_SHA, "path helper"),
            (bridge_path, BRIDGE_SHA, "bridge"),
            (sandbox_path, SANDBOX_SHA, "packaged sandbox"),
        ]:
            require(path.is_file() and sha256(path) == expected, f"{label} identity differs")
        for relative_path, expected in PROTECTED.items():
            path = project / relative_path
            require(
                path.is_file() and sha256(path) == expected,
                f"Protected source differs: {relative_path}",
            )

        # E1. Import the bridge through its qualified SDK module name.
        clear_target_modules()
        project_text = str(project)
        inserted_project_path = False
        if project_text not in sys.path:
            sys.path.insert(0, project_text)
            inserted_project_path = True
        try:
            bridge_module = importlib.import_module(BRIDGE_MODULE)
            imported_modules.append(BRIDGE_MODULE)
        finally:
            if inserted_project_path and sys.path and sys.path[0] == project_text:
                sys.path.pop(0)

        transport_module = sys.modules.get(TRANSPORT_MODULE)
        sandbox_module = sys.modules.get(SANDBOX_MODULE)
        require(transport_module is not None, "Bridge import did not resolve transport module")
        require(sandbox_module is not None, "Bridge import did not resolve packaged sandbox module")
        imported_modules.extend([TRANSPORT_MODULE, SANDBOX_MODULE])

        bridge_class = getattr(bridge_module, "TrustedBridgeSandboxV1", None)
        sandbox_class = getattr(sandbox_module, "SandboxEnv", None)
        transport_class = getattr(transport_module, "TrustedOutcomeTransportV1", None)
        state_class = getattr(transport_module, "TrustedEventSequenceStateV1", None)

        add(
            checks,
            "E1-01",
            "E1",
            bridge_class is not None,
            bridge_class,
            "TrustedBridgeSandboxV1 exported",
            "ADAPTER_PARSE",
        )
        add(
            checks,
            "E1-02",
            "E1",
            sandbox_class is not None
            and Path(inspect.getsourcefile(sandbox_class) or "").resolve() == sandbox_path.resolve(),
            inspect.getsourcefile(sandbox_class) if sandbox_class else None,
            str(sandbox_path.resolve()),
            "ADAPTER_PARSE",
        )
        inheritance_ok = (
            bridge_class is not None
            and sandbox_class is not None
            and issubclass(bridge_class, sandbox_class)
            and bridge_class is not sandbox_class
        )
        add(
            checks,
            "E1-03",
            "E1",
            inheritance_ok,
            [c.__name__ for c in bridge_class.__mro__] if bridge_class else [],
            "TrustedBridgeSandboxV1 subclasses SandboxEnv",
            "ADAPTER_PARSE",
        )
        bridge_signature = str(inspect.signature(bridge_class)) if bridge_class else "NOT_FOUND"
        signature_parameters = inspect.signature(bridge_class).parameters if bridge_class else {}
        signature_ok = (
            "args" in signature_parameters
            and signature_parameters["args"].kind is inspect.Parameter.VAR_POSITIONAL
            and "trusted_transport" in signature_parameters
            and signature_parameters["trusted_transport"].kind
            is inspect.Parameter.KEYWORD_ONLY
            and "kwargs" in signature_parameters
            and signature_parameters["kwargs"].kind is inspect.Parameter.VAR_KEYWORD
        )
        add(
            checks,
            "E1-04",
            "E1",
            signature_ok,
            bridge_signature,
            "(*args, trusted_transport, **kwargs)",
            "ADAPTER_PARSE",
        )
        source_resolution_ok = (
            Path(inspect.getsourcefile(bridge_class) or "").resolve() == bridge_path.resolve()
            if bridge_class
            else False
        )
        add(
            checks,
            "E1-05",
            "E1",
            source_resolution_ok,
            inspect.getsourcefile(bridge_class) if bridge_class else None,
            str(bridge_path.resolve()),
            "FIXTURE",
        )
        bridge_instantiated = False
        sandbox_instantiated = False
        add(
            checks,
            "E1-06",
            "E1",
            not bridge_instantiated and not sandbox_instantiated,
            {"bridge_instantiated": bridge_instantiated, "sandbox_instantiated": sandbox_instantiated},
            "both false",
            "CLAIM_BOUNDARY",
        )
        e1_rows.extend(
            [
                {
                    "control": "bridge_import",
                    "passed": True,
                    "observed": BRIDGE_MODULE,
                },
                {
                    "control": "sandbox_resolution",
                    "passed": sandbox_class is not None,
                    "observed": inspect.getsourcefile(sandbox_class) if sandbox_class else "NOT_FOUND",
                },
                {
                    "control": "bridge_inheritance",
                    "passed": inheritance_ok,
                    "observed": ";".join(c.__name__ for c in bridge_class.__mro__) if bridge_class else "",
                },
                {
                    "control": "bridge_signature",
                    "passed": signature_ok,
                    "observed": bridge_signature,
                },
                {
                    "control": "instantiation_withheld",
                    "passed": True,
                    "observed": "bridge=false;sandbox=false",
                },
            ]
        )

        if any(not row["passed"] for row in checks if row["execution_layer"] == "E1"):
            raise ValueError("E1 failed; E2 withheld")

        # E2. Direct synthetic transport integration. No Bridge or Sandbox instance.
        recorder = RecordingAdapter()
        sequence_state = state_class()
        transport = transport_class(recorder, sequence_state)
        synthetic_value = {"synthetic": [1, "alpha", None]}
        outcome = transport.acknowledge(
            trace_identity="synthetic-trace-1",
            proposal_digest="synthetic-proposal-digest-1",
            tool_name="synthetic.tool",
            success=True,
            canonical_source_path="/synthetic/input.txt",
            post_hook_output=synthetic_value,
        )

        one_call = len(recorder.calls) == 1
        add(checks, "E2-01", "E2", one_call, len(recorder.calls), 1, "AUTHORIZATION_TRANSPORT")
        same_metadata = one_call and recorder.calls[0] == outcome
        add(
            checks,
            "E2-02",
            "E2",
            same_metadata,
            recorder.calls[0] if one_call else None,
            outcome,
            "AUTHORIZATION_TRANSPORT",
        )
        exact_keys = set(outcome) == EXPECTED_OUTCOME_KEYS
        add(
            checks,
            "E2-03",
            "E2",
            exact_keys,
            sorted(outcome),
            sorted(EXPECTED_OUTCOME_KEYS),
            "SECRET_CAPTURE",
        )
        no_prohibited_keys = not (set(outcome) & PROHIBITED_OUTCOME_KEYS)
        add(
            checks,
            "E2-04",
            "E2",
            no_prohibited_keys,
            sorted(set(outcome) & PROHIBITED_OUTCOME_KEYS),
            [],
            "SECRET_CAPTURE",
        )
        metadata_types_ok = (
            outcome.get("success") is True
            and outcome.get("completion_sequence") == 1
            and outcome.get("canonical_source_path") == "/synthetic/input.txt"
            and isinstance(outcome.get("raw_output_sha256"), str)
            and len(outcome["raw_output_sha256"]) == 64
            and isinstance(outcome.get("protected_value_sha256_or_bound_digest"), str)
            and len(outcome["protected_value_sha256_or_bound_digest"]) == 64
        )
        add(
            checks,
            "E2-05",
            "E2",
            metadata_types_ok,
            outcome,
            "value-free typed metadata with two 64-char digests",
            "AUTHORIZATION_TRANSPORT",
        )
        consumed_identity = "synthetic-trace-1:outcome:1"
        consumed_once = consumed_identity in sequence_state.consumed_outcome_identities
        add(
            checks,
            "E2-06",
            "E2",
            consumed_once,
            sorted(sequence_state.consumed_outcome_identities),
            [consumed_identity],
            "REPLAY_ORCHESTRATION",
        )
        duplicate_rejected = False
        try:
            sequence_state.consume_outcome(consumed_identity)
        except ValueError:
            duplicate_rejected = True
        add(
            checks,
            "E2-07",
            "E2",
            duplicate_rejected,
            duplicate_rejected,
            True,
            "REPLAY_ORCHESTRATION",
        )

        # Second independent call verifies one acknowledgement for that call and monotonic sequence.
        second_outcome = transport.acknowledge(
            trace_identity="synthetic-trace-1",
            proposal_digest="synthetic-proposal-digest-2",
            tool_name="synthetic.tool",
            success=False,
            canonical_source_path="/synthetic/input-2.txt",
            post_hook_output="synthetic-output-2",
        )
        second_call_ok = len(recorder.calls) == 2 and second_outcome["completion_sequence"] == 2
        add(
            checks,
            "E2-08",
            "E2",
            second_call_ok,
            {"call_count": len(recorder.calls), "sequence": second_outcome.get("completion_sequence")},
            {"call_count": 2, "sequence": 2},
            "AUTHORIZATION_TRANSPORT",
        )

        # Synthetic adapter-error control. after_tool is called once; failed acknowledgement is not consumed.
        raising_adapter = RaisingAdapter()
        error_state = state_class()
        error_transport = transport_class(raising_adapter, error_state)
        adapter_error_propagated = False
        try:
            error_transport.acknowledge(
                trace_identity="synthetic-error-trace",
                proposal_digest="synthetic-error-proposal",
                tool_name="synthetic.tool",
                success=True,
                canonical_source_path="/synthetic/error.txt",
                post_hook_output="synthetic-error-output",
            )
        except RuntimeError as exc:
            adapter_error_propagated = str(exc) == "synthetic adapter rejection"
        add(
            checks,
            "E2-09",
            "E2",
            adapter_error_propagated and raising_adapter.call_count == 1,
            {"propagated": adapter_error_propagated, "adapter_call_count": raising_adapter.call_count},
            {"propagated": True, "adapter_call_count": 1},
            "AUTHORIZATION_TRANSPORT",
        )
        failure_not_consumed = not error_state.consumed_outcome_identities
        add(
            checks,
            "E2-10",
            "E2",
            failure_not_consumed,
            sorted(error_state.consumed_outcome_identities),
            [],
            "REPLAY_ORCHESTRATION",
        )
        error_sequence_observed = error_state.counter_by_trace.get("synthetic-error-trace") == 1
        add(
            checks,
            "E2-11",
            "E2",
            error_sequence_observed,
            error_state.counter_by_trace,
            {"synthetic-error-trace": 1},
            "REPLAY_ORCHESTRATION",
        )

        e2_rows.extend(
            [
                {"control": "first_acknowledgement", "passed": one_call and same_metadata, "observed": "one call; metadata matched"},
                {"control": "value_free_keys", "passed": exact_keys and no_prohibited_keys, "observed": ";".join(sorted(outcome))},
                {"control": "first_consumption", "passed": consumed_once, "observed": consumed_identity},
                {"control": "duplicate_consumption", "passed": duplicate_rejected, "observed": "ValueError" if duplicate_rejected else "NOT_REJECTED"},
                {"control": "second_acknowledgement", "passed": second_call_ok, "observed": f"calls={len(recorder.calls)};sequence={second_outcome.get('completion_sequence')}"},
                {"control": "adapter_error_propagation", "passed": adapter_error_propagated, "observed": f"calls={raising_adapter.call_count}"},
                {"control": "failed_ack_not_consumed", "passed": failure_not_consumed, "observed": str(sorted(error_state.consumed_outcome_identities))},
            ]
        )

        failed = [row["check_id"] for row in checks if not row["passed"]]
        qualified = not failed
        status = (
            "P2O_E_BRIDGE_IMPORT_AND_SYNTHETIC_INTEGRATION_QUALIFICATION_COMPLETE_PASS"
            if qualified
            else "P2O_E_BRIDGE_IMPORT_AND_SYNTHETIC_INTEGRATION_QUALIFICATION_COMPLETE_WITH_GAPS"
        )
        next_gate = (
            "EX6_P2B_P2O_F_CONTROLLED_BRIDGE_INSTANCE_LIFECYCLE_QUALIFICATION"
            if qualified
            else "EX6_P2B_P2O_E_R1_BRIDGE_OR_TRANSPORT_RECONCILIATION"
        )
        claim_boundary = {
            "allowed": [
                "controlled bridge importability and packaged SandboxEnv resolution",
                "bridge inheritance and constructor-signature observations",
                "direct synthetic transport acknowledgement findings",
                "exactly one adapter acknowledgement per tested acknowledge call",
                "value-free metadata-key findings under synthetic inputs",
                "synthetic sequence-consumption and adapter-error findings",
                "eligibility recommendation for a separate controlled bridge-instance lifecycle gate",
            ],
            "prohibited": [
                "TrustedBridgeSandboxV1 instantiation",
                "SandboxEnv instantiation or behavior",
                "actual fs.read behavior",
                "tool execution",
                "HTTP sink behavior",
                "source retrieval success",
                "real secret capture",
                "protected-value lineage",
                "end-to-end authorization transport correctness",
                "guardrail effectiveness",
                "real exfiltration prevention",
            ],
        }
        result = {
            "version": VERSION,
            "created_at_utc": now(),
            "status": status,
            "classification": "CONTROLLED_BRIDGE_IMPORT_AND_DIRECT_SYNTHETIC_TRANSPORT_INTEGRATION",
            "P2O_D_parent_verified": True,
            "checks": {
                "total": len(checks),
                "passed": len(checks) - len(failed),
                "failed": len(failed),
                "failed_ids": failed,
            },
            "E1": {
                "bridge_imported": True,
                "packaged_sandbox_module_resolved": True,
                "bridge_subclasses_sandbox": inheritance_ok,
                "bridge_constructor_signature": bridge_signature,
                "bridge_instantiated": False,
                "sandbox_instantiated": False,
            },
            "E2": {
                "synthetic_acknowledge_calls": 2,
                "recorded_adapter_calls": len(recorder.calls),
                "exactly_once_per_tested_call": qualified,
                "value_free_outcome_keys": sorted(EXPECTED_OUTCOME_KEYS),
                "adapter_error_call_count": raising_adapter.call_count,
                "failed_acknowledgement_consumed": not failure_not_consumed,
            },
            "readiness": {
                "controlled_bridge_instance_lifecycle_gate_eligible": qualified,
                "bridge_importable": qualified,
                "direct_synthetic_transport_integration_qualified": qualified,
                "bridge_instantiated": False,
                "sandbox_instantiated": False,
                "identity_freeze_eligible": False,
                "controlled_actual_fs_read_eligible": False,
            },
            "execution_boundaries": {
                "source_modified": False,
                "bridge_module_imported": True,
                "packaged_sandbox_module_imported": True,
                "bridge_instantiated": False,
                "sandbox_instantiated": False,
                "sandbox_executed": False,
                "actual_fs_read_executed": False,
                "tools_executed": False,
                "http_sink_executed": False,
                "protected_fixture_contents_read": False,
                "real_secret_values_used": False,
                "gym_executed": False,
                "predicates_executed": False,
                "breach_executed": False,
                "models_used": False,
                "external_effects_observed": False,
            },
            "scientific_verdict": {
                "bridge_importability": "ESTABLISHED" if qualified else "GAPS_IDENTIFIED",
                "direct_synthetic_transport_integration": "ESTABLISHED_WITHIN_TESTED_SYNTHETIC_SCOPE" if qualified else "GAPS_IDENTIFIED",
                "bridge_instance_lifecycle": "NOT_EVALUATED",
                "Sandbox_behavior": "NOT_EVALUATED",
                "actual_source_retrieval": "NOT_EVALUATED",
                "secret_capture": "NOT_ESTABLISHED",
                "protected_value_lineage": "NOT_ESTABLISHED",
                "authorization_transport_correctness": "NOT_ESTABLISHED_END_TO_END",
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": "NOT_ESTABLISHED",
            },
            "claim_boundary": claim_boundary,
            "next_gate": next_gate,
        }

        result_path = output_dir / "ex6_p2b_p2o_e_result.json"
        checks_path = output_dir / "ex6_p2b_p2o_e_checks.csv"
        e1_path = output_dir / "ex6_p2b_p2o_e_e1_bridge_import.csv"
        e2_path = output_dir / "ex6_p2b_p2o_e_e2_synthetic_integration.csv"
        claim_path = output_dir / "ex6_p2b_p2o_e_claim_boundary.json"
        binding_path = output_dir / "ex6_p2b_p2o_e_binding.json"

        write_json(result_path, result)
        write_csv(
            checks_path,
            checks,
            ["check_id", "execution_layer", "passed", "observed", "expected", "failure_layer"],
        )
        write_csv(e1_path, e1_rows, ["control", "passed", "observed"])
        write_csv(e2_path, e2_rows, ["control", "passed", "observed"])
        write_json(claim_path, claim_boundary)
        write_json(
            binding_path,
            {
                "version": VERSION,
                "created_at_utc": now(),
                "runner": identity(Path(__file__).resolve()),
                "inputs": {key: identity(path) for key, path in inputs.items()},
                "sources": {
                    "transport": identity(transport_path),
                    "path_helper": identity(path_helper_path),
                    "bridge": identity(bridge_path),
                    "packaged_sandbox": identity(sandbox_path),
                },
                "project_root": str(project),
                "imported_modules": imported_modules,
                "source_modified": False,
                "bridge_instantiated": False,
                "sandbox_instantiated": False,
            },
        )

        derived = (result_path, checks_path, e1_path, e2_path, claim_path, binding_path)
        bound = tuple(inputs.values())
        sources = (transport_path, path_helper_path, bridge_path, sandbox_path)
        manifest_rows = [
            {**identity(path), "role": "P2O_E_DERIVED"} for path in derived
        ] + [
            {**identity(path), "role": "P2O_E_BOUND"} for path in bound
        ] + [
            {
                **identity(path),
                "role": "P2O_E_IMPORTED_SOURCE"
                if path in {transport_path, bridge_path, sandbox_path}
                else "P2O_E_BOUND_PURE_SOURCE",
            }
            for path in sources
        ]
        manifest_path = output_dir / "ex6_p2b_p2o_e_manifest.csv"
        write_csv(
            manifest_path,
            manifest_rows,
            ["artifact", "role", "size_bytes", "sha256", "path"],
        )
        external_path = output_dir / "ex6_p2b_p2o_e_manifest_external_binding.json"
        write_json(
            external_path,
            {
                "version": VERSION,
                "created_at_utc": now(),
                "status": status,
                "manifest_filename": manifest_path.name,
                "manifest_size_bytes": manifest_path.stat().st_size,
                "manifest_sha256": sha256(manifest_path),
                "runner_sha256": sha256(Path(__file__).resolve()),
                "parent_p2o_d_manifest_sha256": PARENT_MANIFEST_SHA,
                "checks_total": len(checks),
                "checks_passed": len(checks) - len(failed),
                "checks_failed": len(failed),
                "controlled_bridge_instance_lifecycle_gate_eligible": qualified,
                "bridge_module_imported": True,
                "bridge_instantiated": False,
                "sandbox_instantiated": False,
                "controlled_actual_fs_read_eligible": False,
                "source_modified": False,
                "next_gate": next_gate,
            },
        )

        print(
            json.dumps(
                {
                    "status": status,
                    "checks_total": len(checks),
                    "checks_passed": len(checks) - len(failed),
                    "checks_failed": len(failed),
                    "failed_ids": failed,
                    "bridge_constructor_signature": bridge_signature,
                    "bridge_instantiated": False,
                    "sandbox_instantiated": False,
                    "actual_fs_read_executed": False,
                    "manifest_sha256": sha256(manifest_path),
                    "next_gate": next_gate,
                },
                indent=2,
            )
        )
    except Exception as exc:
        failure_path = output_dir / "P2O_E_FAILED.json"
        failure_path.write_text(
            json.dumps(
                {
                    "version": VERSION,
                    "created_at_utc": now(),
                    "status": "P2O_E_QUALIFICATION_BLOCKED",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "checks_frozen": checks,
                    "imported_modules": imported_modules,
                    "source_modified": False,
                    "bridge_instantiated": False,
                    "sandbox_instantiated": False,
                    "actual_fs_read_executed": False,
                    "tools_executed": False,
                    "http_sink_executed": False,
                    "effects_observed": False,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=VERSION)
    for flag in [
        "p2o-d-result",
        "p2o-d-checks",
        "p2o-d-d1-imports",
        "p2o-d-d2-units",
        "p2o-d-claim-boundary",
        "p2o-d-binding",
        "p2o-d-external-binding",
        "p2o-d-manifest",
        "p2o-d-runner",
        "project-root",
        "output-dir",
    ]:
        parser.add_argument("--" + flag, required=True)
    return parser.parse_args()


if __name__ == "__main__":
    try:
        main(parse_args())
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
