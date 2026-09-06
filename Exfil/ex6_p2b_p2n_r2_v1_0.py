#!/usr/bin/env python3
"""EX6 P2B P2N R2 implementation-readiness and change-manifest specification.

Read-only planning gate bound to frozen P2N-R1 evidence. Produces an exact
PROPOSED file/class/helper inventory, insertion-point manifest, change
boundaries, verification requirements, staged qualification plan, freeze
requirements, identity-binding strategy, and claim boundary.

This runner does not modify SDK source, create implementation source, import SDK
modules, execute fs.read/tools/Sandbox/Gym/predicates/breach/models, read fixture
contents, preview/export source values, or observe effects.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX6_P2B_P2N_R2_IMPLEMENTATION_READINESS_AND_CHANGE_MANIFEST_SPECIFICATION_v1.0"
PARENT_VERSION = "EX6_P2B_P2N_R1_INDEPENDENT_DESIGN_QUALIFICATION_v1.0"
PARENT_STATUS = "P2N_R1_INDEPENDENT_DESIGN_QUALIFICATION_COMPLETE_PASS"
PARENT_MANIFEST_SHA = "192CEA12FCB677F16C367F10B5BEA0C5F5042205EDE47A9698836C87FDECE5DD"
PARENT_RUNNER_SHA = "33841FFE1870A2E0DAFBA06DB405A6333FCD23F6006FD80EA2E397589B47F6ED"
EXPECTED_CHECKS = 80


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


def main(args: argparse.Namespace) -> None:
    out = Path(args.output_dir).resolve()
    require(not out.exists(), f"Refusing overwrite: {out}")
    out.mkdir(parents=True)
    try:
        inputs = {
            "result": Path(args.p2n_r1_result).resolve(),
            "checks": Path(args.p2n_r1_checks).resolve(),
            "claim_boundary": Path(args.p2n_r1_claim_boundary).resolve(),
            "binding": Path(args.p2n_r1_binding).resolve(),
            "external_binding": Path(args.p2n_r1_external_binding).resolve(),
            "manifest": Path(args.p2n_r1_manifest).resolve(),
            "runner": Path(args.p2n_r1_runner).resolve(),
        }
        for label, path in inputs.items():
            require(path.is_file(), f"Missing P2N-R1 {label}: {path}")

        parent = json.loads(inputs["result"].read_text(encoding="utf-8-sig"))
        external = json.loads(
            inputs["external_binding"].read_text(encoding="utf-8-sig")
        )
        boundary = json.loads(
            inputs["claim_boundary"].read_text(encoding="utf-8-sig")
        )
        checks = list(
            csv.DictReader(inputs["checks"].open(encoding="utf-8-sig", newline=""))
        )

        require(
            parent.get("version") == PARENT_VERSION
            and parent.get("status") == PARENT_STATUS,
            "P2N-R1 parent differs",
        )
        require(
            parent.get("checks", {}).get("total") == EXPECTED_CHECKS
            and parent.get("checks", {}).get("passed") == EXPECTED_CHECKS
            and parent.get("checks", {}).get("failed") == 0,
            "P2N-R1 check summary differs",
        )
        require(len(checks) == EXPECTED_CHECKS, "P2N-R1 checks CSV count differs")
        require(
            all(row.get("passed") == "True" for row in checks),
            "P2N-R1 contains a failed check",
        )
        require(
            external.get("status") == PARENT_STATUS
            and external.get("manifest_sha256") == PARENT_MANIFEST_SHA,
            "P2N-R1 external binding differs",
        )
        require(
            sha256(inputs["manifest"]) == PARENT_MANIFEST_SHA
            and sha256(inputs["runner"]) == PARENT_RUNNER_SHA,
            "P2N-R1 identities differ",
        )
        require(
            external.get("implementation_authorized") is False
            and external.get("controlled_actual_fs_read_eligible") is False
            and external.get("actual_fs_read_executed") is False,
            "P2N-R1 execution boundary differs",
        )
        require(
            "implementation existence" in boundary.get("prohibited", [])
            and "runtime wiring" in boundary.get("prohibited", []),
            "P2N-R1 claim boundary differs",
        )

        # All names below are proposed planning identities only. No implementation
        # file is written by this gate.
        file_inventory = [
            {
                "change_id": "CHG-001",
                "path": "aicomp_sdk/core/env/trusted_outcome_transport_v1.py",
                "action": "CREATE_PROPOSED",
                "artifact_role": "trusted metadata canonicalization, digest production, event identity, and adapter bridge",
                "implementation_status": "NOT_IMPLEMENTED",
                "expected_parent": "NONE_NEW_FILE",
                "immutable_baseline_impact": "NONE",
            },
            {
                "change_id": "CHG-002",
                "path": "aicomp_sdk/core/env/sandbox_trusted_bridge_v1.py",
                "action": "CREATE_PROPOSED",
                "artifact_role": "opt-in host wrapper or subclass integrating transport without editing packaged SandboxEnv",
                "implementation_status": "NOT_IMPLEMENTED",
                "expected_parent": "aicomp_sdk/core/env/sandbox.py",
                "immutable_baseline_impact": "PACKAGED_SOURCE_UNMODIFIED",
            },
            {
                "change_id": "CHG-003",
                "path": "aicomp_sdk/core/tools/fs_trusted_result_v1.py",
                "action": "CREATE_PROPOSED",
                "artifact_role": "canonical source-path derivation sharing frozen fs resolver semantics",
                "implementation_status": "NOT_IMPLEMENTED",
                "expected_parent": "aicomp_sdk/core/tools/fs.py",
                "immutable_baseline_impact": "PACKAGED_SOURCE_UNMODIFIED",
            },
            {
                "change_id": "CHG-004",
                "path": "aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py",
                "action": "BIND_ONLY_NO_CHANGE",
                "artifact_role": "existing repaired adapter consumer",
                "implementation_status": "EXISTING_FROZEN_INPUT",
                "expected_parent": "BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99",
                "immutable_baseline_impact": "NO_CHANGE",
            },
        ]

        class_inventory = [
            {
                "class_id": "CLS-001",
                "class_name": "TrustedOutcomeTransportV1",
                "proposed_file": "aicomp_sdk/core/env/trusted_outcome_transport_v1.py",
                "responsibility": "construct value-free trusted outcome metadata and call adapter.after_tool",
                "mutable_state": "NONE",
                "status": "PROPOSED_NOT_IMPLEMENTED",
            },
            {
                "class_id": "CLS-002",
                "class_name": "TrustedEventSequenceStateV1",
                "proposed_file": "aicomp_sdk/core/env/trusted_outcome_transport_v1.py",
                "responsibility": "allocate monotonic proposal/outcome identities and track consumed outcomes",
                "mutable_state": "counter_by_trace; consumed_outcome_identities",
                "status": "PROPOSED_NOT_IMPLEMENTED",
            },
            {
                "class_id": "CLS-003",
                "class_name": "TrustedBridgeSandboxV1",
                "proposed_file": "aicomp_sdk/core/env/sandbox_trusted_bridge_v1.py",
                "responsibility": "opt-in host integration preserving frozen SandboxEnv ordering",
                "mutable_state": "transport and sequence snapshots only",
                "status": "PROPOSED_NOT_IMPLEMENTED",
            },
        ]

        helper_inventory = [
            {
                "helper_id": "HLP-001",
                "helper_name": "canonicalize_post_hook_output_v1",
                "proposed_file": "aicomp_sdk/core/env/trusted_outcome_transport_v1.py",
                "inputs": "post-hook-finalized output; explicit type tag",
                "outputs": "canonical bytes",
                "failure": "unsupported/noncanonical type raises fail-closed error",
                "status": "PROPOSED_NOT_IMPLEMENTED",
            },
            {
                "helper_id": "HLP-002",
                "helper_name": "compute_raw_output_sha256_v1",
                "proposed_file": "aicomp_sdk/core/env/trusted_outcome_transport_v1.py",
                "inputs": "canonical bytes",
                "outputs": "64 uppercase hex SHA-256",
                "failure": "no digest on canonicalization failure",
                "status": "PROPOSED_NOT_IMPLEMENTED",
            },
            {
                "helper_id": "HLP-003",
                "helper_name": "compute_protected_value_bound_digest_v1",
                "proposed_file": "aicomp_sdk/core/env/trusted_outcome_transport_v1.py",
                "inputs": "domain tag; trace; proposal digest; outcome identity; canonical path; raw digest",
                "outputs": "64 uppercase hex bound digest",
                "failure": "missing prerequisite blocks digest and acknowledgement",
                "status": "PROPOSED_NOT_IMPLEMENTED",
            },
            {
                "helper_id": "HLP-004",
                "helper_name": "canonical_source_path_v1",
                "proposed_file": "aicomp_sdk/core/tools/fs_trusted_result_v1.py",
                "inputs": "filesystem root; requested path; resolved path",
                "outputs": "workspace-relative POSIX path with one leading slash",
                "failure": "outside root, ambiguity, or normalization mismatch fails closed",
                "status": "PROPOSED_NOT_IMPLEMENTED",
            },
            {
                "helper_id": "HLP-005",
                "helper_name": "snapshot_trusted_transport_state_v1",
                "proposed_file": "aicomp_sdk/core/env/trusted_outcome_transport_v1.py",
                "inputs": "sequence and consumed-identity state",
                "outputs": "deterministic JSON-compatible snapshot",
                "failure": "unrecognized snapshot schema rejected",
                "status": "PROPOSED_NOT_IMPLEMENTED",
            },
        ]

        insertion_points = [
            {
                "insertion_id": "INS-001",
                "host": "TrustedBridgeSandboxV1 proposal path",
                "relative_order": "immediately before adapter.before_decide",
                "design_contract": "P2N-04",
                "operation": "allocate proposal event identity",
                "runtime_status": "NOT_IMPLEMENTED",
            },
            {
                "insertion_id": "INS-002",
                "host": "TrustedBridgeSandboxV1 tool outcome path",
                "relative_order": "after POST_TOOL_CALL output finalization; before serialization",
                "design_contract": "P2N-02|P2N-04|P2N-05",
                "operation": "allocate outcome identity; canonicalize output; derive path; compute raw digest",
                "runtime_status": "NOT_IMPLEMENTED",
            },
            {
                "insertion_id": "INS-003",
                "host": "TrustedBridgeSandboxV1 protected-read path",
                "relative_order": "after protected-path qualification and prerequisites; before adapter.after_tool",
                "design_contract": "P2N-03",
                "operation": "compute protected-value bound digest",
                "runtime_status": "NOT_IMPLEMENTED",
            },
            {
                "insertion_id": "INS-004",
                "host": "TrustedBridgeSandboxV1 acknowledgement path",
                "relative_order": "after trusted metadata production; before serialization, trace insertion, and runtime history",
                "design_contract": "P2N-01",
                "operation": "call adapter.after_tool exactly once",
                "runtime_status": "NOT_IMPLEMENTED",
            },
        ]

        changes = [
            {
                "boundary_id": "BND-001",
                "allowed": "create only the three proposed v1 files after later authorization",
                "prohibited": "modify packaged sandbox.py, fs.py, optimal.py, predicates.py, or frozen adapter v1_1",
                "verification": "pre/post SHA-256 equality for every prohibited file",
            },
            {
                "boundary_id": "BND-002",
                "allowed": "value-free hashes and canonical identities",
                "prohibited": "raw protected value or preview in logs, manifests, JSON, CSV, exceptions, or console",
                "verification": "marker scan plus schema allowlist over every produced artifact",
            },
            {
                "boundary_id": "BND-003",
                "allowed": "opt-in host wrapper qualification",
                "prohibited": "claim packaged runtime integration or hosted parity",
                "verification": "claim-boundary assertion in every result and external binding",
            },
        ]

        verification = [
            {"verification_id":"VER-001","phase":"static","requirement":"new modules parse and import without executing tools","pass_condition":"AST parse PASS; isolated import PASS; no side effects","failure_layer":"ADAPTER_PARSE"},
            {"verification_id":"VER-002","phase":"unit","requirement":"canonical output encoding deterministic for allowed types","pass_condition":"matched inputs reproduce identical bytes/digest; unsupported types fail closed","failure_layer":"SECRET_CAPTURE"},
            {"verification_id":"VER-003","phase":"unit","requirement":"canonical path aliases converge and escapes reject","pass_condition":"frozen positive/boundary/negative matrix passes","failure_layer":"ARGUMENT_FIDELITY"},
            {"verification_id":"VER-004","phase":"unit","requirement":"event sequence monotonic, snapshot-safe, and replay-resistant","pass_condition":"duplicate/cross-trace/nonmonotonic controls rejected","failure_layer":"REPLAY_ORCHESTRATION"},
            {"verification_id":"VER-005","phase":"synthetic_integration","requirement":"bridge constructs exact adapter outcome and calls after_tool once","pass_condition":"proposal retired once; mismatches fail closed; no tool execution","failure_layer":"AUTHORIZATION_TRANSPORT"},
            {"verification_id":"VER-006","phase":"controlled_runtime_later","requirement":"real fs.read result produces value-free identities","pass_condition":"requires separate authorization; no raw value in artifacts","failure_layer":"SOURCE_RETRIEVAL"},
        ]

        runtime_plan = [
            {"stage":"R2A","objective":"static implementation identity and prohibited-file integrity","tools_allowed":"none","source_value_allowed":"false","authorization":"future_gate_required"},
            {"stage":"R2B","objective":"pure helper unit controls","tools_allowed":"none","source_value_allowed":"synthetic_nonsecret_only","authorization":"future_gate_required"},
            {"stage":"R2C","objective":"synthetic bridge integration with adapter","tools_allowed":"none","source_value_allowed":"synthetic_nonsecret_only","authorization":"future_gate_required"},
            {"stage":"R2D","objective":"controlled fs.read preflight","tools_allowed":"none until separately approved","source_value_allowed":"false","authorization":"future_gate_required"},
            {"stage":"R2E","objective":"controlled value-free fs.read qualification","tools_allowed":"fs.read only if explicitly authorized","source_value_allowed":"never exported","authorization":"future_gate_required"},
        ]

        freeze = {
            "implementation_identity_freeze_eligible": False,
            "reason": "implementation files do not yet exist",
            "required_after_implementation": [
                "exact path, size, and SHA-256 for every new file",
                "pre/post SHA-256 equality for every prohibited existing file",
                "AST symbol inventory and signatures",
                "requirements-to-symbol traceability",
                "raw and canonical qualification results",
                "environment and runner identities",
                "manifest plus external manifest binding",
            ],
        }
        identity_strategy = {
            "source_binding": "bind new-file identities plus unchanged frozen parent identities",
            "runner_binding": "runner is external to its output manifest and bound by external binding",
            "event_binding": "trace_identity + event_kind + monotonic event_sequence",
            "proposal_binding": "existing adapter proposal digest contract remains authoritative",
            "output_binding": "domain-tagged canonical post-hook output SHA-256",
            "protected_binding": "domain-tagged digest over trace, proposal, outcome, path, and raw digest",
            "raw_value_policy": "never included in evidence artifacts",
        }
        claim = {
            "allowed": [
                "implementation-readiness plan",
                "proposed file/class/helper identities",
                "proposed insertion and change boundaries",
                "verification and staged qualification requirements",
                "implementation freeze and identity-binding strategy",
            ],
            "prohibited": [
                "implementation existence",
                "source modification",
                "runtime wiring",
                "actual fs.read behavior",
                "source retrieval success",
                "secret capture",
                "protected-value lineage",
                "authorization transport correctness",
                "guardrail effectiveness",
                "real exfiltration prevention",
            ],
        }

        result_out = {
            "version": VERSION,
            "created_at_utc": now(),
            "status": "P2N_R2_IMPLEMENTATION_READINESS_AND_CHANGE_MANIFEST_SPECIFICATION_COMPLETE_PASS",
            "classification": "READ_ONLY_IMPLEMENTATION_PLANNING",
            "P2N_R1_parent_verified": True,
            "inventory_counts": {
                "proposed_files": len(file_inventory),
                "proposed_classes": len(class_inventory),
                "proposed_helpers": len(helper_inventory),
                "insertion_points": len(insertion_points),
                "change_boundaries": len(changes),
                "verification_requirements": len(verification),
                "runtime_plan_stages": len(runtime_plan),
            },
            "readiness": {
                "design_independently_qualified": True,
                "change_manifest_specified": True,
                "implementation_authorized": False,
                "implementation_created": False,
                "identity_freeze_eligible": False,
                "controlled_actual_fs_read_eligible": False,
            },
            "execution_boundaries": {
                "source_modified": False,
                "implementation_created": False,
                "sdk_modules_imported": False,
                "actual_fs_read_executed": False,
                "tools_executed": False,
                "fixture_contents_read": False,
                "source_value_previewed": False,
                "source_value_exported": False,
                "effects_observed": False,
                "sandbox_executed": False,
                "gym_executed": False,
                "predicates_executed": False,
                "breach_executed": False,
                "models_used": False,
            },
            "scientific_verdict": {
                "implementation_readiness_specification": "ESTABLISHED_AS_PLAN_ONLY",
                "implementation": "NOT_IMPLEMENTED",
                "runtime_behavior": "NOT_EVALUATED",
                "actual_source_retrieval": "NOT_EVALUATED",
                "secret_capture": "NOT_ESTABLISHED",
                "protected_value_lineage": "NOT_ESTABLISHED",
                "authorization_transport_correctness": "NOT_ESTABLISHED",
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": "NOT_ESTABLISHED",
            },
            "claim_boundary": claim,
            "next_gate": "EX6_P2B_P2N_R2A_INDEPENDENT_IMPLEMENTATION_READINESS_QUALIFICATION",
        }

        result_path = out / "ex6_p2b_p2n_r2_result.json"
        files_path = out / "ex6_p2b_p2n_r2_files.csv"
        classes_path = out / "ex6_p2b_p2n_r2_classes.csv"
        helpers_path = out / "ex6_p2b_p2n_r2_helpers.csv"
        insertions_path = out / "ex6_p2b_p2n_r2_insertions.csv"
        boundaries_path = out / "ex6_p2b_p2n_r2_change_boundaries.csv"
        verification_path = out / "ex6_p2b_p2n_r2_verification.csv"
        runtime_path = out / "ex6_p2b_p2n_r2_runtime_plan.csv"
        freeze_path = out / "ex6_p2b_p2n_r2_freeze_requirements.json"
        identity_path = out / "ex6_p2b_p2n_r2_identity_strategy.json"
        claim_path = out / "ex6_p2b_p2n_r2_claim_boundary.json"
        binding_path = out / "ex6_p2b_p2n_r2_binding.json"

        write_json(result_path, result_out)
        write_csv(files_path, file_inventory, ["change_id","path","action","artifact_role","implementation_status","expected_parent","immutable_baseline_impact"])
        write_csv(classes_path, class_inventory, ["class_id","class_name","proposed_file","responsibility","mutable_state","status"])
        write_csv(helpers_path, helper_inventory, ["helper_id","helper_name","proposed_file","inputs","outputs","failure","status"])
        write_csv(insertions_path, insertion_points, ["insertion_id","host","relative_order","design_contract","operation","runtime_status"])
        write_csv(boundaries_path, changes, ["boundary_id","allowed","prohibited","verification"])
        write_csv(verification_path, verification, ["verification_id","phase","requirement","pass_condition","failure_layer"])
        write_csv(runtime_path, runtime_plan, ["stage","objective","tools_allowed","source_value_allowed","authorization"])
        write_json(freeze_path, freeze)
        write_json(identity_path, identity_strategy)
        write_json(claim_path, claim)
        write_json(binding_path, {
            "version": VERSION,
            "created_at_utc": now(),
            "runner": identity(Path(__file__).resolve()),
            "inputs": {key: identity(path) for key, path in inputs.items()},
            "source_modified": False,
            "implementation_created": False,
        })

        derived = (
            result_path, files_path, classes_path, helpers_path, insertions_path,
            boundaries_path, verification_path, runtime_path, freeze_path,
            identity_path, claim_path, binding_path,
        )
        bound = tuple(inputs.values())
        manifest_rows = [
            {**identity(path), "role": "P2N_R2_DERIVED"} for path in derived
        ] + [
            {**identity(path), "role": "P2N_R2_BOUND"} for path in bound
        ]
        manifest_path = out / "ex6_p2b_p2n_r2_manifest.csv"
        write_csv(manifest_path, manifest_rows, ["artifact","role","size_bytes","sha256","path"])
        external_path = out / "ex6_p2b_p2n_r2_manifest_external_binding.json"
        write_json(external_path, {
            "version": VERSION,
            "created_at_utc": now(),
            "status": result_out["status"],
            "manifest_filename": manifest_path.name,
            "manifest_size_bytes": manifest_path.stat().st_size,
            "manifest_sha256": sha256(manifest_path),
            "runner_sha256": sha256(Path(__file__).resolve()),
            "parent_manifest_sha256": PARENT_MANIFEST_SHA,
            "implementation_authorized": False,
            "implementation_created": False,
            "identity_freeze_eligible": False,
            "controlled_actual_fs_read_eligible": False,
            "source_modified": False,
            "actual_fs_read_executed": False,
            "next_gate": result_out["next_gate"],
        })
        print(json.dumps({
            "status": result_out["status"],
            "inventory_counts": result_out["inventory_counts"],
            "implementation_authorized": False,
            "implementation_created": False,
            "identity_freeze_eligible": False,
            "controlled_actual_fs_read_eligible": False,
            "manifest_sha256": sha256(manifest_path),
            "next_gate": result_out["next_gate"],
        }, indent=2))
    except Exception as exc:
        (out / "P2N_R2_FAILED.json").write_text(json.dumps({
            "version": VERSION,
            "created_at_utc": now(),
            "status": "P2N_R2_PLANNING_BLOCKED",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "source_modified": False,
            "implementation_created": False,
            "actual_fs_read_executed": False,
            "effects_observed": False,
        }, indent=2), encoding="utf-8")
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=VERSION)
    for flag in [
        "p2n-r1-result", "p2n-r1-checks", "p2n-r1-claim-boundary",
        "p2n-r1-binding", "p2n-r1-external-binding", "p2n-r1-manifest",
        "p2n-r1-runner", "output-dir",
    ]:
        parser.add_argument("--" + flag, required=True)
    return parser.parse_args()


if __name__ == "__main__":
    try:
        main(parse_args())
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
