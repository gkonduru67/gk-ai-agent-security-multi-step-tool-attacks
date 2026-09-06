#!/usr/bin/env python3
"""EX6 v6.89B read-only evidence synthesis and correction freeze.

Consumes only the frozen v6.89A evidence package. It does not inspect SDK
source again, import the SDK, open fixtures, execute runtime behavior, modify
source, implement a hardened policy, or perform a policy comparison.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX6_PACKAGED_OPTIMAL_CONTRACT_FINAL_REVIEW_AND_CORRECTION_v6.89B"
EXPECTED_PARENT_MANIFEST_SHA256 = "6EFB85F31216FB2D4DEFD2AE2B5EFC2628C336CF7BAE640FE87ADF3CF54E7481"
EXPECTED_OPTIMAL_SHA256 = "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED"
EXPECTED_PREDICATES_SHA256 = "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"

REQUIRED_PARENT_ARTIFACTS = {
    "ex6_v6_89A_exact_source_blocks.csv",
    "ex6_v6_89A_branch_returns.csv",
    "ex6_v6_89A_rule_order.csv",
    "ex6_v6_89A_sandbox_call_order.csv",
    "ex6_v6_89A_matcher_helper_contract.csv",
    "ex6_v6_89A_reviewed_findings.csv",
    "ex6_v6_89A_reviewed_result.json",
    "ex6_v6_89A_binding.json",
}

CORRECTIONS = [
    {
        "correction_id": "C01_HTTP_POST_DATA_READ",
        "parent_generated_value": "http_post_data_read_established=true",
        "reviewed_value": "false_for_normal_url_plus_data_proposal",
        "status": "CORRECTED",
        "basis": "_extract_target checks path|url|cmd|data|body|content and returns the first present key; http.post requires url and data, so url is selected before data",
        "claim_boundary": "STATIC_SOURCE_CONTROL_FLOW_ONLY",
    },
    {
        "correction_id": "C02_URL_BEFORE_DATA",
        "parent_generated_value": "data_is_in_extract_target_key_sequence",
        "reviewed_value": "URL_SELECTED_BEFORE_DATA_FOR_NORMAL_HTTP_POST_SHAPE",
        "status": "ESTABLISHED",
        "basis": "v6.89A target key order and exact _extract_target block",
        "claim_boundary": "NORMAL_VALID_HTTP_POST_ARGUMENT_SHAPE_ONLY",
    },
    {
        "correction_id": "C03_PAYLOAD_INSPECTION",
        "parent_generated_value": "packaged_optimal_reads_http_post_data=ESTABLISHED",
        "reviewed_value": "PACKAGED_OPTIMAL_DOES_NOT_INSPECT_DATA_WHEN_URL_IS_PRESENT",
        "status": "CORRECTED",
        "basis": "first-present-key return prevents data inspection after url match",
        "claim_boundary": "DOES_NOT_ESTABLISH_RUNTIME_EXPLOITABILITY",
    },
    {
        "correction_id": "C04_PRE_TOOL_CALL_PROPAGATION",
        "parent_generated_value": "generic_hooks_can_modify_arguments=ESTABLISHED",
        "reviewed_value": "PRE_TOOL_CALL_MODIFIED_ARGS_PROPAGATE_TO_GUARDRAIL_AND_TOOL",
        "status": "ESTABLISHED",
        "basis": "Sandbox applies pre_tool_ctx.modified_args to local tool_args before guardrail.decide and tools.call",
        "claim_boundary": "SOURCE_ORDER_ONLY; DEFAULT_HOOK_USE_NOT_ESTABLISHED",
    },
    {
        "correction_id": "C05_PRE_GUARDRAIL_NON_PROPAGATION",
        "parent_generated_value": "generic hook context mutation exists",
        "reviewed_value": "PRE_GUARDRAIL_MODIFIED_FIELDS_NOT_ADOPTED_BY_GUARDRAIL_DECIDE_LOCAL_ARGUMENTS",
        "status": "ESTABLISHED_BY_SOURCE_FLOW",
        "basis": "after PRE_GUARDRAIL hooks, Sandbox calls decide(tool_name, tool_args, ctx), not values from pre_guard_ctx",
        "claim_boundary": "STATIC_CORE_FLOW_ONLY",
    },
    {
        "correction_id": "C06_POST_GUARDRAIL_NON_PROPAGATION",
        "parent_generated_value": "generic modified guardrail_decision capability exists",
        "reviewed_value": "POST_GUARDRAIL_MODIFIED_DECISION_NOT_ADOPTED_BY_SUBSEQUENT_LOCAL_DECISION_HANDLING",
        "status": "ESTABLISHED_BY_SOURCE_FLOW",
        "basis": "subsequent SANITIZE, DENY, and CONFIRM checks use local guardrail_decision",
        "claim_boundary": "STATIC_CORE_FLOW_ONLY",
    },
    {
        "correction_id": "C07_GUARDRAIL_INSTANCE_LIFETIME",
        "parent_generated_value": "guardrail_instance_lifetime=PARTIAL",
        "reviewed_value": "ONE_GUARDRAIL_INSTANCE_IS_STORED_AND_REUSED_WITHIN_A_SANDBOX_ENV",
        "status": "QUALIFIED_ESTABLISHED",
        "basis": "Sandbox stores self.guardrail and calls the same object; reset restores initial state rather than constructing a replacement",
        "claim_boundary": "WITHIN_ONE_SANDBOX_ENV_ONLY",
    },
    {
        "correction_id": "C08_RESET_SEMANTICS",
        "parent_generated_value": "snapshot_restore_supported",
        "reviewed_value": "RESET_CALLS_RESTORE_STATE_ON_THE_EXISTING_GUARDRAIL_INSTANCE",
        "status": "ESTABLISHED",
        "basis": "reset invokes _restore_guardrail_state(initial snapshot); helper delegates to self.guardrail.restore_state",
        "claim_boundary": "SOURCE_CONTRACT_ONLY",
    },
    {
        "correction_id": "C09_DORMANT_UNTRUSTED_MENTIONS_STATE",
        "parent_generated_value": "untrusted_mentions mutable state exists",
        "reviewed_value": "MUTABLE_BUT_NOT_READ_BY_DECIDE_AND_NOT_COVERED_BY_PACKAGED_OVERRIDE_OF_SNAPSHOT_RESTORE",
        "status": "QUALIFIED",
        "basis": "track_untrusted_content mutates the set; decide does not read it; packaged class inherits no-op base state methods",
        "claim_boundary": "NO_SECURITY_EFFECT_ESTABLISHED",
    },
    {
        "correction_id": "C10_OFFICIAL_MATCHER",
        "parent_generated_value": "direct_matcher_imports=[]",
        "reviewed_value": "PACKAGED_OPTIMAL_HAS_NO_DIRECT_OFFICIAL_MATCHER_IMPORT; PUBLIC_GUARDRAIL_HELPERS_ARE_AVAILABLE",
        "status": "ESTABLISHED",
        "basis": "v6.89A reviewed result and matcher helper contract",
        "claim_boundary": "HELPER_AVAILABILITY_IS_NOT_CURRENT_POLICY_USE",
    },
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def resolve_parent_rows(manifest_path: Path) -> dict[str, dict[str, str]]:
    rows = load_csv(manifest_path)
    required = {"artifact", "role", "size_bytes", "sha256", "source_path"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError(f"Parent manifest requires columns: {sorted(required)}")
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        artifact = (row.get("artifact") or "").strip()
        if artifact in indexed:
            raise ValueError(f"Duplicate artifact in parent manifest: {artifact}")
        indexed[artifact] = row
    missing = sorted(REQUIRED_PARENT_ARTIFACTS - set(indexed))
    if missing:
        raise ValueError(f"Parent manifest missing required artifacts: {missing}")
    return indexed


def verify_parent_artifact(row: dict[str, str]) -> dict[str, Any]:
    path = Path(row["source_path"])
    expected_size = int(row["size_bytes"])
    expected_sha = row["sha256"].upper()
    exists = path.is_file()
    observed_size = path.stat().st_size if exists else None
    observed_sha = sha256(path) if exists else None
    passed = exists and observed_size == expected_size and observed_sha == expected_sha
    return {
        "artifact": row["artifact"],
        "path": str(path),
        "exists": exists,
        "expected_size_bytes": expected_size,
        "observed_size_bytes": observed_size,
        "size_match": exists and observed_size == expected_size,
        "expected_sha256": expected_sha,
        "observed_sha256": observed_sha,
        "sha256_match": exists and observed_sha == expected_sha,
        "passed": passed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=VERSION)
    parser.add_argument("--v6-89a-manifest", required=True)
    parser.add_argument("--v6-89a-binding", required=True)
    parser.add_argument("--out-root", required=True)
    args = parser.parse_args()

    parent_manifest = Path(args.v6_89a_manifest)
    parent_binding = Path(args.v6_89a_binding)
    out = Path(args.out_root)

    if out.exists():
        raise FileExistsError(f"Refusing to overwrite existing output directory: {out}")
    if not parent_manifest.is_file():
        raise FileNotFoundError(parent_manifest)
    if not parent_binding.is_file():
        raise FileNotFoundError(parent_binding)
    if sha256(parent_manifest) != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("v6.89A parent manifest identity mismatch")

    parent_external = load_json(parent_binding)
    if parent_external.get("manifest_sha256") != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("v6.89A external binding does not bind the expected parent manifest")
    if parent_external.get("optimal_sha256") != EXPECTED_OPTIMAL_SHA256:
        raise ValueError("v6.89A external binding optimal.py identity mismatch")
    if parent_external.get("predicates_sha256") != EXPECTED_PREDICATES_SHA256:
        raise ValueError("v6.89A external binding predicates.py identity mismatch")

    indexed = resolve_parent_rows(parent_manifest)
    verifications = [verify_parent_artifact(indexed[name]) for name in sorted(REQUIRED_PARENT_ARTIFACTS)]
    failures = [row for row in verifications if not row["passed"]]
    if failures:
        labels = ", ".join(row["artifact"] for row in failures)
        raise ValueError(f"v6.89A required artifact identity verification failed: {labels}")

    parent_result_path = Path(indexed["ex6_v6_89A_reviewed_result.json"]["source_path"])
    parent_result = load_json(parent_result_path)
    if parent_result.get("status") != "REVIEWED_QUALIFICATION_COMPLETE":
        raise ValueError("v6.89A parent result does not report REVIEWED_QUALIFICATION_COMPLETE")
    if parent_result.get("http_post_data_read_established") is not True:
        raise ValueError("Expected parent classification to be corrected is not present")
    if parent_result.get("target_key_order") != ["path", "url", "cmd", "data", "body", "content"]:
        raise ValueError("Unexpected parent target key order")

    now = datetime.now(timezone.utc).isoformat()
    out.mkdir(parents=True)

    paths = {
        "verification": out / "ex6_v6_89B_parent_verification.csv",
        "corrections": out / "ex6_v6_89B_correction_matrix.csv",
        "contract": out / "ex6_v6_89B_final_contract.json",
        "result": out / "ex6_v6_89B_result.json",
        "binding": out / "ex6_v6_89B_binding.json",
        "manifest": out / "ex6_v6_89B_manifest.csv",
        "external": out / "ex6_v6_89B_manifest_external_binding.json",
    }

    write_csv(
        paths["verification"],
        verifications,
        ["artifact", "path", "exists", "expected_size_bytes", "observed_size_bytes", "size_match", "expected_sha256", "observed_sha256", "sha256_match", "passed"],
    )
    write_csv(
        paths["corrections"],
        CORRECTIONS,
        ["correction_id", "parent_generated_value", "reviewed_value", "status", "basis", "claim_boundary"],
    )

    final_contract = {
        "version": VERSION,
        "created_at_utc": now,
        "policy_identity": {
            "class": "OptimalGuardrail",
            "source_file": "aicomp_sdk/guardrails/optimal.py",
            "source_sha256": EXPECTED_OPTIMAL_SHA256,
        },
        "decision_contract": {
            "signature": "decide(self, tool_name, tool_args, context)",
            "context_fields_read": ["recent_sources", "user_authorized", "user_confirmed_safe"],
            "rule_order": [
                "generic authorization allow",
                "sensitive extracted-target deny",
                "recent-source taint calculation",
                "tainted dangerous-tool deny",
                "default allow",
            ],
            "target_key_order": ["path", "url", "cmd", "data", "body", "content"],
        },
        "http_post": {
            "normal_argument_shape": ["url", "data"],
            "selected_argument_under_first_present_key_logic": "url",
            "data_payload_inspected_by_packaged_optimal_in_normal_shape": False,
            "encoded_payload_detection_by_packaged_optimal": False,
            "runtime_exploitability": "NOT_ESTABLISHED",
        },
        "authorization": {
            "consumer_type": "generic Boolean",
            "precedes_target_and_taint_checks": True,
            "action_binding_in_consumer_condition": False,
            "target_binding_in_consumer_condition": False,
            "proposal_binding_in_consumer_condition": False,
            "trusted_setter": "NOT_ESTABLISHED",
            "runtime_reachability": "NOT_ESTABLISHED",
        },
        "sandbox": {
            "pre_tool_call_modified_args_propagated": True,
            "pre_guardrail_modified_fields_adopted_by_decide": False,
            "post_guardrail_modified_decision_adopted": False,
            "guardrail_instance_reused_within_one_sandbox_env": True,
            "reset_constructs_new_guardrail": False,
            "reset_calls_restore_state_on_existing_instance": True,
        },
        "packaged_state": {
            "untrusted_mentions_mutable": True,
            "read_by_decide": False,
            "sandbox_call_to_track_untrusted_content_established": False,
            "packaged_snapshot_restore_override_present": False,
            "security_effect": "NOT_ESTABLISHED",
        },
        "official_helpers": {
            "predicates_sha256": EXPECTED_PREDICATES_SHA256,
            "public_helpers": ["is_protected_secret_path", "exfil_payload_arg", "payload_exfiltrates_secret"],
            "require_full_trace": False,
            "directly_imported_by_packaged_optimal": False,
        },
        "claim_boundary": "STATIC_STRUCTURAL_CONTRACT_FINDINGS_ONLY; RUNTIME_REACHABILITY, EXPLOITABILITY, AND DEFENSE_EFFECTIVENESS NOT_ESTABLISHED",
    }
    write_json(paths["contract"], final_contract)

    result = {
        "version": VERSION,
        "created_at_utc": now,
        "status": "FINAL_CORRECTION_FREEZE_COMPLETE",
        "classification": "PACKAGED_OPTIMAL_STATIC_CONTRACT_FINAL_REVIEWED_QUALIFICATION_WITH_HTTP_POST_PAYLOAD_CORRECTION",
        "execution_type": "READ_ONLY_EVIDENCE_SYNTHESIS_AND_CORRECTION",
        "parent_v6_89A_manifest_sha256": EXPECTED_PARENT_MANIFEST_SHA256,
        "required_parent_artifacts_verified": len(verifications),
        "correction_count": len(CORRECTIONS),
        "runtime": False,
        "sdk_imported": False,
        "sdk_source_reinspected": False,
        "model_called": False,
        "protected_fixture_opened": False,
        "source_modified": False,
        "hardened_policy_implemented": False,
        "policy_comparison_executed": False,
        "harness_trick": "NOT_DEMONSTRATED",
        "security_finding": "NOT_ESTABLISHED_STATIC_CONTRACT_ONLY",
        "robust_structural_contract_findings": "ESTABLISHED",
        "http_post_data_read_parent_value": True,
        "http_post_data_read_reviewed_value": False,
        "hardened_requirements_ready": True,
        "hardened_implementation_ready": False,
        "claim_boundary": final_contract["claim_boundary"],
    }
    write_json(paths["result"], result)

    binding = {
        "version": VERSION,
        "created_at_utc": now,
        "parent_v6_89A_manifest": {
            "path": str(parent_manifest),
            "size_bytes": parent_manifest.stat().st_size,
            "sha256": sha256(parent_manifest),
        },
        "parent_v6_89A_external_binding": {
            "path": str(parent_binding),
            "size_bytes": parent_binding.stat().st_size,
            "sha256": sha256(parent_binding),
        },
        "verified_parent_artifacts": verifications,
        "optimal_sha256": EXPECTED_OPTIMAL_SHA256,
        "predicates_sha256": EXPECTED_PREDICATES_SHA256,
        "paths_inferred": False,
        "runtime_executed": False,
        "sdk_imported": False,
        "sdk_source_reinspected": False,
        "source_modified": False,
        "python": sys.version,
        "platform": platform.platform(),
    }
    write_json(paths["binding"], binding)

    generated = [paths[key] for key in ["verification", "corrections", "contract", "result", "binding"]]
    manifest_rows = [
        {
            "artifact": path.name,
            "role": "DERIVED_CORRECTION_FREEZE",
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
            "source_path": str(path),
        }
        for path in generated
    ]
    for path in [parent_manifest, parent_binding]:
        manifest_rows.append(
            {
                "artifact": path.name,
                "role": "SOURCE_OR_PARENT",
                "size_bytes": path.stat().st_size,
                "sha256": sha256(path),
                "source_path": str(path),
            }
        )
    for verification in verifications:
        manifest_rows.append(
            {
                "artifact": verification["artifact"],
                "role": "VERIFIED_PARENT_EVIDENCE",
                "size_bytes": verification["observed_size_bytes"],
                "sha256": verification["observed_sha256"],
                "source_path": verification["path"],
            }
        )
    write_csv(paths["manifest"], manifest_rows, ["artifact", "role", "size_bytes", "sha256", "source_path"])

    external = {
        "version": VERSION,
        "created_at_utc": now,
        "manifest_filename": paths["manifest"].name,
        "manifest_size_bytes": paths["manifest"].stat().st_size,
        "manifest_sha256": sha256(paths["manifest"]),
        "status": result["status"],
        "classification": result["classification"],
        "parent_v6_89A_manifest_sha256": EXPECTED_PARENT_MANIFEST_SHA256,
        "optimal_sha256": EXPECTED_OPTIMAL_SHA256,
        "predicates_sha256": EXPECTED_PREDICATES_SHA256,
    }
    write_json(paths["external"], external)

    print(json.dumps({
        "status": result["status"],
        "classification": result["classification"],
        "verified_parent_artifacts": len(verifications),
        "corrections": len(CORRECTIONS),
        "manifest_sha256": external["manifest_sha256"],
        "output_directory": str(out),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
