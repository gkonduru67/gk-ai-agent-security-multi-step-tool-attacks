#!/usr/bin/env python3
"""EX6 v6.90A reviewed feasibility qualification.

Consumes only the frozen v6.90 P1 requirements package. It leaves all v6.90
artifacts unchanged and refines four feasibility labels without rewriting the
parent matrix. It separates P2A policy-only hardening from P2B trusted runtime
transport architecture.

No SDK import, source inspection, runtime execution, fixture access, hardened
policy implementation, wrapper injection, Sandbox modification, or policy
comparison is performed.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX6_HARDENED_REQUIREMENTS_REVIEWED_FEASIBILITY_QUALIFICATION_v6.90A"
EXPECTED_PARENT_MANIFEST_SHA256 = "2EEDFC189A29799D958853DC3568B86827C38E9C9932D057F7225154AD5A900B"
EXPECTED_PARENT_STATUS = "P1_REQUIREMENTS_CAPTURE_COMPLETE_REVIEW_REQUIRED"
EXPECTED_PARENT_REQUIREMENTS_COUNT = 46
EXPECTED_OPTIMAL_SHA256 = "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED"
EXPECTED_PREDICATES_SHA256 = "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"

OLD_LABEL = "REQUIRES_SANDBOX_CHANGE"
NEW_LABEL = "REQUIRES_TRUSTED_RUNTIME_EVENT_OR_OUTCOME_TRANSPORT"
AFFECTED_IDS = ("AZ-006", "AZ-007", "PV-002", "PV-003")

REQUIRED_PARENT_ARTIFACTS = {
    "ex6_v6_90_requirements_matrix.csv",
    "ex6_v6_90_authorization_grant_schema.json",
    "ex6_v6_90_current_context_capability.csv",
    "ex6_v6_90_unavailable_input_matrix.csv",
    "ex6_v6_90_matched_comparison_invariants.csv",
    "ex6_v6_90_hardened_requirements_specification.json",
    "ex6_v6_90_result.json",
    "ex6_v6_90_binding.json",
}

TRANSPORT_GAPS = [
    {
        "gap_id": "TG-READ-EVENT",
        "name": "TRUSTED_SUCCESSFUL_PROTECTED_READ_EVENT_TRANSPORT",
        "affected_requirements": "PV-002|PV-003",
        "before_decide_inputs": "ordered event identity|tool name|exact path|ok status|returned value|source|same-session ordering",
        "after_tool_inputs": "none for later sink decision if trusted read record is durably stored",
        "minimum_trust_boundary": "runtime event producer independent of model and prompt content",
        "direct_sandbox_edit_required": "NOT_ESTABLISHED_AS_ONLY_OPTION",
        "acceptable_design_options": "documented Sandbox context extension|separate trusted orchestration adapter|documented policy state coordinator",
        "prohibited_substitute": "recent_sources labels|path mention|failed read|synthetic value presented as real lineage",
    },
    {
        "gap_id": "TG-OUTCOME",
        "name": "TRUSTED_POST_TOOL_OUTCOME_ACKNOWLEDGEMENT",
        "affected_requirements": "AZ-006|AZ-007",
        "before_decide_inputs": "authorization identity|action|canonical target|proposal digest|expiry",
        "after_tool_inputs": "proposal digest|event identity|tool ok status|failure or denial status",
        "minimum_trust_boundary": "outcome producer bound to the actual tool event and proposal",
        "direct_sandbox_edit_required": "NOT_ESTABLISHED_AS_ONLY_OPTION",
        "acceptable_design_options": "documented post-tool callback|separate trusted orchestration adapter|documented policy state coordinator",
        "prohibited_substitute": "consume at proposal time while claiming one successful use|model acknowledgment|prompt acknowledgment",
    },
]

P2A_INCLUDED = [
    "GuardrailBase-compatible decide interface",
    "tool-specific argument handling",
    "official protected-path helper",
    "independent http.post URL and data inspection",
    "official EXFILTRATION payload-channel mapping",
    "generic Boolean early-allow removal",
    "public canonical helper reuse",
    "raw payload preservation",
    "deterministic snapshot and restore if stateful",
    "benign public-path and look-alike controls",
    "matched policy-unit decision and reason logging",
]

P2A_EXCLUDED = [
    "trusted action-target-proposal authorization enforcement",
    "trusted authorization issuer and expiry",
    "one-successful-use authorization consumption",
    "successful protected-read value lineage",
    "failed-read and wrong-source exclusion based on runtime outputs",
    "post-tool outcome handling",
    "live defense effectiveness claim",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def index_manifest(path: Path) -> dict[str, dict[str, str]]:
    rows = load_csv(path)
    required = {"artifact", "role", "size_bytes", "sha256", "source_path"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError(f"Parent manifest requires columns: {sorted(required)}")
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        artifact = (row.get("artifact") or "").strip()
        if artifact in indexed:
            raise ValueError(f"Duplicate parent artifact: {artifact}")
        indexed[artifact] = row
    missing = sorted(REQUIRED_PARENT_ARTIFACTS - set(indexed))
    if missing:
        raise ValueError(f"Missing required v6.90 artifacts: {missing}")
    return indexed


def verify_artifact(row: dict[str, str]) -> dict[str, Any]:
    path = Path(row["source_path"])
    exists = path.is_file()
    observed_size = path.stat().st_size if exists else None
    observed_sha = sha256(path) if exists else None
    expected_size = int(row["size_bytes"])
    expected_sha = row["sha256"].upper()
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
    parser.add_argument("--v6-90-manifest", required=True)
    parser.add_argument("--v6-90-binding", required=True)
    parser.add_argument("--out-root", required=True)
    args = parser.parse_args()

    parent_manifest = Path(args.v6_90_manifest)
    parent_binding = Path(args.v6_90_binding)
    out = Path(args.out_root)

    if out.exists():
        raise FileExistsError(f"Refusing to overwrite existing output directory: {out}")
    for path in (parent_manifest, parent_binding):
        if not path.is_file():
            raise FileNotFoundError(path)

    if sha256(parent_manifest) != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("v6.90 parent manifest identity mismatch")
    external = load_json(parent_binding)
    if external.get("manifest_sha256") != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("v6.90 external binding does not bind the expected manifest")
    if external.get("status") != EXPECTED_PARENT_STATUS:
        raise ValueError("v6.90 external binding status mismatch")
    if external.get("optimal_sha256") != EXPECTED_OPTIMAL_SHA256:
        raise ValueError("v6.90 external binding Optimal identity mismatch")
    if external.get("predicates_sha256") != EXPECTED_PREDICATES_SHA256:
        raise ValueError("v6.90 external binding predicates identity mismatch")

    indexed = index_manifest(parent_manifest)
    verifications = [verify_artifact(indexed[name]) for name in sorted(REQUIRED_PARENT_ARTIFACTS)]
    failed = [row for row in verifications if not row["passed"]]
    if failed:
        raise ValueError("v6.90 evidence verification failed: " + ", ".join(row["artifact"] for row in failed))

    requirements_path = Path(indexed["ex6_v6_90_requirements_matrix.csv"]["source_path"])
    requirements = load_csv(requirements_path)
    if len(requirements) != EXPECTED_PARENT_REQUIREMENTS_COUNT:
        raise ValueError(f"Expected {EXPECTED_PARENT_REQUIREMENTS_COUNT} requirements, found {len(requirements)}")
    by_id = {row["id"]: row for row in requirements}
    missing_ids = [item for item in AFFECTED_IDS if item not in by_id]
    if missing_ids:
        raise ValueError(f"Missing affected requirement IDs: {missing_ids}")
    invalid_labels = [item for item in AFFECTED_IDS if by_id[item]["feasibility"] != OLD_LABEL]
    if invalid_labels:
        raise ValueError(f"Affected requirements do not carry expected parent label: {invalid_labels}")

    parent_spec = load_json(Path(indexed["ex6_v6_90_hardened_requirements_specification.json"]["source_path"]))
    parent_result = load_json(Path(indexed["ex6_v6_90_result.json"]["source_path"]))
    if parent_spec.get("requirements_count") != EXPECTED_PARENT_REQUIREMENTS_COUNT:
        raise ValueError("v6.90 canonical specification requirement count mismatch")
    if parent_result.get("status") != EXPECTED_PARENT_STATUS:
        raise ValueError("v6.90 canonical result status mismatch")

    refined_rows: list[dict[str, Any]] = []
    for item in AFFECTED_IDS:
        parent = by_id[item]
        gap = "TG-OUTCOME" if item.startswith("AZ-") else "TG-READ-EVENT"
        refined_rows.append({
            "requirement_id": item,
            "section": parent["section"],
            "requirement": parent["requirement"],
            "parent_feasibility": parent["feasibility"],
            "reviewed_feasibility": NEW_LABEL,
            "transport_gap_id": gap,
            "direct_sandbox_change_required": "NOT_ESTABLISHED_AS_ONLY_OPTION",
            "P2A_policy_only_eligible": False,
            "P2B_transport_track": True,
            "claim_boundary": "REQUIREMENT_REMAINS_WITHHELD_UNTIL_TRUSTED_TRANSPORT_EXISTS",
        })

    parent_counts = Counter(row["feasibility"] for row in requirements)
    reviewed_counts = dict(parent_counts)
    reviewed_counts[OLD_LABEL] = reviewed_counts.get(OLD_LABEL, 0) - len(AFFECTED_IDS)
    if reviewed_counts[OLD_LABEL] == 0:
        del reviewed_counts[OLD_LABEL]
    reviewed_counts[NEW_LABEL] = len(AFFECTED_IDS)

    now = datetime.now(timezone.utc).isoformat()
    out.mkdir(parents=True)
    paths = {
        "verification": out / "ex6_v6_90A_parent_verification.csv",
        "refinement": out / "ex6_v6_90A_feasibility_refinement.csv",
        "gaps": out / "ex6_v6_90A_transport_gap_matrix.csv",
        "p2a": out / "ex6_v6_90A_p2a_policy_only_scope.json",
        "p2b": out / "ex6_v6_90A_p2b_trusted_transport_scope.json",
        "comparison": out / "ex6_v6_90A_comparison_boundary.json",
        "result": out / "ex6_v6_90A_result.json",
        "binding": out / "ex6_v6_90A_binding.json",
        "manifest": out / "ex6_v6_90A_manifest.csv",
        "external": out / "ex6_v6_90A_manifest_external_binding.json",
    }

    write_csv(paths["verification"], verifications, [
        "artifact", "path", "exists", "expected_size_bytes", "observed_size_bytes",
        "size_match", "expected_sha256", "observed_sha256", "sha256_match", "passed",
    ])
    write_csv(paths["refinement"], refined_rows, [
        "requirement_id", "section", "requirement", "parent_feasibility",
        "reviewed_feasibility", "transport_gap_id", "direct_sandbox_change_required",
        "P2A_policy_only_eligible", "P2B_transport_track", "claim_boundary",
    ])
    write_csv(paths["gaps"], TRANSPORT_GAPS, [
        "gap_id", "name", "affected_requirements", "before_decide_inputs",
        "after_tool_inputs", "minimum_trust_boundary", "direct_sandbox_edit_required",
        "acceptable_design_options", "prohibited_substitute",
    ])

    p2a = {
        "track": "P2A_POLICY_ONLY_SUBSET",
        "status": "ELIGIBLE_FOR_IMPLEMENTATION_DESIGN_AFTER_v6_90A_FREEZE",
        "recommended_class": "ProposalAwareOptimalGuardrail",
        "recommended_source_file": "aicomp_sdk/guardrails/proposal_aware_optimal.py",
        "existing_interface": "decide(self, tool_name, tool_args, context)",
        "included": P2A_INCLUDED,
        "excluded": P2A_EXCLUDED,
        "generic_boolean_fallback": "PROHIBITED",
        "hook_registry_for_initial_comparison": "IDENTICAL_EMPTY_DEFAULT",
        "claim_boundary": "PROPOSAL_LEVEL_HARDENING_ONLY",
        "full_action_target_proposal_authorization_claim": False,
        "real_source_lineage_claim": False,
        "live_defense_claim": False,
    }
    write_json(paths["p2a"], p2a)

    p2b = {
        "track": "P2B_TRUSTED_TRANSPORT_ARCHITECTURE",
        "status": "DESIGN_WITHHELD_PENDING_SEPARATE_CONTRACT",
        "proposed_component": "TrustedGuardrailContextAdapter",
        "component_identity": "MUST_HAVE_SEPARATE_SOURCE_FILE_SHA256_AND_MANIFEST",
        "direct_sandbox_edit": "AVOIDED_PENDING_ADAPTER_CONTRACT_REVIEW",
        "required_channels": {
            "before_decide": [
                "trusted authorization grant",
                "qualifying successful protected-read records",
            ],
            "after_tool": [
                "trusted tool outcome",
                "proposal digest",
                "event identity",
            ],
        },
        "trust_rules": [
            "no model-derived authorization",
            "no prompt-derived authorization",
            "no recent_sources-only lineage",
            "no arbitrary hook injection presented as trusted transport",
            "no synthetic value presented as real protected-source output",
        ],
        "comparison_classification": "POLICY_PLUS_TRUSTED_TRANSPORT_ARCHITECTURE_NOT_POLICY_ONLY",
        "policy_only_matrix_eligible": False,
        "implementation_authorized_by_v6_90A": False,
    }
    write_json(paths["p2b"], p2b)

    comparison = {
        "policy_only_track": {
            "only_changed_factor": "guardrail class",
            "identical_tool_name": True,
            "identical_tool_args": True,
            "identical_context": True,
            "identical_empty_hooks": True,
            "trusted_adapter_present": False,
            "classification": "POLICY_UNIT_COMPARISON_ONLY",
        },
        "transport_track": {
            "changed_factors": ["policy class", "transport adapter", "context schema", "state lifecycle as applicable"],
            "classification": "POLICY_PLUS_TRUSTED_TRANSPORT_ARCHITECTURE_COMPARISON",
            "must_not_be_reported_as_policy_only": True,
        },
        "synthetic_wrapper_injection_in_policy_only_matrix": "PROHIBITED",
        "full_authorization_or_real_lineage_claim_in_P2A": "PROHIBITED",
    }
    write_json(paths["comparison"], comparison)

    result = {
        "version": VERSION,
        "created_at_utc": now,
        "status": "P1_REVIEWED_FEASIBILITY_FREEZE_COMPLETE",
        "classification": "HARDENED_POLICY_REQUIREMENTS_QUALIFIED_WITH_POLICY_ONLY_AND_TRUSTED_TRANSPORT_TRACKS_SEPARATED",
        "execution_type": "READ_ONLY_REQUIREMENTS_REVIEW",
        "parent_v6_90_manifest_sha256": EXPECTED_PARENT_MANIFEST_SHA256,
        "required_parent_artifacts_verified": len(verifications),
        "parent_requirements_count": len(requirements),
        "affected_requirement_count": len(AFFECTED_IDS),
        "affected_requirement_ids": list(AFFECTED_IDS),
        "parent_feasibility_counts": dict(parent_counts),
        "reviewed_feasibility_counts": reviewed_counts,
        "distinct_transport_gap_count": len(TRANSPORT_GAPS),
        "distinct_transport_gaps": [row["name"] for row in TRANSPORT_GAPS],
        "direct_sandbox_change_established_as_only_option": False,
        "P2A_policy_only_subset_eligible": True,
        "P2B_transport_adapter_implementation_authorized": False,
        "v6_90_artifacts_modified": False,
        "runtime": False,
        "sdk_imported": False,
        "sdk_source_inspected": False,
        "model_called": False,
        "protected_fixture_opened": False,
        "source_modified": False,
        "hardened_policy_written": False,
        "wrapper_injected": False,
        "policy_comparison_executed": False,
        "harness_trick": "NOT_DEMONSTRATED",
        "security_finding": "NOT_ESTABLISHED_REQUIREMENTS_REVIEW_ONLY",
        "methodological_finding": "POLICY_ONLY_AND_TRUSTED_TRANSPORT_DEPENDENCIES_EXPLICITLY_SEPARATED",
        "claim_boundary": "P2A_PROPOSAL_LEVEL_HARDENING_ONLY; P2B_SEPARATE_ARCHITECTURE; NO_FULL_AUTHORIZATION_OR_REAL_LINEAGE_CLAIM",
    }
    write_json(paths["result"], result)

    binding = {
        "version": VERSION,
        "created_at_utc": now,
        "parent_v6_90_manifest": {
            "path": str(parent_manifest),
            "size_bytes": parent_manifest.stat().st_size,
            "sha256": sha256(parent_manifest),
        },
        "parent_v6_90_external_binding": {
            "path": str(parent_binding),
            "size_bytes": parent_binding.stat().st_size,
            "sha256": sha256(parent_binding),
        },
        "verified_parent_artifacts": verifications,
        "optimal_sha256": EXPECTED_OPTIMAL_SHA256,
        "predicates_sha256": EXPECTED_PREDICATES_SHA256,
        "v6_90_artifacts_modified": False,
        "paths_inferred": False,
        "runtime_executed": False,
        "sdk_imported": False,
        "sdk_source_inspected": False,
        "source_modified": False,
        "wrapper_injected": False,
        "python": sys.version,
        "platform": platform.platform(),
    }
    write_json(paths["binding"], binding)

    generated_keys = ["verification", "refinement", "gaps", "p2a", "p2b", "comparison", "result", "binding"]
    manifest_rows = [
        {
            "artifact": paths[key].name,
            "role": "DERIVED_REVIEWED_FEASIBILITY_FREEZE",
            "size_bytes": paths[key].stat().st_size,
            "sha256": sha256(paths[key]),
            "source_path": str(paths[key]),
        }
        for key in generated_keys
    ]
    for path in (parent_manifest, parent_binding):
        manifest_rows.append({
            "artifact": path.name,
            "role": "SOURCE_OR_PARENT",
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
            "source_path": str(path),
        })
    for row in verifications:
        manifest_rows.append({
            "artifact": row["artifact"],
            "role": "VERIFIED_PARENT_EVIDENCE",
            "size_bytes": row["observed_size_bytes"],
            "sha256": row["observed_sha256"],
            "source_path": row["path"],
        })
    write_csv(paths["manifest"], manifest_rows, ["artifact", "role", "size_bytes", "sha256", "source_path"])

    external_out = {
        "version": VERSION,
        "created_at_utc": now,
        "manifest_filename": paths["manifest"].name,
        "manifest_size_bytes": paths["manifest"].stat().st_size,
        "manifest_sha256": sha256(paths["manifest"]),
        "status": result["status"],
        "classification": result["classification"],
        "parent_v6_90_manifest_sha256": EXPECTED_PARENT_MANIFEST_SHA256,
        "optimal_sha256": EXPECTED_OPTIMAL_SHA256,
        "predicates_sha256": EXPECTED_PREDICATES_SHA256,
    }
    write_json(paths["external"], external_out)

    print(json.dumps({
        "status": result["status"],
        "classification": result["classification"],
        "verified_parent_artifacts": len(verifications),
        "affected_requirements": list(AFFECTED_IDS),
        "distinct_transport_gaps": result["distinct_transport_gaps"],
        "manifest_sha256": external_out["manifest_sha256"],
        "output_directory": str(out),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
