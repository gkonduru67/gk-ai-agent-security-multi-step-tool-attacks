#!/usr/bin/env python3
"""EX8-R1 read-only source-contract reconciliation.

Reconciles three frozen EX8 v1.0 expectation mismatches without modifying the
EX8 artifacts or SDK sources:
  EX8-151: api.py is an environment protocol/delegation layer; ToolEvent is
            constructed in sandbox.py and represented through exported traces.
  EX8-152: api.py delegates export_trace_dict; Trace ownership/production is
            outside api.py.
  EX8-306: the packaged baseline implementation class in optimal.py is Guardrail;
            OFFICIAL_BASELINE is its logical role, not its class name.

The runner rehashes the complete EX8 evidence pack, parent, runner, manifest,
and nine authoritative sources. It preserves the three original failed rows,
recomputes all 69 EX8 checks under corrected semantics, and writes a corrected
static parity contract only if all reconciled checks pass.

No SDK import or execution; no Sandbox/Gym construction or interaction; no tool,
fs.read, predicate, breach, model, HTTP, protected fixture value, real secret,
source modification, or external effect.
"""
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX8_R1_SOURCE_CONTRACT_RECONCILIATION_v1.0"
PARENT_VERSION = "EX8_FROZEN_PROPOSAL_SANDBOX_GYM_PARITY_v1.0"
PARENT_STATUS = "EX8_FROZEN_PROPOSAL_SANDBOX_GYM_PARITY_COMPLETE_WITH_GAPS"
PARENT_MANIFEST_SHA = "20F0F91E4FEC80C335A2A1F5FCEC94E12991557E2E01A788AC65DCFCAC05F622"
PARENT_RUNNER_SHA = "ADE531DD31BEB1BB0A7188A77DEBCE399EFA85ABD181186C662C1607B2A6E2D1"
NORMALIZATION_ID = "P2O-G.EVENT.NORMALIZATION.V1"
ORIGINAL_FAILED_IDS = ["EX8-151", "EX8-152", "EX8-306"]
SOURCE_IDENTITIES = {
    "sandbox": ("aicomp_sdk/core/env/sandbox.py", "B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0"),
    "gym": ("aicomp_sdk/core/env/gym.py", "8BBC3479515C388717D76FE9964D957A7CBD9BFB97C28AA894E9C51E3051F8AF"),
    "api": ("aicomp_sdk/core/env/api.py", "60F1E4424EC3DEE73186F87ED1184D2CA1DBC4C2A0022004DECEC8B6E94C7CB1"),
    "predicates": ("aicomp_sdk/core/predicates.py", "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"),
    "optimal": ("aicomp_sdk/guardrails/optimal.py", "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED"),
    "proposal_aware": ("aicomp_sdk/guardrails/proposal_aware_optimal.py", "918FFD61CDB9A406C965F06CF2BEC34C297AB231E26B6FC083AE34B00C37D452"),
    "trusted_adapter": ("aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py", "BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"),
    "transport": ("aicomp_sdk/core/env/trusted_outcome_transport_v1.py", "5C7F7D16A37896959C6F4CC769E5F72A6E5E534EE140BA5CAF2FB70661102CE1"),
    "bridge": ("aicomp_sdk/core/env/sandbox_trusted_bridge_v1.py", "3EE9BBB1E65949795A5639D12C55D81D8D0645357260DFC5A91DB1E9710288B6"),
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
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def add_check(rows, check_id, category, passed, observed, expected, layer, evidence_class="PRIMARY"):
    rows.append({
        "check_id": check_id,
        "category": category,
        "passed": bool(passed),
        "observed": str(observed),
        "expected": str(expected),
        "failure_layer": layer,
        "evidence_class": evidence_class,
    })


def class_names(tree: ast.AST) -> set[str]:
    return {node.name for node in tree.body if isinstance(node, ast.ClassDef)}


def class_methods(tree: ast.AST, class_name: str) -> set[str]:
    node = next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name), None)
    if node is None:
        return set()
    return {n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def call_names(tree: ast.AST) -> set[str]:
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            try:
                names.add(ast.unparse(node.func))
            except Exception:
                pass
    return names


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def bool_text(value: bool) -> str:
    return "True" if value else "False"


def main(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir).resolve()
    require(not output_dir.exists(), f"Refusing overwrite: {output_dir}")
    output_dir.mkdir(parents=True)
    checks: list[dict[str, Any]] = []

    try:
        project = Path(args.project_root).resolve()
        require(project.is_dir(), f"Missing project root: {project}")

        inputs = {
            "result": Path(args.ex8_result).resolve(),
            "checks": Path(args.ex8_checks).resolve(),
            "source_inventory": Path(args.ex8_source_inventory).resolve(),
            "symbol_inventory": Path(args.ex8_symbol_inventory).resolve(),
            "call_inventory": Path(args.ex8_call_inventory).resolve(),
            "assignment_inventory": Path(args.ex8_assignment_inventory).resolve(),
            "contract_excerpts": Path(args.ex8_contract_excerpts).resolve(),
            "route_map": Path(args.ex8_route_map).resolve(),
            "interface_map": Path(args.ex8_interface_map).resolve(),
            "parity_contract": Path(args.ex8_parity_contract).resolve(),
            "claim_boundary": Path(args.ex8_claim_boundary).resolve(),
            "binding": Path(args.ex8_binding).resolve(),
            "external_binding": Path(args.ex8_external_binding).resolve(),
            "manifest": Path(args.ex8_manifest).resolve(),
            "runner": Path(args.ex8_runner).resolve(),
        }
        for label, path in inputs.items():
            require(path.is_file(), f"Missing EX8 {label}: {path}")

        parent_result = json.loads(inputs["result"].read_text(encoding="utf-8-sig"))
        parent_external = json.loads(inputs["external_binding"].read_text(encoding="utf-8-sig"))
        parent_contract = json.loads(inputs["parity_contract"].read_text(encoding="utf-8-sig"))
        parent_claim = json.loads(inputs["claim_boundary"].read_text(encoding="utf-8-sig"))
        parent_checks = load_csv(inputs["checks"])
        source_inventory = load_csv(inputs["source_inventory"])
        symbol_inventory = load_csv(inputs["symbol_inventory"])
        call_inventory = load_csv(inputs["call_inventory"])
        assignment_inventory = load_csv(inputs["assignment_inventory"])
        excerpt_inventory = load_csv(inputs["contract_excerpts"])
        route_map = load_csv(inputs["route_map"])
        interface_map = load_csv(inputs["interface_map"])

        # Gate identity and immutability preflight.
        add_check(checks, "R1-001", "parent", parent_result.get("version") == PARENT_VERSION, parent_result.get("version"), PARENT_VERSION, "FIXTURE")
        add_check(checks, "R1-002", "parent", parent_result.get("status") == PARENT_STATUS, parent_result.get("status"), PARENT_STATUS, "FIXTURE")
        add_check(checks, "R1-003", "parent", parent_result.get("checks") == {"failed": 3, "failed_ids": ORIGINAL_FAILED_IDS, "passed": 66, "total": 69}, parent_result.get("checks"), "66/69 with three frozen failures", "FIXTURE")
        add_check(checks, "R1-004", "parent", sha256(inputs["manifest"]) == PARENT_MANIFEST_SHA and parent_external.get("manifest_sha256") == PARENT_MANIFEST_SHA, sha256(inputs["manifest"]), PARENT_MANIFEST_SHA, "FIXTURE")
        add_check(checks, "R1-005", "parent", sha256(inputs["runner"]) == PARENT_RUNNER_SHA and parent_external.get("runner_sha256") == PARENT_RUNNER_SHA, sha256(inputs["runner"]), PARENT_RUNNER_SHA, "FIXTURE")
        original_failed = [r["check_id"] for r in parent_checks if r.get("passed") == "False"]
        add_check(checks, "R1-006", "parent", len(parent_checks) == 69 and original_failed == ORIGINAL_FAILED_IDS, {"rows": len(parent_checks), "failed": original_failed}, {"rows": 69, "failed": ORIGINAL_FAILED_IDS}, "EVIDENCE")
        add_check(checks, "R1-007", "parent", parent_contract.get("event_normalization") == NORMALIZATION_ID, parent_contract.get("event_normalization"), NORMALIZATION_ID, "FIXTURE")

        # Rehash and parse all nine sources independently.
        source_paths = {key: project / rel for key, (rel, _) in SOURCE_IDENTITIES.items()}
        source_texts: dict[str, str] = {}
        source_trees: dict[str, ast.AST] = {}
        for index, (key, (relative, expected_hash)) in enumerate(SOURCE_IDENTITIES.items(), start=10):
            path = source_paths[key]
            exists = path.is_file()
            actual = sha256(path) if exists else "MISSING"
            add_check(checks, f"R1-{index:03d}", "source_identity", exists and actual == expected_hash, actual, expected_hash, "FIXTURE")
            if exists:
                text = path.read_text(encoding="utf-8")
                source_texts[key] = text
                try:
                    tree = ast.parse(text, filename=str(path))
                    source_trees[key] = tree
                    parsed = True
                except SyntaxError:
                    parsed = False
                add_check(checks, f"R1-{index+20:03d}", "ast_parse", parsed, key, "AST PASS", "ADAPTER_PARSE")

        # Validate inventories are bound to the same nine exact sources.
        source_by_key = {r["source"]: r for r in source_inventory}
        inventory_ok = (
            len(source_inventory) == 9
            and set(source_by_key) == set(SOURCE_IDENTITIES)
            and all(source_by_key[k]["sha256"] == SOURCE_IDENTITIES[k][1] for k in SOURCE_IDENTITIES)
            and all(source_by_key[k]["ast_parse"] == "True" for k in SOURCE_IDENTITIES)
        )
        add_check(checks, "R1-050", "inventory", inventory_ok, {k: source_by_key.get(k, {}).get("sha256") for k in SOURCE_IDENTITIES}, "nine exact source identities and AST pass", "FIXTURE")
        add_check(checks, "R1-051", "inventory", len(symbol_inventory) == 127, len(symbol_inventory), 127, "EVIDENCE")
        add_check(checks, "R1-052", "inventory", len(call_inventory) == 656, len(call_inventory), 656, "EVIDENCE")
        add_check(checks, "R1-053", "inventory", len(assignment_inventory) == 321, len(assignment_inventory), 321, "EVIDENCE")
        add_check(checks, "R1-054", "inventory", len(excerpt_inventory) == 22, len(excerpt_inventory), 22, "EVIDENCE")
        add_check(checks, "R1-055", "inventory", len(route_map) == 7 and all(r["status"] == "STATICALLY_OBSERVED" for r in route_map), route_map, "7/7 statically observed", "ROUTING")

        # Corrected architectural reconciliation from source plus frozen inventories.
        api_tree = source_trees["api"]
        sandbox_tree = source_trees["sandbox"]
        gym_tree = source_trees["gym"]
        optimal_tree = source_trees["optimal"]
        api_classes = class_names(api_tree)
        sandbox_classes = class_names(sandbox_tree)
        optimal_classes = class_names(optimal_tree)
        api_calls = call_names(api_tree)
        gym_calls = call_names(gym_tree)
        sandbox_calls = call_names(sandbox_tree)

        api_protocol_expected = {"EnvInteractionResult", "AttackEnvProtocol", "DiagnosticsEnv"}
        add_check(checks, "R1-060", "api_reconciliation", api_protocol_expected <= api_classes, sorted(api_classes), sorted(api_protocol_expected), "ADAPTER_PARSE")
        add_check(checks, "R1-061", "api_reconciliation", "ToolEvent" not in api_classes and "Trace" not in api_classes, sorted(api_classes), "ToolEvent and Trace not owned by api.py", "ADAPTER_PARSE")
        diagnostics_methods = class_methods(api_tree, "DiagnosticsEnv")
        add_check(checks, "R1-062", "api_reconciliation", {"interact", "export_trace_dict", "snapshot", "restore"} <= diagnostics_methods, sorted(diagnostics_methods), "delegation interface present", "ROUTING")
        add_check(checks, "R1-063", "api_reconciliation", {"self._inner.interact", "self._inner.export_trace_dict", "self._inner.snapshot", "self._inner.restore"} <= api_calls, sorted(api_calls), "inner environment delegation calls", "ROUTING")

        # ToolEvent ownership/production is in Sandbox, not API.
        tool_event_assignments = [r for r in assignment_inventory if r["source"] == "sandbox" and "ToolEvent(" in r["value"]]
        tool_event_calls = [r for r in call_inventory if r["source"] == "sandbox" and r["call"] == "ToolEvent"]
        add_check(checks, "R1-064", "tool_event_reconciliation", "SandboxEnv" in sandbox_classes and len(tool_event_calls) >= 3, {"classes": sorted(sandbox_classes), "ToolEvent_calls": len(tool_event_calls)}, "SandboxEnv and at least successful/recorded/failed ToolEvent construction", "TOOL_CALL_SERIALIZATION")
        successful_rows = [r for r in assignment_inventory if r["source"] == "sandbox" and r["targets"] in {"ev", "recorded_event"} and "ToolEvent(" in r["value"]]
        failed_rows = [r for r in assignment_inventory if r["source"] == "sandbox" and r["targets"] == "event" and "ok=False" in r["value"]]
        add_check(checks, "R1-065", "tool_event_reconciliation", len(successful_rows) >= 2 and len(failed_rows) == 1, {"success": len(successful_rows), "failure": len(failed_rows)}, "successful and failed ToolEvent producers", "TOOL_CALL_SERIALIZATION")
        add_check(checks, "R1-066", "tool_event_reconciliation", "self.trace.add_tool" in sandbox_calls, sorted(sandbox_calls), "Sandbox trace receives ToolEvent", "ROUTING")

        # Trace representation is delegated/exported cross-module.
        add_check(checks, "R1-067", "trace_reconciliation", "export_trace_dict" in diagnostics_methods and "self._inner.export_trace_dict" in api_calls, sorted(diagnostics_methods), "API delegates trace export", "ROUTING")
        add_check(checks, "R1-068", "trace_reconciliation", "export_trace_dict" in class_methods(sandbox_tree, "SandboxEnv"), sorted(class_methods(sandbox_tree, "SandboxEnv")), "Sandbox exports trace dictionary", "ROUTING")
        add_check(checks, "R1-069", "trace_reconciliation", "export_trace_dict" in class_methods(gym_tree, "GymAttackEnv") and "self._sandbox.export_trace_dict" in gym_calls, sorted(gym_calls), "Gym delegates trace dictionary export", "ROUTING")
        add_check(checks, "R1-070", "trace_reconciliation", "eval_predicates" in gym_calls and "is_breach" in gym_calls, sorted(gym_calls), "Gym evaluator-facing trace consumers", "EVALUATOR")

        # Packaged baseline actual identity.
        add_check(checks, "R1-071", "baseline_reconciliation", "Guardrail" in optimal_classes and "OptimalGuardrail" not in optimal_classes, sorted(optimal_classes), "actual class Guardrail; no OptimalGuardrail class", "ADAPTER_PARSE")
        guardrail_methods = class_methods(optimal_tree, "Guardrail")
        add_check(checks, "R1-072", "baseline_reconciliation", {"decide", "track_untrusted_content"} <= guardrail_methods, sorted(guardrail_methods), "packaged Guardrail interface", "ADAPTER_PARSE")
        optimal_symbols = [r for r in symbol_inventory if r["source"] == "optimal" and r["kind"] == "class"]
        add_check(checks, "R1-073", "baseline_reconciliation", any(r["symbol"] == "Guardrail" and r["bases"] == "GuardrailBase" for r in optimal_symbols), optimal_symbols, "Guardrail extends GuardrailBase", "ADAPTER_PARSE")

        # Preserve all original checks and recompute semantic status under corrected expectations.
        reconciliation_table = []
        corrected_status_by_id = {}
        for row in parent_checks:
            cid = row["check_id"]
            original_pass = row["passed"] == "True"
            if cid == "EX8-151":
                corrected_pass = (
                    "ToolEvent" not in api_classes
                    and len(tool_event_calls) >= 3
                    and "self.trace.add_tool" in sandbox_calls
                )
                corrected_expectation = "api.py delegates environment access; Sandbox owns ToolEvent production"
                evidence = "api AST + sandbox call/assignment inventories"
                classification = "CONTRACT_EXPECTATION_RECONCILED"
            elif cid == "EX8-152":
                corrected_pass = (
                    "Trace" not in api_classes
                    and "self._inner.export_trace_dict" in api_calls
                    and "self._sandbox.export_trace_dict" in gym_calls
                )
                corrected_expectation = "trace dictionary is exported through API and Gym delegation"
                evidence = "api/gym AST call inventory"
                classification = "CONTRACT_EXPECTATION_RECONCILED"
            elif cid == "EX8-306":
                corrected_pass = "Guardrail" in optimal_classes and "OptimalGuardrail" not in optimal_classes
                corrected_expectation = "optimal.py actual class Guardrail; logical role OFFICIAL_BASELINE"
                evidence = "optimal.py AST + symbol inventory"
                classification = "SYMBOL_IDENTITY_RECONCILED"
            else:
                corrected_pass = original_pass
                corrected_expectation = row["expected"]
                evidence = "frozen EX8 check carried forward after full artifact/source rehash"
                classification = "UNCHANGED_CHECK_REVALIDATED"
            corrected_status_by_id[cid] = corrected_pass
            reconciliation_table.append({
                "check_id": cid,
                "original_passed": original_pass,
                "original_observed": row["observed"],
                "original_expected": row["expected"],
                "corrected_passed": corrected_pass,
                "corrected_expectation": corrected_expectation,
                "evidence": evidence,
                "classification": classification,
            })

        add_check(checks, "R1-080", "recomputed_69", len(corrected_status_by_id) == 69, len(corrected_status_by_id), 69, "EVIDENCE")
        add_check(checks, "R1-081", "recomputed_69", all(corrected_status_by_id.values()), [k for k, v in corrected_status_by_id.items() if not v], [], "EVIDENCE")
        preserved_failures = [r for r in reconciliation_table if r["check_id"] in ORIGINAL_FAILED_IDS and not r["original_passed"] and r["corrected_passed"]]
        add_check(checks, "R1-082", "reconciliation", len(preserved_failures) == 3, preserved_failures, "three original failures preserved and reconciled", "EVIDENCE")

        # Corrected parity contract is emitted only after all reconciliation controls pass.
        base_prohibited = set(parent_claim.get("prohibited", []))
        required_prohibited = {
            "runtime parity", "hosted parity", "Sandbox or Gym behavior", "tool execution",
            "actual fs.read behavior", "protected fixture values", "real secret capture",
            "protected-value lineage", "guardrail effectiveness", "real exfiltration prevention",
        }
        add_check(checks, "R1-083", "claim_boundary", required_prohibited <= base_prohibited, sorted(base_prohibited), sorted(required_prohibited), "CLAIM_BOUNDARY")

        failed_controls = [r["check_id"] for r in checks if not r["passed"]]
        corrected_69_pass = all(corrected_status_by_id.values()) and len(corrected_status_by_id) == 69
        qualified = not failed_controls and corrected_69_pass
        status = "EX8_R1_SOURCE_CONTRACT_RECONCILIATION_COMPLETE_PASS" if qualified else "EX8_R1_SOURCE_CONTRACT_RECONCILIATION_COMPLETE_WITH_GAPS"
        next_gate = "EX8_INDEPENDENT_PARITY_QUALIFICATION_AND_FREEZE" if qualified else "EX8_R2_RECONCILIATION_REVIEW"

        corrected_contract = {
            "parity_id": "EX8.PROPOSAL.SANDBOX.GYM.STATIC.PARITY.V1.R1",
            "status": "CORRECTED_STATIC_CONTRACT_FROZEN" if qualified else "NOT_FROZEN",
            "classification": "READ_ONLY_STATIC_SOURCE_CONTRACT_RECONCILIATION",
            "parent_parity_id": parent_contract.get("parity_id"),
            "event_normalization": NORMALIZATION_ID,
            "api_layer": {
                "role": "ENVIRONMENT_PROTOCOL_DIAGNOSTICS_AND_DELEGATION",
                "direct_ToolEvent_owner": False,
                "direct_Trace_owner": False,
                "interact_delegation": "DiagnosticsEnv -> inner.interact",
                "trace_delegation": "DiagnosticsEnv -> inner.export_trace_dict",
                "snapshot_delegation": "DiagnosticsEnv -> inner.snapshot/restore",
            },
            "tool_event_representation": {
                "authoritative_producer_module": "aicomp_sdk/core/env/sandbox.py",
                "successful_event_construction": "STATICALLY_ESTABLISHED",
                "failed_event_construction": "STATICALLY_ESTABLISHED",
                "trace_insertion": "SandboxEnv.trace.add_tool",
            },
            "trace_representation": {
                "sandbox_export": "SandboxEnv.export_trace_dict",
                "gym_export": "GymAttackEnv.export_trace_dict -> SandboxEnv.export_trace_dict",
                "api_export": "DiagnosticsEnv.export_trace_dict -> inner.export_trace_dict",
                "evaluator_consumers": ["GymAttackEnv._info -> eval_predicates", "GymAttackEnv._info -> is_breach"],
            },
            "packaged_baseline": {
                "source_file": "aicomp_sdk/guardrails/optimal.py",
                "actual_class": "Guardrail",
                "base_class": "GuardrailBase",
                "logical_role": "OFFICIAL_BASELINE",
                "incorrect_alias": "OptimalGuardrail",
            },
            "proposal_to_guardrail_route": "STATICALLY_ESTABLISHED",
            "successful_and_failed_event_shapes": "STATICALLY_ESTABLISHED",
            "gym_to_sandbox_delegation": "STATICALLY_ESTABLISHED",
            "bridge_to_transport_snapshot": "STATICALLY_ESTABLISHED",
            "transport_to_adapter": "STATICALLY_ESTABLISHED",
            "runtime_parity": "NOT_EVALUATED",
            "hosted_parity": "NOT_ESTABLISHED",
            "actual_fs_read": "NOT_EXECUTED",
        }

        claim_boundary = {
            "allowed": [
                "corrected authoritative API ownership and delegation mapping",
                "corrected Sandbox ToolEvent production mapping",
                "corrected cross-module trace export and evaluator-consumer mapping",
                "corrected packaged baseline class identity Guardrail with OFFICIAL_BASELINE logical role",
                "recomputed 69-check static contract under corrected semantics",
                "eligibility recommendation for independent EX8 parity qualification",
            ],
            "prohibited": sorted(required_prohibited),
        }

        result = {
            "version": VERSION,
            "created_at_utc": now(),
            "status": status,
            "classification": "READ_ONLY_STATIC_EVIDENCE_RECONCILIATION",
            "EX8_v1_0_parent_verified": True,
            "original_EX8": {
                "status": PARENT_STATUS,
                "checks_total": 69,
                "checks_passed": 66,
                "checks_failed": 3,
                "failed_ids": ORIGINAL_FAILED_IDS,
                "preserved_immutable": True,
            },
            "recomputed_EX8_under_corrected_contract": {
                "total": len(corrected_status_by_id),
                "passed": sum(corrected_status_by_id.values()),
                "failed": len(corrected_status_by_id) - sum(corrected_status_by_id.values()),
                "failed_ids": [k for k, v in corrected_status_by_id.items() if not v],
            },
            "reconciliation_controls": {
                "total": len(checks),
                "passed": len(checks) - len(failed_controls),
                "failed": len(failed_controls),
                "failed_ids": failed_controls,
            },
            "reconciled_gaps": {
                "EX8-151": "API_NOT_TOOL_EVENT_OWNER; SANDBOX_TOOL_EVENT_PRODUCTION_ESTABLISHED",
                "EX8-152": "API_NOT_TRACE_OWNER; CROSS_MODULE_EXPORT_TRACE_DICT_DELEGATION_ESTABLISHED",
                "EX8-306": "PACKAGED_CLASS_IS_GUARDRAIL; OFFICIAL_BASELINE_IS_LOGICAL_ROLE",
            },
            "corrected_parity_contract": corrected_contract,
            "readiness": {
                "static_contract_freeze_complete": qualified,
                "independent_EX8_qualification_eligible": qualified,
                "runtime_parity_eligible": False,
                "controlled_actual_fs_read_eligible": False,
            },
            "execution_boundaries": {
                "EX8_v1_0_artifacts_modified": False,
                "source_modified": False,
                "sdk_modules_imported": False,
                "sdk_modules_executed": False,
                "Sandbox_instantiated": False,
                "Sandbox_interact_executed": False,
                "Gym_instantiated": False,
                "Gym_executed": False,
                "real_tools_executed": False,
                "actual_fs_read_executed": False,
                "protected_fixture_values_used": False,
                "real_secret_values_used": False,
                "http_sink_executed": False,
                "predicates_executed": False,
                "breach_executed": False,
                "models_used": False,
                "external_effects_observed": False,
            },
            "scientific_verdict": {
                "corrected_static_proposal_sandbox_gym_contract": "ESTABLISHED" if qualified else "GAPS_IDENTIFIED",
                "runtime_parity": "NOT_EVALUATED",
                "hosted_parity": "NOT_ESTABLISHED",
                "actual_source_retrieval": "NOT_EVALUATED",
                "protected_value_lineage": "NOT_ESTABLISHED",
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": "NOT_ESTABLISHED",
            },
            "claim_boundary": claim_boundary,
            "next_gate": next_gate,
        }

        paths = {
            "result": output_dir / "ex8_r1_result.json",
            "checks": output_dir / "ex8_r1_checks.csv",
            "reconciliation": output_dir / "ex8_r1_reconciliation.csv",
            "contract": output_dir / "ex8_r1_corrected_parity_contract.json",
            "claim": output_dir / "ex8_r1_claim_boundary.json",
            "binding": output_dir / "ex8_r1_binding.json",
        }
        write_json(paths["result"], result)
        write_csv(paths["checks"], checks, ["check_id", "category", "passed", "observed", "expected", "failure_layer", "evidence_class"])
        write_csv(paths["reconciliation"], reconciliation_table, ["check_id", "original_passed", "original_observed", "original_expected", "corrected_passed", "corrected_expectation", "evidence", "classification"])
        if qualified:
            write_json(paths["contract"], corrected_contract)
        else:
            write_json(paths["contract"], {"status": "NOT_FROZEN", "reason": "RECONCILIATION_CONTROLS_FAILED", "failed_ids": failed_controls})
        write_json(paths["claim"], claim_boundary)
        write_json(paths["binding"], {
            "version": VERSION,
            "created_at_utc": now(),
            "runner": identity(Path(__file__).resolve()),
            "inputs": {key: identity(path) for key, path in inputs.items()},
            "sources": {key: identity(path) for key, path in source_paths.items()},
            "project_root": str(project),
            "EX8_v1_0_artifacts_modified": False,
            "source_modified": False,
            "sdk_modules_imported": False,
            "sdk_modules_executed": False,
        })

        derived = tuple(paths.values())
        bound = tuple(inputs.values())
        sources = tuple(source_paths.values())
        manifest_rows = (
            [{**identity(path), "role": "EX8_R1_DERIVED"} for path in derived]
            + [{**identity(path), "role": "EX8_R1_BOUND_EX8_V1_0"} for path in bound]
            + [{**identity(path), "role": "EX8_R1_AUTHORITATIVE_SOURCE"} for path in sources]
        )
        manifest_path = output_dir / "ex8_r1_manifest.csv"
        write_csv(manifest_path, manifest_rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        external_path = output_dir / "ex8_r1_manifest_external_binding.json"
        write_json(external_path, {
            "version": VERSION,
            "created_at_utc": now(),
            "status": status,
            "manifest_filename": manifest_path.name,
            "manifest_size_bytes": manifest_path.stat().st_size,
            "manifest_sha256": sha256(manifest_path),
            "runner_sha256": sha256(Path(__file__).resolve()),
            "parent_EX8_manifest_sha256": PARENT_MANIFEST_SHA,
            "original_checks_total": 69,
            "original_checks_failed": 3,
            "recomputed_checks_total": len(corrected_status_by_id),
            "recomputed_checks_passed": sum(corrected_status_by_id.values()),
            "reconciliation_controls_total": len(checks),
            "reconciliation_controls_passed": len(checks) - len(failed_controls),
            "reconciliation_controls_failed": len(failed_controls),
            "corrected_parity_id": corrected_contract["parity_id"],
            "independent_EX8_qualification_eligible": qualified,
            "runtime_parity": "NOT_EVALUATED",
            "hosted_parity": "NOT_ESTABLISHED",
            "controlled_actual_fs_read_eligible": False,
            "source_modified": False,
            "next_gate": next_gate,
        })

        print(json.dumps({
            "status": status,
            "original_EX8_checks": "66/69",
            "original_failed_ids": ORIGINAL_FAILED_IDS,
            "recomputed_under_corrected_contract": f"{sum(corrected_status_by_id.values())}/{len(corrected_status_by_id)}",
            "reconciliation_controls_total": len(checks),
            "reconciliation_controls_failed": len(failed_controls),
            "corrected_parity_id": corrected_contract["parity_id"],
            "sdk_modules_imported": False,
            "sdk_modules_executed": False,
            "runtime_parity": "NOT_EVALUATED",
            "manifest_sha256": sha256(manifest_path),
            "next_gate": next_gate,
        }, indent=2))

    except Exception as exc:
        failure_path = output_dir / "EX8_R1_FAILED.json"
        failure_path.write_text(json.dumps({
            "version": VERSION,
            "created_at_utc": now(),
            "status": "EX8_R1_RECONCILIATION_BLOCKED",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "checks_frozen": checks,
            "EX8_v1_0_artifacts_modified": False,
            "source_modified": False,
            "sdk_modules_imported": False,
            "sdk_modules_executed": False,
            "actual_fs_read_executed": False,
            "effects_observed": False,
        }, indent=2), encoding="utf-8")
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=VERSION)
    for flag in [
        "ex8-result", "ex8-checks", "ex8-source-inventory", "ex8-symbol-inventory",
        "ex8-call-inventory", "ex8-assignment-inventory", "ex8-contract-excerpts",
        "ex8-route-map", "ex8-interface-map", "ex8-parity-contract",
        "ex8-claim-boundary", "ex8-binding", "ex8-external-binding",
        "ex8-manifest", "ex8-runner", "project-root", "output-dir",
    ]:
        parser.add_argument("--" + flag, required=True)
    return parser.parse_args()


if __name__ == "__main__":
    try:
        main(parse_args())
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
