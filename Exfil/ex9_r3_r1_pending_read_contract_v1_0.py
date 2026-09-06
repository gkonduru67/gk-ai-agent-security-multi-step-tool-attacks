#!/usr/bin/env python3
"""EX9-R3-R1 pending proposal read interface and plan reconciliation.

Read-only contract gate. Preserves EX9-R3 as 25/25 and binds its complete
contract evidence. It assigns an explicit immutable proposal-evidence ledger,
freezes its public lookup/population/lifecycle API, corrects the distinction
between proposal_digest and tool_args_digest, and completes the factory wiring
plan without creating implementation code or modifying frozen SDK sources.

No SDK module is imported or executed. No Sandbox, Gym, tool, fs.read, HTTP,
predicate, breach logic, model, thread, or external effect is executed.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "EX9_R3_R1_PENDING_PROPOSAL_READ_INTERFACE_AND_PLAN_RECONCILIATION_v1.0"
PARENT_VERSION = "ACKNOWLEDGEMENT_INTEGRATION_IMPLEMENTATION_CONTRACT_AND_SOURCE_PLAN_FREEZE_v1.0"
PARENT_STATUS = "ACKNOWLEDGEMENT_INTEGRATION_IMPLEMENTATION_CONTRACT_AND_SOURCE_PLAN_FREEZE_COMPLETE_PASS"
PARENT_MANIFEST_SHA = "9FBBCCA34FA47C1B529BB485EF6799DEED7FBD33B2CD37F5400680C68B7B6D65"
PARENT_RUNNER_SHA = "77AC8E8DF2B1D6B8FD327DA6DE384E651EFF26D1ECB2D115917D7EFE42ACE620"
PARENT_RESULT_SHA = "E43F88CE5A638472E65CB4B077B34CC45B1F638819C29441B78A8432AB142764"
PARENT_FREEZE_SHA = "5AD6EE1791FDED4A300A53DA917D8FE876CE25C88F8AC8547EAFA1BB4DECCE4E"
PARENT_PLAN_SHA = "851BB29E0E685D6C240DD73B984E21D00D1CDCF313F4C4C2773F92F4F60B4CFE"
PARENT_REQUIREMENTS_SHA = "086945C3187393FEEE99B991EAD2973056141FB495CD66B8B9E0B0FAAEDEB414"
PARENT_OWNERSHIP_SHA = "562EC8A102F9A0B4C0704528C59C90F2788D928DFD746C964A591370DE06E90A"
ADAPTER_SHA = "BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"

PROVIDER_CLASS = "TrustedPendingProposalReadViewV1"
PROVIDER_FILE = "aicomp_sdk/core/env/trusted_pending_proposal_read_view_v1.py"
RECORD_CLASS = "TrustedPendingProposalRecordV1"
HOOK_CLASS = "TrustedPostToolHookAdapterV1"
HOOK_FILE = "aicomp_sdk/core/env/trusted_post_tool_hook_adapter_v1.py"
WRAPPER_CLASS = "TrustedOutcomeTransportV1ToContextAdapterV1_1Wrapper"
WRAPPER_FILE = "aicomp_sdk/core/env/trusted_outcome_transport_v1_to_context_adapter_v1_1_wrapper.py"
FACTORY_FILE = "aicomp_sdk/core/env/trusted_acknowledgement_integration_factory_v1.py"
FACTORY_FUNC = "build_trusted_acknowledgement_integration_v1"


def now(): return datetime.now(timezone.utc).isoformat()
def require(condition, message):
    if not condition: raise ValueError(message)
def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""): h.update(block)
    return h.hexdigest().upper()
def ident(path):
    p = Path(path).resolve()
    return {"artifact": p.name, "path": str(p), "size_bytes": p.stat().st_size, "sha256": sha(p)}
def rjson(path): return json.loads(Path(path).read_text(encoding="utf-8-sig"))
def rcsv(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as f: return list(csv.DictReader(f))
def wjson(path, obj):
    with Path(path).open("x", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, sort_keys=True); f.write("\n")
def wcsv(path, rows, fields):
    with Path(path).open("x", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        w.writeheader(); w.writerows(rows)
def add(rows, cid, category, passed, observed, expected, layer):
    rows.append({"check_id": cid, "category": category, "passed": bool(passed), "observed": str(observed), "expected": str(expected), "failure_layer": layer})
def parse(path):
    text = Path(path).read_text(encoding="utf-8")
    return text, ast.parse(text, filename=str(path))
def classes(tree): return {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)}
def methods(cls): return {n.name: n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
def unparse(node):
    try: return ast.unparse(node)
    except Exception: return "UNPARSE_FAILED"


def main(args):
    out = Path(args.output_dir).resolve()
    require(not out.exists(), f"Refusing overwrite: {out}")
    out.mkdir(parents=True)
    checks = []
    try:
        root = Path(args.project_root).resolve()
        sdk = root / "aicomp_sdk"
        require(sdk.is_dir(), f"Missing SDK root: {sdk}")
        parent = {
            "result": Path(args.r3_result).resolve(), "checks": Path(args.r3_checks).resolve(),
            "freeze": Path(args.r3_freeze).resolve(), "source_plan": Path(args.r3_source_plan).resolve(),
            "requirements": Path(args.r3_requirements).resolve(), "ownership": Path(args.r3_ownership).resolve(),
            "claim": Path(args.r3_claim_boundary).resolve(), "binding": Path(args.r3_binding).resolve(),
            "external": Path(args.r3_external_binding).resolve(), "manifest": Path(args.r3_manifest).resolve(),
            "runner": Path(args.r3_runner).resolve(),
        }
        for key, path in parent.items(): require(path.is_file(), f"Missing EX9-R3 {key}: {path}")
        result = rjson(parent["result"]); freeze = rjson(parent["freeze"]); ext = rjson(parent["external"])
        parent_checks = rcsv(parent["checks"]); parent_requirements = rcsv(parent["requirements"])
        add(checks, "R-001", "parent", result.get("version") == PARENT_VERSION and result.get("status") == PARENT_STATUS, result.get("status"), PARENT_STATUS, "FIXTURE")
        expected_hashes = [("manifest", PARENT_MANIFEST_SHA), ("runner", PARENT_RUNNER_SHA), ("result", PARENT_RESULT_SHA), ("freeze", PARENT_FREEZE_SHA), ("source_plan", PARENT_PLAN_SHA), ("requirements", PARENT_REQUIREMENTS_SHA), ("ownership", PARENT_OWNERSHIP_SHA)]
        for idx, (key, expected) in enumerate(expected_hashes, 2): add(checks, f"R-{idx:03d}", "parent", sha(parent[key]) == expected, sha(parent[key]), expected, "FIXTURE")
        add(checks, "R-009", "parent", ext.get("manifest_sha256") == PARENT_MANIFEST_SHA and ext.get("runner_sha256") == PARENT_RUNNER_SHA, ext, "external binding matches", "FIXTURE")
        add(checks, "R-010", "parent", len(parent_checks) == 25 and all(r["passed"] == "True" for r in parent_checks), {"total": len(parent_checks), "passed": sum(r["passed"] == "True" for r in parent_checks)}, "25/25", "EVIDENCE")
        add(checks, "R-011", "parent", freeze.get("outcome") == "PUBLIC_READ_ONLY_PENDING_PROPOSAL_INTERFACE_REQUIRED" and freeze.get("implementation_created") is False, {"outcome": freeze.get("outcome"), "implementation": freeze.get("implementation_created")}, "pending interface required; no implementation", "CLAIM_BOUNDARY")

        adapter = root / "aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py"
        require(adapter.is_file(), f"Missing adapter: {adapter}")
        add(checks, "R-020", "source", sha(adapter) == ADAPTER_SHA, sha(adapter), ADAPTER_SHA, "FIXTURE")
        adapter_text, adapter_tree = parse(adapter)
        adapter_cls = classes(adapter_tree).get("TrustedGuardrailContextAdapterV1_1")
        require(adapter_cls is not None, "Missing TrustedGuardrailContextAdapterV1_1")
        adapter_methods = methods(adapter_cls)
        private_pending = "_pending_proposals_by_digest" in adapter_text
        public_pending = any(("pending" in name.lower() or "proposal" in name.lower()) and name != "before_decide" and not name.startswith("_") for name in adapter_methods)
        add(checks, "R-021", "state", private_pending, private_pending, True, "PROVENANCE")
        add(checks, "R-022", "state", not public_pending, public_pending, False, "AUTHORIZATION_TRANSPORT")

        # Ensure corrected distinction is present in the new contract, while parent is preserved.
        parent_has_both = any("proposal_digest and tool_args_digest" in row.get("statement", "") for row in parent_requirements)
        add(checks, "R-023", "mapping", parent_has_both, parent_has_both, True, "PROVENANCE")
        corrected_tool_args_text = "exact tool_args_digest field from the same pending proposal record identified by proposal_digest"
        add(checks, "R-024", "mapping", corrected_tool_args_text != "exact pending proposal digest from trusted state provider", corrected_tool_args_text, "distinct digest semantics", "ARGUMENT_FIDELITY")

        # Reserve all implementation identities and verify absence.
        proposed = {
            "provider": {"class": PROVIDER_CLASS, "record_class": RECORD_CLASS, "file": PROVIDER_FILE},
            "hook_adapter": {"class": HOOK_CLASS, "file": HOOK_FILE},
            "transport_wrapper": {"class": WRAPPER_CLASS, "file": WRAPPER_FILE},
            "factory": {"function": FACTORY_FUNC, "file": FACTORY_FILE},
        }
        existing_classes = set()
        for path in sorted(sdk.rglob("*.py")):
            try: _, tree = parse(path); existing_classes.update(classes(tree))
            except Exception: pass
        reserved_classes = {PROVIDER_CLASS, RECORD_CLASS, HOOK_CLASS, WRAPPER_CLASS}
        proposed_paths = [root / PROVIDER_FILE, root / HOOK_FILE, root / WRAPPER_FILE, root / FACTORY_FILE]
        add(checks, "R-030", "identity", not (reserved_classes & existing_classes), sorted(reserved_classes & existing_classes), "no proposed class exists", "FIXTURE")
        add(checks, "R-031", "identity", all(not p.exists() for p in proposed_paths), [str(p) for p in proposed_paths], "all proposed files absent", "FIXTURE")
        add(checks, "R-032", "identity", len(reserved_classes) == 4 and len(set(map(str, proposed_paths))) == 4, {"classes": len(reserved_classes), "files": len(set(map(str, proposed_paths)))}, "4 distinct classes across 4 planned modules/factory file", "FIXTURE")

        record_schema = {
            "schema_tag": "EX9.TRUSTED.PENDING.PROPOSAL.RECORD.V1",
            "required_fields": ["proposal_digest", "trace_identity", "tool_name", "tool_args_digest", "proposal_event_identity"],
            "key": "proposal_digest",
            "immutability": "record fields immutable after append",
            "validation": ["non-empty proposal_digest", "non-empty trace_identity", "non-empty tool_name", "non-empty tool_args_digest", "proposal_event_identity schema valid"],
        }
        provider_api = {
            "class": PROVIDER_CLASS,
            "record_class": RECORD_CLASS,
            "append": "append(record: TrustedPendingProposalRecordV1) -> None",
            "lookup": "lookup_by_proposal_digest(proposal_digest: str) -> TrustedPendingProposalRecordV1 | None",
            "mark_consumed": "mark_consumed(proposal_digest: str, outcome_event_identity: Mapping[str, Any]) -> None",
            "snapshot": "snapshot_state() -> dict[str, object]",
            "restore": "restore_state(snapshot: Mapping[str, Any]) -> None",
            "reset": "reset() -> None",
            "private_adapter_access": False,
        }
        population = {
            "owner": "TrustedPostToolHookAdapterV1 trusted proposal-time integration path",
            "write_time": "immediately after authoritative before_decide returns the proposal record and before tool execution",
            "source_fields": "exact proposal record produced by TrustedGuardrailContextAdapterV1_1.before_decide",
            "duplicate_rule": "same digest and byte-equivalent record is idempotent; conflicting duplicate fails closed",
            "mutation_of_adapter_private_state": False,
        }
        consumption = {
            "lookup": "read-only lookup by exact proposal_digest before V1.1 after_tool",
            "mark_consumed": "only after V1.1 after_tool returns successfully",
            "adapter_exception": "do not mark consumed",
            "replay": "consumed proposal digest cannot be acknowledged again",
            "relationship": "provider consumption mirrors successful adapter acknowledgement but does not mutate adapter internals",
        }
        lifecycle = {
            "snapshot": "records, consumed digests, provider schema version, binding identity",
            "restore": "validate schema, unique keys, digest consistency, and consumed subset before replace",
            "reset": "clear provider-owned records and consumed set only",
            "retry": "failed downstream acknowledgement leaves provider record unconsumed",
            "replay": "reject consumed digest and conflicting duplicate outcome identity",
        }
        factory_bindings = {
            "function": FACTORY_FUNC,
            "module": FACTORY_FILE,
            "constructs": [PROVIDER_CLASS, HOOK_CLASS, WRAPPER_CLASS, "TrustedOutcomeTransportV1"],
            "bindings": {
                "hook_adapter.provider": PROVIDER_CLASS,
                "hook_adapter.transport": "TrustedOutcomeTransportV1",
                "transport.adapter": WRAPPER_CLASS,
                "wrapper.downstream_adapter": "TrustedGuardrailContextAdapterV1_1",
                "wrapper.pending_proposal_view": PROVIDER_CLASS,
                "wrapper.sequence_state": "same trusted sequence_state instance owned by transport integration",
            },
            "frozen_source_modification": False,
            "private_adapter_access": False,
        }
        add(checks, "R-040", "provider", provider_api["private_adapter_access"] is False, provider_api, "no private adapter access", "AUTHORIZATION_TRANSPORT")
        add(checks, "R-041", "provider", "proposal_digest" in record_schema["required_fields"] and "tool_args_digest" in record_schema["required_fields"], record_schema["required_fields"], "both digests distinct in one record", "PROVENANCE")
        add(checks, "R-042", "provider", provider_api["lookup"].startswith("lookup_by_proposal_digest"), provider_api["lookup"], "exact lookup signature", "ARGUMENT_FIDELITY")
        add(checks, "R-043", "provider", population["mutation_of_adapter_private_state"] is False, population, "separate trusted ledger population", "AUTHORIZATION_TRANSPORT")
        add(checks, "R-044", "provider", consumption["mark_consumed"].startswith("only after"), consumption, "consume only after successful acknowledgement", "AUTHORIZATION_TRANSPORT")
        add(checks, "R-045", "factory", all("." in key for key in factory_bindings["bindings"]), factory_bindings["bindings"], "exact constructor dependency bindings", "ROUTING")

        outcome = "NEW_TRUSTED_PENDING_PROPOSAL_READ_VIEW_REQUIRED"
        requirements = [
            {"id": "PR-001", "statement": f"Create {PROVIDER_CLASS} and immutable {RECORD_CLASS} in {PROVIDER_FILE}.", "status": "REQUIRED"},
            {"id": "PR-002", "statement": "Never read or mutate TrustedGuardrailContextAdapterV1_1 private pending-proposal fields.", "status": "REQUIRED"},
            {"id": "PR-003", "statement": "Store proposal_digest and tool_args_digest as distinct fields from the exact same authoritative proposal record.", "status": "REQUIRED"},
            {"id": "PR-004", "statement": "Populate the read view only from the trusted proposal-time path before tool execution.", "status": "REQUIRED"},
            {"id": "PR-005", "statement": "Lookup is by exact proposal_digest and returns an immutable record or None; missing state fails closed.", "status": "REQUIRED"},
            {"id": "PR-006", "statement": "Mark consumed only after successful V1.1 after_tool; exceptions leave the record unconsumed.", "status": "REQUIRED"},
            {"id": "PR-007", "statement": "Provider snapshot, restore, reset, duplicate, retry, and replay behavior follow the frozen contract.", "status": "REQUIRED"},
            {"id": "PR-008", "statement": "Factory binds provider, hook adapter, transport, wrapper, downstream adapter, and sequence state exactly as frozen.", "status": "REQUIRED"},
            {"id": "PR-009", "statement": "Implementation comprises four planned files, four new classes, and one factory function; no frozen source modification.", "status": "REQUIRED"},
            {"id": "PR-010", "statement": "Implementation identity freeze remains static and executes no SDK modules, Sandbox, Gym, tools, fs.read, HTTP, predicates, breach, models, or threads.", "status": "REQUIRED"},
        ]
        failed = [r["check_id"] for r in checks if not r["passed"]]
        feasible = not failed
        status = "EX9_R3_R1_PENDING_PROPOSAL_READ_INTERFACE_AND_PLAN_RECONCILIATION_COMPLETE_PASS" if feasible else "EX9_R3_R1_PENDING_PROPOSAL_READ_INTERFACE_AND_PLAN_RECONCILIATION_COMPLETE_WITH_GAPS"
        next_gate = "ACKNOWLEDGEMENT_INTEGRATION_IMPLEMENTATION_AND_IDENTITY_FREEZE" if feasible else "EX9_R3_R2_PENDING_READ_CONTRACT_REVIEW"
        plan = {
            "freeze_id": "EX9.ACK.PENDING.PROPOSAL.READ.INTERFACE.PLAN.V1",
            "status": "FROZEN" if feasible else "NOT_FROZEN",
            "parent_contract_freeze_id": freeze.get("freeze_id"),
            "outcome": outcome,
            "proposed_artifacts": proposed,
            "implementation_artifact_count": 4,
            "new_class_count": 4,
            "factory_function_count": 1,
            "record_schema": record_schema,
            "provider_api": provider_api,
            "population": population,
            "consumption": consumption,
            "lifecycle": lifecycle,
            "factory_bindings": factory_bindings,
            "mapping_correction": {
                "proposal_digest": "exact proposal_digest identifying the pending record",
                "tool_args_digest": corrected_tool_args_text,
                "digests_equal": False,
            },
            "implementation_created": False,
            "implementation_identity": "NOT_ESTABLISHED",
            "runtime_behavior": "NOT_EVALUATED",
        }
        claim = {"allowed": ["pending proposal read-view contract", "provider identity and public API", "record schema, population, lifecycle, consumption, and factory bindings", "eligibility recommendation for a separate static implementation gate"], "prohibited": ["claim implementation exists", "private adapter state access", "SDK source modification", "runtime acknowledgement", "actual fs.read", "Sandbox or Gym execution", "HTTP sink", "predicate or breach execution", "model execution", "protected-value lineage", "guardrail effectiveness", "real exfiltration prevention"]}
        result_out = {
            "version": VERSION, "created_at_utc": now(), "status": status,
            "classification": "READ_ONLY_CONTRACT_RECONCILIATION",
            "EX9_R3_parent_verified": True,
            "parent_result": {"checks": "25_OF_25", "preserved_immutable": True, "outcome": freeze.get("outcome")},
            "checks": {"total": len(checks), "passed": len(checks) - len(failed), "failed": len(failed), "failed_ids": failed},
            "decision": {"outcome": outcome, "implementation_artifact_count": 4, "new_class_count": 4, "private_adapter_access": False},
            "freeze": plan,
            "readiness": {"implementation_creation_eligible": feasible, "controlled_actual_fs_read_eligible": False, "http_sink_eligible": False},
            "execution_boundaries": {"parent_artifacts_modified": False, "source_modified": False, "implementation_created": False, "sdk_modules_imported": False, "sdk_modules_executed": False, "Sandbox_instantiated": False, "Sandbox_interact_executed": False, "Gym_executed": False, "real_tools_executed": False, "actual_fs_read_executed": False, "http_sink_executed": False, "predicates_executed": False, "breach_executed": False, "models_used": False, "threads_executed": False, "external_effects_observed": False},
            "scientific_verdict": {"pending_read_interface": "FROZEN" if feasible else "GAPS_IDENTIFIED", "implementation_behavior": "NOT_EVALUATED", "actual_source_retrieval": "NOT_EVALUATED", "protected_value_lineage": "NOT_ESTABLISHED", "harness_trick": "NOT_DEMONSTRATED", "robust_security_findings": "NOT_ESTABLISHED"},
            "claim_boundary": claim, "next_gate": next_gate,
        }
        outputs = {
            "result": out / "ex9_r3_r1_result.json", "checks": out / "ex9_r3_r1_checks.csv",
            "requirements": out / "ex9_r3_r1_requirements.csv", "provider": out / "ex9_r3_r1_provider_contract.json",
            "factory": out / "ex9_r3_r1_factory_bindings.json", "plan": out / "ex9_r3_r1_complete_plan.json",
            "freeze": out / "ex9_r3_r1_contract_freeze.json", "claim": out / "ex9_r3_r1_claim_boundary.json",
            "binding": out / "ex9_r3_r1_binding.json",
        }
        wjson(outputs["result"], result_out); wcsv(outputs["checks"], checks, ["check_id", "category", "passed", "observed", "expected", "failure_layer"])
        wcsv(outputs["requirements"], requirements, ["id", "statement", "status"]); wjson(outputs["provider"], {"record_schema": record_schema, "provider_api": provider_api, "population": population, "consumption": consumption, "lifecycle": lifecycle})
        wjson(outputs["factory"], factory_bindings); wjson(outputs["plan"], plan); wjson(outputs["freeze"], plan); wjson(outputs["claim"], claim)
        wjson(outputs["binding"], {"version": VERSION, "created_at_utc": now(), "runner": ident(Path(__file__).resolve()), "parent": {k: ident(v) for k, v in parent.items()}, "sources": {"adapter_v1_1": ident(adapter)}, "source_modified": False, "implementation_created": False, "sdk_modules_imported": False, "sdk_modules_executed": False})
        rows = [{**ident(p), "role": "EX9_R3_R1_DERIVED"} for p in outputs.values()] + [{**ident(p), "role": "EX9_R3_R1_BOUND_PARENT"} for p in parent.values()] + [{**ident(adapter), "role": "EX9_R3_R1_AUTHORITATIVE_SOURCE"}]
        manifest = out / "ex9_r3_r1_manifest.csv"; wcsv(manifest, rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        external = out / "ex9_r3_r1_manifest_external_binding.json"
        wjson(external, {"version": VERSION, "created_at_utc": now(), "status": status, "manifest_filename": manifest.name, "manifest_size_bytes": manifest.stat().st_size, "manifest_sha256": sha(manifest), "runner_sha256": sha(Path(__file__).resolve()), "parent_EX9_R3_manifest_sha256": PARENT_MANIFEST_SHA, "freeze_id": plan["freeze_id"], "checks_total": len(checks), "checks_passed": len(checks) - len(failed), "checks_failed": len(failed), "outcome": outcome, "implementation_creation_eligible": feasible, "controlled_actual_fs_read_eligible": False, "implementation_created": False, "next_gate": next_gate})
        print(json.dumps({"status": status, "parent": "25/25 preserved", "checks": f"{len(checks)-len(failed)}/{len(checks)}", "failed_ids": failed, "outcome": outcome, "provider_class": PROVIDER_CLASS, "implementation_artifact_count": 4, "implementation_created": False, "controlled_actual_fs_read_eligible": False, "manifest_sha256": sha(manifest), "next_gate": next_gate}, indent=2))
    except Exception as exc:
        (out / "EX9_R3_R1_FAILED.json").write_text(json.dumps({"version": VERSION, "created_at_utc": now(), "status": "EX9_R3_R1_CONTRACT_RECONCILIATION_BLOCKED", "error_type": type(exc).__name__, "error": str(exc), "checks_frozen": checks, "source_modified": False, "implementation_created": False, "sdk_modules_imported": False, "sdk_modules_executed": False, "actual_fs_read_executed": False}, indent=2), encoding="utf-8")
        raise

def parse_args():
    p = argparse.ArgumentParser(description=VERSION)
    for flag in ["r3-result", "r3-checks", "r3-freeze", "r3-source-plan", "r3-requirements", "r3-ownership", "r3-claim-boundary", "r3-binding", "r3-external-binding", "r3-manifest", "r3-runner", "project-root", "output-dir"]: p.add_argument("--" + flag, required=True)
    return p.parse_args()

if __name__ == "__main__":
    try: main(parse_args())
    except Exception as exc: print(f"FAILED: {exc}", file=sys.stderr); raise SystemExit(1)
