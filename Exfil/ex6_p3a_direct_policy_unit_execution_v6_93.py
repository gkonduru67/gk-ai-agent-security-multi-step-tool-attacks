#!/usr/bin/env python3
"""EX6 v6.93 direct matched policy-unit execution.

Executes only guardrail decide(tool_name, tool_args, context) against the frozen
v6.92R1 matrix. It does not use GPT-OSS, Sandbox, Gym, hooks, wrappers, tools,
fixtures, effects, predicates, breach evaluation, or attack optimization.
"""
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import importlib.util
import json
import os
import platform
import sys
import time
import traceback
from collections import Counter, defaultdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

VERSION = "EX6_P3A_DIRECT_POLICY_UNIT_EXECUTION_v6.93"
EXPECTED_PARENT_MANIFEST_SHA256 = "274A50E19200B2B566C8B5ED298CCFE7EA68B9F97564EBD1905E97D8E339B767"
EXPECTED_PARENT_STATUS = "P3_POLICY_UNIT_MATCHED_MATRIX_DESIGN_FREEZE_COMPLETE"
EXPECTED_PACKAGED_SHA256 = "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED"
EXPECTED_HARDENED_SHA256 = "918FFD61CDB9A406C965F06CF2BEC34C297AB231E26B6FC083AE34B00C37D452"
EXPECTED_PREDICATES_SHA256 = "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
EXPECTED_SCENARIOS = 23
EXPECTED_POLICY_ROWS = 46

REQUIRED_PARENT_ARTIFACTS = {
    "ex6_v6_92_parent_verification.csv",
    "ex6_v6_92_scenario_matrix.csv",
    "ex6_v6_92_policy_hypothesis_rows.csv",
    "ex6_v6_92_matched_invariants.json",
    "ex6_v6_92_claim_boundary.json",
    "ex6_v6_92_source_and_runner_identity.json",
    "ex6_v6_92_result.json",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest().upper()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")


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
        name = (row.get("artifact") or "").strip()
        if name in indexed:
            prior = indexed[name]
            for field in ("size_bytes", "sha256", "source_path"):
                if (prior.get(field) or "").strip() != (row.get(field) or "").strip():
                    raise ValueError(f"Conflicting duplicate parent artifact identity: {name}")
            continue
        indexed[name] = row
    missing = sorted(REQUIRED_PARENT_ARTIFACTS - set(indexed))
    if missing:
        raise ValueError(f"Missing required v6.92 artifacts: {missing}")
    return indexed


def verify_manifest_row(row: dict[str, str]) -> dict[str, Any]:
    path = Path(row["source_path"])
    exists = path.is_file()
    size = path.stat().st_size if exists else None
    observed = sha256(path) if exists else None
    expected_size = int(row["size_bytes"])
    expected = row["sha256"].upper()
    passed = exists and size == expected_size and observed == expected
    return {
        "artifact": row["artifact"], "path": str(path), "exists": exists,
        "expected_size_bytes": expected_size, "observed_size_bytes": size,
        "size_match": exists and size == expected_size,
        "expected_sha256": expected, "observed_sha256": observed,
        "sha256_match": exists and observed == expected, "passed": passed,
    }


def class_candidates(source_path: Path) -> list[dict[str, Any]]:
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    rows = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            bases = [ast.unparse(base) for base in node.bases]
            methods = [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            if "decide" in methods:
                rows.append({"name": node.name, "bases": bases, "methods": methods, "line": node.lineno})
    return rows


def resolve_packaged_class(source_path: Path, explicit: str | None) -> tuple[str, list[dict[str, Any]]]:
    candidates = class_candidates(source_path)
    names = [row["name"] for row in candidates]
    if explicit:
        if explicit not in names:
            raise ValueError(f"Requested packaged class {explicit!r} not found; candidates={names}")
        return explicit, candidates
    preferred = [name for name in ("OptimalGuardrail", "Guardrail") if name in names]
    if len(preferred) == 1:
        return preferred[0], candidates
    if len(candidates) == 1:
        return candidates[0]["name"], candidates
    raise ValueError(f"Unable to uniquely resolve packaged class; candidates={names}")


def resolve_hardened_class(source_path: Path) -> tuple[str, list[dict[str, Any]]]:
    candidates = class_candidates(source_path)
    names = [row["name"] for row in candidates]
    expected = "ProposalAwareOptimalGuardrail"
    if expected not in names:
        raise ValueError(f"Hardened class {expected} not found; candidates={names}")
    return expected, candidates


def import_class(project_root: Path, source_path: Path, class_name: str, unique_name: str) -> type:
    root_text = str(project_root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    spec = importlib.util.spec_from_file_location(unique_name, source_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot create module spec for {source_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module
    spec.loader.exec_module(module)
    cls = getattr(module, class_name, None)
    if not isinstance(cls, type):
        raise TypeError(f"{class_name} is not a class in {source_path}")
    return cls


def enum_or_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    return value


def extract_decision(decision: Any) -> dict[str, Any]:
    if decision is None:
        return {"valid": False, "decision_type": "NoneType", "action": None, "reason": None, "repr": "None"}
    action = None
    for attr in ("action", "decision", "kind", "type"):
        if hasattr(decision, attr):
            action = enum_or_value(getattr(decision, attr))
            break
    reason = None
    for attr in ("reason", "message", "explanation"):
        if hasattr(decision, attr):
            reason = getattr(decision, attr)
            break
    if action is None and isinstance(decision, Enum):
        action = decision.value
    if action is None and isinstance(decision, str):
        action = decision
    action_text = None if action is None else str(action)
    if action_text and "." in action_text:
        action_text = action_text.rsplit(".", 1)[-1]
    if action_text:
        action_text = action_text.upper()
    reason_text = None if reason is None else str(reason)
    return {
        "valid": action_text in {"ALLOW", "DENY", "CONFIRM", "SANITIZE"},
        "decision_type": type(decision).__name__, "action": action_text,
        "reason": reason_text, "repr": repr(decision),
    }


def expected_resolution(expected: str, observed_action: str | None, invocation_status: str) -> str:
    if expected == "EXPECTED_EXCEPTION_OR_UNDEFINED":
        return "NOT_APPLICABLE_EXCEPTION_EXPECTED" if invocation_status == "EXECUTED_EXCEPTION_RAISED" else "OPEN_EXPECTATION_DECISION_RETURNED"
    if expected == "DENY_IF_OFFICIAL_SENTINEL_MATCHES":
        if observed_action == "DENY":
            return "CONDITIONAL_RESOLVED_MATCH"
        return "CONDITIONAL_RESOLVED_NONMATCH"
    if expected == "UNDETERMINED_UNTIL_EXECUTION":
        return "OPEN_HYPOTHESIS_OBSERVED"
    if invocation_status != "EXECUTED_DECISION_RETURNED":
        return "ACTION_MISMATCH"
    return "EXACT_MATCH" if observed_action == expected else "ACTION_MISMATCH"


def reason_resolution(expected: str, observed: str | None, action_resolution: str, invocation_status: str) -> str:
    if invocation_status != "EXECUTED_DECISION_RETURNED":
        return "NOT_APPLICABLE"
    if action_resolution in {"OPEN_HYPOTHESIS_OBSERVED", "OPEN_EXPECTATION_DECISION_RETURNED", "CONDITIONAL_RESOLVED_NONMATCH"}:
        return "NOT_APPLICABLE"
    if observed == expected:
        return "EXACT_MATCH"
    if observed and expected and (observed.startswith(expected) or expected.startswith(observed)):
        return "PREFIX_MATCH"
    return "DIFFERED"


def main() -> int:
    parser = argparse.ArgumentParser(description=VERSION)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--v6-92-manifest", required=True)
    parser.add_argument("--v6-92-binding", required=True)
    parser.add_argument("--packaged-source", required=True)
    parser.add_argument("--hardened-source", required=True)
    parser.add_argument("--predicates-source", required=True)
    parser.add_argument("--out-root", required=True)
    parser.add_argument("--packaged-class")
    args = parser.parse_args()

    runner = Path(__file__).resolve()
    project_root = Path(args.project_root).resolve()
    parent_manifest = Path(args.v6_92_manifest)
    parent_binding = Path(args.v6_92_binding)
    packaged_source = Path(args.packaged_source).resolve()
    hardened_source = Path(args.hardened_source).resolve()
    predicates_source = Path(args.predicates_source).resolve()
    out = Path(args.out_root)

    if out.exists():
        raise FileExistsError(f"Refusing to overwrite existing output directory: {out}")
    for path in (runner, project_root, parent_manifest, parent_binding, packaged_source, hardened_source, predicates_source):
        if not path.exists():
            raise FileNotFoundError(path)
    if sha256(parent_manifest) != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("v6.92 manifest identity mismatch")
    external = load_json(parent_binding)
    if external.get("manifest_sha256") != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("v6.92 external binding manifest mismatch")
    if external.get("status") != EXPECTED_PARENT_STATUS:
        raise ValueError("v6.92 parent status mismatch")
    for path, expected, label in (
        (packaged_source, EXPECTED_PACKAGED_SHA256, "packaged"),
        (hardened_source, EXPECTED_HARDENED_SHA256, "hardened"),
        (predicates_source, EXPECTED_PREDICATES_SHA256, "predicates"),
    ):
        if sha256(path) != expected:
            raise ValueError(f"{label} source identity mismatch")

    indexed = index_manifest(parent_manifest)
    checks = [verify_manifest_row(indexed[name]) for name in sorted(REQUIRED_PARENT_ARTIFACTS)]
    failures = [row for row in checks if not row["passed"]]
    if failures:
        raise ValueError("v6.92 parent evidence mismatch: " + ", ".join(row["artifact"] for row in failures))
    matrix_path = Path(indexed["ex6_v6_92_policy_hypothesis_rows.csv"]["source_path"])
    matrix_rows = load_csv(matrix_path)
    if len(matrix_rows) != EXPECTED_POLICY_ROWS:
        raise ValueError(f"Expected {EXPECTED_POLICY_ROWS} policy rows, found {len(matrix_rows)}")
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in matrix_rows:
        grouped[row["row_id"]].append(row)
    if len(grouped) != EXPECTED_SCENARIOS:
        raise ValueError(f"Expected {EXPECTED_SCENARIOS} scenarios, found {len(grouped)}")
    for row_id, rows in grouped.items():
        if len(rows) != 2 or len({row["input_sha256"] for row in rows}) != 1:
            raise ValueError(f"Matched pair invariant failed for {row_id}")
        if any(row["hook_state"] != "EMPTY_DEFAULT" for row in rows):
            raise ValueError(f"Nonempty hook state in {row_id}")

    packaged_class_name, packaged_candidates = resolve_packaged_class(packaged_source, args.packaged_class)
    hardened_class_name, hardened_candidates = resolve_hardened_class(hardened_source)

    preflight = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "parent_manifest_sha256": sha256(parent_manifest),
        "runner": {"path": str(runner), "size_bytes": runner.stat().st_size, "sha256": sha256(runner)},
        "project_root": str(project_root),
        "matrix": {"path": str(matrix_path), "size_bytes": matrix_path.stat().st_size, "sha256": sha256(matrix_path), "scenario_count": len(grouped), "policy_row_count": len(matrix_rows)},
        "packaged": {"source": str(packaged_source), "sha256": sha256(packaged_source), "class": packaged_class_name, "candidates": packaged_candidates},
        "hardened": {"source": str(hardened_source), "sha256": sha256(hardened_source), "class": hardened_class_name, "candidates": hardened_candidates},
        "predicates": {"source": str(predicates_source), "sha256": sha256(predicates_source)},
        "hooks": "EMPTY_DEFAULT", "gpt_oss": False, "sandbox": False, "gym": False,
        "tools": False, "fixtures": False, "effects": False,
    }

    out.mkdir(parents=True)
    paths = {
        "parent": out / "ex6_v6_93_parent_verification.csv",
        "preflight": out / "ex6_v6_93_preflight.json",
        "raw": out / "ex6_v6_93_raw_results.jsonl",
        "canonical": out / "ex6_v6_93_canonical_results.csv",
        "pairs": out / "ex6_v6_93_pair_summary.csv",
        "summary": out / "ex6_v6_93_summary.json",
        "result": out / "ex6_v6_93_result.json",
        "manifest": out / "ex6_v6_93_manifest.csv",
        "external": out / "ex6_v6_93_manifest_external_binding.json",
    }
    write_csv(paths["parent"], checks, ["artifact","path","exists","expected_size_bytes","observed_size_bytes","size_match","expected_sha256","observed_sha256","sha256_match","passed"])
    write_json(paths["preflight"], preflight)

    try:
        PackagedClass = import_class(project_root, packaged_source, packaged_class_name, "_ex6_packaged_optimal_v693")
        HardenedClass = import_class(project_root, hardened_source, hardened_class_name, "_ex6_proposal_aware_v693")
    except Exception:
        paths["preflight"].write_text(json.dumps({**preflight, "import_status": "FAILED", "import_traceback": traceback.format_exc()}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        raise

    policies = {
        "PACKAGED_OPTIMAL": (PackagedClass, packaged_class_name, EXPECTED_PACKAGED_SHA256),
        "PROPOSAL_AWARE_OPTIMAL": (HardenedClass, hardened_class_name, EXPECTED_HARDENED_SHA256),
    }
    instances: dict[str, Any] = {}
    for policy_id, (cls, _, _) in policies.items():
        try:
            instances[policy_id] = cls()
        except Exception as exc:
            raise RuntimeError(f"Failed to instantiate {policy_id} {cls.__name__}: {exc}") from exc

    raw_rows: list[dict[str, Any]] = []
    for source_row in sorted(matrix_rows, key=lambda r: (int(r["order"]), r["policy_id"])):
        policy_id = source_row["policy_id"]
        instance = instances[policy_id]
        tool_name = json.loads(source_row["tool_name_json"])
        tool_args = json.loads(source_row["tool_args_json"])
        context = json.loads(source_row["context_json"])
        start = time.perf_counter_ns()
        decision_info: dict[str, Any]
        exception_type = None
        exception_message = None
        exception_trace = None
        try:
            decision = instance.decide(tool_name, tool_args, context)
            decision_info = extract_decision(decision)
            invocation_status = "EXECUTED_DECISION_RETURNED" if decision_info["valid"] else "INVALID_DECISION_OBJECT"
        except Exception as exc:
            invocation_status = "EXECUTED_EXCEPTION_RAISED"
            decision_info = {"valid": False, "decision_type": None, "action": None, "reason": None, "repr": None}
            exception_type = type(exc).__name__
            exception_message = str(exc)
            exception_trace = traceback.format_exc()
        duration = time.perf_counter_ns() - start
        action_match = expected_resolution(source_row["expected_action_hypothesis"], decision_info["action"], invocation_status)
        reason_match = reason_resolution(source_row["expected_reason_hypothesis"], decision_info["reason"], action_match, invocation_status)
        raw_rows.append({
            "experiment_version": VERSION,
            "row_id": source_row["row_id"], "order": int(source_row["order"]),
            "category": source_row["category"], "claim_type": source_row["claim_type"],
            "policy_id": policy_id, "import_module_path": str(packaged_source if policy_id == "PACKAGED_OPTIMAL" else hardened_source),
            "import_class": policies[policy_id][1], "guardrail_source_sha256": policies[policy_id][2],
            "predicates_source_sha256": EXPECTED_PREDICATES_SHA256,
            "input_sha256": source_row["input_sha256"],
            "tool_name_json": source_row["tool_name_json"], "tool_args_json": source_row["tool_args_json"],
            "context_json": source_row["context_json"], "hook_state": source_row["hook_state"],
            "expected_action_hypothesis": source_row["expected_action_hypothesis"],
            "expected_reason_hypothesis": source_row["expected_reason_hypothesis"],
            "hypothesis_status": source_row["hypothesis_status"],
            "invocation_status": invocation_status,
            "observed_decision_type": decision_info["decision_type"],
            "observed_action": decision_info["action"],
            "observed_reason_raw": decision_info["reason"],
            "observed_reason_sha256": text_sha256(decision_info["reason"]) if decision_info["reason"] is not None else None,
            "observed_decision_repr": decision_info["repr"],
            "exception_type": exception_type,
            "exception_message_raw": exception_message,
            "exception_message_sha256": text_sha256(exception_message) if exception_message is not None else None,
            "exception_traceback_raw": exception_trace,
            "hypothesis_action_resolution": action_match,
            "hypothesis_reason_resolution": reason_match,
            "execution_duration_ns": duration,
            "runtime_layer": "DIRECT_GUARDRAIL_DECIDE",
            "real_lineage_claim": False, "live_effect_claim": False,
            "predicate_claim": False, "breach_claim": False,
            "superiority_claim": False, "hosted_parity_claim": False,
        })

    write_jsonl(paths["raw"], raw_rows)
    canonical_fields = [
        "experiment_version","row_id","order","category","claim_type","policy_id","import_module_path","import_class",
        "guardrail_source_sha256","predicates_source_sha256","input_sha256","tool_name_json","tool_args_json","context_json","hook_state",
        "expected_action_hypothesis","expected_reason_hypothesis","hypothesis_status","invocation_status","observed_decision_type","observed_action",
        "observed_reason_raw","observed_reason_sha256","exception_type","exception_message_sha256","hypothesis_action_resolution",
        "hypothesis_reason_resolution","execution_duration_ns","runtime_layer","real_lineage_claim","live_effect_claim","predicate_claim",
        "breach_claim","superiority_claim","hosted_parity_claim",
    ]
    write_csv(paths["canonical"], raw_rows, canonical_fields)

    pair_rows: list[dict[str, Any]] = []
    by_row: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in raw_rows:
        by_row[row["row_id"]].append(row)
    for row_id in sorted(by_row, key=lambda rid: int(rid.split("-")[-1])):
        rows = {r["policy_id"]: r for r in by_row[row_id]}
        p = rows["PACKAGED_OPTIMAL"]
        h = rows["PROPOSAL_AWARE_OPTIMAL"]
        pair_rows.append({
            "row_id": row_id, "order": p["order"], "category": p["category"], "claim_type": p["claim_type"],
            "input_sha256": p["input_sha256"], "input_identity_match": p["input_sha256"] == h["input_sha256"],
            "packaged_invocation_status": p["invocation_status"], "packaged_action": p["observed_action"], "packaged_reason_sha256": p["observed_reason_sha256"], "packaged_exception_type": p["exception_type"],
            "hardened_invocation_status": h["invocation_status"], "hardened_action": h["observed_action"], "hardened_reason_sha256": h["observed_reason_sha256"], "hardened_exception_type": h["exception_type"],
            "observed_action_equal": p["observed_action"] == h["observed_action"] and p["invocation_status"] == h["invocation_status"],
            "observed_reason_equal": p["observed_reason_raw"] == h["observed_reason_raw"],
            "packaged_hypothesis_resolution": p["hypothesis_action_resolution"],
            "hardened_hypothesis_resolution": h["hypothesis_action_resolution"],
            "superiority_claim": False,
        })
    write_csv(paths["pairs"], pair_rows, [
        "row_id","order","category","claim_type","input_sha256","input_identity_match",
        "packaged_invocation_status","packaged_action","packaged_reason_sha256","packaged_exception_type",
        "hardened_invocation_status","hardened_action","hardened_reason_sha256","hardened_exception_type",
        "observed_action_equal","observed_reason_equal","packaged_hypothesis_resolution","hardened_hypothesis_resolution","superiority_claim",
    ])

    invocation_counts = Counter(row["invocation_status"] for row in raw_rows)
    resolution_counts = Counter(row["hypothesis_action_resolution"] for row in raw_rows)
    policy_counts = {pid: Counter(row["observed_action"] or row["invocation_status"] for row in raw_rows if row["policy_id"] == pid) for pid in policies}
    summary = {
        "scenario_count": len(pair_rows), "policy_row_count": len(raw_rows),
        "invocation_status_counts": dict(invocation_counts), "hypothesis_action_resolution_counts": dict(resolution_counts),
        "policy_observed_outcome_counts": {k: dict(v) for k, v in policy_counts.items()},
        "pair_action_equal_count": sum(1 for row in pair_rows if row["observed_action_equal"]),
        "pair_action_different_count": sum(1 for row in pair_rows if not row["observed_action_equal"]),
        "claim_boundary": "DIRECT_POLICY_UNIT_DECISIONS_ONLY_NO_EFFECT_OR_SUPERIORITY_CLAIM",
    }
    write_json(paths["summary"], summary)
    result = {
        "version": VERSION, "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "P3A_DIRECT_POLICY_UNIT_EXECUTION_COMPLETE",
        "classification": "MATCHED_DIRECT_GUARDRAIL_DECISIONS_OBSERVED_EFFECT_AND_SUPERIORITY_CLAIMS_WITHHELD",
        "execution_type": "DIRECT_GUARDRAIL_DECIDE_ONLY",
        "required_parent_artifacts_verified": len(checks), "scenario_count": len(pair_rows), "policy_row_count": len(raw_rows),
        "packaged_import_class": packaged_class_name, "hardened_import_class": hardened_class_name,
        "packaged_source_sha256": EXPECTED_PACKAGED_SHA256, "hardened_source_sha256": EXPECTED_HARDENED_SHA256,
        "predicates_source_sha256": EXPECTED_PREDICATES_SHA256, "runner_sha256": sha256(runner),
        "gpt_oss_used": False, "sandbox_used": False, "gym_used": False, "hooks_used": False, "wrapper_used": False,
        "tools_executed": False, "fixtures_opened": False, "effects_observed": False,
        "predicates_recomputed": False, "breach_recomputed": False,
        "harness_trick": "NOT_DEMONSTRATED", "security_finding": "NOT_ESTABLISHED_DIRECT_POLICY_UNIT_DECISIONS_ONLY",
        "superiority_claim": False, "hosted_parity_claim": False,
        "summary": summary, "next_gate": "INDEPENDENT_RESULT_REVIEW_BEFORE_ANY_GPT_OSS_OR_SANDBOX_EXPERIMENT",
    }
    write_json(paths["result"], result)

    generated = ["parent","preflight","raw","canonical","pairs","summary","result"]
    manifest_rows = [{"artifact":paths[k].name,"role":"DERIVED_P3A_DIRECT_EXECUTION","size_bytes":paths[k].stat().st_size,"sha256":sha256(paths[k]),"source_path":str(paths[k])} for k in generated]
    for path, role in ((runner,"CURRENT_RUNNER"),(parent_manifest,"SOURCE_OR_PARENT"),(parent_binding,"SOURCE_OR_PARENT"),(matrix_path,"FROZEN_MATRIX"),(packaged_source,"PACKAGED_SOURCE"),(hardened_source,"HARDENED_SOURCE"),(predicates_source,"EVALUATOR_SOURCE")):
        manifest_rows.append({"artifact":path.name,"role":role,"size_bytes":path.stat().st_size,"sha256":sha256(path),"source_path":str(path)})
    for row in checks:
        manifest_rows.append({"artifact":row["artifact"],"role":"VERIFIED_PARENT_EVIDENCE","size_bytes":row["observed_size_bytes"],"sha256":row["observed_sha256"],"source_path":row["path"]})
    paths["manifest"] = out / "ex6_v6_93_manifest.csv"
    write_csv(paths["manifest"], manifest_rows, ["artifact","role","size_bytes","sha256","source_path"])
    external_out = {
        "version": VERSION, "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "manifest_filename": paths["manifest"].name, "manifest_size_bytes": paths["manifest"].stat().st_size,
        "manifest_sha256": sha256(paths["manifest"]), "status": result["status"], "classification": result["classification"],
        "parent_v6_92_manifest_sha256": EXPECTED_PARENT_MANIFEST_SHA256, "runner_sha256": sha256(runner),
        "matrix_sha256": sha256(matrix_path), "packaged_source_sha256": EXPECTED_PACKAGED_SHA256,
        "hardened_source_sha256": EXPECTED_HARDENED_SHA256, "predicates_sha256": EXPECTED_PREDICATES_SHA256,
    }
    paths["external"] = out / "ex6_v6_93_manifest_external_binding.json"
    write_json(paths["external"], external_out)
    print(json.dumps({
        "status": result["status"], "scenario_count": len(pair_rows), "policy_row_count": len(raw_rows),
        "packaged_import_class": packaged_class_name, "hardened_import_class": hardened_class_name,
        "invocation_status_counts": dict(invocation_counts), "hypothesis_action_resolution_counts": dict(resolution_counts),
        "runner_sha256": sha256(runner), "manifest_sha256": external_out["manifest_sha256"], "output_directory": str(out),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
