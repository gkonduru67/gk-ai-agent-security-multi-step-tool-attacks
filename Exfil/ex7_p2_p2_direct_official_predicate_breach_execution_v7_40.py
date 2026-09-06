#!/usr/bin/env python3
"""EX7 P2 P2 direct official predicate and breach execution.

Imports only the SHA-256-bound predicates.py. For all 24 controls, calls
`eval_predicates(trace)` exactly once to capture the normal-flow result. For 22
NORMAL_FLOW rows, calls `is_breach(trace, observed_predicates)` exactly once.
For two DIRECT_BREACH_UNIT rows, calls
`is_breach(trace, supplied_predicates)` exactly once.

No model, guardrail, Sandbox, Gym, external tool, or effect execution. All
traces are synthetic and cannot establish real source lineage or live defense.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import sys
import time
import traceback
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX7_P2_P2_DIRECT_OFFICIAL_PREDICATE_AND_BREACH_EXECUTION_v7.40"
EXPECTED_PARENT_MANIFEST_SHA256 = "931A38F67B3FC0D8FA77898F57FCDCD9D22FD8725B5648E3E47AED984FBB8663"
EXPECTED_PARENT_STATUS = "EX7_P2_P1A_INDEPENDENT_FIXTURE_RECOMPUTATION_FREEZE_COMPLETE"
EXPECTED_TRACE_MATRIX_SHA256 = "CE21E427F3A7D44F35B5237195C89793F1237058A2FB5310726C732AB770ECD6"
EXPECTED_PREDICATES_SHA256 = "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
EXPECTED_P1A_RUNNER_SHA256 = "1184A2DA15039F4B2A5FEC2C509E17C2C462C54931118EABD19CFCA7FD09187A"
EXPECTED_CONTROL_ROWS = 24
EXPECTED_NORMAL_FLOW = 22
EXPECTED_DIRECT_BREACH_UNIT = 2
EXPECTED_UNIQUE_TRACES = 21
EXPECTED_DUPLICATE_GROUPS = 2

REQUIRED_PARENT_ARTIFACTS = {
    "ex7_v7_30A_parent_verification.csv",
    "ex7_v7_30A_fixture_recomputation.csv",
    "ex7_v7_30A_trace_reuse_groups.csv",
    "ex7_v7_30A_claim_boundary.json",
    "ex7_v7_30A_result.json",
    "ex7_v7_30A_binding.json",
    "ex7_p2_p1a_independent_fixture_recomputation_v7_30A.py",
    "ex7_v7_30_trace_matrix.csv",
    "predicates.py",
}

RAW_FIELDS = [
    "experiment_version", "control_id", "flow_type", "trace_sha256",
    "supplied_predicates_sha256", "predicates_source_sha256",
    "P1A_manifest_sha256", "eval_predicates_call_count",
    "eval_predicates_status", "observed_predicates_json",
    "observed_predicates_sha256", "observed_EXFILTRATION_count",
    "is_breach_call_count", "is_breach_status",
    "breach_predicate_input_source", "breach_predicate_input_json",
    "breach_predicate_input_sha256", "observed_breach",
    "predicate_exception_type", "predicate_exception_message_sha256",
    "predicate_traceback_raw", "breach_exception_type",
    "breach_exception_message_sha256", "breach_traceback_raw",
    "eval_duration_ns", "breach_duration_ns", "execution_duration_ns",
    "expected_predicates_json", "predicate_objects_match",
    "expected_EXFILTRATION_count", "predicate_count_match",
    "expected_breach", "breach_match", "full_expectation_match",
    "synthetic_trace", "real_lineage_claim", "effect_observed",
    "guardrail_executed", "direct_breach_unit", "unique_trace_input",
    "trace_reuse_group_size", "guardrail_semantics",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest().upper()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest().upper()


def parse_bool(text: str) -> bool:
    value = text.strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    raise ValueError(f"Invalid Boolean value: {text!r}")


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
    required_columns = {"artifact", "role", "size_bytes", "sha256", "source_path"}
    if not rows or not required_columns.issubset(rows[0]):
        raise ValueError("Invalid P1A manifest columns")
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        name = row["artifact"].strip()
        if name in indexed:
            prior = indexed[name]
            if any(prior[key].strip() != row[key].strip() for key in ("size_bytes", "sha256", "source_path")):
                raise ValueError(f"Conflicting duplicate artifact: {name}")
            continue
        indexed[name] = row
    missing = sorted(REQUIRED_PARENT_ARTIFACTS - set(indexed))
    if missing:
        raise ValueError(f"Missing required P1A artifacts: {missing}")
    return indexed


def verify_manifest_row(row: dict[str, str]) -> dict[str, Any]:
    path = Path(row["source_path"])
    exists = path.is_file()
    observed_size = path.stat().st_size if exists else None
    observed_sha = sha256_file(path) if exists else None
    expected_size = int(row["size_bytes"])
    expected_sha = row["sha256"].upper()
    passed = exists and observed_size == expected_size and observed_sha == expected_sha
    return {
        "artifact": row["artifact"], "path": str(path), "exists": exists,
        "expected_size_bytes": expected_size, "observed_size_bytes": observed_size,
        "size_match": exists and observed_size == expected_size,
        "expected_sha256": expected_sha, "observed_sha256": observed_sha,
        "sha256_match": exists and observed_sha == expected_sha, "passed": passed,
    }


def import_official_functions(source: Path):
    spec = importlib.util.spec_from_file_location("_ex7_official_predicates_v740", source)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot create module spec for {source}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    eval_fn = getattr(module, "eval_predicates", None)
    breach_fn = getattr(module, "is_breach", None)
    if not callable(eval_fn) or not callable(breach_fn):
        raise TypeError("eval_predicates and is_breach must both be callable")
    return eval_fn, breach_fn


def exception_fields(exc: BaseException) -> tuple[str, str, str]:
    message = str(exc)
    return type(exc).__name__, sha256_text(message), traceback.format_exc()


def main() -> int:
    parser = argparse.ArgumentParser(description=VERSION)
    parser.add_argument("--v7-30a-manifest", required=True)
    parser.add_argument("--v7-30a-binding", required=True)
    parser.add_argument("--predicates-source", required=True)
    parser.add_argument("--out-root", required=True)
    args = parser.parse_args()

    runner = Path(__file__).resolve()
    parent_manifest = Path(args.v7_30a_manifest)
    parent_binding = Path(args.v7_30a_binding)
    predicates_source = Path(args.predicates_source).resolve()
    out = Path(args.out_root)

    if out.exists():
        raise FileExistsError(f"Refusing to overwrite existing output directory: {out}")
    for path in (runner, parent_manifest, parent_binding, predicates_source):
        if not path.is_file():
            raise FileNotFoundError(path)

    if sha256_file(parent_manifest) != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("P1A manifest identity mismatch")
    external = load_json(parent_binding)
    if external.get("manifest_sha256") != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("P1A external-binding manifest mismatch")
    if external.get("status") != EXPECTED_PARENT_STATUS:
        raise ValueError("P1A status mismatch")
    if external.get("trace_matrix_sha256") != EXPECTED_TRACE_MATRIX_SHA256:
        raise ValueError("P1A trace-matrix identity mismatch")
    if external.get("predicates_sha256") != EXPECTED_PREDICATES_SHA256:
        raise ValueError("P1A predicates identity mismatch")
    if external.get("control_rows") != EXPECTED_CONTROL_ROWS:
        raise ValueError("P1A control-row count mismatch")
    if external.get("unique_trace_sha256_values") != EXPECTED_UNIQUE_TRACES:
        raise ValueError("P1A unique-trace count mismatch")
    if external.get("duplicate_trace_groups") != EXPECTED_DUPLICATE_GROUPS:
        raise ValueError("P1A duplicate-group count mismatch")
    if sha256_file(predicates_source) != EXPECTED_PREDICATES_SHA256:
        raise ValueError("predicates.py identity mismatch")

    indexed = index_manifest(parent_manifest)
    checks = [verify_manifest_row(indexed[name]) for name in sorted(REQUIRED_PARENT_ARTIFACTS)]
    failed_checks = [row for row in checks if not row["passed"]]
    if failed_checks:
        raise ValueError("P1A parent verification failed: " + ", ".join(r["artifact"] for r in failed_checks))
    if indexed["ex7_p2_p1a_independent_fixture_recomputation_v7_30A.py"]["sha256"].upper() != EXPECTED_P1A_RUNNER_SHA256:
        raise ValueError("P1A runner identity mismatch")

    matrix_path = Path(indexed["ex7_v7_30_trace_matrix.csv"]["source_path"])
    if sha256_file(matrix_path) != EXPECTED_TRACE_MATRIX_SHA256:
        raise ValueError("Qualified trace-matrix identity mismatch")
    matrix = load_csv(matrix_path)
    if len(matrix) != EXPECTED_CONTROL_ROWS or len({row["control_id"] for row in matrix}) != EXPECTED_CONTROL_ROWS:
        raise ValueError("Expected 24 unique control rows")
    if sum(row["flow_type"] == "NORMAL_FLOW" for row in matrix) != EXPECTED_NORMAL_FLOW:
        raise ValueError("Expected 22 normal-flow controls")
    if sum(row["flow_type"] == "DIRECT_BREACH_UNIT" for row in matrix) != EXPECTED_DIRECT_BREACH_UNIT:
        raise ValueError("Expected two direct breach-unit controls")

    trace_groups: dict[str, list[str]] = defaultdict(list)
    prepared: list[tuple[dict[str, str], dict[str, Any], list[dict[str, Any]]]] = []
    for row in matrix:
        trace = json.loads(row["trace_json"])
        supplied = json.loads(row["supplied_predicates_json"])
        canonical_trace = canonical_json(trace)
        canonical_supplied = canonical_json(supplied)
        if sha256_text(canonical_trace) != row["trace_sha256"]:
            raise ValueError(f"Trace hash mismatch: {row['control_id']}")
        if sha256_text(canonical_supplied) != row["supplied_predicates_sha256"]:
            raise ValueError(f"Supplied-predicate hash mismatch: {row['control_id']}")
        trace_groups[row["trace_sha256"]].append(row["control_id"])
        prepared.append((row, trace, supplied))
    if len(trace_groups) != EXPECTED_UNIQUE_TRACES:
        raise ValueError("Expected 21 unique trace inputs")
    duplicate_groups = {digest: controls for digest, controls in trace_groups.items() if len(controls) > 1}
    if len(duplicate_groups) != EXPECTED_DUPLICATE_GROUPS:
        raise ValueError("Expected two duplicate trace groups")

    out.mkdir(parents=True)
    paths = {
        "parent": out / "ex7_v7_40_parent_verification.csv",
        "preflight": out / "ex7_v7_40_execution_preflight.json",
        "raw": out / "ex7_v7_40_raw_results.jsonl",
        "canonical": out / "ex7_v7_40_canonical_results.csv",
        "reuse": out / "ex7_v7_40_trace_reuse_disclosure.csv",
        "summary": out / "ex7_v7_40_summary.json",
        "claims": out / "ex7_v7_40_claim_boundary.json",
        "result": out / "ex7_v7_40_result.json",
        "binding": out / "ex7_v7_40_binding.json",
        "manifest": out / "ex7_v7_40_manifest.csv",
        "external": out / "ex7_v7_40_manifest_external_binding.json",
    }
    write_csv(paths["parent"], checks, [
        "artifact", "path", "exists", "expected_size_bytes", "observed_size_bytes",
        "size_match", "expected_sha256", "observed_sha256", "sha256_match", "passed",
    ])
    preflight = {
        "version": VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "parent_manifest_sha256": sha256_file(parent_manifest),
        "trace_matrix_sha256": sha256_file(matrix_path),
        "predicates_sha256": sha256_file(predicates_source),
        "runner_sha256": sha256_file(runner),
        "control_rows": len(matrix),
        "normal_flow_controls": EXPECTED_NORMAL_FLOW,
        "direct_breach_unit_controls": EXPECTED_DIRECT_BREACH_UNIT,
        "unique_trace_inputs": len(trace_groups),
        "duplicate_trace_groups": len(duplicate_groups),
        "input_hashes_revalidated": True,
        "official_functions_imported_after_all_identity_gates": True,
        "model": False, "guardrail": False, "sandbox": False,
        "gym": False, "tools": False, "effects": False,
    }
    write_json(paths["preflight"], preflight)

    try:
        eval_predicates, is_breach = import_official_functions(predicates_source)
    except Exception:
        preflight["official_function_import_status"] = "FAILED"
        preflight["official_function_import_traceback"] = traceback.format_exc()
        write_json(paths["preflight"], preflight)
        raise

    results: list[dict[str, Any]] = []
    for matrix_row, trace, supplied_predicates in prepared:
        control_id = matrix_row["control_id"]
        expected_predicates = json.loads(matrix_row["expected_EXFILTRATION_predicate_objects_json"])
        expected_count = int(matrix_row["expected_EXFILTRATION_predicate_count"])
        expected_breach = parse_bool(matrix_row["expected_breach"])

        observed_predicates: Any = None
        predicate_status = "NOT_STARTED"
        predicate_exc_type = predicate_exc_hash = predicate_tb = None
        predicate_start = time.perf_counter_ns()
        try:
            observed_predicates = eval_predicates(trace)
            eval_duration = time.perf_counter_ns() - predicate_start
            predicate_status = "EXECUTED_RETURNED"
        except Exception as exc:
            eval_duration = time.perf_counter_ns() - predicate_start
            predicate_status = "EXECUTED_EXCEPTION_RAISED"
            predicate_exc_type, predicate_exc_hash, predicate_tb = exception_fields(exc)

        if predicate_status == "EXECUTED_RETURNED":
            observed_predicates_json = canonical_json(observed_predicates)
            observed_predicates_sha = sha256_text(observed_predicates_json)
            if not isinstance(observed_predicates, list):
                predicate_status = "EXECUTED_INVALID_RETURN_TYPE"
                observed_exfiltration_count = None
            else:
                observed_exfiltration_count = sum(
                    isinstance(item, dict) and item.get("predicate") == "EXFILTRATION"
                    for item in observed_predicates
                )
        else:
            observed_predicates_json = ""
            observed_predicates_sha = None
            observed_exfiltration_count = None

        direct_unit = matrix_row["flow_type"] == "DIRECT_BREACH_UNIT"
        breach_input = supplied_predicates if direct_unit else observed_predicates
        breach_input_source = "SUPPLIED_PREDICATES" if direct_unit else "OBSERVED_EVAL_PREDICATES"
        breach_input_json = canonical_json(breach_input) if breach_input is not None else ""
        breach_input_sha = sha256_text(breach_input_json) if breach_input is not None else None

        observed_breach: Any = None
        breach_status = "NOT_EXECUTED_DUE_TO_PREDICATE_FAILURE" if breach_input is None else "NOT_STARTED"
        breach_exc_type = breach_exc_hash = breach_tb = None
        breach_duration = 0
        breach_call_count = 0
        if breach_input is not None:
            breach_call_count = 1
            breach_start = time.perf_counter_ns()
            try:
                observed_breach = is_breach(trace, breach_input)
                breach_duration = time.perf_counter_ns() - breach_start
                breach_status = "EXECUTED_BOOLEAN_RETURNED" if isinstance(observed_breach, bool) else "EXECUTED_INVALID_RETURN_TYPE"
            except Exception as exc:
                breach_duration = time.perf_counter_ns() - breach_start
                breach_status = "EXECUTED_EXCEPTION_RAISED"
                breach_exc_type, breach_exc_hash, breach_tb = exception_fields(exc)

        predicate_objects_match = (
            predicate_status == "EXECUTED_RETURNED" and observed_predicates == expected_predicates
        )
        predicate_count_match = observed_exfiltration_count == expected_count
        breach_match = breach_status == "EXECUTED_BOOLEAN_RETURNED" and observed_breach == expected_breach
        full_match = predicate_objects_match and predicate_count_match and breach_match

        results.append({
            "experiment_version": VERSION,
            "control_id": control_id,
            "flow_type": matrix_row["flow_type"],
            "trace_sha256": matrix_row["trace_sha256"],
            "supplied_predicates_sha256": matrix_row["supplied_predicates_sha256"],
            "predicates_source_sha256": EXPECTED_PREDICATES_SHA256,
            "P1A_manifest_sha256": EXPECTED_PARENT_MANIFEST_SHA256,
            "eval_predicates_call_count": 1,
            "eval_predicates_status": predicate_status,
            "observed_predicates_json": observed_predicates_json,
            "observed_predicates_sha256": observed_predicates_sha,
            "observed_EXFILTRATION_count": observed_exfiltration_count,
            "is_breach_call_count": breach_call_count,
            "is_breach_status": breach_status,
            "breach_predicate_input_source": breach_input_source,
            "breach_predicate_input_json": breach_input_json,
            "breach_predicate_input_sha256": breach_input_sha,
            "observed_breach": observed_breach,
            "predicate_exception_type": predicate_exc_type,
            "predicate_exception_message_sha256": predicate_exc_hash,
            "predicate_traceback_raw": predicate_tb,
            "breach_exception_type": breach_exc_type,
            "breach_exception_message_sha256": breach_exc_hash,
            "breach_traceback_raw": breach_tb,
            "eval_duration_ns": eval_duration,
            "breach_duration_ns": breach_duration,
            "execution_duration_ns": eval_duration + breach_duration,
            "expected_predicates_json": canonical_json(expected_predicates),
            "predicate_objects_match": predicate_objects_match,
            "expected_EXFILTRATION_count": expected_count,
            "predicate_count_match": predicate_count_match,
            "expected_breach": expected_breach,
            "breach_match": breach_match,
            "full_expectation_match": full_match,
            "synthetic_trace": True,
            "real_lineage_claim": False,
            "effect_observed": False,
            "guardrail_executed": False,
            "direct_breach_unit": direct_unit,
            "unique_trace_input": len(trace_groups[matrix_row["trace_sha256"]]) == 1,
            "trace_reuse_group_size": len(trace_groups[matrix_row["trace_sha256"]]),
            "guardrail_semantics": "FAILED_SINK_PROXY_ONLY" if control_id == "EXFIL_GUARDRAIL_BLOCK" else "NOT_APPLICABLE",
        })

    write_jsonl(paths["raw"], results)
    write_csv(paths["canonical"], results, RAW_FIELDS)
    reuse_rows = [
        {
            "trace_sha256": digest,
            "control_count": len(controls),
            "controls_json": canonical_json(controls),
            "reuse_classification": "INTENTIONAL_SEMANTIC_FIXTURE_REUSE",
            "independent_input_count": 1,
        }
        for digest, controls in sorted(duplicate_groups.items())
    ]
    write_csv(paths["reuse"], reuse_rows, [
        "trace_sha256", "control_count", "controls_json",
        "reuse_classification", "independent_input_count",
    ])

    normal_results = [row for row in results if row["flow_type"] == "NORMAL_FLOW"]
    direct_results = [row for row in results if row["flow_type"] == "DIRECT_BREACH_UNIT"]
    full_matches = [row for row in results if row["full_expectation_match"]]
    mismatches = [row["control_id"] for row in results if not row["full_expectation_match"]]
    eval_status_counts = Counter(row["eval_predicates_status"] for row in results)
    breach_status_counts = Counter(row["is_breach_status"] for row in results)
    summary = {
        "semantic_control_rows": len(results),
        "normal_flow_denominator": len(normal_results),
        "direct_breach_unit_denominator": len(direct_results),
        "unique_trace_inputs": len(trace_groups),
        "independent_input_denominator": len(trace_groups),
        "duplicate_trace_groups": len(duplicate_groups),
        "eval_predicates_call_count": sum(row["eval_predicates_call_count"] for row in results),
        "is_breach_call_count": sum(row["is_breach_call_count"] for row in results),
        "eval_status_counts": dict(eval_status_counts),
        "breach_status_counts": dict(breach_status_counts),
        "full_expectation_match_count": len(full_matches),
        "full_expectation_mismatch_count": len(mismatches),
        "mismatch_control_ids": mismatches,
        "normal_flow_match_count": sum(row["full_expectation_match"] for row in normal_results),
        "direct_breach_unit_match_count": sum(row["full_expectation_match"] for row in direct_results),
        "guardrail_block_classification": "FAILED_SINK_PROXY_ONLY",
        "claim_boundary": "OFFICIAL_PREDICATE_AND_BREACH_RESULTS_ON_SYNTHETIC_CONTROLS_ONLY_NO_REAL_LINEAGE_EFFECT_OR_GUARDRAIL_EFFECTIVENESS_CLAIM",
    }
    write_json(paths["summary"], summary)
    write_json(paths["claims"], {
        "allowed": [
            "official eval_predicates output for 24 frozen synthetic controls",
            "official is_breach output for 22 normal-flow and two direct breach-unit controls",
            "expectation agreement or disagreement",
            "same-trace ordering behavior", "ok type behavior", "path behavior",
            "source extraction behavior", "predicate multiplicity", "breach-unit behavior",
        ],
        "prohibited": [
            "24 independent input samples", "real source lineage", "real sink effect",
            "actual guardrail denial", "guardrail effectiveness", "policy superiority",
            "hosted parity", "agent-level security effectiveness",
        ],
        "semantic_control_rows": 24,
        "unique_trace_inputs": 21,
        "normal_flow_controls": 22,
        "direct_breach_unit_controls": 2,
        "synthetic_traces": True,
    })

    result = {
        "version": VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "EX7_P2_P2_DIRECT_OFFICIAL_PREDICATE_AND_BREACH_EXECUTION_COMPLETE",
        "classification": "OFFICIAL_PREDICATE_AND_BREACH_SYNTHETIC_CONTROL_RESULTS_FROZEN_REAL_SECURITY_EFFECT_CLAIMS_WITHHELD",
        "execution_type": "DIRECT_OFFICIAL_PREDICATE_AND_BREACH_EXECUTION",
        "required_parent_artifacts_verified": len(checks),
        "semantic_control_rows": 24,
        "normal_flow_controls": 22,
        "direct_breach_unit_controls": 2,
        "unique_trace_inputs": 21,
        "duplicate_trace_groups": 2,
        "eval_predicates_call_count": summary["eval_predicates_call_count"],
        "is_breach_call_count": summary["is_breach_call_count"],
        "full_expectation_match_count": summary["full_expectation_match_count"],
        "full_expectation_mismatch_count": summary["full_expectation_mismatch_count"],
        "mismatch_control_ids": mismatches,
        "predicates_imported": True,
        "eval_predicates_executed": True,
        "is_breach_executed": True,
        "model_used": False,
        "guardrail_used": False,
        "sandbox_used": False,
        "gym_used": False,
        "external_tools_executed": False,
        "effects_observed": False,
        "harness_trick": "NOT_DEMONSTRATED",
        "robust_finding": "OFFICIAL_PREDICATE_AND_BREACH_BEHAVIOR_ESTABLISHED_FOR_FROZEN_SYNTHETIC_CONTROL_POPULATION",
        "security_finding": "REAL_LINEAGE_AND_END_TO_END_SECURITY_EFFECT_NOT_ESTABLISHED",
        "real_lineage_claim": False,
        "guardrail_effectiveness_claim": False,
        "superiority_claim": False,
        "hosted_parity_claim": False,
        "next_gate": "EX7_P2_P2A_INDEPENDENT_RESULT_QUALIFICATION",
        "summary": summary,
    }
    write_json(paths["result"], result)
    write_json(paths["binding"], {
        "version": VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "parent_manifest": {"path": str(parent_manifest), "size_bytes": parent_manifest.stat().st_size, "sha256": sha256_file(parent_manifest)},
        "parent_binding": {"path": str(parent_binding), "size_bytes": parent_binding.stat().st_size, "sha256": sha256_file(parent_binding)},
        "trace_matrix": {"path": str(matrix_path), "size_bytes": matrix_path.stat().st_size, "sha256": sha256_file(matrix_path)},
        "predicates": {"path": str(predicates_source), "size_bytes": predicates_source.stat().st_size, "sha256": sha256_file(predicates_source)},
        "runner": {"path": str(runner), "size_bytes": runner.stat().st_size, "sha256": sha256_file(runner)},
        "verified_parent_artifacts": checks,
        "parent_artifacts_modified": False,
        "trace_matrix_modified": False,
    })

    generated = ["parent", "preflight", "raw", "canonical", "reuse", "summary", "claims", "result", "binding"]
    manifest_rows = [
        {
            "artifact": paths[key].name,
            "role": "DERIVED_EX7_P2_P2_OFFICIAL_EXECUTION",
            "size_bytes": paths[key].stat().st_size,
            "sha256": sha256_file(paths[key]),
            "source_path": str(paths[key]),
        }
        for key in generated
    ]
    for path, role in (
        (runner, "CURRENT_RUNNER"),
        (parent_manifest, "SOURCE_OR_PARENT"),
        (parent_binding, "SOURCE_OR_PARENT"),
        (matrix_path, "EXECUTED_TRACE_MATRIX"),
        (predicates_source, "AUTHORITATIVE_PREDICATE_SOURCE"),
    ):
        manifest_rows.append({
            "artifact": path.name, "role": role, "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path), "source_path": str(path),
        })
    for verified in checks:
        manifest_rows.append({
            "artifact": verified["artifact"], "role": "VERIFIED_PARENT_EVIDENCE",
            "size_bytes": verified["observed_size_bytes"],
            "sha256": verified["observed_sha256"], "source_path": verified["path"],
        })
    write_csv(paths["manifest"], manifest_rows, ["artifact", "role", "size_bytes", "sha256", "source_path"])
    external_out = {
        "version": VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "manifest_filename": paths["manifest"].name,
        "manifest_size_bytes": paths["manifest"].stat().st_size,
        "manifest_sha256": sha256_file(paths["manifest"]),
        "status": result["status"],
        "classification": result["classification"],
        "parent_v7_30A_manifest_sha256": EXPECTED_PARENT_MANIFEST_SHA256,
        "trace_matrix_sha256": EXPECTED_TRACE_MATRIX_SHA256,
        "predicates_sha256": EXPECTED_PREDICATES_SHA256,
        "runner_sha256": sha256_file(runner),
        "semantic_control_rows": 24,
        "normal_flow_controls": 22,
        "direct_breach_unit_controls": 2,
        "unique_trace_inputs": 21,
        "eval_predicates_call_count": summary["eval_predicates_call_count"],
        "is_breach_call_count": summary["is_breach_call_count"],
        "full_expectation_match_count": summary["full_expectation_match_count"],
        "full_expectation_mismatch_count": summary["full_expectation_mismatch_count"],
    }
    write_json(paths["external"], external_out)

    print(json.dumps({
        "status": result["status"],
        "semantic_control_rows": 24,
        "normal_flow_controls": 22,
        "direct_breach_unit_controls": 2,
        "unique_trace_inputs": 21,
        "eval_predicates_call_count": summary["eval_predicates_call_count"],
        "is_breach_call_count": summary["is_breach_call_count"],
        "full_expectation_match_count": summary["full_expectation_match_count"],
        "full_expectation_mismatch_count": summary["full_expectation_mismatch_count"],
        "mismatch_control_ids": mismatches,
        "runner_sha256": sha256_file(runner),
        "manifest_sha256": external_out["manifest_sha256"],
        "output_directory": str(out),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
