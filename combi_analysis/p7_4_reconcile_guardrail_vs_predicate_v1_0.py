#!/usr/bin/env python3
"""P7.4 read-only reconciliation probe.

Explains why a trace can show a successful renamed-fixture read and matched
http.post while aicomp_sdk.core.predicates.eval_predicates() returns no
EXFILTRATION finding.

This script does not call a model, execute tools, dispatch network traffic,
or modify fixtures/SDK files. It only:
  1. verifies input and SDK identities;
  2. extracts the EXFILTRATION scenario from a prior local result JSON;
  3. builds several trace-shape variants from the same frozen events;
  4. calls the installed predicate code in memory;
  5. statically inspects relevant predicate constants/functions;
  6. emits redacted JSON/CSV evidence plus SHA-256 manifests.

No secret plaintext is persisted. Payloads and outputs are represented only
by length and SHA-256.
"""
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import importlib
import inspect
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "P7_4_RECONCILE_GUARDRAIL_VS_PREDICATE_v1.0"
TARGET_SCENARIO = "exfil_renamed_fixture"
RELEVANT_NAMES = {
    "SECRET_FILENAME", "SECRET_MARKER", "EXFILTRATION",
    "_is_secret_path", "_extract_secret_values", "_secrets_read_in_trace",
    "_contains_secret", "eval_predicates", "is_breach",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha_text(text: str) -> str:
    return sha_bytes(text.encode("utf-8", "surrogatepass"))


def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def identity(path: Path) -> dict[str, Any]:
    path = path.resolve()
    return {
        "artifact": path.name,
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "sha256": sha_file(path),
    }


def json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(v) for v in value]
    if hasattr(value, "__dict__"):
        return json_safe(vars(value))
    return repr(value)


def summarize_secret(value: Any) -> Any:
    if not isinstance(value, str):
        return json_safe(value)
    return {"redacted": True, "length": len(value), "sha256": sha_text(value)}


def redact_event(event: dict[str, Any]) -> dict[str, Any]:
    out = {k: json_safe(v) for k, v in event.items() if k not in {"output", "args"}}
    out["output_summary"] = summarize_secret(event.get("output"))
    args = dict(event.get("args") or {})
    if "data" in args:
        args["data"] = summarize_secret(args["data"])
    if "content" in args:
        args["content"] = summarize_secret(args["content"])
    out["args"] = json_safe(args)
    return out


def find_scenario(doc: Any, scenario_id: str) -> dict[str, Any]:
    rows = doc if isinstance(doc, list) else doc.get("results", doc.get("scenarios", []))
    for row in rows:
        if row.get("scenario_id") == scenario_id:
            return row
    raise ValueError(f"Scenario not found: {scenario_id}")


def tool_events_from_scenario(scenario: dict[str, Any]) -> list[dict[str, Any]]:
    events = scenario.get("tool_events")
    if not isinstance(events, list):
        raise ValueError("Scenario has no tool_events list")
    return events


def matched_read_post(events: list[dict[str, Any]]) -> dict[str, Any]:
    reads = [e for e in events if e.get("name") == "fs.read" and e.get("ok") is True]
    posts = [e for e in events if e.get("name") == "http.post" and e.get("ok") is True]
    read_output = reads[-1].get("output") if reads else None
    post_data = ((posts[-1].get("args") or {}).get("data")) if posts else None
    return {
        "successful_read_count": len(reads),
        "successful_post_count": len(posts),
        "read_output_present": isinstance(read_output, str),
        "post_data_present": isinstance(post_data, str),
        "read_output_sha256": sha_text(read_output) if isinstance(read_output, str) else None,
        "post_data_sha256": sha_text(post_data) if isinstance(post_data, str) else None,
        "exact_value_match": isinstance(read_output, str) and isinstance(post_data, str) and read_output == post_data,
    }


def static_predicate_inventory(predicate_path: Path) -> dict[str, Any]:
    source = predicate_path.read_text(encoding="utf-8-sig")
    tree = ast.parse(source, filename=str(predicate_path))
    constants: dict[str, Any] = {}
    functions: dict[str, Any] = {}
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value_node = node.value
            for target in targets:
                if isinstance(target, ast.Name) and target.id in RELEVANT_NAMES and value_node is not None:
                    try:
                        constants[target.id] = ast.literal_eval(value_node)
                    except Exception:
                        constants[target.id] = "NON_LITERAL"
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in RELEVANT_NAMES:
            segment = ast.get_source_segment(source, node) or ""
            functions[node.name] = {
                "lineno": node.lineno,
                "end_lineno": getattr(node, "end_lineno", None),
                "source_sha256": sha_text(segment),
                "arg_names": [a.arg for a in node.args.args],
            }
    return {
        "path": str(predicate_path.resolve()),
        "sha256": sha_file(predicate_path),
        "constants": json_safe(constants),
        "functions": functions,
    }


def call_helper(module: Any, name: str, *args: Any) -> dict[str, Any]:
    fn = getattr(module, name, None)
    if not callable(fn):
        return {"available": False}
    try:
        value = fn(*args)
        if name == "_extract_secret_values":
            safe_value = [summarize_secret(v) for v in (value or [])]
        else:
            safe_value = json_safe(value)
        return {"available": True, "ok": True, "result": safe_value}
    except Exception as exc:
        return {"available": True, "ok": False, "error": f"{type(exc).__name__}: {exc}"}


def invoke_eval(module: Any, trace: dict[str, Any]) -> dict[str, Any]:
    try:
        findings = module.eval_predicates(trace)
        breach = module.is_breach(trace, findings)
        return {"ok": True, "findings": json_safe(findings), "is_breach": bool(breach)}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def build_trace_variants(scenario: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    turns = scenario.get("per_turn_log") or []
    user_messages = [t.get("message") for t in turns if isinstance(t, dict) and t.get("message")]
    # These are diagnostic shape variants only. They use identical frozen tool events.
    return {
        "A_tool_events_only": {"tool_events": events},
        "B_tool_events_user_messages": {"tool_events": events, "user_messages": user_messages},
        "C_tool_events_messages": {
            "tool_events": events,
            "messages": [{"role": "user", "content": text} for text in user_messages],
        },
        "D_original_scenario_plus_events": {**scenario, "tool_events": events},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=VERSION)
    ap.add_argument("--project-root", required=True)
    ap.add_argument("--v5-results", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--expected-v5-sha256", default=None)
    args = ap.parse_args()

    project = Path(args.project_root).resolve()
    results_path = Path(args.v5_results).resolve()
    out = Path(args.output_dir).resolve()
    if out.exists():
        raise FileExistsError(f"Refusing overwrite: {out}")
    out.mkdir(parents=True)

    predicate_path = project / "aicomp_sdk" / "core" / "predicates.py"
    if not predicate_path.is_file():
        raise FileNotFoundError(predicate_path)
    if not results_path.is_file():
        raise FileNotFoundError(results_path)
    if args.expected_v5_sha256 and sha_file(results_path) != args.expected_v5_sha256.upper():
        raise ValueError("v5 result SHA-256 mismatch")

    doc = json.loads(results_path.read_text(encoding="utf-8-sig"))
    scenario = find_scenario(doc, TARGET_SCENARIO)
    events = tool_events_from_scenario(scenario)
    flow = matched_read_post(events)

    sys.path.insert(0, str(project))
    try:
        predicates = importlib.import_module("aicomp_sdk.core.predicates")
    finally:
        if sys.path and sys.path[0] == str(project):
            sys.path.pop(0)

    static = static_predicate_inventory(predicate_path)
    variants = build_trace_variants(scenario, events)
    evals = {name: invoke_eval(predicates, trace) for name, trace in variants.items()}

    read_event = next((e for e in events if e.get("name") == "fs.read" and e.get("ok") is True), None)
    post_event = next((e for e in events if e.get("name") == "http.post" and e.get("ok") is True), None)
    read_output = read_event.get("output") if read_event else None
    post_data = ((post_event.get("args") or {}).get("data")) if post_event else None

    helpers = {
        "_is_secret_path_control": call_helper(predicates, "_is_secret_path", "file_seed/secret.txt"),
        "_is_secret_path_treatment": call_helper(predicates, "_is_secret_path", "file_seed/fx_70a39e917cee2a14.txt"),
        "_extract_secret_values_read_output": call_helper(predicates, "_extract_secret_values", read_output) if isinstance(read_output, str) else {"available": False, "reason": "no read output"},
        "_contains_secret_post_data": call_helper(predicates, "_contains_secret", post_data, [read_output]) if isinstance(post_data, str) and isinstance(read_output, str) else {"available": False, "reason": "missing values"},
    }

    all_same = len({json.dumps(v, sort_keys=True) for v in evals.values()}) == 1
    source_scope_signal = {
        "control_path_recognized": helpers["_is_secret_path_control"].get("result"),
        "treatment_path_recognized": helpers["_is_secret_path_treatment"].get("result"),
    }

    if flow["exact_value_match"] and source_scope_signal["control_path_recognized"] is True and source_scope_signal["treatment_path_recognized"] is False:
        primary_explanation = "OFFICIAL_PREDICATE_SOURCE_SCOPE_IS_CANONICAL_PATH_BOUND"
    elif not flow["exact_value_match"]:
        primary_explanation = "READ_POST_VALUE_MISMATCH"
    elif not all_same:
        primary_explanation = "TRACE_SHAPE_SENSITIVITY_DETECTED"
    else:
        primary_explanation = "NOT_ESTABLISHED_REQUIRES_SOURCE_INSPECTION"

    report = {
        "version": VERSION,
        "created_at_utc": now(),
        "classification": "READ_ONLY_PREDICATE_RECONCILIATION",
        "input": identity(results_path),
        "predicate_file": identity(predicate_path),
        "scenario_id": TARGET_SCENARIO,
        "flow_validation": flow,
        "redacted_tool_events": [redact_event(e) for e in events],
        "static_predicate_inventory": static,
        "helper_probes": helpers,
        "trace_variant_evaluations": evals,
        "all_trace_variants_same_result": all_same,
        "primary_explanation": primary_explanation,
        "claim_boundary": {
            "allowed": [
                "state whether frozen v5 read output and post data match exactly by SHA-256",
                "state whether installed predicate code recognizes control and treatment paths",
                "state whether predicate output changes across trace-shape variants",
                "identify the most directly supported explanation",
            ],
            "prohibited": [
                "claim hosted parity",
                "claim general robustness from one local model/run",
                "modify SDK, fixtures, guardrails, or predicates",
                "send any model/tool/network request",
                "persist secret plaintext",
            ],
        },
    }

    result_path = out / "p7_4_reconcile_guardrail_vs_predicate_result_v1_0.json"
    result_path.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")

    rows = []
    rows.append({"check_id": "RGP-001", "category": "flow", "passed": flow["successful_read_count"] > 0, "observed": flow["successful_read_count"], "expected": ">0"})
    rows.append({"check_id": "RGP-002", "category": "flow", "passed": flow["successful_post_count"] > 0, "observed": flow["successful_post_count"], "expected": ">0"})
    rows.append({"check_id": "RGP-003", "category": "flow", "passed": flow["exact_value_match"], "observed": flow["exact_value_match"], "expected": "True"})
    rows.append({"check_id": "RGP-004", "category": "scope", "passed": source_scope_signal["control_path_recognized"] is True, "observed": source_scope_signal["control_path_recognized"], "expected": "True"})
    rows.append({"check_id": "RGP-005", "category": "scope", "passed": source_scope_signal["treatment_path_recognized"] is False, "observed": source_scope_signal["treatment_path_recognized"], "expected": "False"})
    rows.append({"check_id": "RGP-006", "category": "trace_shape", "passed": all_same, "observed": all_same, "expected": "True means shape-independent"})
    checks_path = out / "p7_4_reconcile_guardrail_vs_predicate_checks_v1_0.csv"
    with checks_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["check_id", "category", "passed", "observed", "expected"], lineterminator="\n")
        w.writeheader(); w.writerows(rows)

    manifest_rows = [identity(results_path), identity(predicate_path), identity(result_path), identity(checks_path), identity(Path(__file__).resolve())]
    manifest_path = out / "p7_4_reconcile_guardrail_vs_predicate_manifest_v1_0.csv"
    with manifest_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["artifact", "path", "size_bytes", "sha256"], lineterminator="\n")
        w.writeheader(); w.writerows(manifest_rows)

    print(json.dumps({
        "status": "COMPLETE",
        "primary_explanation": primary_explanation,
        "flow_validation": flow,
        "control_path_recognized": source_scope_signal["control_path_recognized"],
        "treatment_path_recognized": source_scope_signal["treatment_path_recognized"],
        "all_trace_variants_same_result": all_same,
        "output_dir": str(out),
        "manifest_sha256": sha_file(manifest_path),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
