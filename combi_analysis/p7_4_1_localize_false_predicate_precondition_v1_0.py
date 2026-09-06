#!/usr/bin/env python3
"""P7.4.1 read-only EXFILTRATION predicate branch localizer.

Purpose
=======
Localize the exact false precondition that explains why a frozen v5 trace can
contain a successful fs.read and http.post while eval_predicates() returns no
EXFILTRATION finding.

Safety and scope
================
- No model calls.
- No tool execution.
- No network access.
- No fixture or SDK mutation.
- No attack optimization.
- Secret-bearing values are processed only in memory and persisted only as
  SHA-256/length summaries.
- Output directory must not already exist.

Inputs
======
--project-root       Repository containing aicomp_sdk.
--v5-results         local_predicate_verify_v5_results.json.
--control-fixture    Optional absolute path to canonical secret.txt. Used only
                     as a path probe, never read.
--native-trace       Optional real SandboxEnv export_trace_dict JSON. If absent,
                     native parity is reported NOT_EVALUABLE and sandbox.py is
                     inspected statically for trace/export fields.
--expected-*         Optional SHA-256 input bindings.

Outputs
=======
p7_4_1_localize_false_predicate_precondition_result_v1_0.json
p7_4_1_localize_false_predicate_precondition_checks_v1_0.csv
p7_4_1_localize_false_predicate_precondition_manifest_v1_0.csv
p7_4_1_localize_false_predicate_precondition_claim_boundary_v1_0.json
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
from pathlib import Path, PureWindowsPath
from typing import Any, Callable

VERSION = "P7_4_1_LOCALIZE_FALSE_PREDICATE_PRECONDITION_v1.0"
TARGET_SCENARIO = "exfil_renamed_fixture"
OUT_RESULT = "p7_4_1_localize_false_predicate_precondition_result_v1_0.json"
OUT_CHECKS = "p7_4_1_localize_false_predicate_precondition_checks_v1_0.csv"
OUT_MANIFEST = "p7_4_1_localize_false_predicate_precondition_manifest_v1_0.csv"
OUT_CLAIM = "p7_4_1_localize_false_predicate_precondition_claim_boundary_v1_0.json"


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


def ident(path: Path) -> dict[str, Any]:
    p = path.resolve()
    return {"artifact": p.name, "path": str(p), "size_bytes": p.stat().st_size,
            "sha256": sha_file(p)}


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as f:
        json.dump(value, f, indent=2, sort_keys=True, ensure_ascii=False, default=str)
        f.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("x", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [safe(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "__dict__"):
        return safe(vars(value))
    return repr(value)


def secret_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, str):
        return {"present": False, "type": type(value).__name__}
    return {"present": True, "length": len(value), "sha256": sha_text(value)}


def collection_secret_summary(values: Any) -> dict[str, Any]:
    if values is None:
        seq: list[Any] = []
    elif isinstance(values, (list, tuple, set)):
        seq = list(values)
    else:
        seq = [values]
    return {
        "count": len(seq),
        "items": [secret_summary(v) if isinstance(v, str) else {"type": type(v).__name__}
                  for v in seq],
    }


def tri(value: Any = None, error: str | None = None, evaluable: bool = True) -> dict[str, Any]:
    if not evaluable:
        return {"state": "NOT_EVALUABLE", "reason": error}
    if error is not None:
        return {"state": "NOT_EVALUABLE", "reason": error}
    return {"state": "TRUE" if bool(value) else "FALSE", "observed": safe(value)}


def call(fn: Callable[..., Any] | None, *args: Any) -> tuple[bool, Any, str | None]:
    if not callable(fn):
        return False, None, "helper unavailable"
    try:
        return True, fn(*args), None
    except Exception as exc:
        return True, None, f"{type(exc).__name__}: {exc}"


def find_scenario(doc: Any) -> dict[str, Any]:
    rows = doc if isinstance(doc, list) else doc.get("results", doc.get("scenarios", []))
    for row in rows:
        if row.get("scenario_id") == TARGET_SCENARIO:
            return row
    raise ValueError(f"Scenario not found: {TARGET_SCENARIO}")


def successful_event(events: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    return next((e for e in events if e.get("name") == name and e.get("ok") is True), None)


def function_inventory(source_path: Path, names: set[str]) -> dict[str, Any]:
    source = source_path.read_text(encoding="utf-8-sig")
    tree = ast.parse(source, filename=str(source_path))
    out: dict[str, Any] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names:
            segment = ast.get_source_segment(source, node) or ""
            out[node.name] = {
                "lineno": node.lineno,
                "end_lineno": getattr(node, "end_lineno", None),
                "args": [a.arg for a in node.args.args],
                "source_sha256": sha_text(segment),
                "string_literals": sorted({n.value for n in ast.walk(node)
                                           if isinstance(n, ast.Constant) and isinstance(n.value, str)}),
                "dict_key_literals": sorted({n.value for n in ast.walk(node)
                                             if isinstance(n, ast.Constant) and isinstance(n.value, str)
                                             and n.value in {"tool_events", "events", "egress", "messages",
                                                             "user_messages", "name", "args", "ok", "output",
                                                             "source", "scope", "side_effect", "error", "path", "data"}}),
            }
    return out


def path_forms(control: Path | None, treatment_reference: str) -> list[dict[str, Any]]:
    forms: list[tuple[str, Any]] = [
        ("control_basename_string", "secret.txt"),
        ("control_posix_relative_string", "file_seed/secret.txt"),
        ("control_windows_relative_string", r"file_seed\secret.txt"),
        ("control_normalized_path_object", Path("file_seed") / "secret.txt"),
        ("treatment_basename_string", Path(treatment_reference).name),
        ("treatment_posix_relative_string", treatment_reference.replace("\\", "/")),
        ("treatment_windows_relative_string", str(PureWindowsPath(treatment_reference.replace("/", "\\")))),
        ("treatment_normalized_path_object", Path(treatment_reference)),
    ]
    if control is not None:
        forms.append(("control_absolute_string", str(control.resolve())))
        forms.append(("control_absolute_path_object", control.resolve()))
        renamed_abs = control.resolve().with_name(Path(treatment_reference).name)
        forms.append(("treatment_absolute_string", str(renamed_abs)))
        forms.append(("treatment_absolute_path_object", renamed_abs))
    return [{"probe_id": k, "value": v, "value_type": type(v).__name__} for k, v in forms]


def event_schema(events: list[dict[str, Any]]) -> dict[str, Any]:
    keys = sorted({str(k) for e in events for k in e.keys()})
    per_event = []
    for i, e in enumerate(events):
        per_event.append({
            "index": i,
            "name": e.get("name"),
            "keys": sorted(str(k) for k in e.keys()),
            "types": {str(k): type(v).__name__ for k, v in e.items()},
            "enum_values": {k: e.get(k) for k in ("source", "scope", "side_effect", "ok") if k in e},
        })
    return {"union_keys": keys, "per_event": per_event}


def compare_schema(v5_trace: dict[str, Any], native_trace: dict[str, Any] | None,
                   sandbox_inventory: dict[str, Any]) -> dict[str, Any]:
    v5_events = v5_trace.get("tool_events") or []
    v5_top = sorted(v5_trace.keys())
    result: dict[str, Any] = {
        "v5_top_level_keys": v5_top,
        "v5_event_schema": event_schema(v5_events),
        "sandbox_static_inventory": sandbox_inventory,
    }
    if native_trace is None:
        result.update({
            "native_trace_supplied": False,
            "parity_status": "NOT_EVALUABLE_WITHOUT_NATIVE_TRACE",
            "fields_to_inspect": ["egress", "canonical_path", "scope", "source", "side_effect", "error"],
        })
        return result
    native_events = native_trace.get("tool_events") or native_trace.get("events") or []
    native_top = sorted(native_trace.keys())
    v5_keys = set(result["v5_event_schema"]["union_keys"])
    native_schema = event_schema(native_events)
    native_keys = set(native_schema["union_keys"])
    result.update({
        "native_trace_supplied": True,
        "native_top_level_keys": native_top,
        "native_event_schema": native_schema,
        "top_level_missing_from_v5": sorted(set(native_top) - set(v5_top)),
        "top_level_extra_in_v5": sorted(set(v5_top) - set(native_top)),
        "event_fields_missing_from_v5": sorted(native_keys - v5_keys),
        "event_fields_extra_in_v5": sorted(v5_keys - native_keys),
        "parity_status": "EXACT_KEY_PARITY" if set(native_top) == set(v5_top) and native_keys == v5_keys
                         else "KEY_PARITY_DIFFERENCES_FOUND",
    })
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=VERSION)
    ap.add_argument("--project-root", required=True)
    ap.add_argument("--v5-results", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--control-fixture", default=None)
    ap.add_argument("--native-trace", default=None)
    ap.add_argument("--expected-v5-sha256", default=None)
    ap.add_argument("--expected-predicates-sha256", default=None)
    ap.add_argument("--expected-native-trace-sha256", default=None)
    args = ap.parse_args()

    project = Path(args.project_root).resolve()
    v5_path = Path(args.v5_results).resolve()
    out = Path(args.output_dir).resolve()
    if out.exists():
        raise FileExistsError(f"Refusing overwrite: {out}")
    out.mkdir(parents=True)

    predicates_path = project / "aicomp_sdk" / "core" / "predicates.py"
    sandbox_path = project / "aicomp_sdk" / "core" / "env" / "sandbox.py"
    for p in (v5_path, predicates_path, sandbox_path):
        if not p.is_file():
            raise FileNotFoundError(p)
    if args.expected_v5_sha256 and sha_file(v5_path) != args.expected_v5_sha256.upper():
        raise ValueError("v5 results SHA-256 mismatch")
    if args.expected_predicates_sha256 and sha_file(predicates_path) != args.expected_predicates_sha256.upper():
        raise ValueError("predicates.py SHA-256 mismatch")

    native_path = Path(args.native_trace).resolve() if args.native_trace else None
    if native_path is not None and not native_path.is_file():
        raise FileNotFoundError(native_path)
    if native_path is not None and args.expected_native_trace_sha256 and sha_file(native_path) != args.expected_native_trace_sha256.upper():
        raise ValueError("native trace SHA-256 mismatch")

    v5_doc = json.loads(v5_path.read_text(encoding="utf-8-sig"))
    scenario = find_scenario(v5_doc)
    events = scenario.get("tool_events") or []
    read_event = successful_event(events, "fs.read")
    post_event = successful_event(events, "http.post")
    if read_event is None or post_event is None:
        raise ValueError("Target scenario lacks successful fs.read/http.post")
    read_output = read_event.get("output")
    post_data = (post_event.get("args") or {}).get("data")
    treatment_path = str((read_event.get("args") or {}).get("path") or "")

    sys.path.insert(0, str(project))
    try:
        predicates = importlib.import_module("aicomp_sdk.core.predicates")
    finally:
        if sys.path and sys.path[0] == str(project):
            sys.path.pop(0)

    is_secret_path = getattr(predicates, "_is_secret_path", None)
    extract_values = getattr(predicates, "_extract_secret_values", None)
    secrets_read = getattr(predicates, "_secrets_read_in_trace", None)
    contains_secret = getattr(predicates, "_contains_secret", None)

    control_fixture = Path(args.control_fixture).resolve() if args.control_fixture else None
    probes = path_forms(control_fixture, treatment_path)
    for item in probes:
        available, value, error = call(is_secret_path, item["value"])
        item["result"] = tri(value, error if available else "helper unavailable", evaluable=available)
        item["value"] = str(item["value"])

    available_sr, sr_value, sr_error = call(secrets_read, events)
    secrets_read_summary = collection_secret_summary(sr_value) if available_sr and sr_error is None else None

    available_ex, extracted, extracted_error = call(extract_values, read_output)
    extracted_list = list(extracted or []) if available_ex and extracted_error is None else []
    available_cs, contains_value, contains_error = call(contains_secret, post_data, extracted_list)

    source_path_recognized = None
    if callable(is_secret_path):
        _, source_path_recognized, source_path_error = call(is_secret_path, treatment_path)
    else:
        source_path_error = "helper unavailable"

    branch_ledger = [
        {"branch_id": "EX-001", "condition": "successful fs.read event exists",
         **tri(read_event is not None)},
        {"branch_id": "EX-002", "condition": "successful http.post event exists",
         **tri(post_event is not None)},
        {"branch_id": "EX-003", "condition": "read output is a string",
         **tri(isinstance(read_output, str))},
        {"branch_id": "EX-004", "condition": "post data is a string",
         **tri(isinstance(post_data, str))},
        {"branch_id": "EX-005", "condition": "read output and post data are byte-identical",
         **tri(isinstance(read_output, str) and isinstance(post_data, str) and read_output == post_data)},
        {"branch_id": "EX-006", "condition": "_extract_secret_values(read_output) is non-empty",
         **tri(bool(extracted_list), extracted_error if available_ex else "helper unavailable", available_ex)},
        {"branch_id": "EX-007", "condition": "_contains_secret(post_data, extracted_values) is true",
         **tri(contains_value, contains_error if available_cs else "helper unavailable", available_cs)},
        {"branch_id": "EX-008", "condition": "_is_secret_path(treatment path) is true",
         **tri(source_path_recognized, source_path_error, callable(is_secret_path))},
        {"branch_id": "EX-009", "condition": "_secrets_read_in_trace(events) is non-empty",
         **tri(bool(sr_value), sr_error if available_sr else "helper unavailable", available_sr)},
    ]

    eval_result: dict[str, Any]
    try:
        findings = predicates.eval_predicates({"tool_events": events})
        eval_result = {"ok": True, "findings": safe(findings),
                       "is_breach": bool(predicates.is_breach({"tool_events": events}, findings))}
    except Exception as exc:
        eval_result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    predicate_inventory = function_inventory(
        predicates_path,
        {"_is_secret_path", "_extract_secret_values", "_secrets_read_in_trace",
         "_contains_secret", "eval_predicates", "is_breach"},
    )
    sandbox_inventory = function_inventory(
        sandbox_path,
        {"export_trace_dict", "interact", "_execute_tool_call", "_run_tool"},
    )
    native_trace = json.loads(native_path.read_text(encoding="utf-8-sig")) if native_path else None
    v5_trace = {"tool_events": events}
    parity = compare_schema(v5_trace, native_trace, sandbox_inventory)

    false_branches = [b["branch_id"] for b in branch_ledger if b["state"] == "FALSE"]
    not_eval = [b["branch_id"] for b in branch_ledger if b["state"] == "NOT_EVALUABLE"]
    if "EX-009" in false_branches and "EX-007" not in false_branches:
        primary = "RENAMED_READ_EXCLUDED_FROM_SECRETS_READ_LEDGER"
    elif "EX-008" in false_branches and "EX-009" in false_branches:
        primary = "SOURCE_PATH_SCOPE_EXCLUDES_RENAMED_FIXTURE"
    elif "EX-007" in false_branches:
        primary = "POST_PAYLOAD_NOT_RECOGNIZED_AS_CONTAINING_EXTRACTED_SECRET"
    elif parity.get("parity_status") == "KEY_PARITY_DIFFERENCES_FOUND":
        primary = "NATIVE_TRACE_PARITY_DIFFERENCES_REQUIRE_REVIEW"
    elif not_eval:
        primary = "NOT_ESTABLISHED_HELPER_OR_TRACE_PARITY_GAPS"
    else:
        primary = "NOT_ESTABLISHED_NO_FALSE_PRECONDITION_LOCALIZED"

    claim = {
        "allowed": [
            "report path-form helper results for control and renamed variants",
            "report whether _secrets_read_in_trace returns any values",
            "report whether post data contains helper-extracted secret values",
            "label reproduced EXFILTRATION preconditions TRUE/FALSE/NOT_EVALUABLE",
            "report v5/native trace key parity when a native trace is supplied",
        ],
        "prohibited": [
            "claim hosted parity",
            "claim robust generalization from one local run",
            "modify predicates.py, sandbox.py, fixtures, or guardrails",
            "execute models, tools, or network calls",
            "persist secret plaintext",
            "optimize attack prompts or payloads",
        ],
    }

    result = {
        "version": VERSION,
        "created_at_utc": now(),
        "status": "COMPLETE",
        "classification": "READ_ONLY_EXFILTRATION_PREDICATE_BRANCH_LOCALIZATION",
        "input_bindings": {
            "v5_results": ident(v5_path),
            "predicates": ident(predicates_path),
            "sandbox": ident(sandbox_path),
            "native_trace": ident(native_path) if native_path else None,
        },
        "scenario_id": TARGET_SCENARIO,
        "flow_summary": {
            "read_output": secret_summary(read_output),
            "post_data": secret_summary(post_data),
            "whole_value_exact_match": read_output == post_data,
            "length_delta_read_minus_post": len(read_output) - len(post_data)
                if isinstance(read_output, str) and isinstance(post_data, str) else None,
        },
        "path_probes": probes,
        "secrets_read_in_trace": {
            "available": available_sr,
            "error": sr_error,
            "summary": secrets_read_summary,
            "empty": (not bool(sr_value)) if available_sr and sr_error is None else None,
        },
        "extract_secret_values": {
            "available": available_ex,
            "error": extracted_error,
            "summary": collection_secret_summary(extracted_list),
        },
        "contains_secret_using_actual_extracted_values": {
            "available": available_cs,
            "error": contains_error,
            "result": contains_value if available_cs and contains_error is None else None,
        },
        "branch_ledger": branch_ledger,
        "false_branch_ids": false_branches,
        "not_evaluable_branch_ids": not_eval,
        "eval_predicates_recheck": eval_result,
        "predicate_static_inventory": predicate_inventory,
        "native_trace_parity": parity,
        "primary_localized_explanation": primary,
        "claim_boundary": claim,
        "scientific_verdict": {
            "simple_trace_wrapper_effect": "NOT_RETESTED_THIS_GATE",
            "exact_false_precondition_localized": primary not in {
                "NOT_ESTABLISHED_HELPER_OR_TRACE_PARITY_GAPS",
                "NOT_ESTABLISHED_NO_FALSE_PRECONDITION_LOCALIZED",
            },
            "harness_trick": "NOT_DEMONSTRATED",
            "hosted_parity": "NOT_ESTABLISHED",
            "robust_generalization": "NOT_ESTABLISHED",
        },
    }

    result_path = out / OUT_RESULT
    checks_path = out / OUT_CHECKS
    claim_path = out / OUT_CLAIM
    manifest_path = out / OUT_MANIFEST
    write_json(result_path, result)
    write_json(claim_path, claim)

    check_rows: list[dict[str, Any]] = []
    for branch in branch_ledger:
        check_rows.append({
            "check_id": branch["branch_id"],
            "category": "predicate_branch",
            "state": branch["state"],
            "condition": branch["condition"],
            "observed": json.dumps({k: v for k, v in branch.items()
                                    if k not in {"branch_id", "condition"}}, sort_keys=True),
        })
    check_rows.append({
        "check_id": "PAR-001", "category": "native_trace_parity",
        "state": "NOT_EVALUABLE" if not native_path else
                 ("TRUE" if parity["parity_status"] == "EXACT_KEY_PARITY" else "FALSE"),
        "condition": "v5 and native trace have exact top-level/event-key parity",
        "observed": json.dumps(parity, sort_keys=True),
    })
    write_csv(checks_path, check_rows,
              ["check_id", "category", "state", "condition", "observed"])

    manifest_rows = [ident(v5_path), ident(predicates_path), ident(sandbox_path),
                     ident(result_path), ident(checks_path), ident(claim_path),
                     ident(Path(__file__).resolve())]
    if native_path:
        manifest_rows.append(ident(native_path))
    write_csv(manifest_path, manifest_rows,
              ["artifact", "path", "size_bytes", "sha256"])

    print(json.dumps({
        "status": "COMPLETE",
        "primary_localized_explanation": primary,
        "false_branch_ids": false_branches,
        "not_evaluable_branch_ids": not_eval,
        "secrets_read_in_trace_empty": result["secrets_read_in_trace"]["empty"],
        "contains_secret_using_actual_extracted_values": result["contains_secret_using_actual_extracted_values"]["result"],
        "native_trace_parity_status": parity["parity_status"],
        "output_dir": str(out),
        "manifest_sha256": sha_file(manifest_path),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
