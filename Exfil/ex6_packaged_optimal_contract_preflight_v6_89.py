#!/usr/bin/env python3
"""EX6 v6.89: read-only packaged Optimal and hardened-policy contract preflight.

Static source/AST inspection only. The runner does not import the SDK, execute a
model, instantiate Sandbox/Gym, open fixtures, call tools, modify sources, or
write outside a new output directory.
"""
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import platform
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

VERSION = "EX6_PACKAGED_OPTIMAL_AND_HARDENED_POLICY_CONTRACT_PREFLIGHT_v6.89"
EXPECTED_OPTIMAL_SHA256 = "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED"
EXPECTED_PREDICATES_SHA256 = "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"

PRIMARY_FILES = {
    "optimal": "aicomp_sdk/guardrails/optimal.py",
    "predicates": "aicomp_sdk/core/predicates.py",
    "sandbox": "aicomp_sdk/core/env/sandbox.py",
    "api": "aicomp_sdk/core/env/api.py",
    "gym": "aicomp_sdk/core/env/gym.py",
    "base_rules": "aicomp_sdk/attacks/baselines/guardrail_rules.py",
    "cli_test": "aicomp_sdk/cli/commands/test.py",
}

SEARCH_TERMS = [
    "user_authorized", "user_confirmed_safe", "confirmed_safe", "authorization",
    "confirmation", "confirm", "Guardrail", "guardrail", "GuardrailDecision",
    "ToolEvent", "ToolCall", "tool_call", "proposal", "recent_sources", "context",
    "fs.read", "http.post", "secret.txt", "protected", "sensitive", "path",
    "resolve", "canonical", "normalize", "url", "data", "_decode_candidates",
    "_contains_secret", "eval_predicates", "is_breach", "PRE_GUARDRAIL",
    "POST_GUARDRAIL", "hook", "hooks",
]

QUESTION_ORDER = [
    "exact_decision_method_signature",
    "fields_read_from_context",
    "fields_read_from_proposed_tool_call",
    "exact_rule_order",
    "authorization_before_target_normalization",
    "explicit_sensitive_tools_and_targets",
    "inspects_prior_tool_events_or_source_outputs",
    "inspects_http_post_data",
    "performs_decoding_or_calls_official_matcher",
    "exact_object_passed_to_guardrail",
    "arguments_validated_before_guardrail",
    "proposal_arguments_mutable",
    "hooks_can_mutate_context_or_proposal",
    "documented_guardrail_selection_interface",
    "same_interface_supports_packaged_and_hardened",
    "guardrail_instance_reused_across_interactions",
    "additional_authorization_context_fields",
    "confirmation_sets_user_confirmed_safe",
    "confirmation_action_specific",
    "confirmation_target_specific",
    "confirmation_persists_after_execution_or_failure",
    "fs_read_path_normalization",
    "http_post_target_extraction_and_url_handling",
    "official_matcher_reuse_feasibility",
]

@dataclass
class SourceInfo:
    label: str
    relative_path: str
    absolute_path: str
    exists: bool
    size_bytes: int | None
    line_count: int | None
    sha256: str | None
    ast_parse: str


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def source_info(label: str, rel: str, root: Path) -> SourceInfo:
    p = root / rel
    if not p.is_file():
        return SourceInfo(label, rel, str(p), False, None, None, None, "NOT_AVAILABLE")
    text = p.read_text(encoding="utf-8", errors="replace")
    try:
        ast.parse(text)
        ast_status = "OK"
    except SyntaxError as e:
        ast_status = f"ERROR:{e.lineno}:{e.offset}:{e.msg}"
    return SourceInfo(label, rel, str(p), True, p.stat().st_size, len(text.splitlines()), sha256_file(p), ast_status)


def iter_python_files(root: Path) -> Iterable[Path]:
    sdk = root / "aicomp_sdk"
    if not sdk.is_dir():
        return []
    return sorted(p for p in sdk.rglob("*.py") if p.is_file() and "__pycache__" not in p.parts)


def line_matches(path: Path, root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for lineno, line in enumerate(text.splitlines(), 1):
        matched = [term for term in SEARCH_TERMS if term.lower() in line.lower()]
        if matched:
            rows.append({
                "relative_path": path.relative_to(root).as_posix(),
                "line": lineno,
                "terms": "|".join(matched),
                "source_text": line.strip(),
                "source_line_sha256": hashlib.sha256(line.encode("utf-8")).hexdigest().upper(),
            })
    return rows


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Subscript): return dotted_name(node.value)
    if isinstance(node, ast.Call): return dotted_name(node.func)
    return ""


def ast_rows(path: Path, root: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    lines = text.splitlines()
    rows: list[dict[str, Any]] = []
    rel = path.relative_to(root).as_posix()
    for node in ast.walk(tree):
        kind = None; name = ""; detail = ""
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            kind = "FUNCTION"; name = node.name
            args = [a.arg for a in node.args.args]
            detail = f"signature={node.name}({', '.join(args)})"
        elif isinstance(node, ast.ClassDef):
            kind = "CLASS"; name = node.name
            detail = "bases=" + "|".join(filter(None, (dotted_name(b) for b in node.bases)))
        elif isinstance(node, ast.If):
            kind = "IF_CONDITION"; name = "if"
            detail = ast.get_source_segment(text, node.test) or ""
        elif isinstance(node, ast.Call):
            callee = dotted_name(node.func)
            if any(t.lower() in callee.lower() for t in SEARCH_TERMS):
                kind = "CALL"; name = callee; detail = ast.get_source_segment(text, node) or ""
        elif isinstance(node, ast.Attribute):
            full = dotted_name(node)
            if full.startswith("context.") or any(t.lower() in full.lower() for t in ["authorized", "confirm", "proposal", "tool", "guardrail"]):
                kind = "ATTRIBUTE_READ_OR_WRITE"; name = full; detail = full
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            parts = []
            for alias in node.names: parts.append(alias.name)
            if any("guardrail" in p.lower() or "predicate" in p.lower() for p in parts + [getattr(node, "module", "") or ""]):
                kind = "IMPORT"; name = getattr(node, "module", "") or "import"; detail = "|".join(parts)
        if kind:
            start = getattr(node, "lineno", None); end = getattr(node, "end_lineno", start)
            snippet = "\n".join(lines[start-1:end]) if start else ""
            rows.append({
                "relative_path": rel,
                "node_type": kind,
                "name": name,
                "line_start": start,
                "line_end": end,
                "detail": detail[:2000],
                "snippet_sha256": hashlib.sha256(snippet.encode("utf-8")).hexdigest().upper(),
            })
    return rows


def infer_answers(line_rows: list[dict[str, Any]], nodes: list[dict[str, Any]], inventory: dict[str, SourceInfo]) -> list[dict[str, Any]]:
    def evidence(term: str) -> list[str]:
        refs = [f"{r['relative_path']}:{r['line']}" for r in line_rows if term.lower() in r['terms'].lower()]
        return refs[:10]
    def answer(q: str, status: str, basis: str, refs: list[str] | None = None) -> dict[str, Any]:
        return {"question_id": q, "status": status, "answer": basis, "evidence_refs": "|".join(refs or []), "runtime_required": status in {"NOT_ESTABLISHED", "PARTIAL"}}

    optimal_nodes = [r for r in nodes if r["relative_path"] == PRIMARY_FILES["optimal"]]
    funcs = [r for r in optimal_nodes if r["node_type"] == "FUNCTION"]
    signatures = [r["detail"] for r in funcs]
    context_attrs = sorted({r["name"] for r in optimal_nodes if r["node_type"] == "ATTRIBUTE_READ_OR_WRITE" and r["name"].startswith("context.")})
    optimal_lines = [r for r in line_rows if r["relative_path"] == PRIMARY_FILES["optimal"]]
    optimal_text = "\n".join(r["source_text"] for r in optimal_lines)

    rows = []
    rows.append(answer("exact_decision_method_signature", "ESTABLISHED" if signatures else "NOT_ESTABLISHED", "; ".join(signatures) if signatures else "No function signature extracted from optimal.py", [f"{r['relative_path']}:{r['line_start']}" for r in funcs]))
    rows.append(answer("fields_read_from_context", "ESTABLISHED" if context_attrs else "NOT_ESTABLISHED", "|".join(context_attrs) if context_attrs else "No context attribute reads extracted", [f"{r['relative_path']}:{r['line_start']}" for r in optimal_nodes if r["name"] in context_attrs]))
    rows.append(answer("fields_read_from_proposed_tool_call", "PARTIAL", "AST and line evidence captured; manual review required to classify proposal fields", evidence("proposal") + evidence("tool_call")))
    rows.append(answer("exact_rule_order", "PARTIAL", "Ordered line-bound conditions captured; reviewer must freeze semantic rule ordering", [f"{r['relative_path']}:{r['line_start']}" for r in optimal_nodes if r["node_type"] == "IF_CONDITION"]))
    rows.append(answer("authorization_before_target_normalization", "PARTIAL", "Authorization and target/path evidence are captured, but semantic precedence requires manual line review", evidence("user_authorized") + evidence("path")))
    rows.append(answer("explicit_sensitive_tools_and_targets", "PARTIAL", "Sensitive/protected/tool literal evidence captured", evidence("sensitive") + evidence("protected") + evidence("fs.read") + evidence("http.post")))
    rows.append(answer("inspects_prior_tool_events_or_source_outputs", "PARTIAL", "ToolEvent/recent_sources evidence captured; direct use must be manually confirmed", evidence("ToolEvent") + evidence("recent_sources")))
    rows.append(answer("inspects_http_post_data", "ESTABLISHED" if "http.post" in optimal_text and "data" in optimal_text else "NOT_ESTABLISHED", "optimal.py contains line evidence for both http.post and data" if "http.post" in optimal_text and "data" in optimal_text else "No co-occurring line-evidence basis established", evidence("http.post") + evidence("data")))
    matcher_refs = evidence("_contains_secret") + evidence("_decode_candidates") + evidence("eval_predicates")
    rows.append(answer("performs_decoding_or_calls_official_matcher", "ESTABLISHED" if any(r["relative_path"] == PRIMARY_FILES["optimal"] for r in line_rows if any(t in r["terms"] for t in ["_contains_secret", "_decode_candidates", "eval_predicates"])) else "NOT_ESTABLISHED", "Direct matcher/decoder reference in optimal.py" if matcher_refs else "No direct optimal.py matcher/decoder reference located", matcher_refs))
    rows.append(answer("exact_object_passed_to_guardrail", "PARTIAL", "Sandbox guardrail call sites and signatures captured", evidence("guardrail")))
    rows.append(answer("arguments_validated_before_guardrail", "PARTIAL", "Validation and guardrail line evidence captured; exact precedence requires manual review", evidence("validation") + evidence("guardrail")))
    rows.append(answer("proposal_arguments_mutable", "NOT_ESTABLISHED", "Static inspection captures assignments and hooks but does not prove runtime immutability", evidence("proposal") + evidence("hook")))
    rows.append(answer("hooks_can_mutate_context_or_proposal", "PARTIAL", "Hook call/assignment evidence captured; mutation semantics require manual review", evidence("hook") + evidence("context")))
    rows.append(answer("documented_guardrail_selection_interface", "PARTIAL", "Constructor/configuration call sites captured in Sandbox, API, Gym, and CLI", evidence("Guardrail") + evidence("guardrail")))
    rows.append(answer("same_interface_supports_packaged_and_hardened", "NOT_ESTABLISHED", "Hardened class does not exist; interface compatibility cannot yet be claimed"))
    rows.append(answer("guardrail_instance_reused_across_interactions", "PARTIAL", "Construction and assignment evidence captured; lifetime requires manual review or later runtime control", evidence("guardrail")))
    auth_fields = sorted({a for a in context_attrs if "author" in a.lower() or "confirm" in a.lower() or "safe" in a.lower()})
    rows.append(answer("additional_authorization_context_fields", "ESTABLISHED" if auth_fields else "NOT_ESTABLISHED", "|".join(auth_fields) if auth_fields else "No authorization-like context attributes extracted from optimal.py"))
    rows.append(answer("confirmation_sets_user_confirmed_safe", "PARTIAL", "Exact-name set/read evidence captured across SDK; manual setter classification required", evidence("user_confirmed_safe") + evidence("confirmation")))
    rows.append(answer("confirmation_action_specific", "NOT_ESTABLISHED", "No action-binding claim made from static keyword evidence"))
    rows.append(answer("confirmation_target_specific", "NOT_ESTABLISHED", "No target-binding claim made from static keyword evidence"))
    rows.append(answer("confirmation_persists_after_execution_or_failure", "NOT_ESTABLISHED", "Static construction/lifetime evidence is insufficient without explicit reset or persistence contract"))
    rows.append(answer("fs_read_path_normalization", "PARTIAL", "fs.read/path/resolve/canonical/normalize evidence captured for manual contract review", evidence("fs.read") + evidence("resolve") + evidence("canonical") + evidence("normalize")))
    rows.append(answer("http_post_target_extraction_and_url_handling", "PARTIAL", "http.post/url/data evidence captured for manual contract review", evidence("http.post") + evidence("url") + evidence("data")))
    predicate_exists = inventory["predicates"].exists
    rows.append(answer("official_matcher_reuse_feasibility", "PARTIAL" if predicate_exists else "NOT_ESTABLISHED", "Matcher helper definitions/import visibility captured; reuse requires public-interface and coupling review", matcher_refs))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=VERSION)
    ap.add_argument("--project-root", required=True)
    ap.add_argument("--parent-manifest", required=False, help="Optional v6.88C manifest to bind")
    ap.add_argument("--parent-binding", required=False, help="Optional v6.88C external binding to bind")
    ap.add_argument("--out-root", required=True)
    args = ap.parse_args()

    root = Path(args.project_root)
    out = Path(args.out_root)
    if not root.is_dir(): raise FileNotFoundError(f"Project root not found: {root}")
    if out.exists(): raise FileExistsError(f"Refusing to overwrite existing output directory: {out}")

    inventory = {label: source_info(label, rel, root) for label, rel in PRIMARY_FILES.items()}
    if not inventory["optimal"].exists: raise FileNotFoundError(inventory["optimal"].absolute_path)
    if inventory["optimal"].sha256 != EXPECTED_OPTIMAL_SHA256:
        raise ValueError(f"optimal.py SHA-256 mismatch: {inventory['optimal'].sha256}")
    if not inventory["predicates"].exists or inventory["predicates"].sha256 != EXPECTED_PREDICATES_SHA256:
        raise ValueError(f"predicates.py SHA-256 mismatch: {inventory['predicates'].sha256}")

    py_files = list(iter_python_files(root))
    line_rows: list[dict[str, Any]] = []
    node_rows: list[dict[str, Any]] = []
    for p in py_files:
        line_rows.extend(line_matches(p, root))
        node_rows.extend(ast_rows(p, root))

    answers = infer_answers(line_rows, node_rows, inventory)
    out.mkdir(parents=True, exist_ok=False)
    created = datetime.now(timezone.utc).isoformat()

    inventory_csv = out / "ex6_v6_89_source_inventory.csv"
    line_csv = out / "ex6_v6_89_line_bound_evidence.csv"
    ast_csv = out / "ex6_v6_89_ast_bound_evidence.csv"
    interface_csv = out / "ex6_v6_89_guardrail_interface_matrix.csv"
    context_csv = out / "ex6_v6_89_context_field_matrix.csv"
    target_csv = out / "ex6_v6_89_target_normalization_matrix.csv"
    auth_csv = out / "ex6_v6_89_authorization_consumer_transport_matrix.csv"
    matcher_csv = out / "ex6_v6_89_matcher_reuse_feasibility.csv"
    questions_csv = out / "ex6_v6_89_answered_vs_missing_preflight.csv"
    result_json = out / "ex6_v6_89_preflight_result.json"
    binding_json = out / "ex6_v6_89_binding.json"
    manifest_csv = out / "ex6_v6_89_manifest.csv"
    external_json = out / "ex6_v6_89_manifest_external_binding.json"

    inv_rows = [asdict(v) for v in inventory.values()]
    write_csv(inventory_csv, inv_rows, list(inv_rows[0].keys()))
    write_csv(line_csv, line_rows, ["relative_path", "line", "terms", "source_text", "source_line_sha256"])
    write_csv(ast_csv, node_rows, ["relative_path", "node_type", "name", "line_start", "line_end", "detail", "snippet_sha256"])

    interface_terms = ["Guardrail", "guardrail", "decision", "proposal", "tool_call", "hook"]
    context_terms = ["context", "recent_sources", "user_authorized", "user_confirmed_safe", "confirmation"]
    target_terms = ["fs.read", "http.post", "path", "resolve", "canonical", "normalize", "url", "data"]
    auth_terms = ["user_authorized", "user_confirmed_safe", "authorization", "confirmation", "confirm"]
    matcher_terms = ["_decode_candidates", "_contains_secret", "eval_predicates", "is_breach"]
    def subset(terms: list[str]) -> list[dict[str, Any]]:
        return [r for r in line_rows if any(t.lower() in r["terms"].lower() for t in terms)]
    common_fields = ["relative_path", "line", "terms", "source_text", "source_line_sha256"]
    write_csv(interface_csv, subset(interface_terms), common_fields)
    write_csv(context_csv, subset(context_terms), common_fields)
    write_csv(target_csv, subset(target_terms), common_fields)
    write_csv(auth_csv, subset(auth_terms), common_fields)
    write_csv(matcher_csv, subset(matcher_terms), common_fields)
    write_csv(questions_csv, answers, ["question_id", "status", "answer", "evidence_refs", "runtime_required"])

    counts = {status: sum(1 for r in answers if r["status"] == status) for status in ["ESTABLISHED", "PARTIAL", "NOT_ESTABLISHED"]}
    result = {
        "version": VERSION,
        "created_at_utc": created,
        "status": "PREFLIGHT_COMPLETE_REVIEW_REQUIRED",
        "classification": "PACKAGED_OPTIMAL_CONTRACT_STATIC_EVIDENCE_CAPTURED_HARDENED_IMPLEMENTATION_WITHHELD",
        "execution_type": "READ_ONLY_SOURCE_AND_AST_INSPECTION",
        "runtime": False,
        "model_called": False,
        "sdk_imported": False,
        "source_modified": False,
        "protected_fixture_opened": False,
        "python_files_scanned": len(py_files),
        "line_evidence_rows": len(line_rows),
        "ast_evidence_rows": len(node_rows),
        "question_status_counts": counts,
        "optimal_sha256": inventory["optimal"].sha256,
        "predicates_sha256": inventory["predicates"].sha256,
        "hardened_policy_implementation": "WITHHELD",
        "runtime_comparison": "WITHHELD",
        "harness_trick": "NOT_DEMONSTRATED",
        "security_finding": "NOT_ESTABLISHED_STATIC_CONTRACT_PREFLIGHT_ONLY",
        "claim_boundary": "STATIC_SOURCE_AND_AST_EVIDENCE_REQUIRES_REVIEW_BEFORE_BEHAVIORAL_OR_POLICY_EFFECTIVENESS_CLAIMS",
    }
    write_json(result_json, result)

    parent_entries = []
    for label, value in [("parent_manifest", args.parent_manifest), ("parent_binding", args.parent_binding)]:
        if value:
            p = Path(value)
            if not p.is_file(): raise FileNotFoundError(f"{label} not found: {p}")
            parent_entries.append({"label": label, "path": str(p), "size_bytes": p.stat().st_size, "sha256": sha256_file(p)})
    binding = {
        "version": VERSION,
        "created_at_utc": created,
        "project_root": str(root),
        "parent_entries": parent_entries,
        "expected_optimal_sha256": EXPECTED_OPTIMAL_SHA256,
        "expected_predicates_sha256": EXPECTED_PREDICATES_SHA256,
        "paths_inferred": False,
        "sdk_imported": False,
        "runtime_executed": False,
        "source_modified": False,
        "python": sys.version,
        "platform": platform.platform(),
    }
    write_json(binding_json, binding)

    targets = [inventory_csv, line_csv, ast_csv, interface_csv, context_csv, target_csv, auth_csv, matcher_csv, questions_csv, result_json, binding_json]
    manifest_rows = [{"artifact": p.name, "role": "DERIVED_PREFLIGHT", "size_bytes": p.stat().st_size, "sha256": sha256_file(p), "source_path": str(p)} for p in targets]
    for e in parent_entries:
        manifest_rows.append({"artifact": Path(e["path"]).name, "role": "SOURCE_OR_PARENT", "size_bytes": e["size_bytes"], "sha256": e["sha256"], "source_path": e["path"]})
    for info in inventory.values():
        if info.exists:
            manifest_rows.append({"artifact": Path(info.absolute_path).name, "role": "SOURCE_SDK", "size_bytes": info.size_bytes, "sha256": info.sha256, "source_path": info.absolute_path})
    write_csv(manifest_csv, manifest_rows, ["artifact", "role", "size_bytes", "sha256", "source_path"])
    external = {
        "version": VERSION,
        "created_at_utc": created,
        "manifest_filename": manifest_csv.name,
        "manifest_size_bytes": manifest_csv.stat().st_size,
        "manifest_sha256": sha256_file(manifest_csv),
        "status": result["status"],
        "classification": result["classification"],
        "optimal_sha256": inventory["optimal"].sha256,
        "predicates_sha256": inventory["predicates"].sha256,
    }
    write_json(external_json, external)
    print(json.dumps({"status": result["status"], "classification": result["classification"], "manifest_sha256": external["manifest_sha256"], "output_directory": str(out)}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
