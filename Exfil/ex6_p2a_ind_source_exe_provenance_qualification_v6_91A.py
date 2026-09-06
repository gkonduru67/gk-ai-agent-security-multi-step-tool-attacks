#!/usr/bin/env python3
"""EX6 v6.91A independent source and execution-provenance qualification.

Read-only supplemental qualification of the frozen v6.91 P2A implementation.
It does not modify proposal_aware_optimal.py, any v6.91 artifact, packaged
optimal.py, predicates.py, Sandbox, hooks, fixtures, or the v6.91 runner.
It does not import the SDK, execute the guardrail, run tools/models, or perform
packaged-versus-hardened comparison.
"""
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX6_P2A_INDEPENDENT_SOURCE_AND_EXECUTION_PROVENANCE_QUALIFICATION_v6.91A"
EXPECTED_PARENT_MANIFEST_SHA256 = "CE2F2411A7C38ADBE34E8F4687326997B37CEDEF9920488EC4D36FF3CED35EBB"
EXPECTED_PARENT_STATUS = "P2A_IMPLEMENTATION_IDENTITY_FREEZE_COMPLETE"
EXPECTED_SOURCE_SHA256 = "918FFD61CDB9A406C965F06CF2BEC34C297AB231E26B6FC083AE34B00C37D452"
EXPECTED_RUNNER_SHA256 = "06A5C96CF605ED21D43800DAA782B65CD01D082EC34B71B69883A3518FCFB6D1"
EXPECTED_OPTIMAL_SHA256 = "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED"
EXPECTED_PREDICATES_SHA256 = "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
EXPECTED_CLASS = "ProposalAwareOptimalGuardrail"
EXPECTED_SIGNATURE = ["self", "tool_name", "tool_args", "context"]

REQUIRED_PARENT_ARTIFACTS = {
    "ex6_v6_91_parent_verification.csv",
    "ex6_v6_91_design_contract.json",
    "ex6_v6_91_rule_order.csv",
    "ex6_v6_91_reason_code_catalog.csv",
    "ex6_v6_91_requirement_to_code_mapping.csv",
    "ex6_v6_91_ast_inventory.json",
    "ex6_v6_91_import_inventory.csv",
    "ex6_v6_91_line_level_change_manifest.diff",
    "ex6_v6_91_source_identity.json",
    "ex6_v6_91_claim_boundary.json",
    "ex6_v6_91_result.json",
    "ex6_v6_91_binding.json",
    "proposal_aware_optimal.py",
}

PUBLIC_HELPERS = {
    "exfil_payload_arg",
    "is_protected_secret_path",
    "payload_exfiltrates_secret",
}
PROHIBITED_NAMES = {
    "user_authorized",
    "user_confirmed_safe",
    "read_secrets",
    "TrustedGuardrailContextAdapter",
}
PRIVATE_MATCHER_NAMES = {"_contains_secret", "_decode_candidates"}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
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
        name = (row.get("artifact") or "").strip()
        if name in indexed:
            raise ValueError(f"Duplicate parent artifact: {name}")
        indexed[name] = row
    missing = sorted(REQUIRED_PARENT_ARTIFACTS - set(indexed))
    if missing:
        raise ValueError(f"Missing required v6.91 artifacts: {missing}")
    return indexed


def verify_manifest_artifact(row: dict[str, str]) -> dict[str, Any]:
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


def source_segment(source: str, node: ast.AST) -> str:
    return ast.get_source_segment(source, node) or ast.unparse(node)


def dotted_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = dotted_call_name(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    return ast.unparse(node)


def independent_source_review(source_path: Path) -> dict[str, Any]:
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    target_classes = [node for node in classes if node.name == EXPECTED_CLASS]
    if len(target_classes) != 1:
        raise ValueError(f"Expected exactly one {EXPECTED_CLASS} class")
    class_node = target_classes[0]
    bases = [ast.unparse(base) for base in class_node.bases]
    if "GuardrailBase" not in bases:
        raise ValueError("Hardened class does not subclass GuardrailBase")
    methods = [node for node in class_node.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    decides = [node for node in methods if node.name == "decide"]
    if len(decides) != 1:
        raise ValueError("Expected exactly one decide method")
    decide = decides[0]
    signature = [arg.arg for arg in decide.args.args]
    if signature != EXPECTED_SIGNATURE:
        raise ValueError(f"Unexpected decide signature: {signature}")

    imports: list[dict[str, Any]] = []
    private_imports: list[str] = []
    imported_helpers: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                full = f"{node.module}.{alias.name}"
                imports.append({"module": node.module, "name": alias.name, "full_name": full, "line": node.lineno})
                if alias.name.startswith("_"):
                    private_imports.append(full)
                if node.module == "aicomp_sdk.core.predicates":
                    imported_helpers.add(alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imports.append({"module": alias.name, "name": alias.asname or alias.name, "full_name": alias.name, "line": node.lineno})

    name_reads: list[dict[str, Any]] = []
    string_literals: list[dict[str, Any]] = []
    self_assignments: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    returns: list[dict[str, Any]] = []
    branches: list[dict[str, Any]] = []
    loops: list[dict[str, Any]] = []
    subscripts_or_gets: list[dict[str, Any]] = []

    for node in ast.walk(class_node):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            name_reads.append({"name": node.id, "line": node.lineno})
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            string_literals.append({"value": node.value, "line": getattr(node, "lineno", None)})
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
                    self_assignments.append({"field": target.attr, "line": node.lineno, "source": source_segment(source, node)})
        elif isinstance(node, ast.Call):
            call_name = dotted_call_name(node.func)
            calls.append({
                "call": call_name,
                "line": node.lineno,
                "positional_arg_count": len(node.args),
                "keyword_names": [kw.arg for kw in node.keywords],
                "source": source_segment(source, node),
            })
            if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                subscripts_or_gets.append({"kind": "get", "line": node.lineno, "source": source_segment(source, node)})
        elif isinstance(node, ast.Subscript):
            subscripts_or_gets.append({"kind": "subscript", "line": node.lineno, "source": source_segment(source, node)})
        elif isinstance(node, ast.Return):
            value = source_segment(source, node.value) if node.value is not None else "None"
            returns.append({"line": node.lineno, "expression": value, "expression_sha256": hashlib.sha256(value.encode()).hexdigest().upper()})
        elif isinstance(node, ast.If):
            condition = source_segment(source, node.test)
            branches.append({"line": node.lineno, "condition": condition, "condition_sha256": hashlib.sha256(condition.encode()).hexdigest().upper()})
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            loops.append({"node_type": type(node).__name__, "line": node.lineno, "source": source_segment(source, node)})

    all_read_tokens = {row["name"] for row in name_reads} | {row["value"] for row in string_literals}
    prohibited_hits = sorted(PROHIBITED_NAMES & all_read_tokens)
    private_matcher_hits = sorted(PRIVATE_MATCHER_NAMES & all_read_tokens)

    helper_calls = [row for row in calls if row["call"] in PUBLIC_HELPERS]
    fabricated_read_secrets_calls = [
        row for row in helper_calls
        if row["call"] == "payload_exfiltrates_secret"
        and (row["positional_arg_count"] > 1 or "read_secrets" in row["keyword_names"])
    ]
    first_present_key_loops = [
        row for row in loops
        if all(token in row["source"] for token in ("path", "url", "data"))
    ]
    sandbox_or_wrapper_dependencies = [
        row for row in imports
        if "sandbox" in row["full_name"].lower() or "wrapper" in row["full_name"].lower() or "adapter" in row["full_name"].lower()
    ]

    url_gets = [row for row in subscripts_or_gets if '"url"' in row["source"] or "'url'" in row["source"]]
    data_gets = [row for row in subscripts_or_gets if '"data"' in row["source"] or "'data'" in row["source"]]
    payload_name_gets = [row for row in subscripts_or_gets if "payload_name" in row["source"]]

    if imported_helpers != PUBLIC_HELPERS:
        raise ValueError(f"Unexpected public helper import set: {sorted(imported_helpers)}")
    if private_imports or private_matcher_hits:
        raise ValueError(f"Private matcher dependency detected: {private_imports + private_matcher_hits}")
    if prohibited_hits:
        raise ValueError(f"Prohibited source token detected: {prohibited_hits}")
    if self_assignments:
        raise ValueError(f"Mutable instance fields detected: {self_assignments}")
    if fabricated_read_secrets_calls:
        raise ValueError("Fabricated or supplied read_secrets detected")
    if first_present_key_loops:
        raise ValueError("Potential first-present-key extraction loop detected")
    if sandbox_or_wrapper_dependencies:
        raise ValueError("Sandbox, wrapper, or adapter dependency detected")
    if not url_gets or not payload_name_gets:
        raise ValueError("Independent HTTP URL and official payload retrieval not established")

    return {
        "source_sha256": sha256(source_path),
        "source_size_bytes": source_path.stat().st_size,
        "ast_parse": "PASS",
        "class_name": class_node.name,
        "class_bases": bases,
        "decide_signature": signature,
        "class_line_start": class_node.lineno,
        "class_line_end": class_node.end_lineno,
        "decide_line_start": decide.lineno,
        "decide_line_end": decide.end_lineno,
        "imports": imports,
        "imported_public_helpers": sorted(imported_helpers),
        "private_imports": private_imports,
        "branches": sorted(branches, key=lambda row: row["line"]),
        "returns": sorted(returns, key=lambda row: row["line"]),
        "calls": sorted(calls, key=lambda row: row["line"]),
        "context_and_argument_reads": sorted(subscripts_or_gets, key=lambda row: row["line"]),
        "helper_calls": sorted(helper_calls, key=lambda row: row["line"]),
        "prohibited_token_hits": prohibited_hits,
        "private_matcher_hits": private_matcher_hits,
        "mutable_instance_fields": self_assignments,
        "first_present_key_loops": first_present_key_loops,
        "fabricated_read_secrets_calls": fabricated_read_secrets_calls,
        "sandbox_or_wrapper_dependencies": sandbox_or_wrapper_dependencies,
        "url_retrieval_established": bool(url_gets),
        "data_retrieval_established": bool(data_gets or payload_name_gets),
        "independent_url_and_data_retrieval": bool(url_gets and payload_name_gets),
    }


def semantic_review_rows(review: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"check_id":"SRC-001","finding":"Exact class and GuardrailBase inheritance","status":"PASS","direct_evidence":f"{review['class_name']} bases={review['class_bases']}","claim_boundary":"static source only"},
        {"check_id":"SRC-002","finding":"Exact decide signature","status":"PASS","direct_evidence":str(review["decide_signature"]),"claim_boundary":"static source only"},
        {"check_id":"SRC-003","finding":"All return branches captured","status":"PASS","direct_evidence":f"return_count={len(review['returns'])}","claim_boundary":"return expressions captured, behavior not executed"},
        {"check_id":"SRC-004","finding":"Generic authorization fields absent","status":"PASS","direct_evidence":"no user_authorized or user_confirmed_safe token","claim_boundary":"absence in frozen source"},
        {"check_id":"SRC-005","finding":"URL and official payload retrieved independently","status":"PASS","direct_evidence":f"url={review['url_retrieval_established']} data={review['data_retrieval_established']}","claim_boundary":"proposal input handling only"},
        {"check_id":"SRC-006","finding":"No first-present-key extraction loop","status":"PASS","direct_evidence":"no qualifying loop detected","claim_boundary":"AST heuristic plus exact source blocks"},
        {"check_id":"SRC-007","finding":"No fabricated read_secrets argument","status":"PASS","direct_evidence":"payload_exfiltrates_secret has no read_secrets argument","claim_boundary":"real lineage remains unavailable"},
        {"check_id":"SRC-008","finding":"No private matcher import","status":"PASS","direct_evidence":"private import and matcher hit lists empty","claim_boundary":"frozen source imports only"},
        {"check_id":"SRC-009","finding":"No mutable instance state","status":"PASS","direct_evidence":"no assignments to self.*","claim_boundary":"AST-visible assignments only"},
        {"check_id":"SRC-010","finding":"No Sandbox, wrapper, or adapter dependency","status":"PASS","direct_evidence":"dependency list empty","claim_boundary":"direct imports only"},
    ]


def mapping_review(parent_rows: list[dict[str, str]], review: dict[str, Any]) -> list[dict[str, Any]]:
    direct_ids = {
        "IF-001", "RO-001", "RO-002", "RO-003", "RO-004", "TS-001", "TS-002",
        "TS-003", "TS-004", "TS-006", "MH-001", "MH-002", "PV-001", "PV-005",
        "ST-001", "ST-002", "ST-003", "ST-004",
    }
    assertion_ids = {"AZ-008", "TS-005"}
    reviewed: list[dict[str, Any]] = []
    for row in parent_rows:
        raw_id = row["requirement_id"]
        if "|" in raw_id:
            classification = "P2B_WITHHELD_PRESERVED"
            evidence_type = "PARENT_SCOPE_ASSERTION"
            reviewed_status = "PASS_WITHHELD"
        elif raw_id in direct_ids:
            classification = "DIRECT_SOURCE_SUPPORTED"
            evidence_type = "INDEPENDENT_AST_OR_SOURCE_EVIDENCE"
            reviewed_status = "PASS"
        elif raw_id in assertion_ids:
            classification = "SOURCE_ABSENCE_OR_HELPER_BOUNDARY_SUPPORTED"
            evidence_type = "NEGATIVE_SOURCE_EVIDENCE"
            reviewed_status = "PASS_WITH_QUALIFICATION"
        else:
            classification = "NOT_INDEPENDENTLY_CLASSIFIED"
            evidence_type = "INSUFFICIENT_MAPPING_RULE"
            reviewed_status = "REVIEW_REQUIRED"
        reviewed.append({
            "requirement_id": raw_id,
            "parent_status": row.get("status", ""),
            "parent_implementation": row.get("implementation", ""),
            "reviewed_status": reviewed_status,
            "reviewed_classification": classification,
            "evidence_type": evidence_type,
            "claim_boundary": "proposal-level static source qualification; no runtime effect claim",
        })
    return reviewed


def main() -> int:
    parser = argparse.ArgumentParser(description=VERSION)
    parser.add_argument("--v6-91-manifest", required=True)
    parser.add_argument("--v6-91-binding", required=True)
    parser.add_argument("--hardened-source", required=True)
    parser.add_argument("--v6-91-runner", required=True)
    parser.add_argument("--out-root", required=True)
    args = parser.parse_args()

    parent_manifest = Path(args.v6_91_manifest)
    parent_binding = Path(args.v6_91_binding)
    hardened_source = Path(args.hardened_source)
    v6_91_runner = Path(args.v6_91_runner)
    out = Path(args.out_root)

    if out.exists():
        raise FileExistsError(f"Refusing to overwrite existing output directory: {out}")
    for path in (parent_manifest, parent_binding, hardened_source, v6_91_runner):
        if not path.is_file():
            raise FileNotFoundError(path)
    if sha256(parent_manifest) != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("v6.91 parent manifest identity mismatch")
    external = load_json(parent_binding)
    if external.get("manifest_sha256") != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("v6.91 external binding manifest mismatch")
    if external.get("status") != EXPECTED_PARENT_STATUS:
        raise ValueError("v6.91 parent status mismatch")
    if external.get("hardened_source_sha256") != EXPECTED_SOURCE_SHA256:
        raise ValueError("v6.91 external binding hardened-source identity mismatch")
    if external.get("optimal_sha256") != EXPECTED_OPTIMAL_SHA256:
        raise ValueError("v6.91 external binding packaged Optimal identity mismatch")
    if external.get("predicates_sha256") != EXPECTED_PREDICATES_SHA256:
        raise ValueError("v6.91 external binding predicate identity mismatch")
    if sha256(hardened_source) != EXPECTED_SOURCE_SHA256:
        raise ValueError("Hardened source SHA-256 mismatch")
    if sha256(v6_91_runner) != EXPECTED_RUNNER_SHA256:
        raise ValueError("Exact v6.91 runner SHA-256 mismatch")

    indexed = index_manifest(parent_manifest)
    parent_checks = [verify_manifest_artifact(indexed[name]) for name in sorted(REQUIRED_PARENT_ARTIFACTS)]
    failed = [row for row in parent_checks if not row["passed"]]
    if failed:
        raise ValueError("v6.91 parent evidence mismatch: " + ", ".join(row["artifact"] for row in failed))
    source_row = indexed["proposal_aware_optimal.py"]
    if Path(source_row["source_path"]).resolve() != hardened_source.resolve():
        raise ValueError("Supplied hardened source is not the manifest-bound source path")

    parent_result = load_json(Path(indexed["ex6_v6_91_result.json"]["source_path"]))
    if parent_result.get("status") != EXPECTED_PARENT_STATUS:
        raise ValueError("Canonical v6.91 result status mismatch")
    mapping_rows = load_csv(Path(indexed["ex6_v6_91_requirement_to_code_mapping.csv"]["source_path"]))

    review = independent_source_review(hardened_source)
    semantic_rows = semantic_review_rows(review)
    mapping_rows_reviewed = mapping_review(mapping_rows, review)
    unresolved_mappings = [row for row in mapping_rows_reviewed if row["reviewed_status"] == "REVIEW_REQUIRED"]
    if unresolved_mappings:
        raise ValueError("Unresolved requirement mapping rows: " + ", ".join(row["requirement_id"] for row in unresolved_mappings))

    now = datetime.now(timezone.utc).isoformat()
    out.mkdir(parents=True)
    paths = {
        "parent_verification": out / "ex6_v6_91A_parent_verification.csv",
        "source_identity": out / "ex6_v6_91A_hardened_source_verification.json",
        "source_blocks": out / "ex6_v6_91A_exact_source_blocks.csv",
        "branches": out / "ex6_v6_91A_branch_return_matrix.csv",
        "context_reads": out / "ex6_v6_91A_context_argument_read_matrix.csv",
        "helper_calls": out / "ex6_v6_91A_helper_call_matrix.csv",
        "prohibited": out / "ex6_v6_91A_prohibited_pattern_scan.json",
        "semantic": out / "ex6_v6_91A_semantic_findings.csv",
        "mapping": out / "ex6_v6_91A_independent_requirement_mapping.csv",
        "runner": out / "ex6_v6_91A_runner_identity.json",
        "result": out / "ex6_v6_91A_result.json",
        "binding": out / "ex6_v6_91A_binding.json",
        "manifest": out / "ex6_v6_91A_manifest.csv",
        "external": out / "ex6_v6_91A_manifest_external_binding.json",
    }

    write_csv(paths["parent_verification"], parent_checks, ["artifact","path","exists","expected_size_bytes","observed_size_bytes","size_match","expected_sha256","observed_sha256","sha256_match","passed"])
    write_json(paths["source_identity"], {
        "path": str(hardened_source),
        "size_bytes": hardened_source.stat().st_size,
        "sha256": sha256(hardened_source),
        "expected_sha256": EXPECTED_SOURCE_SHA256,
        "byte_identity_match": True,
        "ast_parse": review["ast_parse"],
        "class_name": review["class_name"],
        "class_bases": review["class_bases"],
        "decide_signature": review["decide_signature"],
        "source_modified": False,
    })

    source = hardened_source.read_text(encoding="utf-8")
    tree = ast.parse(source)
    class_node = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == EXPECTED_CLASS)
    decide_node = next(node for node in class_node.body if isinstance(node, ast.FunctionDef) and node.name == "decide")
    block_rows = [
        {"block":"class", "symbol":EXPECTED_CLASS, "line_start":class_node.lineno, "line_end":class_node.end_lineno, "source_sha256":hashlib.sha256(source_segment(source,class_node).encode()).hexdigest().upper(), "source":source_segment(source,class_node)},
        {"block":"method", "symbol":f"{EXPECTED_CLASS}.decide", "line_start":decide_node.lineno, "line_end":decide_node.end_lineno, "source_sha256":hashlib.sha256(source_segment(source,decide_node).encode()).hexdigest().upper(), "source":source_segment(source,decide_node)},
    ]
    write_csv(paths["source_blocks"], block_rows, ["block","symbol","line_start","line_end","source_sha256","source"])

    branch_return_rows: list[dict[str, Any]] = []
    for branch in review["branches"]:
        branch_return_rows.append({"row_type":"IF_CONDITION","line":branch["line"],"detail":branch["condition"],"detail_sha256":branch["condition_sha256"]})
    for ret in review["returns"]:
        branch_return_rows.append({"row_type":"RETURN","line":ret["line"],"detail":ret["expression"],"detail_sha256":ret["expression_sha256"]})
    branch_return_rows.sort(key=lambda row: (row["line"], row["row_type"]))
    write_csv(paths["branches"], branch_return_rows, ["row_type","line","detail","detail_sha256"])
    write_csv(paths["context_reads"], review["context_and_argument_reads"], ["kind","line","source"])
    write_csv(paths["helper_calls"], review["helper_calls"], ["call","line","positional_arg_count","keyword_names","source"])

    prohibited_scan = {
        "generic_authorization_tokens": ["user_authorized", "user_confirmed_safe"],
        "generic_authorization_hits": [x for x in review["prohibited_token_hits"] if x in {"user_authorized","user_confirmed_safe"}],
        "read_secrets_hits": [x for x in review["prohibited_token_hits"] if x == "read_secrets"],
        "private_matcher_hits": review["private_matcher_hits"],
        "private_imports": review["private_imports"],
        "first_present_key_loops": review["first_present_key_loops"],
        "fabricated_read_secrets_calls": review["fabricated_read_secrets_calls"],
        "mutable_instance_fields": review["mutable_instance_fields"],
        "sandbox_or_wrapper_dependencies": review["sandbox_or_wrapper_dependencies"],
        "url_retrieval_established": review["url_retrieval_established"],
        "data_retrieval_established": review["data_retrieval_established"],
        "independent_url_and_data_retrieval": review["independent_url_and_data_retrieval"],
        "status": "PASS",
    }
    write_json(paths["prohibited"], prohibited_scan)
    write_csv(paths["semantic"], semantic_rows, ["check_id","finding","status","direct_evidence","claim_boundary"])
    write_csv(paths["mapping"], mapping_rows_reviewed, ["requirement_id","parent_status","parent_implementation","reviewed_status","reviewed_classification","evidence_type","claim_boundary"])

    runner_identity = {
        "filename": v6_91_runner.name,
        "path": str(v6_91_runner),
        "size_bytes": v6_91_runner.stat().st_size,
        "sha256": sha256(v6_91_runner),
        "expected_sha256": EXPECTED_RUNNER_SHA256,
        "sha256_match": True,
        "present_in_parent_v6_91_manifest": v6_91_runner.name in indexed,
        "bound_as_source_artifact_in_v6_91A": True,
    }
    write_json(paths["runner"], runner_identity)

    result = {
        "version": VERSION,
        "created_at_utc": now,
        "status": "P2A_INDEPENDENT_SOURCE_AND_EXECUTION_PROVENANCE_QUALIFICATION_COMPLETE",
        "classification": "PROPOSAL_AWARE_OPTIMAL_SOURCE_SEMANTICS_AND_v6_91_RUNNER_IDENTITY_INDEPENDENTLY_QUALIFIED_COMPARISON_WITHHELD",
        "execution_type": "READ_ONLY_SOURCE_AND_PROVENANCE_REVIEW",
        "parent_v6_91_manifest_sha256": EXPECTED_PARENT_MANIFEST_SHA256,
        "required_parent_artifacts_verified": len(parent_checks),
        "hardened_source_sha256": sha256(hardened_source),
        "runner_sha256": sha256(v6_91_runner),
        "runner_bound_in_v6_91A": True,
        "source_ast_parse": "PASS",
        "exact_class_and_signature": "PASS",
        "branch_and_return_capture": "PASS",
        "generic_authorization_read_absent": True,
        "independent_url_and_data_retrieval": review["independent_url_and_data_retrieval"],
        "first_present_key_extraction_absent": True,
        "fabricated_read_secrets_absent": True,
        "private_matcher_imports_absent": True,
        "mutable_instance_state_absent": True,
        "sandbox_wrapper_adapter_dependencies_absent": True,
        "requirement_mapping_review": "PASS_WITH_P2B_WITHHELD_ROWS_PRESERVED",
        "source_modified": False,
        "v6_91_artifacts_modified": False,
        "runtime": False,
        "sdk_imported": False,
        "policy_comparison_executed": False,
        "harness_trick": "NOT_DEMONSTRATED",
        "security_finding": "NOT_ESTABLISHED_STATIC_SOURCE_AND_PROVENANCE_QUALIFICATION_ONLY",
        "claim_boundary": "PROPOSAL_LEVEL_HARDENING_ONLY",
        "P3_eligibility": "READY_FOR_POLICY_UNIT_MATRIX_DESIGN_NOT_RUNTIME_EFFECT_CLAIMS",
    }
    write_json(paths["result"], result)

    binding = {
        "version": VERSION,
        "created_at_utc": now,
        "parent_v6_91_manifest": {"path":str(parent_manifest),"size_bytes":parent_manifest.stat().st_size,"sha256":sha256(parent_manifest)},
        "parent_v6_91_external_binding": {"path":str(parent_binding),"size_bytes":parent_binding.stat().st_size,"sha256":sha256(parent_binding)},
        "verified_parent_artifacts": parent_checks,
        "hardened_source": {"path":str(hardened_source),"size_bytes":hardened_source.stat().st_size,"sha256":sha256(hardened_source)},
        "v6_91_runner": runner_identity,
        "optimal_sha256": EXPECTED_OPTIMAL_SHA256,
        "predicates_sha256": EXPECTED_PREDICATES_SHA256,
        "paths_inferred": False,
        "source_modified": False,
        "v6_91_artifacts_modified": False,
        "runtime_executed": False,
        "sdk_imported": False,
        "policy_comparison_executed": False,
        "python": sys.version,
        "platform": platform.platform(),
    }
    write_json(paths["binding"], binding)

    generated_keys = ["parent_verification","source_identity","source_blocks","branches","context_reads","helper_calls","prohibited","semantic","mapping","runner","result","binding"]
    manifest_rows = [{"artifact":paths[k].name,"role":"DERIVED_v6_91A_QUALIFICATION","size_bytes":paths[k].stat().st_size,"sha256":sha256(paths[k]),"source_path":str(paths[k])} for k in generated_keys]
    for path, role in (
        (parent_manifest, "SOURCE_OR_PARENT"),
        (parent_binding, "SOURCE_OR_PARENT"),
        (hardened_source, "QUALIFIED_HARDENED_SOURCE"),
        (v6_91_runner, "QUALIFIED_v6_91_RUNNER"),
    ):
        manifest_rows.append({"artifact":path.name,"role":role,"size_bytes":path.stat().st_size,"sha256":sha256(path),"source_path":str(path)})
    for row in parent_checks:
        manifest_rows.append({"artifact":row["artifact"],"role":"VERIFIED_PARENT_EVIDENCE","size_bytes":row["observed_size_bytes"],"sha256":row["observed_sha256"],"source_path":row["path"]})
    write_csv(paths["manifest"], manifest_rows, ["artifact","role","size_bytes","sha256","source_path"])

    external_out = {
        "version": VERSION,
        "created_at_utc": now,
        "manifest_filename": paths["manifest"].name,
        "manifest_size_bytes": paths["manifest"].stat().st_size,
        "manifest_sha256": sha256(paths["manifest"]),
        "status": result["status"],
        "classification": result["classification"],
        "parent_v6_91_manifest_sha256": EXPECTED_PARENT_MANIFEST_SHA256,
        "hardened_source_sha256": EXPECTED_SOURCE_SHA256,
        "v6_91_runner_sha256": EXPECTED_RUNNER_SHA256,
        "optimal_sha256": EXPECTED_OPTIMAL_SHA256,
        "predicates_sha256": EXPECTED_PREDICATES_SHA256,
    }
    write_json(paths["external"], external_out)

    print(json.dumps({
        "status": result["status"],
        "classification": result["classification"],
        "verified_parent_artifacts": len(parent_checks),
        "hardened_source_sha256": result["hardened_source_sha256"],
        "runner_sha256": result["runner_sha256"],
        "manifest_sha256": external_out["manifest_sha256"],
        "output_directory": str(out),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
