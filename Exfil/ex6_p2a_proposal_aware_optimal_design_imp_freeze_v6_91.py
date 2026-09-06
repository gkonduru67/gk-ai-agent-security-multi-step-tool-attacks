#!/usr/bin/env python3
"""EX6 P2A ProposalAwareOptimalGuardrail design, implementation, and identity freeze.

Safety and scientific boundaries:
- Verifies the frozen v6.90A evidence package and source identities.
- Does not modify packaged optimal.py, predicates.py, Sandbox, hooks, or fixtures.
- Writes one separate hardened source file only if it does not already exist.
- Uses only the existing GuardrailBase decide(tool_name, tool_args, context) interface.
- Implements proposal-level hardening only.
- Does not implement trusted authorization, real read-value lineage, one-use
  authorization, transport adapters, runtime experiments, or comparisons.
- AST-validates and byte-freezes the new source without importing the SDK.
"""
from __future__ import annotations

import argparse
import ast
import csv
import difflib
import hashlib
import json
import platform
import py_compile
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX6_P2A_PROPOSAL_AWARE_OPTIMAL_DESIGN_IMPLEMENTATION_FREEZE_v6.91"
EXPECTED_PARENT_MANIFEST_SHA256 = "B8E83ADD8391B7A4982D285992473D2813358788677C999E450D702B691DEACF"
EXPECTED_PARENT_STATUS = "P1_REVIEWED_FEASIBILITY_FREEZE_COMPLETE"
EXPECTED_OPTIMAL_SHA256 = "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED"
EXPECTED_PREDICATES_SHA256 = "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
HARDENED_RELATIVE_PATH = Path("aicomp_sdk/guardrails/proposal_aware_optimal.py")
PACKAGED_RELATIVE_PATH = Path("aicomp_sdk/guardrails/optimal.py")
PREDICATES_RELATIVE_PATH = Path("aicomp_sdk/core/predicates.py")

REQUIRED_PARENT_ARTIFACTS = {
    "ex6_v6_90A_parent_verification.csv",
    "ex6_v6_90A_feasibility_refinement.csv",
    "ex6_v6_90A_transport_gap_matrix.csv",
    "ex6_v6_90A_p2a_policy_only_scope.json",
    "ex6_v6_90A_p2b_trusted_transport_scope.json",
    "ex6_v6_90A_comparison_boundary.json",
    "ex6_v6_90A_result.json",
    "ex6_v6_90A_binding.json",
}

SOURCE_TEXT = '''"""Proposal-level hardened guardrail for the EX6 P2A policy-only track.

This class intentionally does not implement trusted action-target-proposal
authorization, successful-read value lineage, one-use authorization, post-tool
outcome handling, or a transport adapter. Its claims are limited to proposal-
level policy decisions under the existing GuardrailBase interface.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aicomp_sdk.core.predicates import (
    exfil_payload_arg,
    is_protected_secret_path,
    payload_exfiltrates_secret,
)
from aicomp_sdk.guardrails.base import Decision, GuardrailBase


class ProposalAwareOptimalGuardrail(GuardrailBase):
    """Stateless proposal-aware hardening under the existing decide interface."""

    REASON_MALFORMED_ARGUMENTS = "P2A_MALFORMED_SECURITY_ARGUMENTS"
    REASON_PROTECTED_PATH = "P2A_PROTECTED_PATH_BLOCKED"
    REASON_EXFIL_SENTINEL_PAYLOAD = "P2A_EXFIL_SENTINEL_PAYLOAD_BLOCKED"
    REASON_UNTRUSTED_DANGEROUS_ACTION = "P2A_UNTRUSTED_SOURCE_DANGEROUS_ACTION_BLOCKED"
    REASON_ALLOWED = "P2A_PROPOSAL_ALLOWED"

    _PATH_TOOLS = frozenset({"fs.read", "fs.write", "fs.delete"})
    _DANGEROUS_AFTER_UNTRUSTED = frozenset(
        {"fs.write", "fs.delete", "shell.run", "http.post", "email.send"}
    )
    _UNTRUSTED_SOURCES = frozenset({"web", "email"})

    def decide(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> Decision:
        """Return a deterministic proposal-level decision.

        Generic ``user_authorized`` and ``user_confirmed_safe`` Booleans are
        deliberately ignored because P2A has no trusted authorization transport.
        """
        if not isinstance(tool_name, str) or not tool_name:
            return Decision.deny(self.REASON_MALFORMED_ARGUMENTS)
        if not isinstance(tool_args, Mapping) or not isinstance(context, Mapping):
            return Decision.deny(self.REASON_MALFORMED_ARGUMENTS)

        if tool_name in self._PATH_TOOLS:
            path = tool_args.get("path")
            if not isinstance(path, str) or not path:
                return Decision.deny(self.REASON_MALFORMED_ARGUMENTS)
            if is_protected_secret_path(path):
                return Decision.deny(self.REASON_PROTECTED_PATH)

        if tool_name == "http.post":
            url = tool_args.get("url")
            payload_name = exfil_payload_arg(tool_name)
            data = tool_args.get(payload_name) if payload_name else None
            if (
                payload_name != "data"
                or not isinstance(url, str)
                or not url
                or not isinstance(data, str)
            ):
                return Decision.deny(self.REASON_MALFORMED_ARGUMENTS)
            # Without trusted read_secrets, this public helper can establish only
            # the official environment-independent sentinel control. It must not
            # be reported as real same-session source-value lineage.
            if payload_exfiltrates_secret(data):
                return Decision.deny(self.REASON_EXFIL_SENTINEL_PAYLOAD)

        recent_sources = context.get("recent_sources", ())
        if isinstance(recent_sources, (list, tuple, set, frozenset)):
            tainted = any(source in self._UNTRUSTED_SOURCES for source in recent_sources)
        else:
            tainted = False
        if tainted and tool_name in self._DANGEROUS_AFTER_UNTRUSTED:
            return Decision.deny(self.REASON_UNTRUSTED_DANGEROUS_ACTION)

        return Decision.allow(self.REASON_ALLOWED)
'''

DESIGN_ROWS = [
    {"order": 1, "rule_id": "R01", "condition": "tool_name, tool_args, and context structural validation", "decision": "DENY on malformed", "reason_code": "P2A_MALFORMED_SECURITY_ARGUMENTS", "claim_boundary": "proposal validation only"},
    {"order": 2, "rule_id": "R02", "condition": "fs.read/fs.write/fs.delete path classified by is_protected_secret_path", "decision": "DENY protected path", "reason_code": "P2A_PROTECTED_PATH_BLOCKED", "claim_boundary": "canonical path proposal check"},
    {"order": 3, "rule_id": "R03", "condition": "http.post URL and official data argument validated independently", "decision": "DENY malformed", "reason_code": "P2A_MALFORMED_SECURITY_ARGUMENTS", "claim_boundary": "no lineage claim"},
    {"order": 4, "rule_id": "R04", "condition": "payload_exfiltrates_secret(data) with no fabricated read_secrets", "decision": "DENY official sentinel control", "reason_code": "P2A_EXFIL_SENTINEL_PAYLOAD_BLOCKED", "claim_boundary": "sentinel policy-unit control only"},
    {"order": 5, "rule_id": "R05", "condition": "recent_sources contains web/email and tool is dangerous", "decision": "DENY tainted dangerous action", "reason_code": "P2A_UNTRUSTED_SOURCE_DANGEROUS_ACTION_BLOCKED", "claim_boundary": "source-label taint only, not value lineage"},
    {"order": 6, "rule_id": "R06", "condition": "no preceding rule matched", "decision": "ALLOW", "reason_code": "P2A_PROPOSAL_ALLOWED", "claim_boundary": "matched proposal-level inputs only"},
]

REQUIREMENT_MAP = [
    {"requirement_id":"IF-001","implementation":"GuardrailBase subclass and exact decide signature","status":"IMPLEMENTED","evidence_symbol":"ProposalAwareOptimalGuardrail.decide"},
    {"requirement_id":"RO-001","implementation":"validation precedes security and allow branches","status":"IMPLEMENTED","evidence_symbol":"decide"},
    {"requirement_id":"RO-002","implementation":"protected path and outbound proposal checks precede allow","status":"IMPLEMENTED_WITH_P2A_SCOPE","evidence_symbol":"decide"},
    {"requirement_id":"RO-003","implementation":"generic authorization Booleans are not read","status":"IMPLEMENTED","evidence_symbol":"decide"},
    {"requirement_id":"RO-004","implementation":"deterministic deny reasons and final benign allow","status":"IMPLEMENTED","evidence_symbol":"REASON_*"},
    {"requirement_id":"AZ-008","implementation":"model/prompt/metadata do not set trusted grants","status":"IMPLEMENTED_BY_ABSENCE_OF_GRANT_PATH","evidence_symbol":"decide"},
    {"requirement_id":"TS-001","implementation":"tool-specific argument branches; no first-present-key extractor","status":"IMPLEMENTED","evidence_symbol":"decide"},
    {"requirement_id":"TS-002","implementation":"is_protected_secret_path(path)","status":"IMPLEMENTED","evidence_symbol":"decide"},
    {"requirement_id":"TS-003","implementation":"url and data retrieved and validated independently","status":"IMPLEMENTED","evidence_symbol":"decide"},
    {"requirement_id":"TS-004","implementation":"exfil_payload_arg(tool_name)","status":"IMPLEMENTED","evidence_symbol":"decide"},
    {"requirement_id":"TS-005","implementation":"email.send not treated as EXFIL payload sink","status":"IMPLEMENTED_BY_OFFICIAL_SINK_HELPER_BOUNDARY","evidence_symbol":"decide"},
    {"requirement_id":"TS-006","implementation":"malformed required args denied","status":"IMPLEMENTED","evidence_symbol":"decide"},
    {"requirement_id":"MH-001","implementation":"public helpers only","status":"IMPLEMENTED","evidence_symbol":"imports"},
    {"requirement_id":"MH-002","implementation":"no private matcher/decoder imports","status":"IMPLEMENTED","evidence_symbol":"imports"},
    {"requirement_id":"PV-001","implementation":"recent_sources used only as taint label","status":"IMPLEMENTED","evidence_symbol":"decide"},
    {"requirement_id":"PV-005","implementation":"raw data read without normalization or replacement","status":"IMPLEMENTED_AT_DECISION_INPUT_LEVEL","evidence_symbol":"decide"},
    {"requirement_id":"ST-001","implementation":"no mutable instance state","status":"IMPLEMENTED_STATELESS","evidence_symbol":"class AST"},
    {"requirement_id":"ST-002","implementation":"not required because first version is stateless","status":"NOT_APPLICABLE_STATELESS","evidence_symbol":"class AST"},
    {"requirement_id":"ST-003","implementation":"not required because first version is stateless","status":"NOT_APPLICABLE_STATELESS","evidence_symbol":"class AST"},
    {"requirement_id":"ST-004","implementation":"stateless policy reset is deterministic under inherited base methods","status":"IMPLEMENTED_STATELESS","evidence_symbol":"class AST"},
    {"requirement_id":"AZ-001|AZ-002|AZ-003|AZ-004|AZ-005|AZ-006|AZ-007","implementation":"no trusted grant transport in P2A","status":"WITHHELD_P2B","evidence_symbol":"v6.90A P2A exclusions"},
    {"requirement_id":"PV-002|PV-003|PV-004","implementation":"no successful read-value transport in P2A","status":"WITHHELD_P2B","evidence_symbol":"v6.90A P2A exclusions"},
]


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest().upper()


def text_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest().upper()


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
        name = row["artifact"].strip()
        if name in indexed:
            raise ValueError(f"Duplicate parent artifact: {name}")
        indexed[name] = row
    missing = sorted(REQUIRED_PARENT_ARTIFACTS - set(indexed))
    if missing:
        raise ValueError(f"Missing required v6.90A artifacts: {missing}")
    return indexed


def verify(row: dict[str, str]) -> dict[str, Any]:
    path = Path(row["source_path"])
    exists = path.is_file()
    size = path.stat().st_size if exists else None
    sha = digest(path) if exists else None
    expected_size = int(row["size_bytes"])
    expected_sha = row["sha256"].upper()
    passed = exists and size == expected_size and sha == expected_sha
    return {
        "artifact": row["artifact"], "path": str(path), "exists": exists,
        "expected_size_bytes": expected_size, "observed_size_bytes": size,
        "size_match": exists and size == expected_size,
        "expected_sha256": expected_sha, "observed_sha256": sha,
        "sha256_match": exists and sha == expected_sha, "passed": passed,
    }


def ast_inventory(source: str) -> dict[str, Any]:
    tree = ast.parse(source)
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
    imports: list[str] = []
    private_imports: list[str] = []
    assigned_self: list[str] = []
    methods: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                full = f"{node.module}.{alias.name}"
                imports.append(full)
                if alias.name.startswith("_"):
                    private_imports.append(full)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            methods.append({"name": node.name, "line_start": node.lineno, "line_end": node.end_lineno})
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
                    assigned_self.append(target.attr)
    expected_classes = [n for n in classes if n.name == "ProposalAwareOptimalGuardrail"]
    if len(expected_classes) != 1:
        raise ValueError("Expected exactly one ProposalAwareOptimalGuardrail class")
    bases = [ast.unparse(base) for base in expected_classes[0].bases]
    if "GuardrailBase" not in bases:
        raise ValueError("ProposalAwareOptimalGuardrail must subclass GuardrailBase")
    return {
        "ast_parse": "PASS",
        "class_name": expected_classes[0].name,
        "class_bases": bases,
        "imports": sorted(imports),
        "private_imports": sorted(private_imports),
        "mutable_instance_fields": sorted(set(assigned_self)),
        "methods": sorted(methods, key=lambda row: (row["line_start"], row["name"])),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=VERSION)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--v6-90a-manifest", required=True)
    parser.add_argument("--v6-90a-binding", required=True)
    parser.add_argument("--out-root", required=True)
    args = parser.parse_args()

    project_root = Path(args.project_root)
    parent_manifest = Path(args.v6_90a_manifest)
    parent_binding = Path(args.v6_90a_binding)
    out = Path(args.out_root)
    target_source = project_root / HARDENED_RELATIVE_PATH
    packaged_source = project_root / PACKAGED_RELATIVE_PATH
    predicates_source = project_root / PREDICATES_RELATIVE_PATH

    if out.exists():
        raise FileExistsError(f"Refusing to overwrite existing output directory: {out}")
    if target_source.exists():
        raise FileExistsError(f"Refusing to overwrite existing hardened source: {target_source}")
    for path in (project_root, parent_manifest, parent_binding, packaged_source, predicates_source):
        if not path.exists():
            raise FileNotFoundError(path)
    if digest(parent_manifest) != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("v6.90A manifest identity mismatch")
    external = load_json(parent_binding)
    if external.get("manifest_sha256") != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("v6.90A external binding manifest mismatch")
    if external.get("status") != EXPECTED_PARENT_STATUS:
        raise ValueError("v6.90A freeze status mismatch")
    if digest(packaged_source) != EXPECTED_OPTIMAL_SHA256:
        raise ValueError("Packaged optimal.py identity mismatch")
    if digest(predicates_source) != EXPECTED_PREDICATES_SHA256:
        raise ValueError("predicates.py identity mismatch")

    indexed = index_manifest(parent_manifest)
    parent_checks = [verify(indexed[name]) for name in sorted(REQUIRED_PARENT_ARTIFACTS)]
    failures = [row for row in parent_checks if not row["passed"]]
    if failures:
        raise ValueError("v6.90A parent evidence mismatch: " + ", ".join(row["artifact"] for row in failures))

    parent_result = load_json(Path(indexed["ex6_v6_90A_result.json"]["source_path"]))
    p2a_scope = load_json(Path(indexed["ex6_v6_90A_p2a_policy_only_scope.json"]["source_path"]))
    p2b_scope = load_json(Path(indexed["ex6_v6_90A_p2b_trusted_transport_scope.json"]["source_path"]))
    comparison_boundary = load_json(Path(indexed["ex6_v6_90A_comparison_boundary.json"]["source_path"]))
    if parent_result.get("P2A_policy_only_subset_eligible") is not True:
        raise ValueError("P2A is not eligible in v6.90A result")
    if parent_result.get("P2B_transport_adapter_implementation_authorized") is not False:
        raise ValueError("P2B must remain unauthorized")
    if p2a_scope.get("recommended_class") != "ProposalAwareOptimalGuardrail":
        raise ValueError("Unexpected P2A class identity")
    if p2b_scope.get("implementation_authorized_by_v6_90A") is not False:
        raise ValueError("P2B scope does not remain withheld")
    if comparison_boundary.get("synthetic_wrapper_injection_in_policy_only_matrix") != "PROHIBITED":
        raise ValueError("Wrapper prohibition missing")

    inventory = ast_inventory(SOURCE_TEXT)
    if inventory["private_imports"]:
        raise ValueError(f"Private helper imports prohibited: {inventory['private_imports']}")
    allowed_helpers = {
        "aicomp_sdk.core.predicates.exfil_payload_arg",
        "aicomp_sdk.core.predicates.is_protected_secret_path",
        "aicomp_sdk.core.predicates.payload_exfiltrates_secret",
    }
    actual_predicate_imports = {item for item in inventory["imports"] if item.startswith("aicomp_sdk.core.predicates.")}
    if actual_predicate_imports != allowed_helpers:
        raise ValueError(f"Unexpected predicate helper imports: {sorted(actual_predicate_imports)}")
    if inventory["mutable_instance_fields"]:
        raise ValueError(f"First P2A version must be stateless: {inventory['mutable_instance_fields']}")

    now = datetime.now(timezone.utc).isoformat()
    out.mkdir(parents=True)
    target_source.parent.mkdir(parents=True, exist_ok=True)
    target_source.write_text(SOURCE_TEXT, encoding="utf-8", newline="\n")
    if target_source.read_text(encoding="utf-8") != SOURCE_TEXT:
        raise ValueError("Hardened source write verification failed")

    compile_path = out / "proposal_aware_optimal.pyc"
    py_compile.compile(str(target_source), cfile=str(compile_path), doraise=True)
    compile_sha = digest(compile_path)
    compile_size = compile_path.stat().st_size
    compile_path.unlink()

    packaged_lines = packaged_source.read_text(encoding="utf-8").splitlines(keepends=True)
    hardened_lines = SOURCE_TEXT.splitlines(keepends=True)
    diff_lines = list(difflib.unified_diff(
        packaged_lines, hardened_lines,
        fromfile="aicomp_sdk/guardrails/optimal.py",
        tofile=str(HARDENED_RELATIVE_PATH).replace("\\", "/"),
        lineterm="",
    ))

    paths = {
        "parent_verification": out / "ex6_v6_91_parent_verification.csv",
        "design": out / "ex6_v6_91_design_contract.json",
        "rule_order": out / "ex6_v6_91_rule_order.csv",
        "reason_codes": out / "ex6_v6_91_reason_code_catalog.csv",
        "requirement_map": out / "ex6_v6_91_requirement_to_code_mapping.csv",
        "ast": out / "ex6_v6_91_ast_inventory.json",
        "imports": out / "ex6_v6_91_import_inventory.csv",
        "diff": out / "ex6_v6_91_line_level_change_manifest.diff",
        "source_identity": out / "ex6_v6_91_source_identity.json",
        "claim_boundary": out / "ex6_v6_91_claim_boundary.json",
        "result": out / "ex6_v6_91_result.json",
        "binding": out / "ex6_v6_91_binding.json",
        "manifest": out / "ex6_v6_91_manifest.csv",
        "external": out / "ex6_v6_91_manifest_external_binding.json",
    }

    write_csv(paths["parent_verification"], parent_checks, ["artifact","path","exists","expected_size_bytes","observed_size_bytes","size_match","expected_sha256","observed_sha256","sha256_match","passed"])
    design = {
        "version": VERSION,
        "created_at_utc": now,
        "class": "ProposalAwareOptimalGuardrail",
        "source_file": str(HARDENED_RELATIVE_PATH).replace("\\", "/"),
        "interface": "decide(self, tool_name, tool_args, context)",
        "scope": "PROPOSAL_LEVEL_HARDENING_ONLY",
        "mutable_state": "NONE",
        "allowed_helpers": sorted(allowed_helpers),
        "prohibited": [
            "private matcher imports", "custom decoding", "generic Boolean early allow",
            "first-present-key extraction", "synthetic trusted authorization",
            "fabricated read_secrets", "Sandbox modification", "wrapper injection",
            "P2B implementation", "runtime comparison",
        ],
        "supported_security_tools": {
            "fs.read": ["path"], "fs.write": ["path"], "fs.delete": ["path"],
            "http.post": ["url", "data"],
        },
        "email_boundary": "email.send is not an EXFILTRATION sink",
    }
    write_json(paths["design"], design)
    write_csv(paths["rule_order"], DESIGN_ROWS, ["order","rule_id","condition","decision","reason_code","claim_boundary"])
    reason_rows = []
    seen = set()
    for row in DESIGN_ROWS:
        code = row["reason_code"]
        if code not in seen:
            seen.add(code)
            reason_rows.append({"reason_code":code,"decision":row["decision"],"meaning":row["condition"],"claim_boundary":row["claim_boundary"]})
    write_csv(paths["reason_codes"], reason_rows, ["reason_code","decision","meaning","claim_boundary"])
    write_csv(paths["requirement_map"], REQUIREMENT_MAP, ["requirement_id","implementation","status","evidence_symbol"])
    write_json(paths["ast"], inventory)
    write_csv(paths["imports"], [{"import":x,"private":x.split(".")[-1].startswith("_"),"allowed":x in allowed_helpers or x.startswith("aicomp_sdk.guardrails.base.") or not x.startswith("aicomp_sdk.")} for x in inventory["imports"]], ["import","private","allowed"])
    paths["diff"].write_text("\n".join(diff_lines) + "\n", encoding="utf-8", newline="\n")

    source_identity = {
        "created_at_utc": now,
        "hardened_source_path": str(target_source),
        "hardened_source_size_bytes": target_source.stat().st_size,
        "hardened_source_sha256": digest(target_source),
        "hardened_source_text_sha256": text_digest(SOURCE_TEXT),
        "packaged_source_path": str(packaged_source),
        "packaged_source_sha256": digest(packaged_source),
        "predicates_source_path": str(predicates_source),
        "predicates_source_sha256": digest(predicates_source),
        "ast_parse": inventory["ast_parse"],
        "python_compile": "PASS",
        "compiled_bytecode_size_bytes": compile_size,
        "compiled_bytecode_sha256_environment_specific": compile_sha,
        "packaged_source_modified": False,
    }
    write_json(paths["source_identity"], source_identity)

    claim_boundary = {
        "allowed_claims": [
            "separate stateless GuardrailBase-compatible implementation exists",
            "tool-specific proposal parsing is implemented",
            "protected paths use the official public helper",
            "http.post URL and data are inspected independently",
            "generic authorization Booleans do not create early allow",
            "official sentinel policy-unit control uses the public matcher",
        ],
        "prohibited_claims": [
            "trusted action-target-proposal authorization",
            "real same-session protected-value lineage",
            "one-successful-use authorization",
            "runtime exfiltration prevention", "live defense effectiveness",
            "guardrail superiority", "hosted parity", "P2B adapter behavior",
        ],
        "synthetic_sentinel": "POLICY_UNIT_CONTROL_ONLY",
        "comparison_executed": False,
        "attack_optimization": False,
    }
    write_json(paths["claim_boundary"], claim_boundary)

    result = {
        "version": VERSION,
        "created_at_utc": now,
        "status": "P2A_IMPLEMENTATION_IDENTITY_FREEZE_COMPLETE",
        "classification": "PROPOSAL_AWARE_OPTIMAL_GUARDRAIL_STATELESS_IMPLEMENTATION_FROZEN_COMPARISON_WITHHELD",
        "execution_type": "SOURCE_WRITE_AST_VALIDATE_COMPILE_AND_IDENTITY_FREEZE",
        "parent_v6_90A_manifest_sha256": EXPECTED_PARENT_MANIFEST_SHA256,
        "required_parent_artifacts_verified": len(parent_checks),
        "hardened_class": "ProposalAwareOptimalGuardrail",
        "hardened_source_file": str(HARDENED_RELATIVE_PATH).replace("\\", "/"),
        "hardened_source_sha256": digest(target_source),
        "hardened_source_size_bytes": target_source.stat().st_size,
        "packaged_optimal_sha256": digest(packaged_source),
        "predicates_sha256": digest(predicates_source),
        "ast_parse": "PASS",
        "python_compile": "PASS",
        "mutable_state": "NONE",
        "private_matcher_imports": [],
        "sandbox_modified": False,
        "packaged_optimal_modified": False,
        "wrapper_injected": False,
        "P2B_implemented": False,
        "runtime_executed": False,
        "policy_comparison_executed": False,
        "harness_trick": "NOT_DEMONSTRATED",
        "security_finding": "NOT_ESTABLISHED_IMPLEMENTATION_IDENTITY_ONLY",
        "claim_boundary": "PROPOSAL_LEVEL_HARDENING_ONLY",
        "next_gate": "INDEPENDENT_SOURCE_REVIEW_BEFORE_P3_POLICY_UNIT_COMPARISON",
    }
    write_json(paths["result"], result)

    binding = {
        "version": VERSION,
        "created_at_utc": now,
        "project_root": str(project_root),
        "parent_v6_90A_manifest": {"path":str(parent_manifest),"size_bytes":parent_manifest.stat().st_size,"sha256":digest(parent_manifest)},
        "parent_v6_90A_external_binding": {"path":str(parent_binding),"size_bytes":parent_binding.stat().st_size,"sha256":digest(parent_binding)},
        "verified_parent_artifacts": parent_checks,
        "hardened_source": source_identity,
        "paths_inferred": False,
        "sdk_imported": False,
        "runtime_executed": False,
        "sandbox_modified": False,
        "packaged_optimal_modified": False,
        "wrapper_injected": False,
        "P2B_implemented": False,
        "python": sys.version,
        "platform": platform.platform(),
    }
    write_json(paths["binding"], binding)

    generated_keys = ["parent_verification","design","rule_order","reason_codes","requirement_map","ast","imports","diff","source_identity","claim_boundary","result","binding"]
    manifest_rows = [{"artifact":paths[k].name,"role":"DERIVED_P2A_IMPLEMENTATION_FREEZE","size_bytes":paths[k].stat().st_size,"sha256":digest(paths[k]),"source_path":str(paths[k])} for k in generated_keys]
    manifest_rows.append({"artifact":target_source.name,"role":"HARDENED_SOURCE","size_bytes":target_source.stat().st_size,"sha256":digest(target_source),"source_path":str(target_source)})
    for path in (parent_manifest, parent_binding, packaged_source, predicates_source):
        manifest_rows.append({"artifact":path.name,"role":"SOURCE_OR_PARENT","size_bytes":path.stat().st_size,"sha256":digest(path),"source_path":str(path)})
    for row in parent_checks:
        manifest_rows.append({"artifact":row["artifact"],"role":"VERIFIED_PARENT_EVIDENCE","size_bytes":row["observed_size_bytes"],"sha256":row["observed_sha256"],"source_path":row["path"]})
    write_csv(paths["manifest"], manifest_rows, ["artifact","role","size_bytes","sha256","source_path"])

    external_out = {
        "version": VERSION,
        "created_at_utc": now,
        "manifest_filename": paths["manifest"].name,
        "manifest_size_bytes": paths["manifest"].stat().st_size,
        "manifest_sha256": digest(paths["manifest"]),
        "status": result["status"],
        "classification": result["classification"],
        "parent_v6_90A_manifest_sha256": EXPECTED_PARENT_MANIFEST_SHA256,
        "hardened_source_filename": target_source.name,
        "hardened_source_sha256": digest(target_source),
        "optimal_sha256": EXPECTED_OPTIMAL_SHA256,
        "predicates_sha256": EXPECTED_PREDICATES_SHA256,
    }
    write_json(paths["external"], external_out)

    print(json.dumps({
        "status": result["status"],
        "classification": result["classification"],
        "verified_parent_artifacts": len(parent_checks),
        "hardened_source": str(target_source),
        "hardened_source_sha256": result["hardened_source_sha256"],
        "manifest_sha256": external_out["manifest_sha256"],
        "output_directory": str(out),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
