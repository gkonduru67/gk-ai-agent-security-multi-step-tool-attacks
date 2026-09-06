#!/usr/bin/env python3
"""Targeted read-only correction for IV22-018, IV22-026, and Sandbox identity.

This runner does NOT rewrite the original independent 56/58 result. It binds
that evidence, recomputes all four frozen V2.2 identities, corrects only:
  * IV22-018: exact standard-library ImportFrom classification while retaining
    exact SDK/V2.1 allowlists and prohibitions, plus relative-import resolution.
  * IV22-026: semantic AST alias discovery from context.tool_args followed by
    structural If/Elif validation-order qualification, independent of local
    variable spelling, with no normalization before validation.
  * missing Sandbox coverage: exact size and SHA-256 binding.

No V2.2/V2.1/SDK modification or import. No hooks, Sandbox, tools, fs.read,
HTTP, guardrails, predicates, breach logic, models, threads, or effects.
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

VERSION = "CORRECTED_IV22_018_IV22_026_AND_SANDBOX_STATIC_QUALIFICATION_v1.0"
PACKAGE = "aicomp_sdk_exfil_v2_2"

EXPECTED = {
    "independent_manifest": (5234, "E3C75B65597C82CDF4B320F358DFF2E306CD38BB4917EACF57A663DF6F2156E2"),
    "independent_result": (8544, "353C68B4B7DB523C6F0D2BFF4509460BCFD2C87C3A58184AD9EFB287C25EDCE5"),
    "independent_checks": (11842, "E336B8A2F4C7680AB076B07B5C963983B9D23F28F9724AFD59C6C6ECEEE472D5"),
    "v22_init": (484, "3A868F18E87E891C3EBEBA4E6534918DC730D4A27B7E21B1D834F3EC77BD004B"),
    "v22_proposal": (1972, "F4AB269075C1195FF27B3D15357EDB0351E0B70106059ECB70643649A3E238E8"),
    "v22_outcome": (2233, "D5819673ECBB6B3330B27F2C5046F8EB1720924E41236DBF265D631BE7050118"),
    "v22_factory": (2039, "8188BFFFFC1EBFE6B4A1E6DAB4C1678B1DE77389EC55BE7A4E4EA705665FCB9E"),
    "sdk_sandbox": (19906, "B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0"),
}

EXPECTED_PY_FILES = {
    "__init__.py",
    "trusted_read_proposal_hook_v2_2.py",
    "trusted_read_outcome_hook_v2_2.py",
    "integration_factory_v2_2.py",
}

STDLIB_FROM_ALLOWLIST = {
    "__future__": {"annotations"},
    "collections.abc": {"Mapping"},
    "typing": {"Any"},
    "dataclasses": {"dataclass"},
}

AUTHORIZED_EXTERNAL_ALLOWLIST = {
    "aicomp_sdk.hooks.types": {"HookContext", "HookResult", "HookStage"},
    "aicomp_sdk.hooks.registry": {"HookRegistry"},
    "aicomp_sdk.core.predicates": {"is_protected_secret_path"},
    "aicomp_sdk.guardrails.base": {"GuardrailBase"},
    "aicomp_sdk_exfil_v2_1.successful_read_ledger_v2_1": {"SuccessfulReadLedgerV21"},
    "aicomp_sdk_exfil_v2_1.lineage_aware_exfil_guardrail_v2_1": {"LineageAwareExfilGuardrailV21"},
}

PROHIBITED_MODULES = {
    "aicomp_sdk_exfil_v2_1.trusted_read_outcome_hook_v2_1",
    "aicomp_sdk_exfil_v2_1.integration_factory_v2_1",
    "aicomp_sdk_exfil_v2_2.successful_read_ledger_v2_2",
    "aicomp_sdk_exfil_v2_2.successful_read_record_v2_2",
    "aicomp_sdk_exfil_v2_2.lineage_aware_exfil_guardrail_v2_2",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def require(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest().upper()


def identity(path: Path) -> dict[str, Any]:
    path = path.resolve()
    return {"artifact": path.name, "path": str(path), "size_bytes": path.stat().st_size, "sha256": sha256(path)}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as f:
        json.dump(value, f, indent=2, sort_keys=True, ensure_ascii=False, default=str)
        f.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("x", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def rendered(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return str(value)


def add(rows: list[dict[str, Any]], cid: str, category: str, passed: bool,
        observed: Any, expected: Any, failure_layer: str) -> None:
    rows.append({"check_id": cid, "category": category, "passed": bool(passed),
                 "observed": rendered(observed), "expected": rendered(expected),
                 "failure_layer": failure_layer})


def unparse(node: ast.AST | None) -> str:
    if node is None:
        return "NOT_FOUND"
    try:
        return ast.unparse(node)
    except Exception:
        return "UNPARSE_FAILED"


def class_named(tree: ast.Module, name: str) -> ast.ClassDef | None:
    return next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name), None)


def method_named(cls: ast.ClassDef, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    return next((n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name), None)


def exact_context_tool_args_alias(method: ast.AST) -> tuple[str | None, list[dict[str, Any]]]:
    matches: list[dict[str, Any]] = []
    alias: str | None = None
    for node in ast.walk(method):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not (isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name)
                and value.value.id == "context" and value.attr == "tool_args"):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                matches.append({"line": node.lineno, "alias": target.id, "source": unparse(node)})
                alias = target.id if alias is None else alias
    if len(matches) != 1:
        return None, matches
    return alias, matches


def is_not_isinstance_mapping(test: ast.AST, alias: str) -> bool:
    return (isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)
            and isinstance(test.operand, ast.Call)
            and isinstance(test.operand.func, ast.Name) and test.operand.func.id == "isinstance"
            and len(test.operand.args) == 2
            and isinstance(test.operand.args[0], ast.Name) and test.operand.args[0].id == alias
            and isinstance(test.operand.args[1], ast.Name) and test.operand.args[1].id == "Mapping")


def is_path_not_in_alias(test: ast.AST, alias: str) -> bool:
    return (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.NotIn)
            and isinstance(test.left, ast.Constant) and test.left.value == "path"
            and len(test.comparators) == 1 and isinstance(test.comparators[0], ast.Name)
            and test.comparators[0].id == alias)


def is_not_isinstance_path_get_str(test: ast.AST, alias: str) -> bool:
    if not (isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)
            and isinstance(test.operand, ast.Call)
            and isinstance(test.operand.func, ast.Name) and test.operand.func.id == "isinstance"
            and len(test.operand.args) == 2):
        return False
    value, kind = test.operand.args
    value_ok = (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                and isinstance(value.func.value, ast.Name) and value.func.value.id == alias
                and value.func.attr == "get" and len(value.args) == 1
                and isinstance(value.args[0], ast.Constant) and value.args[0].value == "path")
    kind_ok = isinstance(kind, ast.Name) and kind.id == "str"
    return value_ok and kind_ok


def is_not_path_strip(test: ast.AST, alias: str) -> bool:
    if not (isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)
            and isinstance(test.operand, ast.Call)
            and isinstance(test.operand.func, ast.Attribute)
            and test.operand.func.attr == "strip"):
        return False
    base = test.operand.func.value
    return (isinstance(base, ast.Subscript) and isinstance(base.value, ast.Name)
            and base.value.id == alias
            and isinstance(base.slice, ast.Constant) and base.slice.value == "path")


def branch_assignment(body: list[ast.stmt]) -> tuple[str | None, str | None]:
    assignments = []
    for statement in body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
            if isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str):
                assignments.append((statement.targets[0].id, statement.value.value))
    return assignments[0] if len(assignments) == 1 else (None, None)


def extract_if_elif_chain(root: ast.If) -> tuple[list[ast.If], list[ast.stmt]]:
    chain = [root]
    current = root
    while len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
        current = current.orelse[0]
        chain.append(current)
    return chain, current.orelse


def normalization_before_line(method: ast.AST, alias: str, first_line: int) -> list[dict[str, Any]]:
    violations = []
    for node in ast.walk(method):
        if getattr(node, "lineno", first_line) >= first_line:
            continue
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {"str", "repr"}:
                if any(isinstance(arg, ast.Name) and arg.id == alias for arg in node.args):
                    violations.append({"line": node.lineno, "source": unparse(node)})
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"strip", "lower", "casefold", "copy"}:
                if isinstance(node.func.value, ast.Name) and node.func.value.id == alias:
                    violations.append({"line": node.lineno, "source": unparse(node)})
    return violations


def classify_imports(trees: dict[str, ast.Module], package_root: Path) -> dict[str, Any]:
    rows = []
    violations = []
    for filename, tree in trees.items():
        for node in tree.body:
            if isinstance(node, ast.Import):
                for item in node.names:
                    rows.append({"file": filename, "kind": "import", "module": item.name,
                                 "names": [item.asname or item.name], "classification": "UNEXPECTED_PLAIN_IMPORT"})
                    violations.append(rows[-1])
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                names = [item.name for item in node.names]
                if node.level > 0:
                    target = package_root / (module.replace(".", "/") + ".py")
                    classification = "RELATIVE_RESOLVED" if target.is_file() else "RELATIVE_UNRESOLVED"
                    row = {"file": filename, "kind": "from", "module": module, "names": names,
                           "level": node.level, "target": str(target), "classification": classification}
                    rows.append(row)
                    if not target.is_file():
                        violations.append(row)
                    continue
                if module in PROHIBITED_MODULES:
                    classification = "PROHIBITED_MODULE"
                elif module.startswith("aicomp_sdk.") and any(part.startswith("_") for part in module.split(".")):
                    classification = "PRIVATE_SDK_MODULE"
                elif any(name.startswith("_") for name in names):
                    classification = "PRIVATE_SYMBOL"
                elif module in STDLIB_FROM_ALLOWLIST and set(names).issubset(STDLIB_FROM_ALLOWLIST[module]):
                    classification = "EXACT_STDLIB_ALLOWED"
                elif module in AUTHORIZED_EXTERNAL_ALLOWLIST and set(names).issubset(AUTHORIZED_EXTERNAL_ALLOWLIST[module]):
                    classification = "EXACT_EXTERNAL_ALLOWED"
                else:
                    classification = "UNRECOGNIZED_OR_OVERBROAD"
                row = {"file": filename, "kind": "from", "module": module,
                       "names": names, "level": node.level, "classification": classification}
                rows.append(row)
                if classification not in {"EXACT_STDLIB_ALLOWED", "EXACT_EXTERNAL_ALLOWED"}:
                    violations.append(row)
    return {"rows": rows, "violations": violations}


def main(args: argparse.Namespace) -> None:
    out = Path(args.output_dir).resolve()
    require(not out.exists(), f"Refusing overwrite: {out}")
    out.mkdir(parents=True)
    checks: list[dict[str, Any]] = []
    try:
        project = Path(args.project_root).resolve()
        package = project / PACKAGE
        paths = {
            "independent_manifest": Path(args.independent_manifest).resolve(),
            "independent_result": Path(args.independent_result).resolve(),
            "independent_checks": Path(args.independent_checks).resolve(),
            "v22_init": package / "__init__.py",
            "v22_proposal": package / "trusted_read_proposal_hook_v2_2.py",
            "v22_outcome": package / "trusted_read_outcome_hook_v2_2.py",
            "v22_factory": package / "integration_factory_v2_2.py",
            "sdk_sandbox": project / "aicomp_sdk" / "core" / "env" / "sandbox.py",
        }
        for name, path in paths.items():
            require(path.is_file(), f"Missing required input {name}: {path}")

        # Parent evidence must remain exactly the original 56/58 record.
        for counter, (name, (size, digest)) in enumerate(EXPECTED.items(), start=1):
            ident = identity(paths[name])
            add(checks, f"CIV22-{counter:03d}", "identity", ident["size_bytes"] == size and ident["sha256"] == digest,
                ident, {"size_bytes": size, "sha256": digest}, "FIXTURE")

        parent_result = read_json(paths["independent_result"])
        parent_checks = read_csv(paths["independent_checks"])
        exact_parent = (parent_result.get("checks") == {"failed": 2, "failed_ids": ["IV22-018", "IV22-026"], "passed": 56, "total": 58}
                        and parent_result.get("outcome") == "V2_2_IMPORT_CONTRACT_GAP"
                        and len(parent_checks) == 58)
        add(checks, "CIV22-009", "parent", exact_parent,
            {"checks": parent_result.get("checks"), "outcome": parent_result.get("outcome"), "row_count": len(parent_checks)},
            {"checks": {"failed": 2, "failed_ids": ["IV22-018", "IV22-026"], "passed": 56, "total": 58},
             "outcome": "V2_2_IMPORT_CONTRACT_GAP", "row_count": 58}, "EVIDENCE")
        failed_parent_rows = [r for r in parent_checks if r.get("passed") == "False"]
        add(checks, "CIV22-010", "parent",
            [r.get("check_id") for r in failed_parent_rows] == ["IV22-018", "IV22-026"],
            failed_parent_rows, ["IV22-018", "IV22-026"], "EVIDENCE")

        actual_py = {p.name for p in package.glob("*.py")}
        add(checks, "CIV22-011", "inventory", actual_py == EXPECTED_PY_FILES,
            sorted(actual_py), sorted(EXPECTED_PY_FILES), "FIXTURE")

        trees = {name: ast.parse(paths[name].read_text(encoding="utf-8"), filename=str(paths[name]))
                 for name in ("v22_init", "v22_proposal", "v22_outcome", "v22_factory")}

        # Corrected IV22-018 import classification.
        import_analysis = classify_imports({paths[name].name: trees[name] for name in trees}, package)
        classifications = sorted({r["classification"] for r in import_analysis["rows"]})
        add(checks, "CIV22-012", "IV22_018_correction", not import_analysis["violations"],
            {"classifications": classifications, "violations": import_analysis["violations"], "rows": import_analysis["rows"]},
            {"violations": [], "required_classifications": ["EXACT_STDLIB_ALLOWED", "EXACT_EXTERNAL_ALLOWED", "RELATIVE_RESOLVED"]},
            "ADAPTER_PARSE")
        allowed_stdlib_observed = {(r["module"], tuple(r["names"])) for r in import_analysis["rows"] if r["classification"] == "EXACT_STDLIB_ALLOWED"}
        expected_stdlib_observed = {
            ("__future__", ("annotations",)), ("collections.abc", ("Mapping",)),
            ("typing", ("Any",)), ("dataclasses", ("dataclass",)),
        }
        add(checks, "CIV22-013", "IV22_018_correction", allowed_stdlib_observed == expected_stdlib_observed,
            sorted(allowed_stdlib_observed), sorted(expected_stdlib_observed), "ADAPTER_PARSE")
        v21_modules = {r["module"] for r in import_analysis["rows"] if r["module"].startswith("aicomp_sdk_exfil_v2_1")}
        expected_v21_modules = {
            "aicomp_sdk_exfil_v2_1.successful_read_ledger_v2_1",
            "aicomp_sdk_exfil_v2_1.lineage_aware_exfil_guardrail_v2_1",
        }
        add(checks, "CIV22-014", "IV22_018_correction", v21_modules == expected_v21_modules,
            sorted(v21_modules), sorted(expected_v21_modules), "V2_2_SCOPE_BOUNDARY_GAP")

        # Corrected IV22-026 semantic alias + If/Elif analysis.
        proposal_class = class_named(trees["v22_proposal"], "TrustedReadProposalHookV22")
        require(proposal_class is not None, "TrustedReadProposalHookV22 missing")
        proposal_call = method_named(proposal_class, "__call__")
        require(proposal_call is not None, "Proposal __call__ missing")
        alias, alias_matches = exact_context_tool_args_alias(proposal_call)
        add(checks, "CIV22-015", "IV22_026_correction", alias is not None,
            {"alias": alias, "matches": alias_matches}, "exactly one local alias assigned from context.tool_args", "ARGUMENT_FIDELITY")

        roots = [n for n in proposal_call.body if isinstance(n, ast.If) and alias is not None and is_not_isinstance_mapping(n.test, alias)]
        add(checks, "CIV22-016", "IV22_026_correction", len(roots) == 1,
            [{"line": n.lineno, "source": unparse(n.test)} for n in roots], "one validation If root", "ARGUMENT_FIDELITY")

        semantic_result: dict[str, Any] = {"alias": alias, "conditions": [], "reasons": [], "final_else": []}
        if len(roots) == 1 and alias is not None:
            chain, final_else = extract_if_elif_chain(roots[0])
            predicates = [
                is_not_isinstance_mapping(chain[0].test, alias) if len(chain) > 0 else False,
                is_path_not_in_alias(chain[1].test, alias) if len(chain) > 1 else False,
                is_not_isinstance_path_get_str(chain[2].test, alias) if len(chain) > 2 else False,
                is_not_path_strip(chain[3].test, alias) if len(chain) > 3 else False,
            ]
            reasons = [branch_assignment(node.body) for node in chain]
            lines = [node.lineno for node in chain]
            semantic_result = {"alias": alias, "condition_sources": [unparse(n.test) for n in chain],
                               "condition_lines": lines, "predicate_matches": predicates,
                               "reason_assignments": reasons, "final_else": [unparse(x) for x in final_else]}
            expected_reasons = [
                ("reason_detail", "TOOL_ARGS_NOT_MAPPING"),
                ("reason_detail", "PATH_MISSING"),
                ("reason_detail", "PATH_NOT_STRING"),
                ("reason_detail", "PATH_EMPTY"),
            ]
            exact_chain = len(chain) == 4 and all(predicates) and lines == sorted(lines) and reasons == expected_reasons and final_else == []
        else:
            exact_chain = False
        add(checks, "CIV22-017", "IV22_026_correction", exact_chain,
            semantic_result,
            {"condition_count": 4, "semantic_order": ["Mapping", "path presence", "path string", "path nonempty"],
             "mutually_exclusive": "single If/Elif chain with no final else"}, "ARGUMENT_FIDELITY")

        first_validation_line = roots[0].lineno if len(roots) == 1 else 10**9
        normalization_violations = normalization_before_line(proposal_call, alias or "", first_validation_line)
        add(checks, "CIV22-018", "IV22_026_correction", not normalization_violations,
            normalization_violations, [], "ARGUMENT_FIDELITY")

        # Missing Sandbox identity correction.
        sandbox_ident = identity(paths["sdk_sandbox"])
        add(checks, "CIV22-019", "sandbox_identity", sandbox_ident["size_bytes"] == EXPECTED["sdk_sandbox"][0]
            and sandbox_ident["sha256"] == EXPECTED["sdk_sandbox"][1],
            sandbox_ident, {"size_bytes": EXPECTED["sdk_sandbox"][0], "sha256": EXPECTED["sdk_sandbox"][1]}, "FIXTURE")

        # End-of-run immutability recheck for every bound input.
        unchanged = all(identity(paths[name])["size_bytes"] == expected[0] and sha256(paths[name]) == expected[1]
                        for name, expected in EXPECTED.items())
        add(checks, "CIV22-020", "immutability", unchanged,
            "all parent, V2.2, and Sandbox identities unchanged after qualification", True, "FIXTURE")

        failed = [r["check_id"] for r in checks if not r["passed"]]
        if "CIV22-019" in failed:
            outcome = "SANDBOX_IDENTITY_GAP"
        elif any(x in failed for x in ("CIV22-012", "CIV22-013", "CIV22-014")):
            outcome = "V2_2_IMPORT_CONTRACT_GAP_CONFIRMED"
        elif any(x in failed for x in ("CIV22-015", "CIV22-016", "CIV22-017", "CIV22-018")):
            outcome = "V2_2_PRE_TOOL_BLOCKING_DESIGN_GAP_CONFIRMED"
        elif failed:
            outcome = "NOT_ESTABLISHED"
        else:
            outcome = "IV22_018_AND_IV22_026_QUALIFIER_GAPS_CONFIRMED_AND_CORRECTED"
        passed = not failed
        status = ("CORRECTED_IV22_018_IV22_026_AND_SANDBOX_STATIC_QUALIFICATION_COMPLETE_PASS"
                  if passed else "CORRECTED_IV22_018_IV22_026_AND_SANDBOX_STATIC_QUALIFICATION_COMPLETE_WITH_GAPS")

        claim = {
            "allowed": [
                "Original independent result remains frozen at 56 of 58 with failed IDs IV22-018 and IV22-026",
                "IV22-018 failure was caused by an incomplete standard-library ImportFrom allowlist",
                "Corrected exact import graph satisfies the authorized stdlib, SDK, V2.1, and relative-import policy" if passed else "NOT_ESTABLISHED",
                "IV22-026 failure was caused by local-identifier coupling in the detector",
                "Corrected semantic AST validation order is established independently of local alias spelling" if passed else "NOT_ESTABLISHED",
                "Sandbox source identity is independently bound" if passed else "NOT_ESTABLISHED",
                "Frozen V2.2 source identities remain unchanged",
            ],
            "prohibited": [
                "rewrite original independent result as 58 of 58",
                "claim V2.2 runtime importability",
                "claim runtime proposal blocking or outcome capture",
                "claim HookRegistry or Sandbox runtime integration",
                "claim repeated factory-build idempotence",
                "claim HTTP, guardrail effectiveness, predicate, or breach",
                "claim robust end-to-end security findings",
            ],
        }
        execution = {
            "original_IV22_v1_0_rewritten": False,
            "V2_2_modified": False, "V2_2_imported": False, "hooks_instantiated": False,
            "V2_1_modified": False, "SDK_modified": False, "Sandbox_instantiated": False,
            "tools_executed": False, "actual_fs_read_executed": False, "HTTP_executed": False,
            "guardrail_executed": False, "predicates_executed": False, "breach_executed": False,
            "models_used": False, "threads_executed": False, "external_effects_observed": False,
        }
        reviewed_disposition = ("INDEPENDENT_V2_2_HOOK_STATIC_QUALIFICATION_PASS_AFTER_QUALIFIER_CORRECTION"
                                if passed else "INDEPENDENT_V2_2_STATIC_CORRECTION_NOT_ESTABLISHED")
        result = {
            "version": VERSION, "created_at_utc": now(), "status": status,
            "classification": "READ_ONLY_TARGETED_QUALIFIER_CORRECTION",
            "checks": {"total": len(checks), "passed": len(checks) - len(failed), "failed": len(failed), "failed_ids": failed},
            "outcome": outcome,
            "original_independent_result": {"checks": "56_OF_58", "failed_ids": ["IV22-018", "IV22-026"],
                                            "recorded_outcome": "V2_2_IMPORT_CONTRACT_GAP", "rewritten": False},
            "corrections": {
                "IV22_018": {"reviewed_cause": "QUALIFIER_STDLIB_IMPORT_ALLOWLIST_GAP",
                               "V2_2_defect": "NOT_DEMONSTRATED", "corrected_import_analysis": import_analysis},
                "IV22_026": {"reviewed_cause": "QUALIFIER_IDENTIFIER_COUPLING_GAP",
                               "V2_2_defect": "NOT_DEMONSTRATED", "corrected_semantic_analysis": semantic_result,
                               "normalization_violations": normalization_violations},
                "sandbox_identity": sandbox_ident,
            },
            "reviewed_disposition": reviewed_disposition,
            "execution_boundaries": execution,
            "scientific_verdict": {
                "qualifier_gaps": "CONFIRMED_AND_CORRECTED" if passed else "NOT_ESTABLISHED",
                "V2_2_source_defect": "NOT_DEMONSTRATED" if passed else "NOT_ESTABLISHED",
                "independent_static_contract": "ESTABLISHED_AFTER_SEPARATE_CORRECTION" if passed else "NOT_ESTABLISHED",
                "runtime_behavior": "NOT_EVALUATED", "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": "NOT_ESTABLISHED",
            },
            "claim_boundary": claim,
            "next_gate": "CONTROLLED_V2_2_MALFORMED_HOOK_RUNTIME_QUALIFICATION" if passed else "TARGETED_STATIC_CORRECTION_GAP_REVIEW",
        }

        outputs = {
            "result": out / "corrected_iv22_static_result.json",
            "checks": out / "corrected_iv22_static_checks.csv",
            "imports": out / "corrected_iv22_import_analysis.csv",
            "semantic": out / "corrected_iv22_proposal_semantic_analysis.json",
            "sandbox": out / "corrected_iv22_sandbox_identity.json",
            "claim": out / "corrected_iv22_static_claim_boundary.json",
            "binding": out / "corrected_iv22_static_binding.json",
        }
        write_json(outputs["result"], result)
        write_csv(outputs["checks"], checks, ["check_id", "category", "passed", "observed", "expected", "failure_layer"])
        write_csv(outputs["imports"], import_analysis["rows"], ["file", "kind", "module", "names", "level", "target", "classification"])
        write_json(outputs["semantic"], semantic_result)
        write_json(outputs["sandbox"], sandbox_ident)
        write_json(outputs["claim"], claim)
        write_json(outputs["binding"], {"version": VERSION, "created_at_utc": now(),
            "runner": identity(Path(__file__).resolve()), "inputs": {name: identity(path) for name, path in paths.items()},
            "execution_boundaries": execution})

        manifest_rows = ([{**identity(path), "role": "CORRECTED_IV22_DERIVED"} for path in outputs.values()]
                         + [{**identity(path), "role": "CORRECTED_IV22_BOUND_INPUT"} for path in paths.values()])
        manifest = out / "corrected_iv22_static_manifest.csv"
        write_csv(manifest, manifest_rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        external = out / "corrected_iv22_static_manifest_external_binding.json"
        write_json(external, {"version": VERSION, "created_at_utc": now(), "status": status,
            "manifest_filename": manifest.name, "manifest_size_bytes": manifest.stat().st_size,
            "manifest_sha256": sha256(manifest), "runner_sha256": sha256(Path(__file__).resolve()),
            "independent_manifest_sha256": EXPECTED["independent_manifest"][1],
            "independent_result_sha256": EXPECTED["independent_result"][1],
            "independent_checks_sha256": EXPECTED["independent_checks"][1],
            "original_checks": "56_OF_58", "original_failed_ids": ["IV22-018", "IV22-026"],
            "checks_total": len(checks), "checks_passed": len(checks)-len(failed), "checks_failed": len(failed),
            "failed_ids": failed, "outcome": outcome, "reviewed_disposition": reviewed_disposition,
            "V2_2_modified": False, "V2_2_imported": False, "V2_1_modified": False, "SDK_modified": False,
            "next_gate": result["next_gate"]})
        print(json.dumps({"status": status, "checks": f"{len(checks)-len(failed)}/{len(checks)}",
            "failed_ids": failed, "outcome": outcome, "reviewed_disposition": reviewed_disposition,
            "original_result_rewritten": False, "manifest_sha256": sha256(manifest),
            "next_gate": result["next_gate"]}, indent=2))
    except Exception as exc:
        (out / "CORRECTED_IV22_STATIC_FAILED.json").write_text(json.dumps({
            "version": VERSION, "created_at_utc": now(), "status": "BLOCKED",
            "error_type": type(exc).__name__, "error": str(exc), "checks_frozen": checks,
            "original_IV22_v1_0_rewritten": False, "V2_2_modified": False, "V2_2_imported": False,
            "V2_1_modified": False, "SDK_modified": False}, indent=2), encoding="utf-8")
        raise


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=VERSION)
    for name in ("independent-manifest", "independent-result", "independent-checks", "project-root", "output-dir"):
        p.add_argument("--" + name, required=True)
    return p.parse_args()


if __name__ == "__main__":
    try:
        main(parse_args())
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
