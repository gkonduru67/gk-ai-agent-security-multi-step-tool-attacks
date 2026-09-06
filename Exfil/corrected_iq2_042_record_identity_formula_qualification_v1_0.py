#!/usr/bin/env python3
"""Corrected IQ2-042 record-identity formula qualification v1.0.

Read-only targeted correction for the independent V2 qualifier's IQ2-042.
The runner binds the frozen 59/60 result, locates _record_identity_v2 through
AST, inspects only the assignment to `material`, extracts f-string formatted
expressions in AST order, validates pipe separators and the hash consumer, and
revalidates IQ2-043/IQ2-044 independently.

It does not modify, import, instantiate, or execute V2, V1, SDK, restore,
candidate extraction, predicates, Sandbox, Gym, tools, fs.read, HTTP, breach,
models, threads, or external effects.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "CORRECTED_IQ2_042_RECORD_IDENTITY_FORMULA_QUALIFICATION_v1.0"
PARENT_VERSION = "INDEPENDENT_STATEFUL_GUARDRAIL_V2_STATIC_QUALIFICATION_v1.0"
PARENT_STATUS = "INDEPENDENT_STATEFUL_GUARDRAIL_V2_STATIC_QUALIFICATION_COMPLETE_WITH_GAPS"
EXPECTED_FAILED_ID = "IQ2-042"
EXPECTED_FIELDS = [
    "RECORD_TAG_V2",
    "sequence",
    "tool_name",
    "canonical_path",
    "tool_args_digest",
    "output_digest",
]
EXPECTED = {
    "independent_result": "684935BC42F9C76EE527D42418A0C740AB95538317A67D27BD994411D3638815",
    "independent_checks": "80528F668B3BA3EFC718FB212DDA2BABD2C4E4C59007972A82DE308EB6937D9D",
    "independent_manifest": "205284E446C3FD3890478ECC4C7666A2CECF3363B6AC727AE20EC07D42F63993",
    "independent_binding": "2D44913F93E698F9141403699F38B09EA2E6F1AFA4FA14683401E1D45222E49E",
    "independent_runner": "CE725396E2836E0C4686F0B06E5B5588980992F0FA3F388E1452116104757C9C",
    "v2_manifest": "E4012BAEE67A8B93D4B54DEA90415CB4E5A38B4385DC301EF50D9B2E748A9521",
    "v2_ledger": "609B22AA7ABD3555B24484E2AF313A5460877BA3C446FBE2978C6136D662857E",
}
V2_LEDGER_SIZE = 6645


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def identity(path: Path) -> dict[str, object]:
    path = path.resolve()
    return {
        "artifact": path.name,
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str]) -> None:
    with path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fields,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def add_check(
    rows: list[dict[str, object]],
    check_id: str,
    category: str,
    passed: bool,
    observed: object,
    expected: object,
    failure_layer: str,
) -> None:
    rows.append(
        {
            "check_id": check_id,
            "category": category,
            "passed": bool(passed),
            "observed": str(observed),
            "expected": str(expected),
            "failure_layer": failure_layer,
        }
    )


def unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return "UNPARSE_FAILED"


def top_functions(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def class_methods(node: ast.ClassDef) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {
        child.name: child
        for child in node.body
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def named_calls(node: ast.AST, terminal_name: str) -> list[ast.Call]:
    calls: list[ast.Call] = []
    for candidate in ast.walk(node):
        if isinstance(candidate, ast.Call) and unparse(candidate.func).endswith(terminal_name):
            calls.append(candidate)
    return calls


def assigned_name(node: ast.Assign | ast.AnnAssign, name: str) -> bool:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return any(isinstance(target, ast.Name) and target.id == name for target in targets)


def joined_string_analysis(node: ast.JoinedStr) -> tuple[list[str], list[str]]:
    fields: list[str] = []
    literal_parts: list[str] = []
    for value in node.values:
        if isinstance(value, ast.FormattedValue):
            fields.append(unparse(value.value))
        elif isinstance(value, ast.Constant) and isinstance(value.value, str):
            literal_parts.append(value.value)
        else:
            literal_parts.append(f"UNEXPECTED:{type(value).__name__}")
    return fields, literal_parts


def main(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir).resolve()
    require(not output_dir.exists(), f"Refusing overwrite: {output_dir}")
    output_dir.mkdir(parents=True)
    checks: list[dict[str, object]] = []

    try:
        project_root = Path(args.project_root).resolve()
        ledger = project_root / "aicomp_sdk_exfil_v2" / "successful_read_ledger_v2.py"
        parent = {
            "independent_result": Path(args.independent_result).resolve(),
            "independent_checks": Path(args.independent_checks).resolve(),
            "independent_manifest": Path(args.independent_manifest).resolve(),
            "independent_binding": Path(args.independent_binding).resolve(),
            "independent_runner": Path(args.independent_runner).resolve(),
            "v2_manifest": Path(args.v2_manifest).resolve(),
            "v2_ledger": ledger,
        }
        for name, path in parent.items():
            require(path.is_file(), f"Missing required input {name}: {path}")

        result = read_json(parent["independent_result"])
        original_checks = read_csv(parent["independent_checks"])

        add_check(
            checks,
            "C42-001",
            "parent",
            isinstance(result, dict)
            and result.get("version") == PARENT_VERSION
            and result.get("status") == PARENT_STATUS,
            result.get("status") if isinstance(result, dict) else type(result).__name__,
            PARENT_STATUS,
            "FIXTURE",
        )
        for index, (name, expected_hash) in enumerate(EXPECTED.items(), start=2):
            actual_hash = sha256_file(parent[name])
            add_check(
                checks,
                f"C42-{index:03d}",
                "identity",
                actual_hash == expected_hash,
                actual_hash,
                expected_hash,
                "FIXTURE",
            )

        failed_rows = [row for row in original_checks if row.get("passed") != "True"]
        preserved_59_of_60 = (
            len(original_checks) == 60
            and sum(row.get("passed") == "True" for row in original_checks) == 59
            and [row.get("check_id") for row in failed_rows] == [EXPECTED_FAILED_ID]
        )
        add_check(
            checks,
            "C42-009",
            "parent",
            preserved_59_of_60,
            {
                "total": len(original_checks),
                "passed": sum(row.get("passed") == "True" for row in original_checks),
                "failed": [row.get("check_id") for row in failed_rows],
            },
            "59/60 with only IQ2-042 failed",
            "EVIDENCE",
        )
        add_check(
            checks,
            "C42-010",
            "identity",
            ledger.stat().st_size == V2_LEDGER_SIZE,
            ledger.stat().st_size,
            V2_LEDGER_SIZE,
            "FIXTURE",
        )

        source_text = ledger.read_text(encoding="utf-8")
        tree = ast.parse(source_text, filename=str(ledger))
        functions = top_functions(tree)
        identity_function = functions.get("_record_identity_v2")
        add_check(
            checks,
            "C42-011",
            "formula",
            isinstance(identity_function, ast.FunctionDef),
            identity_function.name if isinstance(identity_function, ast.FunctionDef) else None,
            "_record_identity_v2",
            "PROVENANCE",
        )
        require(isinstance(identity_function, ast.FunctionDef), "_record_identity_v2 not established")

        material_assignments = [
            node
            for node in ast.walk(identity_function)
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and assigned_name(node, "material")
        ]
        add_check(
            checks,
            "C42-012",
            "formula",
            len(material_assignments) == 1,
            len(material_assignments),
            1,
            "PROVENANCE",
        )
        require(len(material_assignments) == 1, "Exactly one material assignment not established")

        material_assignment = material_assignments[0]
        material_value = material_assignment.value
        add_check(
            checks,
            "C42-013",
            "formula",
            isinstance(material_value, ast.JoinedStr),
            type(material_value).__name__,
            "JoinedStr",
            "PROVENANCE",
        )

        formatted_fields: list[str] = []
        literal_parts: list[str] = []
        if isinstance(material_value, ast.JoinedStr):
            formatted_fields, literal_parts = joined_string_analysis(material_value)

        add_check(
            checks,
            "C42-014",
            "formula",
            formatted_fields == EXPECTED_FIELDS,
            formatted_fields,
            EXPECTED_FIELDS,
            "PROVENANCE",
        )

        combined_literals = "".join(
            part for part in literal_parts if not part.startswith("UNEXPECTED:")
        )
        unexpected_literal_nodes = [
            part for part in literal_parts if part.startswith("UNEXPECTED:")
        ]
        add_check(
            checks,
            "C42-015",
            "formula",
            not unexpected_literal_nodes and combined_literals == "|||||",
            {
                "literal_parts": literal_parts,
                "combined": combined_literals,
                "pipe_count": combined_literals.count("|"),
            },
            {"combined": "|||||", "pipe_count": 5},
            "PROVENANCE",
        )

        return_nodes = [
            node for node in identity_function.body if isinstance(node, ast.Return)
        ]
        hash_consumes_material = False
        return_expression = None
        if len(return_nodes) == 1 and return_nodes[0].value is not None:
            return_expression = unparse(return_nodes[0].value)
            value = return_nodes[0].value
            hash_consumes_material = (
                isinstance(value, ast.Call)
                and unparse(value.func) == "_sha256_text_v2"
                and len(value.args) == 1
                and isinstance(value.args[0], ast.Name)
                and value.args[0].id == "material"
                and not value.keywords
            )
        add_check(
            checks,
            "C42-016",
            "formula",
            len(return_nodes) == 1 and hash_consumes_material,
            {"return_count": len(return_nodes), "expression": return_expression},
            "return _sha256_text_v2(material)",
            "PROVENANCE",
        )

        ledger_class = next(
            (
                node
                for node in tree.body
                if isinstance(node, ast.ClassDef) and node.name == "SuccessfulReadLedgerV2"
            ),
            None,
        )
        require(isinstance(ledger_class, ast.ClassDef), "SuccessfulReadLedgerV2 missing")
        ledger_methods = class_methods(ledger_class)
        append_method = ledger_methods.get("append_successful_read")
        restore_method = ledger_methods.get("restore_state")
        require(append_method is not None and restore_method is not None, "append/restore missing")

        append_calls = named_calls(append_method, "_record_identity_v2")
        restore_calls = named_calls(restore_method, "_record_identity_v2")
        add_check(
            checks,
            "C42-017",
            "supporting_evidence",
            len(append_calls) == 1 and len(restore_calls) == 1,
            {"append": len(append_calls), "restore": len(restore_calls)},
            {"append": 1, "restore": 1},
            "PROVENANCE",
        )

        def keyword_order(call: ast.Call) -> list[str | None]:
            return [keyword.arg for keyword in call.keywords]

        expected_call_fields = EXPECTED_FIELDS[1:]
        append_order = keyword_order(append_calls[0]) if len(append_calls) == 1 else []
        restore_order = keyword_order(restore_calls[0]) if len(restore_calls) == 1 else []
        add_check(
            checks,
            "C42-018",
            "supporting_evidence",
            append_order == restore_order == expected_call_fields,
            {"append": append_order, "restore": restore_order},
            expected_call_fields,
            "PROVENANCE",
        )

        original_iq2_042 = next(
            (row for row in original_checks if row.get("check_id") == "IQ2-042"),
            None,
        )
        original_iq2_043 = next(
            (row for row in original_checks if row.get("check_id") == "IQ2-043"),
            None,
        )
        original_iq2_044 = next(
            (row for row in original_checks if row.get("check_id") == "IQ2-044"),
            None,
        )
        add_check(
            checks,
            "C42-019",
            "historical_consistency",
            original_iq2_042 is not None
            and original_iq2_042.get("passed") == "False"
            and original_iq2_043 is not None
            and original_iq2_043.get("passed") == "True"
            and original_iq2_044 is not None
            and original_iq2_044.get("passed") == "True",
            {
                "IQ2-042": original_iq2_042.get("passed") if original_iq2_042 else None,
                "IQ2-043": original_iq2_043.get("passed") if original_iq2_043 else None,
                "IQ2-044": original_iq2_044.get("passed") if original_iq2_044 else None,
            },
            {"IQ2-042": "False", "IQ2-043": "True", "IQ2-044": "True"},
            "EVIDENCE",
        )

        formula_check_ids = [
            "C42-011",
            "C42-012",
            "C42-013",
            "C42-014",
            "C42-015",
            "C42-016",
            "C42-017",
            "C42-018",
        ]
        by_id = {row["check_id"]: row for row in checks}
        formula_pass = all(by_id[check_id]["passed"] for check_id in formula_check_ids)
        parent_pass = all(
            row["passed"] for row in checks if row["check_id"] <= "C42-010"
        )

        if not parent_pass:
            outcome = "NOT_ESTABLISHED"
        elif formula_pass and preserved_59_of_60:
            outcome = "IQ2_042_QUALIFIER_METHOD_GAP_CONFIRMED"
        elif not formula_pass:
            outcome = "V2_RECORD_IDENTITY_FORMULA_GAP_CONFIRMED"
        else:
            outcome = "NOT_ESTABLISHED"

        failed_ids = [row["check_id"] for row in checks if not row["passed"]]
        status = (
            "CORRECTED_IQ2_042_RECORD_IDENTITY_FORMULA_QUALIFICATION_COMPLETE_PASS"
            if outcome == "IQ2_042_QUALIFIER_METHOD_GAP_CONFIRMED"
            else "CORRECTED_IQ2_042_RECORD_IDENTITY_FORMULA_QUALIFICATION_COMPLETE_WITH_GAPS"
        )
        reviewed_static_disposition = (
            "INDEPENDENT_V2_STATIC_QUALIFICATION_PASS_AFTER_METHOD_CORRECTION"
            if outcome == "IQ2_042_QUALIFIER_METHOD_GAP_CONFIRMED"
            else "INDEPENDENT_V2_STATIC_QUALIFICATION_REMAINS_BLOCKED"
        )
        next_gate = (
            "CONTROLLED_SUCCESSFUL_FS_READ_LEDGER_QUALIFICATION"
            if outcome == "IQ2_042_QUALIFIER_METHOD_GAP_CONFIRMED"
            else (
                "V2_RECORD_IDENTITY_IMPLEMENTATION_REPAIR"
                if outcome == "V2_RECORD_IDENTITY_FORMULA_GAP_CONFIRMED"
                else "IQ2_042_EVIDENCE_REVIEW"
            )
        )

        claim_boundary = {
            "allowed": [
                "preserve the original 59-of-60 independent V2 result",
                "classify IQ2-042 using only the material f-string AST",
                "freeze ordered identity-material fields and pipe separators",
                "freeze that _sha256_text_v2 consumes material",
                "retain IQ2-043 and IQ2-044 as separate supporting evidence",
                "assign the reviewed independent V2 static disposition",
            ],
            "prohibited": [
                "modify V2, V1, or aicomp_sdk",
                "claim V2 importability by execution",
                "claim runtime restore rejection",
                "claim runtime candidate parity",
                "claim successful fs.read capture",
                "claim protected-value lineage",
                "claim guardrail effectiveness",
                "claim robust security findings",
            ],
        }
        result_document = {
            "version": VERSION,
            "created_at_utc": utc_now(),
            "status": status,
            "classification": "READ_ONLY_TARGETED_STATIC_METHOD_CORRECTION",
            "checks": {
                "total": len(checks),
                "passed": len(checks) - len(failed_ids),
                "failed": len(failed_ids),
                "failed_ids": failed_ids,
            },
            "preserved_recorded_result": {
                "checks_total": 60,
                "checks_passed": 59,
                "checks_failed": 1,
                "failed_ids": ["IQ2-042"],
                "recorded_outcome": "V2_RESTORE_IDENTITY_GAP",
            },
            "corrected_IQ2_042": {
                "material_assignment_count": len(material_assignments),
                "material_expression_type": type(material_value).__name__,
                "formatted_value_order": formatted_fields,
                "literal_parts": literal_parts,
                "pipe_count": combined_literals.count("|"),
                "hash_consumes_material": hash_consumes_material,
                "append_identity_call_count": len(append_calls),
                "restore_identity_call_count": len(restore_calls),
                "append_keyword_order": append_order,
                "restore_keyword_order": restore_order,
            },
            "outcome": outcome,
            "reviewed_static_disposition": reviewed_static_disposition,
            "readiness": {
                "controlled_successful_fs_read_ledger_qualification_eligible": outcome
                == "IQ2_042_QUALIFIER_METHOD_GAP_CONFIRMED",
                "controlled_actual_fs_read_eligible": False,
                "http_sink_eligible": False,
            },
            "execution_boundaries": {
                "V2_modified": False,
                "V1_modified": False,
                "frozen_aicomp_sdk_modified": False,
                "V2_imported": False,
                "V2_instantiated": False,
                "restore_executed": False,
                "candidate_extraction_executed": False,
                "predicates_executed": False,
                "Sandbox_instantiated": False,
                "Gym_executed": False,
                "actual_fs_read_executed": False,
                "http_sink_executed": False,
                "breach_executed": False,
                "models_used": False,
                "threads_executed": False,
                "external_effects_observed": False,
            },
            "scientific_verdict": {
                "IQ2_042": outcome,
                "V2_record_identity_formula": (
                    "ESTABLISHED_STATICALLY"
                    if outcome == "IQ2_042_QUALIFIER_METHOD_GAP_CONFIRMED"
                    else "NOT_ESTABLISHED"
                ),
                "V2_runtime_behavior": "NOT_EVALUATED",
                "protected_value_lineage": "NOT_ESTABLISHED",
                "guardrail_effectiveness": "NOT_EVALUATED",
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": "NOT_ESTABLISHED",
            },
            "claim_boundary": claim_boundary,
            "next_gate": next_gate,
        }

        outputs = {
            "result": output_dir / "corrected_iq2_042_result.json",
            "checks": output_dir / "corrected_iq2_042_checks.csv",
            "formula": output_dir / "corrected_iq2_042_formula_ast.json",
            "claim": output_dir / "corrected_iq2_042_claim_boundary.json",
            "binding": output_dir / "corrected_iq2_042_binding.json",
        }
        write_json(outputs["result"], result_document)
        write_csv(
            outputs["checks"],
            checks,
            ["check_id", "category", "passed", "observed", "expected", "failure_layer"],
        )
        write_json(
            outputs["formula"],
            {
                "source_file": identity(ledger),
                "function": "_record_identity_v2",
                "function_line_start": identity_function.lineno,
                "function_line_end": getattr(identity_function, "end_lineno", identity_function.lineno),
                "material_assignment_line": material_assignment.lineno,
                "material_assignment_source": unparse(material_assignment),
                "material_expression_type": type(material_value).__name__,
                "formatted_value_order": formatted_fields,
                "literal_parts": literal_parts,
                "combined_literals": combined_literals,
                "pipe_count": combined_literals.count("|"),
                "return_expression": return_expression,
                "hash_consumes_material": hash_consumes_material,
                "append_identity_keyword_order": append_order,
                "restore_identity_keyword_order": restore_order,
            },
        )
        write_json(outputs["claim"], claim_boundary)
        write_json(
            outputs["binding"],
            {
                "version": VERSION,
                "created_at_utc": utc_now(),
                "runner": identity(Path(__file__).resolve()),
                "inputs": {name: identity(path) for name, path in parent.items()},
                "V2_modified": False,
                "V1_modified": False,
                "frozen_aicomp_sdk_modified": False,
                "V2_imported": False,
                "restore_executed": False,
            },
        )

        manifest_rows = [
            {**identity(path), "role": "CORRECTED_IQ2_042_DERIVED"}
            for path in outputs.values()
        ] + [
            {**identity(path), "role": "CORRECTED_IQ2_042_BOUND_INPUT"}
            for path in parent.values()
        ]
        manifest = output_dir / "corrected_iq2_042_manifest.csv"
        write_csv(manifest, manifest_rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        external = output_dir / "corrected_iq2_042_manifest_external_binding.json"
        write_json(
            external,
            {
                "version": VERSION,
                "created_at_utc": utc_now(),
                "status": status,
                "manifest_filename": manifest.name,
                "manifest_size_bytes": manifest.stat().st_size,
                "manifest_sha256": sha256_file(manifest),
                "runner_sha256": sha256_file(Path(__file__).resolve()),
                "parent_independent_manifest_sha256": EXPECTED["independent_manifest"],
                "V2_implementation_manifest_sha256": EXPECTED["v2_manifest"],
                "checks_total": len(checks),
                "checks_passed": len(checks) - len(failed_ids),
                "checks_failed": len(failed_ids),
                "failed_ids": failed_ids,
                "outcome": outcome,
                "reviewed_static_disposition": reviewed_static_disposition,
                "V2_modified": False,
                "V2_imported": False,
                "controlled_actual_fs_read_eligible": False,
                "next_gate": next_gate,
            },
        )

        print(
            json.dumps(
                {
                    "status": status,
                    "checks": f"{len(checks) - len(failed_ids)}/{len(checks)}",
                    "failed_ids": failed_ids,
                    "outcome": outcome,
                    "formatted_value_order": formatted_fields,
                    "pipe_count": combined_literals.count("|"),
                    "hash_consumes_material": hash_consumes_material,
                    "reviewed_static_disposition": reviewed_static_disposition,
                    "V2_modified": False,
                    "V2_imported": False,
                    "controlled_actual_fs_read_eligible": False,
                    "manifest_sha256": sha256_file(manifest),
                    "next_gate": next_gate,
                },
                indent=2,
            )
        )
    except Exception as exc:
        failure = output_dir / "CORRECTED_IQ2_042_FAILED.json"
        failure.write_text(
            json.dumps(
                {
                    "version": VERSION,
                    "created_at_utc": utc_now(),
                    "status": "CORRECTED_IQ2_042_BLOCKED",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "checks_frozen": checks,
                    "V2_modified": False,
                    "V2_imported": False,
                    "restore_executed": False,
                    "actual_fs_read_executed": False,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=VERSION)
    for name in [
        "independent-result",
        "independent-checks",
        "independent-manifest",
        "independent-binding",
        "independent-runner",
        "v2-manifest",
        "project-root",
        "output-dir",
    ]:
        parser.add_argument("--" + name, required=True)
    return parser.parse_args()


if __name__ == "__main__":
    try:
        main(parse_args())
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
