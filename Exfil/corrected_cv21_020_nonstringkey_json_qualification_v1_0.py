#!/usr/bin/env python3
"""Corrected CV21-020 non-string-key JSON boundary qualification v1.0.

Read-only targeted expectation correction. Preserves the original controlled
V2.1 26/27 result and CV21-020 failure. It does not import, instantiate,
execute, or modify V2.1, V2, V1, SDK, tools, hooks, guardrails, predicates,
Sandbox, Gym, HTTP, breach logic, models, threads, or external effects.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "CORRECTED_CV21_020_NON_STRING_KEY_JSON_BOUNDARY_QUALIFICATION_v1.0"
EXPECTED = {
    "controlled_manifest": "7A21A13D0A560379BBBFDACCD066422497498D6C6D49B577389F6E094C85C80D",
    "controlled_result": "2C136DEF45FAA789EE9AE530E8798D71B75AC3EEAF731A25C775028BE1C93BC8",
    "controlled_checks": "9119319EC2CC9FA1ECBD5334DFFA96B76B39D19673C3FBF68666FD70FDACAF47",
    "json_controls": "8A02F1BE89D4695F0B850486A2537BCCA661332B52B4A9209E1B989DCC2A7918",
    "controlled_binding": "71731D0A05219FED7BD07021C8B69239C8B3ADB6D8CD6E66C4BB1ACA43A96DDE",
    "controlled_runner": "E18C0587411991DE4DD0E7513DE36439C3E043D38C9785132187EECD8BE2E476",
    "independent_boundaries": "18027C543E70560E8A48E01D86D3AC2CD5548F750DA5022CEEB762587A289E71",
    "independent_result": "37B4B04748C1AA72B8B49558DFCEE505E4EF79249E67800867ED9222CEBCDEC9",
    "v21_ledger": "18146742E6866C491A032AA96EFC248FFED05706895D32FDE724145D0878009C",
}
RUNNER_SIZE = 31872
LEDGER_SIZE = 8335
TARGET_ID = "CV21-020"
TARGET_CONTROL = "tool_args_non_string_key"
EXPECTED_ERROR = "tool_args are not canonically JSON serializable"


def now() -> str:
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


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
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
    rows: list[dict[str, Any]],
    check_id: str,
    category: str,
    passed: bool,
    observed: Any,
    expected: Any,
    layer: str,
) -> None:
    rows.append(
        {
            "check_id": check_id,
            "category": category,
            "passed": bool(passed),
            "observed": json.dumps(observed, sort_keys=True, ensure_ascii=False, default=str)
            if isinstance(observed, (dict, list, tuple))
            else str(observed),
            "expected": json.dumps(expected, sort_keys=True, ensure_ascii=False, default=str)
            if isinstance(expected, (dict, list, tuple))
            else str(expected),
            "failure_layer": layer,
        }
    )


def unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return "UNPARSE_FAILED"


def function(tree: ast.Module, name: str) -> ast.FunctionDef | None:
    return next(
        (node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name),
        None,
    )


def main(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir).resolve()
    require(not output_dir.exists(), f"Refusing overwrite: {output_dir}")
    output_dir.mkdir(parents=True)
    checks: list[dict[str, Any]] = []

    try:
        project_root = Path(args.project_root).resolve()
        ledger = project_root / "aicomp_sdk_exfil_v2_1" / "successful_read_ledger_v2_1.py"
        inputs = {
            "controlled_manifest": Path(args.controlled_manifest).resolve(),
            "controlled_external": Path(args.controlled_external).resolve(),
            "controlled_result": Path(args.controlled_result).resolve(),
            "controlled_checks": Path(args.controlled_checks).resolve(),
            "json_controls": Path(args.json_controls).resolve(),
            "controlled_binding": Path(args.controlled_binding).resolve(),
            "controlled_runner": Path(args.controlled_runner).resolve(),
            "independent_boundaries": Path(args.independent_boundaries).resolve(),
            "independent_result": Path(args.independent_result).resolve(),
            "v21_ledger": ledger,
        }
        for name, path in inputs.items():
            require(path.is_file(), f"Missing required input {name}: {path}")

        index = 1
        for name, expected_hash in EXPECTED.items():
            actual = sha256_file(inputs[name])
            add_check(
                checks,
                f"C20-{index:03d}",
                "identity",
                actual == expected_hash,
                actual,
                expected_hash,
                "FIXTURE",
            )
            index += 1
        add_check(
            checks,
            f"C20-{index:03d}",
            "identity",
            inputs["controlled_runner"].stat().st_size == RUNNER_SIZE
            and ledger.stat().st_size == LEDGER_SIZE,
            {
                "controlled_runner_size": inputs["controlled_runner"].stat().st_size,
                "ledger_size": ledger.stat().st_size,
            },
            {"controlled_runner_size": RUNNER_SIZE, "ledger_size": LEDGER_SIZE},
            "FIXTURE",
        )
        index += 1

        original_result = read_json(inputs["controlled_result"])
        original_checks = read_csv(inputs["controlled_checks"])
        json_rows = read_csv(inputs["json_controls"])
        external = read_json(inputs["controlled_external"])
        boundaries = read_json(inputs["independent_boundaries"])
        independent_result = read_json(inputs["independent_result"])

        original_26_of_27 = (
            original_result.get("checks")
            == {"failed": 1, "failed_ids": [TARGET_ID], "passed": 26, "total": 27}
            and original_result.get("outcome") == "V2_1_JSON_BOUNDARY_RUNTIME_GAP"
            and len(original_checks) == 27
            and [row.get("check_id") for row in original_checks if row.get("passed") != "True"]
            == [TARGET_ID]
        )
        add_check(
            checks,
            f"C20-{index:03d}",
            "historical_preservation",
            original_26_of_27,
            {
                "result_checks": original_result.get("checks"),
                "result_outcome": original_result.get("outcome"),
                "failed_rows": [
                    row.get("check_id")
                    for row in original_checks
                    if row.get("passed") != "True"
                ],
            },
            "original 26/27 with only CV21-020 failed",
            "EVIDENCE",
        )
        index += 1

        external_ok = (
            external.get("manifest_sha256") == EXPECTED["controlled_manifest"]
            and external.get("runner_sha256") == EXPECTED["controlled_runner"]
            and external.get("checks_total") == 27
            and external.get("checks_passed") == 26
            and external.get("checks_failed") == 1
            and external.get("failed_ids") == [TARGET_ID]
        )
        add_check(
            checks,
            f"C20-{index:03d}",
            "parent_binding",
            external_ok,
            external,
            "controlled external binding preserves 26/27 and exact manifest/runner",
            "EVIDENCE",
        )
        index += 1

        by_control = {row.get("control_id"): row for row in json_rows}
        expected_controls = [
            "tool_args_custom_object",
            "tool_args_nan",
            "tool_args_positive_infinity",
            "tool_args_negative_infinity",
            TARGET_CONTROL,
        ]
        add_check(
            checks,
            f"C20-{index:03d}",
            "control_inventory",
            list(by_control) == expected_controls,
            list(by_control),
            expected_controls,
            "EVIDENCE",
        )
        index += 1

        explicit_invalid = expected_controls[:4]
        four_correct = all(
            by_control[name].get("expected") == "REJECT"
            and by_control[name].get("observed") == "REJECT"
            and by_control[name].get("exception_type") == "ValueError"
            and by_control[name].get("message") == EXPECTED_ERROR
            and by_control[name].get("match") == "True"
            for name in explicit_invalid
        )
        add_check(
            checks,
            f"C20-{index:03d}",
            "json_boundary",
            four_correct,
            {name: by_control.get(name) for name in explicit_invalid},
            "four explicit invalid values rejected as expected",
            "ARGUMENT_FIDELITY",
        )
        index += 1

        target = by_control.get(TARGET_CONTROL, {})
        target_rejected_fail_closed = (
            target.get("expected") == "ACCEPT_JSON_COERCION_OBSERVED"
            and target.get("observed") == "REJECT"
            and target.get("exception_type") == "ValueError"
            and target.get("message") == EXPECTED_ERROR
            and target.get("match") == "False"
        )
        add_check(
            checks,
            f"C20-{index:03d}",
            "json_boundary",
            target_rejected_fail_closed,
            target,
            {
                "recorded_expected": "ACCEPT_JSON_COERCION_OBSERVED",
                "observed": "REJECT",
                "exception_type": "ValueError",
                "message": EXPECTED_ERROR,
                "recorded_match": "False",
            },
            "ARGUMENT_FIDELITY",
        )
        index += 1

        target_check = next(
            (row for row in original_checks if row.get("check_id") == TARGET_ID), None
        )
        target_check_consistent = (
            target_check is not None
            and target_check.get("category") == "json_boundary"
            and target_check.get("passed") == "False"
            and "ACCEPT_JSON_COERCION_OBSERVED" in target_check.get("observed", "")
            and '"observed": "REJECT"' in target_check.get("observed", "")
        )
        add_check(
            checks,
            f"C20-{index:03d}",
            "historical_consistency",
            target_check_consistent,
            target_check,
            "CV21-020 failed only within JSON boundary aggregate",
            "EVIDENCE",
        )
        index += 1

        source_text = ledger.read_text(encoding="utf-8")
        tree = ast.parse(source_text, filename=str(ledger))
        detach = function(tree, "_detach_json_value_v21")
        canonical_args = function(tree, "_canonical_args_json_v21")
        require(detach is not None and canonical_args is not None, "JSON helpers missing")
        detach_text = unparse(detach)
        canonical_text = unparse(canonical_args)
        source_contract = (
            "sort_keys=True" in detach_text
            and "allow_nan=False" in detach_text
            and "ensure_ascii=False" in detach_text
            and "except (TypeError, ValueError)" in detach_text
            and "raise ValueError" in detach_text
            and "sort_keys=True" in canonical_text
            and "allow_nan=False" in canonical_text
        )
        add_check(
            checks,
            f"C20-{index:03d}",
            "source_contract",
            source_contract,
            {"detach": detach_text, "canonical_args": canonical_text},
            "deterministic JSON with fail-closed TypeError/ValueError",
            "ARGUMENT_FIDELITY",
        )
        index += 1

        frozen_boundary_text = json.dumps(boundaries, sort_keys=True)
        independent_text = json.dumps(independent_result, sort_keys=True)
        acceptance_required = any(
            token in (frozen_boundary_text + independent_text)
            for token in [
                "ACCEPT_JSON_COERCION_OBSERVED",
                "NON_STRING_KEYS_MUST_BE_ACCEPTED",
                "non-string keys accepted",
            ]
        )
        add_check(
            checks,
            f"C20-{index:03d}",
            "requirement_trace",
            not acceptance_required,
            {
                "acceptance_requirement_found": acceptance_required,
                "independent_error_contract": boundaries.get("error_value"),
                "independent_runtime_status": independent_result.get("scientific_verdict"),
            },
            "no frozen parent requirement demands non-string-key acceptance",
            "EVIDENCE",
        )
        index += 1

        original_files_unchanged = all(
            sha256_file(inputs[name]) == expected_hash
            for name, expected_hash in EXPECTED.items()
        )
        add_check(
            checks,
            f"C20-{index:03d}",
            "immutability",
            original_files_unchanged,
            "all bound inputs unchanged after review",
            True,
            "FIXTURE",
        )

        failed_ids = [row["check_id"] for row in checks if not row["passed"]]
        pass_conditions = not failed_ids and original_26_of_27 and target_rejected_fail_closed and not acceptance_required
        if pass_conditions:
            outcome = "CV21_020_QUALIFIER_EXPECTATION_GAP_CONFIRMED"
        elif not target_rejected_fail_closed or acceptance_required:
            outcome = "V2_1_NON_STRING_KEY_CONTRACT_GAP_CONFIRMED"
        else:
            outcome = "NOT_ESTABLISHED"
        complete_pass = outcome == "CV21_020_QUALIFIER_EXPECTATION_GAP_CONFIRMED"
        status = (
            "CORRECTED_CV21_020_NON_STRING_KEY_JSON_BOUNDARY_QUALIFICATION_COMPLETE_PASS"
            if complete_pass
            else "CORRECTED_CV21_020_NON_STRING_KEY_JSON_BOUNDARY_QUALIFICATION_COMPLETE_WITH_GAPS"
        )
        reviewed_disposition = (
            "CONTROLLED_V2_1_LEDGER_QUALIFICATION_PASS_AFTER_EXPECTATION_CORRECTION"
            if complete_pass
            else "CONTROLLED_V2_1_LEDGER_QUALIFICATION_REMAINS_BLOCKED"
        )
        next_gate = (
            "CONTROLLED_ACTUAL_FS_READ_HOOK_AND_LEDGER_QUALIFICATION"
            if complete_pass
            else "V2_1_JSON_CONTRACT_REVIEW"
        )

        claim_boundary = {
            "allowed": [
                "preserve original controlled V2.1 26-of-27 result",
                "preserve original CV21-020 failure and recorded outcome",
                "classify five noncanonical JSON controls from frozen runtime evidence",
                "classify non-string-key rejection as fail-closed behavior",
                "assign reviewed controlled-ledger disposition",
            ],
            "prohibited": [
                "modify V2.1",
                "modify original controlled artifacts",
                "claim original controlled run passed 27 of 27",
                "claim actual fs.read",
                "claim hook transport",
                "claim guardrail effectiveness",
                "claim protected-value lineage",
                "claim robust end-to-end security findings",
            ],
        }
        result = {
            "version": VERSION,
            "created_at_utc": now(),
            "status": status,
            "classification": "READ_ONLY_TARGETED_EXPECTATION_CORRECTION",
            "checks": {
                "total": len(checks),
                "passed": len(checks) - len(failed_ids),
                "failed": len(failed_ids),
                "failed_ids": failed_ids,
            },
            "preserved_original_result": {
                "checks_total": 27,
                "checks_passed": 26,
                "checks_failed": 1,
                "failed_ids": [TARGET_ID],
                "recorded_outcome": "V2_1_JSON_BOUNDARY_RUNTIME_GAP",
                "original_artifacts_modified": False,
            },
            "corrected_CV21_020": {
                "recorded_expected": target.get("expected"),
                "observed": target.get("observed"),
                "exception_type": target.get("exception_type"),
                "exception_message": target.get("message"),
                "corrected_expected": "REJECT_FAIL_CLOSED",
                "implementation_gap": "NOT_DEMONSTRATED"
                if complete_pass
                else "NOT_ESTABLISHED",
            },
            "outcome": outcome,
            "reviewed_disposition": reviewed_disposition,
            "readiness": {
                "controlled_actual_fs_read_hook_and_ledger_qualification_eligible": complete_pass,
                "controlled_actual_fs_read_eligible": False,
                "http_sink_eligible": False,
            },
            "execution_boundaries": {
                "V2_1_modified": False,
                "V2_1_imported": False,
                "V2_1_instantiated": False,
                "original_controlled_artifacts_modified": False,
                "actual_fs_read_executed": False,
                "hook_registered": False,
                "guardrail_executed": False,
                "http_sink_executed": False,
                "predicates_executed": False,
                "breach_executed": False,
                "Sandbox_instantiated": False,
                "Gym_executed": False,
                "models_used": False,
                "threads_executed": False,
                "external_effects_observed": False,
            },
            "scientific_verdict": {
                "CV21_020": outcome,
                "V2_1_non_string_key_behavior": "REJECT_FAIL_CLOSED"
                if complete_pass
                else "NOT_ESTABLISHED",
                "V2_1_JSON_implementation_gap": "NOT_DEMONSTRATED"
                if complete_pass
                else "NOT_ESTABLISHED",
                "actual_source_retrieval": "NOT_EVALUATED",
                "hook_transport": "NOT_EVALUATED",
                "protected_value_lineage": "NOT_ESTABLISHED",
                "guardrail_effectiveness": "NOT_EVALUATED",
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": "NOT_ESTABLISHED",
            },
            "claim_boundary": claim_boundary,
            "next_gate": next_gate,
        }

        outputs = {
            "result": output_dir / "corrected_cv21_020_result.json",
            "checks": output_dir / "corrected_cv21_020_checks.csv",
            "control": output_dir / "corrected_cv21_020_control_review.json",
            "source": output_dir / "corrected_cv21_020_source_contract.json",
            "claim": output_dir / "corrected_cv21_020_claim_boundary.json",
            "binding": output_dir / "corrected_cv21_020_binding.json",
        }
        write_json(outputs["result"], result)
        write_csv(
            outputs["checks"],
            checks,
            ["check_id", "category", "passed", "observed", "expected", "failure_layer"],
        )
        write_json(
            outputs["control"],
            {
                "target_check_id": TARGET_ID,
                "target_control_id": TARGET_CONTROL,
                "original_check": target_check,
                "original_control_row": target,
                "four_explicit_invalid_controls": {
                    name: by_control[name] for name in explicit_invalid
                },
                "corrected_expected": "REJECT_FAIL_CLOSED",
                "reviewed_classification": outcome,
            },
        )
        write_json(
            outputs["source"],
            {
                "source_file": identity(ledger),
                "detach_function": "_detach_json_value_v21",
                "detach_source": detach_text,
                "canonical_args_function": "_canonical_args_json_v21",
                "canonical_args_source": canonical_text,
                "sort_keys": True,
                "allow_nan": False,
                "ensure_ascii": False,
                "fail_closed_exceptions": ["TypeError", "ValueError"],
                "non_string_key_acceptance_requirement_found": acceptance_required,
            },
        )
        write_json(outputs["claim"], claim_boundary)
        write_json(
            outputs["binding"],
            {
                "version": VERSION,
                "created_at_utc": now(),
                "runner": identity(Path(__file__).resolve()),
                "inputs": {name: identity(path) for name, path in inputs.items()},
                "V2_1_modified": False,
                "V2_1_imported": False,
                "original_controlled_artifacts_modified": False,
                "actual_fs_read_executed": False,
            },
        )

        manifest_rows = [
            {**identity(path), "role": "CORRECTED_CV21_020_DERIVED"}
            for path in outputs.values()
        ] + [
            {**identity(path), "role": "CORRECTED_CV21_020_BOUND_INPUT"}
            for path in inputs.values()
        ]
        manifest = output_dir / "corrected_cv21_020_manifest.csv"
        write_csv(
            manifest,
            manifest_rows,
            ["artifact", "role", "size_bytes", "sha256", "path"],
        )
        external_binding = output_dir / "corrected_cv21_020_manifest_external_binding.json"
        write_json(
            external_binding,
            {
                "version": VERSION,
                "created_at_utc": now(),
                "status": status,
                "manifest_filename": manifest.name,
                "manifest_size_bytes": manifest.stat().st_size,
                "manifest_sha256": sha256_file(manifest),
                "runner_sha256": sha256_file(Path(__file__).resolve()),
                "original_controlled_manifest_sha256": EXPECTED["controlled_manifest"],
                "checks_total": len(checks),
                "checks_passed": len(checks) - len(failed_ids),
                "checks_failed": len(failed_ids),
                "failed_ids": failed_ids,
                "outcome": outcome,
                "reviewed_disposition": reviewed_disposition,
                "V2_1_modified": False,
                "V2_1_imported": False,
                "actual_fs_read_executed": False,
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
                    "reviewed_disposition": reviewed_disposition,
                    "original_result_preserved": "26_OF_27",
                    "non_string_key_behavior": "REJECT_FAIL_CLOSED",
                    "V2_1_modified": False,
                    "V2_1_imported": False,
                    "actual_fs_read_executed": False,
                    "manifest_sha256": sha256_file(manifest),
                    "next_gate": next_gate,
                },
                indent=2,
            )
        )
    except Exception as exc:
        failure = output_dir / "CORRECTED_CV21_020_FAILED.json"
        failure.write_text(
            json.dumps(
                {
                    "version": VERSION,
                    "created_at_utc": now(),
                    "status": "CORRECTED_CV21_020_BLOCKED",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "checks_frozen": checks,
                    "V2_1_modified": False,
                    "V2_1_imported": False,
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
        "controlled-manifest",
        "controlled-external",
        "controlled-result",
        "controlled-checks",
        "json-controls",
        "controlled-binding",
        "controlled-runner",
        "independent-boundaries",
        "independent-result",
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
