#!/usr/bin/env python3
"""
EX6 Hardened P2B Implementation Identity Freeze

Read-only, fail-closed identity and traceability freeze for:
  * packaged OptimalGuardrail baseline
  * separate hardened guardrail implementation
  * TrustedGuardrailContextAdapter component
  * requirements specification
  * change manifest

This phase does NOT execute guardrail decisions, tools, Sandbox, Gym, models,
predicates, breach logic, effects, or matched policy comparisons.

Default validation is static AST inspection. Optional import checks are isolated
in child Python processes and validate importability only; no instances are
constructed and no guardrail method is called.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import os
import platform
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

VERSION = "EX6_HARDENED_P2B_IMPLEMENTATION_IDENTITY_FREEZE_v1.0"
STATUS = "P2B_IMPLEMENTATION_IDENTITY_FREEZE_COMPLETE_PASS"
CLASSIFICATION = "IDENTITY_REQUIREMENT_AND_INTERFACE_FREEZE_ONLY"

CHANGE_FIELDS = (
    "change_id",
    "requirement_id",
    "source_location",
    "change_type",
    "packaged_behavior",
    "hardened_behavior",
    "security_rationale",
    "expected_allowed_case",
    "expected_denied_case",
    "implementation_status",
    "source_evidence",
)

REQUIRED_INTERFACE_NAMES = (
    "before_decide",
    "after_tool",
    "snapshot_state",
    "restore_state",
)

ALLOWED_CLAIMS = (
    "packaged source identity",
    "hardened source identity",
    "adapter source identity",
    "separate class and file identity",
    "change-manifest completeness",
    "requirement-to-code traceability",
    "static interface presence",
    "importability if explicitly checked",
)

PROHIBITED_CLAIMS = (
    "guardrail effectiveness",
    "security improvement",
    "policy superiority",
    "reduced attack success",
    "real exfiltration prevention",
    "sandbox parity",
    "gym parity",
    "hosted parity",
)

IDENTITY_HEX_LENGTH = 64


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest().upper()


def identity(path: Path) -> dict[str, Any]:
    return {
        "artifact": path.name,
        "path": str(path.resolve()),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as fh:
        json.dump(value, fh, indent=2, sort_keys=True, ensure_ascii=False)
        fh.write("\n")


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fields: list[str]) -> None:
    with path.open("x", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def require_file(path: Path, label: str) -> Path:
    require(path.is_file(), f"{label} not found: {path}")
    return path.resolve()


def parse_source(path: Path) -> ast.Module:
    text = path.read_text(encoding="utf-8-sig")
    return ast.parse(text, filename=str(path))


def class_catalog(tree: ast.Module) -> dict[str, ast.ClassDef]:
    return {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
    }


def callable_catalog(class_node: ast.ClassDef) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {
        node.name: node
        for node in class_node.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def signature_from_ast(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Any]:
    args = node.args
    positional = [a.arg for a in list(args.posonlyargs) + list(args.args)]
    kwonly = [a.arg for a in args.kwonlyargs]
    return {
        "name": node.name,
        "kind": "async" if isinstance(node, ast.AsyncFunctionDef) else "sync",
        "positional_parameters": positional,
        "keyword_only_parameters": kwonly,
        "has_varargs": args.vararg is not None,
        "has_varkw": args.kwarg is not None,
        "decorators": [ast.unparse(x) for x in node.decorator_list],
        "line_start": node.lineno,
        "line_end": getattr(node, "end_lineno", node.lineno),
    }


def inspect_class(path: Path, expected_class: str) -> dict[str, Any]:
    tree = parse_source(path)
    classes = class_catalog(tree)
    require(expected_class in classes,
            f"Expected class {expected_class!r} not found in {path}")
    node = classes[expected_class]
    methods = callable_catalog(node)
    return {
        "class_name": expected_class,
        "line_start": node.lineno,
        "line_end": getattr(node, "end_lineno", node.lineno),
        "bases": [ast.unparse(x) for x in node.bases],
        "methods": {name: signature_from_ast(methods[name]) for name in sorted(methods)},
    }


def inspect_adapter(path: Path, adapter_class: str) -> dict[str, Any]:
    result = inspect_class(path, adapter_class)
    methods = result["methods"]
    missing = [name for name in REQUIRED_INTERFACE_NAMES if name not in methods]
    require(not missing,
            f"Adapter {adapter_class} lacks required interfaces: {missing}")

    # Digest/event binding are frozen as explicit evidence, not guessed from names.
    source_text = path.read_text(encoding="utf-8-sig")
    result["required_interfaces"] = {
        "before_decide_trusted_context_enrichment": "before_decide" in methods,
        "after_tool_trusted_outcome_acknowledgement": "after_tool" in methods,
        "deterministic_snapshot_restore":
            "snapshot_state" in methods and "restore_state" in methods,
        "proposal_digest_binding_evidence_present":
            "proposal_digest" in source_text,
        "event_identity_binding_evidence_present":
            "event_identity" in source_text or "event_id" in source_text,
    }
    require(result["required_interfaces"]["proposal_digest_binding_evidence_present"],
            "Adapter source lacks literal proposal_digest binding evidence")
    require(result["required_interfaces"]["event_identity_binding_evidence_present"],
            "Adapter source lacks literal event_identity or event_id binding evidence")
    return result


def normalize_requirements(data: Any) -> dict[str, dict[str, Any]]:
    if isinstance(data, dict) and "requirements" in data:
        data = data["requirements"]
    if isinstance(data, dict):
        rows = []
        for key, value in data.items():
            if isinstance(value, dict):
                rows.append({"requirement_id": key, **value})
            else:
                rows.append({"requirement_id": key, "text": value})
    elif isinstance(data, list):
        rows = data
    else:
        raise ValueError("Requirements JSON must be a list or mapping")

    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        require(isinstance(row, dict), "Each requirement must be an object")
        rid = str(row.get("requirement_id", "")).strip()
        require(rid, "Requirement without requirement_id")
        require(rid not in result, f"Duplicate requirement_id: {rid}")
        result[rid] = row
    require(result, "Requirements specification is empty")
    return result


def validate_change_manifest(path: Path,
                             requirements: dict[str, dict[str, Any]],
                             hardened_source: Path,
                             hardened_lines: int,
                             adapter_source: Path,
                             adapter_lines: int) -> dict[str, Any]:
    rows = load_csv(path)
    require(rows, "Change manifest is empty")
    require(set(CHANGE_FIELDS).issubset(rows[0].keys()),
            f"Change manifest requires columns: {CHANGE_FIELDS}")

    seen: set[str] = set()
    covered: set[str] = set()
    normalized = []
    valid_sources = {
        hardened_source.name: hardened_lines,
        adapter_source.name: adapter_lines,
    }

    for index, raw in enumerate(rows, start=2):
        row = {field: str(raw.get(field, "")).strip() for field in CHANGE_FIELDS}
        empty = [field for field, value in row.items() if not value]
        require(not empty, f"Change manifest row {index} has empty fields: {empty}")
        cid = row["change_id"]
        rid = row["requirement_id"]
        require(cid not in seen, f"Duplicate change_id: {cid}")
        require(rid in requirements, f"Unknown requirement_id {rid} in {cid}")
        require(row["implementation_status"].upper() in {"IMPLEMENTED", "VERIFIED"},
                f"Non-frozen implementation_status for {cid}: {row['implementation_status']}")

        # Required source_location syntax: filename.py:start-end or filename.py:line
        location = row["source_location"]
        require(":" in location, f"Invalid source_location for {cid}: {location}")
        filename, line_part = location.rsplit(":", 1)
        require(Path(filename).name in valid_sources,
                f"source_location for {cid} does not bind hardened/adapter source")
        bounds = line_part.split("-", 1)
        start = int(bounds[0])
        end = int(bounds[1]) if len(bounds) == 2 else start
        require(1 <= start <= end <= valid_sources[Path(filename).name],
                f"Out-of-range source_location for {cid}: {location}")

        seen.add(cid)
        covered.add(rid)
        normalized.append(row)

    uncovered = sorted(set(requirements) - covered)
    require(not uncovered, f"Requirements without change-manifest coverage: {uncovered}")
    return {
        "change_count": len(normalized),
        "requirement_count": len(requirements),
        "covered_requirement_count": len(covered),
        "all_requirements_covered": True,
        "change_type_counts": dict(sorted(Counter(x["change_type"] for x in normalized).items())),
        "implementation_status_counts": dict(sorted(Counter(x["implementation_status"] for x in normalized).items())),
        "rows": normalized,
    }


def isolated_import_check(module: str, class_name: str, project_root: Path) -> dict[str, Any]:
    snippet = (
        "import importlib, json; "
        f"m=importlib.import_module({module!r}); "
        f"c=getattr(m,{class_name!r}); "
        "print(json.dumps({'module':m.__name__,'class':c.__name__}))"
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(project_root) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, "-I", "-c",
         "import sys; sys.path.insert(0, " + repr(str(project_root)) + "); " + snippet],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
        cwd=str(project_root),
    )
    return {
        "performed": True,
        "module": module,
        "class": class_name,
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
        "passed": proc.returncode == 0,
        "instance_constructed": False,
        "guardrail_method_called": False,
    }


def ensure_new_dir(path: Path) -> None:
    require(not path.exists(), f"Refusing to overwrite output directory: {path}")
    path.mkdir(parents=True, exist_ok=False)


def run(args: argparse.Namespace) -> None:
    project_root = Path(args.project_root).resolve()
    packaged = require_file(Path(args.packaged_source), "Packaged source")
    hardened = require_file(Path(args.hardened_source), "Hardened source")
    adapter = require_file(Path(args.adapter_source), "Adapter source")
    requirements_path = require_file(Path(args.requirements_json), "Requirements JSON")
    changes_path = require_file(Path(args.change_manifest_csv), "Change manifest CSV")
    p2a_path = require_file(Path(args.p2a_manifest), "P2A manifest/binding")
    output_dir = Path(args.output_dir).resolve()

    require(project_root.is_dir(), f"Project root not found: {project_root}")
    require(packaged != hardened, "Hardened source must be separate from packaged source")
    require(packaged != adapter, "Adapter source must be separate from packaged source")
    require(args.packaged_class == "OptimalGuardrail",
            "Packaged baseline class must remain OptimalGuardrail")
    require(args.hardened_class != args.packaged_class,
            "Hardened class must have a distinct name")
    require(args.hardened_class != "distinct_new_name",
            "Replace placeholder distinct_new_name with the exact hardened class")
    require(args.adapter_class == "TrustedGuardrailContextAdapter",
            "Adapter class must be TrustedGuardrailContextAdapter for this P2B scope")

    ensure_new_dir(output_dir)
    try:
        packaged_info = inspect_class(packaged, args.packaged_class)
        hardened_info = inspect_class(hardened, args.hardened_class)
        adapter_info = inspect_adapter(adapter, args.adapter_class)

        requirements = normalize_requirements(load_json(requirements_path))
        hardened_lines = len(hardened.read_text(encoding="utf-8-sig").splitlines())
        adapter_lines = len(adapter.read_text(encoding="utf-8-sig").splitlines())
        changes = validate_change_manifest(
            changes_path, requirements, hardened, hardened_lines, adapter, adapter_lines
        )

        import_checks: list[dict[str, Any]] = []
        if args.perform_import_checks:
            require(args.packaged_module and args.hardened_module and args.adapter_module,
                    "Module names are required when --perform-import-checks is used")
            for module, name in (
                (args.packaged_module, args.packaged_class),
                (args.hardened_module, args.hardened_class),
                (args.adapter_module, args.adapter_class),
            ):
                check = isolated_import_check(module, name, project_root)
                require(check["passed"],
                        f"Import check failed for {module}.{name}: {check['stderr']}")
                import_checks.append(check)

        source_identities = {
            "packaged_guardrail": {**identity(packaged), "class": args.packaged_class,
                                    "role": "OFFICIAL_BASELINE", "modified": False},
            "hardened_guardrail": {**identity(hardened), "class": args.hardened_class,
                                    "role": "PROPOSED_DEFENSE",
                                    "packaged_source_modified": False},
            "trusted_context_adapter": {**identity(adapter), "class": args.adapter_class,
                                         "role": "TRUSTED_CONTEXT_ADAPTER"},
            "requirements_specification": identity(requirements_path),
            "change_manifest": identity(changes_path),
            "p2a_preflight_binding": identity(p2a_path),
            "p2b_freeze_runner": identity(Path(__file__).resolve()),
        }

        result = {
            "version": VERSION,
            "created_at_utc": now_utc(),
            "status": STATUS,
            "classification": CLASSIFICATION,
            "source_artifacts_modified": False,
            "source_identities": source_identities,
            "static_inspection": {
                "packaged": packaged_info,
                "hardened": hardened_info,
                "adapter": adapter_info,
            },
            "requirements": {
                "count": len(requirements),
                "ids": sorted(requirements),
                "source_sha256": source_identities["requirements_specification"]["sha256"],
            },
            "change_manifest_validation": {
                key: value for key, value in changes.items() if key != "rows"
            },
            "import_checks": {
                "performed": args.perform_import_checks,
                "checks": import_checks,
                "instances_constructed": False,
                "guardrail_methods_called": False,
            },
            "execution_boundaries": {
                "guardrail_decisions_executed": False,
                "matched_policy_comparison_executed": False,
                "model_used": False,
                "sandbox_used": False,
                "gym_used": False,
                "tools_executed": False,
                "effects_observed": False,
                "predicates_executed": False,
                "breach_executed": False,
                "real_lineage_established": False,
            },
            "claim_boundary": {
                "allowed": list(ALLOWED_CLAIMS),
                "prohibited": list(PROHIBITED_CLAIMS),
            },
            "scientific_verdict": {
                "implementation_identity": "ESTABLISHED",
                "requirement_to_code_traceability": "ESTABLISHED",
                "documented_static_interface_presence": "ESTABLISHED",
                "guardrail_effectiveness": "NOT_EVALUATED",
                "policy_superiority": "NOT_EVALUATED",
                "real_exfiltration_prevention": "NOT_EVALUATED",
            },
            "next_gate": "EX8_FROZEN_PROPOSAL_SANDBOX_GYM_PARITY",
        }

        result_path = output_dir / "ex6_p2b_identity_freeze_result.json"
        changes_copy_path = output_dir / "ex6_p2b_validated_change_manifest.csv"
        boundary_path = output_dir / "ex6_p2b_claim_boundary.json"
        state_path = output_dir / "ex6_p2b_recommended_state.json"

        write_json(result_path, result)
        write_csv(changes_copy_path, changes["rows"], list(CHANGE_FIELDS))
        write_json(boundary_path, result["claim_boundary"])
        write_json(state_path, {
            "current_focus": {"phase": "EXFILTRATION",
                              "stage": "EX6_HARDENED_P2B_IMPLEMENTATION_IDENTITY_FREEZE_COMPLETE"},
            "EX6_HARDENED_P2B": {
                "status": STATUS,
                "immutable": True,
                "implementation_identity": "ESTABLISHED",
                "requirement_to_code_traceability": "ESTABLISHED",
                "guardrail_effectiveness": "NOT_EVALUATED",
                "policy_superiority": "NOT_EVALUATED",
            },
            "attack_optimization": False,
            "next_single_step": {"action": "EX8_FROZEN_PROPOSAL_SANDBOX_GYM_PARITY"},
        })

        content_paths = [result_path, changes_copy_path, boundary_path, state_path]
        manifest_rows = []
        for path in content_paths:
            item = identity(path)
            manifest_rows.append({**item, "role": "P2B_FREEZE_DERIVED_ARTIFACT"})
        for key, item in source_identities.items():
            manifest_rows.append({
                "artifact": item["artifact"],
                "path": item["path"],
                "size_bytes": item["size_bytes"],
                "sha256": item["sha256"],
                "role": "P2B_BOUND_SOURCE_" + key.upper(),
            })

        manifest_path = output_dir / "ex6_p2b_identity_freeze_manifest.csv"
        write_csv(manifest_path, manifest_rows,
                  ["artifact", "role", "size_bytes", "sha256", "path"])
        manifest_id = identity(manifest_path)

        binding_path = output_dir / "ex6_p2b_identity_freeze_manifest_external_binding.json"
        write_json(binding_path, {
            "version": VERSION,
            "created_at_utc": now_utc(),
            "status": STATUS,
            "manifest_filename": manifest_id["artifact"],
            "manifest_size_bytes": manifest_id["size_bytes"],
            "manifest_sha256": manifest_id["sha256"],
            "freeze_runner_sha256": source_identities["p2b_freeze_runner"]["sha256"],
            "packaged_source_sha256": source_identities["packaged_guardrail"]["sha256"],
            "hardened_source_sha256": source_identities["hardened_guardrail"]["sha256"],
            "adapter_source_sha256": source_identities["trusted_context_adapter"]["sha256"],
            "requirements_source_sha256": source_identities["requirements_specification"]["sha256"],
            "change_manifest_source_sha256": source_identities["change_manifest"]["sha256"],
            "guardrail_effectiveness": "NOT_EVALUATED",
            "policy_superiority": "NOT_EVALUATED",
        })

        print(json.dumps({
            "status": STATUS,
            "output_dir": str(output_dir),
            "manifest_sha256": manifest_id["sha256"],
            "packaged_class": args.packaged_class,
            "hardened_class": args.hardened_class,
            "adapter_class": args.adapter_class,
            "next_gate": "EX8_FROZEN_PROPOSAL_SANDBOX_GYM_PARITY",
        }, indent=2))

    except Exception:
        failed = output_dir / "FREEZE_FAILED.txt"
        if output_dir.is_dir() and not failed.exists():
            failed.write_text(
                "EX6 P2B identity freeze failed. No identity, interface, "
                "effectiveness, or superiority claim is allowed.\n",
                encoding="utf-8",
            )
        raise


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=VERSION)
    p.add_argument("--project-root", required=True)
    p.add_argument("--packaged-source", required=True)
    p.add_argument("--packaged-class", default="OptimalGuardrail")
    p.add_argument("--hardened-source", required=True)
    p.add_argument("--hardened-class", required=True)
    p.add_argument("--adapter-source", required=True)
    p.add_argument("--adapter-class", default="TrustedGuardrailContextAdapter")
    p.add_argument("--requirements-json", required=True)
    p.add_argument("--change-manifest-csv", required=True)
    p.add_argument("--p2a-manifest", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--perform-import-checks", action="store_true")
    p.add_argument("--packaged-module")
    p.add_argument("--hardened-module")
    p.add_argument("--adapter-module")
    return p.parse_args()


if __name__ == "__main__":
    try:
        run(parse_args())
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
