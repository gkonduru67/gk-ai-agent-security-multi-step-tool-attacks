#!/usr/bin/env python3
"""EX6 P2B P2F R1 package-discovery and import/interface preflight.

Controlled import only. Establishes project-root/package visibility, validates
package markers, imports aicomp_sdk, imports the repaired adapter by its package
name, and inspects the class interface. It does not instantiate the adapter or
execute guardrails, models, tools, Sandbox, Gym, predicates, breach, or effects.
"""
from __future__ import annotations
import argparse, csv, hashlib, importlib, importlib.util, inspect, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX6_P2B_P2F_R1_PACKAGE_DISCOVERY_PREFLIGHT_v1.1"
EXPECTED_P2E_STATUS = "P2B_P2E_CORRECTED_QUALIFIER_REQUALIFICATION_COMPLETE_PASS"
EXPECTED_P2E_MANIFEST_SHA = "8AC9DDFF56180619D39C4E715E2883F29DBDA59F57B9A0DE957B86ACEB05F5A4"
EXPECTED_SOURCE_SHA = "BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"
EXPECTED_CLASS = "TrustedGuardrailContextAdapterV1_1"
EXPECTED_MODULE = "aicomp_sdk.guardrails.trusted_context_adapter_v1_1"
REQUIRED_METHODS = {
    "__init__", "register_trusted_grant", "before_decide", "decide",
    "after_tool", "snapshot_state", "restore_state", "reset_state",
}

def now(): return datetime.now(timezone.utc).isoformat()
def require(condition: bool, message: str):
    if not condition: raise ValueError(message)
def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""): h.update(block)
    return h.hexdigest().upper()
def identity(path: Path) -> dict[str, Any]:
    return {"artifact": path.name, "path": str(path.resolve()), "size_bytes": path.stat().st_size, "sha256": sha256(path)}
def load_json(path: Path): return json.loads(path.read_text(encoding="utf-8-sig"))
def write_json(path: Path, value: Any):
    with path.open("x", encoding="utf-8", newline="\n") as f:
        json.dump(value, f, indent=2, sort_keys=True); f.write("\n")
def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]):
    with path.open("x", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        w.writeheader(); w.writerows(rows)

def derive_project_root(source: Path) -> Path:
    # Required layout: <project_root>/aicomp_sdk/guardrails/<source>.py
    require(source.parent.name == "guardrails", "source parent must be guardrails")
    require(source.parent.parent.name == "aicomp_sdk", "source grandparent must be aicomp_sdk")
    return source.parent.parent.parent.resolve()

def marker(path: Path) -> dict[str, Any]:
    return {"path": str(path), "exists": path.is_file(), "identity": identity(path) if path.is_file() else None}

def main(args):
    output = Path(args.output_dir).resolve()
    require(not output.exists(), f"Refusing overwrite: {output}")
    output.mkdir(parents=True)
    original_sys_path = list(sys.path)
    inserted = False
    try:
        p2e_result = Path(args.p2e_result).resolve()
        p2e_binding = Path(args.p2e_external_binding).resolve()
        source = Path(args.repaired_source).resolve()
        for label, path in (("p2e result", p2e_result), ("p2e external binding", p2e_binding), ("repaired source", source)):
            require(path.is_file(), f"Missing {label}: {path}")

        result_parent = load_json(p2e_result)
        binding_parent = load_json(p2e_binding)
        require(result_parent.get("status") == EXPECTED_P2E_STATUS, "P2E result is not PASS")
        require(binding_parent.get("status") == EXPECTED_P2E_STATUS, "P2E binding is not PASS")
        require(binding_parent.get("manifest_sha256") == EXPECTED_P2E_MANIFEST_SHA, "P2E manifest authority differs")
        require(binding_parent.get("repaired_source_sha256") == EXPECTED_SOURCE_SHA, "P2E source identity differs")
        require(binding_parent.get("runtime_validated") is False, "P2E crossed runtime boundary")
        require(binding_parent.get("requirements_satisfied") is False, "P2E claims requirement satisfaction")
        require(sha256(source) == EXPECTED_SOURCE_SHA, "Current repaired source SHA differs")

        project_root = derive_project_root(source)
        package_root = project_root / "aicomp_sdk"
        guardrails_root = package_root / "guardrails"
        checks = [
            {"check": "project_root_exists", "passed": project_root.is_dir(), "evidence": str(project_root)},
            {"check": "aicomp_sdk_directory_exists", "passed": package_root.is_dir(), "evidence": str(package_root)},
            {"check": "guardrails_directory_exists", "passed": guardrails_root.is_dir(), "evidence": str(guardrails_root)},
        ]
        require(all(row["passed"] for row in checks), "Derived package layout is incomplete")
        markers = {
            "aicomp_sdk_init": marker(package_root / "__init__.py"),
            "guardrails_init": marker(guardrails_root / "__init__.py"),
        }

        project_text = str(project_root)
        if project_text not in sys.path:
            sys.path.insert(0, project_text); inserted = True
        importlib.invalidate_caches()

        discovery = {}
        root_spec = importlib.util.find_spec("aicomp_sdk")
        discovery["aicomp_sdk_spec_found"] = root_spec is not None
        discovery["aicomp_sdk_spec_origin"] = getattr(root_spec, "origin", None) if root_spec else None
        discovery["aicomp_sdk_search_locations"] = list(root_spec.submodule_search_locations or []) if root_spec else []
        require(root_spec is not None, "aicomp_sdk remains undiscoverable after controlled sys.path insertion")

        package = importlib.import_module("aicomp_sdk")
        package_file = getattr(package, "__file__", None)
        module_spec = importlib.util.find_spec(EXPECTED_MODULE)
        require(module_spec is not None, f"Module spec not found: {EXPECTED_MODULE}")
        module = importlib.import_module(EXPECTED_MODULE)
        require(hasattr(module, EXPECTED_CLASS), f"Expected class absent: {EXPECTED_CLASS}")
        adapter_class = getattr(module, EXPECTED_CLASS)
        method_inventory = {}
        for method in sorted(REQUIRED_METHODS):
            present = hasattr(adapter_class, method)
            value = getattr(adapter_class, method, None)
            method_inventory[method] = {
                "present": present,
                "callable": callable(value),
                "signature": str(inspect.signature(value)) if present and callable(value) else None,
            }
        interface_pass = all(x["present"] and x["callable"] for x in method_inventory.values())
        require(interface_pass, "Required class interface incomplete")

        result = {
            "version": VERSION, "created_at_utc": now(),
            "status": "P2F_R1_PACKAGE_DISCOVERY_AND_IMPORT_INTERFACE_PREFLIGHT_COMPLETE_PASS",
            "classification": "CONTROLLED_PACKAGE_DISCOVERY_IMPORT_AND_INTERFACE_PREFLIGHT",
            "P2E_parent_verified": True,
            "repaired_source_identity": identity(source),
            "project_root": str(project_root), "package_root": str(package_root),
            "package_markers": markers, "controlled_sys_path_inserted": inserted,
            "aicomp_sdk_importable": True, "aicomp_sdk_file": package_file,
            "adapter_module_name": EXPECTED_MODULE,
            "adapter_module_importable": True,
            "expected_class": EXPECTED_CLASS, "expected_class_visible": True,
            "method_inventory": method_inventory,
            "execution_boundaries": {
                "sdk_package_imported": True, "adapter_module_imported": True,
                "adapter_instantiated": False, "guardrail_decision_executed": False,
                "sandbox_executed": False, "gym_executed": False, "tools_executed": False,
                "predicates_executed": False, "breach_executed": False, "effects_observed": False,
            },
            "scientific_verdict": {
                "package_discovery": "ESTABLISHED", "module_importability": "ESTABLISHED",
                "static_interface_compatibility": "ESTABLISHED",
                "constructor_compatibility": "NOT_EVALUATED", "runtime_compatibility": "NOT_ESTABLISHED",
                "authorization_transport_correctness": "NOT_ESTABLISHED",
                "requirement_satisfaction": "NOT_ESTABLISHED", "guardrail_effectiveness": "NOT_EVALUATED",
                "harness_trick": "NOT_DEMONSTRATED", "robust_security_findings": "NOT_ESTABLISHED",
            },
            "claim_boundary": {
                "allowed": ["package-root discovery", "aicomp_sdk importability", "adapter module importability", "class and method interface visibility"],
                "prohibited": ["constructor correctness", "runtime compatibility", "authorization transport correctness", "requirement satisfaction", "guardrail effectiveness", "security improvement", "real exfiltration prevention", "Sandbox parity", "Gym parity", "hosted parity"],
            },
            "next_gate": "EX6_P2B_P2G_CONTROLLED_CONSTRUCTOR_AND_STATE_INTERFACE_PREFLIGHT",
        }
        rp = output / "ex6_p2b_p2f_r1_result.json"
        cp = output / "ex6_p2b_p2f_r1_discovery_checks.csv"
        bp = output / "ex6_p2b_p2f_r1_binding.json"
        cb = output / "ex6_p2b_p2f_r1_claim_boundary.json"
        write_json(rp, result); write_csv(cp, checks, ["check", "passed", "evidence"])
        write_json(cb, result["claim_boundary"])
        write_json(bp, {"version": VERSION, "created_at_utc": now(), "runner": identity(Path(__file__).resolve()), "inputs": {"p2e_result": identity(p2e_result), "p2e_external_binding": identity(p2e_binding), "repaired_source": identity(source)}, "project_root": str(project_root), "source_modified": False})
        artifacts = [rp, cp, bp, cb]
        manifest_rows = [{**identity(x), "role": "P2F_R1_DERIVED"} for x in artifacts]
        manifest_rows += [{**identity(x), "role": "P2F_R1_BOUND"} for x in (p2e_result, p2e_binding, source)]
        manifest = output / "ex6_p2b_p2f_r1_manifest.csv"
        write_csv(manifest, manifest_rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        external = output / "ex6_p2b_p2f_r1_manifest_external_binding.json"
        write_json(external, {"version": VERSION, "created_at_utc": now(), "status": result["status"], "manifest_filename": manifest.name, "manifest_size_bytes": manifest.stat().st_size, "manifest_sha256": sha256(manifest), "runner_sha256": sha256(Path(__file__).resolve()), "repaired_source_sha256": sha256(source), "adapter_instantiated": False, "runtime_validated": False, "requirements_satisfied": False, "next_gate": result["next_gate"]})
        print(json.dumps({"status": result["status"], "project_root": str(project_root), "aicomp_sdk_importable": True, "adapter_module_importable": True, "expected_class_visible": True, "manifest_sha256": sha256(manifest), "adapter_instantiated": False, "runtime_validated": False, "next_gate": result["next_gate"]}, indent=2))
    except Exception as exc:
        failure = output / "P2F_R1_FAILED.json"
        failure.write_text(json.dumps({"version": VERSION, "created_at_utc": now(), "status": "P2F_R1_PACKAGE_DISCOVERY_PREFLIGHT_BLOCKED", "error_type": type(exc).__name__, "error": str(exc), "sys_path_inserted": inserted, "runtime_validated": False, "requirements_satisfied": False}, indent=2), encoding="utf-8")
        raise
    finally:
        sys.path[:] = original_sys_path

def parse_args():
    p=argparse.ArgumentParser(description=VERSION)
    p.add_argument('--p2e-result', required=True)
    p.add_argument('--p2e-external-binding', required=True)
    p.add_argument('--repaired-source', required=True)
    p.add_argument('--output-dir', required=True)
    return p.parse_args()

if __name__ == '__main__':
    try: main(parse_args())
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr); raise SystemExit(1)
