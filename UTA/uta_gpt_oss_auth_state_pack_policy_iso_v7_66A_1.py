#!/usr/bin/env python3
"""Strict guardrail-binding correction for v7.66A packaged-policy isolation.

Loads the frozen v7.66A runner, replaces only guardrail construction with
explicit SDK class binding, and validates the produced preflight/report.
No name scanning and no fallback to GuardrailBase are permitted.
"""
from __future__ import annotations
import argparse, hashlib, importlib, importlib.util, json, sys
from pathlib import Path

VERSION = "UTA_GPT_OSS_AUTHORITY_STATE_PACKAGED_POLICY_ISOLATION_v7.66A.1"
EXPECTED = {
    "default_allow": "aicomp_sdk.guardrails.base.GuardrailBase",
    "base_rules": "aicomp_sdk.attacks.baselines.guardrail_rules.Guardrail",
    "optimal": "aicomp_sdk.guardrails.optimal.Guardrail",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def strict_instantiate_guardrail(kind: str, _ignored_base=None):
    if kind not in EXPECTED:
        raise ValueError(f"Unsupported guardrail kind: {kind}")
    if kind == "default_allow":
        module_name, class_name = "aicomp_sdk.guardrails.base", "GuardrailBase"
    elif kind == "base_rules":
        module_name, class_name = (
            "aicomp_sdk.attacks.baselines.guardrail_rules", "Guardrail"
        )
    else:
        module_name, class_name = "aicomp_sdk.guardrails.optimal", "Guardrail"
    module = importlib.import_module(module_name)
    cls = getattr(module, class_name, None)
    if cls is None:
        raise RuntimeError(f"Missing required class {module_name}.{class_name}")
    obj = cls()
    actual = type(obj).__module__ + "." + type(obj).__qualname__
    if actual != EXPECTED[kind]:
        raise RuntimeError(
            f"Guardrail identity mismatch for {kind}: expected={EXPECTED[kind]} actual={actual}"
        )
    return obj


def validate_outputs(out_dir: Path) -> None:
    preflight = out_dir / "uta_gpt_oss_authority_state_packaged_policy_isolation_v7_66A_preflight.json"
    report = out_dir / "uta_gpt_oss_authority_state_packaged_policy_isolation_v7_66A.json"
    if not preflight.is_file() or not report.is_file():
        raise RuntimeError("Expected v7.66A preflight/report artifacts were not produced")
    pre = json.loads(preflight.read_text(encoding="utf-8"))
    observed = {
        key: value.get("type")
        for key, value in (pre.get("guardrail_preflight") or {}).items()
    }
    if observed != EXPECTED:
        raise RuntimeError(
            "Post-run guardrail preflight mismatch: "
            + json.dumps({"expected": EXPECTED, "observed": observed}, sort_keys=True)
        )
    rep = json.loads(report.read_text(encoding="utf-8"))
    rows = rep.get("rows") or []
    if len(rows) != 27:
        raise RuntimeError(f"Expected 27 rows, observed {len(rows)}")
    for row in rows:
        kind = row.get("guardrail")
        if kind not in EXPECTED:
            raise RuntimeError(f"Unexpected row guardrail label: {kind}")
    audit = {
        "schema": "UTA_V766A1_STRICT_GUARDRAIL_BINDING_AUDIT_V1",
        "version": VERSION,
        "base_report": report.name,
        "base_report_sha256": sha256_file(report),
        "base_preflight": preflight.name,
        "base_preflight_sha256": sha256_file(preflight),
        "expected_and_observed_types": EXPECTED,
        "row_count": len(rows),
        "validation": "PASSED",
        "interpretation_boundary": (
            "This audit validates concrete guardrail class identity. Scientific outcome "
            "interpretation remains based on the frozen ordered tool events."
        ),
    }
    audit_path = out_dir / "uta_gpt_oss_authority_state_packaged_policy_isolation_v7_66A_1_binding_audit.json"
    if audit_path.exists():
        raise FileExistsError(f"Refusing overwrite: {audit_path}")
    audit_path.write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
    print(f"Strict binding audit: {audit_path}")
    print(f"Audit SHA256: {sha256_file(audit_path)}")


def main() -> int:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--isolation-runner", required=True, type=Path)
    pre.add_argument("--out-dir", required=True, type=Path)
    args, remaining = pre.parse_known_args()
    base_runner = args.base_runner.resolve()
    out_dir = args.out_dir.resolve()
    if not base_runner.is_file():
        raise SystemExit(f"Missing base runner: {base_runner}")
    module = load_module(base_runner, "uta_v766a_strict_binding_base")
    module.instantiate_guardrail = strict_instantiate_guardrail
    module.VERSION = VERSION
    old_argv = sys.argv
    sys.argv = [str(base_runner), *remaining, "--out-dir", str(out_dir)]
    try:
        rc = int(module.main())
    finally:
        sys.argv = old_argv
    if rc == 0:
        validate_outputs(out_dir)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
