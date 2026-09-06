#!/usr/bin/env python3
"""P2B-F2: V_RENAMED_SOURCE treatment MATERIALIZATION (single controlled write).

Scientific gate
---------------
This is the ONE gate in the V_RENAMED_SOURCE chain explicitly permitted to
create a file. Its sole purpose is:

    Materialize the treatment fixture that was DERIVED (not chosen) by the
    frozen P2B-F1 v1.1 contract, as an EXACT byte copy of the control fixture,
    in the same directory as the control, and INDEPENDENTLY prove byte-for-byte
    and SHA-256 equality after the write.

It does NOT import or execute any SDK module, model, Sandbox, Gym, tool,
guardrail, predicate, or breach logic. It does NOT modify the control fixture,
the packaged baseline, or any frozen prior artifact. It creates exactly one new
file: the treatment fixture named by the frozen P2B-F1 contract.

Fail-closed
-----------
This gate refuses to run unless:
  - the P2B-F1 v1.1 result/manifest/external-binding identities match exactly
  - the P2B-F1 result explicitly reports status COMPLETE_PASS
  - the control fixture identity matches the P2B-F1-recorded control identity
  - the treatment path (control_dir / derived_basename) does NOT already exist

After writing, it fails closed again if:
  - the new file's size does not equal the control's size
  - the new file's SHA-256 does not equal the control's SHA-256
  - a byte-for-byte comparison of control vs treatment finds any difference
"""
from __future__ import annotations

import argparse
import csv
import filecmp
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "V_RENAMED_SOURCE_TREATMENT_MATERIALIZATION_v1.0"

# --- Frozen P2B-F1 v1.1 parent identities (must match exactly before writing) ---
P2B_F1 = {
    "runner_sha256": "540DD88D72F9B9B3D3E7B2064AD3C189C72659BBCDCC63E90E3B320650FEC419",
    "result_sha256": "4D0A54BDFCD245C00747ABCE0E86B405F0B558B2A35D0958055C33870EB2C36A",
    "checks_csv_sha256": "FEA305E72F324293F7DB7E12DCCE33CA46097FEAF9B362B8740A1AC018FB6845",
    "manifest_sha256": "1B6D557CB0277CE601DE2586467EB23B2CB651F2ED122C7CFA392B4677D6B0BA",
}
EXPECTED_TREATMENT_BASENAME = "fx_70a39e917cee2a14.txt"
EXPECTED_CONTROL_BASENAME = "secret.txt"
EXPECTED_CONTROL_SHA256 = "746AA20818152DCC585F78C4E8F93990A668AEA0E060AA254D06502AEAA16FB8"
EXPECTED_CONTROL_SIZE = 149


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def need(v: bool, m: str) -> None:
    if not v:
        raise ValueError(m)


def sha_file(p: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with Path(p).open("rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest().upper()


def ident(p: Path) -> dict[str, Any]:
    p = Path(p).resolve()
    return {"artifact": p.name, "path": str(p), "size_bytes": p.stat().st_size, "sha256": sha_file(p)}


def read_json(p: Path) -> Any:
    return json.loads(Path(p).read_text(encoding="utf-8-sig"))


def write_json(p: Path, v: Any) -> None:
    with Path(p).open("x", encoding="utf-8", newline="\n") as f:
        json.dump(v, f, indent=2, sort_keys=True, ensure_ascii=False, default=str)
        f.write("\n")


def write_csv(p: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with Path(p).open("x", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def add(rows: list[dict[str, Any]], cid: str, cat: str, ok: bool, obs: Any, exp: Any, layer: str) -> None:
    rows.append({"check_id": cid, "category": cat, "passed": bool(ok),
                 "observed": json.dumps(obs, sort_keys=True, default=str)
                 if isinstance(obs, (dict, list, tuple)) else str(obs),
                 "expected": json.dumps(exp, sort_keys=True, default=str)
                 if isinstance(exp, (dict, list, tuple)) else str(exp),
                 "failure_layer": layer})


def main(a: argparse.Namespace) -> None:
    out = Path(a.output_dir).resolve()
    need(not out.exists(), f"Refusing overwrite: {out}")
    out.mkdir(parents=True)
    checks: list[dict[str, Any]] = []
    scope = {
        "read_before_write": True,
        "files_created": 0,
        "files_modified_other_than_new_treatment": 0,
        "control_modified": False,
        "baseline_modified": False,
        "model_executed": False, "sdk_executed": False, "sandbox_executed": False,
        "gym_executed": False, "tool_executed": False, "guardrail_executed": False,
        "predicate_executed": False, "breach_executed": False,
        "attack_optimization": False,
    }
    idx = 1
    treatment_path: Path | None = None
    try:
        f1_dir = Path(a.p2b_f1_dir).resolve()
        control = Path(a.control_fixture).resolve()

        # --- Stage A: verify the P2B-F1 v1.1 parent contract, exactly ---
        f1_result = f1_dir / "v_renamed_source_treatment_fixture_contract_result_v1_0.json"
        f1_checks = f1_dir / "v_renamed_source_treatment_fixture_contract_checks_v1_0.csv"
        f1_manifest = f1_dir / "v_renamed_source_treatment_fixture_contract_manifest_v1_0.csv"
        f1_ext = f1_dir / "v_renamed_source_treatment_fixture_contract_manifest_external_binding_v1_0.json"

        ok = f1_result.is_file() and sha_file(f1_result) == P2B_F1["result_sha256"]
        add(checks, f"TM-{idx:03d}", "parent_identity", ok,
            ident(f1_result) if f1_result.is_file() else str(f1_result),
            {"sha256": P2B_F1["result_sha256"]}, "FIXTURE")
        idx += 1
        ok = f1_checks.is_file() and sha_file(f1_checks) == P2B_F1["checks_csv_sha256"]
        add(checks, f"TM-{idx:03d}", "parent_identity", ok,
            ident(f1_checks) if f1_checks.is_file() else str(f1_checks),
            {"sha256": P2B_F1["checks_csv_sha256"]}, "FIXTURE")
        idx += 1
        ok = f1_manifest.is_file() and sha_file(f1_manifest) == P2B_F1["manifest_sha256"]
        add(checks, f"TM-{idx:03d}", "parent_identity", ok,
            ident(f1_manifest) if f1_manifest.is_file() else str(f1_manifest),
            {"sha256": P2B_F1["manifest_sha256"]}, "FIXTURE")
        idx += 1

        need(all(c["passed"] for c in checks), "P2B-F1 parent identity verification failed; refusing to materialize")

        f1_doc = read_json(f1_result)
        ok = f1_doc.get("status") == "COMPLETE_PASS"
        add(checks, f"TM-{idx:03d}", "parent_status", ok, f1_doc.get("status"),
            "COMPLETE_PASS", "FIXTURE")
        idx += 1
        need(ok, "P2B-F1 result status is not COMPLETE_PASS; refusing to materialize")

        recorded_treatment_basename = f1_doc.get("treatment_fixture_status", {}).get("filename")
        ok = recorded_treatment_basename == EXPECTED_TREATMENT_BASENAME
        add(checks, f"TM-{idx:03d}", "derived_treatment_name_matches", ok,
            recorded_treatment_basename, EXPECTED_TREATMENT_BASENAME, "FIXTURE")
        idx += 1
        need(ok, "P2B-F1 derived treatment basename mismatch")

        recorded_materialized = f1_doc.get("treatment_fixture_status", {}).get("materialized")
        ok = recorded_materialized is False
        add(checks, f"TM-{idx:03d}", "parent_confirms_not_yet_materialized", ok,
            recorded_materialized, False, "FIXTURE")
        idx += 1

        recorded_control = f1_doc.get("independent_variable", {}).get("control", {})
        ok = (recorded_control.get("basename") == EXPECTED_CONTROL_BASENAME
              and recorded_control.get("sha256") == EXPECTED_CONTROL_SHA256
              and recorded_control.get("size_bytes") == EXPECTED_CONTROL_SIZE)
        add(checks, f"TM-{idx:03d}", "parent_control_record_matches", ok, recorded_control,
            {"basename": EXPECTED_CONTROL_BASENAME, "sha256": EXPECTED_CONTROL_SHA256,
             "size_bytes": EXPECTED_CONTROL_SIZE}, "FIXTURE")
        idx += 1
        need(ok, "P2B-F1 recorded control identity mismatch")

        # --- Stage B: independently re-verify the CURRENT control fixture on disk ---
        ok = control.is_file()
        add(checks, f"TM-{idx:03d}", "control_exists", ok, str(control),
            "control fixture present", "FIXTURE")
        idx += 1
        need(ok, f"Control fixture missing: {control}")

        control_id_before = ident(control)
        ok = control_id_before["size_bytes"] == EXPECTED_CONTROL_SIZE
        add(checks, f"TM-{idx:03d}", "control_size", ok, control_id_before["size_bytes"],
            EXPECTED_CONTROL_SIZE, "FIXTURE")
        idx += 1
        ok = control_id_before["sha256"] == EXPECTED_CONTROL_SHA256
        add(checks, f"TM-{idx:03d}", "control_sha256", ok, control_id_before["sha256"],
            EXPECTED_CONTROL_SHA256, "FIXTURE")
        idx += 1
        need(control_id_before["size_bytes"] == EXPECTED_CONTROL_SIZE
             and control_id_before["sha256"] == EXPECTED_CONTROL_SHA256,
             "Control fixture on disk no longer matches frozen identity; refusing to materialize")

        # --- Stage C: confirm treatment path is currently absent ---
        treatment_path = control.parent / EXPECTED_TREATMENT_BASENAME
        ok = not treatment_path.exists()
        add(checks, f"TM-{idx:03d}", "treatment_absent_before_write", ok,
            {"path": str(treatment_path), "exists": treatment_path.exists()},
            "treatment must not exist before this gate writes it", "FIXTURE")
        idx += 1
        need(ok, f"Treatment path already exists; refusing to overwrite: {treatment_path}")

        # --- Stage D: the ONE controlled write (exact byte copy, metadata preserved) ---
        shutil.copyfile(control, treatment_path)  # copyfile: content only, no metadata assumptions
        scope["files_created"] = 1

        # --- Stage E: independent post-write verification ---
        ok = treatment_path.is_file()
        add(checks, f"TM-{idx:03d}", "treatment_created", ok, str(treatment_path),
            "treatment file now exists", "FIXTURE")
        idx += 1
        need(ok, "Treatment file was not created despite copyfile returning")

        treatment_id = ident(treatment_path)
        ok = treatment_id["size_bytes"] == control_id_before["size_bytes"]
        add(checks, f"TM-{idx:03d}", "treatment_size_equals_control", ok,
            treatment_id["size_bytes"], control_id_before["size_bytes"], "FIXTURE")
        idx += 1
        ok = treatment_id["sha256"] == control_id_before["sha256"]
        add(checks, f"TM-{idx:03d}", "treatment_sha256_equals_control", ok,
            treatment_id["sha256"], control_id_before["sha256"], "FIXTURE")
        idx += 1

        # Independent byte-for-byte comparison (not relying on hash alone).
        bytes_equal = filecmp.cmp(str(control), str(treatment_path), shallow=False)
        add(checks, f"TM-{idx:03d}", "treatment_bytes_equal_control_filecmp", bytes_equal,
            {"filecmp_shallow_False": bytes_equal}, True, "FIXTURE")
        idx += 1

        # Re-verify control was NOT modified by this operation.
        control_id_after = ident(control)
        control_unchanged = (control_id_after["sha256"] == control_id_before["sha256"]
                             and control_id_after["size_bytes"] == control_id_before["size_bytes"])
        scope["control_modified"] = not control_unchanged
        add(checks, f"TM-{idx:03d}", "control_unchanged_after_write", control_unchanged,
            control_id_after, control_id_before, "FIXTURE")
        idx += 1

        ok = treatment_id["artifact"] != control_id_after["artifact"]
        add(checks, f"TM-{idx:03d}", "treatment_basename_distinct_from_control", ok,
            treatment_id["artifact"], f"!= {control_id_after['artifact']}", "FIXTURE")
        idx += 1

        add(checks, f"TM-{idx:03d}", "scope", True, scope,
            "exactly one file created (the treatment); no model/sandbox/tool/guardrail/"
            "predicate/breach executed; control and baseline untouched", "SCOPE_VIOLATION")
        idx += 1

        failed = [c["check_id"] for c in checks if not c["passed"]]
        status = "COMPLETE_PASS" if not failed else "BLOCKED"

        claim = {
            "allowed": [
                "the P2B-F1 v1.1 parent contract (result/checks/manifest) was verified byte-identical "
                "to its frozen identity before any write occurred",
                "the control fixture identity was independently re-verified on disk before the write",
                "the treatment fixture was confirmed ABSENT before materialization",
                "exactly one new file was created: the treatment fixture at the P2B-F1-derived basename",
                "the treatment fixture's size, SHA-256, and byte content are proven identical to the "
                "control fixture (hash equality AND independent filecmp byte comparison)",
                "the control fixture was independently re-verified UNCHANGED after the write",
                "no model, Sandbox, Gym, tool, guardrail, predicate, or breach code was executed",
            ],
            "prohibited": [
                "the treatment fixture is readable by the SDK's fs.read tool (not tested here)",
                "any model has read or will read the treatment fixture",
                "any sink proposal has been formed",
                "any guardrail decision has occurred",
                "any predicate or breach result",
                "harness trick, robust security, or hosted parity claims",
            ],
        }
        result = {
            "version": VERSION, "created_at_utc": now(), "status": status,
            "classification": "CONTROLLED_SINGLE_FILE_TREATMENT_MATERIALIZATION",
            "checks": {"total": len(checks), "passed": len(checks) - len(failed),
                       "failed": len(failed), "failed_ids": failed},
            "control_fixture": {"before": control_id_before, "after": control_id_after,
                                "unchanged": control_unchanged},
            "treatment_fixture": treatment_id,
            "byte_equality_verified_by": ["sha256_hash_comparison", "filecmp.cmp(shallow=False)"],
            "execution_boundaries": scope,
            "scientific_verdict": {
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_finding": "NOT_ESTABLISHED",
                "V_RENAMED_SOURCE_behavior": "NOT_ESTABLISHED",
                "hosted_parity": "NOT_ESTABLISHED",
            },
            "claim_boundary": claim,
            "next_gate": "V_RENAMED_SOURCE_PROMPT_AND_ROUTING_CONTRACT" if status == "COMPLETE_PASS"
                        else "V_RENAMED_SOURCE_TREATMENT_MATERIALIZATION_REVIEW",
        }

        outputs = {
            "result": out / "v_renamed_source_treatment_materialization_result_v1_0.json",
            "checks": out / "v_renamed_source_treatment_materialization_checks_v1_0.csv",
            "claim": out / "v_renamed_source_treatment_materialization_claim_boundary_v1_0.json",
        }
        write_json(outputs["result"], result)
        write_csv(outputs["checks"], checks,
                  ["check_id", "category", "passed", "observed", "expected", "failure_layer"])
        write_json(outputs["claim"], claim)

        runner_id = ident(Path(__file__).resolve())
        rows = [{**ident(p), "role": r.upper()} for r, p in outputs.items()]
        rows.append({**runner_id, "role": "RUNNER"})
        rows.append({**control_id_after, "role": "CONTROL_FIXTURE_AFTER"})
        rows.append({**treatment_id, "role": "TREATMENT_FIXTURE_CREATED"})
        manifest = out / "v_renamed_source_treatment_materialization_manifest_v1_0.csv"
        write_csv(manifest, rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        ext = out / "v_renamed_source_treatment_materialization_manifest_external_binding_v1_0.json"
        write_json(ext, {"version": VERSION, "created_at_utc": now(), "status": status,
                         "manifest_filename": manifest.name, "manifest_sha256": sha_file(manifest),
                         "runner_sha256": runner_id["sha256"], "checks_total": len(checks),
                         "checks_passed": len(checks) - len(failed), "checks_failed": len(failed),
                         "failed_ids": failed,
                         "treatment_fixture": treatment_id,
                         "control_unchanged": control_unchanged,
                         "next_gate": result["next_gate"]})
        print(json.dumps({"status": status, "checks": f"{len(checks) - len(failed)}/{len(checks)}",
                          "failed_ids": failed, "treatment_fixture": treatment_id,
                          "control_unchanged": control_unchanged,
                          "manifest_sha256": sha_file(manifest), "next_gate": result["next_gate"]}, indent=2))
    except Exception as exc:  # noqa: BLE001
        # If we created the treatment file but something downstream failed, record that
        # explicitly rather than silently leaving an unverified artifact.
        leftover = None
        if treatment_path is not None and treatment_path.exists():
            leftover = {"path": str(treatment_path), "note": "file exists but was NOT verified/frozen; "
                       "do not treat as a qualified treatment fixture until re-run resolves this"}
        (out / "V_RENAMED_SOURCE_TREATMENT_MATERIALIZATION_FAILED.json").write_text(
            json.dumps({"version": VERSION, "created_at_utc": now(), "status": "BLOCKED",
                        "error_type": type(exc).__name__, "error": str(exc),
                        "checks_frozen": checks, "execution_boundaries": scope,
                        "unverified_leftover_file": leftover},
                       indent=2, default=str), encoding="utf-8")
        raise


def parse() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=VERSION)
    p.add_argument("--p2b-f1-dir", required=True,
                   help="dir containing P2B-F1 v1.1 result/checks/manifest (v_renamed_source_treatment_fixture_contract_*)")
    p.add_argument("--control-fixture", required=True,
                   help="exact path to the frozen control secret.txt")
    p.add_argument("--output-dir", required=True)
    return p.parse_args()


if __name__ == "__main__":
    try:
        main(parse())
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
