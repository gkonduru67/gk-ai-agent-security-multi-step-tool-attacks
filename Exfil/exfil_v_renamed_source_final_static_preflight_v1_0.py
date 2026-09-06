#!/usr/bin/env python3
"""P2B-Q: V_RENAMED_SOURCE FINAL STATIC PREFLIGHT (read-only, last gate before P2C).

Scientific gate
---------------
This is the LAST static gate before any model, Sandbox, Gym, tool, guardrail,
predicate, or breach code is permitted to execute. Its purpose:

    Immediately before authorizing P2C runtime, re-verify (a) the entire P2B
    sub-chain (F1 fixture contract, F2 materialization, P prompt/routing
    contract) as ONE consolidated chain, (b) an IMMEDIATE rehash of the five
    core SDK contract files required by the standing
    sdk_contract_to_revalidate_before_runtime_claim status, (c) the V2.1
    lineage guardrail/ledger and fs.py identities, and (d) freeze the exact
    ordered-event evidence schema that P2C's output must populate -- all
    without executing any of it.

This gate performs NO fixture creation or mutation, and executes NO model,
SDK, Sandbox, Gym, tool, guardrail, predicate, or breach code. It only reads
and hashes files, and parses/validates already-frozen JSON documents.

Fail-closed
-----------
Refuses to reach a GO decision if ANY of the following do not hold exactly:
  - P2B-F1 v1.1 runner/result/checks/manifest identities unchanged
  - P2B-F2 runner/result/checks/claim/manifest identities unchanged, and its
    result explicitly reports the treatment fixture byte-identical to control
  - P2B-P v1.1 runner/result/checks/claim/manifest identities unchanged, and
    its result explicitly reports COMPLETE_PASS with the exact substitution
    proof method (not the superseded fuzzy-diff method)
  - the five SDK contract files (predicates.py, sandbox.py, api.py, gym.py,
    optimal.py) hash IDENTICAL to their expected frozen digests, freshly
    computed NOW (not reused from any earlier gate's cached value)
  - the V2.1 lineage guardrail, V2.1 successful-read ledger, and fs.py hash
    identical to their expected frozen digests
  - the treatment and control fixtures on disk still hash identical to each
    other and to their frozen digest
  - the frozen v1.2 per-run evidence schema parent still hashes identical
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "V_RENAMED_SOURCE_FINAL_STATIC_PREFLIGHT_v1.0"

# --- P2B-F1 v1.1 parent identities ---
P2B_F1 = {
    "runner": ("exfil_v_renamed_source_treatment_fixture_contract_v1_1.py",
              "540DD88D72F9B9B3D3E7B2064AD3C189C72659BBCDCC63E90E3B320650FEC419"),
    "result": ("v_renamed_source_treatment_fixture_contract_result_v1_0.json",
              "4D0A54BDFCD245C00747ABCE0E86B405F0B558B2A35D0958055C33870EB2C36A"),
    "checks": ("v_renamed_source_treatment_fixture_contract_checks_v1_0.csv",
              "FEA305E72F324293F7DB7E12DCCE33CA46097FEAF9B362B8740A1AC018FB6845"),
    "manifest": ("v_renamed_source_treatment_fixture_contract_manifest_v1_0.csv",
                "1B6D557CB0277CE601DE2586467EB23B2CB651F2ED122C7CFA392B4677D6B0BA"),
}
# --- P2B-F2 parent identities ---
P2B_F2 = {
    "runner": ("exfil_v_renamed_source_treatment_materialization_v1_0.py",
              "E2E84F60F7B5C3C4B4088E92570353895120413607F957B8F0992AD09ECB6B27"),
    "result": ("v_renamed_source_treatment_materialization_result_v1_0.json",
              "2DE77801C8D3D0D93183254E1A87E590FC64E3B0DA87E5D9ADB2CB8A51B8CBC5"),
    "checks": ("v_renamed_source_treatment_materialization_checks_v1_0.csv",
              "9F81188D22E20C26196BCA112FABB89BEC1F9BEB77C9F637B050DFF9D9D0FB92"),
    "claim": ("v_renamed_source_treatment_materialization_claim_boundary_v1_0.json",
             "9FDB5AA0DFD80679D7B1CDEADCCBF74D46A7D84EF5D22A276D4119E6BCAB67C5"),
    "manifest": ("v_renamed_source_treatment_materialization_manifest_v1_0.csv",
                "AFF410D2FEBD3A6271DD1EDE96C2DADF49BF3F9EF532B74635A1FE58E5639038"),
}
# --- P2B-P v1.1 parent identities ---
P2B_P = {
    "runner": ("exfil_v_renamed_source_prompt_and_routing_contract_v1_1.py",
              "F51BDE031D63301E10517870A3218995C99C10AA00E78E2C5D5F071883FD4E65"),
    "result": ("v_renamed_source_prompt_and_routing_contract_result_v1_0.json",
              "AF07FD4957A4DC8EE066A950E6D510B90F6FDB08D684BDDF412346204972BB45"),
    "checks": ("v_renamed_source_prompt_and_routing_contract_checks_v1_0.csv",
              "5E2E346D23DA6B1386B76C6B83D8A3C9FFF1B4000780987DF5F92920788CDE96"),
    "claim": ("v_renamed_source_prompt_and_routing_contract_claim_boundary_v1_0.json",
             "F1D7B268931306B754698F770A37D8198792E20D6EB67F8DDC7EF62B682C7F12"),
    "manifest": ("v_renamed_source_prompt_and_routing_contract_manifest_v1_0.csv",
                "DC07D9879F09EB61A375D55740F011C788873177C50C1CB6523E0A7F83A19385"),
}

# --- Core SDK contract files (must revalidate IMMEDIATELY before any runtime claim) ---
SDK_CONTRACT_FILES = {
    "predicate_file": ("aicomp_sdk/core/predicates.py",
                       "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"),
    "sandbox_file": ("aicomp_sdk/core/env/sandbox.py",
                     "B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0"),
    "api_file": ("aicomp_sdk/core/env/api.py",
                "60F1E4424EC3DEE73186F87ED1184D2CA1DBC4C2A0022004DECEC8B6E94C7CB1"),
    "gym_file": ("aicomp_sdk/core/env/gym.py",
                "8BBC3479515C388717D76FE9964D957A7CBD9BFB97C28AA894E9C51E3051F8AF"),
    "packaged_optimal_file": ("aicomp_sdk/guardrails/optimal.py",
                             "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED"),
}
LINEAGE_FILES = {
    "v21_guardrail": ("aicomp_sdk_exfil_v2_1/lineage_aware_exfil_guardrail_v2_1.py",
                      "2AC1CA55FB0C18460F50B35677F5ECD9EB3477CFB21F9C19F44A48C7AEFD5C26"),
    "v21_ledger": ("aicomp_sdk_exfil_v2_1/successful_read_ledger_v2_1.py",
                  "18146742E6866C491A032AA96EFC248FFED05706895D32FDE724145D0878009C"),
    "fs_tool": ("aicomp_sdk/core/tools/fs.py",
               "4B8C54032ED807CE4C35BAB403EE622141881158E10F600A4B6D329E6D6F95B8"),
}

CONTROL_EXPECTED_SHA256 = "746AA20818152DCC585F78C4E8F93990A668AEA0E060AA254D06502AEAA16FB8"
TREATMENT_EXPECTED_SHA256 = "746AA20818152DCC585F78C4E8F93990A668AEA0E060AA254D06502AEAA16FB8"
TREATMENT_EXPECTED_BASENAME = "fx_70a39e917cee2a14.txt"
CONTROL_EXPECTED_BASENAME = "secret.txt"
CONTROL_PROMPT_SHA_EXPECTED = "3F8BA146E8B3DEDD45EBB4D276A6D55F0BEC8C7C0EFAC2B272B3B21239635176"
TREATMENT_PROMPT_SHA_EXPECTED = "BFB31FCB66C7DB60DEC9DF10F80152546C6491517E9616B9B8D514C5E8D234E0"
V1_2_PER_RUN_SHA256 = "7CDD7B4DE50F67A52BC6A065A30869639DD6F0B9B2B816FFA258FFCBFB509940"

# The exact ordered-event evidence schema P2C must populate per tool event.
FROZEN_ORDERED_EVENT_SCHEMA = {
    "required_fields": ["index", "name", "ok", "error", "source", "args", "output_sha256"],
    "args_redaction_rule": "any resolved secret value MUST be replaced with "
                           "<REDACTED_SECRET_SHA256:first16hexuppercase> before persistence",
    "raw_vs_normalized": "raw tool output MUST be hashed (output_sha256) separately from any "
                        "normalized/decoded candidate; both preserved distinctly if both exist",
    "ordering": "events MUST be recorded in exact chronological/execution order; no reordering "
               "or deduplication permitted",
}


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


def verify_group(checks: list[dict[str, Any]], idx: int, group_name: str, base_dir: Path,
                 group: dict[str, tuple[str, str]]) -> tuple[int, dict[str, Any]]:
    idents: dict[str, Any] = {}
    for key, (fname, expected) in group.items():
        p = base_dir / fname
        ok = p.is_file() and sha_file(p) == expected
        add(checks, f"PQ-{idx:03d}", f"{group_name}_{key}", ok,
            ident(p) if p.is_file() else str(p), {"sha256": expected}, "FIXTURE")
        idx += 1
        if p.is_file():
            idents[key] = ident(p)
    return idx, idents


def main(a: argparse.Namespace) -> None:
    out = Path(a.output_dir).resolve()
    need(not out.exists(), f"Refusing overwrite: {out}")
    out.mkdir(parents=True)
    checks: list[dict[str, Any]] = []
    scope = {
        "read_only": True, "fixture_created": False, "fixture_mutated": False,
        "model_executed": False, "sdk_executed": False, "sandbox_executed": False,
        "gym_executed": False, "tool_executed": False, "guardrail_executed": False,
        "predicate_executed": False, "breach_executed": False,
        "attack_optimization": False,
    }
    idx = 1
    try:
        project = Path(a.project_root).resolve()
        f1_dir = Path(a.p2b_f1_dir).resolve()
        f2_dir = Path(a.p2b_f2_dir).resolve()
        p_dir = Path(a.p2b_p_dir).resolve()
        v12_dir = Path(a.v1_2_dir).resolve()
        control = Path(a.control_fixture).resolve()
        treatment = Path(a.treatment_fixture).resolve()

        # --- Stage A: consolidated re-verification of the entire P2B sub-chain ---
        idx, f1_ids = verify_group(checks, idx, "P2B_F1", f1_dir, P2B_F1)
        idx, f2_ids = verify_group(checks, idx, "P2B_F2", f2_dir, P2B_F2)
        idx, p_ids = verify_group(checks, idx, "P2B_P", p_dir, P2B_P)

        need(all(c["passed"] for c in checks), "One or more P2B sub-chain identity checks failed; refusing preflight")

        # --- Stage B: parse frozen results and cross-check their internal claims ---
        f1_doc = json.loads((f1_dir / P2B_F1["result"][0]).read_text(encoding="utf-8-sig"))
        ok = f1_doc.get("status") == "COMPLETE_PASS"
        add(checks, f"PQ-{idx:03d}", "P2B_F1_status", ok, f1_doc.get("status"), "COMPLETE_PASS", "FIXTURE")
        idx += 1

        f2_doc = json.loads((f2_dir / P2B_F2["result"][0]).read_text(encoding="utf-8-sig"))
        ok = f2_doc.get("status") == "COMPLETE_PASS"
        add(checks, f"PQ-{idx:03d}", "P2B_F2_status", ok, f2_doc.get("status"), "COMPLETE_PASS", "FIXTURE")
        idx += 1
        f2_treatment = f2_doc.get("treatment_fixture", {})
        f2_control = f2_doc.get("control_fixture", {}).get("after", {})
        ok = (f2_treatment.get("sha256") == f2_control.get("sha256")
              and f2_control.get("sha256") == CONTROL_EXPECTED_SHA256)
        add(checks, f"PQ-{idx:03d}", "P2B_F2_reports_byte_identical_pair", ok,
            {"treatment_sha256": f2_treatment.get("sha256"), "control_sha256": f2_control.get("sha256")},
            {"both_equal": CONTROL_EXPECTED_SHA256}, "FIXTURE")
        idx += 1

        p_doc = json.loads((p_dir / P2B_P["result"][0]).read_text(encoding="utf-8-sig"))
        ok = p_doc.get("status") == "COMPLETE_PASS"
        add(checks, f"PQ-{idx:03d}", "P2B_P_status", ok, p_doc.get("status"), "COMPLETE_PASS", "FIXTURE")
        idx += 1
        proof_method = p_doc.get("treatment_prompt", {}).get("substitution_proof", {}).get("method")
        ok = proof_method == "exact_prefix_suffix_reconstruction_not_fuzzy_diff"
        add(checks, f"PQ-{idx:03d}", "P2B_P_used_corrected_substitution_method", ok, proof_method,
            "exact_prefix_suffix_reconstruction_not_fuzzy_diff", "FIXTURE")
        idx += 1
        ok = (p_doc.get("control_prompt", {}).get("sha256") == CONTROL_PROMPT_SHA_EXPECTED
              and p_doc.get("treatment_prompt", {}).get("sha256") == TREATMENT_PROMPT_SHA_EXPECTED)
        add(checks, f"PQ-{idx:03d}", "P2B_P_prompt_hashes_match_frozen", ok,
            {"control": p_doc.get("control_prompt", {}).get("sha256"),
             "treatment": p_doc.get("treatment_prompt", {}).get("sha256")},
            {"control": CONTROL_PROMPT_SHA_EXPECTED, "treatment": TREATMENT_PROMPT_SHA_EXPECTED}, "FIXTURE")
        idx += 1
        declared_hops = p_doc.get("routing_contract", {}).get("p2c_max_tool_hops_declared")
        ok = isinstance(declared_hops, int) and declared_hops >= 1
        add(checks, f"PQ-{idx:03d}", "P2B_P_hop_budget_present", ok, declared_hops, ">=1", "ROUTING")
        idx += 1

        # --- Stage C: IMMEDIATE rehash of the five core SDK contract files (NOW, not cached) ---
        sdk_idents: dict[str, Any] = {}
        for key, (rel, expected) in SDK_CONTRACT_FILES.items():
            p = project / rel
            ok = p.is_file() and sha_file(p) == expected
            add(checks, f"PQ-{idx:03d}", f"sdk_contract_{key}", ok,
                ident(p) if p.is_file() else str(p), {"sha256": expected}, "FIXTURE")
            idx += 1
            if p.is_file():
                sdk_idents[key] = ident(p)

        # --- Stage D: V2.1 lineage + fs.py re-verification ---
        lineage_idents: dict[str, Any] = {}
        for key, (rel, expected) in LINEAGE_FILES.items():
            p = project / rel
            ok = p.is_file() and sha_file(p) == expected
            add(checks, f"PQ-{idx:03d}", f"lineage_{key}", ok,
                ident(p) if p.is_file() else str(p), {"sha256": expected}, "FIXTURE")
            idx += 1
            if p.is_file():
                lineage_idents[key] = ident(p)

        # --- Stage E: fixtures re-verified on disk, right now ---
        ok = control.is_file() and sha_file(control) == CONTROL_EXPECTED_SHA256 and control.name == CONTROL_EXPECTED_BASENAME
        add(checks, f"PQ-{idx:03d}", "control_fixture_now", ok,
            ident(control) if control.is_file() else str(control),
            {"basename": CONTROL_EXPECTED_BASENAME, "sha256": CONTROL_EXPECTED_SHA256}, "FIXTURE")
        idx += 1
        ok = (treatment.is_file() and sha_file(treatment) == TREATMENT_EXPECTED_SHA256
              and treatment.name == TREATMENT_EXPECTED_BASENAME)
        add(checks, f"PQ-{idx:03d}", "treatment_fixture_now", ok,
            ident(treatment) if treatment.is_file() else str(treatment),
            {"basename": TREATMENT_EXPECTED_BASENAME, "sha256": TREATMENT_EXPECTED_SHA256}, "FIXTURE")
        idx += 1

        # --- Stage F: v1.2 per-run evidence-schema parent re-verified ---
        v12_per_run = v12_dir / "model_generation_exfiltration_v1_2_per_run.json"
        ok = v12_per_run.is_file() and sha_file(v12_per_run) == V1_2_PER_RUN_SHA256
        add(checks, f"PQ-{idx:03d}", "v1_2_per_run_schema_parent", ok,
            ident(v12_per_run) if v12_per_run.is_file() else str(v12_per_run),
            {"sha256": V1_2_PER_RUN_SHA256}, "FIXTURE")
        idx += 1

        # --- Stage G: scope ---
        add(checks, f"PQ-{idx:03d}", "scope", True, scope,
            "read-only re-verification and immediate rehash only; no fixture created/mutated; "
            "no model/sdk/sandbox/gym/tool/guardrail/predicate/breach executed", "SCOPE_VIOLATION")
        idx += 1

        failed = [c["check_id"] for c in checks if not c["passed"]]
        status = "GO" if not failed else "STOP"

        claim = {
            "allowed": [
                "the entire P2B sub-chain (F1, F2, P) was re-verified byte-identical to its frozen identity",
                "each P2B sub-gate's internal result was cross-checked (status, byte-identity claims, "
                "corrected substitution method, prompt hashes, hop-budget presence)",
                "the five core SDK contract files were rehashed IMMEDIATELY (not reused from any prior "
                "cached value) and confirmed unchanged since Stage-0",
                "the V2.1 lineage guardrail, V2.1 successful-read ledger, and fs.py were re-verified unchanged",
                "the control and treatment fixtures were re-verified on disk, right now, still byte-identical",
                "the v1.2 per-run evidence-schema parent was re-verified unchanged",
                "the exact ordered-event evidence schema P2C must populate was frozen",
                f"final decision: {status}",
            ],
            "prohibited": [
                "any model, SDK, Sandbox, Gym, tool, guardrail, predicate, or breach execution occurred",
                "any fixture was created or mutated by this gate",
                "any claim about V_RENAMED_SOURCE runtime behavior, harness trick, robust security, "
                "or hosted parity",
                "a GO decision here constitutes a prediction of P2C's outcome",
            ],
        }
        result = {
            "version": VERSION, "created_at_utc": now(), "status": status,
            "classification": "READ_ONLY_FINAL_STATIC_PREFLIGHT_CONSOLIDATED_CHAIN_VERIFICATION",
            "checks": {"total": len(checks), "passed": len(checks) - len(failed),
                       "failed": len(failed), "failed_ids": failed},
            "p2b_f1_identities": f1_ids, "p2b_f2_identities": f2_ids, "p2b_p_identities": p_ids,
            "sdk_contract_identities_rehashed_now": sdk_idents,
            "lineage_identities_rehashed_now": lineage_idents,
            "control_fixture_now": ident(control) if control.is_file() else None,
            "treatment_fixture_now": ident(treatment) if treatment.is_file() else None,
            "frozen_prompt_digests": {"control": CONTROL_PROMPT_SHA_EXPECTED, "treatment": TREATMENT_PROMPT_SHA_EXPECTED},
            "p2c_max_tool_hops_declared": declared_hops,
            "frozen_ordered_event_evidence_schema": FROZEN_ORDERED_EVENT_SCHEMA,
            "execution_boundaries": scope,
            "scientific_verdict": {
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_finding": "NOT_ESTABLISHED",
                "V_RENAMED_SOURCE_behavior": "NOT_ESTABLISHED",
                "hosted_parity": "NOT_ESTABLISHED",
            },
            "claim_boundary": claim,
            "next_gate": "V_RENAMED_SOURCE_CONTROLLED_RUNTIME" if status == "GO"
                        else "V_RENAMED_SOURCE_FINAL_STATIC_PREFLIGHT_REVIEW",
        }

        outputs = {
            "result": out / "v_renamed_source_final_static_preflight_result_v1_0.json",
            "checks": out / "v_renamed_source_final_static_preflight_checks_v1_0.csv",
            "claim": out / "v_renamed_source_final_static_preflight_claim_boundary_v1_0.json",
        }
        write_json(outputs["result"], result)
        write_csv(outputs["checks"], checks,
                  ["check_id", "category", "passed", "observed", "expected", "failure_layer"])
        write_json(outputs["claim"], claim)

        runner_id = ident(Path(__file__).resolve())
        rows = [{**ident(p), "role": r.upper()} for r, p in outputs.items()]
        rows.append({**runner_id, "role": "RUNNER"})
        for label, d in (("P2B_F1", f1_ids), ("P2B_F2", f2_ids), ("P2B_P", p_ids),
                        ("SDK", sdk_idents), ("LINEAGE", lineage_idents)):
            for k, v in d.items():
                rows.append({**v, "role": f"{label}_{k.upper()}"})
        if control.is_file():
            rows.append({**ident(control), "role": "CONTROL_FIXTURE"})
        if treatment.is_file():
            rows.append({**ident(treatment), "role": "TREATMENT_FIXTURE"})
        manifest = out / "v_renamed_source_final_static_preflight_manifest_v1_0.csv"
        write_csv(manifest, rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        ext = out / "v_renamed_source_final_static_preflight_manifest_external_binding_v1_0.json"
        write_json(ext, {"version": VERSION, "created_at_utc": now(), "status": status,
                         "manifest_filename": manifest.name, "manifest_sha256": sha_file(manifest),
                         "runner_sha256": runner_id["sha256"], "checks_total": len(checks),
                         "checks_passed": len(checks) - len(failed), "checks_failed": len(failed),
                         "failed_ids": failed, "p2c_max_tool_hops_declared": declared_hops,
                         "next_gate": result["next_gate"]})
        print(json.dumps({"status": status, "checks": f"{len(checks) - len(failed)}/{len(checks)}",
                          "failed_ids": failed, "p2c_max_tool_hops_declared": declared_hops,
                          "manifest_sha256": sha_file(manifest), "next_gate": result["next_gate"]}, indent=2))
    except Exception as exc:  # noqa: BLE001
        (out / "V_RENAMED_SOURCE_FINAL_STATIC_PREFLIGHT_FAILED.json").write_text(
            json.dumps({"version": VERSION, "created_at_utc": now(), "status": "BLOCKED",
                        "error_type": type(exc).__name__, "error": str(exc),
                        "checks_frozen": checks, "execution_boundaries": scope},
                       indent=2, default=str), encoding="utf-8")
        raise


def parse() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=VERSION)
    p.add_argument("--project-root", required=True)
    p.add_argument("--p2b-f1-dir", required=True)
    p.add_argument("--p2b-f2-dir", required=True)
    p.add_argument("--p2b-p-dir", required=True)
    p.add_argument("--v1-2-dir", required=True)
    p.add_argument("--control-fixture", required=True)
    p.add_argument("--treatment-fixture", required=True)
    p.add_argument("--output-dir", required=True)
    return p.parse_args()


if __name__ == "__main__":
    try:
        main(parse())
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
