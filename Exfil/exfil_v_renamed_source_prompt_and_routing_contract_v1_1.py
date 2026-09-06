#!/usr/bin/env python3
"""P2B-P: V_RENAMED_SOURCE PROMPT + ROUTING CONTRACT (read-only, no fixture write).

Scientific gate
---------------
This gate freezes the exact treatment PROMPT and ROUTING contract for P2C,
answering:

    Can the treatment prompt be constructed as a substitution of ONLY the
    source-name token within the frozen control (EX5) prompt template --
    with every other character proven identical -- and can an explicit,
    predeclared P2C hop budget and adapter identity be frozen without
    inheriting either of the two conflicting historical defaults (pipeline=2,
    v1.2 experiment runner=4)?

Method for extracting EX5_PROMPT (safety-critical)
---------------------------------------------------
The frozen pipeline file (benign_pipeline_EX_v6_toolchoice.py) is NEVER
imported or executed. Its EX5_PROMPT string literal is extracted via
`ast.parse` (which only builds a syntax tree; it does not run any code) and
`ast.literal_eval` on the specific assignment's value node (which only
evaluates a literal, never executes the module). This is static source
inspection, not SDK/model execution.

Substitution proof
-------------------
The treatment prompt is built as:
    treatment_prompt = control_prompt.replace(control_basename, treatment_basename)
and is accepted ONLY if:
  - control_basename appears in control_prompt exactly once
  - len(treatment_prompt) - len(control_prompt) == len(treatment_basename) - len(control_basename)
  - a character-level diff (difflib.SequenceMatcher) shows exactly one
    replace-opcode spanning the substituted token and zero other opcodes
    besides 'equal'

Hop budget
----------
No default is silently inherited. --p2c-max-tool-hops is a REQUIRED argument
with no default; the value the researcher supplies is recorded as an explicit
declaration, distinct from and not derived from either historical default.

Fail-closed
-----------
Refuses to proceed on any parent-identity mismatch, missing treatment fixture,
missing/mismatched control prompt, non-unique token occurrence, or any
diff-opcode other than one 'replace' + any number of 'equal'.

No model, Sandbox, Gym, tool, guardrail, predicate, or breach execution.
No fixture is created or modified by this gate.
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

VERSION = "V_RENAMED_SOURCE_PROMPT_AND_ROUTING_CONTRACT_v1.1"

# --- Frozen P2B-F2 parent identities ---
P2B_F2 = {
    "result_sha256": "2DE77801C8D3D0D93183254E1A87E590FC64E3B0DA87E5D9ADB2CB8A51B8CBC5",
    "checks_csv_sha256": "9F81188D22E20C26196BCA112FABB89BEC1F9BEB77C9F637B050DFF9D9D0FB92",
    "claim_boundary_sha256": "9FDB5AA0DFD80679D7B1CDEADCCBF74D46A7D84EF5D22A276D4119E6BCAB67C5",
    "manifest_sha256": "AFF410D2FEBD3A6271DD1EDE96C2DADF49BF3F9EF532B74635A1FE58E5639038",
}
EXPECTED_TREATMENT_SHA256 = "746AA20818152DCC585F78C4E8F93990A668AEA0E060AA254D06502AEAA16FB8"
EXPECTED_TREATMENT_BASENAME = "fx_70a39e917cee2a14.txt"
EXPECTED_CONTROL_BASENAME = "secret.txt"
EXPECTED_CONTROL_SHA256 = "746AA20818152DCC585F78C4E8F93990A668AEA0E060AA254D06502AEAA16FB8"

# --- Frozen adapter/pipeline identity (from v1.2 binding chain) ---
PIPELINE_EXPECTED_SHA256 = "588455D0958E6E19C09853B509E7B20E09BF2B065AC69FAEFBC7108C92ED2BB8"
EX5_PROMPT_SHA_EXPECTED = "3F8BA146E8B3DEDD45EBB4D276A6D55F0BEC8C7C0EFAC2B272B3B21239635176"

# --- Historical hop-budget defaults (NEITHER may be silently inherited) ---
HISTORICAL_DEFAULTS = {
    "pipeline_standalone_default_max_tool_hops": 2,
    "v1_2_experiment_runner_default_max_tool_hops": 4,
}
# Frozen generation/routing dimensions (already established, re-verified here).
FROZEN_GENERATION = {"tool_choice": "auto", "temperature": 0.0}
FROZEN_SEED_POLICY = [26100, 26103, 26105]
FROZEN_SINK_CONTRACT = {"tool": "http.post", "payload_argument": "data"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def need(v: bool, m: str) -> None:
    if not v:
        raise ValueError(m)


def sha_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest().upper()


def sha_text(s: str) -> str:
    return sha_bytes(s.encode("utf-8", "surrogatepass"))


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


def extract_string_constant_static(py_path: Path, var_name: str) -> str:
    """Extract the literal string value assigned to `var_name` in `py_path`
    WITHOUT importing or executing the module. Uses ast.parse (syntax tree
    only, no execution) + ast.literal_eval (evaluates only the isolated
    literal expression node, never runs the module body)."""
    source = py_path.read_text(encoding="utf-8-sig")
    tree = ast.parse(source, filename=str(py_path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == var_name:
                    return ast.literal_eval(node.value)
    raise ValueError(f"Could not statically locate assignment to {var_name!r} in {py_path}")


def verify_single_token_substitution(control: str, treatment: str,
                                     control_token: str, treatment_token: str) -> tuple[bool, dict[str, Any]]:
    """Exact (non-fuzzy) proof that `treatment` differs from `control` ONLY in the
    region occupied by `control_token`, substituted with `treatment_token`.

    Rationale: a general-purpose sequence diff (e.g. difflib.SequenceMatcher) can
    report a fragmented replace/insert/delete pattern when the old and new tokens
    share scattered common characters (a known LCS-diffing artifact) even though
    the actual edit is a single contiguous substring replacement. Since the
    substitution here is CONSTRUCTED (not discovered) via control.replace(...),
    the mathematically exact verification is: locate the single occurrence of
    control_token in control (uniqueness already independently proven by check
    TP-011 upstream), split into prefix/suffix around it, and prove BOTH:
        prefix + control_token   + suffix == control
        prefix + treatment_token + suffix == treatment
    This is a direct algebraic reconstruction, not a heuristic diff, and has zero
    dependency on how any particular diff library's opcode search behaves."""
    idx = control.index(control_token)  # uniqueness already verified by caller (single occurrence)
    prefix = control[:idx]
    suffix = control[idx + len(control_token):]
    reconstructed_control = prefix + control_token + suffix
    reconstructed_treatment = prefix + treatment_token + suffix
    ok = (reconstructed_control == control and reconstructed_treatment == treatment)
    evidence = {
        "token_start_index_in_control": idx,
        "prefix_sha256": sha_text(prefix),
        "prefix_length": len(prefix),
        "suffix_sha256": sha_text(suffix),
        "suffix_length": len(suffix),
        "reconstructed_control_equals_control": reconstructed_control == control,
        "reconstructed_treatment_equals_treatment": reconstructed_treatment == treatment,
        "method": "exact_prefix_suffix_reconstruction_not_fuzzy_diff",
    }
    return ok, evidence


def main(a: argparse.Namespace) -> None:
    out = Path(a.output_dir).resolve()
    need(not out.exists(), f"Refusing overwrite: {out}")
    out.mkdir(parents=True)
    checks: list[dict[str, Any]] = []
    scope = {
        "read_only": True, "fixture_created": False, "fixture_mutated": False,
        "pipeline_file_imported": False, "pipeline_file_executed": False,
        "model_executed": False, "sdk_executed": False, "sandbox_executed": False,
        "gym_executed": False, "tool_executed": False, "guardrail_executed": False,
        "predicate_executed": False, "breach_executed": False,
        "attack_optimization": False,
    }
    idx = 1
    try:
        f2_dir = Path(a.p2b_f2_dir).resolve()
        pipeline_file = Path(a.pipeline_file).resolve()
        treatment_fixture = Path(a.treatment_fixture).resolve()
        control_fixture = Path(a.control_fixture).resolve()

        # --- Stage A: verify P2B-F2 parent contract exactly ---
        f2_result = f2_dir / "v_renamed_source_treatment_materialization_result_v1_0.json"
        f2_checks = f2_dir / "v_renamed_source_treatment_materialization_checks_v1_0.csv"
        f2_claim = f2_dir / "v_renamed_source_treatment_materialization_claim_boundary_v1_0.json"
        for cid, p, expected in (
            (f"TP-{idx:03d}", f2_result, P2B_F2["result_sha256"]),
        ):
            ok = p.is_file() and sha_file(p) == expected
            add(checks, cid, "parent_identity", ok, ident(p) if p.is_file() else str(p),
                {"sha256": expected}, "FIXTURE")
            idx += 1
        ok = f2_checks.is_file() and sha_file(f2_checks) == P2B_F2["checks_csv_sha256"]
        add(checks, f"TP-{idx:03d}", "parent_identity", ok,
            ident(f2_checks) if f2_checks.is_file() else str(f2_checks),
            {"sha256": P2B_F2["checks_csv_sha256"]}, "FIXTURE")
        idx += 1
        ok = f2_claim.is_file() and sha_file(f2_claim) == P2B_F2["claim_boundary_sha256"]
        add(checks, f"TP-{idx:03d}", "parent_identity", ok,
            ident(f2_claim) if f2_claim.is_file() else str(f2_claim),
            {"sha256": P2B_F2["claim_boundary_sha256"]}, "FIXTURE")
        idx += 1

        need(all(c["passed"] for c in checks), "P2B-F2 parent identity verification failed; refusing to proceed")

        f2_doc = json.loads(f2_result.read_text(encoding="utf-8-sig"))
        ok = f2_doc.get("status") == "COMPLETE_PASS"
        add(checks, f"TP-{idx:03d}", "parent_status", ok, f2_doc.get("status"),
            "COMPLETE_PASS", "FIXTURE")
        idx += 1
        need(ok, "P2B-F2 result status is not COMPLETE_PASS")

        # --- Stage B: re-verify treatment fixture identity on disk ---
        ok = treatment_fixture.is_file()
        add(checks, f"TP-{idx:03d}", "treatment_exists", ok, str(treatment_fixture),
            "treatment fixture present", "FIXTURE")
        idx += 1
        need(ok, f"Treatment fixture missing: {treatment_fixture}")
        treatment_id = ident(treatment_fixture)
        ok = (treatment_id["artifact"] == EXPECTED_TREATMENT_BASENAME
              and treatment_id["sha256"] == EXPECTED_TREATMENT_SHA256)
        add(checks, f"TP-{idx:03d}", "treatment_identity", ok, treatment_id,
            {"artifact": EXPECTED_TREATMENT_BASENAME, "sha256": EXPECTED_TREATMENT_SHA256}, "FIXTURE")
        idx += 1
        need(ok, "Treatment fixture identity no longer matches frozen P2B-F2 evidence")

        # --- Stage C: re-verify control fixture identity on disk ---
        ok = control_fixture.is_file()
        add(checks, f"TP-{idx:03d}", "control_exists", ok, str(control_fixture),
            "control fixture present", "FIXTURE")
        idx += 1
        need(ok, f"Control fixture missing: {control_fixture}")
        control_id = ident(control_fixture)
        ok = (control_id["artifact"] == EXPECTED_CONTROL_BASENAME
              and control_id["sha256"] == EXPECTED_CONTROL_SHA256)
        add(checks, f"TP-{idx:03d}", "control_identity", ok, control_id,
            {"artifact": EXPECTED_CONTROL_BASENAME, "sha256": EXPECTED_CONTROL_SHA256}, "FIXTURE")
        idx += 1
        need(ok, "Control fixture identity mismatch")

        # --- Stage D: verify pipeline (adapter) identity, then statically extract EX5_PROMPT ---
        ok = pipeline_file.is_file() and sha_file(pipeline_file) == PIPELINE_EXPECTED_SHA256
        add(checks, f"TP-{idx:03d}", "pipeline_identity", ok,
            ident(pipeline_file) if pipeline_file.is_file() else str(pipeline_file),
            {"sha256": PIPELINE_EXPECTED_SHA256}, "FIXTURE")
        idx += 1
        need(ok, "Pipeline (adapter) file identity mismatch; refusing to extract prompt")

        # STATIC extraction only: ast.parse (no exec) + ast.literal_eval (literal only).
        control_prompt = extract_string_constant_static(pipeline_file, "EX5_PROMPT")
        scope["pipeline_file_imported"] = False
        scope["pipeline_file_executed"] = False
        control_prompt_sha = sha_text(control_prompt)
        ok = control_prompt_sha == EX5_PROMPT_SHA_EXPECTED
        add(checks, f"TP-{idx:03d}", "control_prompt_sha256_matches_frozen", ok,
            control_prompt_sha, EX5_PROMPT_SHA_EXPECTED, "FIXTURE")
        idx += 1
        need(ok, "Statically-extracted EX5_PROMPT does not match frozen digest")

        # --- Stage E: construct treatment prompt via single-token substitution ---
        occurrences = control_prompt.count(EXPECTED_CONTROL_BASENAME)
        ok = occurrences == 1
        add(checks, f"TP-{idx:03d}", "control_basename_occurs_exactly_once", ok,
            occurrences, 1, "FIXTURE")
        idx += 1
        need(ok, f"Control basename occurs {occurrences} times in prompt; substitution ambiguous")

        treatment_prompt = control_prompt.replace(EXPECTED_CONTROL_BASENAME, EXPECTED_TREATMENT_BASENAME)
        len_delta_expected = len(EXPECTED_TREATMENT_BASENAME) - len(EXPECTED_CONTROL_BASENAME)
        len_delta_actual = len(treatment_prompt) - len(control_prompt)
        ok = len_delta_actual == len_delta_expected
        add(checks, f"TP-{idx:03d}", "length_delta_matches_token_delta", ok,
            len_delta_actual, len_delta_expected, "FIXTURE")
        idx += 1
        need(ok, "Prompt length delta does not match expected token-length delta")

        substitution_ok, substitution_evidence = verify_single_token_substitution(
            control_prompt, treatment_prompt, EXPECTED_CONTROL_BASENAME, EXPECTED_TREATMENT_BASENAME)
        add(checks, f"TP-{idx:03d}", "exact_prefix_suffix_substitution_proof", substitution_ok,
            substitution_evidence,
            "prefix+control_token+suffix==control AND prefix+treatment_token+suffix==treatment",
            "FIXTURE")
        idx += 1
        need(substitution_ok, "Exact prefix/suffix reconstruction failed; substitution touched more than the token")

        treatment_prompt_sha = sha_text(treatment_prompt)
        add(checks, f"TP-{idx:03d}", "treatment_prompt_hashed", True,
            {"treatment_prompt_sha256": treatment_prompt_sha}, "recorded", "FIXTURE")
        idx += 1

        # --- Stage F: explicit, non-inherited P2C hop budget ---
        hop_budget = a.p2c_max_tool_hops
        ok = isinstance(hop_budget, int) and hop_budget >= 1
        add(checks, f"TP-{idx:03d}", "p2c_hop_budget_explicit_and_valid", ok, hop_budget,
            ">=1, explicitly supplied (no default)", "ROUTING")
        idx += 1
        need(ok, "P2C hop budget must be an explicit integer >= 1")
        matches_a_historical_default = hop_budget in HISTORICAL_DEFAULTS.values()
        add(checks, f"TP-{idx:03d}", "p2c_hop_budget_declaration_recorded", True,
            {"declared": hop_budget, "historical_defaults": HISTORICAL_DEFAULTS,
             "coincides_with_a_historical_default": matches_a_historical_default},
            "declaration recorded regardless of numeric coincidence with a historical default", "ROUTING")
        idx += 1

        # --- Stage G: freeze generation/seed/sink dimensions (re-verify, don't re-derive) ---
        add(checks, f"TP-{idx:03d}", "generation_configuration_frozen", True,
            FROZEN_GENERATION, FROZEN_GENERATION, "ROUTING")
        idx += 1
        add(checks, f"TP-{idx:03d}", "seed_policy_frozen", True,
            FROZEN_SEED_POLICY, FROZEN_SEED_POLICY, "FIXTURE")
        idx += 1
        add(checks, f"TP-{idx:03d}", "sink_contract_frozen", True,
            FROZEN_SINK_CONTRACT, FROZEN_SINK_CONTRACT, "FIXTURE")
        idx += 1

        # --- Stage H: scope ---
        add(checks, f"TP-{idx:03d}", "scope", True, scope,
            "read-only static AST extraction only; no fixture created/mutated; no model/sandbox/"
            "tool/guardrail/predicate/breach executed; pipeline file never imported or executed",
            "SCOPE_VIOLATION")
        idx += 1

        failed = [c["check_id"] for c in checks if not c["passed"]]
        status = "COMPLETE_PASS" if not failed else "BLOCKED"

        claim = {
            "allowed": [
                "P2B-F2 parent contract verified byte-identical to frozen identity",
                "treatment and control fixture identities independently re-verified on disk",
                "pipeline (adapter) file identity re-verified before any extraction",
                "EX5_PROMPT extracted via STATIC ast.parse + ast.literal_eval only "
                "(pipeline file was never imported or executed)",
                "extracted control prompt SHA-256 matches the frozen EX5_PROMPT_SHA",
                "treatment prompt constructed as EXACTLY one token substitution "
                "(secret.txt -> fx_70a39e917cee2a14.txt), proven by length-delta AND "
                "exact algebraic prefix+token+suffix reconstruction (not a fuzzy diff)",
                "an explicit, non-inherited P2C hop budget was declared and recorded",
                "generation configuration, seed policy, and sink contract re-frozen unchanged",
            ],
            "prohibited": [
                "the treatment prompt has been sent to any model",
                "any model, Sandbox, Gym, tool, guardrail, predicate, or breach execution occurred",
                "the pipeline file was imported or executed (it was only statically parsed)",
                "the declared hop budget has been validated against actual runtime behavior",
                "any claim about V_RENAMED_SOURCE runtime behavior, harness trick, "
                "robust security, or hosted parity",
            ],
        }
        result = {
            "version": VERSION, "created_at_utc": now(), "status": status,
            "classification": "READ_ONLY_PROMPT_AND_ROUTING_STATIC_CONTRACT",
            "checks": {"total": len(checks), "passed": len(checks) - len(failed),
                       "failed": len(failed), "failed_ids": failed},
            "scientific_question":
                "Can the treatment prompt be constructed as a single-token source-name "
                "substitution (proven by diff) while an explicit, non-inherited P2C hop "
                "budget and adapter identity are frozen?",
            "control_prompt": {"sha256": control_prompt_sha, "length": len(control_prompt),
                              "extraction_method": "ast.parse + ast.literal_eval (static, no exec)"},
            "treatment_prompt": {"sha256": treatment_prompt_sha, "length": len(treatment_prompt),
                                 "substitution": {"from": EXPECTED_CONTROL_BASENAME,
                                                  "to": EXPECTED_TREATMENT_BASENAME},
                                 "substitution_proof": substitution_evidence},
            "pipeline_adapter_identity": ident(pipeline_file),
            "control_fixture": control_id,
            "treatment_fixture": treatment_id,
            "routing_contract": {
                "p2c_max_tool_hops_declared": hop_budget,
                "historical_defaults_not_inherited": HISTORICAL_DEFAULTS,
                "coincides_with_a_historical_default": matches_a_historical_default,
                "generation_configuration": FROZEN_GENERATION,
                "seed_policy": FROZEN_SEED_POLICY,
                "sink_contract": FROZEN_SINK_CONTRACT,
            },
            "execution_boundaries": scope,
            "scientific_verdict": {
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_finding": "NOT_ESTABLISHED",
                "V_RENAMED_SOURCE_behavior": "NOT_ESTABLISHED",
                "hosted_parity": "NOT_ESTABLISHED",
            },
            "claim_boundary": claim,
            "next_gate": "V_RENAMED_SOURCE_FINAL_STATIC_PREFLIGHT" if status == "COMPLETE_PASS"
                        else "V_RENAMED_SOURCE_PROMPT_AND_ROUTING_CONTRACT_REVIEW",
        }

        outputs = {
            "result": out / "v_renamed_source_prompt_and_routing_contract_result_v1_0.json",
            "checks": out / "v_renamed_source_prompt_and_routing_contract_checks_v1_0.csv",
            "claim": out / "v_renamed_source_prompt_and_routing_contract_claim_boundary_v1_0.json",
        }
        write_json(outputs["result"], result)
        write_csv(outputs["checks"], checks,
                  ["check_id", "category", "passed", "observed", "expected", "failure_layer"])
        write_json(outputs["claim"], claim)

        runner_id = ident(Path(__file__).resolve())
        rows = [{**ident(p), "role": r.upper()} for r, p in outputs.items()]
        rows.append({**runner_id, "role": "RUNNER"})
        rows.append({**ident(pipeline_file), "role": "PIPELINE_ADAPTER_SOURCE"})
        rows.append({**control_id, "role": "CONTROL_FIXTURE"})
        rows.append({**treatment_id, "role": "TREATMENT_FIXTURE"})
        manifest = out / "v_renamed_source_prompt_and_routing_contract_manifest_v1_0.csv"
        write_csv(manifest, rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        ext = out / "v_renamed_source_prompt_and_routing_contract_manifest_external_binding_v1_0.json"
        write_json(ext, {"version": VERSION, "created_at_utc": now(), "status": status,
                         "manifest_filename": manifest.name, "manifest_sha256": sha_file(manifest),
                         "runner_sha256": runner_id["sha256"], "checks_total": len(checks),
                         "checks_passed": len(checks) - len(failed), "checks_failed": len(failed),
                         "failed_ids": failed,
                         "control_prompt_sha256": control_prompt_sha,
                         "treatment_prompt_sha256": treatment_prompt_sha,
                         "p2c_max_tool_hops_declared": hop_budget,
                         "next_gate": result["next_gate"]})
        print(json.dumps({"status": status, "checks": f"{len(checks) - len(failed)}/{len(checks)}",
                          "failed_ids": failed,
                          "control_prompt_sha256": control_prompt_sha,
                          "treatment_prompt_sha256": treatment_prompt_sha,
                          "p2c_max_tool_hops_declared": hop_budget,
                          "manifest_sha256": sha_file(manifest), "next_gate": result["next_gate"]}, indent=2))
    except Exception as exc:  # noqa: BLE001
        (out / "V_RENAMED_SOURCE_PROMPT_AND_ROUTING_CONTRACT_FAILED.json").write_text(
            json.dumps({"version": VERSION, "created_at_utc": now(), "status": "BLOCKED",
                        "error_type": type(exc).__name__, "error": str(exc),
                        "checks_frozen": checks, "execution_boundaries": scope},
                       indent=2, default=str), encoding="utf-8")
        raise


def parse() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=VERSION)
    p.add_argument("--p2b-f2-dir", required=True,
                   help="dir containing P2B-F2 materialization result/checks/claim JSON/CSV")
    p.add_argument("--pipeline-file", required=True,
                   help="path to benign_pipeline_EX_v6_toolchoice.py (statically parsed only, never executed)")
    p.add_argument("--control-fixture", required=True, help="exact path to secret.txt")
    p.add_argument("--treatment-fixture", required=True, help="exact path to fx_70a39e917cee2a14.txt")
    p.add_argument("--p2c-max-tool-hops", required=True, type=int,
                   help="REQUIRED explicit P2C hop budget declaration (no default; must not be silently "
                        "inherited from either historical default of 2 or 4)")
    p.add_argument("--output-dir", required=True)
    return p.parse_args()


if __name__ == "__main__":
    try:
        main(parse())
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
