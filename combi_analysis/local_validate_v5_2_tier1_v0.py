#!/usr/bin/env python3
r"""
local_validate_v5_2_tier1.py
==========================================================================
LOCAL VALIDATOR for the 7 Tier-1 candidates in
attack_yaml_harness_v5_2_tier1_additions.py (DW22, EX25, CD13, CD14,
CD15, DW23, CD09_v2).

THIS SCRIPT DOES NOT TOUCH v5.1. It does not import FAMILIES_CONFIG or
build_all_candidates_and_manifest from attack_yaml_harness_v5_1_inline --
only the execution engine (run_candidate, import_real_sdk, fixture-safety
helpers, retry/backoff, classify_verdict, etc.) is reused, UNCHANGED, from
local_validate_v5_1.py. v5.1 itself is never imported as a candidate
source and never re-hashed or re-validated by this script.

WHY A SEPARATE SCRIPT (not --family tier1 bolted onto local_validate_v5_1)
---------------------------------------------------------------------------
v5.1 is currently running/submitted on Kaggle. Editing local_validate_v5_1
.py at all -- even to add a new --family choice -- creates a real risk of
touching code that is defended by the _EXPECTED_TOTAL_CANDIDATES == 58
guard and the verify_v4_subset_unchanged() import-time assertion. This
script imports local_validate_v5_1 read-only (for its functions) and never
modifies it on disk.

EVIDENCE DISCIPLINE (identical to every prior script in this project):
  - Real fixtures_dir is NEVER modified; every candidate runs inside a
    fresh throwaway tempfile.mkdtemp() copy.
  - Real fixture hashes are snapshotted before the first candidate and
    re-verified byte-identical after the last one (fail-closed).
  - Harmony-parse-failure classifier + temperature-escalation retry,
    generic transport-failure retry-with-backoff: reused UNCHANGED.
  - --i-authorize-* gate: will not run without an explicit flag.
  - These 7 candidates all run against the REAL packaged default-deny
    aicomp_sdk.guardrails.optimal.OptimalGuardrail -- none of them require
    a base_allow override (unlike E6/D2 in positive_controls_v5_1.py).

USAGE:
  # Dry-run (prints the plan, runs nothing):
  python local_validate_v5_2_tier1.py --project-root "C:\...\ai-agent-security-multi-step-tool-attacks"

  # Real run, all 7 Tier-1 candidates, 3 repeats each (recommended):
  python local_validate_v5_2_tier1.py --i-authorize-local-validation ^
      --project-root "C:\...\ai-agent-security-multi-step-tool-attacks" ^
      --model-url http://127.0.0.1:8080/v1/chat/completions ^
      --n-repeats 3

  # Just one candidate while iterating (e.g. the CD09 redesign):
  python local_validate_v5_2_tier1.py --i-authorize-local-validation ^
      --project-root "C:\...\ai-agent-security-multi-step-tool-attacks" ^
      --model-url http://127.0.0.1:8080/v1/chat/completions ^
      --instruction-id CD09_v2_multistep_revocation_before_execution --n-repeats 5
==========================================================================
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

# Execution engine reused UNCHANGED from local_validate_v5_1.py -- zero
# logic drift, same real-model/real-guardrail/real-predicate code path
# that validated the frozen 58. NOTE: importing this module runs its
# top-level verify_v4_subset_unchanged() check against v5.1's own
# FAMILIES_CONFIG (harmless, read-only integrity check; does not touch
# this script's own candidate set).
from local_validate_v5_1 import (  # noqa: E402
    assert_real_hashes_unchanged,
    classify_verdict,
    import_real_sdk,
    inject_synthetic_fixtures,
    load_json_container,
    prepare_temp_fixtures_dir,
    run_candidate,
    snapshot_real_hashes,
    write_json,
)

# Candidate source: the new, additive-only Tier-1 config -- NOT v5.1's
# FAMILIES_CONFIG.
from attack_yaml_harness_v5_2_tier1_additions import (  # noqa: E402
    build_tier1_candidates_and_manifest,
    verify_no_id_collision_with_v5_1,
)

verify_no_id_collision_with_v5_1()

_EXPECTED_TIER1_CANDIDATE_COUNT = 7


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--i-authorize-local-validation", action="store_true")
    ap.add_argument("--project-root", required=True)
    ap.add_argument("--fixtures-dir", default=None)
    ap.add_argument("--model-url", default="http://127.0.0.1:8080/v1/chat/completions")
    ap.add_argument("--instruction-id", default=None,
                     help="Optional: run only this one instruction_id (e.g. "
                          "CD09_v2_multistep_revocation_before_execution). Default: all 7.")
    ap.add_argument("--n-repeats", type=int, default=1)
    ap.add_argument("--max-tokens", type=int, default=1536)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--max-retries", type=int, default=2)
    ap.add_argument("--backoff-base-s", type=float, default=1.5)
    ap.add_argument("--out", default="local_validate_v5_2_tier1_summary.json")
    args = ap.parse_args()

    candidates, manifest = build_tier1_candidates_and_manifest()
    assert len(candidates) == _EXPECTED_TIER1_CANDIDATE_COUNT, (
        f"Tier-1 candidate-count guard: expected {_EXPECTED_TIER1_CANDIDATE_COUNT}, "
        f"got {len(candidates)} -- investigate attack_yaml_harness_v5_2_tier1_additions.py."
    )
    if args.instruction_id:
        keep_idx = [i for i, m in enumerate(manifest) if m["instruction_id"] == args.instruction_id]
        if not keep_idx:
            valid_ids = sorted({m["instruction_id"] for m in manifest})
            print(f"FATAL: --instruction-id {args.instruction_id!r} not found. Valid ids: {valid_ids}")
            sys.exit(2)
        candidates = [candidates[i] for i in keep_idx]
        manifest = [manifest[i] for i in keep_idx]

    if not args.i_authorize_local_validation:
        print(f"Plan: locally validate {len(candidates)} Tier-1 candidate(s) from "
              f"attack_yaml_harness_v5_2_tier1_additions.py against a REAL GPT-OSS model "
              f"at {args.model_url}.")
        print(f"  Instruction-id filter: {args.instruction_id or 'all 7'}")
        print(f"  Repeats per candidate: {args.n_repeats}")
        for m in manifest:
            print(f"    {m['family']}/{m['instruction_id']}  expected={m['expected']}  "
                  f"n_hops={m['n_hops']}")
        print(f"\nThis is a LOCAL VALIDATION run only. No network call to any Kaggle endpoint is "
              f"made by this script, and attack_yaml_harness_v5_1_inline.py / "
              f"local_validate_v5_1.py are never modified. Pass "
              f"--i-authorize-local-validation to execute for real.")
        sys.exit(3)

    project_root = Path(args.project_root).resolve()
    real_fixtures_dir = Path(args.fixtures_dir).resolve() if args.fixtures_dir else project_root / "aicomp_sdk" / "fixtures"

    print("=" * 70)
    print("STEP 1: Import real predicates.py + real OptimalGuardrail")
    print("=" * 70)
    sdk = import_real_sdk(project_root)
    for a in sdk["import_attempts"]:
        print(f"  [{'OK' if a['ok'] else 'FAILED'}] {a['target']}" + (f" -- {a.get('error')}" if not a["ok"] else ""))
    if not (sdk["predicates_module"] and sdk["guardrail"]):
        print("\nFATAL: could not import required real SDK components. Check --project-root.")
        sys.exit(1)
    if not real_fixtures_dir.is_dir():
        print(f"FATAL: real fixtures_dir not found at {real_fixtures_dir}")
        sys.exit(1)

    hash_targets = ["mail_seed.json", "web_corpus.json", "file_seed/readme.txt",
                     "file_seed/note.txt", "file_seed/report.txt"]
    hash_targets = [t for t in hash_targets if (real_fixtures_dir / t).is_file()]
    real_hashes_before = snapshot_real_hashes(real_fixtures_dir, hash_targets)
    print(f"  [safety] real fixture hashes captured BEFORE anything runs (targets: {hash_targets})")

    all_results: list[dict[str, Any]] = []
    seed_counter = 90000  # distinct seed range from local_validate_v5_1's 60000, avoids any accidental overlap

    try:
        print("\n" + "=" * 70)
        print(f"RUNNING {len(candidates)} Tier-1 candidate(s) x {args.n_repeats} repeat(s)")
        print("=" * 70)
        for candidate, m in zip(candidates, manifest):
            case_label = f"{m['family']}/{m['instruction_id']}#{m['candidate_idx']}"
            for repeat_no in range(1, args.n_repeats + 1):
                seed_counter += 1
                tag = f"{m['instruction_id']}_{m['candidate_idx']}_r{repeat_no}"
                fixture_root = prepare_temp_fixtures_dir(real_fixtures_dir, tag)
                inject_synthetic_fixtures(fixture_root)
                mail_container = load_json_container(fixture_root, "mail_seed.json")
                web_container = load_json_container(fixture_root, "web_corpus.json")
                print(f"  [{repeat_no}/{args.n_repeats}] {case_label} ...", end=" ", flush=True)
                result = run_candidate(case_label, candidate.user_messages, m.get("expected"),
                                        m.get("hypothesis"), sdk["predicates_module"], sdk["guardrail"],
                                        args.model_url, args.max_tokens, args.timeout, fixture_root,
                                        mail_container, web_container, args.max_retries,
                                        args.backoff_base_s, seed_counter)
                result["family"] = m["family"]
                result["instruction_id"] = m["instruction_id"]
                result["candidate_idx"] = m["candidate_idx"]
                result["repeat_no"] = repeat_no
                result["verdict"] = classify_verdict(result["outcome_summary"], m.get("expected"))
                os_ = result["outcome_summary"]
                print(f"attempted={os_.get('any_action_attempted')} denied={os_.get('any_action_denied')} "
                      f"succeeded={os_.get('any_action_succeeded')} verdict={result['verdict']}")
                all_results.append(result)
    finally:
        print("\n" + "=" * 70)
        print("FINAL SAFETY VERIFICATION -- real fixtures_dir unchanged?")
        print("=" * 70)
        safety_report = assert_real_hashes_unchanged(real_fixtures_dir, hash_targets, real_hashes_before)
        print("  PASS: every real fixture touched during this run is byte-identical before and after.")

    n_match = sum(1 for r in all_results if r["verdict"] == "MATCH")
    n_mismatch = sum(1 for r in all_results if r["verdict"] == "MISMATCH")
    n_unclear = sum(1 for r in all_results if r["verdict"].startswith("UNCLEAR"))
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Total runs: {len(all_results)}")
    print(f"  MATCH (real outcome matches documented expectation): {n_match}")
    print(f"  MISMATCH (real outcome diverges -- investigate before trusting this candidate): {n_mismatch}")
    print(f"  UNCLEAR (ambiguous auto-classification -- review manually): {n_unclear}")
    if n_mismatch > 0:
        print("\n  MISMATCHED CASES (do not treat these as reconfirmed without manual review):")
        for r in all_results:
            if r["verdict"] == "MISMATCH":
                print(f"    - {r['family']}/{r['instruction_id']}#{r['candidate_idx']} repeat{r['repeat_no']}: "
                      f"expected={r['expected']} outcome={r['outcome_summary']}")

    out_path = Path(args.out)
    write_json(out_path, {
        "instruction_id_filter": args.instruction_id or "all", "n_repeats": args.n_repeats,
        "summary": {"n_match": n_match, "n_mismatch": n_mismatch, "n_unclear": n_unclear, "n_total": len(all_results)},
        "results": all_results, "safety_verification": safety_report,
        "note": ("This is a LOCAL VALIDATION summary for the 7 Tier-1 candidates only "
                 "(DW22/EX25/CD13/CD14/CD15/DW23/CD09_v2). It does NOT touch, re-validate, "
                 "or affect the frozen v5.1 58-candidate submission in any way. No network "
                 "call to any Kaggle endpoint was made."),
    })
    print(f"\nFull Tier-1 local validation summary written to: {out_path.resolve()}")


if __name__ == "__main__":
    main()
