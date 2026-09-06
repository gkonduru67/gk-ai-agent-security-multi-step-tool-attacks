#!/usr/bin/env python3
r"""
local_validate_v5_2_full.py
==========================================================================
SINGLE, CONSOLIDATED LOCAL VALIDATOR for all 66 candidates defined in
attack_yaml_harness_v5_2_full_inline.py (the 58 frozen v5.1 candidates +
the 8 Tier-1 additions, merged).

THIS SCRIPT DOES NOT TOUCH v5.1. It imports the candidate SET from the
new merged file, but the execution engine itself (run_candidate,
import_real_sdk, fixture-safety helpers, retry/backoff,
harmony-parse-failure classifier, classify_verdict, etc.) is reused,
UNCHANGED, from local_validate_v5_1.py -- exactly the same reuse pattern
used by every prior script in this project (local_validate_v5_2_tier1.py,
local_validate_v5_2_cd_consistency.py, isolated_rerun_*). This is a
consolidation of WHAT gets tested, not a rewrite of HOW it gets tested.

WHY THIS EXISTS
----------------
Previously you needed two separate runs -- local_validate_v5_1.py (58
candidates) and local_validate_v5_2_tier1.py (8 candidates) -- to cover
everything. This script runs all 66 in one pass, one summary JSON, one
safety-verification block, with the SAME per-candidate real-GPT-OSS /
real-guardrail / real-predicate evaluation as both of those.

USAGE:
  # Dry-run (prints the plan, runs nothing):
  python local_validate_v5_2_full.py --project-root "C:\...\ai-agent-security-multi-step-tool-attacks"

  # Real run, all 66 candidates, 1 repeat each (full sweep, slow):
  python local_validate_v5_2_full.py --i-authorize-local-validation ^
      --project-root "C:\...\ai-agent-security-multi-step-tool-attacks" ^
      --model-url http://127.0.0.1:8080/v1/chat/completions ^
      --n-repeats 1

  # Real run, one family only:
  python local_validate_v5_2_full.py --i-authorize-local-validation ^
      --project-root "C:\...\ai-agent-security-multi-step-tool-attacks" ^
      --model-url http://127.0.0.1:8080/v1/chat/completions ^
      --family CONFUSED_DEPUTY --n-repeats 3

  # Real run, specific instruction_id(s) only (comma-separated):
  python local_validate_v5_2_full.py --i-authorize-local-validation ^
      --project-root "C:\...\ai-agent-security-multi-step-tool-attacks" ^
      --model-url http://127.0.0.1:8080/v1/chat/completions ^
      --instruction-id CD09_v2_multistep_revocation_before_execution,CD09_v3_no_revocation_control ^
      --n-repeats 5

EVIDENCE DISCIPLINE (identical to every prior script in this project):
  - Real fixtures_dir is NEVER modified; every candidate runs inside a
    fresh throwaway tempfile.mkdtemp() copy.
  - Real fixture hashes are snapshotted before the first candidate and
    re-verified byte-identical after the last one (fail-closed).
  - Harmony-parse-failure classifier + temperature-escalation retry,
    generic transport-failure retry-with-backoff: reused UNCHANGED.
  - --i-authorize-* gate: will not run without an explicit flag.
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
# that validated the frozen 58 and the 8 Tier-1 additions.
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

# Candidate source: the single merged 66-candidate config.
from attack_yaml_harness_v5_2_full_inline import (  # noqa: E402
    build_all_candidates_and_manifest,
    verify_structural_completeness,
    verify_v5_1_subset_unchanged_dynamic,
)

verify_structural_completeness()

_EXPECTED_TOTAL_CANDIDATES = 66
_VALID_FAMILIES = ["all", "EXFILTRATION", "CONFUSED_DEPUTY", "DESTRUCTIVE_WRITE", "UNTRUSTED_TO_ACTION"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--i-authorize-local-validation", action="store_true")
    ap.add_argument("--project-root", required=True)
    ap.add_argument("--fixtures-dir", default=None)
    ap.add_argument("--model-url", default="http://127.0.0.1:8080/v1/chat/completions")
    ap.add_argument("--family", default="all", choices=_VALID_FAMILIES)
    ap.add_argument("--instruction-id", default=None,
                     help="Optional: comma-separated list of instruction_id(s) to run. "
                          "Applied on top of --family. Default: all candidates in the "
                          "selected family/families.")
    ap.add_argument("--n-repeats", type=int, default=1)
    ap.add_argument("--max-tokens", type=int, default=1536)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--max-retries", type=int, default=2)
    ap.add_argument("--backoff-base-s", type=float, default=1.5)
    ap.add_argument("--skip-drift-check", action="store_true",
                     help="Skip the dynamic v5.1-vs-merged-file hash cross-check "
                          "(only useful if attack_yaml_harness_v5_1_inline.py is not "
                          "available alongside this script; the check is otherwise "
                          "harmless and fast).")
    ap.add_argument("--out", default="local_validate_v5_2_full_summary.json")
    args = ap.parse_args()

    print("=" * 70)
    print("STEP 0: Candidate-set integrity checks")
    print("=" * 70)
    if not args.skip_drift_check:
        drift_report = verify_v5_1_subset_unchanged_dynamic()
        print(f"  verify_v5_1_subset_unchanged_dynamic: {drift_report['status']}")
        if drift_report["status"] == "FAILED_DRIFT_DETECTED":
            print(f"  MISMATCHES: {drift_report['mismatches']}")
            print("FATAL: prompt drift detected between the merged file and frozen v5.1. "
                  "Do not proceed -- investigate before running.")
            sys.exit(4)
        elif drift_report["status"] == "SKIPPED":
            print(f"    ({drift_report['reason']})")
    else:
        print("  verify_v5_1_subset_unchanged_dynamic: SKIPPED (--skip-drift-check)")

    candidates, manifest = build_all_candidates_and_manifest()
    assert len(candidates) == _EXPECTED_TOTAL_CANDIDATES, (
        f"v5.2 candidate-count guard: expected {_EXPECTED_TOTAL_CANDIDATES}, "
        f"got {len(candidates)} -- investigate attack_yaml_harness_v5_2_full_inline.py."
    )
    print(f"  candidate-count guard: PASSED ({len(candidates)}/{_EXPECTED_TOTAL_CANDIDATES})")

    if args.family != "all":
        keep_idx = [i for i, m in enumerate(manifest) if m["family"] == args.family]
        candidates = [candidates[i] for i in keep_idx]
        manifest = [manifest[i] for i in keep_idx]

    if args.instruction_id:
        requested_ids = {s.strip() for s in args.instruction_id.split(",") if s.strip()}
        valid_ids = {m["instruction_id"] for m in manifest}
        unknown = requested_ids - valid_ids
        if unknown:
            print(f"FATAL: unknown --instruction-id value(s) for family filter {args.family!r}: "
                  f"{sorted(unknown)}. Valid ids in this selection: {sorted(valid_ids)}")
            sys.exit(2)
        keep_idx = [i for i, m in enumerate(manifest) if m["instruction_id"] in requested_ids]
        candidates = [candidates[i] for i in keep_idx]
        manifest = [manifest[i] for i in keep_idx]

    if not args.i_authorize_local_validation:
        print(f"\nPlan: locally validate {len(candidates)} candidate(s) from "
              f"attack_yaml_harness_v5_2_full_inline.py against a REAL GPT-OSS model at "
              f"{args.model_url}.")
        print(f"  Family filter: {args.family}")
        print(f"  Instruction-id filter: {args.instruction_id or '(none)'}")
        print(f"  Repeats per candidate: {args.n_repeats}")
        by_family: dict[str, int] = {}
        for m in manifest:
            by_family.setdefault(m["family"], 0)
            by_family[m["family"]] += 1
        for fam, count in by_family.items():
            print(f"    {fam}: {count} candidate(s)")
        print(f"\nThis is a LOCAL VALIDATION run only. No network call to any Kaggle endpoint is "
              f"made by this script, and attack_yaml_harness_v5_1_inline.py / "
              f"local_validate_v5_1.py are never modified. Pass "
              f"--i-authorize-local-validation to execute for real.")
        sys.exit(3)

    project_root = Path(args.project_root).resolve()
    real_fixtures_dir = Path(args.fixtures_dir).resolve() if args.fixtures_dir else project_root / "aicomp_sdk" / "fixtures"

    print("\n" + "=" * 70)
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
                     "file_seed/note.txt", "file_seed/report.txt", "file_seed/api_keys.txt",
                     "file_seed/writable.txt", "file_seed/writable2.txt", "file_seed/temp.txt"]
    hash_targets = [t for t in hash_targets if (real_fixtures_dir / t).is_file()]
    real_hashes_before = snapshot_real_hashes(real_fixtures_dir, hash_targets)
    print(f"  [safety] real fixture hashes captured BEFORE anything runs (targets: {hash_targets})")

    all_results: list[dict[str, Any]] = []
    seed_counter = 100000  # distinct seed range from every prior script's ranges (60000/90000/91000)

    try:
        print("\n" + "=" * 70)
        print(f"RUNNING {len(candidates)} candidate(s) x {args.n_repeats} repeat(s) "
              f"= {len(candidates) * args.n_repeats} total model conversations")
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
    print(f"  MATCH: {n_match}   MISMATCH: {n_mismatch}   UNCLEAR: {n_unclear}")
    print("\n  Per-family breakdown:")
    by_family_results: dict[str, dict[str, int]] = {}
    for r in all_results:
        d = by_family_results.setdefault(r["family"], {"MATCH": 0, "MISMATCH": 0, "UNCLEAR": 0})
        if r["verdict"] == "MATCH":
            d["MATCH"] += 1
        elif r["verdict"] == "MISMATCH":
            d["MISMATCH"] += 1
        else:
            d["UNCLEAR"] += 1
    for fam, d in by_family_results.items():
        print(f"    {fam}: MATCH={d['MATCH']} MISMATCH={d['MISMATCH']} UNCLEAR={d['UNCLEAR']}")
    if n_mismatch > 0:
        print("\n  MISMATCHED CASES (review manually -- note some MISMATCHes are known classifier "
              "artifacts, e.g. DW23's DENY-shaped expectation after a successful clean prerequisite "
              "write; see project notes before treating any MISMATCH as a live regression):")
        for r in all_results:
            if r["verdict"] == "MISMATCH":
                print(f"    - {r['family']}/{r['instruction_id']}#{r['candidate_idx']} repeat{r['repeat_no']}: "
                      f"expected={r['expected']} outcome={r['outcome_summary']}")

    out_path = Path(args.out)
    write_json(out_path, {
        "family_filter": args.family, "instruction_id_filter": args.instruction_id or "all",
        "n_repeats": args.n_repeats,
        "summary": {"n_match": n_match, "n_mismatch": n_mismatch, "n_unclear": n_unclear, "n_total": len(all_results)},
        "per_family_summary": by_family_results,
        "results": all_results, "safety_verification": safety_report,
        "note": ("Single consolidated local validation summary covering all candidates from "
                 "attack_yaml_harness_v5_2_full_inline.py (58 frozen v5.1 + 8 Tier-1, merged). "
                 "Does NOT touch, re-validate, or affect the frozen v5.1 58-candidate Kaggle "
                 "submission in any way. No network call to any Kaggle endpoint was made."),
    })
    print(f"\nFull local validation summary written to: {out_path.resolve()}")


if __name__ == "__main__":
    main()
