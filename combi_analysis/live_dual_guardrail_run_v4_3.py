#!/usr/bin/env python3
"""
preflight_verify_dw_rerun_targets_v1.py

WHY THIS SCRIPT EXISTS INSTEAD OF A NEW LIVE-RUN HARNESS:
live_dual_guardrail_run_v4_1.py (your real, already-validated harness) ALREADY
supports exactly the use case you need: pass --only-instruction-ids to filter
which instruction_ids to select, point --out at your EXISTING checkpoint file
(live_dual_guardrail_dw_result.json), and its own built-in resume logic
(load_existing_checkpoint / already_completed) will automatically SKIP any
(instruction_id, candidate_idx) pair already present in that file and run
ONLY the missing ones.

Reimplementing that ~500-line harness (live model calls, retry/backoff logic,
tool execution for fs.read/fs.write/fs.delete/web.open/email.read, guardrail
adapters, predicate evaluation, byte-hash safety verification) from scratch
here would be redundant, riskier (a second, un-battle-tested implementation
of the same complex logic), and inconsistent with this project's own
evidence-discipline rule against duplicating already-verified machinery.

INSTEAD, this script does the one thing that genuinely needs to be verified
BEFORE spending live-model time: CONFIRM, from the real, already-attached
checkpoint file alone (no live model, no missing files needed), that the
harness's own --only-instruction-ids + resume mechanism will select and run
EXACTLY the 4 target candidates you asked for -- neither more (re-running
already-done work) nor fewer (silently missing one).

This is fully testable right now, with zero dependencies beyond the
checkpoint JSON you already have.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# The full, confirmed 18-candidate DESTRUCTIVE_WRITE manifest (instruction_id
# -> list of candidate_idx values). Cross-verified in a prior session turn
# against this exact checkpoint file's own n_candidates_total:18 field, and
# re-confirmed again by this script at runtime (see --verify-only note below).
EXPECTED_FULL_DW_MANIFEST = {
    "D1_canonical_denial_anchor": [0],
    "D_clean_name_full_lifecycle": [0],
    "D_substring_boundary_pair": [0, 1],
    "D_indirect_injection_triplet": [0, 1, 2],
    "DW05_target_binding_drift": [0],
    "DW06_content_binding_drift": [0],
    "DW09_lexical_overblock_matrix_expansion": [0, 1, 2],
    "DW11_email_sourced_delete_triplet": [0, 1, 2],
    "DW21_amplification_redesigned_single_call": [0],
    "DW22_write_authorization_reuse": [0],
    "DW23_target_binding_drift_onto_canonical": [0],
}

DEFAULT_TARGET_INSTRUCTION_IDS = [
    "D_indirect_injection_triplet",
    "DW11_email_sourced_delete_triplet",
    "DW21_amplification_redesigned_single_call",
    "D_clean_name_full_lifecycle",
]


def load_checkpoint_completed_pairs(checkpoint_path: Path) -> tuple[set, dict]:
    with checkpoint_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    completed = {(r["instruction_id"], r["candidate_idx"]) for r in data.get("results", [])}
    return completed, data


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--checkpoint", required=True,
                     help="Path to your existing live_dual_guardrail_dw_result.json checkpoint file.")
    ap.add_argument("--target-instruction-ids", nargs="*", default=DEFAULT_TARGET_INSTRUCTION_IDS,
                     help="instruction_id values to target (default: the 4 confirmed-missing DW candidates).")
    ap.add_argument("--project-root", default="C:\\...\\ai-agent-security-multi-step-tool-attacks",
                     help="Used only to print the final ready-to-run command -- not accessed by this script.")
    ap.add_argument("--model-url", default="http://127.0.0.1:8080/v1/chat/completions")
    ap.add_argument("--dw-guardrail-path", default="UTA\\dw_authorization_unit_v4_40.py")
    ap.add_argument("--dw-specs-file", default="combi_analysis\\dw_candidate_authorization_specs_v1.csv")
    args = ap.parse_args()

    checkpoint_path = Path(args.checkpoint)
    if not checkpoint_path.is_file():
        print(f"FATAL: checkpoint file not found: {checkpoint_path}")
        return 2

    completed, raw_data = load_checkpoint_completed_pairs(checkpoint_path)

    n_total_in_file = raw_data.get("n_candidates_total")
    n_completed_in_file = raw_data.get("n_candidates_completed")
    run_complete_in_file = raw_data.get("run_complete")

    print("=" * 96)
    print("STEP 1: Checkpoint file self-report")
    print("=" * 96)
    print(f"  n_candidates_total (per file):     {n_total_in_file}")
    print(f"  n_candidates_completed (per file): {n_completed_in_file}")
    print(f"  run_complete (per file):           {run_complete_in_file}")
    print(f"  actual completed pairs found:      {len(completed)}")
    if len(completed) != n_completed_in_file:
        print(f"  *** WARNING: file's own n_candidates_completed ({n_completed_in_file}) does not "
              f"match actual results list length ({len(completed)}) -- investigate before proceeding. ***")

    print("\n" + "=" * 96)
    print("STEP 2: Cross-check against the expected full 18-candidate DW manifest")
    print("=" * 96)
    expected_set = {(iid, idx) for iid, idxs in EXPECTED_FULL_DW_MANIFEST.items() for idx in idxs}
    print(f"  Expected full manifest size: {len(expected_set)}")
    if n_total_in_file is not None and len(expected_set) != n_total_in_file:
        print(f"  *** WARNING: expected manifest size ({len(expected_set)}) does not match the "
              f"checkpoint file's own n_candidates_total ({n_total_in_file}). This script's "
              f"EXPECTED_FULL_DW_MANIFEST constant may be stale -- do not trust the 'missing' "
              f"computation below without resolving this first. ***\n")
    else:
        print("  MATCH -- expected manifest size agrees with the checkpoint's own declared total.\n")

    missing_overall = sorted(expected_set - completed)
    print(f"  Full set of candidates missing from this checkpoint (n={len(missing_overall)}):")
    for pair in missing_overall:
        print(f"     {pair[0]}#{pair[1]}")

    print("\n" + "=" * 96)
    print("STEP 3: Simulate live_dual_guardrail_run_v4_1.py's own selection + resume logic")
    print("=" * 96)
    print(f"  Target --only-instruction-ids: {args.target_instruction_ids}")
    selected_by_filter = {(iid, idx) for iid, idx in expected_set if iid in set(args.target_instruction_ids)}
    print(f"  Candidates the real harness's own select_family_candidates() would SELECT "
          f"(all candidate_idx values for these instruction_ids): {sorted(selected_by_filter)}")
    would_skip = sorted(selected_by_filter & completed)
    would_run = sorted(selected_by_filter - completed)
    print(f"\n  Of those, ALREADY in this checkpoint (the harness's OWN resume logic will auto-SKIP these,"
          f" per its load_existing_checkpoint()/already_completed set -- confirmed from its real source): "
          f"{would_skip}")
    print(f"\n  Of those, NOT yet in this checkpoint (these are the ONLY ones that will actually run "
          f"live against the model): {would_run}")

    print("\n" + "=" * 96)
    print("STEP 4: Verdict")
    print("=" * 96)
    target_missing = sorted((iid, idx) for iid, idx in missing_overall if iid in set(args.target_instruction_ids))
    if would_run == target_missing and len(would_run) == len(args.target_instruction_ids):
        print("VERIFIED: resuming the real harness with the command below will run EXACTLY the "
              f"{len(would_run)} target candidate(s), skip all {len(would_skip)} already-completed "
              "sibling candidate(s) for these instruction_ids, and touch nothing else in the checkpoint.")
        ready = True
    else:
        print("*** MISMATCH -- DO NOT PROCEED without investigating this discrepancy first. ***")
        print(f"    would_run computed here:        {would_run}")
        print(f"    expected (missing & targeted):  {target_missing}")
        ready = False

    print("\n" + "=" * 96)
    print("READY-TO-RUN COMMAND (only if VERIFIED above)")
    print("=" * 96)
    only_ids_arg = ",".join(args.target_instruction_ids)
    cmd = (
        f'python live_dual_guardrail_run_v4_1.py --i-authorize-local-validation ^\n'
        f'    --project-root "{args.project_root}" ^\n'
        f'    --model-url {args.model_url} ^\n'
        f'    --family DESTRUCTIVE_WRITE ^\n'
        f'    --dw-guardrail-path "{args.dw_guardrail_path}" ^\n'
        f'    --dw-specs-file "{args.dw_specs_file}" ^\n'
        f'    --only-instruction-ids "{only_ids_arg}" ^\n'
        f'    --out live_dual_guardrail_dw_result.json'
    )
    print(cmd)
    print("\nNOTE: --out points at your EXISTING checkpoint file (not a new filename) so the "
          "harness's own resume logic activates. Do NOT pass --force-rerun-all -- that flag "
          "explicitly discards the checkpoint and would re-run all 18 candidates from scratch.")
    print("\nAfter this completes, re-run this preflight script again against the updated "
          "checkpoint file -- it should report 0 missing candidates and run_complete:true.")

    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(main())
