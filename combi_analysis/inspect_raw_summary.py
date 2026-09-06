#!/usr/bin/env python3
# =============================================================================
# inspect_raw_summary.py  (v2 -- fixes a bug in the tool itself)
#
# WHAT WAS WRONG WITH v1: it used a SIMPLIFIED, incomplete normalizer that
# only checked "is the top-level a dict-of-lists" -- it did NOT check for a
# wrapper key like "results" (the ACTUAL shape of your real file, confirmed
# by your last run: a single dict with 8 keys including "results" -> a list
# of 198 record dicts). Because of that gap, v1 treated your entire
# top-level dict as ONE record, which is why it reported "Total flattened
# records: 1" and found no tool_events.
#
# v2 fixes this by reusing the EXACT SAME normalize_raw_summary() logic
# already tested and confirmed working inside priority1_paired_replay.py
# (that harness's real run against your file printed "Normalized ... -> 198
# per-run records", proving THAT function already handles the "results"
# wrapper key correctly) -- verified again here against a synthetic file
# matching your exact confirmed real shape before this was shipped.
#
# This tool is still READ-ONLY -- no replay logic, no file modification.
#
# HOW TO RUN (same as before):
#   python inspect_raw_summary.py --file "C:\x_ai_logs\Combi_analysis\local_validate_v5_2_full_summary.json"
#
# Please paste the ENTIRE output back.
# =============================================================================

import argparse
import json


def normalize_raw_summary(raw_summary):
    """EXACT SAME logic as priority1_paired_replay.py's tested version --
    confirmed correct against your real file (produced 198 records)."""
    if isinstance(raw_summary, list):
        return raw_summary

    if isinstance(raw_summary, dict):
        for wrapper_key in ("runs", "results", "records", "data", "summary"):
            if wrapper_key in raw_summary and isinstance(raw_summary[wrapper_key], list):
                return raw_summary[wrapper_key]

        flattened = []
        sample_value = next(iter(raw_summary.values()), None)
        if isinstance(sample_value, list):
            for candidate_id, repeat_list in raw_summary.items():
                for run_record in repeat_list:
                    if isinstance(run_record, dict):
                        run_record = dict(run_record)
                        run_record.setdefault("candidate_id", candidate_id)
                        flattened.append(run_record)
            if flattened:
                return flattened
        elif isinstance(sample_value, dict):
            for candidate_id, run_record in raw_summary.items():
                run_record = dict(run_record)
                run_record.setdefault("candidate_id", candidate_id)
                flattened.append(run_record)
            if flattened:
                return flattened

    raise ValueError("Could not determine structure -- top-level type: {}".format(type(raw_summary).__name__))


def summarize_value(value, max_len=200):
    if isinstance(value, str):
        if len(value) > max_len:
            return "<str, len={}> {!r}...".format(len(value), value[:max_len])
        return repr(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return repr(value)
    if isinstance(value, list):
        return "<list, len={}>".format(len(value))
    if isinstance(value, dict):
        return "<dict, keys={}>".format(sorted(value.keys()))
    return "<{}>".format(type(value).__name__)


def main():
    parser = argparse.ArgumentParser(description="Read-only inspector for local_validate_v5_2_full_summary.json (v2)")
    parser.add_argument("--file", required=True)
    args = parser.parse_args()

    with open(args.file, "r", encoding="utf-8") as f:
        raw = json.load(f)

    print("=" * 78)
    print("STEP 1: top-level structure")
    print("=" * 78)
    print("Top-level type:", type(raw).__name__)
    if isinstance(raw, dict):
        print("Number of top-level keys:", len(raw))
        print("All top-level keys:", sorted(raw.keys()))

    records = normalize_raw_summary(raw)
    print()
    print("Total flattened records (using the SAME normalizer already confirmed")
    print("working in priority1_paired_replay.py):", len(records))

    print()
    print("=" * 78)
    print("STEP 2: find one DESTRUCTIVE_WRITE record with NON-EMPTY tool_events")
    print("=" * 78)
    dw_record = None
    for r in records:
        family_val = r.get("family") or r.get("category")
        te = r.get("tool_events")
        if family_val == "DESTRUCTIVE_WRITE" and isinstance(te, list) and len(te) > 0:
            dw_record = r
            break
    if dw_record is None:
        # relax: any DW record, even with empty tool_events, so we at least
        # see the top-level shape; separately search for ANY record (any
        # family) with a non-empty tool_events for Step 3.
        for r in records:
            if (r.get("family") or r.get("category")) == "DESTRUCTIVE_WRITE":
                dw_record = r
                break
    if dw_record is None:
        print("WARNING: no record found with family=='DESTRUCTIVE_WRITE' -- using the first record instead.")
        dw_record = records[0]

    print("Using record with case_id/candidate_id:", dw_record.get("case_id") or dw_record.get("candidate_id"))
    print()
    print("--- Top-level fields of this ONE record (value summarized) ---")
    for key in sorted(dw_record.keys()):
        print("  {!r}: {}".format(key, summarize_value(dw_record[key])))

    print()
    print("=" * 78)
    print("STEP 3: inspect 'tool_events' internal shape (THE CRITICAL PART)")
    print("=" * 78)
    tool_events = dw_record.get("tool_events")
    if not (isinstance(tool_events, list) and len(tool_events) > 0):
        print("This specific record's tool_events is empty/missing. Searching ALL")
        print("records for the first one with a NON-EMPTY tool_events list...")
        for r in records:
            te = r.get("tool_events")
            if isinstance(te, list) and len(te) > 0:
                print("Found one: case_id/candidate_id =", r.get("case_id") or r.get("candidate_id"),
                      " family =", r.get("family") or r.get("category"))
                tool_events = te
                dw_record = r
                break

    if isinstance(tool_events, list) and len(tool_events) > 0:
        print("tool_events is a list with {} entries. Full JSON of entry [0]:".format(len(tool_events)))
        print(json.dumps(tool_events[0], indent=2, default=str))
        if len(tool_events) > 1:
            print()
            print("Full JSON of entry [1] (to confirm the shape is consistent):")
            print(json.dumps(tool_events[1], indent=2, default=str))
    else:
        print("Could not find ANY record (in all {} records) with a non-empty".format(len(records)))
        print("tool_events list. This is unexpected given n_total_runs=198 with real")
        print("guardrail activity -- please double check tool_events is really the field")
        print("name (see the full key list printed in Step 2 above for alternatives).")

    print()
    print("=" * 78)
    print("STEP 4: inspect 'per_turn_log' internal shape (may hold the turn/hop number")
    print("         separately from tool_events)")
    print("=" * 78)
    per_turn_log = dw_record.get("per_turn_log")
    if isinstance(per_turn_log, list) and len(per_turn_log) > 0:
        print("per_turn_log is a list with {} entries. Full JSON of entry [0]:".format(len(per_turn_log)))
        print(json.dumps(per_turn_log[0], indent=2, default=str))
        if len(per_turn_log) > 1:
            print()
            print("Full JSON of entry [1]:")
            print(json.dumps(per_turn_log[1], indent=2, default=str))
    else:
        print("per_turn_log is empty, missing, or not a list on this record:", summarize_value(per_turn_log))

    print()
    print("=" * 78)
    print("STEP 5: other potentially-relevant fields on this record, summarized")
    print("=" * 78)
    for key in ("expected", "verdict", "is_breach", "predicates_triggered", "outcome_summary",
                "tools_offered", "instruction_id", "candidate_idx", "hypothesis"):
        if key in dw_record:
            print("  {!r}: {}".format(key, json.dumps(dw_record[key], default=str)[:300]))

    print()
    print("=" * 78)
    print("DONE. Please copy/paste this ENTIRE output back into the chat.")
    print("=" * 78)


if __name__ == "__main__":
    main()
