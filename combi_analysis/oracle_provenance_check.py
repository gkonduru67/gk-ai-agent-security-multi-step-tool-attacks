#!/usr/bin/env python3
# =============================================================================
# oracle_provenance_check.py
# AI_AGENT_SECURITY -- Phase 1, Priority 0 helper
#
# PURPOSE
# -------
# You flagged you couldn't determine whether these two candidate files:
#   ex6f_encoded_derivation_trace_enc_exact_oracle.json
#   ex6f_post_without_successful_effect_trace_oracle.json
# satisfy the priority_0 rule that independent_expected_policy_labels must
# be "authored BEFORE running replay, not derived from its output."
#
# This script CANNOT give you a definitive yes/no -- provenance (who wrote
# a file, and from what) is not fully recoverable from the file alone. What
# it CAN do is give you concrete, inspectable evidence across three
# independent signals, so you make the final call with real information
# instead of a guess:
#
#   1. NAME-BASED RED FLAGS (weak signal, but immediate and free):
#      both filenames literally contain "trace" and "derivation" --
#      words that suggest "the output of processing something" rather
#      than "a label I wrote down." This is flagged, not treated as proof.
#
#   2. SCHEMA/FIELD-NAME FINGERPRINTING (moderate signal):
#      loads each JSON file and checks its field names against two lists:
#        - DERIVED_FINGERPRINT_FIELDS: field names that can ONLY exist if
#          computed by actually running a guardrail/predicate over a trace
#          (e.g. "guardrail_decision", "tool_executed", "is_breach").
#          Presence of ANY of these is a strong signal the file was
#          generated FROM a replay/execution, not authored independently.
#        - AUTHORED_FINGERPRINT_FIELDS: field names consistent with a
#          human-written oracle label (e.g. "expected_label", "rationale",
#          "authored_by", "candidate_id" alone with no execution fields).
#      Presence of derived fields is disqualifying regardless of anything
#      else. Presence of ONLY authored fields is supportive, not proof.
#
#   3. TIMESTAMP CROSS-CHECK (weak-to-moderate signal, Windows-caveat'd):
#      compares each oracle file's mtime against the raw 198-run summary's
#      mtime and the candidate corpus's mtime. A file that is NEWER than
#      the 198-run summary and shares unusual structural similarity to it
#      is more suspicious than one that predates it -- but mtime can be
#      reset by copies/moves, so this is explicitly labeled unreliable
#      alone.
#
#   4. CANDIDATE-ID CROSS-REFERENCE (informational, not a red/green flag):
#      reports whether the oracle file's candidate IDs (if a candidate_id-
#      like field is found) cover all 66 candidates or only a subset --
#      useful for Priority 1 readiness regardless of the provenance verdict.
#
# The script prints a verdict for each file: LIKELY_DERIVED_DO_NOT_USE,
# INCONCLUSIVE_REVIEW_MANUALLY, or NO_RED_FLAGS_FOUND -- and always prints
# its full reasoning, never just the verdict. If a file trips ANY derived-
# fingerprint field, the verdict is forced to LIKELY_DERIVED_DO_NOT_USE
# regardless of other signals.
#
# IF THE VERDICT IS INCONCLUSIVE OR LIKELY_DERIVED:
# You asked "if i am not able identify can we rerun code?" -- yes. The
# safest path consistent with your own evidence-discipline rule is to
# NOT use either file as-is, and instead author fresh policy labels now,
# before Priority 1 starts. Run this script with --emit-template to
# generate independent_expected_policy_labels_v1.csv, a clean starting
# point you fill in by hand (see template docstring below for the
# authoring workflow this implies).
#
# Run command:
#   python oracle_provenance_check.py --oracle-file "C:\...\ex6f_encoded_derivation_trace_enc_exact_oracle.json" --oracle-file "C:\...\ex6f_post_without_successful_effect_trace_oracle.json" --raw-summary "C:\x_ai_logs\Combi_analysis\local_validate_v5_2_full_summary.json" --candidate-corpus "C:\...\combi_analysis\attack_yaml_harness_v5_2_full_inline.json"
#   python oracle_provenance_check.py --emit-template
# =============================================================================

import os
import sys
import json
import argparse
import datetime

SCRIPT_VERSION = "oracle_provenance_check_v1.0"

# -----------------------------------------------------------------------------
# Fingerprint field lists. These are deliberately conservative: a field name
# has to closely match known execution/trace-output vocabulary (drawn
# directly from your own priority_1 per_candidate_per_repeat_record schema)
# to count as a DERIVED fingerprint.
# -----------------------------------------------------------------------------

DERIVED_FINGERPRINT_FIELDS = {
    "guardrail_decision", "guardrail_reason", "tool_executed",
    "side_effect_or_state_delta", "official_predicate_result",
    "is_breach", "proposal_formed", "predicate_fired", "trace_id",
    "run_id", "hop", "episode_id", "tool_call_result", "denied_by",
    "allowed_by", "actual_effect", "observed_decision", "replay_output",
}

AUTHORED_FINGERPRINT_FIELDS = {
    "expected_label", "expected_policy", "expected_policy_label",
    "rationale", "authored_by", "authored_date", "author", "candidate_id",
    "family", "policy_basis", "ground_truth_label", "reviewer",
    "labeling_notes", "created_before_replay",
}

NAME_RED_FLAG_SUBSTRINGS = ["trace", "derivation", "derived", "replay_output", "recovery"]


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def win_long_path(p):
    if os.name != "nt":
        return p
    if p.startswith("\\\\?\\"):
        return p
    if p.startswith("\\\\"):
        return "\\\\?\\UNC\\" + p.lstrip("\\")
    return "\\\\?\\" + p


def load_json_safely(path):
    try:
        with open(win_long_path(path), "r", encoding="utf-8") as f:
            return json.load(f), None
    except json.JSONDecodeError as e:
        return None, "JSON_DECODE_ERROR: {}".format(e)
    except OSError as e:
        return None, "FILE_READ_ERROR: {}".format(e)


def collect_field_names(obj, depth=0, max_depth=6, acc=None):
    """Recursively collect all dict keys seen anywhere in the JSON structure,
    lowercased, so field-name fingerprinting doesn't depend on exact nesting."""
    if acc is None:
        acc = set()
    if depth > max_depth:
        return acc
    if isinstance(obj, dict):
        for k, v in obj.items():
            acc.add(str(k).lower())
            collect_field_names(v, depth + 1, max_depth, acc)
    elif isinstance(obj, list):
        for item in obj[:50]:  # cap to avoid pathological huge arrays
            collect_field_names(item, depth + 1, max_depth, acc)
    return acc


def find_candidate_ids(obj, id_key_candidates=("candidate_id", "id", "candidate", "name"), depth=0, max_depth=6, found=None):
    if found is None:
        found = set()
    if depth > max_depth:
        return found
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in id_key_candidates and isinstance(v, (str, int)):
                found.add(str(v))
            find_candidate_ids(v, id_key_candidates, depth + 1, max_depth, found)
    elif isinstance(obj, list):
        for item in obj:
            find_candidate_ids(item, id_key_candidates, depth + 1, max_depth, found)
    return found


def analyze_oracle_file(path, raw_summary_mtime=None, corpus_mtime=None):
    report = {"path": path}

    name_flags = [s for s in NAME_RED_FLAG_SUBSTRINGS if s in os.path.basename(path).lower()]
    report["filename_red_flags"] = name_flags

    if not os.path.isfile(win_long_path(path)):
        report["error"] = "FILE_NOT_FOUND"
        report["verdict"] = "CANNOT_ANALYZE"
        return report

    try:
        mtime = os.path.getmtime(win_long_path(path))
        report["mtime_utc"] = datetime.datetime.fromtimestamp(mtime, tz=datetime.timezone.utc).isoformat()
    except OSError:
        report["mtime_utc"] = None
        mtime = None

    timestamp_notes = []
    if mtime is not None and raw_summary_mtime is not None:
        if mtime > raw_summary_mtime:
            timestamp_notes.append(
                "Oracle file mtime is AFTER the 198-run raw summary's mtime. "
                "Not proof of derivation (mtime resets on copy/move on Windows), "
                "but worth noting -- an independently-authored oracle would more "
                "typically predate or be contemporaneous with data collection."
            )
        else:
            timestamp_notes.append(
                "Oracle file mtime is BEFORE (or equal to) the 198-run raw summary's "
                "mtime -- consistent with, but not proof of, independent pre-authorship."
            )
    else:
        timestamp_notes.append("Insufficient timestamp data to compare (pass --raw-summary to enable this check).")
    report["timestamp_notes"] = timestamp_notes

    data, err = load_json_safely(path)
    if err:
        report["error"] = err
        report["verdict"] = "CANNOT_ANALYZE"
        return report

    fields = collect_field_names(data)
    derived_hits = sorted(fields & DERIVED_FINGERPRINT_FIELDS)
    authored_hits = sorted(fields & AUTHORED_FINGERPRINT_FIELDS)
    report["derived_fingerprint_fields_found"] = derived_hits
    report["authored_fingerprint_fields_found"] = authored_hits
    report["all_field_names_seen"] = sorted(fields)

    candidate_ids = find_candidate_ids(data)
    report["candidate_ids_found"] = sorted(candidate_ids)
    report["candidate_id_count"] = len(candidate_ids)

    if derived_hits:
        report["verdict"] = "LIKELY_DERIVED_DO_NOT_USE"
        report["verdict_reason"] = (
            "Found field name(s) {} that only make sense as OUTPUT of running a "
            "guardrail/predicate over a trace, not as independently-authored "
            "labels. Per your own priority_0 rule, do not use this file as the "
            "independent_expected_policy_label source.".format(derived_hits)
        )
    elif authored_hits and not derived_hits:
        report["verdict"] = "NO_RED_FLAGS_FOUND"
        report["verdict_reason"] = (
            "Field names found ({}) are consistent with independently-authored "
            "labels, and no execution/trace-derived field names were found. "
            "This SUPPORTS (does not prove) independent authorship. Still "
            "recommend manually opening the file and reading a few records "
            "to confirm the labels reflect POLICY INTENT, not observed behavior.".format(authored_hits)
        )
    else:
        report["verdict"] = "INCONCLUSIVE_REVIEW_MANUALLY"
        report["verdict_reason"] = (
            "Neither a clear derived-fingerprint nor a clear authored-fingerprint "
            "field was found. Field names present: {}. You will need to open this "
            "file directly and judge whether each record reflects a POLICY "
            "DECISION MADE IN ADVANCE, or an OBSERVATION of what actually "
            "happened when something was run.".format(sorted(fields)[:20])
        )

    if name_flags:
        report["verdict_reason"] += (
            " ADDITIONALLY: the filename itself contains {} -- a naming "
            "convention more typical of derived/computed artifacts than "
            "hand-authored labels. This alone does not override a "
            "NO_RED_FLAGS_FOUND schema verdict, but raises the bar for how "
            "carefully you should manually spot-check this file before "
            "trusting it.".format(name_flags)
        )

    return report


def emit_template(out_path, known_candidate_ids=None):
    """
    Emits a starting CSV template for independent_expected_policy_labels.
    Columns are chosen to be schema-compatible with priority_1's
    per_candidate_per_repeat_record.independent_expected_policy_label
    requirement, while staying clearly on the "authored label" side of the
    derived/authored fingerprint distinction used above (no execution-
    result columns are included on purpose).
    """
    import csv
    header = [
        "candidate_id", "family",
        "expected_policy_label",   # e.g. "should_deny" / "should_allow" / "should_confirm"
        "rationale",               # why -- cite the policy rule, not observed behavior
        "policy_basis",            # e.g. "no explicit user intent to share" (CONFUSED_DEPUTY predicate text)
        "authored_by",
        "authored_date_utc",
        "reviewer",
        "labeling_notes",
    ]
    seed_ids = known_candidate_ids or [
        "E1", "EX06", "EX09", "EX17", "EX18",
        "DW05", "DW23", "DW06",
        "CD11", "CD12", "CD13", "CD14", "CD15",
        "C3", "C_recipient_drift", "C_body_scope_expansion", "C_explicit_unauthorized_send",
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for cid in seed_ids:
            w.writerow([cid, "", "", "", "", "", "", "", ""])
    print("Wrote template: {}".format(os.path.abspath(out_path)))
    print("NOTE: seeded with the {} candidate IDs explicitly named across your".format(len(seed_ids)))
    print("plan documents (matched-control and ledger discussion sections) as a")
    print("starting point ONLY. You must add rows for all 66 candidates -- this")
    print("script has no access to your actual candidate corpus contents, only")
    print("its hash, so it cannot enumerate the full 66 IDs for you.")
    print("Fill in candidate_id/family/expected_policy_label/rationale by hand,")
    print("BEFORE running priority_1 replay. authored_date_utc should be set to")
    print("today, giving you an unambiguous, self-declared authorship timestamp")
    print("that resolves this exact ambiguity for any FUTURE version of this file.")


def main():
    parser = argparse.ArgumentParser(description="Check provenance of candidate independent_expected_policy_labels files.")
    parser.add_argument("--oracle-file", action="append", default=[],
                         help="Path to a candidate oracle/label JSON file. Repeatable.")
    parser.add_argument("--raw-summary", default=None,
                         help="Path to local_validate_v5_2_full_summary.json (for timestamp comparison).")
    parser.add_argument("--candidate-corpus", default=None,
                         help="Path to attack_yaml_harness_v5_2_full_inline (for timestamp comparison).")
    parser.add_argument("--output", default="oracle_provenance_report.json")
    parser.add_argument("--emit-template", action="store_true",
                         help="Skip analysis; just write independent_expected_policy_labels_v1.csv template.")
    parser.add_argument("--template-output", default="independent_expected_policy_labels_v1.csv")
    args = parser.parse_args()

    if args.emit_template:
        emit_template(args.template_output)
        return 0

    if not args.oracle_file:
        print("ERROR: pass at least one --oracle-file, or use --emit-template.")
        return 2

    raw_summary_mtime = None
    if args.raw_summary and os.path.isfile(win_long_path(args.raw_summary)):
        raw_summary_mtime = os.path.getmtime(win_long_path(args.raw_summary))

    corpus_mtime = None
    if args.candidate_corpus and os.path.isfile(win_long_path(args.candidate_corpus)):
        corpus_mtime = os.path.getmtime(win_long_path(args.candidate_corpus))

    results = []
    for oracle_path in args.oracle_file:
        r = analyze_oracle_file(oracle_path, raw_summary_mtime, corpus_mtime)
        results.append(r)

    output = {
        "script_version": SCRIPT_VERSION,
        "generated_at_utc": utc_now(),
        "raw_summary_path": args.raw_summary,
        "raw_summary_mtime_utc": (
            datetime.datetime.fromtimestamp(raw_summary_mtime, tz=datetime.timezone.utc).isoformat()
            if raw_summary_mtime else None
        ),
        "results": results,
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print("=" * 78)
    print("ORACLE PROVENANCE CHECK")
    print("=" * 78)
    for r in results:
        print()
        print("File: {}".format(r["path"]))
        print("  Verdict: {}".format(r.get("verdict", "?")))
        print("  Reason:  {}".format(r.get("verdict_reason", r.get("error", "?"))))
        if "candidate_id_count" in r:
            print("  Candidate IDs found: {} -- {}".format(r["candidate_id_count"], r["candidate_ids_found"][:10]))
        for note in r.get("timestamp_notes", []):
            print("  Timestamp note: {}".format(note))
    print()
    print("Wrote full report: {}".format(os.path.abspath(args.output)))
    print()
    any_derived = any(r.get("verdict") == "LIKELY_DERIVED_DO_NOT_USE" for r in results)
    any_inconclusive = any(r.get("verdict") == "INCONCLUSIVE_REVIEW_MANUALLY" for r in results)
    any_unanalyzable = any(r.get("verdict") == "CANNOT_ANALYZE" for r in results)
    if any_unanalyzable:
        print("ERROR: one or more files could not be analyzed at all (see CANNOT_ANALYZE")
        print("entries above -- check the path and try again).")
    if any_derived or any_inconclusive or any_unanalyzable:
        print("RECOMMENDATION: at least one file did not get a clean NO_RED_FLAGS_FOUND")
        print("verdict. Per your priority_0 rule and your own evidence-discipline")
        print("standard, do NOT use it as independent_expected_policy_labels as-is.")
        print("Run:  python oracle_provenance_check.py --emit-template")
        print("to generate a fresh, unambiguous starting point instead.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
