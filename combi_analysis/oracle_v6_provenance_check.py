#!/usr/bin/env python3
# =============================================================================
# oracle_provenance_check.py  (v1.1 -- corpus-based candidate ID extraction)
# AI_AGENT_SECURITY -- Phase 1, Priority 0 helper
#
# CHANGELOG vs v1.0
# ------------------
#   v1.1: --emit-template now accepts --candidate-corpus, and attempts a
#   SAFE STATIC extraction of your actual 66 candidate IDs from the frozen
#   attack_yaml_harness_v5_2_full_inline file, instead of only offering
#   the 17 IDs explicitly named in your plan docs. "Safe static" means:
#   the corpus file is NEVER imported/exec'd/eval'd -- it is read as text,
#   optionally walked via ast.parse() (which only builds a syntax tree,
#   it does not run anything), plus a regex pass matching your project's
#   own candidate-ID naming conventions (E#, EX##, DW##, CD##, C_*, UTA*).
#   If extraction finds a count other than 66, this is surfaced as an
#   explicit WARNING (never silently accepted) -- per this project's
#   standing evidence-discipline requirement.
#
# WHAT "NEEDS TO BE DONE" FOR independent_expected_policy_labels
# ------------------------------------------------------------------
# This is fundamentally NOT a file-finding problem -- it's an authoring
# task only you can do, because the labels must encode POLICY INTENT
# (what SHOULD happen for each candidate under the rules you designed),
# not observed behavior. Concretely, the steps are:
#   1. Run --emit-template (ideally with --candidate-corpus) to get a
#      CSV pre-populated with candidate IDs.
#   2. For EACH of the 66 rows, fill in:
#        family                  -- which of the 4 families it belongs to
#        expected_policy_label   -- e.g. should_deny / should_allow /
#                                    should_confirm, based on the POLICY
#                                    RULE, not on what the guardrail
#                                    actually did when you ran it
#        rationale               -- cite the specific rule (e.g. "renamed-
#                                    path bypass of a protected read" or
#                                    "legitimate split-turn authorization")
#        policy_basis            -- the predicate/guardrail rule text this
#                                    traces back to
#        authored_by / authored_date_utc -- so authorship timing is
#                                    self-evident for anyone auditing later
#   3. Save as e.g. independent_expected_policy_labels_v1.csv under your
#      combi_analysis folder, then rerun manifest_v1_generator.py -- it
#      already searches ALL_ROOTS + authored_artifacts_root for this
#      filename pattern.
# There is no way to script step 2 -- it requires your judgment about what
# SHOULD happen, which is precisely the point of having an independent
# oracle (if it could be derived automatically, it wouldn't be independent).
#
# Run command examples:
#   python oracle_provenance_check.py --oracle-file "C:\...\file1.json" --oracle-file "C:\...\file2.json" --raw-summary "C:\x_ai_logs\Combi_analysis\local_validate_v5_2_full_summary.json"
#   python oracle_provenance_check.py --emit-template --candidate-corpus "C:\...\combi_analysis\attack_yaml_harness_v5_2_full_inline.py"
# =============================================================================

import os
import sys
import json
import argparse
import datetime
import re
import ast

SCRIPT_VERSION = "oracle_provenance_check_v1.1"

DERIVED_FINGERPRINT_FIELDS = {
    "guardrail_decision", "guardrail_reason", "tool_executed",
    "side_effect_or_state_delta", "official_predicate_result",
    "is_breach", "proposal_formed", "predicate_fired", "trace_id",
    "run_id", "hop", "episode_id", "tool_call_result", "denied_by",
    "allowed_by", "actual_effect", "observed_decision", "replay_output",
    "assistant_messages", "user_messages", "tool_events",
    "live_external_effect", "side_effect", "egress", "synthetic_control",
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
    if acc is None:
        acc = set()
    if depth > max_depth:
        return acc
    if isinstance(obj, dict):
        for k, v in obj.items():
            acc.add(str(k).lower())
            collect_field_names(v, depth + 1, max_depth, acc)
    elif isinstance(obj, list):
        for item in obj[:50]:
            collect_field_names(item, depth + 1, max_depth, acc)
    return acc


def find_candidate_ids_in_json(obj, id_key_candidates=("candidate_id", "id", "candidate", "name"), depth=0, max_depth=6, found=None):
    if found is None:
        found = set()
    if depth > max_depth:
        return found
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in id_key_candidates and isinstance(v, (str, int)):
                found.add(str(v))
            find_candidate_ids_in_json(v, id_key_candidates, depth + 1, max_depth, found)
    elif isinstance(obj, list):
        for item in obj:
            find_candidate_ids_in_json(item, id_key_candidates, depth + 1, max_depth, found)
    return found


def analyze_oracle_file(path, raw_summary_mtime=None):
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
                "Oracle file mtime is AFTER the 198-run raw summary's mtime. Not proof "
                "of derivation (mtime resets on copy/move on Windows), but worth noting."
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

    candidate_ids = find_candidate_ids_in_json(data)
    report["candidate_ids_found"] = sorted(candidate_ids)
    report["candidate_id_count"] = len(candidate_ids)

    if derived_hits:
        report["verdict"] = "LIKELY_DERIVED_DO_NOT_USE"
        report["verdict_reason"] = (
            "Found field name(s) {} that only make sense as OUTPUT of running a "
            "guardrail/predicate over a trace, not as independently-authored "
            "labels. Do not use this file as the independent_expected_policy_label "
            "source.".format(derived_hits)
        )
    elif authored_hits and not derived_hits:
        report["verdict"] = "NO_RED_FLAGS_FOUND"
        report["verdict_reason"] = (
            "Field names found ({}) are consistent with independently-authored "
            "labels, and no execution/trace-derived field names were found. This "
            "SUPPORTS (does not prove) independent authorship. Still recommend "
            "manually opening the file to confirm labels reflect POLICY INTENT, "
            "not observed behavior.".format(authored_hits)
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
            "hand-authored labels.".format(name_flags)
        )

    return report


# =============================================================================
# NEW in v1.1: safe static candidate-ID extraction from the frozen corpus
# =============================================================================

CANDIDATE_ID_REGEX = re.compile(
    r'\b('
    r'E\d{1,3}|EX\d{1,3}[A-Za-z]?|'          # E1, EX06, EX09, EX17, EX18 ...
    r'DW\d{1,3}[A-Za-z]?|'                    # DW05, DW23 ...
    r'CD\d{1,3}[A-Za-z]?|'                    # CD11 .. CD15 ...
    r'C_[A-Za-z][A-Za-z0-9_]*|'               # C3, C_recipient_drift, ...
    r'UTA[-_]?\d{1,3}[A-Za-z]?'               # UTA-family ids, if similarly named
    r')\b'
)


def extract_candidate_ids_from_corpus(corpus_path):
    """Best-effort STATIC extraction of candidate IDs from the frozen
    candidate corpus file. NEVER executes/imports/evals the file --
    reads as text, optionally parses as an AST (syntax tree only, no
    execution) if it's a .py file, plus a regex pass. Returns
    (sorted_ids_list, method_used, warning_or_None)."""
    if not corpus_path or not os.path.isfile(win_long_path(corpus_path)):
        return [], "no_corpus_file", "Corpus file not found: {}".format(corpus_path)

    with open(win_long_path(corpus_path), "r", encoding="utf-8", errors="replace") as f:
        raw_text = f.read()

    ext = os.path.splitext(corpus_path)[1].lower()
    ids_from_ast = set()
    ast_error = None

    if ext == ".py":
        try:
            tree = ast.parse(raw_text)
            for node in ast.walk(tree):
                if isinstance(node, ast.Dict):
                    for k, v in zip(node.keys, node.values):
                        if (isinstance(k, ast.Constant) and isinstance(k.value, str)
                                and k.value.lower() in ("id", "candidate_id", "name", "case_id")
                                and isinstance(v, ast.Constant) and isinstance(v.value, str)):
                            if CANDIDATE_ID_REGEX.fullmatch(v.value) or CANDIDATE_ID_REGEX.search(v.value):
                                ids_from_ast.add(v.value)
        except SyntaxError as e:
            ast_error = "AST parse failed (file may not be pure Python, or uses dynamic construction): {}".format(e)

    ids_from_regex = set(CANDIDATE_ID_REGEX.findall(raw_text))
    all_ids = sorted(ids_from_ast | ids_from_regex)
    method = "ast+regex" if ids_from_ast else "regex_only"

    warning = None
    if len(all_ids) == 0:
        warning = ("No candidate-ID-shaped strings found at all -- check "
                    "CANDIDATE_ID_REGEX matches your actual naming convention.")
    elif len(all_ids) < 66:
        warning = ("Found {} candidate IDs, but the plan states 66 candidates exist. "
                    "Some may use a naming pattern not covered by CANDIDATE_ID_REGEX -- "
                    "review the raw file directly and add missing IDs by hand.".format(len(all_ids)))
    elif len(all_ids) > 66:
        warning = ("Found {} candidate-ID-shaped strings -- MORE than the expected 66. "
                    "Likely includes false positives -- review and prune before use.".format(len(all_ids)))
    if ast_error:
        warning = (warning + " " if warning else "") + ast_error

    return all_ids, method, warning


def emit_template(out_path, known_candidate_ids=None, candidate_corpus_path=None):
    import csv
    header = [
        "candidate_id", "family", "expected_policy_label", "rationale",
        "policy_basis", "authored_by", "authored_date_utc", "reviewer", "labeling_notes",
    ]

    fallback_ids = [
        "E1", "EX06", "EX09", "EX17", "EX18",
        "DW05", "DW23", "DW06",
        "CD11", "CD12", "CD13", "CD14", "CD15",
        "C3", "C_recipient_drift", "C_body_scope_expansion", "C_explicit_unauthorized_send",
    ]

    seed_ids = known_candidate_ids
    extraction_warning = None
    extraction_method = "manual_fallback_list"

    if seed_ids is None and candidate_corpus_path:
        extracted, extraction_method, extraction_warning = extract_candidate_ids_from_corpus(candidate_corpus_path)
        seed_ids = extracted if extracted else fallback_ids
        if not extracted:
            extraction_method = "manual_fallback_list (extraction found nothing)"
    elif seed_ids is None:
        seed_ids = fallback_ids

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for cid in seed_ids:
            w.writerow([cid, "", "", "", "", "", "", "", ""])

    print("Wrote template: {}".format(os.path.abspath(out_path)))
    print("Seeded with {} candidate ID(s), via method: {}".format(len(seed_ids), extraction_method))
    if extraction_warning:
        print("WARNING: {}".format(extraction_warning))
    if extraction_method == "manual_fallback_list":
        print("NOTE: these are only the 17 candidate IDs explicitly named across your")
        print("plan documents -- NOT extracted from your actual corpus. Pass")
        print("--candidate-corpus pointing at attack_yaml_harness_v5_2_full_inline.* to")
        print("attempt automatic extraction of all 66 real IDs instead.")
    print("In all cases: manually verify the row count matches your actual 66")
    print("candidates before treating this as complete. Fill in")
    print("family/expected_policy_label/rationale by hand, BEFORE running priority_1 replay.")


def main():
    parser = argparse.ArgumentParser(description="Check provenance of candidate independent_expected_policy_labels files.")
    parser.add_argument("--oracle-file", action="append", default=[], help="Path to a candidate oracle/label JSON file. Repeatable.")
    parser.add_argument("--raw-summary", default=None, help="Path to local_validate_v5_2_full_summary.json (for timestamp comparison).")
    parser.add_argument("--output", default="oracle_provenance_report.json")
    parser.add_argument("--emit-template", action="store_true", help="Skip analysis; just write independent_expected_policy_labels_v1.csv template.")
    parser.add_argument("--template-output", default="independent_expected_policy_labels_v1.csv")
    parser.add_argument("--candidate-corpus", default=None,
                         help="Path to attack_yaml_harness_v5_2_full_inline.* -- attempts safe static extraction of real candidate IDs for --emit-template.")
    args = parser.parse_args()

    if args.emit_template:
        emit_template(args.template_output, candidate_corpus_path=args.candidate_corpus)
        return 0

    if not args.oracle_file:
        print("ERROR: pass at least one --oracle-file, or use --emit-template.")
        return 2

    raw_summary_mtime = None
    if args.raw_summary and os.path.isfile(win_long_path(args.raw_summary)):
        raw_summary_mtime = os.path.getmtime(win_long_path(args.raw_summary))

    results = [analyze_oracle_file(p, raw_summary_mtime) for p in args.oracle_file]

    output = {
        "script_version": SCRIPT_VERSION, "generated_at_utc": utc_now(),
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
        print("ERROR: one or more files could not be analyzed at all (see CANNOT_ANALYZE entries above).")
    if any_derived or any_inconclusive or any_unanalyzable:
        print("RECOMMENDATION: at least one file did not get a clean NO_RED_FLAGS_FOUND")
        print("verdict. Do NOT use it as independent_expected_policy_labels as-is.")
        print("Run:  python oracle_provenance_check.py --emit-template --candidate-corpus <path>")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
