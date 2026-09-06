#!/usr/bin/env python3
# =============================================================================
# manifest_v1_generator.py  (v1.5 -- fixes duplicate-root double-counting bug)
# AI_AGENT_SECURITY -- Phase 1, Priority 0 (BLOCKING)
#
# CHANGELOG vs v1.4
# ------------------
#   v1.5 fixes a real bug your actual run surfaced: v1.4 added
#   "authored_artifacts_root" as a NEW root key pointing at the same
#   physical folder as the existing "combi_code" root key (both = your
#   combi_analysis folder). Because independent_expected_policy_labels'
#   and output_schema_definitions' search_roots included BOTH root keys,
#   the SAME physical file got walked and indexed TWICE (once per root
#   key), producing two file_index entries with identical abs_path and
#   sha256 but different root_key. For artifacts with
#   expect_single_canonical_copy=False, this caused a false
#   FOUND_MULTIPLE_CANDIDATES_NEEDS_REVIEW verdict on a file that is, in
#   reality, the ONE and ONLY copy that exists -- confirmed against your
#   actual gaps report, which listed the exact same path twice as
#   "different candidates."
#
#   FIX: find_matches_for_artifact() now deduplicates by abs_path (first
#   match wins), so a file that happens to be reachable via more than one
#   configured root key is only ever counted once. This is a general,
#   defensive fix -- it protects against ANY future root-key overlap, not
#   just this specific combi_code/authored_artifacts_root case. Verified
#   against an isolated unit test reproducing your exact scenario before
#   this file was written.
#
# Everything else (v1.4 output_schema_definitions pattern narrowing,
# environment-epoch/redaction-policy overlay merge; v1.3 the
# FOUND_CONSISTENT_MULTIPLE_COPIES non-blocking fix; v1.2 canonical-root
# pinning; v1.1 long-path fix) is unchanged.
#
# Run command (unchanged):
#   python manifest_v1_generator.py ^
#       --environment-epoch-file environment_epoch_v1.json ^
#       --redaction-policy-file redaction_policy_v1.json
#
# NOTE ON YOUR LAST RUN'S "file not found" ENVIRONMENT_EPOCH/REDACTION
# POLICY OVERLAY ERRORS: those are NOT a bug -- they mean
# environment_epoch_v1.json / redaction_policy_v1.json were not found in
# the directory you ran the command from. Either:
#   (a) run capture_environment_epoch.py / redaction_policy_tool.py
#       define FIRST, in that same directory, so the files exist there, or
#   (b) pass the FULL PATH to wherever those files actually are, e.g.
#       --environment-epoch-file "C:\...\combi_analysis\environment_epoch_v1.json"
# =============================================================================

import os
import sys
import json
import hashlib
import fnmatch
import argparse
import datetime
import subprocess

SCRIPT_VERSION = "manifest_v1_generator_v1.5"


def _utc_now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def win_long_path(abs_path):
    if os.name != "nt":
        return abs_path
    if abs_path.startswith("\\\\?\\"):
        return abs_path
    if abs_path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + abs_path.lstrip("\\")
    return "\\\\?\\" + abs_path


# =============================================================================
# CONFIG SECTION
# =============================================================================

ROOTS = {
    "exfil_code": r"C:\Users\gkonduru\OneDrive - Forescout Technologies, Inc\F_drive\forescout\Learning\Kaggle\ai-agent-security-multi-step-tool-attacks-Jun11-Sep1\ai-agent-security-multi-step-tool-attacks\Exfil",
    "cd_code":    r"C:\Users\gkonduru\OneDrive - Forescout Technologies, Inc\F_drive\forescout\Learning\Kaggle\ai-agent-security-multi-step-tool-attacks-Jun11-Sep1\ai-agent-security-multi-step-tool-attacks\CD",
    "uta_code":   r"C:\Users\gkonduru\OneDrive - Forescout Technologies, Inc\F_drive\forescout\Learning\Kaggle\ai-agent-security-multi-step-tool-attacks-Jun11-Sep1\ai-agent-security-multi-step-tool-attacks\UTA",
    "dw_code":    r"C:\Users\gkonduru\OneDrive - Forescout Technologies, Inc\F_drive\forescout\Learning\Kaggle\ai-agent-security-multi-step-tool-attacks-Jun11-Sep1\ai-agent-security-multi-step-tool-attacks\DW",
    "exfil_logs": r"C:\x_ai_logs\Exfil",
    "cd_logs":    r"C:\x_ai_logs\CD",
    "dw_logs":    r"C:\x_ai_logs\DW",
    "uta_logs":   r"C:\x_ai_logs\UTA",
    "combi_code": r"C:\Users\gkonduru\OneDrive - Forescout Technologies, Inc\F_drive\forescout\Learning\Kaggle\ai-agent-security-multi-step-tool-attacks-Jun11-Sep1\ai-agent-security-multi-step-tool-attacks\combi_analysis",
    "combi_logs": r"C:\x_ai_logs\Combi_analysis",
    "sdk_official_root": r"C:\Users\gkonduru\OneDrive - Forescout Technologies, Inc\F_drive\forescout\Learning\Kaggle\ai-agent-security-multi-step-tool-attacks-Jun11-Sep1\ai-agent-security-multi-step-tool-attacks\aicomp_sdk",
    "exfil_v2_1_root":   r"C:\Users\gkonduru\OneDrive - Forescout Technologies, Inc\F_drive\forescout\Learning\Kaggle\ai-agent-security-multi-step-tool-attacks-Jun11-Sep1\ai-agent-security-multi-step-tool-attacks\aicomp_sdk_exfil_v2_1",
    # NOTE: authored_artifacts_root REMOVED in v1.5 -- it was physically
    # identical to combi_code, causing the double-counting bug above.
    # combi_code is already searched for the authored artifacts; no
    # separate root key is needed. If you ever move these authored files
    # to a genuinely DIFFERENT folder, add a new root key here (with a
    # path that is NOT identical to any existing root) and reference it
    # in the relevant artifacts' search_roots below.
}

EXCLUDE_DIR_NAMES = {
    ".git", "__pycache__", ".ipynb_checkpoints", "node_modules",
    "venv", ".venv", "env_venv", "dist", "build", ".mypy_cache", ".pytest_cache",
}
EXCLUDE_EXTENSIONS = {".pyc", ".pyo", ".DS_Store"}

ALL_CODE_ROOTS = ["exfil_code", "cd_code", "uta_code", "dw_code", "combi_code", "sdk_official_root", "exfil_v2_1_root"]
ALL_ROOTS = list(ROOTS.keys())

EXPECTED_ARTIFACTS = [
    {"id": "guardrail_proposal_aware_optimal", "role": "specialized_guardrail_source (packaged-family variant)",
     "category": "specialized_guardrails", "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ALL_CODE_ROOTS, "name_patterns": ["proposal_aware_optimal.py"], "path_hint_contains": None,
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": ["proposal_aware", "optimal"],
     "canonical_root_keys": ["sdk_official_root"]},
    {"id": "guardrail_lineage_aware_exfil_v2_1", "role": "specialized_guardrail_source (EXFILTRATION family)",
     "category": "specialized_guardrails", "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ["exfil_code", "combi_code", "exfil_v2_1_root"],
     "name_patterns": ["lineage_aware_exfil_guardrail_v2_1.py", "lineage_aware_exfil_guardrail_v2_1"],
     "path_hint_contains": None, "required": True, "expect_single_canonical_copy": True,
     "fuzzy_keywords": ["lineage", "exfil_guardrail"], "canonical_root_keys": ["exfil_v2_1_root"]},
    {"id": "guardrail_dw_authorization_boundary_v4_30", "role": "specialized_guardrail_source (DESTRUCTIVE_WRITE family)",
     "category": "specialized_guardrails", "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ["dw_code", "combi_code"],
     "name_patterns": ["dw_authorization_boundary_v4_30.py", "dw_authorization_boundary_v4_30"],
     "path_hint_contains": None, "required": True, "expect_single_canonical_copy": True,
     "fuzzy_keywords": ["authorization_boundary"], "canonical_root_keys": None},
    {"id": "guardrail_structured_confused_deputy_v1_1", "role": "specialized_guardrail_source (CONFUSED_DEPUTY family)",
     "category": "specialized_guardrails", "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ["cd_code", "combi_code"],
     "name_patterns": ["structured_confused_deputy_guardrail_v1_1.py", "structured_confused_deputy_guardrail_v1_1"],
     "path_hint_contains": None, "required": True, "expect_single_canonical_copy": True,
     "fuzzy_keywords": ["confused_deputy"], "canonical_root_keys": None},
    {"id": "guardrail_optimal_plus_v7_71a", "role": "specialized_guardrail_source (UNTRUSTED_TO_ACTION family)",
     "category": "specialized_guardrails", "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ["uta_code", "combi_code"],
     "name_patterns": ["optimal_plus_v7_71a.py", "optimal_plus_v7_71a"],
     "path_hint_contains": None, "required": True, "expect_single_canonical_copy": True,
     "fuzzy_keywords": ["optimal_plus"], "canonical_root_keys": None},
    {"id": "baseline_guardrail_optimal", "role": "packaged_baseline_guardrail (byte-for-byte, unchanged -- do not touch)",
     "category": "baseline_guardrail", "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ALL_ROOTS, "name_patterns": ["optimal.py"], "path_hint_contains": None,
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": ["aicomp_sdk", "packaged"],
     "canonical_root_keys": ["sdk_official_root"]},
    {"id": "official_predicates", "role": "official_scorer (predicates.py / eval_predicates / is_breach -- unmodified)",
     "category": "official_scorer", "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ALL_ROOTS, "name_patterns": ["predicates.py"], "path_hint_contains": None,
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": ["predicate", "is_breach", "aicomp_sdk"],
     "canonical_root_keys": ["sdk_official_root"]},
    {"id": "sdk_env_sandbox", "role": "sdk_core", "category": "sdk_core",
     "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
     "search_roots": ALL_ROOTS, "name_patterns": ["sandbox.py"], "path_hint_contains": ["env"],
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": ["sandbox", "aicomp_sdk"],
     "canonical_root_keys": ["sdk_official_root"]},
    {"id": "sdk_env_api", "role": "sdk_core", "category": "sdk_core",
     "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
     "search_roots": ALL_ROOTS, "name_patterns": ["api.py"], "path_hint_contains": ["env"],
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": ["aicomp_sdk"],
     "canonical_root_keys": ["sdk_official_root"]},
    {"id": "sdk_env_gym", "role": "sdk_core", "category": "sdk_core",
     "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
     "search_roots": ALL_ROOTS, "name_patterns": ["gym.py"], "path_hint_contains": ["env"],
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": ["gym", "aicomp_sdk"],
     "canonical_root_keys": ["sdk_official_root"]},
    {"id": "sdk_guardrails_base", "role": "sdk_core", "category": "sdk_core",
     "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
     "search_roots": ALL_ROOTS, "name_patterns": ["base.py"], "path_hint_contains": ["guardrails"],
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": ["aicomp_sdk"],
     "canonical_root_keys": ["sdk_official_root"]},
    {"id": "sdk_attacks_baselines_guardrail_rules", "role": "sdk_core", "category": "sdk_core",
     "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
     "search_roots": ALL_ROOTS, "name_patterns": ["guardrail_rules.py"], "path_hint_contains": ["attacks", "baselines"],
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": ["guardrail_rules", "aicomp_sdk"],
     "canonical_root_keys": ["sdk_official_root"]},
    {"id": "sdk_cli_commands_test", "role": "sdk_core", "category": "sdk_core",
     "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
     "search_roots": ALL_ROOTS, "name_patterns": ["test.py"], "path_hint_contains": ["cli", "commands"],
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": ["aicomp_sdk"],
     "canonical_root_keys": ["sdk_official_root"]},
    {"id": "candidate_corpus_v5_2_full_inline", "role": "frozen_candidate_corpus (66 candidates, attack_yaml_harness_v5_2_full_inline)",
     "category": "candidate_corpus", "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ALL_CODE_ROOTS,
     "name_patterns": ["attack_yaml_harness_v5_2_full_inline.py", "attack_yaml_harness_v5_2_full_inline.yaml",
                        "attack_yaml_harness_v5_2_full_inline.yml", "attack_yaml_harness_v5_2_full_inline.json"],
     "path_hint_contains": None, "required": True, "expect_single_canonical_copy": True,
     "fuzzy_keywords": None, "canonical_root_keys": None},
    {"id": "raw_198run_summary", "role": "raw_output (198-run local_validate_v5_2_full_summary.json -- already collected, do not rerun)",
     "category": "raw_results", "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ALL_ROOTS, "name_patterns": ["local_validate_v5_2_full_summary.json"], "path_hint_contains": None,
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": None, "canonical_root_keys": None},
    {"id": "fixture_api_keys", "role": "real_fixture (byte-verified unchanged)", "category": "fixtures",
     "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ALL_ROOTS, "name_patterns": ["api_keys.txt"], "path_hint_contains": None,
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": None,
     "canonical_root_keys": ["sdk_official_root"]},
    {"id": "fixture_note", "role": "real_fixture (byte-verified unchanged)", "category": "fixtures",
     "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ALL_ROOTS, "name_patterns": ["note.txt"], "path_hint_contains": None,
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": None,
     "canonical_root_keys": ["sdk_official_root"]},
    {"id": "fixture_readme", "role": "real_fixture (byte-verified unchanged)", "category": "fixtures",
     "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ALL_ROOTS, "name_patterns": ["readme.txt"], "path_hint_contains": None,
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": None,
     "canonical_root_keys": ["sdk_official_root"]},
    {"id": "fixture_report", "role": "real_fixture (byte-verified unchanged)", "category": "fixtures",
     "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ALL_ROOTS, "name_patterns": ["report.txt"], "path_hint_contains": None,
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": None,
     "canonical_root_keys": ["sdk_official_root"]},
    {"id": "fixture_temp", "role": "real_fixture (byte-verified unchanged)", "category": "fixtures",
     "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ALL_ROOTS, "name_patterns": ["temp.txt"], "path_hint_contains": None,
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": None,
     "canonical_root_keys": ["sdk_official_root"]},
    {"id": "fixture_writable", "role": "real_fixture (byte-verified unchanged)", "category": "fixtures",
     "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ALL_ROOTS, "name_patterns": ["writable.txt"], "path_hint_contains": None,
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": None,
     "canonical_root_keys": ["sdk_official_root"]},
    {"id": "fixture_writable2", "role": "real_fixture (byte-verified unchanged)", "category": "fixtures",
     "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ALL_ROOTS, "name_patterns": ["writable2.txt"], "path_hint_contains": None,
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": None,
     "canonical_root_keys": ["sdk_official_root"]},
    {"id": "fixture_mail_seed", "role": "real_fixture (byte-verified unchanged)", "category": "fixtures",
     "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ALL_ROOTS, "name_patterns": ["mail_seed.json"], "path_hint_contains": None,
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": None,
     "canonical_root_keys": ["sdk_official_root"]},
    {"id": "fixture_web_corpus", "role": "real_fixture (byte-verified unchanged)", "category": "fixtures",
     "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ALL_ROOTS, "name_patterns": ["web_corpus.json"], "path_hint_contains": None,
     "required": True, "expect_single_canonical_copy": True, "fuzzy_keywords": None,
     "canonical_root_keys": ["sdk_official_root"]},
    # FIXED in v1.5: search_roots no longer includes the now-removed
    # "authored_artifacts_root" duplicate -- combi_code alone is correct
    # and sufficient (it was always in ALL_ROOTS).
    {"id": "independent_expected_policy_labels",
     "role": "independent_expected_policy_label (per-candidate oracle labels, authored BEFORE replay -- NOT derived from replay output)",
     "category": "policy_oracle", "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
     "search_roots": ALL_ROOTS,
     "name_patterns": ["expected_policy_labels*.csv", "expected_policy_labels*.json", "policy_oracle*.csv",
                        "policy_oracle*.json", "independent_expected_policy*.csv", "independent_expected_policy*.json"],
     "path_hint_contains": None, "required": True, "expect_single_canonical_copy": False,
     "fuzzy_keywords": ["policy_label", "expected_policy", "oracle"], "canonical_root_keys": None},
    {"id": "output_schema_definitions", "role": "output_schema_definitions (for every result table produced in priority_1-6)",
     "category": "schema", "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
     "search_roots": ALL_ROOTS,
     "name_patterns": ["output_schema_definitions_v1.yaml", "output_schema_definitions_v1.yml",
                        "output_schema_definitions_v1.json", "output_schema_definitions*.yaml",
                        "output_schema_definitions*.yml", "output_schema_definitions*.json"],
     "path_hint_contains": None, "required": True, "expect_single_canonical_copy": False,
     "fuzzy_keywords": None, "canonical_root_keys": None},
]

ENVIRONMENT_EPOCH_DEFAULT = {
    "sdk_or_evaluator_commit_hash": "REQUIRES_MANUAL_ENTRY", "model": "REQUIRES_MANUAL_ENTRY",
    "adapter": "REQUIRES_MANUAL_ENTRY", "tokenizer": "REQUIRES_MANUAL_ENTRY",
    "sampling_temperature": "REQUIRES_MANUAL_ENTRY", "sampling_max_tokens": "REQUIRES_MANUAL_ENTRY",
    "guardrail_composition_used_in_198_run_batch": "REQUIRES_MANUAL_ENTRY",
    "notes": ("Fill in every REQUIRES_MANUAL_ENTRY field above before this manifest "
              "is cited by phase_2_publication. Use capture_environment_epoch.py to "
              "generate an overlay file, then pass --environment-epoch-file."),
}
REDACTION_POLICY_P6B_DEFAULT = {
    "policy_defined": False, "policy_text": "REQUIRES_MANUAL_ENTRY",
    "notes": ("Per phase_1_write.priority_0 additional_requirements: publish a redaction "
              "policy for the single real-runtime EXFILTRATION divergence sample BEFORE "
              "it appears in a publication draft. Use redaction_policy_tool.py define, "
              "then pass --redaction-policy-file."),
}

# =============================================================================
# CORE LOGIC
# =============================================================================

def sha256_of_file(path, chunk_size=1024 * 1024):
    with open(win_long_path(path), "rb") as f:
        h = hashlib.sha256()
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def should_skip_dir(dirname):
    return dirname in EXCLUDE_DIR_NAMES


def should_skip_file(filename):
    _, ext = os.path.splitext(filename)
    return ext in EXCLUDE_EXTENSIONS


def walk_root(root_key, root_path, max_file_mb, errors):
    results = []
    if not os.path.isdir(win_long_path(root_path)):
        errors.append({"root_key": root_key, "root_path": root_path, "error": "ROOT_NOT_FOUND_OR_NOT_A_DIRECTORY"})
        return results
    max_bytes = max_file_mb * 1024 * 1024
    for dirpath, dirnames, filenames in os.walk(win_long_path(root_path)):
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d)]
        for fname in filenames:
            if should_skip_file(fname):
                continue
            abs_path = os.path.join(dirpath, fname)
            display_path = abs_path[4:] if abs_path.startswith("\\\\?\\") and os.name == "nt" else abs_path
            try:
                size = os.path.getsize(abs_path)
            except OSError as e:
                errors.append({"root_key": root_key, "path": display_path, "error": str(e)})
                continue
            rel_path = os.path.relpath(display_path, root_path)
            entry = {"root_key": root_key, "root_path": root_path, "abs_path": display_path,
                      "rel_path": rel_path.replace("\\", "/"), "filename": fname, "size_bytes": size}
            if size > max_bytes:
                entry["sha256"] = None
                entry["skipped_large_file"] = True
            else:
                try:
                    entry["sha256"] = sha256_of_file(display_path)
                    entry["skipped_large_file"] = False
                except (OSError, PermissionError) as e:
                    errors.append({"root_key": root_key, "path": display_path, "error": str(e)})
                    continue
            try:
                mtime = os.path.getmtime(abs_path)
                entry["mtime_utc"] = datetime.datetime.fromtimestamp(mtime, tz=datetime.timezone.utc).isoformat()
            except OSError:
                entry["mtime_utc"] = None
            results.append(entry)
    return results


def path_matches_hints(rel_path_lower, hints):
    if not hints:
        return True
    parts = rel_path_lower.replace("\\", "/").split("/")
    return all(any(h.lower() in p for p in parts) for h in hints)


def find_matches_for_artifact(artifact, file_index):
    """
    FIXED in v1.5: deduplicates by abs_path. If two configured root keys
    happen to point at the same (or overlapping) physical location, the
    same real file would otherwise be indexed once per root key and
    counted as multiple "candidates" -- this collapses those back down
    to one match per real file on disk.
    """
    search_roots = artifact.get("search_roots") or list(ROOTS.keys())
    patterns = [p.lower() for p in artifact["name_patterns"]]
    hints = artifact.get("path_hint_contains")
    matches = []
    seen_abs_paths = set()
    for entry in file_index:
        if entry["root_key"] not in search_roots:
            continue
        fname_lower = entry["filename"].lower()
        if not any(fnmatch.fnmatch(fname_lower, pat) for pat in patterns):
            continue
        if not path_matches_hints(entry["rel_path"].lower(), hints):
            continue
        if entry["abs_path"] in seen_abs_paths:
            continue
        seen_abs_paths.add(entry["abs_path"])
        matches.append(entry)
    return matches


def find_fuzzy_suggestions(artifact, file_index, max_suggestions=25):
    keywords = artifact.get("fuzzy_keywords")
    if not keywords:
        return []
    search_roots = artifact.get("search_roots") or list(ROOTS.keys())
    hits, seen = [], set()
    for entry in file_index:
        if entry["root_key"] not in search_roots:
            continue
        haystack = (entry["rel_path"] + " " + entry["filename"]).lower()
        if any(kw.lower() in haystack for kw in keywords):
            if entry["abs_path"] not in seen:
                seen.add(entry["abs_path"])
                hits.append({"path": entry["abs_path"], "sha256": entry["sha256"]})
    return hits[:max_suggestions]


def classify_artifact_status_legacy(artifact, matches):
    if not matches:
        return "MISSING"
    hashes = set(m["sha256"] for m in matches if m["sha256"] is not None)
    if any(m["sha256"] is None for m in matches):
        return "FOUND_BUT_TOO_LARGE_TO_HASH"
    if artifact.get("expect_single_canonical_copy", False):
        if len(hashes) == 1:
            return "FOUND_CONSISTENT" if len(matches) == 1 else "FOUND_CONSISTENT_MULTIPLE_COPIES"
        else:
            return "FOUND_DIVERGENT_COPIES"
    else:
        return "FOUND_CONSISTENT" if len(matches) == 1 else "FOUND_MULTIPLE_CANDIDATES_NEEDS_REVIEW"


def resolve_artifact(artifact, matches):
    canonical_keys = artifact.get("canonical_root_keys")
    if canonical_keys:
        canonical_matches = [m for m in matches if m["root_key"] in canonical_keys]
        if canonical_matches:
            canonical_hashes = set(m["sha256"] for m in canonical_matches if m["sha256"] is not None)
            if len(canonical_hashes) > 1:
                return ("CANONICAL_ROOT_ITSELF_DIVERGENT", None, [], canonical_matches)
            canonical = canonical_matches[0]
            others = [m for m in matches if m["abs_path"] != canonical["abs_path"]]
            consistent = [m for m in others if m["sha256"] == canonical["sha256"]]
            divergent = [m for m in others if m["sha256"] != canonical["sha256"]]
            return ("CANONICAL_CONFIRMED", canonical, consistent, divergent)
    status = classify_artifact_status_legacy(artifact, matches)
    canonical = matches[0] if matches else None
    others = matches[1:] if len(matches) > 1 else []
    if status in ("FOUND_CONSISTENT", "FOUND_CONSISTENT_MULTIPLE_COPIES"):
        return (status, canonical, others, [])
    elif status == "FOUND_DIVERGENT_COPIES":
        return (status, canonical, [], others)
    else:
        return (status, canonical, [], [])


def load_overlay_file(path, label):
    if not path:
        return None, None
    if not os.path.isfile(win_long_path(path)):
        return None, "{} file not found: {}".format(label, path)
    try:
        with open(win_long_path(path), "r", encoding="utf-8") as f:
            return json.load(f), None
    except json.JSONDecodeError as e:
        return None, "{} file is not valid JSON: {}".format(label, e)


def merge_environment_epoch(overlay):
    merged = dict(ENVIRONMENT_EPOCH_DEFAULT)
    if not overlay:
        return merged, []
    filled = []
    for key in ("sdk_or_evaluator_commit_hash", "model", "adapter", "tokenizer",
                "sampling_temperature", "sampling_max_tokens",
                "guardrail_composition_used_in_198_run_batch"):
        val = overlay.get(key)
        if val is not None and val != "REQUIRES_MANUAL_ENTRY":
            merged[key] = val
            filled.append(key)
    if "captured_at_utc" in overlay:
        merged["overlay_captured_at_utc"] = overlay["captured_at_utc"]
    return merged, filled


def merge_redaction_policy(overlay):
    merged = dict(REDACTION_POLICY_P6B_DEFAULT)
    if not overlay:
        return merged, False
    if overlay.get("policy_defined"):
        merged["policy_defined"] = True
        merged["method"] = overlay.get("method")
        merged["placeholder_token"] = overlay.get("placeholder_token")
        merged["policy_text"] = overlay.get("policy_text")
        merged["policy_text_looks_like_placeholder"] = overlay.get("policy_text_looks_like_placeholder", False)
        merged["defined_at_utc"] = overlay.get("defined_at_utc")
        return merged, True
    return merged, False


def build_manifest(args):
    scan_errors = []
    file_index = []
    root_scan_status = {}

    for root_key, root_path in ROOTS.items():
        entries = walk_root(root_key, root_path, args.max_file_mb, scan_errors)
        root_scan_status[root_key] = {"root_path": root_path, "exists": os.path.isdir(win_long_path(root_path)),
                                        "files_scanned": len(entries)}
        file_index.extend(entries)

    # Defensive check: warn (in the manifest itself) if any two configured
    # roots physically overlap -- this is exactly the class of bug that
    # caused the v1.4 double-count. Surfaced explicitly so it's never
    # silently reintroduced by a future edit to ROOTS.
    overlapping_roots = []
    seen_paths = {}
    for k, v in ROOTS.items():
        norm = os.path.normcase(os.path.normpath(v))
        if norm in seen_paths:
            overlapping_roots.append((seen_paths[norm], k, v))
        else:
            seen_paths[norm] = k

    env_overlay, env_err = load_overlay_file(args.environment_epoch_file, "environment-epoch")
    redaction_overlay, redaction_err = load_overlay_file(args.redaction_policy_file, "redaction-policy")
    environment_epoch, env_filled_fields = merge_environment_epoch(env_overlay)
    redaction_policy, redaction_applied = merge_redaction_policy(redaction_overlay)

    artifacts_out = []
    gaps = []
    fuzzy_suggestions_out = {}
    matched_abs_paths = set()

    NON_BLOCKING_STATUSES = ("CANONICAL_CONFIRMED", "FOUND_CONSISTENT", "FOUND_CONSISTENT_MULTIPLE_COPIES")

    for artifact in EXPECTED_ARTIFACTS:
        matches = find_matches_for_artifact(artifact, file_index)
        status, canonical, hist_consistent, hist_divergent = resolve_artifact(artifact, matches)

        record = {"id": artifact["id"], "role": artifact["role"], "category": artifact["category"],
                   "first_used_in": artifact["first_used_in"], "required": artifact["required"], "status": status}

        if canonical is not None:
            record["path"] = canonical["abs_path"]
            record["sha256"] = canonical["sha256"]
            record["size_bytes"] = canonical["size_bytes"]
            record["mtime_utc"] = canonical["mtime_utc"]
        else:
            record["path"] = None
            record["sha256"] = None

        if hist_consistent:
            record["historical_variants_consistent"] = [{"path": m["abs_path"], "sha256": m["sha256"]} for m in hist_consistent]
        if hist_divergent:
            record["historical_variants_diverge_from_canonical"] = [{"path": m["abs_path"], "sha256": m["sha256"]} for m in hist_divergent]

        for m in matches:
            matched_abs_paths.add(m["abs_path"])

        artifacts_out.append(record)

        is_blocking_gap = artifact["required"] and status not in NON_BLOCKING_STATUSES
        if is_blocking_gap:
            gap_entry = {
                "id": artifact["id"], "role": artifact["role"], "status": status, "required": artifact["required"],
                "reason": {
                    "MISSING": "No file matching the configured name pattern(s) was found under the configured search roots.",
                    "FOUND_DIVERGENT_COPIES": "Multiple copies found with DIFFERENT sha256 hashes -- a human must pick the canonical copy; this script will not guess.",
                    "FOUND_BUT_TOO_LARGE_TO_HASH": "A matching file was found but exceeded --max-file-mb; rerun with a higher limit or hash it manually.",
                    "FOUND_MULTIPLE_CANDIDATES_NEEDS_REVIEW": "Multiple distinct candidate files found for an artifact that was not expected to have multiple canonical copies -- review and either consolidate or narrow name_patterns.",
                    "CANONICAL_ROOT_ITSELF_DIVERGENT": "CRITICAL: multiple files inside the designated canonical root itself disagree on hash.",
                }.get(status, "See status."),
                "candidates": [m["abs_path"] for m in matches] if matches else [],
            }
            gaps.append(gap_entry)
            if args.suggest_fuzzy_matches and status == "MISSING":
                suggestions = find_fuzzy_suggestions(artifact, file_index)
                if suggestions:
                    fuzzy_suggestions_out[artifact["id"]] = suggestions

    unclassified_count = sum(1 for e in file_index if e["abs_path"] not in matched_abs_paths)

    manifest = {
        "manifest_version": "v1", "generator_script_version": SCRIPT_VERSION, "generated_at_utc": _utc_now_iso(),
        "generator_script_sha256": sha256_of_file(os.path.abspath(__file__)),
        "roots_scanned": root_scan_status,
        "overlapping_roots_detected": [
            {"root_key_a": a, "root_key_b": b, "shared_path": p} for a, b, p in overlapping_roots
        ],
        "environment_epoch": environment_epoch,
        "environment_epoch_overlay_status": {
            "overlay_file": args.environment_epoch_file,
            "overlay_load_error": env_err,
            "fields_filled_from_overlay": env_filled_fields,
        },
        "redaction_policy_p6b_secret": redaction_policy,
        "redaction_policy_overlay_status": {
            "overlay_file": args.redaction_policy_file,
            "overlay_load_error": redaction_err,
            "policy_applied_from_overlay": redaction_applied,
        },
        "artifacts": artifacts_out,
        "gaps": gaps, "gaps_count": len(gaps),
        "scan_summary": {"total_files_scanned_across_all_roots": len(file_index),
                          "matched_to_an_expected_artifact": len(matched_abs_paths),
                          "unclassified_files_not_in_scope": unclassified_count, "scan_errors": scan_errors},
    }
    return manifest, file_index, fuzzy_suggestions_out


def write_gaps_report(manifest, out_path, fuzzy_suggestions=None):
    lines = ["=" * 78, "MANIFEST_V1 GAPS REPORT -- Phase 1, Priority 0",
             "Generated: {}".format(manifest["generated_at_utc"]),
             "Generator: {}".format(manifest["generator_script_version"]), "=" * 78, ""]

    if manifest.get("overlapping_roots_detected"):
        lines.append("WARNING: configured ROOTS contain overlapping/duplicate physical paths:")
        for o in manifest["overlapping_roots_detected"]:
            lines.append("  '{}' and '{}' both point to: {}".format(o["root_key_a"], o["root_key_b"], o["shared_path"]))
        lines.append("  This can cause false FOUND_MULTIPLE_CANDIDATES results -- the dedup fix")
        lines.append("  in this version compensates automatically, but consider removing the")
        lines.append("  redundant root_key from ROOTS if it serves no distinct purpose.")
        lines.append("")

    confirmed = [a for a in manifest["artifacts"] if a["status"] == "CANONICAL_CONFIRMED"]
    if confirmed:
        lines.append("{} artifact(s) resolved via canonical-root pinning this run:".format(len(confirmed)))
        for a in confirmed:
            lines.append("  [OK] {} -> {}".format(a["id"], a["path"]))
            if "historical_variants_diverge_from_canonical" in a:
                lines.append("       ({} older/other copy(ies) found elsewhere that DIFFER from canonical -- kept for evidence trail)".format(
                    len(a["historical_variants_diverge_from_canonical"])))
        lines.append("")

    non_blocking_dupes = [a for a in manifest["artifacts"] if a["status"] == "FOUND_CONSISTENT_MULTIPLE_COPIES"]
    if non_blocking_dupes:
        lines.append("{} artifact(s) found as byte-identical duplicate copies (non-blocking):".format(len(non_blocking_dupes)))
        for a in non_blocking_dupes:
            lines.append("  [OK] {} -> {} (+{} identical copy/copies elsewhere)".format(
                a["id"], a["path"], len(a.get("historical_variants_consistent", []))))
        lines.append("")

    found_consistent = [a for a in manifest["artifacts"] if a["status"] == "FOUND_CONSISTENT"]
    if found_consistent:
        lines.append("{} artifact(s) found, single consistent copy (non-blocking):".format(len(found_consistent)))
        for a in found_consistent:
            lines.append("  [OK] {} -> {}".format(a["id"], a["path"]))
        lines.append("")

    if not manifest["gaps"]:
        lines.append("NO BLOCKING GAPS. All required artifacts found and consistent.")
        lines.append("Priority 0 manifest is complete -- Priority 1 may proceed once")
        lines.append("ENVIRONMENT_EPOCH and REDACTION_POLICY_P6B fields are also filled in.")
    else:
        lines.append("{} BLOCKING GAP(S) -- Priority 1 must NOT start until these are".format(len(manifest["gaps"])))
        lines.append("resolved (found, reconciled, or explicitly re-scoped).")
        lines.append("")
        for g in manifest["gaps"]:
            lines.append("- [{}] {}".format(g["status"], g["id"]))
            lines.append("    role:   {}".format(g["role"]))
            lines.append("    reason: {}".format(g["reason"]))
            if g["candidates"]:
                lines.append("    candidate paths found:")
                for c in g["candidates"]:
                    lines.append("      * {}".format(c))
            if fuzzy_suggestions and g["id"] in fuzzy_suggestions:
                lines.append("    FUZZY SUGGESTIONS (unverified -- human review required):")
                for s in fuzzy_suggestions[g["id"]]:
                    lines.append("      ? {}  [sha256={}]".format(s["path"], s["sha256"]))
            lines.append("")

    env_status = manifest["environment_epoch_overlay_status"]
    env_manual = [k for k, v in manifest["environment_epoch"].items()
                  if v == "REQUIRES_MANUAL_ENTRY"]
    lines.append("-" * 78)
    if env_status["overlay_file"]:
        if env_status["overlay_load_error"]:
            lines.append("ENVIRONMENT_EPOCH overlay file error: {}".format(env_status["overlay_load_error"]))
            lines.append("  -> This means the file was not found AT THE PATH GIVEN. If you already")
            lines.append("     ran capture_environment_epoch.py, either rerun this command from the")
            lines.append("     SAME directory that file was written to, or pass its FULL PATH via")
            lines.append("     --environment-epoch-file.")
        else:
            lines.append("ENVIRONMENT_EPOCH overlay loaded from: {}".format(env_status["overlay_file"]))
            lines.append("  Fields filled from overlay: {}".format(env_status["fields_filled_from_overlay"]))
    if env_manual:
        lines.append("ENVIRONMENT_EPOCH fields still needing manual entry:")
        for k in env_manual:
            lines.append("  - {}".format(k))
    else:
        lines.append("ENVIRONMENT_EPOCH: all fields filled.")

    redaction_status = manifest["redaction_policy_overlay_status"]
    lines.append("-" * 78)
    if redaction_status["overlay_file"]:
        if redaction_status["overlay_load_error"]:
            lines.append("REDACTION POLICY overlay file error: {}".format(redaction_status["overlay_load_error"]))
            lines.append("  -> Same cause as above: file not found at the given path. Rerun from the")
            lines.append("     directory redaction_policy_tool.py define wrote it to, or pass the full path.")
        elif redaction_status["policy_applied_from_overlay"]:
            lines.append("REDACTION POLICY loaded from overlay: {}".format(redaction_status["overlay_file"]))
    if not manifest["redaction_policy_p6b_secret"]["policy_defined"]:
        lines.append("REDACTION POLICY for the P6b real secret value is NOT YET DEFINED.")
    else:
        lines.append("REDACTION POLICY: defined (method={}).".format(manifest["redaction_policy_p6b_secret"].get("method")))
        if manifest["redaction_policy_p6b_secret"].get("policy_text_looks_like_placeholder"):
            lines.append("  WARNING: policy_text still looks like a placeholder -- see redaction_policy_tool.py output.")

    if manifest["scan_summary"]["scan_errors"]:
        lines.append("-" * 78)
        lines.append("SCAN ERRORS:")
        for e in manifest["scan_summary"]["scan_errors"]:
            lines.append("  - {}".format(e))

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate manifest_v1.sha256.json (Phase 1, Priority 0).")
    parser.add_argument("--output", default="manifest_v1.sha256.json")
    parser.add_argument("--gaps-report", default="manifest_v1_gaps_report.txt")
    parser.add_argument("--emit-full-inventory", action="store_true")
    parser.add_argument("--full-inventory-output", default="full_file_inventory_v1.sha256.json")
    parser.add_argument("--list-roots", action="store_true")
    parser.add_argument("--max-file-mb", type=int, default=200)
    parser.add_argument("--suggest-fuzzy-matches", action="store_true")
    parser.add_argument("--fuzzy-suggestions-output", default="manifest_v1_fuzzy_suggestions.json")
    parser.add_argument("--environment-epoch-file", default=None)
    parser.add_argument("--redaction-policy-file", default=None)
    args = parser.parse_args()

    if args.list_roots:
        for k, v in ROOTS.items():
            exists = os.path.isdir(win_long_path(v))
            print("[{}] {} -> {}".format("OK " if exists else "MISSING", k, v))
        return 0

    manifest, file_index, fuzzy_suggestions = build_manifest(args)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    report_text = write_gaps_report(manifest, args.gaps_report, fuzzy_suggestions)

    if args.emit_full_inventory:
        full_inv = {"generated_at_utc": manifest["generated_at_utc"], "note": "Full audit-trail scan.", "files": file_index}
        with open(args.full_inventory_output, "w", encoding="utf-8") as f:
            json.dump(full_inv, f, indent=2)

    if args.suggest_fuzzy_matches and fuzzy_suggestions:
        with open(args.fuzzy_suggestions_output, "w", encoding="utf-8") as f:
            json.dump({"note": "ADVISORY ONLY.", "generated_at_utc": manifest["generated_at_utc"],
                       "suggestions": fuzzy_suggestions}, f, indent=2)
        print("Wrote: {}".format(os.path.abspath(args.fuzzy_suggestions_output)))

    print(report_text)
    print()
    print("Wrote: {}".format(os.path.abspath(args.output)))
    print("Wrote: {}".format(os.path.abspath(args.gaps_report)))
    if args.emit_full_inventory:
        print("Wrote: {}".format(os.path.abspath(args.full_inventory_output)))

    return 1 if manifest["gaps_count"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
