#!/usr/bin/env python3
# =============================================================================
# manifest_v1_generator.py  (v1.1 -- long-path fix + fuzzy-match diagnostics)
# AI_AGENT_SECURITY -- Phase 1, Priority 0 (BLOCKING)
#
# CHANGELOG vs v1.0
# ------------------
#   v1.1: Two independent fixes, based on your two real runs' evidence:
#     1. LONG-PATH FIX (real bug): one file
#        ("...Exfil\ex5_6_gpt_oss_reasoning_channel_output_completion_
#        preflight_v5_60.py") is exactly 260 characters -- the Windows
#        MAX_PATH limit -- and failed with WinError 3 in BOTH your runs.
#        This was NOT a folder-name typo (EXfil vs Exfil never mattered;
#        both runs scanned exactly 298 files under exfil_code either way).
#        Fixed by using the "\\?\" extended-length-path prefix on Windows
#        for every file open/getsize/getmtime call.
#     2. FUZZY-MATCH SUGGESTIONS (diagnostic only, opt-in via
#        --suggest-fuzzy-matches): your 14 gaps are NOT caused by the
#        long-path bug (only 1 file errored, and it doesn't match any
#        expected-artifact pattern anyway). They are genuine: 11 required
#        artifacts were not found anywhere across all 10 roots by their
#        exact configured name. Rather than silently loosening the name
#        patterns (which would risk mis-attaching the wrong file to a
#        "byte-for-byte unchanged" claim), this version adds an opt-in,
#        clearly-separated suggestions report: for artifacts you tag with
#        fuzzy_keywords below, it lists filenames elsewhere in the scan
#        that merely CONTAIN those keywords, for YOUR visual confirmation.
#        These suggestions are never written into manifest_v1.sha256.json
#        itself and never affect artifact "status" -- they are advisory
#        only, printed/written to a separate file.
#
# Everything else (purpose, design rules, read-only guarantee, no-silent-
# disambiguation, no-fabricated-metadata, blocking-gap behavior, no YAML
# dependency) is unchanged from v1.0. See inline comments below.
#
# Run command (Windows PowerShell):
#   python manifest_v1_generator.py
#   python manifest_v1_generator.py --suggest-fuzzy-matches   (diagnostic add-on)
#
# Other flags:
#   --output PATH, --gaps-report PATH, --emit-full-inventory,
#   --full-inventory-output PATH, --list-roots, --max-file-mb N
# =============================================================================

import os
import sys
import json
import hashlib
import fnmatch
import argparse
import datetime
import subprocess

SCRIPT_VERSION = "manifest_v1_generator_v1.1"


def _utc_now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


# =============================================================================
# LONG-PATH SUPPORT (the confirmed fix)
# -----------------------------------------------------------------------------
# Windows historically limits MAX_PATH to 260 characters for legacy Win32
# file APIs. Prefixing an absolute path with "\\?\" (or "\\?\UNC\" for UNC
# paths) tells Windows to use the newer, longer-path-capable code path.
# This is a no-op / harmless on POSIX systems (Linux/macOS have no such
# limit), so the helper below only activates on os.name == "nt".
# =============================================================================

def win_long_path(abs_path):
    if os.name != "nt":
        return abs_path
    if abs_path.startswith("\\\\?\\"):
        return abs_path  # already prefixed
    if abs_path.startswith("\\\\"):
        # UNC path: \\server\share\... -> \\?\UNC\server\share\...
        return "\\\\?\\UNC\\" + abs_path.lstrip("\\")
    return "\\\\?\\" + abs_path


# =============================================================================
# CONFIG SECTION -- edit this, not the logic below.
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
}

# NOTE: per your two runs' evidence, casing of "Exfil" vs "EXfil" made zero
# difference (298 files scanned either way -- Windows paths are case-
# insensitive). Left as "Exfil" (matches your most recent run) but this is
# NOT the fix; see win_long_path() above for the actual bug fix.

# -----------------------------------------------------------------------------
# NOTE ON THE 11th LOCATION (UNRESOLVED -- NEEDS YOUR INPUT, NOT GUESSED):
# Across all 10 roots (3,613 files scanned in your last run), these were
# NEVER found by exact name:
#   optimal.py, predicates.py, env/sandbox.py, env/api.py, env/gym.py,
#   guardrails/base.py, attacks/baselines/guardrail_rules.py,
#   cli/commands/test.py
# One schema-match hit revealed a folder named "aicomp_sdk" nested inside
# x_ai_logs\UTA\uta_fixture_preflight_v7_31_encoding_repair\project_overlay\
# -- which suggests the OFFICIAL, canonical SDK package (pip install,
# separate repo clone, or similar) lives somewhere NOT among these 10
# roots. This script cannot guess that 11th location. If you tell me
# where the canonical, unmodified SDK/package lives, add it to ROOTS above
# as e.g. "sdk_root": r"C:\path\to\it" and add "sdk_root" to the relevant
# artifacts' search_roots lists below, then rerun.
# -----------------------------------------------------------------------------

EXCLUDE_DIR_NAMES = {
    ".git", "__pycache__", ".ipynb_checkpoints", "node_modules",
    "venv", ".venv", "env_venv", "dist", "build", ".mypy_cache", ".pytest_cache",
}
EXCLUDE_EXTENSIONS = {".pyc", ".pyo", ".DS_Store"}

ALL_CODE_ROOTS = ["exfil_code", "cd_code", "uta_code", "dw_code", "combi_code"]
ALL_ROOTS = list(ROOTS.keys())

# -----------------------------------------------------------------------------
# EXPECTED_ARTIFACTS -- same scope/semantics as v1.0. New optional key:
#   fuzzy_keywords : list[str] -- ONLY used by --suggest-fuzzy-matches to
#                    surface candidate filenames for human review. NEVER
#                    used to auto-resolve the artifact's actual status.
# -----------------------------------------------------------------------------

EXPECTED_ARTIFACTS = [
    {
        "id": "guardrail_proposal_aware_optimal",
        "role": "specialized_guardrail_source (packaged-family variant)",
        "category": "specialized_guardrails",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ALL_CODE_ROOTS,
        "name_patterns": ["proposal_aware_optimal.py"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": ["proposal_aware", "optimal"],
    },
    {
        "id": "guardrail_lineage_aware_exfil_v2_1",
        "role": "specialized_guardrail_source (EXFILTRATION family)",
        "category": "specialized_guardrails",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ["exfil_code", "combi_code"],
        "name_patterns": ["lineage_aware_exfil_guardrail_v2_1.py", "lineage_aware_exfil_guardrail_v2_1"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": ["lineage", "exfil_guardrail"],
    },
    {
        "id": "guardrail_dw_authorization_boundary_v4_30",
        "role": "specialized_guardrail_source (DESTRUCTIVE_WRITE family)",
        "category": "specialized_guardrails",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ["dw_code", "combi_code"],
        "name_patterns": ["dw_authorization_boundary_v4_30.py", "dw_authorization_boundary_v4_30"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": ["authorization_boundary"],
    },
    {
        "id": "guardrail_structured_confused_deputy_v1_1",
        "role": "specialized_guardrail_source (CONFUSED_DEPUTY family)",
        "category": "specialized_guardrails",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ["cd_code", "combi_code"],
        "name_patterns": ["structured_confused_deputy_guardrail_v1_1.py", "structured_confused_deputy_guardrail_v1_1"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": ["confused_deputy"],
    },
    {
        "id": "guardrail_optimal_plus_v7_71a",
        "role": "specialized_guardrail_source (UNTRUSTED_TO_ACTION family)",
        "category": "specialized_guardrails",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ["uta_code", "combi_code"],
        "name_patterns": ["optimal_plus_v7_71a.py", "optimal_plus_v7_71a"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": ["optimal_plus"],
    },
    {
        "id": "baseline_guardrail_optimal",
        "role": "packaged_baseline_guardrail (byte-for-byte, unchanged -- do not touch)",
        "category": "baseline_guardrail",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["optimal.py"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": ["aicomp_sdk", "packaged"],
    },
    {
        "id": "official_predicates",
        "role": "official_scorer (predicates.py / eval_predicates / is_breach -- unmodified)",
        "category": "official_scorer",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["predicates.py"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": ["predicate", "is_breach", "aicomp_sdk"],
    },
    {
        "id": "sdk_env_sandbox",
        "role": "sdk_core",
        "category": "sdk_core",
        "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["sandbox.py"],
        "path_hint_contains": ["env"],
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": ["sandbox", "aicomp_sdk"],
    },
    {
        "id": "sdk_env_api",
        "role": "sdk_core",
        "category": "sdk_core",
        "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["api.py"],
        "path_hint_contains": ["env"],
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": ["aicomp_sdk"],
    },
    {
        "id": "sdk_env_gym",
        "role": "sdk_core",
        "category": "sdk_core",
        "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["gym.py"],
        "path_hint_contains": ["env"],
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": ["gym", "aicomp_sdk"],
    },
    {
        "id": "sdk_guardrails_base",
        "role": "sdk_core",
        "category": "sdk_core",
        "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["base.py"],
        "path_hint_contains": ["guardrails"],
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": ["aicomp_sdk"],
    },
    {
        "id": "sdk_attacks_baselines_guardrail_rules",
        "role": "sdk_core",
        "category": "sdk_core",
        "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["guardrail_rules.py"],
        "path_hint_contains": ["attacks", "baselines"],
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": ["guardrail_rules", "aicomp_sdk"],
    },
    {
        "id": "sdk_cli_commands_test",
        "role": "sdk_core",
        "category": "sdk_core",
        "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["test.py"],
        "path_hint_contains": ["cli", "commands"],
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": ["aicomp_sdk"],
    },
    {
        "id": "candidate_corpus_v5_2_full_inline",
        "role": "frozen_candidate_corpus (66 candidates, attack_yaml_harness_v5_2_full_inline)",
        "category": "candidate_corpus",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ALL_CODE_ROOTS,
        "name_patterns": [
            "attack_yaml_harness_v5_2_full_inline.py",
            "attack_yaml_harness_v5_2_full_inline.yaml",
            "attack_yaml_harness_v5_2_full_inline.yml",
            "attack_yaml_harness_v5_2_full_inline.json",
        ],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": None,
    },
    {
        "id": "raw_198run_summary",
        "role": "raw_output (198-run local_validate_v5_2_full_summary.json -- already collected, do not rerun)",
        "category": "raw_results",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["local_validate_v5_2_full_summary.json"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": None,
    },
    {
        "id": "fixture_api_keys",
        "role": "real_fixture (byte-verified unchanged)",
        "category": "fixtures",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["api_keys.txt"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": None,
    },
    {
        "id": "fixture_note",
        "role": "real_fixture (byte-verified unchanged)",
        "category": "fixtures",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["note.txt"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": None,
    },
    {
        "id": "fixture_readme",
        "role": "real_fixture (byte-verified unchanged)",
        "category": "fixtures",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["readme.txt"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": None,
    },
    {
        "id": "fixture_report",
        "role": "real_fixture (byte-verified unchanged)",
        "category": "fixtures",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["report.txt"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": None,
    },
    {
        "id": "fixture_temp",
        "role": "real_fixture (byte-verified unchanged)",
        "category": "fixtures",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["temp.txt"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": None,
    },
    {
        "id": "fixture_writable",
        "role": "real_fixture (byte-verified unchanged)",
        "category": "fixtures",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["writable.txt"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": None,
    },
    {
        "id": "fixture_writable2",
        "role": "real_fixture (byte-verified unchanged)",
        "category": "fixtures",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["writable2.txt"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": None,
    },
    {
        "id": "fixture_mail_seed",
        "role": "real_fixture (byte-verified unchanged)",
        "category": "fixtures",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["mail_seed.json"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": None,
    },
    {
        "id": "fixture_web_corpus",
        "role": "real_fixture (byte-verified unchanged)",
        "category": "fixtures",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ALL_ROOTS,
        "name_patterns": ["web_corpus.json"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
        "fuzzy_keywords": None,
    },
    {
        "id": "independent_expected_policy_labels",
        "role": "independent_expected_policy_label (per-candidate oracle labels, authored BEFORE replay -- NOT derived from replay output)",
        "category": "policy_oracle",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ALL_ROOTS,
        "name_patterns": [
            "expected_policy_labels*.csv", "expected_policy_labels*.json",
            "policy_oracle*.csv", "policy_oracle*.json",
            "independent_expected_policy*.csv", "independent_expected_policy*.json",
        ],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": False,
        "fuzzy_keywords": ["policy_label", "expected_policy", "oracle"],
    },
    {
        "id": "output_schema_definitions",
        "role": "output_schema_definitions (for every result table produced in priority_1-6)",
        "category": "schema",
        "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
        "search_roots": ALL_ROOTS,
        "name_patterns": [
            "*schema*.json", "*schema*.yaml", "*schema*.yml", "*schema*.py",
        ],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": False,
        "fuzzy_keywords": None,  # already broad; fuzzy pass would be redundant
    },
]

# -----------------------------------------------------------------------------
# ENVIRONMENT_EPOCH -- cannot be derived from file bytes. Fill by hand.
# -----------------------------------------------------------------------------
ENVIRONMENT_EPOCH = {
    "sdk_or_evaluator_commit_hash": "REQUIRES_MANUAL_ENTRY",
    "model": "REQUIRES_MANUAL_ENTRY",
    "adapter": "REQUIRES_MANUAL_ENTRY",
    "tokenizer": "REQUIRES_MANUAL_ENTRY",
    "sampling_temperature": "REQUIRES_MANUAL_ENTRY",
    "sampling_max_tokens": "REQUIRES_MANUAL_ENTRY",
    "guardrail_composition_used_in_198_run_batch": "REQUIRES_MANUAL_ENTRY",
    "notes": (
        "Fill in every REQUIRES_MANUAL_ENTRY field above before this manifest "
        "is cited by phase_2_publication. The generator script cannot infer "
        "model/sampling/commit metadata from file hashes alone."
    ),
}

REDACTION_POLICY_P6B = {
    "policy_defined": False,
    "policy_text": "REQUIRES_MANUAL_ENTRY",
    "notes": (
        "Per phase_1_write.priority_0 additional_requirements: publish a "
        "redaction policy for the single real-runtime EXFILTRATION "
        "divergence sample BEFORE it appears in a publication draft. "
        "Set policy_defined=True and fill policy_text once decided."
    ),
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


def safe_getsize(path):
    return os.path.getsize(win_long_path(path))


def safe_getmtime(path):
    return os.path.getmtime(win_long_path(path))


def should_skip_dir(dirname):
    return dirname in EXCLUDE_DIR_NAMES


def should_skip_file(filename):
    _, ext = os.path.splitext(filename)
    return ext in EXCLUDE_EXTENSIONS


def walk_root(root_key, root_path, max_file_mb, errors):
    results = []
    if not os.path.isdir(win_long_path(root_path)):
        errors.append({
            "root_key": root_key,
            "root_path": root_path,
            "error": "ROOT_NOT_FOUND_OR_NOT_A_DIRECTORY",
        })
        return results

    max_bytes = max_file_mb * 1024 * 1024
    # os.walk itself can also choke on long paths for the *directory* listing
    # step on some Windows/Python combinations; walking via the long-path-
    # prefixed root defends against that too.
    for dirpath, dirnames, filenames in os.walk(win_long_path(root_path)):
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d)]
        for fname in filenames:
            if should_skip_file(fname):
                continue
            abs_path = os.path.join(dirpath, fname)
            # Strip any \\?\ prefix back off for display/storage purposes,
            # so the manifest JSON shows normal-looking paths.
            display_path = abs_path[4:] if abs_path.startswith("\\\\?\\") and os.name == "nt" else abs_path
            try:
                size = os.path.getsize(abs_path)
            except OSError as e:
                errors.append({"root_key": root_key, "path": display_path, "error": str(e)})
                continue
            rel_path = os.path.relpath(display_path, root_path)
            entry = {
                "root_key": root_key,
                "root_path": root_path,
                "abs_path": display_path,
                "rel_path": rel_path.replace("\\", "/"),
                "filename": fname,
                "size_bytes": size,
            }
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
    search_roots = artifact.get("search_roots") or list(ROOTS.keys())
    patterns = [p.lower() for p in artifact["name_patterns"]]
    hints = artifact.get("path_hint_contains")
    matches = []
    for entry in file_index:
        if entry["root_key"] not in search_roots:
            continue
        fname_lower = entry["filename"].lower()
        if not any(fnmatch.fnmatch(fname_lower, pat) for pat in patterns):
            continue
        if not path_matches_hints(entry["rel_path"].lower(), hints):
            continue
        matches.append(entry)
    return matches


def find_fuzzy_suggestions(artifact, file_index, max_suggestions=25):
    keywords = artifact.get("fuzzy_keywords")
    if not keywords:
        return []
    search_roots = artifact.get("search_roots") or list(ROOTS.keys())
    hits = []
    seen = set()
    for entry in file_index:
        if entry["root_key"] not in search_roots:
            continue
        haystack = (entry["rel_path"] + " " + entry["filename"]).lower()
        if any(kw.lower() in haystack for kw in keywords):
            if entry["abs_path"] not in seen:
                seen.add(entry["abs_path"])
                hits.append({"path": entry["abs_path"], "sha256": entry["sha256"]})
    return hits[:max_suggestions]


def classify_artifact_status(artifact, matches):
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


def get_git_commit_hash(path):
    try:
        out = subprocess.run(
            ["git", "-C", path, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0:
            return out.stdout.strip()
        return "NOT_A_GIT_REPOSITORY"
    except Exception as e:
        return "GIT_CHECK_FAILED: {}".format(e)


def build_manifest(args):
    scan_errors = []
    file_index = []
    root_scan_status = {}

    for root_key, root_path in ROOTS.items():
        entries = walk_root(root_key, root_path, args.max_file_mb, scan_errors)
        root_scan_status[root_key] = {
            "root_path": root_path,
            "exists": os.path.isdir(win_long_path(root_path)),
            "files_scanned": len(entries),
        }
        file_index.extend(entries)

    artifacts_out = []
    gaps = []
    fuzzy_suggestions_out = {}
    matched_abs_paths = set()

    for artifact in EXPECTED_ARTIFACTS:
        matches = find_matches_for_artifact(artifact, file_index)
        status = classify_artifact_status(artifact, matches)

        record = {
            "id": artifact["id"],
            "role": artifact["role"],
            "category": artifact["category"],
            "first_used_in": artifact["first_used_in"],
            "required": artifact["required"],
            "status": status,
        }

        if matches:
            canonical = matches[0]
            record["path"] = canonical["abs_path"]
            record["sha256"] = canonical["sha256"]
            record["size_bytes"] = canonical["size_bytes"]
            record["mtime_utc"] = canonical["mtime_utc"]
            if len(matches) > 1:
                record["all_matched_paths"] = [
                    {"path": m["abs_path"], "sha256": m["sha256"]} for m in matches
                ]
            for m in matches:
                matched_abs_paths.add(m["abs_path"])
        else:
            record["path"] = None
            record["sha256"] = None

        artifacts_out.append(record)

        is_blocking_gap = (
            artifact["required"]
            and status in ("MISSING", "FOUND_DIVERGENT_COPIES",
                           "FOUND_BUT_TOO_LARGE_TO_HASH",
                           "FOUND_MULTIPLE_CANDIDATES_NEEDS_REVIEW")
        )
        if is_blocking_gap:
            gap_entry = {
                "id": artifact["id"],
                "role": artifact["role"],
                "status": status,
                "required": artifact["required"],
                "reason": {
                    "MISSING": "No file matching the configured name pattern(s) was found under the configured search roots.",
                    "FOUND_DIVERGENT_COPIES": "Multiple copies found with DIFFERENT sha256 hashes -- a human must pick the canonical copy; this script will not guess.",
                    "FOUND_BUT_TOO_LARGE_TO_HASH": "A matching file was found but exceeded --max-file-mb; rerun with a higher limit or hash it manually.",
                    "FOUND_MULTIPLE_CANDIDATES_NEEDS_REVIEW": "Multiple distinct candidate files found for an artifact that was not expected to have multiple canonical copies (e.g. policy-label or schema files) -- review and either consolidate or narrow name_patterns.",
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
        "manifest_version": "v1",
        "generator_script_version": SCRIPT_VERSION,
        "generated_at_utc": _utc_now_iso(),
        "generator_script_sha256": sha256_of_file(os.path.abspath(__file__)),
        "roots_scanned": root_scan_status,
        "environment_epoch": ENVIRONMENT_EPOCH,
        "redaction_policy_p6b_secret": REDACTION_POLICY_P6B,
        "artifacts": artifacts_out,
        "gaps": gaps,
        "gaps_count": len(gaps),
        "scan_summary": {
            "total_files_scanned_across_all_roots": len(file_index),
            "matched_to_an_expected_artifact": len(matched_abs_paths),
            "unclassified_files_not_in_scope": unclassified_count,
            "scan_errors": scan_errors,
        },
    }
    return manifest, file_index, fuzzy_suggestions_out


def write_gaps_report(manifest, out_path, fuzzy_suggestions=None):
    lines = []
    lines.append("=" * 78)
    lines.append("MANIFEST_V1 GAPS REPORT -- Phase 1, Priority 0")
    lines.append("Generated: {}".format(manifest["generated_at_utc"]))
    lines.append("Generator: {}".format(manifest["generator_script_version"]))
    lines.append("=" * 78)
    lines.append("")
    if not manifest["gaps"]:
        lines.append("NO BLOCKING GAPS. All required artifacts found and consistent.")
        lines.append("Priority 0 manifest is complete -- Priority 1 may proceed once")
        lines.append("ENVIRONMENT_EPOCH and REDACTION_POLICY_P6B fields are also filled in")
        lines.append("(REQUIRES_MANUAL_ENTRY strings are NOT gaps this script can detect")
        lines.append("from file bytes alone, so re-check those by eye).")
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
                lines.append("    FUZZY SUGGESTIONS (unverified -- human review required,")
                lines.append("    NOT part of the manifest, keyword-substring match only):")
                for s in fuzzy_suggestions[g["id"]]:
                    lines.append("      ? {}  [sha256={}]".format(s["path"], s["sha256"]))
            lines.append("")

    env_manual = [k for k, v in manifest["environment_epoch"].items() if v == "REQUIRES_MANUAL_ENTRY"]
    if env_manual:
        lines.append("-" * 78)
        lines.append("ENVIRONMENT_EPOCH fields still needing manual entry (edit the script's")
        lines.append("ENVIRONMENT_EPOCH dict, then rerun):")
        for k in env_manual:
            lines.append("  - {}".format(k))

    if not manifest["redaction_policy_p6b_secret"]["policy_defined"]:
        lines.append("-" * 78)
        lines.append("REDACTION POLICY for the P6b real secret value is NOT YET DEFINED.")
        lines.append("This must be set before that sample appears in any publication draft.")

    if manifest["scan_summary"]["scan_errors"]:
        lines.append("-" * 78)
        lines.append("SCAN ERRORS (files/roots that could not be read):")
        for e in manifest["scan_summary"]["scan_errors"]:
            lines.append("  - {}".format(e))
        lines.append("")
        lines.append("NOTE: as of v1.1, file open/getsize/hash calls use the Windows")
        lines.append("\"\\\\?\\\" extended-length-path prefix, which resolves MAX_PATH (260-char)")
        lines.append("failures. If errors still appear above, they are a DIFFERENT issue")
        lines.append("(e.g. permissions, file locked by another process) -- read the error")
        lines.append("text for the specific cause; do not assume it's the same long-path bug.")

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
    parser.add_argument("--suggest-fuzzy-matches", action="store_true",
                         help="For MISSING artifacts with fuzzy_keywords configured, list "
                              "filenames elsewhere in the scan containing those keywords, for "
                              "your own visual review. Advisory only -- never auto-resolves "
                              "an artifact's status or writes into manifest_v1.sha256.json.")
    parser.add_argument("--fuzzy-suggestions-output", default="manifest_v1_fuzzy_suggestions.json")
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
        full_inv = {
            "generated_at_utc": manifest["generated_at_utc"],
            "note": "Full audit-trail scan of all files under all 10 roots. NOT the scoped manifest_v1 flat list -- see manifest_v1.sha256.json for that.",
            "files": file_index,
        }
        with open(args.full_inventory_output, "w", encoding="utf-8") as f:
            json.dump(full_inv, f, indent=2)

    if args.suggest_fuzzy_matches and fuzzy_suggestions:
        with open(args.fuzzy_suggestions_output, "w", encoding="utf-8") as f:
            json.dump({
                "note": "ADVISORY ONLY. Keyword-substring matches for MISSING artifacts, for human review. Never auto-attached to manifest_v1.sha256.json.",
                "generated_at_utc": manifest["generated_at_utc"],
                "suggestions": fuzzy_suggestions,
            }, f, indent=2)
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
