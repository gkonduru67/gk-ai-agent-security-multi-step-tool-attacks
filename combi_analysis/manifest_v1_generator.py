#!/usr/bin/env python3
# =============================================================================
# manifest_v1_generator.py
# AI_AGENT_SECURITY -- Phase 1, Priority 0 (BLOCKING)
#
# Purpose
# -------
# Produce ONE cross-family SHA-256 manifest (manifest_v1.sha256.json) before
# any replay/ablation code (Priority 1+) is run. Every later result table and
# every publication claim must resolve to an entry in this manifest.
#
# Design rules this script enforces (do not relax these without deciding to,
# on purpose, in the config section below):
#
#   1. READ-ONLY.  This script only opens files in binary-read mode to hash
#      them. It never writes, renames, moves, or deletes anything inside the
#      10 source roots you gave. All output is written next to the script
#      (or to --output / --gaps-report if you redirect it).
#
#   2. NO SILENT DISAMBIGUATION.  If more than one file matches an expected
#      artifact's search pattern:
#         - if all matches have the SAME sha256           -> status FOUND_CONSISTENT
#         - if matches have DIFFERENT sha256 (divergence)  -> status
#           FOUND_DIVERGENT_COPIES  (this is flagged as a GAP -- a human must
#           pick the canonical copy; the script will not guess which "optimal.py"
#           or "predicates.py" is the real one).
#
#   3. NO FABRICATED METADATA.  Things no file-hash can tell you -- model,
#      adapter, tokenizer, sampling parameters, SDK/evaluator commit hash,
#      the P6b secret-redaction policy -- are left as explicit
#      "REQUIRES_MANUAL_ENTRY" strings in ENVIRONMENT_EPOCH below. They will
#      NOT be silently omitted; they show up in the JSON so gaps are visible,
#      not hidden.
#
#   4. REQUIRED-BUT-MISSING IS A GAP, NOT A SKIP.  Any artifact in
#      EXPECTED_ARTIFACTS with required=True that isn't found is written to
#      the "gaps" block of the manifest AND to manifest_v1_gaps_report.txt,
#      and causes the script to exit with code 1 (so you -- or a future CI
#      step -- can tell at a glance that Priority 0 is not actually closed).
#
#   5. NO YAML DEPENDENCY.  Per your standing preference, all configuration
#      is embedded directly in this .py file below. Edit the CONFIG SECTION
#      to add/remove/rename expected artifacts or roots -- nothing is read
#      from an external config file.
#
# What this script deliberately does NOT do
# ------------------------------------------
#   - It does not run any replay, ablation, or predicate code (that's
#     Priority 1+, and it depends on this manifest existing first).
#   - It does not decide which candidate labels are "expected policy" --
#     that oracle must be authored by you, independently, before replay.
#   - It does not touch the frozen 198-run summary JSON's contents beyond
#     hashing the file as bytes.
#
# Run command (Windows PowerShell, matches your existing workflow):
#   python manifest_v1_generator.py
#
# Useful flags:
#   --output PATH            (default: manifest_v1.sha256.json)
#   --gaps-report PATH       (default: manifest_v1_gaps_report.txt)
#   --emit-full-inventory    (also dump EVERY scanned file's hash to
#                             full_file_inventory_v1.sha256.json -- useful as
#                             an audit trail, but NOT part of the scoped
#                             manifest_v1 flat list itself)
#   --list-roots             (just print the configured roots and exit)
#   --max-file-mb N          (skip hashing files bigger than N MB during the
#                             full-inventory pass; default 200. Does not
#                             affect EXPECTED_ARTIFACTS matching.)
# =============================================================================

import os
import sys
import json
import hashlib
import fnmatch
import argparse
import datetime
import subprocess

def _utc_now_iso():
    # timezone-aware, avoids the datetime.utcnow() deprecation warning on
    # newer Python versions while keeping the same "...Z" string format.
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

SCRIPT_VERSION = "manifest_v1_generator_v1.0"

# =============================================================================
# CONFIG SECTION -- edit this, not the logic below.
# =============================================================================

# -----------------------------------------------------------------------------
# 1. ROOTS -- exactly the 10 locations you gave. Edit paths here only.
# -----------------------------------------------------------------------------
ROOTS = {
    "exfil_code": r"C:\Users\gkonduru\OneDrive - Forescout Technologies, Inc\F_drive\forescout\Learning\Kaggle\ai-agent-security-multi-step-tool-attacks-Jun11-Sep1\ai-agent-security-multi-step-tool-attacks\EXfil",
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

# Directory names to always skip while walking (noise, not evidence).
EXCLUDE_DIR_NAMES = {
    ".git", "__pycache__", ".ipynb_checkpoints", "node_modules",
    "venv", ".venv", "env_venv", "dist", "build", ".mypy_cache", ".pytest_cache",
}

# File extensions to always skip (compiled/cache artifacts, not source evidence).
EXCLUDE_EXTENSIONS = {".pyc", ".pyo", ".DS_Store"}

# -----------------------------------------------------------------------------
# 2. EXPECTED_ARTIFACTS -- the manifest_scope from the frozen plan, made
#    concrete and searchable. Each entry:
#      id                : unique short key
#      role              : human-readable role, copied into the manifest
#      category          : grouping used only for the console summary
#      first_used_in     : which plan step first CONSUMES this artifact
#                           (best-effort per the plan doc -- if you disagree,
#                           edit here; this is a claim about the plan, not
#                           something derivable from file bytes)
#      search_roots      : which ROOTS keys to search (default: all code roots
#                           for source files, all roots for fixtures/results)
#      name_patterns      : list of fnmatch-style, case-insensitive filename
#                           patterns. Version-suffix variants are included
#                           explicitly rather than wildcarded blindly, so a
#                           differently-versioned file does NOT silently match.
#      path_hint_contains : optional list of substrings the file's relative
#                           path must contain (used for the SDK core files,
#                           where the bare filename e.g. "test.py" is too
#                           generic to search on safely).
#      required           : True  -> absence is a blocking GAP
#                           False -> absence is reported but non-blocking
#      expect_single_canonical_copy : True -> if found in >1 place, all copies
#                           must hash identically or it's a DIVERGENT gap
#                           (this is the "byte-for-byte, unchanged" check)
# -----------------------------------------------------------------------------

ALL_CODE_ROOTS = ["exfil_code", "cd_code", "uta_code", "dw_code", "combi_code"]
ALL_ROOTS = list(ROOTS.keys())

EXPECTED_ARTIFACTS = [
    # --- specialized guardrail decide() implementations (one per family) ---
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
    },

    # --- packaged baseline guardrail: must be byte-for-byte unchanged ---
    {
        "id": "baseline_guardrail_optimal",
        "role": "packaged_baseline_guardrail (byte-for-byte, unchanged -- do not touch)",
        "category": "baseline_guardrail",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ALL_CODE_ROOTS,
        "name_patterns": ["optimal.py"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
    },

    # --- official scorer (never treated as ground-truth policy oracle) ---
    {
        "id": "official_predicates",
        "role": "official_scorer (predicates.py / eval_predicates / is_breach -- unmodified)",
        "category": "official_scorer",
        "first_used_in": "phase_1_write.priority_1_paired_replay_66_case_corpus",
        "search_roots": ALL_CODE_ROOTS,
        "name_patterns": ["predicates.py"],
        "path_hint_contains": None,
        "required": True,
        "expect_single_canonical_copy": True,
    },

    # --- SDK core files (path-qualified because filenames are generic) ---
    {
        "id": "sdk_env_sandbox",
        "role": "sdk_core",
        "category": "sdk_core",
        "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
        "search_roots": ALL_CODE_ROOTS,
        "name_patterns": ["sandbox.py"],
        "path_hint_contains": ["env"],
        "required": True,
        "expect_single_canonical_copy": True,
    },
    {
        "id": "sdk_env_api",
        "role": "sdk_core",
        "category": "sdk_core",
        "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
        "search_roots": ALL_CODE_ROOTS,
        "name_patterns": ["api.py"],
        "path_hint_contains": ["env"],
        "required": True,
        "expect_single_canonical_copy": True,
    },
    {
        "id": "sdk_env_gym",
        "role": "sdk_core",
        "category": "sdk_core",
        "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
        "search_roots": ALL_CODE_ROOTS,
        "name_patterns": ["gym.py"],
        "path_hint_contains": ["env"],
        "required": True,
        "expect_single_canonical_copy": True,
    },
    {
        "id": "sdk_guardrails_base",
        "role": "sdk_core",
        "category": "sdk_core",
        "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
        "search_roots": ALL_CODE_ROOTS,
        "name_patterns": ["base.py"],
        "path_hint_contains": ["guardrails"],
        "required": True,
        "expect_single_canonical_copy": True,
    },
    {
        "id": "sdk_attacks_baselines_guardrail_rules",
        "role": "sdk_core",
        "category": "sdk_core",
        "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
        "search_roots": ALL_CODE_ROOTS,
        "name_patterns": ["guardrail_rules.py"],
        "path_hint_contains": ["attacks", "baselines"],
        "required": True,
        "expect_single_canonical_copy": True,
    },
    {
        "id": "sdk_cli_commands_test",
        "role": "sdk_core",
        "category": "sdk_core",
        "first_used_in": "phase_1_write.priority_0_freeze_experimental_contract",
        "search_roots": ALL_CODE_ROOTS,
        "name_patterns": ["test.py"],
        "path_hint_contains": ["cli", "commands"],
        "required": True,
        "expect_single_canonical_copy": True,
    },

    # --- 66-candidate frozen corpus ---
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
    },

    # --- already-collected 198-run raw output ---
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
    },

    # --- 9 real fixtures, byte-verified unchanged ---
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
    },

    # --- Artifacts that the plan explicitly says must be AUTHORED, not
    #     derived. These are almost certainly NOT YET ON DISK. They are kept
    #     in EXPECTED_ARTIFACTS on purpose: their absence must show up as a
    #     loud, named gap rather than being quietly left out of the manifest
    #     scope. If you have already authored these under a different name,
    #     add that filename to name_patterns below and rerun.
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
    },
]

# -----------------------------------------------------------------------------
# 3. ENVIRONMENT_EPOCH -- cannot be derived from file bytes. Fill these in
#    by hand; anything left as "REQUIRES_MANUAL_ENTRY" is copied verbatim
#    into the manifest so the gap stays visible instead of being dropped.
# -----------------------------------------------------------------------------
ENVIRONMENT_EPOCH = {
    "sdk_or_evaluator_commit_hash": "REQUIRES_MANUAL_ENTRY",  # git commit / release tag
    "model": "REQUIRES_MANUAL_ENTRY",                          # e.g. "gpt-oss-XXb"
    "adapter": "REQUIRES_MANUAL_ENTRY",
    "tokenizer": "REQUIRES_MANUAL_ENTRY",
    "sampling_temperature": "REQUIRES_MANUAL_ENTRY",
    "sampling_max_tokens": "REQUIRES_MANUAL_ENTRY",
    "guardrail_composition_used_in_198_run_batch": "REQUIRES_MANUAL_ENTRY",  # e.g. "packaged optimal.py only" / "all 4 specialized modules"
    "notes": (
        "Fill in every REQUIRES_MANUAL_ENTRY field above before this manifest "
        "is cited by phase_2_publication. The generator script cannot infer "
        "model/sampling/commit metadata from file hashes alone."
    ),
}

# -----------------------------------------------------------------------------
# 4. REDACTION POLICY for the single real secret value referenced in P6b.
#    Must be defined before that data appears in any publication draft.
# -----------------------------------------------------------------------------
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
# CORE LOGIC -- should not normally need editing.
# =============================================================================

def sha256_of_file(path, chunk_size=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_of_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def should_skip_dir(dirname):
    return dirname in EXCLUDE_DIR_NAMES


def should_skip_file(filename):
    _, ext = os.path.splitext(filename)
    return ext in EXCLUDE_EXTENSIONS


def walk_root(root_key, root_path, max_file_mb, errors):
    """Yield dicts for every eligible file under root_path. Never raises on
    a single bad file/permission error -- those are collected in `errors`
    and surfaced in the report instead of crashing the whole scan."""
    results = []
    if not os.path.isdir(root_path):
        errors.append({
            "root_key": root_key,
            "root_path": root_path,
            "error": "ROOT_NOT_FOUND_OR_NOT_A_DIRECTORY",
        })
        return results

    max_bytes = max_file_mb * 1024 * 1024
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d)]
        for fname in filenames:
            if should_skip_file(fname):
                continue
            abs_path = os.path.join(dirpath, fname)
            try:
                size = os.path.getsize(abs_path)
            except OSError as e:
                errors.append({"root_key": root_key, "path": abs_path, "error": str(e)})
                continue
            rel_path = os.path.relpath(abs_path, root_path)
            entry = {
                "root_key": root_key,
                "root_path": root_path,
                "abs_path": abs_path,
                "rel_path": rel_path.replace("\\", "/"),
                "filename": fname,
                "size_bytes": size,
            }
            if size > max_bytes:
                entry["sha256"] = None
                entry["skipped_large_file"] = True
            else:
                try:
                    entry["sha256"] = sha256_of_file(abs_path)
                    entry["skipped_large_file"] = False
                except (OSError, PermissionError) as e:
                    errors.append({"root_key": root_key, "path": abs_path, "error": str(e)})
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
    """Best-effort: if `path` sits inside a git repo, return its commit hash.
    Never raises; returns a descriptive string on any failure."""
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
            "exists": os.path.isdir(root_path),
            "files_scanned": len(entries),
        }
        file_index.extend(entries)

    artifacts_out = []
    gaps = []
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
            # canonical entry = first match; all matches listed for transparency
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
            gaps.append({
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
            })

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
    return manifest, file_index


def write_gaps_report(manifest, out_path):
    lines = []
    lines.append("=" * 78)
    lines.append("MANIFEST_V1 GAPS REPORT -- Phase 1, Priority 0")
    lines.append("Generated: {}".format(manifest["generated_at_utc"]))
    lines.append("=" * 78)
    lines.append("")
    if not manifest["gaps"]:
        lines.append("NO BLOCKING GAPS. All required artifacts found and consistent.")
        lines.append("Priority 0 manifest is complete -- Priority 1 may proceed once")
        lines.append("ENVIRONMENT_EPOCH and REDACTION_POLICY_P6B fields are also filled in")
        lines.append("(check the manifest JSON -- REQUIRES_MANUAL_ENTRY strings are NOT")
        lines.append("gaps this script can detect from file bytes, so re-check by eye).")
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

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate manifest_v1.sha256.json (Phase 1, Priority 0).")
    parser.add_argument("--output", default="manifest_v1.sha256.json")
    parser.add_argument("--gaps-report", default="manifest_v1_gaps_report.txt")
    parser.add_argument("--emit-full-inventory", action="store_true",
                         help="Also write full_file_inventory_v1.sha256.json with every scanned file's hash.")
    parser.add_argument("--full-inventory-output", default="full_file_inventory_v1.sha256.json")
    parser.add_argument("--list-roots", action="store_true", help="Print configured roots and exit.")
    parser.add_argument("--max-file-mb", type=int, default=200,
                         help="Skip hashing files larger than this (MB). Default 200.")
    args = parser.parse_args()

    if args.list_roots:
        for k, v in ROOTS.items():
            exists = os.path.isdir(v)
            print("[{}] {} -> {}".format("OK " if exists else "MISSING", k, v))
        return 0

    manifest, file_index = build_manifest(args)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    report_text = write_gaps_report(manifest, args.gaps_report)

    if args.emit_full_inventory:
        full_inv = {
            "generated_at_utc": manifest["generated_at_utc"],
            "note": "Full audit-trail scan of all files under all 10 roots. NOT the scoped manifest_v1 flat list -- see manifest_v1.sha256.json for that.",
            "files": [
                {k: v for k, v in e.items() if k != "abs_path" or True}
                for e in file_index
            ],
        }
        with open(args.full_inventory_output, "w", encoding="utf-8") as f:
            json.dump(full_inv, f, indent=2)

    print(report_text)
    print()
    print("Wrote: {}".format(os.path.abspath(args.output)))
    print("Wrote: {}".format(os.path.abspath(args.gaps_report)))
    if args.emit_full_inventory:
        print("Wrote: {}".format(os.path.abspath(args.full_inventory_output)))

    return 1 if manifest["gaps_count"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())


