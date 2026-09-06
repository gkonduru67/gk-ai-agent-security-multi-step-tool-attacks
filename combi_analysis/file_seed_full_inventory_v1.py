#!/usr/bin/env python3
r"""
file_seed_full_inventory_v1.py  (P7.2)
==========================================================================
Full, read-only re-inventory of the aicomp_sdk/fixtures/file_seed directory
(and, for completeness, the two top-level corpus files). Unlike the earlier
P7/P7.1 inventory (which only checked a hardcoded list of 7 expected
filenames), this script enumerates and hashes EVERY file actually present
in file_seed -- so newly-discovered fixtures are caught automatically, not
just the ones a prior document happened to name.

What this does (all read-only -- never writes, moves, renames, or deletes
anything):
  1. Recursively scans --fixtures-dir/file_seed (depth-limited, default 3)
     and hashes (SHA-256) every regular file found, regardless of whether
     it was previously known about.
  2. Also hashes mail_seed.json / web_corpus.json at --fixtures-dir root,
     for a single consolidated manifest.
  3. Applies a HEURISTIC, filename-pattern-based role classifier to each
     file_seed file (e.g. "looks like a credential-flavored fixture",
     "looks like a writable/scratch target"). This is explicitly labeled
     as a heuristic guess, not an authoritative classification -- it is
     meant to prioritize which files a human should manually review next,
     not to assert ground truth.
  4. Specifically checks secret.txt's SHA-256 against the documented P8
     prefix "746aa208" (from AI_Agent_Security_Project_EXFILTRATION_
     CONSOLIDATED_v2.docx). Reports CONFIRMED_MATCH / MISMATCH /
     FILE_NOT_FOUND -- never assumes a match without checking.
  5. Flags zero-byte files and files that fail to open, rather than
     silently skipping them.

What this deliberately does NOT do:
  - Does not assume any role classification is correct -- every entry in
    likely_role_heuristic carries a `confidence: heuristic_only` marker.
  - Does not hardcode expected content hashes for any file other than
    secret.txt (the only file with a documented, evidence-bound hash in
    this project's artifacts). Guessing expected hashes for the other
    ~23 files would risk false MISMATCH flags from formatting drift in
    how content was previously transcribed elsewhere -- safer to report
    only size/hash/role-guess for those and let a human confirm content.

Usage (PowerShell):
  python file_seed_full_inventory_v1.py --fixtures-dir "C:\...\aicomp_sdk\fixtures"

No third-party dependencies. Python 3.8+.
==========================================================================
"""

from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


# The only hash this project has independently, evidence-bound documented:
# AI_Agent_Security_Project_EXFILTRATION_CONSOLIDATED_v2.docx (P8 finding),
# "file_seed/secret.txt (sha256 746aa208...)". Only the 8-char prefix was
# recorded in that source; we check startswith, not full equality, and we
# say so explicitly in the output rather than pretend we have the full hash.
KNOWN_SECRET_TXT_SHA256_PREFIX = "746aa208"
KNOWN_SECRET_TXT_SIZE_BYTES = 149  # also documented in the same P8 finding


# --------------------------------------------------------------------------
# Heuristic role classifier -- filename-pattern based ONLY. Every result is
# tagged confidence: "heuristic_only" and includes the matched pattern/
# reasoning, so a human can immediately see WHY the guess was made and
# override it.
# --------------------------------------------------------------------------
ROLE_RULES: List[tuple] = [
    (re.compile(r"^secret\.txt$", re.I),
     "CANONICAL_PROTECTED_TARGET",
     "Exact filename match to the byte-verified P8 canonical protected fixture."),
    (re.compile(r"^(api_keys|credentials)\.(txt|json)$", re.I),
     "CREDENTIAL_LIKE_CANDIDATE",
     "Filename suggests stored credential/key material; treat as a candidate protected target pending review."),
    (re.compile(r"^config\.(txt|json)$", re.I),
     "CONFIG_ARTIFACT_LOW_SENSITIVITY_CANDIDATE",
     "Filename suggests application configuration; may or may not contain sensitive values -- review content before assuming either way."),
    (re.compile(r"^writable2?\.txt$", re.I),
     "WRITABLE_SCRATCH_TARGET_CANDIDATE",
     "Filename suggests an agent-writable scratch fixture (consistent with DESTRUCTIVE_WRITE append/overwrite scenario evidence)."),
    (re.compile(r"^temp\.txt$", re.I),
     "SCRATCH_TARGET_CANDIDATE",
     "Filename suggests a disposable/temporary scratch fixture (consistent with DESTRUCTIVE_WRITE delete scenario evidence)."),
    (re.compile(r"^compromised\.txt$", re.I),
     "NARRATIVE_OR_DECOY_CANDIDATE",
     "Filename and prior content review suggest a pre-written 'incident narrative' decoy rather than a live protected fixture -- review content to confirm it is not itself sensitive."),
    (re.compile(r"^mh_\w+\.txt$", re.I),
     "MULTI_HOP_BRIDGE_CANDIDATE",
     "The 'mh_' prefix is suggestive of a multi-hop scenario bridge/instruction fixture (cf. HARNESS_ARTIFACT_PATTERNS mh_(email|web)_* naming convention seen elsewhere in this project's corpora) -- role UNVERIFIED, recommend manual content review before use in any detector logic."),
    (re.compile(r"^fx_[0-9a-f]{8,}\.txt$", re.I),
     "HASH_NAMED_ARTIFACT_UNKNOWN_ROLE",
     "Filename itself resembles a hash/identifier, suggesting a dynamically-generated or per-run fixture -- role UNKNOWN, flagged for manual review."),
    (re.compile(r"^(report|weekly_report|weekly_metrics_report|diag_bundle_list|telemetry_data)\.(txt|md)$", re.I),
     "REPORT_OR_LOG_ARTIFACT_CANDIDATE",
     "Filename suggests report/log/telemetry-style content; likely low-sensitivity but not yet content-reviewed."),
    (re.compile(r"^(readme|install|package|setup_complete|setup_completion|runbook_notes|note)\.(txt|md)$", re.I),
     "GENERIC_DOCUMENTATION_OR_SETUP_CANDIDATE",
     "Filename pattern matches generic project documentation/setup-log style content; prior spot-checks of similarly-named files in this project showed benign placeholder text, but this specific file has not been individually content-reviewed."),
]


def classify_role(filename: str) -> Dict[str, str]:
    for pattern, role, reasoning in ROLE_RULES:
        if pattern.match(filename):
            return {"likely_role_heuristic": role, "reasoning": reasoning, "confidence": "heuristic_only"}
    return {
        "likely_role_heuristic": "UNCLASSIFIED",
        "reasoning": "Filename did not match any known heuristic pattern.",
        "confidence": "heuristic_only",
    }


def sha256_of_file(path: Path, chunk_size: int = 65536) -> Optional[str]:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def scan_and_hash(root: Path, max_depth: int) -> List[Dict[str, Any]]:
    """Recursively enumerate every regular file under root, up to max_depth,
    and hash each one. Never raises on a per-file error -- records it
    instead so one bad file doesn't abort the whole inventory."""
    results = []
    root = root.resolve()
    root_depth = len(root.parts)

    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        depth = len(current.parts) - root_depth
        if depth >= max_depth:
            dirnames[:] = []
            continue

        for fname in sorted(filenames):
            fpath = current / fname
            entry: Dict[str, Any] = {
                "name": fname,
                "relative_path": str(fpath.relative_to(root)),
                "absolute_path": str(fpath),
            }
            try:
                stat = fpath.stat()
                entry["size_bytes"] = stat.st_size
                entry["mtime_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime))
            except Exception as exc:
                entry["stat_error"] = f"{type(exc).__name__}: {exc}"
                entry["size_bytes"] = None
                entry["mtime_utc"] = None

            digest = sha256_of_file(fpath)
            if digest is None:
                entry["sha256"] = None
                entry["read_status"] = "READ_FAILED"
            else:
                entry["sha256"] = digest
                entry["read_status"] = "OK"
                if entry.get("size_bytes") == 0:
                    entry["read_status"] = "OK_BUT_ZERO_BYTES"

            results.append(entry)

    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fixtures-dir", required=True,
                    help=r"Directory containing mail_seed.json / web_corpus.json and a file_seed subfolder")
    ap.add_argument("--file-seed-dir", required=False, default=None,
                    help=r"Override: directory to scan directly (default: <fixtures-dir>\file_seed)")
    ap.add_argument("--max-depth", type=int, default=3,
                    help="Max recursion depth under file_seed (default 3)")
    ap.add_argument("--out", required=False, default="p72_file_seed_full_inventory.json",
                    help="Output JSON manifest path (default: p72_file_seed_full_inventory.json)")
    args = ap.parse_args()

    fixtures_dir = Path(args.fixtures_dir).resolve()
    file_seed_dir = Path(args.file_seed_dir).resolve() if args.file_seed_dir else fixtures_dir / "file_seed"

    report: Dict[str, Any] = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "resolved_fixtures_dir": str(fixtures_dir),
        "resolved_file_seed_dir": str(file_seed_dir),
        "fixtures_dir_exists": fixtures_dir.is_dir(),
        "file_seed_dir_exists": file_seed_dir.is_dir(),
    }

    # --- Top-level corpus files (for a single consolidated manifest) ---
    top_level_targets = {"mail_seed.json": fixtures_dir / "mail_seed.json",
                          "web_corpus.json": fixtures_dir / "web_corpus.json"}
    top_level_entries = {}
    for name, path in top_level_targets.items():
        if path.is_file():
            top_level_entries[name] = {
                "absolute_path": str(path),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_of_file(path),
                "read_status": "OK",
            }
        else:
            top_level_entries[name] = {"read_status": "NOT_FOUND", "absolute_path": str(path)}
    report["top_level_corpus_files"] = top_level_entries

    # --- Full file_seed scan ---
    if not report["file_seed_dir_exists"]:
        report["file_seed_full_manifest"] = []
        report["error"] = f"file_seed directory not found at {file_seed_dir}"
    else:
        raw_entries = scan_and_hash(file_seed_dir, args.max_depth)
        full_manifest = []
        for entry in raw_entries:
            role_info = classify_role(entry["name"])
            entry.update(role_info)
            full_manifest.append(entry)
        report["file_seed_full_manifest"] = full_manifest
        report["file_seed_file_count"] = len(full_manifest)

    # --- secret.txt targeted identity check (the specific P7.2 ask) ---
    secret_check: Dict[str, Any] = {
        "documented_sha256_prefix": KNOWN_SECRET_TXT_SHA256_PREFIX,
        "documented_size_bytes": KNOWN_SECRET_TXT_SIZE_BYTES,
        "documented_source": "AI_Agent_Security_Project_EXFILTRATION_CONSOLIDATED_v2.docx (P8 finding)",
    }
    secret_entry = next(
        (e for e in report.get("file_seed_full_manifest", []) if e["name"].lower() == "secret.txt"),
        None,
    )
    if secret_entry is None:
        secret_check["status"] = "FILE_NOT_FOUND"
    elif secret_entry.get("sha256") is None:
        secret_check["status"] = "FOUND_BUT_UNREADABLE"
        secret_check["read_status"] = secret_entry.get("read_status")
    else:
        actual_hash = secret_entry["sha256"]
        actual_size = secret_entry.get("size_bytes")
        prefix_match = actual_hash.lower().startswith(KNOWN_SECRET_TXT_SHA256_PREFIX.lower())
        size_match = actual_size == KNOWN_SECRET_TXT_SIZE_BYTES
        secret_check["actual_sha256_full"] = actual_hash
        secret_check["actual_size_bytes"] = actual_size
        secret_check["sha256_prefix_match"] = prefix_match
        secret_check["size_match"] = size_match
        if prefix_match and size_match:
            secret_check["status"] = "CONFIRMED_MATCH"
        elif prefix_match and not size_match:
            secret_check["status"] = "PREFIX_MATCHES_BUT_SIZE_DIFFERS_INVESTIGATE"
        elif not prefix_match and size_match:
            secret_check["status"] = "SIZE_MATCHES_BUT_HASH_PREFIX_DIFFERS_INVESTIGATE"
        else:
            secret_check["status"] = "MISMATCH"
    report["secret_txt_identity_check"] = secret_check

    # --- Summary by heuristic role ---
    role_counts: Dict[str, int] = {}
    zero_byte_files: List[str] = []
    unreadable_files: List[str] = []
    for e in report.get("file_seed_full_manifest", []):
        role = e.get("likely_role_heuristic", "UNCLASSIFIED")
        role_counts[role] = role_counts.get(role, 0) + 1
        if e.get("read_status") == "OK_BUT_ZERO_BYTES":
            zero_byte_files.append(e["name"])
        if e.get("read_status") == "READ_FAILED":
            unreadable_files.append(e["name"])
    report["summary"] = {
        "total_files_in_file_seed": len(report.get("file_seed_full_manifest", [])),
        "role_counts_heuristic": role_counts,
        "zero_byte_files": zero_byte_files,
        "unreadable_files": unreadable_files,
        "secret_txt_status": secret_check.get("status"),
    }

    out_path = Path(args.out)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps(report, indent=2))
    print(f"\nManifest written to: {out_path.resolve()}", file=sys.stderr)
    print("\n--- Quick read ---", file=sys.stderr)
    print(f"  file_seed files found: {report['summary']['total_files_in_file_seed']}", file=sys.stderr)
    print(f"  secret.txt identity check: {secret_check.get('status')}", file=sys.stderr)
    if zero_byte_files:
        print(f"  WARNING zero-byte files: {zero_byte_files}", file=sys.stderr)
    if unreadable_files:
        print(f"  WARNING unreadable files: {unreadable_files}", file=sys.stderr)
    print("  role breakdown (heuristic, review before trusting):", file=sys.stderr)
    for role, count in sorted(role_counts.items(), key=lambda x: -x[1]):
        print(f"    {role}: {count}", file=sys.stderr)


if __name__ == "__main__":
    main()
