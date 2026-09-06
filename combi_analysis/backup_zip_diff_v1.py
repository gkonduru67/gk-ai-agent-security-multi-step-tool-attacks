#!/usr/bin/env python3
r"""
backup_zip_diff_v1.py  (P7.3 support tool)
==========================================================================
Formalizes the "is this file present in my backup zip?" check with code,
instead of manual eyeballing. Built specifically to help resolve the
fx_70a39e917cee2a14.txt causal-origin question, but generic enough to diff
any current file_seed directory against any zip archive of an earlier SDK
snapshot.

Read-only: never writes to, modifies, or extracts-to-disk the zip or the
current directory. Reads zip member bytes in-memory only to compute SHA-256
for content comparison.

FAIL-CLOSED DESIGN (same discipline as diagnose_file_seed_v1.py /
file_seed_full_inventory_v1.py): this script does NOT assume it knows the
internal folder layout of your backup zip. It first auto-detects every
directory inside the zip whose name is exactly "file_seed" (case-
insensitive) and lists all candidates found. If exactly one candidate
exists, it is used automatically. If zero or more than one is found, the
script STOPS and asks you to pass --zip-file-seed-prefix explicitly --
it will never silently guess a path and risk a false "not present"
finding (this is exactly the class of bug that caused the earlier P7.1
false-negative on file_seed itself).

Output classifies every filename found in either location as one of:
  - ADDED_SINCE_BACKUP     (in current dir only -- created after the backup)
  - REMOVED_SINCE_BACKUP   (in backup zip only -- deleted since the backup)
  - UNCHANGED              (present in both, identical SHA-256)
  - MODIFIED_SINCE_BACKUP  (present in both, different SHA-256)

Usage (PowerShell):
  python backup_zip_diff_v1.py ^
      --backup-zip "C:\path\to\aicomp_sdk_backup.zip" ^
      --current-dir "C:\...\aicomp_sdk\fixtures\file_seed" ^
      --out p73_backup_diff.json

If auto-detection finds multiple or zero "file_seed"-named folders inside
the zip, re-run with --zip-file-seed-prefix "exact/internal/path/" using
one of the candidates printed in the first run's output.

No third-party dependencies. Python 3.8+.
==========================================================================
"""

from __future__ import annotations
import argparse
import hashlib
import json
import os
import sys
import time
import zipfile
from pathlib import Path
from typing import Dict, List, Optional


def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def find_file_seed_candidates(zf: zipfile.ZipFile) -> List[str]:
    """Return sorted list of distinct internal zip directory paths (ending
    in '/') whose final path component is exactly 'file_seed'
    (case-insensitive), based on the zip's namelist."""
    candidates = set()
    for name in zf.namelist():
        norm = name.replace("\\", "/")
        parts = [p for p in norm.split("/") if p != ""]
        for i, part in enumerate(parts):
            if part.lower() == "file_seed":
                prefix = "/".join(parts[: i + 1]) + "/"
                candidates.add(prefix)
    return sorted(candidates)


def list_members_under_prefix(zf: zipfile.ZipFile, prefix: str) -> Dict[str, zipfile.ZipInfo]:
    """Return {basename: ZipInfo} for regular files directly under the given
    prefix (not recursing into further subdirectories, to mirror a flat
    file_seed folder; adjust if your real layout nests further)."""
    out = {}
    for info in zf.infolist():
        norm = info.filename.replace("\\", "/")
        if not norm.startswith(prefix):
            continue
        if info.is_dir():
            continue
        remainder = norm[len(prefix):]
        if "/" in remainder:
            continue  # skip files in deeper subdirectories for this flat comparison
        if remainder:
            out[remainder] = info
    return out


def list_current_dir_files(current_dir: Path) -> Dict[str, Path]:
    out = {}
    if not current_dir.is_dir():
        return out
    for entry in sorted(current_dir.iterdir()):
        if entry.is_file():
            out[entry.name] = entry
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backup-zip", required=True, help="Path to the backup zip archive of the SDK")
    ap.add_argument("--current-dir", required=True,
                     help="Path to the CURRENT file_seed directory to compare against the backup")
    ap.add_argument("--zip-file-seed-prefix", required=False, default=None,
                     help="Exact internal zip path prefix for file_seed (e.g. 'aicomp_sdk/fixtures/file_seed/'). "
                          "Required only if auto-detection finds 0 or >1 candidates.")
    ap.add_argument("--out", required=False, default="p73_backup_diff.json")
    args = ap.parse_args()

    zip_path = Path(args.backup_zip)
    current_dir = Path(args.current_dir)

    report: Dict = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "backup_zip_path": str(zip_path),
        "backup_zip_exists": zip_path.is_file(),
        "current_dir_path": str(current_dir),
        "current_dir_exists": current_dir.is_dir(),
    }

    if not report["backup_zip_exists"]:
        report["error"] = f"Backup zip not found at {zip_path}"
        print(json.dumps(report, indent=2))
        sys.exit(1)

    try:
        report["backup_zip_mtime_utc"] = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(zip_path.stat().st_mtime)
        )
    except Exception:
        report["backup_zip_mtime_utc"] = None

    with zipfile.ZipFile(zip_path, "r") as zf:
        candidates = find_file_seed_candidates(zf)
        report["auto_detected_file_seed_candidates_in_zip"] = candidates

        if args.zip_file_seed_prefix:
            chosen_prefix = args.zip_file_seed_prefix.replace("\\", "/")
            if not chosen_prefix.endswith("/"):
                chosen_prefix += "/"
            report["prefix_source"] = "user_specified"
        elif len(candidates) == 1:
            chosen_prefix = candidates[0]
            report["prefix_source"] = "auto_detected_single_candidate"
        else:
            report["prefix_source"] = None
            report["chosen_prefix"] = None
            report["status"] = (
                "AMBIGUOUS_OR_NOT_FOUND: 0 or >1 'file_seed'-named folders found inside the zip. "
                "Re-run with --zip-file-seed-prefix set to one of "
                "auto_detected_file_seed_candidates_in_zip above."
            )
            (Path(args.out)).write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(json.dumps(report, indent=2))
            sys.exit(2)

        report["chosen_prefix"] = chosen_prefix

        zip_members = list_members_under_prefix(zf, chosen_prefix)
        current_files = list_current_dir_files(current_dir)

        all_names = sorted(set(zip_members.keys()) | set(current_files.keys()))
        diff_entries = []
        for name in all_names:
            entry = {"name": name}
            in_zip = name in zip_members
            in_current = name in current_files

            zip_hash = None
            zip_size = None
            if in_zip:
                info = zip_members[name]
                zip_size = info.file_size
                try:
                    with zf.open(info, "r") as member_f:
                        zip_bytes = member_f.read()
                    zip_hash = sha256_of_bytes(zip_bytes)
                except Exception as exc:
                    entry["zip_read_error"] = f"{type(exc).__name__}: {exc}"

            current_hash = None
            current_size = None
            if in_current:
                cpath = current_files[name]
                try:
                    current_size = cpath.stat().st_size
                except Exception:
                    pass
                current_hash = sha256_of_file(cpath)

            entry["in_backup_zip"] = in_zip
            entry["in_current_dir"] = in_current
            entry["backup_sha256"] = zip_hash
            entry["backup_size_bytes"] = zip_size
            entry["current_sha256"] = current_hash
            entry["current_size_bytes"] = current_size

            if in_current and not in_zip:
                entry["status"] = "ADDED_SINCE_BACKUP"
            elif in_zip and not in_current:
                entry["status"] = "REMOVED_SINCE_BACKUP"
            elif zip_hash is not None and current_hash is not None and zip_hash == current_hash:
                entry["status"] = "UNCHANGED"
            elif zip_hash is not None and current_hash is not None:
                entry["status"] = "MODIFIED_SINCE_BACKUP"
            else:
                entry["status"] = "COMPARISON_INCOMPLETE (see *_read_error fields)"

            diff_entries.append(entry)

        report["diff"] = diff_entries
        report["summary"] = {
            "total_names_compared": len(diff_entries),
            "added_since_backup": [e["name"] for e in diff_entries if e["status"] == "ADDED_SINCE_BACKUP"],
            "removed_since_backup": [e["name"] for e in diff_entries if e["status"] == "REMOVED_SINCE_BACKUP"],
            "modified_since_backup": [e["name"] for e in diff_entries if e["status"] == "MODIFIED_SINCE_BACKUP"],
            "unchanged_count": sum(1 for e in diff_entries if e["status"] == "UNCHANGED"),
        }

    out_path = Path(args.out)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))

    print(f"\nManifest written to: {out_path.resolve()}", file=sys.stderr)
    print("\n--- Quick read ---", file=sys.stderr)
    print(f"  Chosen zip prefix: {report.get('chosen_prefix')}", file=sys.stderr)
    s = report["summary"]
    print(f"  ADDED_SINCE_BACKUP:    {s['added_since_backup']}", file=sys.stderr)
    print(f"  REMOVED_SINCE_BACKUP:  {s['removed_since_backup']}", file=sys.stderr)
    print(f"  MODIFIED_SINCE_BACKUP: {s['modified_since_backup']}", file=sys.stderr)
    print(f"  UNCHANGED (count):     {s['unchanged_count']}", file=sys.stderr)


if __name__ == "__main__":
    main()
