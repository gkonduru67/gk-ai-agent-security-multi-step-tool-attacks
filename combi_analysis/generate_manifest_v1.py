#!/usr/bin/env python3
"""
generate_manifest_v1.py

Builds manifest_v1.sha256.json (per this project's own hash_manifest_
requirement: "EVERY figure, table, number, and quoted result in BOTH
documents must resolve to a {path, sha256} entry... No claim may cite an
artifact not in the manifest.") by recursively hashing every file under a
given content root -- deliberately NOT a curated subset. Which files
"matter enough" to cite is a decision for the paper's author, not for this
script; the manifest's job is to make every real artifact resolvable, not
to pre-judge relevance.

Also runs a SAFETY SCAN (not a silent exclusion) over filenames, flagging
anything that might warrant a manual look before a public GitHub push --
e.g. this project's own P10/P11 EXFILTRATION traces may contain the
literal test secret string in intermediate JSON, which is fine locally but
worth a conscious check before going public.

USAGE:
    python generate_manifest_v1.py --content-root "C:\\...\\combi_analysis" --out-dir "C:\\...\\combi_analysis"

OUTPUTS (written into --out-dir, default = --content-root itself):
    manifest_v1.sha256.json   -- the real manifest: {path, sha256, size_bytes,
                                  modified_utc, category} per file
    manifest_v1_summary.txt   -- human-readable counts by category + the
                                  safety-scan flag list, for a quick pre-push review
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Files to always skip hashing entirely -- these are NEVER real evidence
# artifacts, just repo/OS noise. Anything else, however uninteresting it
# looks, gets a real manifest entry -- deliberately not curated further
# than this.
ALWAYS_SKIP_DIR_NAMES = {"__pycache__", ".git", ".ipynb_checkpoints", "node_modules", ".venv", "venv"}
ALWAYS_SKIP_FILE_NAMES = {".DS_Store", "Thumbs.db"}

# Category classification -- purely for the human-readable summary, has
# ZERO effect on which files get a manifest entry (every file gets one).
CATEGORY_RULES = [
    ("script", ["*.py"]),
    ("table_csv", ["*.csv"]),
    ("raw_json_result", ["*_result*.json", "*_report*.json", "*_summary*.json", "*_battery*.json",
                          "*_scaffold*.json", "*_baseline*.json", "*.jsonl"]),
    ("other_json", ["*.json"]),
    ("doc", ["*.docx", "*.pdf", "*.md", "*.txt"]),
    ("yaml_state", ["*.yml", "*.yaml"]),
]

# Filename PATTERNS (not content-scanned -- filenames only, fast and safe)
# that warrant a manual look before a public push. Deliberately conservative
# and non-exhaustive; this is a FLAG for human review, not a redaction tool.
SAFETY_SCAN_PATTERNS = [
    "*secret*", "*password*", "*credential*", "*api_key*", "*apikey*",
    "*.env", "*token*", "*private_key*", "*.pem", "*.key",
]


def sha256_of_file(path: Path, chunk_size: int = 1 << 20) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def categorize(path: Path) -> str:
    name = path.name
    for category, patterns in CATEGORY_RULES:
        if any(fnmatch.fnmatch(name, p) for p in patterns):
            return category
    return "other"


def matches_safety_pattern(path: Path) -> bool:
    name_lower = path.name.lower()
    return any(fnmatch.fnmatch(name_lower, p) for p in SAFETY_SCAN_PATTERNS)


def build_manifest(content_root: Path) -> dict:
    entries = []
    safety_flags = []
    total_bytes = 0

    for dirpath, dirnames, filenames in os.walk(content_root):
        dirnames[:] = [d for d in dirnames if d not in ALWAYS_SKIP_DIR_NAMES]
        for filename in sorted(filenames):
            if filename in ALWAYS_SKIP_FILE_NAMES:
                continue
            full_path = Path(dirpath) / filename
            try:
                rel_path = full_path.relative_to(content_root).as_posix()
                stat = full_path.stat()
                digest = sha256_of_file(full_path)
            except (OSError, PermissionError) as exc:
                entries.append({
                    "path": full_path.relative_to(content_root).as_posix() if full_path.is_relative_to(content_root) else str(full_path),
                    "sha256": None,
                    "size_bytes": None,
                    "modified_utc": None,
                    "category": "UNREADABLE",
                    "error": f"{type(exc).__name__}: {exc}",
                })
                continue

            category = categorize(full_path)
            entries.append({
                "path": rel_path,
                "sha256": digest,
                "size_bytes": stat.st_size,
                "modified_utc": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "category": category,
            })
            total_bytes += stat.st_size

            if matches_safety_pattern(full_path):
                safety_flags.append(rel_path)

    manifest = {
        "manifest_version": "v1",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "content_root": str(content_root),
        "hash_algorithm": "sha256",
        "n_files": len(entries),
        "total_bytes": total_bytes,
        "entries": entries,
        "safety_scan_flagged_paths": safety_flags,
        "safety_scan_note": (
            "Filename-pattern-only scan (content of files was NOT inspected) -- flags files "
            "whose NAME suggests they may contain a real secret/credential/token value. Review "
            "each flagged file manually before a public GitHub push. This project's own P10/P11 "
            "EXFILTRATION traces are the most likely source of a real flag here, since some "
            "intermediate JSON may contain the literal test secret string used in those "
            "experiments -- confirm whether that's acceptable to publish as-is, or should be "
            "redacted/excluded, before pushing."
        ),
    }
    return manifest


def write_summary(manifest: dict, out_path: Path) -> None:
    by_category: dict[str, list[dict]] = {}
    for e in manifest["entries"]:
        by_category.setdefault(e["category"], []).append(e)

    lines = []
    lines.append(f"MANIFEST SUMMARY -- generated {manifest['generated_utc']}")
    lines.append(f"Content root: {manifest['content_root']}")
    lines.append(f"Total files: {manifest['n_files']}  |  Total size: {manifest['total_bytes']:,} bytes")
    lines.append("")
    lines.append("Counts by category:")
    for category in sorted(by_category, key=lambda c: -len(by_category[c])):
        lines.append(f"  {category:20s}: {len(by_category[category])}")
    lines.append("")

    unreadable = by_category.get("UNREADABLE", [])
    if unreadable:
        lines.append(f"*** {len(unreadable)} FILE(S) COULD NOT BE READ/HASHED -- review before trusting manifest completeness ***")
        for e in unreadable:
            lines.append(f"  {e['path']}: {e.get('error')}")
        lines.append("")

    flagged = manifest["safety_scan_flagged_paths"]
    lines.append(f"SAFETY SCAN: {len(flagged)} file(s) flagged by filename pattern (review before public push)")
    for p in flagged:
        lines.append(f"  {p}")
    lines.append("")
    lines.append(manifest["safety_scan_note"])

    out_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--content-root", required=True, help="Root directory to recursively hash (e.g. your combi_analysis folder).")
    ap.add_argument("--out-dir", default=None, help="Where to write manifest_v1.sha256.json + summary (default: same as --content-root).")
    args = ap.parse_args()

    content_root = Path(args.content_root).resolve()
    if not content_root.is_dir():
        print(f"FATAL: --content-root does not exist or is not a directory: {content_root}")
        return 2

    out_dir = Path(args.out_dir).resolve() if args.out_dir else content_root
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Hashing all files under: {content_root}")
    manifest = build_manifest(content_root)

    manifest_path = out_dir / "manifest_v1.sha256.json"
    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    summary_path = out_dir / "manifest_v1_summary.txt"
    write_summary(manifest, summary_path)

    print(f"\nDONE. {manifest['n_files']} files hashed, {manifest['total_bytes']:,} bytes total.")
    print(f"  Manifest: {manifest_path}")
    print(f"  Summary:  {summary_path}")
    if manifest["safety_scan_flagged_paths"]:
        print(f"\n*** {len(manifest['safety_scan_flagged_paths'])} file(s) flagged by the safety scan -- see summary before pushing to GitHub. ***")
    unreadable_count = sum(1 for e in manifest["entries"] if e["category"] == "UNREADABLE")
    if unreadable_count:
        print(f"\n*** WARNING: {unreadable_count} file(s) could not be read/hashed -- see summary. ***")
    return 0


if __name__ == "__main__":
    sys.exit(main())
