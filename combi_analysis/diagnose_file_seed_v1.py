#!/usr/bin/env python3
"""
diagnose_file_seed_v1.py
==========================================================================
Answers: "I can see file_seed files with my naked eye in Explorer -- how do
I prove that programmatically, and why did `inventory` report them missing?"

This does NOT assume the prior inventory result was wrong. It systematically
checks every plausible cause, in order of likelihood, and reports exactly
which one (if any) explains the mismatch -- so the P7.1 gate can close on
evidence, not on "it looked fine in Explorer."

Checks performed, in order:
  1. Resolves and prints the ABSOLUTE path being checked (catches relative-
     path / working-directory mismatches).
  2. Lists the literal byte-for-byte directory contents of --fixtures-dir
     and --fixtures-dir/file_seed via os.scandir (catches trailing spaces,
     smart-quote characters, case differences, and double extensions that
     look identical in Explorer but differ as strings).
  3. Case-insensitive + whitespace-trimmed fuzzy match against each expected
     filename, reporting the EXACT byte difference if a near-miss is found.
  4. Recursive search (os.walk, depth-limited) under --fixtures-dir for each
     expected basename, in case a file exists but one directory level off
     from where inventory expected it.
  5. Windows/OneDrive "Files On-Demand" cloud-placeholder detection (best
     effort, Windows-only): a file can be VISIBLE in Explorer with correct
     name/size metadata while its actual bytes are not yet synced to disk.
     Python's os.path.isfile() can behave inconsistently with such
     placeholders depending on attribute state. Reported as a flag, not
     silently assumed to be the cause.
  6. Permission check: confirms the running user can actually open() each
     resolved file, not just stat() it.

Usage (PowerShell, from anywhere):
  python diagnose_file_seed_v1.py --fixtures-dir "C:\\...\\aicomp_sdk\\fixtures"

No third-party dependencies. Python 3.8+. Safe to re-run any number of times
(read-only; never writes, moves, or deletes anything).
==========================================================================
"""

from __future__ import annotations
import argparse
import ctypes
import json
import os
import sys
import unicodedata


EXPECTED_FILE_SEED_FILES = [
    "api_keys.txt",
    "writable.txt",
    "writable2.txt",
    "temp.txt",
    "report.txt",
]

# Windows FILE_ATTRIBUTE flags relevant to OneDrive Files On-Demand.
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000


def norm(s: str) -> str:
    """Normalize a string for fuzzy comparison: NFC unicode form, stripped
    whitespace, casefolded. Used ONLY for diagnostic near-miss reporting,
    never for deciding a real match."""
    return unicodedata.normalize("NFC", s).strip().casefold()


def describe_bytes(s: str) -> str:
    """Render a string's exact byte/codepoint content for diffing near-miss
    filenames that look identical to the human eye (trailing space, smart
    quote, zero-width char, etc.)."""
    return " ".join(f"U+{ord(c):04X}({c!r})" for c in s)


def get_windows_attributes(path: str):
    """Best-effort Windows file attribute lookup. Returns None on any
    failure (non-Windows OS, path not found, permission error) rather than
    raising -- this is a supplementary diagnostic, not a hard requirement."""
    if os.name != "nt":
        return None
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))  # type: ignore[attr-defined]
        if attrs == 0xFFFFFFFF:
            return None
        return {
            "raw": attrs,
            "offline": bool(attrs & FILE_ATTRIBUTE_OFFLINE),
            "recall_on_data_access": bool(attrs & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS),
            "recall_on_open": bool(attrs & FILE_ATTRIBUTE_RECALL_ON_OPEN),
        }
    except Exception:
        return None


def scan_directory(path: str):
    """Literal, byte-honest directory listing. Returns [] if the directory
    itself does not exist or cannot be read (reported separately)."""
    entries = []
    try:
        with os.scandir(path) as it:
            for entry in it:
                try:
                    stat = entry.stat()
                    size = stat.st_size
                except OSError:
                    size = None
                entries.append({
                    "name": entry.name,
                    "name_bytes": describe_bytes(entry.name),
                    "is_file": entry.is_file(follow_symlinks=False),
                    "is_dir": entry.is_dir(follow_symlinks=False),
                    "size_bytes": size,
                })
    except FileNotFoundError:
        return None
    except PermissionError:
        return "PERMISSION_DENIED"
    return entries


def recursive_search(root: str, target_basename: str, max_depth: int = 4):
    """Depth-limited case-insensitive search for target_basename anywhere
    under root. Returns list of matching absolute paths found."""
    matches = []
    root = os.path.abspath(root)
    root_depth = root.rstrip(os.sep).count(os.sep)
    target_norm = norm(target_basename)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = dirpath.rstrip(os.sep).count(os.sep) - root_depth
        if depth >= max_depth:
            dirnames[:] = []  # stop descending further
            continue
        for fname in filenames:
            if norm(fname) == target_norm:
                matches.append(os.path.join(dirpath, fname))
    return matches


def check_readable(path: str) -> dict:
    try:
        with open(path, "rb") as f:
            first_bytes = f.read(16)
        return {"readable": True, "first_16_bytes_hex": first_bytes.hex()}
    except Exception as exc:
        return {"readable": False, "error": f"{type(exc).__name__}: {exc}"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fixtures-dir", required=True,
                    help=r"Directory expected to contain mail_seed.json / web_corpus.json "
                         r"and a file_seed subfolder, e.g. ...\aicomp_sdk\fixtures")
    ap.add_argument("--file-seed-dir", required=False, default=None,
                    help=r"Override: directory expected to directly contain "
                         r"api_keys.txt/writable.txt/etc. Default: <fixtures-dir>\file_seed")
    ap.add_argument("--search-depth", type=int, default=4,
                    help="How many directory levels to recurse when searching for a near-miss (default 4)")
    args = ap.parse_args()

    fixtures_dir_abs = os.path.abspath(args.fixtures_dir)
    file_seed_dir_abs = os.path.abspath(args.file_seed_dir) if args.file_seed_dir else os.path.join(fixtures_dir_abs, "file_seed")

    report = {
        "resolved_fixtures_dir": fixtures_dir_abs,
        "fixtures_dir_exists": os.path.isdir(fixtures_dir_abs),
        "resolved_file_seed_dir": file_seed_dir_abs,
        "file_seed_dir_exists": os.path.isdir(file_seed_dir_abs),
    }

    # Step 1-2: literal directory listings
    report["fixtures_dir_listing"] = scan_directory(fixtures_dir_abs)
    report["file_seed_dir_listing"] = scan_directory(file_seed_dir_abs)

    # Step 3-4: per-expected-file diagnosis
    per_file = {}
    for fname in EXPECTED_FILE_SEED_FILES:
        expected_path = os.path.join(file_seed_dir_abs, fname)
        entry = {
            "expected_path": expected_path,
            "exact_match_exists": os.path.isfile(expected_path),
        }

        # Fuzzy match against what's actually in file_seed_dir_listing
        near_misses = []
        listing = report["file_seed_dir_listing"]
        if isinstance(listing, list):
            for item in listing:
                if item["is_file"] and norm(item["name"]) == norm(fname) and item["name"] != fname:
                    near_misses.append({
                        "found_name": item["name"],
                        "found_name_bytes": item["name_bytes"],
                        "expected_name_bytes": describe_bytes(fname),
                    })
        entry["near_misses_in_file_seed_dir"] = near_misses

        # If not found at all (exact or near), search recursively under fixtures_dir
        if not entry["exact_match_exists"] and not near_misses:
            found_elsewhere = recursive_search(fixtures_dir_abs, fname, max_depth=args.search_depth)
            entry["found_elsewhere_under_fixtures_dir"] = found_elsewhere
        else:
            entry["found_elsewhere_under_fixtures_dir"] = []

        # Windows OneDrive cloud-placeholder check (best effort)
        if entry["exact_match_exists"]:
            entry["windows_attributes"] = get_windows_attributes(expected_path)
            entry["readability_check"] = check_readable(expected_path)
        else:
            entry["windows_attributes"] = None
            entry["readability_check"] = None

        per_file[fname] = entry

    report["per_expected_file"] = per_file

    # Summary verdict per file, fail-closed (never claims FOUND without a
    # successful open() + byte read)
    summary = {}
    for fname, entry in per_file.items():
        if entry["exact_match_exists"] and entry["readability_check"] and entry["readability_check"]["readable"]:
            verdict = "CONFIRMED_PRESENT_AND_READABLE"
        elif entry["exact_match_exists"]:
            verdict = "PRESENT_BUT_UNREADABLE (see readability_check.error)"
        elif entry["near_misses_in_file_seed_dir"]:
            verdict = "NEAR_MISS_FOUND (see near_misses_in_file_seed_dir -- likely name/case/whitespace mismatch)"
        elif entry["found_elsewhere_under_fixtures_dir"]:
            verdict = "FOUND_AT_DIFFERENT_PATH (see found_elsewhere_under_fixtures_dir)"
        else:
            verdict = "NOT_FOUND_ANYWHERE_UNDER_FIXTURES_DIR (genuinely absent, or outside search depth/root)"
        summary[fname] = verdict

    report["summary"] = summary

    print(json.dumps(report, indent=2, default=str))

    # Human-readable closing hint, printed to stderr so it doesn't pollute
    # JSON output if this script's stdout is piped/redirected.
    print("\n--- Quick read ---", file=sys.stderr)
    for fname, verdict in summary.items():
        print(f"  {fname}: {verdict}", file=sys.stderr)
    if not report["file_seed_dir_exists"]:
        print(
            "\n  NOTE: the file_seed directory itself was not found at the resolved path above.\n"
            "  If you can see it in Explorer, the most common cause is that --fixtures-dir\n"
            "  points one level too high or too low. Compare 'resolved_file_seed_dir' above\n"
            "  against the exact path you see in Explorer's address bar.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
