#!/usr/bin/env python3
# =============================================================================
# p7_evidence_inventory_readonly_v1_0.py
# -----------------------------------------------------------------------------
# PHASE:            P7 — Evidence Inventory & Hash Freeze
# AUTHORIZED SCOPE: Read-only hash inventory (STEP 1) + local SHA-256 recompute
#                   (STEP 2) of all P0-P6 / F1 / F2 artifacts across the
#                   Exfil / x_ai_logs / notes roots.
#
# FAIL-CLOSED CONTRACT (enforced by this script):
#   * READ-ONLY. Files are opened strictly in binary read mode ('rb').
#   * NO reruns, NO execution of discovered artifacts, NO modification.
#   * NO attack optimization. This script performs discovery + hashing only.
#   * Missing root / unreadable file  -> recorded as NOT_ESTABLISHED, never
#     silently dropped and never treated as success or as safety.
#   * Absent evidence is labeled NOT_ESTABLISHED, per the frozen evidence rule.
#
# OUTPUT: a hash-bound manifest (JSON + CSV) plus a top-level manifest SHA-256
#         so the reproducibility package can move off PARTIALLY_ESTABLISHED.
#
# NOTE: This runner deliberately does NOT implement STEP 3 (raw /v1/chat/
#       completions capture), STEP 4 (system-prompt fixture resolution write),
#       or STEP 5 (P6C re-run). Those are gated behind P8/P9/P10 and are out of
#       scope for the currently authorized action.
# =============================================================================

import argparse
import csv
import datetime as _dt
import hashlib
import json
import os
import platform
import sys

SCRIPT_ID = "p7_evidence_inventory_readonly_v1_0"
SCRIPT_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Phase classification patterns (filename-substring, case-insensitive).
# Order matters: the FIRST matching rule wins, so more specific phases are
# listed before generic ones. Anything unmatched -> UNCLASSIFIED (NOT a guess).
# ---------------------------------------------------------------------------
PHASE_RULES = [
    ("P6C", ["p6c", "formation_result", "transport_extraction_fix",
             "real_agent_formation", "transport_parser_discovery",
             "module_candidates", "pre_generation", "raw_body_capture"]),
    ("P6B", ["p6b", "raw_transport", "channel_extraction"]),
    ("P6",  ["ex6", "route_binding", "chat_completions", "transport_health"]),
    ("P5",  ["ex5", "gpt_oss", "formation_preflight", "adapter_parse"]),
    ("P4",  ["guardrail", "sink_denial", "post_denied", "secret_marker"]),
    ("P3",  ["candidate_funnel", "v1_14", "v1_15", "direct_marker",
             "fixture_derived"]),
    ("P2",  ["parser_scan", "v1_06", "http_post_matches", "mail_seed",
             "web_corpus"]),
    ("P1",  ["baseline_diagnosis", "baseline"]),
    ("P0",  ["scorer_control", "synthetic", "expected_trace_shape",
             "positive_control"]),
    ("F2",  ["claim_gating", "fail_closed", "design_spec"]),
    ("F1",  ["publication", "ieee"]),
    # SDK / contract core files are cross-phase; classify explicitly.
    ("SDK", ["predicates.py", "sandbox.py", "optimal.py", "attack.py",
             "test.py", "ledger", "sdk_core", "core_contract"]),
]

# ---------------------------------------------------------------------------
# Known scientific status for specific frozen artifacts (from Recommended
# State). Keyed by exact filename (lowercased). Anything not listed here is
# labeled UNVERIFIED_PENDING_REVIEW rather than assigned a status by guess.
# ---------------------------------------------------------------------------
KNOWN_STATUS = {
    "p6c_formation_result_v1_0.json":
        "ESTABLISHED_as_null_at_formation",
    "p6c_transport_extraction_fix_result_v1_4.json":
        "ESTABLISHED_for_transport_parser_qualification_ONLY",
    "p6c_real_agent_formation_test_design_spec_v1_0.md":
        "PRE_REGISTERED_design_spec (fixture system-prompt loc NOT_ESTABLISHED)",
    "ai_agent_security_ieee_baseline.docx":
        "ESTABLISHED_local_prevention",
    "predicates.py": "SDK_CONTRACT_source (verify hash)",
    "sandbox.py":    "SDK_CONTRACT_source (verify hash)",
    "optimal.py":    "SDK_CONTRACT_source (verify hash)",
}

DEFAULT_ROOTS = ["Exfil", "x_ai_logs", "notes"]
DEFAULT_EXCLUDE_DIRS = {".git", "__pycache__", ".ipynb_checkpoints",
                        ".venv", "node_modules"}


def utc_now_iso():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def classify_phase(filename):
    low = filename.lower()
    for phase, needles in PHASE_RULES:
        for n in needles:
            if n in low:
                return phase
    return "UNCLASSIFIED"


def known_status_for(filename):
    return KNOWN_STATUS.get(filename.lower(), "UNVERIFIED_PENDING_REVIEW")


def sha256_of_file(path, chunk_size=1024 * 1024):
    """Read-only streaming SHA-256. Never opens for write. Returns (hex, size)."""
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:            # 'rb' == read-only, fail-closed
        while True:
            block = fh.read(chunk_size)
            if not block:
                break
            h.update(block)
            total += len(block)
    return h.hexdigest(), total


def iso_mtime(path):
    ts = os.path.getmtime(path)
    return _dt.datetime.fromtimestamp(
        ts, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def walk_root(root, exclude_dirs):
    """Yield absolute file paths under root, skipping excluded dirs."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for name in filenames:
            yield os.path.join(dirpath, name)


def build_inventory(roots, base_dir, exclude_dirs):
    records = []
    root_status = []
    counters = {"files": 0, "hashed": 0, "errors": 0, "missing_roots": 0}

    for root in roots:
        abs_root = root if os.path.isabs(root) else os.path.join(base_dir, root)
        if not os.path.isdir(abs_root):
            # Fail-closed: record the gap, do not crash, do not assume safe.
            root_status.append({
                "root": root,
                "resolved_path": abs_root,
                "present": False,
                "status": "NOT_ESTABLISHED_root_absent",
            })
            counters["missing_roots"] += 1
            continue

        root_status.append({
            "root": root,
            "resolved_path": abs_root,
            "present": True,
            "status": "PRESENT",
        })

        for fpath in walk_root(abs_root, exclude_dirs):
            counters["files"] += 1
            fname = os.path.basename(fpath)
            rec = {
                "filename": fname,
                "abs_path": os.path.abspath(fpath),
                "root": root,
                "rel_path": os.path.relpath(fpath, abs_root),
                "phase": classify_phase(fname),
                "scientific_status": known_status_for(fname),
                "size_bytes": None,
                "mtime_utc": None,
                "sha256": None,
                "hash_status": None,
            }
            try:
                rec["mtime_utc"] = iso_mtime(fpath)
                digest, size = sha256_of_file(fpath)
                rec["sha256"] = digest
                rec["size_bytes"] = size
                rec["hash_status"] = "OK"
                counters["hashed"] += 1
            except (OSError, PermissionError) as exc:
                # Fail-closed on unreadable file.
                rec["hash_status"] = "NOT_ESTABLISHED_unreadable"
                rec["error"] = f"{type(exc).__name__}: {exc}"
                counters["errors"] += 1
            records.append(rec)

    # Deterministic ordering for reproducible manifest hashing.
    records.sort(key=lambda r: (r["root"], r["rel_path"], r["filename"]))
    return records, root_status, counters


def manifest_self_hash(manifest_without_hash):
    """Canonical-JSON SHA-256 of the manifest body (excluding the field itself)."""
    canonical = json.dumps(manifest_without_hash, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def write_csv(records, csv_path):
    cols = ["root", "rel_path", "filename", "phase", "scientific_status",
            "size_bytes", "mtime_utc", "sha256", "hash_status"]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in records:
            w.writerow(r)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="P7 read-only evidence inventory + SHA-256 recompute "
                    "(no reruns, no modification).")
    ap.add_argument("--base-dir", default=os.getcwd(),
                    help="Base directory that contains the roots "
                         "(default: current working directory).")
    ap.add_argument("--roots", nargs="*", default=DEFAULT_ROOTS,
                    help="Root folders to inventory "
                         "(default: Exfil x_ai_logs notes). "
                         "Absolute paths are honored as-is.")
    ap.add_argument("--out-dir", default=os.getcwd(),
                    help="Directory to write manifest JSON/CSV "
                         "(default: current working directory).")
    ap.add_argument("--tag", default="v1_0",
                    help="Version tag appended to output filenames.")
    args = ap.parse_args(argv)

    os.makedirs(args.out_dir, exist_ok=True)

    started = utc_now_iso()
    records, root_status, counters = build_inventory(
        args.roots, args.base_dir, DEFAULT_EXCLUDE_DIRS)
    finished = utc_now_iso()

    # Phase + status roll-ups for a quick reviewer-facing summary.
    by_phase, by_status = {}, {}
    for r in records:
        by_phase[r["phase"]] = by_phase.get(r["phase"], 0) + 1
        by_status[r["scientific_status"]] = \
            by_status.get(r["scientific_status"], 0) + 1

    manifest_body = {
        "script_id": SCRIPT_ID,
        "script_version": SCRIPT_VERSION,
        "authorized_scope": "P7 read-only inventory + SHA-256 recompute",
        "read_only": True,
        "reran_artifacts": False,
        "modified_artifacts": False,
        "evidence_rule": "Absent/unreadable evidence -> NOT_ESTABLISHED.",
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "run": {
            "base_dir": os.path.abspath(args.base_dir),
            "roots_requested": args.roots,
            "started_utc": started,
            "finished_utc": finished,
        },
        "root_status": root_status,
        "counters": counters,
        "rollup_by_phase": by_phase,
        "rollup_by_scientific_status": by_status,
        "records": records,
    }
    manifest_body["manifest_sha256"] = manifest_self_hash(manifest_body)

    json_path = os.path.join(args.out_dir,
                             f"p7_evidence_inventory_manifest_{args.tag}.json")
    csv_path = os.path.join(args.out_dir,
                            f"p7_evidence_inventory_manifest_{args.tag}.csv")

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(manifest_body, fh, indent=2, ensure_ascii=False)
    write_csv(records, csv_path)

    # Reviewer-facing console summary (stdout only; no artifact mutation).
    print("=" * 70)
    print(f"{SCRIPT_ID}  (READ-ONLY)")
    print("=" * 70)
    print(f"Base dir        : {os.path.abspath(args.base_dir)}")
    print(f"Roots requested : {args.roots}")
    for rs in root_status:
        flag = "PRESENT" if rs["present"] else "ABSENT -> NOT_ESTABLISHED"
        print(f"  - {rs['root']:<12} {flag}")
    print("-" * 70)
    print(f"Files seen      : {counters['files']}")
    print(f"Hashed OK       : {counters['hashed']}")
    print(f"Unreadable      : {counters['errors']}  (NOT_ESTABLISHED)")
    print(f"Missing roots   : {counters['missing_roots']}")
    print("-" * 70)
    print("By phase        :", dict(sorted(by_phase.items())))
    print("-" * 70)
    print(f"Manifest SHA-256: {manifest_body['manifest_sha256']}")
    print(f"JSON manifest   : {json_path}")
    print(f"CSV manifest    : {csv_path}")
    print("=" * 70)

    # Exit code discipline: non-zero if any fail-closed condition triggered,
    # so a wrapper/CI cannot mistake a partial run for a clean pass.
    if counters["errors"] > 0 or counters["missing_roots"] > 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
