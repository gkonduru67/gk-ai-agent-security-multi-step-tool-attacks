#!/usr/bin/env python3
# =============================================================================
# p7_evidence_inventory_readonly_v1_1.py
# -----------------------------------------------------------------------------
# PHASE:            P7 - Evidence Inventory & Hash Freeze
# AUTHORIZED SCOPE: Read-only hash inventory (STEP 1) + local SHA-256 recompute
#                   (STEP 2) of all P0-P6 / F1 / F2 artifacts across roots that
#                   may live at DIFFERENT absolute locations
#                   (e.g. Exfil under the project dir, x_ai_logs at C:\x_ai_logs,
#                    notes one level above the project dir).
#
# WHY v1_1 (vs v1_0):
#   v1_0 joined EVERY root to a single --base-dir. Your three roots live under
#   three different parents, so x_ai_logs and notes were (correctly) flagged
#   NOT_ESTABLISHED_root_absent. v1_1 lets each root carry its OWN absolute path
#   via --root LABEL=PATH, while keeping a clean short label in the manifest.
#   It also hardens Windows file reads against:
#     (a) long paths (>260 chars) via the \\?\ extended-length prefix, and
#     (b) OneDrive "Files On-Demand" cloud-only placeholders, which os.walk can
#         enumerate but open() cannot read when offline/unhydrated. These are
#         labeled distinctly so a placeholder is never confused with a truly
#         missing artifact.
#
# FAIL-CLOSED CONTRACT (unchanged, enforced):
#   * READ-ONLY. Files opened strictly 'rb'. No reruns, no execution, no writes
#     to any discovered artifact.
#   * No attack optimization. Discovery + hashing only.
#   * Missing root / unreadable file -> NOT_ESTABLISHED, never dropped, never
#     treated as success or as safety.
#   * Non-zero exit code if ANY gap (missing root / unreadable file) is present,
#     so a wrapper cannot mistake a partial run for a clean pass.
#
# OUT OF SCOPE (gated behind P8/P9/P10; deliberately NOT implemented here):
#   STEP 3 raw /v1/chat/completions capture; STEP 4 system-prompt fixture write;
#   STEP 5 P6C re-run.
# =============================================================================

import argparse
import csv
import datetime as _dt
import hashlib
import json
import os
import platform
import sys

SCRIPT_ID = "p7_evidence_inventory_readonly_v1_1"
SCRIPT_VERSION = "1.1"

IS_WINDOWS = (os.name == "nt")

# ---------------------------------------------------------------------------
# Phase classification patterns (filename-substring, case-insensitive).
# First match wins; more specific phases first. Unmatched -> UNCLASSIFIED.
# NOTE: this is a filename HEURISTIC to seed review, not ground truth. Hashes
# are authoritative; phase labels are a first-pass draft for you to tune.
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
    ("SDK", ["predicates.py", "sandbox.py", "optimal.py", "attack.py",
             "test.py", "ledger", "sdk_core", "core_contract"]),
]

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

# Default label->relative mapping used only in legacy --base-dir mode.
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


def long_path(p):
    r"""Return a Windows extended-length path (\\?\...) so open()/stat() work
    past the legacy 260-char MAX_PATH limit. No-op on non-Windows or if the
    prefix is already present. UNC paths get the \\?\UNC\ form."""
    if not IS_WINDOWS:
        return p
    p = os.path.abspath(p)
    if p.startswith("\\\\?\\"):
        return p
    if p.startswith("\\\\"):                       # UNC \\server\share
        return "\\\\?\\UNC\\" + p[2:]
    return "\\\\?\\" + p


def is_cloud_placeholder(path):
    """Best-effort detection of a OneDrive/Files-On-Demand cloud-only stub.
    Such files enumerate via os.walk but can't be read while unhydrated.
    Detected via FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS (0x400000) or
    RECALL_ON_OPEN (0x40000) / OFFLINE (0x1000). Returns True/False/None."""
    if not IS_WINDOWS:
        return None
    try:
        attrs = os.stat(path, follow_symlinks=False).st_file_attributes
    except (OSError, AttributeError):
        return None
    RECALL_ON_DATA_ACCESS = 0x00400000
    RECALL_ON_OPEN = 0x00040000
    OFFLINE = 0x00001000
    return bool(attrs & (RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN | OFFLINE))


def sha256_of_file(path, chunk_size=1024 * 1024):
    """Read-only streaming SHA-256. 'rb' only. Returns (hex, size)."""
    h = hashlib.sha256()
    total = 0
    with open(long_path(path), "rb") as fh:
        while True:
            block = fh.read(chunk_size)
            if not block:
                break
            h.update(block)
            total += len(block)
    return h.hexdigest(), total


def iso_mtime(path):
    ts = os.path.getmtime(long_path(path))
    return _dt.datetime.fromtimestamp(
        ts, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def walk_root(abs_root, exclude_dirs):
    for dirpath, dirnames, filenames in os.walk(abs_root):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for name in filenames:
            yield os.path.join(dirpath, name)


def parse_root_specs(root_args, roots_legacy, base_dir):
    """Build an ordered list of (label, abs_path) pairs.

    Priority:
      1) --root LABEL=PATH  (repeatable)  -> label + explicit absolute path
      2) --root PATH        (repeatable)  -> basename label + that path
      3) legacy --roots names + --base-dir (each name joined to base-dir)
         (absolute names honored as-is, basename as label)
    """
    specs = []
    for item in (root_args or []):
        if "=" in item:
            label, path = item.split("=", 1)
            label, path = label.strip(), path.strip()
        else:
            path = item.strip()
            label = os.path.basename(os.path.normpath(path)) or path
        specs.append((label, os.path.abspath(os.path.expanduser(path))))

    if not specs:  # legacy behavior
        for name in (roots_legacy or DEFAULT_ROOTS):
            if os.path.isabs(name):
                specs.append((os.path.basename(os.path.normpath(name)),
                              os.path.abspath(name)))
            else:
                specs.append((name, os.path.abspath(os.path.join(base_dir,
                                                                 name))))
    return specs


def build_inventory(root_specs, exclude_dirs):
    records = []
    root_status = []
    counters = {"files": 0, "hashed": 0, "errors": 0,
                "cloud_placeholders": 0, "missing_roots": 0}
    seen_labels = {}

    for label, abs_root in root_specs:
        # De-duplicate identical labels pointing at different paths.
        if label in seen_labels and seen_labels[label] != abs_root:
            label = f"{label}#{sum(1 for l in seen_labels if l.split('#')[0] == label) + 1}"
        seen_labels[label] = abs_root

        if not os.path.isdir(long_path(abs_root)):
            root_status.append({
                "root": label, "resolved_path": abs_root,
                "present": False, "status": "NOT_ESTABLISHED_root_absent",
            })
            counters["missing_roots"] += 1
            continue

        root_status.append({
            "root": label, "resolved_path": abs_root,
            "present": True, "status": "PRESENT",
        })

        for fpath in walk_root(abs_root, exclude_dirs):
            counters["files"] += 1
            fname = os.path.basename(fpath)
            rec = {
                "filename": fname,
                "abs_path": os.path.abspath(fpath),
                "root": label,
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
                cloud = is_cloud_placeholder(fpath)
                if cloud:
                    rec["hash_status"] = "NOT_ESTABLISHED_cloud_placeholder"
                    counters["cloud_placeholders"] += 1
                else:
                    rec["hash_status"] = "NOT_ESTABLISHED_unreadable"
                rec["error"] = f"{type(exc).__name__}: {exc}"
                rec["cloud_placeholder"] = cloud
                counters["errors"] += 1
            records.append(rec)

    records.sort(key=lambda r: (r["root"], r["rel_path"], r["filename"]))
    return records, root_status, counters


def manifest_self_hash(manifest_without_hash):
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
        description="P7 read-only evidence inventory + SHA-256 recompute for "
                    "roots at DIFFERENT absolute locations (no reruns, no "
                    "modification).")
    ap.add_argument(
        "--root", action="append", metavar="LABEL=PATH", default=[],
        help="Repeatable. A root to inventory, as LABEL=PATH (clean label + "
             "explicit absolute path), or just PATH (basename becomes label). "
             "Use one per real location, e.g. "
             '--root "Exfil=C:\\...\\Exfil" '
             '--root "x_ai_logs=C:\\x_ai_logs" '
             '--root "notes=C:\\...\\Jun11-Sep1\\notes".')
    ap.add_argument(
        "--roots", nargs="*", default=None,
        help="Legacy mode: bare names joined to --base-dir (Exfil x_ai_logs "
             "notes). Ignored if any --root is given.")
    ap.add_argument(
        "--base-dir", default=os.getcwd(),
        help="Legacy mode base dir for --roots (default: cwd).")
    ap.add_argument("--out-dir", default=os.getcwd(),
                    help="Directory for manifest JSON/CSV (default: cwd).")
    ap.add_argument("--tag", default="v1_1",
                    help="Version tag appended to output filenames.")
    args = ap.parse_args(argv)

    os.makedirs(args.out_dir, exist_ok=True)

    root_specs = parse_root_specs(args.root, args.roots, args.base_dir)

    started = utc_now_iso()
    records, root_status, counters = build_inventory(
        root_specs, DEFAULT_EXCLUDE_DIRS)
    finished = utc_now_iso()

    by_phase, by_status = {}, {}
    for r in records:
        by_phase[r["phase"]] = by_phase.get(r["phase"], 0) + 1
        by_status[r["hash_status"]] = by_status.get(r["hash_status"], 0) + 1

    manifest_body = {
        "script_id": SCRIPT_ID,
        "script_version": SCRIPT_VERSION,
        "authorized_scope": "P7 read-only inventory + SHA-256 recompute",
        "read_only": True,
        "reran_artifacts": False,
        "modified_artifacts": False,
        "evidence_rule": "Absent/unreadable/cloud-placeholder -> NOT_ESTABLISHED.",
        "host": {"platform": platform.platform(),
                 "python": platform.python_version(),
                 "is_windows": IS_WINDOWS},
        "run": {"root_specs": [{"label": l, "path": p} for l, p in root_specs],
                "started_utc": started, "finished_utc": finished},
        "root_status": root_status,
        "counters": counters,
        "rollup_by_phase": by_phase,
        "rollup_by_hash_status": by_status,
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

    print("=" * 72)
    print(f"{SCRIPT_ID}  (READ-ONLY)")
    print("=" * 72)
    for rs in root_status:
        flag = "PRESENT" if rs["present"] else "ABSENT -> NOT_ESTABLISHED"
        print(f"  {rs['root']:<14} {flag}")
        print(f"      {rs['resolved_path']}")
    print("-" * 72)
    print(f"Files seen         : {counters['files']}")
    print(f"Hashed OK          : {counters['hashed']}")
    print(f"Unreadable         : {counters['errors'] - counters['cloud_placeholders']}"
          "  (NOT_ESTABLISHED_unreadable)")
    print(f"Cloud placeholders : {counters['cloud_placeholders']}"
          "  (NOT_ESTABLISHED_cloud_placeholder)")
    print(f"Missing roots      : {counters['missing_roots']}")
    print("-" * 72)
    print("By phase           :", dict(sorted(by_phase.items())))
    print("-" * 72)
    print(f"Manifest SHA-256   : {manifest_body['manifest_sha256']}")
    print(f"JSON manifest      : {json_path}")
    print(f"CSV manifest       : {csv_path}")
    print("=" * 72)

    if (counters["errors"] > 0 or counters["missing_roots"] > 0):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
