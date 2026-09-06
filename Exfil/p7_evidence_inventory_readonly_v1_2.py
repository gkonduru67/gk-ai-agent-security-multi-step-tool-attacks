#!/usr/bin/env python3
# =============================================================================
# p7_evidence_inventory_readonly_v1_2.py
# -----------------------------------------------------------------------------
# PHASE:            P7 - Evidence Inventory & Hash Freeze (re-run upgrade)
# AUTHORIZED SCOPE: Read-only inventory + SHA-256 recompute, PLUS three
#                   scoped-and-authorized upgrades over v1_1:
#     (a) NOISE FILTER: exclude any path containing a Python bytecode / package
#         cache component ANYWHERE in the tree (__pycache__, *.pyc, *.pyo,
#         site-packages, .egg-info, dist-info). v1_1 only matched an exact
#         top-level dir name, so a NESTED/renamed cache mirror slipped in and
#         inflated UNCLASSIFIED to 2240. This closes that leak.
#     (b) OUT-OF-CLASS TAGGING: optionally tag CD / DW / UTA artifacts (the
#         frozen prior classes) as class_scope=OUT_OF_CLASS so the EXFILTRATION
#         rollup is clean. These files are NOT deleted or hidden - only labeled,
#         so provenance/chain-of-custody is preserved.
#     (c) VERIFY-AGAINST: diff freshly computed SHA-256s against a prior
#         manifest (e.g. v1_1) to detect DRIFT / NEW / REMOVED artifacts, and
#         to FREEZE the two frozen-evidence hashes as a baseline assertion.
#
# STILL FAIL-CLOSED, STILL READ-ONLY:
#   * Files opened strictly 'rb'. No reruns, no execution, no writes to any
#     discovered artifact. Only the manifest JSON/CSV are written to --out-dir.
#   * Missing root / unreadable file / cloud placeholder -> NOT_ESTABLISHED.
#   * Baseline FROZEN-hash mismatch, or any drift when --fail-on-drift is set,
#     forces a non-zero exit so a wrapper cannot mistake it for a clean pass.
#
# EXPLICITLY OUT OF SCOPE (gated behind P8/P9/P10, NOT implemented here):
#   * P8 fixture-identity CLOSURE writes (freezing secret.txt/predicates/etc).
#     v1_2 only REPORTS candidate fixture identities read-only; it never freezes.
#   * STEP 3 raw /v1/chat/completions capture; STEP 5 P6C re-run.
# =============================================================================

import argparse
import csv
import datetime as _dt
import hashlib
import json
import os
import platform
import re
import sys

SCRIPT_ID = "p7_evidence_inventory_readonly_v1_2"
SCRIPT_VERSION = "1.2"
IS_WINDOWS = (os.name == "nt")

# ---------------------------------------------------------------------------
# (a) NOISE FILTER - path-component / suffix rules applied to EVERY file's full
# path, case-insensitive. A file is excluded if ANY of these hit. Directory
# components are also pruned during the walk for speed.
# ---------------------------------------------------------------------------
NOISE_DIR_COMPONENTS = {
    "__pycache__", "site-packages", ".ipynb_checkpoints", ".git",
    ".venv", "venv", "node_modules", ".mypy_cache", ".pytest_cache",
}
NOISE_DIR_SUFFIXES = (".egg-info", ".dist-info")          # dir name endswith
NOISE_FILE_SUFFIXES = (".pyc", ".pyo", ".pyd")            # file name endswith

# ---------------------------------------------------------------------------
# (b) OUT-OF-CLASS TAGGING - prior frozen classes. Detected by a path-component
# match (root label or any directory named exactly CD/DW/UTA), so we do not
# accidentally catch substrings inside longer names.
# ---------------------------------------------------------------------------
OUT_OF_CLASS_COMPONENTS = {"cd", "dw", "uta"}
IN_CLASS_HINTS = ("exfil",)   # a path clearly under an Exfil tree stays in-class

# ---------------------------------------------------------------------------
# Phase classification (filename-substring heuristic). First match wins.
# Hashes are authoritative; phase labels are a review DRAFT.
# ---------------------------------------------------------------------------
PHASE_RULES = [
    ("P7",  ["p7_evidence_inventory"]),
    ("P6C", ["p6c", "formation_result", "transport_extraction_fix",
             "real_agent_formation", "transport_parser_discovery",
             "module_candidates", "pre_generation", "raw_body_capture",
             "fixture_and_task_prompt_freeze"]),
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

# Frozen-evidence baseline: these filenames carry an ESTABLISHED status and
# MUST NOT drift. If --verify-against is supplied and their hash differs from
# the prior manifest, that is a hard fail (fail-closed on frozen evidence).
FROZEN_EVIDENCE_FILENAMES = {
    "p6c_formation_result_v1_0.json",
    "p6c_transport_extraction_fix_result_v1_4.json",
}

# P8 candidate fixtures to REPORT (read-only) - never frozen here.
P8_FIXTURE_FILENAMES = {
    "secret.txt", "frozen_system_prompt.txt",
    "predicates.py", "sandbox.py", "optimal.py",
}

DEFAULT_EXCLUDE_DIRS = set(NOISE_DIR_COMPONENTS)


def utc_now_iso():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def norm_components(path):
    """Lower-cased path components, split on both separators."""
    return [c for c in re.split(r"[\\/]+", path) if c]


def is_noise_path(full_path):
    """(a) True if the file is Python bytecode / package-cache noise anywhere."""
    low = full_path.lower()
    comps = norm_components(low)
    for c in comps:
        if c in NOISE_DIR_COMPONENTS:
            return True
        if c.endswith(NOISE_DIR_SUFFIXES):
            return True
    if low.endswith(NOISE_FILE_SUFFIXES):
        return True
    return False


def class_scope_for(full_path):
    """(b) IN_CLASS vs OUT_OF_CLASS by path component (CD/DW/UTA)."""
    comps = [c.lower() for c in norm_components(full_path)]
    if any(h in c for h in IN_CLASS_HINTS for c in comps):
        # A path that lives under an Exfil tree is in-class even if a token
        # like 'cd' appears elsewhere; Exfil hint wins.
        if not any(c in OUT_OF_CLASS_COMPONENTS for c in comps):
            return "IN_CLASS"
    if any(c in OUT_OF_CLASS_COMPONENTS for c in comps):
        return "OUT_OF_CLASS"
    return "IN_CLASS"


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
    r"""Windows extended-length (\\?\) prefix so open()/stat() beat MAX_PATH."""
    if not IS_WINDOWS:
        return p
    p = os.path.abspath(p)
    if p.startswith("\\\\?\\"):
        return p
    if p.startswith("\\\\"):
        return "\\\\?\\UNC\\" + p[2:]
    return "\\\\?\\" + p


def is_cloud_placeholder(path):
    if not IS_WINDOWS:
        return None
    try:
        attrs = os.stat(long_path(path), follow_symlinks=False).st_file_attributes
    except (OSError, AttributeError):
        return None
    RECALL_ON_DATA_ACCESS = 0x00400000
    RECALL_ON_OPEN = 0x00040000
    OFFLINE = 0x00001000
    return bool(attrs & (RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN | OFFLINE))


def sha256_of_file(path, chunk_size=1024 * 1024):
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


def walk_root(abs_root):
    for dirpath, dirnames, filenames in os.walk(abs_root):
        # Prune noise dirs (incl. *.egg-info / *.dist-info) during the walk.
        kept = []
        for d in dirnames:
            dl = d.lower()
            if dl in NOISE_DIR_COMPONENTS or dl.endswith(NOISE_DIR_SUFFIXES):
                continue
            kept.append(d)
        dirnames[:] = kept
        for name in filenames:
            yield os.path.join(dirpath, name)


def parse_root_specs(root_args, roots_legacy, base_dir):
    specs = []
    for item in (root_args or []):
        if "=" in item:
            label, path = item.split("=", 1)
            label, path = label.strip(), path.strip()
        else:
            path = item.strip()
            label = os.path.basename(os.path.normpath(path)) or path
        specs.append((label, os.path.abspath(os.path.expanduser(path))))
    if not specs:
        for name in (roots_legacy or ["Exfil", "x_ai_logs", "notes"]):
            if os.path.isabs(name):
                specs.append((os.path.basename(os.path.normpath(name)),
                              os.path.abspath(name)))
            else:
                specs.append((name, os.path.abspath(os.path.join(base_dir, name))))
    return specs


def load_prior_manifest(path):
    """(c) Load prior manifest -> {sha256_by_key, keys_set}. Read-only."""
    with open(path, "r", encoding="utf-8") as fh:
        m = json.load(fh)
    by_key = {}
    for r in m.get("records", []):
        key = (r.get("root", ""), r.get("rel_path", ""))
        by_key[key] = {
            "sha256": r.get("sha256"),
            "filename": r.get("filename"),
            "hash_status": r.get("hash_status"),
        }
    return by_key


def build_inventory(root_specs, tag_out_of_class):
    records = []
    root_status = []
    counters = {"files_seen_raw": 0, "files": 0, "noise_skipped": 0,
                "hashed": 0, "errors": 0, "cloud_placeholders": 0,
                "missing_roots": 0, "out_of_class": 0}
    seen_labels = {}

    for label, abs_root in root_specs:
        if label in seen_labels and seen_labels[label] != abs_root:
            label = f"{label}#{len(seen_labels) + 1}"
        seen_labels[label] = abs_root

        if not os.path.isdir(long_path(abs_root)):
            root_status.append({"root": label, "resolved_path": abs_root,
                                "present": False,
                                "status": "NOT_ESTABLISHED_root_absent"})
            counters["missing_roots"] += 1
            continue

        root_status.append({"root": label, "resolved_path": abs_root,
                            "present": True, "status": "PRESENT"})

        for fpath in walk_root(abs_root):
            counters["files_seen_raw"] += 1
            if is_noise_path(fpath):
                counters["noise_skipped"] += 1
                continue
            counters["files"] += 1

            fname = os.path.basename(fpath)
            scope = class_scope_for(fpath) if tag_out_of_class else "IN_CLASS"
            if scope == "OUT_OF_CLASS":
                counters["out_of_class"] += 1

            rec = {
                "filename": fname,
                "abs_path": os.path.abspath(fpath),
                "root": label,
                "rel_path": os.path.relpath(fpath, abs_root),
                "phase": classify_phase(fname),
                "class_scope": scope,
                "scientific_status": known_status_for(fname),
                "size_bytes": None, "mtime_utc": None,
                "sha256": None, "hash_status": None,
            }
            try:
                rec["mtime_utc"] = iso_mtime(fpath)
                digest, size = sha256_of_file(fpath)
                rec["sha256"], rec["size_bytes"] = digest, size
                rec["hash_status"] = "OK"
                counters["hashed"] += 1
            except (OSError, PermissionError) as exc:
                cloud = is_cloud_placeholder(fpath)
                rec["hash_status"] = ("NOT_ESTABLISHED_cloud_placeholder"
                                      if cloud else "NOT_ESTABLISHED_unreadable")
                if cloud:
                    counters["cloud_placeholders"] += 1
                rec["error"] = f"{type(exc).__name__}: {exc}"
                rec["cloud_placeholder"] = cloud
                counters["errors"] += 1
            records.append(rec)

    records.sort(key=lambda r: (r["root"], r["rel_path"], r["filename"]))
    return records, root_status, counters


def diff_against_prior(records, prior_by_key):
    """(c) Return drift report + frozen-evidence verification."""
    fresh_keys = set()
    drift = {"changed": [], "unchanged": 0, "new": [], "removed": [],
             "frozen_verified": [], "frozen_mismatch": []}

    for r in records:
        key = (r["root"], r["rel_path"])
        fresh_keys.add(key)
        prior = prior_by_key.get(key)
        is_frozen = r["filename"].lower() in FROZEN_EVIDENCE_FILENAMES
        if prior is None:
            drift["new"].append(r["rel_path"])
            continue
        if prior["sha256"] == r["sha256"] and r["sha256"] is not None:
            drift["unchanged"] += 1
            if is_frozen:
                drift["frozen_verified"].append(
                    {"file": r["filename"], "sha256": r["sha256"]})
        else:
            entry = {"file": r["filename"], "rel_path": r["rel_path"],
                     "prior_sha256": prior["sha256"], "fresh_sha256": r["sha256"]}
            drift["changed"].append(entry)
            if is_frozen:
                drift["frozen_mismatch"].append(entry)

    for key in prior_by_key:
        if key not in fresh_keys:
            drift["removed"].append(key[1])

    return drift


def collect_p8_candidates(records):
    """Read-only REPORT of P8 fixture candidates grouped by SHA-256.
    Never freezes; just surfaces duplicates so YOU can pick the authoritative
    copy in the P8 phase."""
    out = {}
    for r in records:
        if r["filename"].lower() in P8_FIXTURE_FILENAMES and r["sha256"]:
            out.setdefault(r["filename"].lower(), {}).setdefault(
                r["sha256"], []).append(r["abs_path"])
    report = {}
    for fname, by_hash in out.items():
        report[fname] = {
            "distinct_hashes": len(by_hash),
            "copies": [{"sha256": h, "count": len(paths), "paths": paths}
                       for h, paths in sorted(by_hash.items())],
            "note": ("SINGLE authoritative candidate" if len(by_hash) == 1
                     else "MULTIPLE distinct hashes -> resolve in P8 (read-only here)"),
        }
    return report


def manifest_self_hash(body):
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def write_csv(records, csv_path):
    cols = ["root", "rel_path", "filename", "phase", "class_scope",
            "scientific_status", "size_bytes", "mtime_utc", "sha256",
            "hash_status"]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in records:
            w.writerow(r)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="P7 v1_2 read-only inventory with noise filter, "
                    "out-of-class tagging, and verify-against drift diff.")
    ap.add_argument("--root", action="append", metavar="LABEL=PATH", default=[],
                    help="Repeatable root as LABEL=PATH or PATH.")
    ap.add_argument("--roots", nargs="*", default=None,
                    help="Legacy: bare names joined to --base-dir.")
    ap.add_argument("--base-dir", default=os.getcwd())
    ap.add_argument("--out-dir", default=os.getcwd())
    ap.add_argument("--tag", default="v1_2")
    ap.add_argument("--tag-out-of-class", action="store_true",
                    help="(b) Tag CD/DW/UTA paths as class_scope=OUT_OF_CLASS.")
    ap.add_argument("--verify-against", default=None, metavar="PRIOR.json",
                    help="(c) Prior manifest JSON to diff SHA-256s against.")
    ap.add_argument("--fail-on-drift", action="store_true",
                    help="Non-zero exit if ANY changed/new/removed vs prior.")
    args = ap.parse_args(argv)

    os.makedirs(args.out_dir, exist_ok=True)
    root_specs = parse_root_specs(args.root, args.roots, args.base_dir)

    started = utc_now_iso()
    records, root_status, counters = build_inventory(
        root_specs, args.tag_out_of_class)
    finished = utc_now_iso()

    # Rollups. EXFILTRATION rollup counts IN_CLASS only when tagging is on.
    by_phase_all, by_phase_inclass, by_status, by_scope = {}, {}, {}, {}
    for r in records:
        by_phase_all[r["phase"]] = by_phase_all.get(r["phase"], 0) + 1
        by_status[r["hash_status"]] = by_status.get(r["hash_status"], 0) + 1
        by_scope[r["class_scope"]] = by_scope.get(r["class_scope"], 0) + 1
        if r["class_scope"] == "IN_CLASS":
            by_phase_inclass[r["phase"]] = by_phase_inclass.get(r["phase"], 0) + 1

    drift = None
    if args.verify_against:
        prior = load_prior_manifest(args.verify_against)
        drift = diff_against_prior(records, prior)

    p8_candidates = collect_p8_candidates(records)

    body = {
        "script_id": SCRIPT_ID, "script_version": SCRIPT_VERSION,
        "authorized_scope": "P7 read-only inventory + SHA-256 + noise filter + "
                            "out-of-class tag + verify-against (no writes to "
                            "artifacts, no P8 freeze, no reruns)",
        "read_only": True, "reran_artifacts": False, "modified_artifacts": False,
        "froze_fixtures": False,
        "evidence_rule": "Absent/unreadable/cloud-placeholder -> NOT_ESTABLISHED.",
        "options": {"tag_out_of_class": args.tag_out_of_class,
                    "verify_against": args.verify_against,
                    "fail_on_drift": args.fail_on_drift},
        "host": {"platform": platform.platform(),
                 "python": platform.python_version(), "is_windows": IS_WINDOWS},
        "run": {"root_specs": [{"label": l, "path": p} for l, p in root_specs],
                "started_utc": started, "finished_utc": finished},
        "root_status": root_status,
        "counters": counters,
        "rollup_by_phase_all": by_phase_all,
        "rollup_by_phase_in_class": by_phase_inclass,
        "rollup_by_class_scope": by_scope,
        "rollup_by_hash_status": by_status,
        "verify_against": drift,
        "p8_fixture_candidates_readonly": p8_candidates,
        "records": records,
    }
    body["manifest_sha256"] = manifest_self_hash(body)

    json_path = os.path.join(args.out_dir,
                             f"p7_evidence_inventory_manifest_{args.tag}.json")
    csv_path = os.path.join(args.out_dir,
                            f"p7_evidence_inventory_manifest_{args.tag}.csv")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(body, fh, indent=2, ensure_ascii=False)
    write_csv(records, csv_path)

    # ---- console summary ----
    print("=" * 74)
    print(f"{SCRIPT_ID}  (READ-ONLY)")
    print("=" * 74)
    for rs in root_status:
        flag = "PRESENT" if rs["present"] else "ABSENT -> NOT_ESTABLISHED"
        print(f"  {rs['root']:<14} {flag}  {rs['resolved_path']}")
    print("-" * 74)
    print(f"Raw files walked   : {counters['files_seen_raw']}")
    print(f"Noise skipped      : {counters['noise_skipped']}  "
          "(.pyc/__pycache__/site-packages/etc)")
    print(f"Files inventoried  : {counters['files']}")
    print(f"Hashed OK          : {counters['hashed']}")
    print(f"Unreadable         : {counters['errors'] - counters['cloud_placeholders']}")
    print(f"Cloud placeholders : {counters['cloud_placeholders']}")
    print(f"Missing roots      : {counters['missing_roots']}")
    if args.tag_out_of_class:
        print(f"OUT_OF_CLASS (CD/DW/UTA): {counters['out_of_class']}")
    print("-" * 74)
    print("Phase (ALL)        :", dict(sorted(by_phase_all.items())))
    if args.tag_out_of_class:
        print("Phase (IN_CLASS)   :", dict(sorted(by_phase_inclass.items())))
    print("-" * 74)
    if drift is not None:
        print("VERIFY-AGAINST (vs prior manifest):")
        print(f"  unchanged        : {drift['unchanged']}")
        print(f"  changed (drift)  : {len(drift['changed'])}")
        print(f"  new              : {len(drift['new'])}")
        print(f"  removed          : {len(drift['removed'])}")
        print(f"  FROZEN verified  : {len(drift['frozen_verified'])}")
        print(f"  FROZEN mismatch  : {len(drift['frozen_mismatch'])}  "
              "(MUST be 0)")
        for fv in drift["frozen_verified"]:
            print(f"    OK  {fv['file']}  {fv['sha256'][:16]}...")
        for fm in drift["frozen_mismatch"]:
            print(f"    !!  {fm['file']}  prior={str(fm['prior_sha256'])[:12]} "
                  f"fresh={str(fm['fresh_sha256'])[:12]}")
        print("-" * 74)
    if p8_candidates:
        print("P8 FIXTURE CANDIDATES (read-only report; NOT frozen):")
        for fname, info in sorted(p8_candidates.items()):
            print(f"  {fname:<24} distinct_hashes={info['distinct_hashes']}  "
                  f"-> {info['note']}")
        print("-" * 74)
    print(f"Manifest SHA-256   : {body['manifest_sha256']}")
    print(f"JSON manifest      : {json_path}")
    print(f"CSV manifest       : {csv_path}")
    print("=" * 74)

    # ---- fail-closed exit discipline ----
    exit_code = 0
    if counters["errors"] > 0 or counters["missing_roots"] > 0:
        exit_code = 2
    if drift is not None and drift["frozen_mismatch"]:
        # Frozen evidence drift is ALWAYS a hard fail.
        exit_code = 3
    if args.fail_on_drift and drift is not None and (
            drift["changed"] or drift["new"] or drift["removed"]):
        exit_code = max(exit_code, 4)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
