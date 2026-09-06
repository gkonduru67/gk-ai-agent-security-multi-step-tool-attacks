#!/usr/bin/env python3
# =============================================================================
# p8_toolsuite_locator_v1_1.py
# -----------------------------------------------------------------------------
# PHASE:            P8 - Fixture Identity Closure (read-only symbol locator)
# AUTHORIZED SCOPE: Locate the REAL ToolSuite / fs-runtime factory by scanning
#                   .py source under a root for a BROAD set of loader symbols,
#                   then (optionally) feed the top candidates into the P8 static
#                   inspector's loader classifier. READ-ONLY throughout.
#
# WHY v1_1 (vs guessing a path): the prior inspector run failed with
#   NOT_ESTABLISHED_file_missing because core/env/tools/__init__.py + state.py
#   were not at the guessed path, and the user reports NOT seeing fs_backup /
#   fs_workspace at all. So we must DISCOVER the factory by symbol evidence
#   instead of assuming a filename. We search a superset of names:
#     class ToolSuite, ToolRuntimeState, ToolContext, fs_backup, fs_workspace,
#     fs_root, filesystem_root, isolate_fs, TemporaryDirectory, mkdtemp,
#     read_text/read_bytes/copytree (copy signals), secrets/token_hex (seed
#     signals), canonical_source_path (guardrail path helper), etc.
#
# SAFETY (same contract as the inspector):
#   * ast.parse ONLY for structure; plain text scan for symbol lines. NEVER
#     imports or executes any target module. Zero side effects.
#   * Target files opened 'r'/'rb' only. Only the REPORT is written to out-dir.
#   * Every scanned hit file is SHA-256 hash-bound (chain-of-custody).
#   * Noise excluded anywhere in path: __pycache__, *.pyc/.pyo, site-packages,
#     .egg-info, .dist-info, .git, .venv (same rule family as P7 v1_2).
#   * Fail-closed: if zero strong candidates, exit non-zero (do NOT pretend the
#     loader was found).
#
# OUT OF SCOPE: no runtime, no fixture materialization, no P6C rerun.
# =============================================================================

import argparse
import ast
import datetime as _dt
import hashlib
import json
import os
import re
import sys

SCRIPT_ID = "p8_toolsuite_locator_v1_1"
SCRIPT_VERSION = "1.1"

# --- noise exclusion (path-component / suffix), same family as P7 v1_2 ---
NOISE_DIR_COMPONENTS = {"__pycache__", "site-packages", ".ipynb_checkpoints",
                        ".git", ".venv", "venv", "node_modules",
                        ".mypy_cache", ".pytest_cache"}
NOISE_DIR_SUFFIXES = (".egg-info", ".dist-info")
NOISE_FILE_SUFFIXES = (".pyc", ".pyo", ".pyd")

# --- symbol vocabulary, weighted. Strong = defines the factory/state;
#     medium = population mechanism; weak = corroborating hints. ---
STRONG_SYMBOLS = {
    "class ToolSuite": 10,
    "class ToolRuntimeState": 8,
    "fs_backup": 7,
    "fs_workspace": 7,
    "def build_state": 6,
    "def make_state": 6,
    "def create_state": 6,
}
MEDIUM_SYMBOLS = {
    "isolate_fs": 4,
    "filesystem_root": 3,
    "fs_root": 3,
    "TemporaryDirectory": 4,
    "mkdtemp": 4,
    "fixtures_dir": 4,
    "read_text": 2,
    "read_bytes": 2,
    "copytree": 3,
    "shutil": 2,
    "token_hex": 3,       # seed signal
    "secrets.": 2,        # seed signal
    "random.seed": 3,     # seed signal
}
WEAK_SYMBOLS = {
    "class ToolContext": 2,
    "canonical_source_path": 2,
    "egress_sink": 1,
    "mark_source": 1,
    "last_source": 1,
    "secret.txt": 1,
    "protected": 1,
    "file_seed": 1,
}
ALL_SYMBOLS = {**STRONG_SYMBOLS, **MEDIUM_SYMBOLS, **WEAK_SYMBOLS}


def utc_now_iso():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def norm_components(path):
    return [c for c in re.split(r"[\\/]+", path) if c]


def is_noise_path(full_path):
    low = full_path.lower()
    for c in norm_components(low):
        if c in NOISE_DIR_COMPONENTS or c.endswith(NOISE_DIR_SUFFIXES):
            return True
    return low.endswith(NOISE_FILE_SUFFIXES)


def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def walk_py(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d.lower() not in NOISE_DIR_COMPONENTS
                       and not d.lower().endswith(NOISE_DIR_SUFFIXES)]
        for name in filenames:
            if name.lower().endswith(".py"):
                yield os.path.join(dirpath, name)


def scan_file(path):
    """Read-only text + AST scan. Returns dict of hits or an error record."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError as exc:
        return {"path": os.path.abspath(path),
                "status": f"NOT_ESTABLISHED_unreadable: {type(exc).__name__}"}

    lines = src.splitlines()
    hits = []
    score = 0
    for sym, weight in ALL_SYMBOLS.items():
        for i, line in enumerate(lines, start=1):
            if sym in line:
                hits.append({"symbol": sym, "weight": weight,
                             "lineno": i, "line": line.strip()[:200]})
                score += weight

    # AST: record class/def defs of interest (structure, not just text).
    defs = []
    try:
        tree = ast.parse(src, filename=path)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                defs.append({"kind": "class", "name": node.name,
                             "lineno": node.lineno})
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if any(k in node.name.lower() for k in
                       ("state", "suite", "load", "build", "make", "reset",
                        "fixture", "materialize", "populate")):
                    defs.append({"kind": "def", "name": node.name,
                                 "lineno": node.lineno})
        parse_ok = True
    except SyntaxError as exc:
        parse_ok = False
        defs.append({"kind": "parse_error", "name": str(exc), "lineno": 0})

    return {
        "path": os.path.abspath(path),
        "status": "SCANNED",
        "sha256": sha256_of_file(path),
        "score": score,
        "hit_count": len(hits),
        "hits": hits,
        "defs_of_interest": defs,
        "parse_ok": parse_ok,
        "defines_toolsuite": any(d["kind"] == "class" and d["name"] == "ToolSuite"
                                 for d in defs),
        "defines_runtime_state": any(d["kind"] == "class" and
                                     d["name"] == "ToolRuntimeState"
                                     for d in defs),
    }


def manifest_self_hash(body):
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="P8 read-only locator for the ToolSuite/fs-runtime factory "
                    "(symbol scan; never imports/executes targets).")
    ap.add_argument("--root", action="append", default=[], metavar="DIR",
                    help="Directory root(s) to scan (e.g. the aicomp_sdk dir). "
                         "Repeatable.")
    ap.add_argument("--out-dir", default=os.getcwd())
    ap.add_argument("--tag", default="v1_1")
    ap.add_argument("--top", type=int, default=10,
                    help="How many top-ranked candidates to list (default 10).")
    ap.add_argument("--run-inspector", action="store_true",
                    help="If p8_static_source_inspector_v1_0.py is importable, "
                         "classify the top candidate(s) inline (still read-only).")
    args = ap.parse_args(argv)

    os.makedirs(args.out_dir, exist_ok=True)
    started = utc_now_iso()

    scanned, errors, noise_skipped = [], [], 0
    roots_status = []
    for root in (args.root or [os.getcwd()]):
        if not os.path.isdir(root):
            roots_status.append({"root": os.path.abspath(root),
                                 "present": False,
                                 "status": "NOT_ESTABLISHED_root_absent"})
            continue
        roots_status.append({"root": os.path.abspath(root),
                            "present": True, "status": "PRESENT"})
        for fpath in walk_py(root):
            if is_noise_path(fpath):
                noise_skipped += 1
                continue
            rec = scan_file(fpath)
            if rec.get("status", "").startswith("NOT_ESTABLISHED"):
                errors.append(rec)
            elif rec["score"] > 0:
                scanned.append(rec)

    scanned.sort(key=lambda r: (r["defines_toolsuite"], r["score"]),
                 reverse=True)
    top = scanned[:args.top]

    # Optional inline classification via the inspector (read-only import of MY
    # own tool; it defines functions and does not execute targets).
    inspector_results = None
    if args.run_inspector and top:
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import p8_static_source_inspector_v1_0 as insp
            inspector_results = []
            for cand in top:
                try:
                    with open(cand["path"], "r", encoding="utf-8",
                              errors="replace") as fh:
                        csrc = fh.read()
                    tree, err = insp.safe_parse(csrc, cand["path"])
                    if tree is None:
                        inspector_results.append({"path": cand["path"],
                                                  "verdict": "UNPARSEABLE",
                                                  "error": err})
                        continue
                    verdict, touching = insp.classify_loader(tree, csrc)
                    inspector_results.append({
                        "path": cand["path"], "verdict": verdict,
                        "functions_touching": [t["function"] for t in touching],
                    })
                except Exception as exc:  # never let classification crash locate
                    inspector_results.append({"path": cand["path"],
                                              "verdict": "CLASSIFY_ERROR",
                                              "error": str(exc)})
        except Exception as exc:
            inspector_results = [{"verdict": "INSPECTOR_UNAVAILABLE",
                                  "error": str(exc)}]

    body = {
        "script_id": SCRIPT_ID, "script_version": SCRIPT_VERSION,
        "authorized_scope": "P8 read-only ToolSuite locator (symbol scan; no "
                            "import/exec of targets)",
        "read_only": True, "executed_target_code": False,
        "imported_target_code": False,
        "started_utc": started,
        "roots_status": roots_status,
        "counters": {"files_with_hits": len(scanned),
                     "noise_skipped": noise_skipped,
                     "unreadable": len(errors)},
        "top_candidates": top,
        "all_hits": scanned,
        "unreadable": errors,
        "inspector_results": inspector_results,
    }
    body["finished_utc"] = utc_now_iso()
    body["manifest_sha256"] = manifest_self_hash(body)

    out_json = os.path.join(args.out_dir,
                            f"p8_toolsuite_locator_{args.tag}.json")
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(body, fh, indent=2, ensure_ascii=False)

    # ---- console summary ----
    print("=" * 74)
    print(f"{SCRIPT_ID}  (READ-ONLY symbol scan; no import/exec)")
    print("=" * 74)
    for rs in roots_status:
        print(f"  root {'OK ' if rs['present'] else 'ABSENT'} {rs['root']}")
    print(f"  files with hits : {len(scanned)}   noise skipped: {noise_skipped}"
          f"   unreadable: {len(errors)}")
    print("-" * 74)
    print(f"TOP {len(top)} CANDIDATES (by ToolSuite-def, then score):")
    for c in top:
        flags = []
        if c["defines_toolsuite"]:
            flags.append("DEFINES ToolSuite")
        if c["defines_runtime_state"]:
            flags.append("DEFINES ToolRuntimeState")
        print(f"  [{c['score']:>3}] {c['path']}")
        if flags:
            print(f"        *** {' | '.join(flags)} ***")
        strong = sorted({h['symbol'] for h in c['hits']
                         if h['symbol'] in STRONG_SYMBOLS})
        if strong:
            print(f"        strong: {strong}")
    if inspector_results:
        print("-" * 74)
        print("INLINE LOADER CLASSIFICATION (top candidates):")
        for r in inspector_results:
            print(f"  {r.get('verdict')}  <- {r.get('path','')}")
    print("-" * 74)
    print(f"Report SHA-256 : {body['manifest_sha256']}")
    print(f"JSON report    : {out_json}")
    print("=" * 74)

    # Fail-closed: no candidate that actually DEFINES ToolSuite/RuntimeState.
    strong_hit = any(c["defines_toolsuite"] or c["defines_runtime_state"]
                     for c in top)
    if not scanned:
        return 2          # nothing matched at all
    if not strong_hit:
        return 3          # matched hints but no factory definition located
    return 0


if __name__ == "__main__":
    sys.exit(main())
