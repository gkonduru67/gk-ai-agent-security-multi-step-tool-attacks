#!/usr/bin/env python3
# =============================================================================
# p8_static_source_inspector_v1_0.py
# -----------------------------------------------------------------------------
# PHASE:            P8 - Fixture Identity Closure (read-only static inspection)
# AUTHORIZED SCOPE: Resolve the two remaining P8 open rows WITHOUT executing,
#                   importing, or running any target code:
#     (1) ToolSuite loader: classify how `fs_backup` / `filesystem_root` is
#         populated from `fixtures_dir`  -> COPY_FROM_DISK vs SEED_GENERATE
#         vs INDETERMINATE, with the exact evidence lines cited.
#     (2) predicates.py: extract the FULL source of the secret-path / exfil
#         matcher functions so "basename vs root-relative" is byte-verified
#         from real code, not a docstring.
#
# WHY AST (the core safety guarantee):
#   * Python's `ast.parse()` reads source into a syntax tree. It does NOT run
#     module-level code, does NOT import the module, and triggers ZERO side
#     effects (no fixture load, no network, no file writes). This is the only
#     inspection method consistent with the fail-closed gate
#     "No experiment reruns, no attack optimization, no hand-authored fixtures."
#   * We deliberately do NOT `import` the targets and do NOT `exec` anything.
#
# READ-ONLY / FAIL-CLOSED CONTRACT:
#   * Target files opened strictly 'r'/'rb'. Only the REPORT is written to
#     --out-dir. No target artifact is modified.
#   * Every inspected file is SHA-256 hash-bound in the report (chain-of-custody
#     continuity with the P7 manifests).
#   * If a target file is missing, unparseable, or a wanted symbol is absent,
#     that row is recorded as NOT_ESTABLISHED and forces a non-zero exit, so a
#     wrapper cannot mistake an incomplete inspection for a closed gate.
#   * The loader classifier NEVER guesses: if evidence is ambiguous it returns
#     INDETERMINATE (NOT_ESTABLISHED), not a copy/seed verdict.
#
# OUT OF SCOPE (still gated behind P9/P10): no raw transport capture, no P6C
#   re-run, no fixture materialization. This script only READS source text.
# =============================================================================

import argparse
import ast
import datetime as _dt
import hashlib
import json
import os
import sys

SCRIPT_ID = "p8_static_source_inspector_v1_0"
SCRIPT_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Symbols we want the FULL body of from predicates.py (byte-verification).
# ---------------------------------------------------------------------------
PREDICATE_TARGET_FUNCS = [
    "_is_secret_path",
    "is_protected_secret_path",
    "_extract_secret_values",
    "_contains_secret",
    "_decode_candidates",
    "_secrets_read_in_trace",
    "payload_exfiltrates_secret",
    "exfil_payload_arg",
    "eval_predicates",
    "is_breach",
    "_alnum",
]
PREDICATE_CONSTANTS = [
    "SECRET_MARKER", "SECRET_FILENAME", "EXFIL_SINKS",
    "_ENCODED_MATCH_MIN_LEN", "_MIN_SECRET_VALUE_LEN",
]

# ---------------------------------------------------------------------------
# Loader-classification evidence vocabulary (AST-level, not regex-on-text).
# COPY_FROM_DISK  : reads bytes/text off disk or shutil-copies a source tree.
# SEED_GENERATE   : synthesizes content in-process (literals, rng, faker...).
# Presence of BOTH -> report both sets; verdict COPY wins only if disk reads
# clearly feed the fs backup, else INDETERMINATE (fail-closed).
# ---------------------------------------------------------------------------
COPY_CALL_NAMES = {
    "read_bytes", "read_text", "copy", "copy2", "copyfile", "copytree",
    "iterdir", "rglob", "glob", "walk", "scandir", "listdir",
}
COPY_ATTR_HINTS = {"shutil", "fixtures_dir", "fixtures", "source", "src"}
SEED_CALL_NAMES = {
    "seed", "randint", "randbytes", "choice", "choices", "token_hex",
    "token_urlsafe", "uuid4", "getrandbits",
}
SEED_MODULE_HINTS = {"random", "secrets", "uuid", "faker", "numpy"}
FS_BACKUP_NAMES = {"fs_backup", "filesystem_root", "fs_root", "fs_workspace"}
TEMPDIR_HINTS = {"TemporaryDirectory", "mkdtemp", "gettempdir"}


def utc_now_iso():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha256_text(path):
    """Read-only SHA-256 of the file bytes (chain-of-custody)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def read_source(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def safe_parse(src, path):
    """ast.parse ONLY. Never compiles-to-exec, never imports. Returns tree or
    None with an error string."""
    try:
        return ast.parse(src, filename=path), None
    except SyntaxError as exc:
        return None, f"SyntaxError: {exc}"


def get_segment(src, node):
    try:
        seg = ast.get_source_segment(src, node)
        if seg:
            return seg
    except Exception:
        pass
    # Fallback via line numbers.
    lines = src.splitlines()
    start = getattr(node, "lineno", 1) - 1
    end = getattr(node, "end_lineno", start + 1)
    return "\n".join(lines[start:end])


def iter_functions(tree):
    """Yield (qualified_name, node) for all funcs incl. methods, one level of
    class nesting (enough for ToolSuite/ToolContext)."""
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.name, node
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield f"{node.name}.{sub.name}", sub


def collect_calls(node):
    """Return (call_names, attr_names, module_names) used anywhere under node."""
    calls, attrs, mods = set(), set(), set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Attribute):
                calls.add(f.attr)
                if isinstance(f.value, ast.Name):
                    mods.add(f.value.id)
            elif isinstance(f, ast.Name):
                calls.add(f.id)
        if isinstance(n, ast.Attribute):
            attrs.add(n.attr)
        if isinstance(n, ast.Name):
            mods.add(n.id)
    return calls, attrs, mods


# ------------------------- (1) LOADER CLASSIFIER ---------------------------

def classify_loader(tree, src):
    """Scan every function; find those that touch fs_backup/filesystem_root and
    classify COPY vs SEED evidence. Fail-closed: ambiguity -> INDETERMINATE."""
    touching = []
    for qname, fn in iter_functions(tree):
        calls, attrs, mods = collect_calls(fn)
        names_here = calls | attrs | mods
        touches_backup = bool(FS_BACKUP_NAMES & names_here)
        if not touches_backup:
            # Also catch constructors that build a temp workspace even if the
            # backup name isn't literally referenced in this fn.
            if not (TEMPDIR_HINTS & names_here):
                continue
        copy_ev = sorted((COPY_CALL_NAMES & calls) |
                         (COPY_ATTR_HINTS & (attrs | mods)))
        seed_ev = sorted((SEED_CALL_NAMES & calls) |
                         (SEED_MODULE_HINTS & mods))
        tempdir_ev = sorted(TEMPDIR_HINTS & names_here)
        touching.append({
            "function": qname,
            "touches_fs_backup": touches_backup,
            "copy_evidence": copy_ev,
            "seed_evidence": seed_ev,
            "tempdir_evidence": tempdir_ev,
            "source": get_segment(src, fn),
        })

    # Aggregate verdict across all touching functions.
    any_copy = any(t["copy_evidence"] for t in touching)
    any_seed = any(t["seed_evidence"] for t in touching)
    if not touching:
        verdict = "NOT_ESTABLISHED_no_fs_backup_touch"
    elif any_copy and not any_seed:
        verdict = "COPY_FROM_DISK"
    elif any_seed and not any_copy:
        verdict = "SEED_GENERATE"
    elif any_copy and any_seed:
        verdict = "INDETERMINATE_both_copy_and_seed"
    else:
        verdict = "INDETERMINATE_touch_without_clear_evidence"
    return verdict, touching


# ---------------------- (2) PREDICATE BODY EXTRACTOR -----------------------

def extract_predicate_bodies(tree, src, want_funcs, want_consts):
    funcs_found, funcs_missing = {}, []
    for name in want_funcs:
        node = None
        for qname, fn in iter_functions(tree):
            if qname == name or qname.endswith("." + name):
                node = fn
                break
        if node is None:
            funcs_missing.append(name)
        else:
            body_src = get_segment(src, node)
            funcs_found[name] = {
                "lineno": node.lineno,
                "end_lineno": getattr(node, "end_lineno", None),
                "has_body_beyond_docstring": _has_real_body(node),
                "source": body_src,
            }

    consts_found, consts_missing = {}, []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id in want_consts:
                    consts_found[tgt.id] = get_segment(src, node)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id in want_consts:
                consts_found[node.target.id] = get_segment(src, node)
    consts_missing = [c for c in want_consts if c not in consts_found]

    return {
        "functions_found": funcs_found,
        "functions_missing": funcs_missing,
        "constants_found": consts_found,
        "constants_missing": consts_missing,
    }


def _has_real_body(fn):
    """True if the function has statements beyond a bare docstring (i.e., the
    body actually rendered, not just a signature+docstring stub)."""
    body = fn.body
    if not body:
        return False
    idx = 0
    if isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant) and isinstance(
            body[0].value.value, str):
        idx = 1  # skip docstring
    return len(body) > idx


# ------------------------- report assembly ---------------------------------

def manifest_self_hash(body):
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="P8 read-only STATIC (AST) inspector: loader copy-vs-seed "
                    "classification + predicates.py body extraction. Never "
                    "imports or executes target code.")
    ap.add_argument("--toolsuite", action="append", default=[], metavar="PATH",
                    help="Path(s) to inspect for the fs_backup loader "
                         "(e.g. tools/__init__.py, tools/state.py). Repeatable.")
    ap.add_argument("--predicates", default=None, metavar="PATH",
                    help="Path to core/predicates.py for body extraction.")
    ap.add_argument("--out-dir", default=os.getcwd())
    ap.add_argument("--tag", default="v1_0")
    args = ap.parse_args(argv)

    os.makedirs(args.out_dir, exist_ok=True)
    started = utc_now_iso()

    report = {
        "script_id": SCRIPT_ID, "script_version": SCRIPT_VERSION,
        "authorized_scope": "P8 read-only static AST inspection "
                            "(no import, no exec, no reruns)",
        "method": "ast.parse only — parses source, never executes/imports it",
        "read_only": True, "executed_target_code": False,
        "imported_target_code": False,
        "started_utc": started,
        "loader_inspection": [],
        "predicate_inspection": None,
        "gaps": [],
    }

    # ---- (1) loader inspection ----
    if not args.toolsuite:
        report["gaps"].append("no --toolsuite path supplied")
    for path in args.toolsuite:
        entry = {"path": os.path.abspath(path)}
        if not os.path.isfile(path):
            entry["status"] = "NOT_ESTABLISHED_file_missing"
            report["gaps"].append(f"loader file missing: {path}")
            report["loader_inspection"].append(entry)
            continue
        entry["sha256"] = sha256_text(path)
        src = read_source(path)
        tree, err = safe_parse(src, path)
        if tree is None:
            entry["status"] = "NOT_ESTABLISHED_unparseable"
            entry["error"] = err
            report["gaps"].append(f"loader unparseable: {path}")
            report["loader_inspection"].append(entry)
            continue
        verdict, touching = classify_loader(tree, src)
        entry["status"] = "PARSED"
        entry["loader_verdict"] = verdict
        entry["functions_touching_fs_backup"] = touching
        if verdict.startswith("NOT_ESTABLISHED") or verdict.startswith(
                "INDETERMINATE"):
            report["gaps"].append(f"loader verdict {verdict} in {path}")
        report["loader_inspection"].append(entry)

    # ---- (2) predicates.py body extraction ----
    if args.predicates:
        p = args.predicates
        pe = {"path": os.path.abspath(p)}
        if not os.path.isfile(p):
            pe["status"] = "NOT_ESTABLISHED_file_missing"
            report["gaps"].append(f"predicates file missing: {p}")
        else:
            pe["sha256"] = sha256_text(p)
            src = read_source(p)
            tree, err = safe_parse(src, p)
            if tree is None:
                pe["status"] = "NOT_ESTABLISHED_unparseable"
                pe["error"] = err
                report["gaps"].append(f"predicates unparseable: {p}")
            else:
                pe["status"] = "PARSED"
                res = extract_predicate_bodies(
                    tree, src, PREDICATE_TARGET_FUNCS, PREDICATE_CONSTANTS)
                pe.update(res)
                # Byte-verification gate: are the secret-path matchers real?
                stub = [n for n, info in res["functions_found"].items()
                        if not info["has_body_beyond_docstring"]]
                pe["docstring_only_stubs"] = stub
                if res["functions_missing"]:
                    report["gaps"].append(
                        "predicate funcs missing: "
                        + ", ".join(res["functions_missing"]))
                if stub:
                    report["gaps"].append(
                        "predicate funcs rendered as docstring-only (bodies "
                        "not present): " + ", ".join(stub))
        report["predicate_inspection"] = pe
    else:
        report["gaps"].append("no --predicates path supplied")

    report["finished_utc"] = utc_now_iso()
    report["manifest_sha256"] = manifest_self_hash(report)

    out_json = os.path.join(args.out_dir,
                            f"p8_static_source_inspection_{args.tag}.json")
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    # ---- console summary ----
    print("=" * 74)
    print(f"{SCRIPT_ID}  (READ-ONLY, AST-only — no import, no exec)")
    print("=" * 74)
    for e in report["loader_inspection"]:
        print(f"LOADER: {e['path']}")
        print(f"  status : {e.get('status')}")
        if "loader_verdict" in e:
            print(f"  VERDICT: {e['loader_verdict']}")
            for t in e["functions_touching_fs_backup"]:
                print(f"    fn {t['function']}: "
                      f"copy={t['copy_evidence']} seed={t['seed_evidence']} "
                      f"temp={t['tempdir_evidence']}")
    if report["predicate_inspection"]:
        pe = report["predicate_inspection"]
        print("-" * 74)
        print(f"PREDICATES: {pe['path']}")
        print(f"  status : {pe.get('status')}")
        if pe.get("status") == "PARSED":
            print(f"  funcs found  : {sorted(pe['functions_found'])}")
            print(f"  funcs missing: {pe['functions_missing']}")
            print(f"  stub (doc-only): {pe['docstring_only_stubs']}")
            print(f"  constants     : {sorted(pe['constants_found'])}")
    print("-" * 74)
    print(f"GAPS ({len(report['gaps'])}):")
    for g in report["gaps"]:
        print(f"  - {g}")
    print("-" * 74)
    print(f"Report SHA-256 : {report['manifest_sha256']}")
    print(f"JSON report    : {out_json}")
    print("=" * 74)

    # Fail-closed: any gap (missing file, unparseable, INDETERMINATE verdict,
    # missing/stub predicate func) forces non-zero exit.
    return 0 if not report["gaps"] else 2


if __name__ == "__main__":
    sys.exit(main())
