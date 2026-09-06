#!/usr/bin/env python3
# =============================================================================
# p11_ledger_inspector_v1_0.py
# -----------------------------------------------------------------------------
# PHASE:            P11 - Guardrail Divergence Study (ledger / hook static
#                   inspection; READ-ONLY, no execution, no imports)
#
# PURPOSE: closes the "unmodeled ledger dependency" scope gap from the P11
# dry-run comparator v1.0. This tool extracts, via AST ONLY (never imports or
# execs), the qualification/population logic of:
#   (1) a ledger class (e.g. SuccessfulReadLedgerV21) - specifically the
#       append_*() write path and the qualifying_secret_values() read path.
#   (2) a POST_TOOL_CALL hook class (e.g. TrustedReadOutcomeHookV21) - the
#       gating conditions that decide whether the hook ever calls the
#       ledger's append method at all.
#
# PROVENANCE NOTE: the specific ledger/hook byte-verified in this session were
# already read-only inspected in a PRIOR, separate piece of work
# (p2c_r7b_read_capture_hook_result_v1_0.json, created_at_utc
# 2026-08-24T09:29:20Z, execution_boundaries: model_executed=false,
# sandbox_executed=false, sdk_imported=false, read_only=true). That result
# recorded:
#   successful_read_ledger_v2_1.py   sha256=18146742E6866C491A032AA96EFC248F
#                                     FED05706895D32FDE724145D0878009C (159 lines)
#   trusted_read_outcome_hook_v2_1.py sha256=F2DE8D42EE5DBCD3BA4CACD8E98DCCB2
#                                     EBA63F82EC8683D129C503CCED1CE770 (21 lines)
# This tool is a GENERAL-PURPOSE, standalone inspector (not a copy of that
# prior artifact) that can be re-run against those same files, or any other
# ledger/hook pair, to independently re-derive the same facts via AST alone -
# never trusting a docstring, never importing the real module.
#
# SAFETY CONTRACT (identical discipline to every prior P11 tool):
#   * ast.parse ONLY. Never imports, execs, or instantiates the target class.
#   * Opens files read-only ('r'). Writes ONLY its own JSON report.
#   * Every extracted precondition (raise/return-early guard) is reported
#     VERBATIM from the source segment - not paraphrased into a claim that
#     could drift from the literal code.
#   * If a file is missing/unparseable, or the expected method names are not
#     found, reports NOT_ESTABLISHED for that piece - never fabricates.
# =============================================================================

import argparse
import ast
import hashlib
import json
import os
import sys

SCRIPT_ID = "p11_ledger_inspector_v1_0"
SCRIPT_VERSION = "1.0"

# Method-name vocabulary for the two roles this tool understands.
LEDGER_APPEND_NAMES = {"append_successful_read", "append_read", "append_record",
                       "append"}
LEDGER_READ_NAMES = {"qualifying_secret_values", "records", "qualifying_values"}
HOOK_CALL_NAMES = {"__call__", "on_post_tool_call", "handle"}


def sha256_text(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def get_segment(src, node):
    try:
        seg = ast.get_source_segment(src, node)
        if seg:
            return seg
    except Exception:
        pass
    lines = src.splitlines()
    start = getattr(node, "lineno", 1) - 1
    end = getattr(node, "end_lineno", start + 1)
    return "\n".join(lines[start:end])


def iter_functions(tree):
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.name, node, None
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield f"{node.name}.{sub.name}", sub, node.name


def extract_guard_conditions(fn_node, src):
    """Extract every early-return / raise statement guarding a function body -
    the literal preconditions that gate whether execution proceeds past that
    point. Returned VERBATIM (source text), never paraphrased."""
    guards = []
    for node in ast.walk(fn_node):
        if isinstance(node, ast.Raise):
            guards.append({"kind": "raise", "lineno": node.lineno,
                           "source": get_segment(src, node)})
        elif isinstance(node, ast.Return) and node is not fn_node.body[-1]:
            # An early return (not the function's final statement) is very
            # likely a guard clause. We still report ALL returns; the reader
            # can see for themselves which are guards vs. the main result.
            guards.append({"kind": "return", "lineno": node.lineno,
                           "source": get_segment(src, node)})
    return guards


def collect_calls_and_attrs(fn_node):
    calls, attrs = set(), set()
    for n in ast.walk(fn_node):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                calls.add(f.id)
            elif isinstance(f, ast.Attribute):
                calls.add(f.attr)
        if isinstance(n, ast.Attribute):
            attrs.add(n.attr)
    return sorted(calls), sorted(attrs)


def inspect_component(path, role_hint):
    """role_hint: 'ledger' or 'hook' - just affects which method-name
    vocabulary we prioritize for the summary; both roles are fully AST-parsed
    regardless."""
    rec = {"path": os.path.abspath(path), "role_hint": role_hint}
    if not os.path.isfile(path):
        rec["status"] = "NOT_ESTABLISHED_file_missing"
        return rec
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError as exc:
        rec["status"] = f"NOT_ESTABLISHED_unreadable: {type(exc).__name__}"
        return rec
    rec["file_sha256"] = sha256_file(path)
    try:
        tree = ast.parse(src, filename=path)
    except SyntaxError as exc:
        rec["status"] = "NOT_ESTABLISHED_unparseable"
        rec["error"] = str(exc)
        return rec

    functions = {}
    for qname, node, cls in iter_functions(tree):
        calls, attrs = collect_calls_and_attrs(node)
        guards = extract_guard_conditions(node, src)
        functions[qname] = {
            "class": cls, "lineno": node.lineno,
            "byte_sha256": sha256_text(get_segment(src, node)),
            "args": [a.arg for a in node.args.args if a.arg != "self"],
            "calls_referenced": calls,
            "attrs_referenced": attrs,
            "guard_conditions": guards,
            "source": get_segment(src, node),
        }

    rec["status"] = "PARSED"
    rec["functions_found"] = functions

    found_append = [q for q in functions if q.split(".")[-1] in LEDGER_APPEND_NAMES]
    found_read = [q for q in functions if q.split(".")[-1] in LEDGER_READ_NAMES]
    found_hook = [q for q in functions if q.split(".")[-1] in HOOK_CALL_NAMES]
    rec["append_methods"] = found_append
    rec["qualifying_read_methods"] = found_read
    rec["hook_call_methods"] = found_hook
    return rec


def summarize_qualification_chain(hook_rec, ledger_rec):
    """Builds a human-readable, EVIDENCE-CITED chain of exactly what must be
    true (per the byte-verified guard conditions found) for a secret value to
    ever reach qualifying_secret_values(). Every claim below is tagged with
    the exact function + line it came from - never inferred beyond that."""
    chain = []
    if hook_rec and hook_rec.get("status") == "PARSED":
        for q in hook_rec.get("hook_call_methods", []):
            info = hook_rec["functions_found"][q]
            chain.append({
                "stage": f"hook.{q}", "lineno": info["lineno"],
                "guard_conditions_verbatim": [g["source"] for g in info["guard_conditions"]],
                "note": "These are the EXACT early-return/raise statements found "
                       "in this function. Any one of them returning/raising "
                       "prevents the ledger append below from ever being called.",
            })
    if ledger_rec and ledger_rec.get("status") == "PARSED":
        for q in ledger_rec.get("append_methods", []):
            info = ledger_rec["functions_found"][q]
            chain.append({
                "stage": f"ledger.{q}", "lineno": info["lineno"],
                "guard_conditions_verbatim": [g["source"] for g in info["guard_conditions"]],
                "note": "Preconditions the ledger's OWN append method enforces "
                       "(independent of the hook) before a record is stored.",
            })
        for q in ledger_rec.get("qualifying_read_methods", []):
            info = ledger_rec["functions_found"][q]
            chain.append({
                "stage": f"ledger.{q}", "lineno": info["lineno"],
                "source_verbatim": info["source"],
                "note": "The read-side method whose return value the "
                       "consuming guardrail (e.g. lineage_v2_1.decide) queries.",
            })
    return chain


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="P11 read-only ledger/hook inspector (AST only; never "
                    "imports/executes). Extracts append/qualify methods and "
                    "their literal guard conditions.")
    ap.add_argument("--hook-path", default=None,
                    help="Path to the POST_TOOL_CALL hook file (e.g. "
                        "trusted_read_outcome_hook_v2_1.py).")
    ap.add_argument("--ledger-path", default=None,
                    help="Path to the ledger file (e.g. "
                        "successful_read_ledger_v2_1.py).")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    hook_rec = inspect_component(args.hook_path, "hook") if args.hook_path else None
    ledger_rec = inspect_component(args.ledger_path, "ledger") if args.ledger_path else None
    chain = summarize_qualification_chain(hook_rec, ledger_rec)

    report = {
        "script_id": SCRIPT_ID, "script_version": SCRIPT_VERSION,
        "read_only": True, "executed_target_code": False, "imported_target_code": False,
        "hook": hook_rec, "ledger": ledger_rec,
        "qualification_chain": chain,
    }

    print("=" * 84)
    print(f"{SCRIPT_ID} (READ-ONLY, AST-only; never imports/executes)")
    print("=" * 84)
    if hook_rec:
        print(f"HOOK   : {hook_rec.get('status')}  sha256={hook_rec.get('file_sha256','-')[:16]}  "
              f"hook_call_methods={hook_rec.get('hook_call_methods')}")
    if ledger_rec:
        print(f"LEDGER : {ledger_rec.get('status')}  sha256={ledger_rec.get('file_sha256','-')[:16]}  "
              f"append={ledger_rec.get('append_methods')}  read={ledger_rec.get('qualifying_read_methods')}")
    print("-" * 84)
    print("QUALIFICATION CHAIN (every guard condition, verbatim, that must be "
         "satisfied for a value to ever reach qualifying_secret_values()):")
    for step in chain:
        print(f"  [{step['stage']}] line {step['lineno']}")
        for g in step.get("guard_conditions_verbatim", []):
            print(f"      guard: {g.strip()[:100]}")
    print("=" * 84)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"Report written: {args.out}")

    ok = bool(hook_rec and hook_rec.get("status") == "PARSED" and
             ledger_rec and ledger_rec.get("status") == "PARSED")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
