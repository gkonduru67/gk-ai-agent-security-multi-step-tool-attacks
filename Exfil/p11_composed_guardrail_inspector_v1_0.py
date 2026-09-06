#!/usr/bin/env python3
# =============================================================================
# p11_composed_guardrail_inspector_v1_0.py
# -----------------------------------------------------------------------------
# PHASE:            P11 - Guardrail Divergence Study (composed-guardrail
#                   IDENTIFICATION + static inspection; READ-ONLY, no exec)
#
# PURPOSE (closes the P11 scaffold's readiness gap):
#   The P11 scaffold needs a --composed-path pointing at the REAL runtime
#   guardrail. The user is unsure which file that is (optimal.py? base.py?
#   proposal_aware_optimal.py?). This companion tool RESOLVES that ambiguity
#   by EVIDENCE rather than guessing:
#
#     (1) Takes MULTIPLE candidate guardrail files (--candidate, repeatable),
#         plus the known reference --optimal-path.
#     (2) AST-parses each (NEVER imports/executes) and extracts the FULL body
#         of every decision-relevant function (decide, compose_guardrail,
#         is_protected_secret_path, _contains_secret, _is_secret_path, plus
#         any *decide* method on any class).
#     (3) Computes a STRUCTURAL FINGERPRINT of each decide()-family function:
#           - sha256 of the exact source segment (byte identity), AND
#           - sha256 of a NORMALIZED AST dump (structural identity, ignoring
#             comments/whitespace/formatting) so "same logic, reformatted" is
#             detectable as equivalent.
#     (4) Classifies each candidate vs the reference optimal.py:
#           IDENTICAL_BYTES / IDENTICAL_STRUCTURE / DIVERGENT / NO_DECIDE_FOUND
#         => tells you whether the composed guardrail actually DIFFERS from
#            optimal.py (if not, P11 divergence is a NULL by construction).
#     (5) Emits a readiness verdict: which single candidate is the strongest
#         "composed/runtime guardrail" pick to feed back into the P11 scaffold
#         as --composed-path.
#
# HARD SAFETY CONTRACT (identical discipline to P8/P11 scaffold):
#   * ast.parse ONLY. Never imports, never exec/eval, never calls decide().
#   * Opens files read-only ('r'). Writes ONLY its own JSON report to --out.
#   * On a missing/unparseable file or a missing decide(), records
#     NOT_ESTABLISHED for that candidate and continues (fail-closed, no crash).
#   * Makes NO claim about runtime behavior - it compares SOURCE LOGIC only.
#     Whether a given file is the ACTUAL runtime guardrail is reported as a
#     ranked hypothesis with evidence, never asserted as fact.
# =============================================================================

import argparse
import ast
import hashlib
import json
import os
import sys

SCRIPT_ID = "p11_composed_guardrail_inspector_v1_0"
SCRIPT_VERSION = "1.0"

# Decision-relevant function names we want the full body of.
DECIDE_FUNC_NAMES = {"decide", "compose_guardrail", "is_protected_secret_path",
                     "_contains_secret", "_is_secret_path", "_extract_target",
                     "_is_ultra_dangerous"}

# Symbols that suggest a file is a "runtime/composed" guardrail rather than a
# pure reference matcher. Used only for RANKING a hypothesis, never asserted.
COMPOSED_HINTS = ("compose", "composed", "runtime", "adapter", "trusted_context",
                  "proposal_aware", "policy", "pipeline")
REFERENCE_HINTS = ("optimal",)


def sha256_text(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


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


def normalized_ast_dump(node):
    """Structural fingerprint: dump the AST without attributes (lineno/col),
    so reformatting/whitespace/comment changes don't affect it, but LOGIC
    changes do. This is what lets us say 'same logic, different formatting'."""
    try:
        return ast.dump(node, annotate_fields=True, include_attributes=False)
    except TypeError:
        # older signature fallback
        return ast.dump(node)


def iter_functions(tree):
    """Yield (qualified_name, node) for module-level and one-level-nested
    (class method) functions."""
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.name, node
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield f"{node.name}.{sub.name}", sub


def collect_calls(node):
    calls = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                calls.add(f.id)
            elif isinstance(f, ast.Attribute):
                calls.add(f.attr)
    return sorted(calls)


def inspect_file(path):
    """Read-only AST inspection of one guardrail candidate. Returns a dict;
    never raises for expected error conditions."""
    rec = {"path": os.path.abspath(path)}
    if not os.path.isfile(path):
        rec["status"] = "NOT_ESTABLISHED_file_missing"
        return rec
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError as exc:
        rec["status"] = f"NOT_ESTABLISHED_unreadable: {type(exc).__name__}"
        return rec
    rec["file_sha256"] = sha256_text(src)
    try:
        tree = ast.parse(src, filename=path)
    except SyntaxError as exc:
        rec["status"] = "NOT_ESTABLISHED_unparseable"
        rec["error"] = str(exc)
        return rec

    funcs = {}
    for qname, node in iter_functions(tree):
        base = qname.split(".")[-1]
        # capture any decide()-family function, plus anything literally named
        # with 'decide' (defensive: catches decide_v2 etc.)
        if base in DECIDE_FUNC_NAMES or "decide" in base.lower():
            seg = get_segment(src, node)
            funcs[qname] = {
                "lineno": node.lineno,
                "byte_sha256": sha256_text(seg),
                "structure_sha256": sha256_text(normalized_ast_dump(node)),
                "calls_referenced": collect_calls(node),
                "source": seg,
            }
    rec["status"] = "PARSED"
    rec["decision_functions"] = funcs
    rec["decide_present"] = any(q.split(".")[-1] == "decide" or
                                q.lower().endswith(".decide") or q == "decide"
                                for q in funcs)
    return rec


def pick_primary_decide(inspection):
    """Return (qname, info) for the best 'decide' function in a file, or
    (None,None). Prefers a method literally named 'decide'."""
    if inspection.get("status") != "PARSED":
        return None, None
    funcs = inspection.get("decision_functions", {})
    # exact 'decide' method first
    for q, info in funcs.items():
        if q.split(".")[-1] == "decide":
            return q, info
    # else any *decide*
    for q, info in funcs.items():
        if "decide" in q.lower():
            return q, info
    return None, None


def classify_vs_reference(candidate_info, ref_info):
    """Compare a candidate decide() against the reference optimal decide()."""
    if candidate_info is None or ref_info is None:
        return "NO_DECIDE_FOUND"
    if candidate_info["byte_sha256"] == ref_info["byte_sha256"]:
        return "IDENTICAL_BYTES"
    if candidate_info["structure_sha256"] == ref_info["structure_sha256"]:
        return "IDENTICAL_STRUCTURE"   # same logic, reformatted
    return "DIVERGENT"


def composed_likelihood_score(path, inspection):
    """Heuristic RANKING (not an assertion) of how likely a file is the
    runtime/composed guardrail. Evidence-based, transparent."""
    low = path.lower()
    score = 0
    reasons = []
    for h in COMPOSED_HINTS:
        if h in low:
            score += 3
            reasons.append(f"filename contains '{h}' (+3)")
    for h in REFERENCE_HINTS:
        if h in low:
            score -= 2
            reasons.append(f"filename contains reference-hint '{h}' (-2)")
    if inspection.get("status") == "PARSED":
        funcs = inspection.get("decision_functions", {})
        # a composed guardrail often references the content matchers
        joined_calls = {c for f in funcs.values() for c in f["calls_referenced"]}
        for marker in ("is_protected_secret_path", "_contains_secret",
                       "compose_guardrail"):
            if marker in joined_calls:
                score += 2
                reasons.append(f"references '{marker}' (+2)")
        if inspection.get("decide_present"):
            score += 1
            reasons.append("defines a decide() (+1)")
    return score, reasons


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="P11 composed-guardrail identifier + static inspector "
                    "(read-only AST; never imports/executes). Resolves which "
                    "candidate is the composed/runtime guardrail and whether "
                    "it diverges from optimal.py.")
    ap.add_argument("--optimal-path", required=True,
                    help="Path to the reference guardrails/optimal.py.")
    ap.add_argument("--candidate", action="append", default=[], metavar="PATH",
                    help="Candidate composed/runtime guardrail file(s). "
                         "Repeatable. Pass every plausible file (e.g. base.py, "
                         "proposal_aware_optimal.py, trusted_context_adapter*.py).")
    ap.add_argument("--out", default=None, help="Optional JSON report path.")
    args = ap.parse_args(argv)

    ref = inspect_file(args.optimal_path)
    ref_q, ref_info = pick_primary_decide(ref)

    candidates = []
    for cpath in args.candidate:
        insp = inspect_file(cpath)
        cq, cinfo = pick_primary_decide(insp)
        classification = classify_vs_reference(cinfo, ref_info)
        like_score, like_reasons = composed_likelihood_score(cpath, insp)
        candidates.append({
            "path": os.path.abspath(cpath),
            "status": insp.get("status"),
            "primary_decide": cq,
            "vs_optimal": classification,
            "composed_likelihood_score": like_score,
            "composed_likelihood_reasons": like_reasons,
            "decision_functions_found": list(
                insp.get("decision_functions", {}).keys()),
            "decide_source": (cinfo or {}).get("source"),
        })

    # Rank the best composed pick. A truly DIVERGENT decide() is the only
    # thing worth studying in a DIVERGENCE analysis; an IDENTICAL_STRUCTURE
    # candidate has the SAME logic as optimal (just reformatted) so it is NOT
    # useful for divergence and must never outrank a DIVERGENT one, regardless
    # of filename score. We therefore rank by (is_truly_divergent, score).
    _rank_tier = {"DIVERGENT": 2, "IDENTICAL_STRUCTURE": 1}
    divergent = [c for c in candidates if c["vs_optimal"] in _rank_tier]
    ranked = sorted(
        divergent,
        key=lambda c: (_rank_tier[c["vs_optimal"]],
                       c["composed_likelihood_score"]),
        reverse=True)

    if not ref_info:
        overall = "NOT_READY_optimal_decide_not_parsed"
        recommendation = ("Could not parse a decide() in --optimal-path; "
                          "verify the path.")
    elif ranked:
        best = ranked[0]
        overall = "COMPOSED_CANDIDATE_IDENTIFIED"
        recommendation = (
            f"Feed this back into the P11 scaffold as --composed-path:\n  "
            f"{best['path']}\n(It defines a decide() that DIVERGES from "
            f"optimal.py, and scores highest on composed-guardrail evidence. "
            f"vs_optimal={best['vs_optimal']}, "
            f"score={best['composed_likelihood_score']}.)")
    elif (any(c["status"] == "PARSED" for c in candidates) and
          all(c["vs_optimal"] == "IDENTICAL_BYTES"
              for c in candidates if c["status"] == "PARSED")):
        overall = "NULL_ALL_CANDIDATES_IDENTICAL_TO_OPTIMAL"
        recommendation = (
            "Every candidate's decide() is byte-identical to optimal.py. "
            "There is NO composed-vs-optimal divergence to study - P11 "
            "divergence would be a documented NULL. Your instinct that "
            "'it is optimal.py' would then be correct, and the composed "
            "guardrail is simply optimal.py itself.")
    else:
        overall = "NOT_READY_no_divergent_candidate"
        recommendation = ("No candidate both parsed a decide() AND diverged "
                          "from optimal.py. Supply more candidate files.")

    report = {
        "script_id": SCRIPT_ID, "script_version": SCRIPT_VERSION,
        "read_only": True, "executed_target_code": False,
        "optimal": {
            "path": ref["path"], "status": ref.get("status"),
            "primary_decide": ref_q,
            "decide_byte_sha256": (ref_info or {}).get("byte_sha256"),
            "decide_structure_sha256": (ref_info or {}).get("structure_sha256"),
            "decide_source": (ref_info or {}).get("source"),
        },
        "candidates": candidates,
        "overall_verdict": overall,
        "recommended_composed_path": (ranked[0]["path"] if ranked else None),
        "recommendation": recommendation,
    }

    print("=" * 76)
    print(f"{SCRIPT_ID} (READ-ONLY, AST-only; no import/exec)")
    print("=" * 76)
    print(f"optimal.py: {ref.get('status')}  decide={ref_q}  "
          f"byte_sha={(ref_info or {}).get('byte_sha256','-')[:12]}")
    print("-" * 76)
    for c in candidates:
        print(f"CANDIDATE {c['status']:<10} vs_optimal={c['vs_optimal']:<20} "
              f"score={c['composed_likelihood_score']:>2}")
        print(f"   {c['path']}")
        if c["primary_decide"]:
            print(f"   decide={c['primary_decide']}  "
                  f"funcs={c['decision_functions_found']}")
    print("-" * 76)
    print(f"OVERALL: {overall}")
    print(recommendation)
    print("=" * 76)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"Report written: {args.out}")

    # exit code: 0 if a composed candidate identified OR clean null; 2 otherwise
    return 0 if overall in ("COMPOSED_CANDIDATE_IDENTIFIED",
                            "NULL_ALL_CANDIDATES_IDENTICAL_TO_OPTIMAL") else 2


if __name__ == "__main__":
    sys.exit(main())
