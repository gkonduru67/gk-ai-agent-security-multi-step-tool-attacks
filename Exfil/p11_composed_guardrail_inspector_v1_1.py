#!/usr/bin/env python3
# =============================================================================
# p11_composed_guardrail_inspector_v1_1.py
# -----------------------------------------------------------------------------
# PHASE:            P11 - Guardrail Divergence Study (static inspection)
# READ-ONLY / NO EXECUTION: ast.parse only. Never imports, never exec/eval,
#                           never calls decide(). Writes only its own report.
#
# WHY v1.1 (vs v1.0): v1.0's `composed_likelihood_score` RANKED guardrails by
# filename + visible-call heuristics. That systematically MIS-RANKED stateful
# guardrails: it recommended proposal_aware_optimal (score 4) OVER the stronger
# lineage_aware_v2_1 (score 1), precisely because V2.1 externalizes its power
# into runtime LEDGER STATE and INNER-WRAPPER composition that a surface scan
# cannot see. v1.1 fixes this with THREE evidence-based upgrades the user
# requested:
#
#   (a) STATEFUL / LEDGER-DEPENDENCE DETECTION
#       Flags a guardrail whose decide() reads mutable external/ledger state
#       (e.g. self._ledger.qualifying_secret_values(), self._records, snapshot
#       restore, or any attribute call that feeds the decision). When present,
#       the tool emits: "STATIC DIFF INCOMPLETE - STATE-DEPENDENT" so a static
#       logic comparison is never mistaken for the whole story.
#
#   (b) INNER-WRAPPER / COMPOSITION DETECTION
#       Flags a guardrail whose decide() delegates to an inner guardrail
#       (self._inner.decide(...), self.inner.decide(...), super().decide(...)).
#       Such a guardrail is a COMPOSITION NODE, not a leaf - its true behavior
#       is (its own gate) THEN (inner's gate). The tool reports the composition
#       edge so the reviewer knows the static body is only the outer layer.
#
#   (c) ROLE-LABELED COMPARISON TABLE (replaces the filename score)
#       Instead of a misleading numeric "likelihood", each guardrail is
#       classified into an evidence-based ROLE by what its decide() actually
#       does:
#         - REFERENCE_CONTEXT_TAINT : context flags + source taint, no content
#         - PATH_GATE               : denies protected-path reads
#         - SENTINEL_PAYLOAD_GATE   : denies posts whose payload matches the
#                                     official sentinel (content, stateless)
#         - LINEAGE_PAYLOAD_GATE    : denies posts matching a LEDGER of real
#                                     read values (content, stateful)
#         - DEFAULT_ALLOW_STUB      : returns allow unconditionally
#         - HARD_DENY_STUB          : returns deny unconditionally (adapter)
#         - UNCLASSIFIED            : none of the above signatures matched
#       Roles are assigned by AST/marker EVIDENCE, and every role carries the
#       exact markers that justified it (auditable, not a black box).
#
# The tool still reports vs_optimal (IDENTICAL_BYTES / IDENTICAL_STRUCTURE /
# DIVERGENT) from v1.0, but the PRIMARY output is now the role table + the
# state/composition flags - NOT a single "recommended" file, since (as v1.0
# proved twice) a single filename-driven pick is unreliable.
# =============================================================================

import argparse
import ast
import hashlib
import json
import os
import sys

SCRIPT_ID = "p11_composed_guardrail_inspector_v1_1"
SCRIPT_VERSION = "1.1"

DECIDE_FUNC_NAMES = {"decide", "compose_guardrail", "is_protected_secret_path",
                     "_contains_secret", "_is_secret_path", "_extract_target",
                     "_is_ultra_dangerous", "before_decide"}

# --- (a) markers that a decide() consults MUTABLE / LEDGER state ---
LEDGER_STATE_CALL_MARKERS = {
    "qualifying_secret_values", "records", "snapshot_state", "restore_state",
    "append_successful_read", "reset",
}
LEDGER_ATTR_MARKERS = {"_ledger", "ledger", "_records", "_state", "_history"}

# --- (b) markers that a decide() DELEGATES to an inner/wrapped guardrail ---
INNER_ATTR_MARKERS = {"_inner", "inner", "_wrapped", "wrapped", "_delegate"}

# --- (c) role-signature markers (content evidence, not filename) ---
ROLE_MARKERS = {
    "path_gate": {"is_protected_secret_path"},           # denies protected read path
    "sentinel_payload": {"payload_exfiltrates_secret"},  # payload content gate
    "lineage_payload": {"read_secrets", "qualifying_secret_values"},  # stateful payload
    "context_taint": {"recent_sources", "user_authorized", "user_confirmed_safe",
                      "dangerous_operations"},
}


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
    try:
        return ast.dump(node, annotate_fields=True, include_attributes=False)
    except TypeError:
        return ast.dump(node)


def iter_functions(tree):
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.name, node
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield f"{node.name}.{sub.name}", sub


def collect_call_names(node):
    """Every called name / attribute-call in a function body."""
    calls = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                calls.add(f.id)
            elif isinstance(f, ast.Attribute):
                calls.add(f.attr)
    return calls


def collect_attribute_accesses(node):
    """Every self.<attr> and <name>.<attr> reference (attr names + base names)."""
    attrs, bases = set(), set()
    for n in ast.walk(node):
        if isinstance(n, ast.Attribute):
            attrs.add(n.attr)
            if isinstance(n.value, ast.Name):
                bases.add(n.value.id)
            elif isinstance(n.value, ast.Attribute):
                bases.add(n.value.attr)
    return attrs, bases


def detect_state_dependence(decide_node):
    """(a) Returns (is_stateful, evidence[])."""
    calls = collect_call_names(decide_node)
    attrs, _bases = collect_attribute_accesses(decide_node)
    evidence = []
    for m in sorted(LEDGER_STATE_CALL_MARKERS & calls):
        evidence.append(f"calls state method '{m}()'")
    for m in sorted(LEDGER_ATTR_MARKERS & attrs):
        evidence.append(f"reads state attribute 'self.{m}'")
    return (len(evidence) > 0), evidence


def detect_inner_composition(decide_node):
    """(b) Returns (wraps_inner, evidence[]). Detects self._inner.decide(...),
    super().decide(...), or any delegate attribute whose .decide is called."""
    evidence = []
    for n in ast.walk(decide_node):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                and n.func.attr == "decide":
            base = n.func.value
            # self._inner.decide(...)
            if isinstance(base, ast.Attribute) and base.attr in INNER_ATTR_MARKERS:
                evidence.append(f"delegates to 'self.{base.attr}.decide(...)'")
            # inner.decide(...) where inner is a bare name hint
            elif isinstance(base, ast.Name) and base.id in INNER_ATTR_MARKERS:
                evidence.append(f"delegates to '{base.id}.decide(...)'")
            # super().decide(...)
            elif isinstance(base, ast.Call) and isinstance(base.func, ast.Name) \
                    and base.func.id == "super":
                evidence.append("delegates to 'super().decide(...)'")
    # de-dup, keep order
    seen, uniq = set(), []
    for e in evidence:
        if e not in seen:
            seen.add(e); uniq.append(e)
    return (len(uniq) > 0), uniq


def classify_role(decide_node, all_calls_in_file):
    """(c) Evidence-based role classification. Returns (role, markers[])."""
    calls = collect_call_names(decide_node)
    names = calls | all_calls_in_file  # helper predicates may be module-level refs
    body_src = ""
    # gather Name ids too (e.g. 'recent_sources' variable, constant strings)
    name_ids = set()
    const_strs = set()
    for n in ast.walk(decide_node):
        if isinstance(n, ast.Name):
            name_ids.add(n.id)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            const_strs.add(n.value)
        elif isinstance(n, ast.Attribute):
            name_ids.add(n.attr)
    universe = names | name_ids

    markers = {}
    for role, ms in ROLE_MARKERS.items():
        hit = sorted(ms & universe)
        if hit:
            markers[role] = hit

    # Detect trivial stubs first (highest precedence - unconditional return).
    returns = [n for n in ast.walk(decide_node) if isinstance(n, ast.Return)]
    non_return_stmts = [n for n in ast.walk(decide_node)
                        if isinstance(n, (ast.If, ast.For, ast.While, ast.Try))]
    is_trivial = (len(non_return_stmts) == 0)
    if is_trivial and len(returns) >= 1:
        # look at what it returns
        allow_like = any("allow" in const_strs_join(r) for r in returns) or \
                     _returns_decision(returns, "allow")
        deny_like = _returns_decision(returns, "deny")
        if deny_like and not allow_like:
            return "HARD_DENY_STUB", ["unconditional Decision.deny(...)"]
        if allow_like and not deny_like:
            return "DEFAULT_ALLOW_STUB", ["unconditional Decision.allow(...)"]

    # Compose a role from strongest present gate. Priority reflects the
    # user's escalation ladder: lineage > sentinel > path > context.
    if "lineage_payload" in markers:
        return "LINEAGE_PAYLOAD_GATE", _flatten_markers(markers, "lineage_payload",
                                                        ["sentinel_payload", "path_gate"])
    if "sentinel_payload" in markers and "path_gate" in markers:
        return "PATH_AND_SENTINEL_GATE", _flatten_markers(markers,
                                                          "sentinel_payload", ["path_gate"])
    if "sentinel_payload" in markers:
        return "SENTINEL_PAYLOAD_GATE", markers["sentinel_payload"]
    if "path_gate" in markers:
        return "PATH_GATE", markers["path_gate"]
    if "context_taint" in markers:
        return "REFERENCE_CONTEXT_TAINT", markers["context_taint"]
    return "UNCLASSIFIED", []


def _flatten_markers(markers, primary, extras):
    out = list(markers.get(primary, []))
    for e in extras:
        out += [f"+{m}" for m in markers.get(e, [])]
    return out


def const_strs_join(return_node):
    parts = []
    for n in ast.walk(return_node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            parts.append(n.value.lower())
    return " ".join(parts)


def _returns_decision(returns, kind):
    """True if any Return calls Decision.<kind>(...)."""
    for r in returns:
        for n in ast.walk(r):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                    and n.func.attr == kind:
                if isinstance(n.func.value, ast.Name) and n.func.value.id == "Decision":
                    return True
    return False


def module_level_calls(tree):
    calls = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for n in ast.walk(node):
                if isinstance(n, ast.Call):
                    f = n.func
                    if isinstance(f, ast.Name):
                        calls.add(f.id)
                    elif isinstance(f, ast.Attribute):
                        calls.add(f.attr)
    return calls


def pick_primary_decide(funcs):
    for q, info in funcs.items():
        if q.split(".")[-1] == "decide":
            return q, info
    for q, info in funcs.items():
        if "decide" in q.lower():
            return q, info
    return None, None


def inspect_file(path):
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

    file_calls = module_level_calls(tree)
    funcs = {}
    for qname, node in iter_functions(tree):
        base = qname.split(".")[-1]
        if base in DECIDE_FUNC_NAMES or "decide" in base.lower():
            funcs[qname] = {"lineno": node.lineno,
                            "byte_sha256": sha256_text(get_segment(src, node)),
                            "structure_sha256": sha256_text(normalized_ast_dump(node)),
                            "source": get_segment(src, node),
                            "_node": node}
    rec["status"] = "PARSED"
    q, info = pick_primary_decide(funcs)
    rec["primary_decide"] = q
    if info is None:
        rec["role"] = "NO_DECIDE_FOUND"
        rec["stateful"] = False
        rec["wraps_inner"] = False
        rec["decision_functions"] = list(funcs.keys())
        return rec

    node = info["_node"]
    is_stateful, state_ev = detect_state_dependence(node)
    wraps_inner, inner_ev = detect_inner_composition(node)
    role, role_markers = classify_role(node, file_calls)

    rec["decide_byte_sha256"] = info["byte_sha256"]
    rec["decide_structure_sha256"] = info["structure_sha256"]
    rec["decide_source"] = info["source"]
    rec["decision_functions"] = list(funcs.keys())
    rec["role"] = role
    rec["role_markers"] = role_markers
    rec["stateful"] = is_stateful
    rec["state_evidence"] = state_ev
    rec["wraps_inner"] = wraps_inner
    rec["inner_evidence"] = inner_ev
    rec["static_diff_complete"] = not (is_stateful or wraps_inner)
    rec["static_diff_caveat"] = (
        "STATIC DIFF INCOMPLETE - STATE-DEPENDENT AND/OR COMPOSED"
        if (is_stateful or wraps_inner) else
        "static diff complete (pure function of decide() inputs)")
    return rec


def classify_vs_reference(cand, ref):
    if not cand or not ref:
        return "NO_DECIDE_FOUND"
    # A candidate that did not parse / has no decide() is NOT "divergent" -
    # it is simply absent. Guard against comparing a None hash to a real one
    # (which would spuriously read as DIVERGENT).
    if cand.get("status") != "PARSED" or not cand.get("decide_byte_sha256"):
        return "NO_DECIDE_FOUND"
    if cand.get("decide_byte_sha256") == ref.get("decide_byte_sha256"):
        return "IDENTICAL_BYTES"
    if cand.get("decide_structure_sha256") == ref.get("decide_structure_sha256"):
        return "IDENTICAL_STRUCTURE"
    return "DIVERGENT"


def build_role_table(ref, candidates):
    rows = []
    ref_row = {
        "label": "optimal.py (REFERENCE)", "path": ref["path"],
        "role": ref.get("role"), "stateful": ref.get("stateful"),
        "wraps_inner": ref.get("wraps_inner"),
        "static_diff": ref.get("static_diff_caveat"),
        "vs_optimal": "REFERENCE",
    }
    rows.append(ref_row)
    for c in candidates:
        rows.append({
            "label": os.path.basename(c["path"]),
            "path": c["path"], "role": c.get("role"),
            "stateful": c.get("stateful"), "wraps_inner": c.get("wraps_inner"),
            "static_diff": c.get("static_diff_caveat"),
            "vs_optimal": c.get("vs_optimal"),
        })
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="P11 composed-guardrail inspector v1.1 - stateful + "
                    "inner-composition detection + role-labeled table. "
                    "Read-only AST; never imports/executes.")
    ap.add_argument("--optimal-path", required=True)
    ap.add_argument("--candidate", action="append", default=[], metavar="PATH")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    ref = inspect_file(args.optimal_path)
    candidates = []
    for cpath in args.candidate:
        c = inspect_file(cpath)
        c["vs_optimal"] = classify_vs_reference(c, ref)
        candidates.append(c)

    role_table = build_role_table(ref, candidates)

    # Which candidates are genuinely worth comparing? DIVERGENT ones. But we do
    # NOT collapse to a single "recommended" file (that was v1.0's flaw). We
    # report ALL divergent candidates with their roles + caveats.
    divergent = [c for c in candidates if c["vs_optimal"] == "DIVERGENT"]
    stateful_flagged = [c for c in candidates if c.get("stateful")]
    composed_flagged = [c for c in candidates if c.get("wraps_inner")]

    report = {
        "script_id": SCRIPT_ID, "script_version": SCRIPT_VERSION,
        "read_only": True, "executed_target_code": False,
        "optimal": {k: ref.get(k) for k in
                    ("path", "status", "primary_decide", "role", "stateful",
                     "wraps_inner", "decide_byte_sha256", "decide_source")},
        "candidates": [{k: c.get(k) for k in
                        ("path", "status", "primary_decide", "vs_optimal",
                         "role", "role_markers", "stateful", "state_evidence",
                         "wraps_inner", "inner_evidence", "static_diff_complete",
                         "static_diff_caveat", "decide_source")}
                       for c in candidates],
        "role_table": role_table,
        "divergent_candidates": [os.path.basename(c["path"]) for c in divergent],
        "stateful_candidates": [os.path.basename(c["path"]) for c in stateful_flagged],
        "composed_candidates": [os.path.basename(c["path"]) for c in composed_flagged],
        "note": ("v1.1 deliberately does NOT emit a single recommended_composed_"
                 "path. Rank by ROLE + state/composition flags below; a "
                 "filename-driven single pick mis-ranked stateful guardrails "
                 "twice in v1.0."),
    }

    # ---- console ----
    print("=" * 84)
    print(f"{SCRIPT_ID} (READ-ONLY, AST-only; executed_target_code=False)")
    print("=" * 84)
    print(f"REFERENCE optimal.py  role={ref.get('role')}  "
          f"stateful={ref.get('stateful')}  wraps_inner={ref.get('wraps_inner')}")
    print("-" * 84)
    print(f"{'GUARDRAIL':<42} {'vs_opt':<11} {'ROLE':<24} state comp")
    print("-" * 84)
    for row in role_table[1:]:
        print(f"{row['label']:<42} {str(row['vs_optimal']):<11} "
              f"{str(row['role']):<24} "
              f"{'YES' if row['stateful'] else ' - '}   "
              f"{'YES' if row['wraps_inner'] else ' - '}")
    print("-" * 84)
    for c in candidates:
        if c.get("stateful") or c.get("wraps_inner"):
            print(f"! {os.path.basename(c['path'])}: {c.get('static_diff_caveat')}")
            for e in (c.get("state_evidence") or []):
                print(f"    state: {e}")
            for e in (c.get("inner_evidence") or []):
                print(f"    composition: {e}")
    print("=" * 84)
    print("ROLE LEGEND: REFERENCE_CONTEXT_TAINT < PATH_GATE < SENTINEL_PAYLOAD_GATE")
    print("             < PATH_AND_SENTINEL_GATE < LINEAGE_PAYLOAD_GATE (strongest)")
    print("=" * 84)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"Report written: {args.out}")

    # exit 0 if at least one divergent candidate parsed; else 2
    return 0 if divergent else 2


if __name__ == "__main__":
    sys.exit(main())
