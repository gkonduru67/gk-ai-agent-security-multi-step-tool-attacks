#!/usr/bin/env python3
"""EX6F-M1A read-only Sandbox post-tool continuation contract inspection.

Statically inspects the frozen Sandbox source using Python AST. It extracts the
line-bound bodies and contracts for SandboxEnv.interact and directly called
local helper methods, then classifies the position of hop-limit checks relative
to agent calls, ToolResult/history updates, and ToolEvent execution.

It does not import the SDK, contact a model/server, construct SandboxEnv,
execute tools, or modify M1 artifacts.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json
from pathlib import Path
from typing import Any

VERSION = "EX6F_M1A_SANDBOX_POST_TOOL_CONTINUATION_CONTRACT_INSPECTION_v6.72"
EXPECTED_PARENT_MANIFEST = "72818AED7016E958295699D42953E09EA1875A02EA7D2A14A47849E3692C9584"
EXPECTED_M1_RESULT = "09027056109FC26DF009794EE408EDE8BDB163B776354A16DC8C8D8F0D673B7F"
EXPECTED_M1_TRACE = "42C7000BEF878787E0FF2FE973D2031A8944C395467B16271F6B866BF56CB1F1"
EXPECTED_SANDBOX = "B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0"

def hf(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda: f.read(1048576), b""):
            h.update(b)
    return h.hexdigest().upper()

def hs(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest().upper()

def dumpx(p: Path, value: Any) -> None:
    with p.open("x", encoding="utf-8") as f:
        json.dump(value, f, indent=2, sort_keys=True, default=str)
        f.write("\n")

def csvout(p: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    with p.open("x", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="raise")
        w.writeheader(); w.writerows(rows)

def dotted(n: ast.AST | None) -> str:
    if isinstance(n, ast.Name): return n.id
    if isinstance(n, ast.Attribute):
        left = dotted(n.value)
        return f"{left}.{n.attr}" if left else n.attr
    return ""

def annotation(n: ast.AST | None) -> str:
    if n is None: return ""
    try: return ast.unparse(n)
    except Exception: return ""

def method_map(tree: ast.Module, class_name: str) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return {x.name: x for x in node.body if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef))}
    return {}

def call_rows(fn: ast.AST, text: str, owner: str) -> list[dict[str, Any]]:
    rows = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            src = ast.get_source_segment(text, n) or ""
            rows.append({
                "owner": owner, "line": n.lineno, "end_line": getattr(n, "end_lineno", n.lineno),
                "callee": dotted(n.func), "source_sha256": hs(src),
                "mentions_max_tool_hops": "max_tool_hops" in src,
                "mentions_history": "history" in src.lower(),
                "mentions_tool_result": "toolresult" in src.replace("_", "").lower(),
                "mentions_tool_event": "toolevent" in src.replace("_", "").lower(),
                "mentions_agent_turn": "agent_turn" in src.lower(),
            })
    return sorted(rows, key=lambda x: (x["line"], x["callee"]))

def control_rows(fn: ast.AST, text: str, owner: str) -> list[dict[str, Any]]:
    rows = []
    for n in ast.walk(fn):
        if isinstance(n, (ast.For, ast.While, ast.If, ast.Break, ast.Continue, ast.Return, ast.Raise)):
            src = ast.get_source_segment(text, n) or ""
            if isinstance(n, ast.If): kind, expr = "if", ast.get_source_segment(text, n.test) or ""
            elif isinstance(n, ast.For): kind, expr = "for", ast.get_source_segment(text, n.iter) or ""
            elif isinstance(n, ast.While): kind, expr = "while", ast.get_source_segment(text, n.test) or ""
            else: kind, expr = type(n).__name__.lower(), ""
            rows.append({
                "owner": owner, "kind": kind, "line": n.lineno, "end_line": getattr(n, "end_lineno", n.lineno),
                "expression": expr, "source_sha256": hs(src),
                "mentions_max_tool_hops": "max_tool_hops" in src,
                "mentions_tool_event": "tool_event" in src.lower(),
                "mentions_agent_turn": "agent_turn" in src.lower(),
                "mentions_history": "history" in src.lower(),
            })
    return sorted(rows, key=lambda x: (x["line"], x["kind"]))

def function_evidence(path: Path, class_name: str, name: str, node: ast.AST, text: str) -> dict[str, Any]:
    body = ast.get_source_segment(text, node) or ""
    args = []
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for a in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
            args.append({"name": a.arg, "annotation": annotation(a.annotation)})
    return {
        "source_file": path.name, "class": class_name, "symbol": name,
        "qualified_symbol": f"{class_name}.{name}", "start_line": node.lineno,
        "end_line": getattr(node, "end_lineno", node.lineno), "source_sha256": hs(body),
        "arguments": args, "return_annotation": annotation(getattr(node, "returns", None)),
        "source_body": body,
    }

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--parent-manifest", required=True, type=Path)
    ap.add_argument("--parent-binding", required=True, type=Path)
    ap.add_argument("--m1-result", required=True, type=Path)
    ap.add_argument("--m1-trace", required=True, type=Path)
    ap.add_argument("--sandbox-source", required=True, type=Path)
    ap.add_argument("--out-root", required=True, type=Path)
    a = ap.parse_args(); out = a.out_root.resolve()
    if out.exists(): ap.error(f"Refusing to overwrite: {out}")
    frozen = [
        (a.parent_manifest, EXPECTED_PARENT_MANIFEST, "parent manifest"),
        (a.m1_result, EXPECTED_M1_RESULT, "M1 result"),
        (a.m1_trace, EXPECTED_M1_TRACE, "M1 trace"),
        (a.sandbox_source, EXPECTED_SANDBOX, "Sandbox source"),
    ]
    for p, digest, label in frozen:
        if not p.is_file() or hf(p) != digest: ap.error(f"Frozen {label} identity mismatch: {p}")
    binding = json.loads(a.parent_binding.read_text(encoding="utf-8"))
    if binding.get("manifest_sha256") != hf(a.parent_manifest): ap.error("Parent binding mismatch")
    text = a.sandbox_source.read_text(encoding="utf-8")
    tree = ast.parse(text)
    methods = method_map(tree, "SandboxEnv")
    if "interact" not in methods: ap.error("SandboxEnv.interact not found")
    interact = methods["interact"]
    direct_calls = call_rows(interact, text, "SandboxEnv.interact")
    local_direct = []
    for row in direct_calls:
        callee = row["callee"]
        if callee.startswith("self."):
            candidate = callee.split(".")[-1]
            if candidate in methods and candidate not in local_direct: local_direct.append(candidate)
    selected = ["interact", *local_direct]
    evidence = []
    calls = []; controls = []
    for name in selected:
        node = methods[name]
        evidence.append(function_evidence(a.sandbox_source, "SandboxEnv", name, node, text))
        calls.extend(call_rows(node, text, f"SandboxEnv.{name}"))
        controls.extend(control_rows(node, text, f"SandboxEnv.{name}"))
    interact_body = evidence[0]["source_body"]
    hop_controls = [r for r in controls if r["owner"] == "SandboxEnv.interact" and r["mentions_max_tool_hops"]]
    agent_calls = [r for r in calls if "agent" in r["callee"].lower() and ("next_action" in r["callee"] or r["callee"].endswith("agent"))]
    history_calls = [r for r in calls if r["mentions_history"] or "history" in r["callee"].lower()]
    tool_result_calls = [r for r in calls if r["mentions_tool_result"] or "tool_result" in r["callee"].lower()]
    tool_event_calls = [r for r in calls if r["mentions_tool_event"] or "tool" in r["callee"].lower()]
    agent_turn_mentions = [r for r in controls + calls if r["mentions_agent_turn"]]
    hop_lines = [r["line"] for r in hop_controls]
    agent_lines = [r["line"] for r in agent_calls]
    history_lines = [r["line"] for r in history_calls]
    tool_result_lines = [r["line"] for r in tool_result_calls]
    # Source-grounded classification from relative line order only.
    if not hop_controls:
        classification = "MAX_TOOL_HOPS_STOP_CONTRACT_NOT_IDENTIFIED"
    elif agent_lines and max(hop_lines) < min(agent_lines):
        classification = "HOP_LIMIT_CHECK_PRECEDES_AGENT_CALL"
    elif tool_result_lines and max(tool_result_lines) < max(hop_lines):
        classification = "TOOL_RESULT_UPDATE_PRECEDES_LATER_HOP_LIMIT_CHECK"
    else:
        classification = "HOP_LIMIT_RELATIVE_ORDER_REQUIRES_MANUAL_LINE_REVIEW"
    m1 = json.loads(a.m1_result.read_text(encoding="utf-8"))
    result = {
        "schema": "EX6F_M1A_V6_72", "version": VERSION, "classification": classification,
        "execution_type": "READ_ONLY_LINE_BOUND_SANDBOX_CONTINUATION_CONTRACT_INSPECTION",
        "m1_parent": {"classification": m1.get("classification"), "max_tool_hops": m1.get("max_tool_hops"), "transport_response_count": m1.get("transport_response_count"), "final_local_response_established": m1.get("final_local_response_established")},
        "findings": {
            "direct_local_helpers_called_by_interact": local_direct,
            "hop_limit_control_count": len(hop_controls), "hop_limit_control_lines": hop_lines,
            "agent_call_lines": agent_lines, "history_related_call_lines": history_lines,
            "tool_result_related_call_lines": tool_result_lines,
            "tool_event_related_call_lines": [r["line"] for r in tool_event_calls],
            "agent_turn_counter_references_present": bool(agent_turn_mentions),
            "max_tool_hops_text_present": "max_tool_hops" in interact_body,
            "EnvInteractionResult_text_present": "EnvInteractionResult" in interact_body,
        },
        "questions": {
            "how_max_tool_hops_is_counted": "SEE_LINE_BOUND_SOURCE_AND_CONTROL_INVENTORY",
            "final_model_turn_after_last_tool": "ESTABLISHED_ONLY_IF_EXPLICIT_IN_SOURCE_BODY",
            "ToolResult_appended_before_hop_check": "SEE_RELATIVE_LINE_ORDER_AND_SOURCE_BODY",
            "one_hop_semantics": "SEE_CLASSIFICATION_AND_SOURCE_BODY",
            "agent_turns_separate_from_tool_events": "ESTABLISHED" if "agent_turn" in interact_body and "tool_event" in interact_body else "NOT_ESTABLISHED",
            "EnvInteractionResult_on_exhaustion": "SEE_RETURN_EXPRESSIONS_IN_SOURCE_BODY",
        },
        "claim_boundaries": {
            "source_inspection_only": True, "SDK_imported": False, "model_called": False,
            "server_contacted": False, "Sandbox_constructed": False, "tool_execution": False,
            "M1_rerun": False, "security_finding": "NOT_ESTABLISHED", "harness_trick": "NOT_DEMONSTRATED",
        },
        "authorization": {
            "manual_source_review": True,
            "M1A_orchestration_corrected_runner_development": classification != "MAX_TOOL_HOPS_STOP_CONTRACT_NOT_IDENTIFIED",
            "M1A_execution": False, "M2_execution": False, "attack_optimization": False,
        },
    }
    out.mkdir(parents=True)
    dumpx(out / "ex6f_m1a_contract_reconciliation.json", result)
    dumpx(out / "ex6f_m1a_line_bound_source_evidence.json", {"version": VERSION, "functions": evidence})
    call_fields = ["owner", "line", "end_line", "callee", "source_sha256", "mentions_max_tool_hops", "mentions_history", "mentions_tool_result", "mentions_tool_event", "mentions_agent_turn"]
    control_fields = ["owner", "kind", "line", "end_line", "expression", "source_sha256", "mentions_max_tool_hops", "mentions_tool_event", "mentions_agent_turn", "mentions_history"]
    csvout(out / "ex6f_m1a_call_inventory.csv", call_fields, calls)
    csvout(out / "ex6f_m1a_control_flow_inventory.csv", control_fields, controls)
    sources = [a.parent_manifest, a.parent_binding, a.m1_result, a.m1_trace, a.sandbox_source, Path(__file__).resolve()]
    manifest = [{"artifact": p.name, "role": "SOURCE_OR_PARENT", "size_bytes": p.stat().st_size, "sha256": hf(p)} for p in sources]
    for p in out.iterdir():
        if p.is_file(): manifest.append({"artifact": p.name, "role": "DERIVED", "size_bytes": p.stat().st_size, "sha256": hf(p)})
    mp = out / "ex6f_m1a_manifest.csv"
    csvout(mp, ["artifact", "role", "size_bytes", "sha256"], manifest)
    dumpx(out / "ex6f_m1a_manifest_external_binding.json", {"manifest_filename": mp.name, "manifest_size_bytes": mp.stat().st_size, "manifest_sha256": hf(mp), "binding_scope": "EXTERNAL_SELF_BINDING_RECORD"})
    print(json.dumps({"version": VERSION, "classification": classification, "direct_local_helpers": local_direct, "hop_limit_control_lines": hop_lines, "agent_call_lines": agent_lines, "manifest_sha256": hf(mp)}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
