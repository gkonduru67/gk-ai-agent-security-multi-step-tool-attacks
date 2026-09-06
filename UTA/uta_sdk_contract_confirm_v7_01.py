#!/usr/bin/env python3
"""Focused UTA SDK contract confirmation v7.01.

Confirms five narrow static-source questions left open by v7.00:
1. Complete UNTRUSTED_TO_ACTION WRITE predicate condition.
2. UNTRUSTED_TO_ACTION branch in is_breach.
3. Sandbox guardrail context construction and denied-proposal recording.
4. Exact web and email tool lookup signatures.
5. optimal.py dangerous_operations and track_untrusted_content invocation.

This script performs static analysis only. It never imports or executes aicomp_sdk,
never modifies SDK sources/fixtures, and refuses to overwrite output artifacts.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import platform
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

VERSION = "UTA_SDK_CONFIRM_v7.01"

CORE_FILES = {
    "predicates": "aicomp_sdk/core/predicates.py",
    "sandbox": "aicomp_sdk/core/env/sandbox.py",
    "optimal": "aicomp_sdk/guardrails/optimal.py",
    "guardrail_base": "aicomp_sdk/guardrails/base.py",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def read_source(path: Path) -> str:
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8-sig")


def line_span(node: ast.AST) -> dict[str, int]:
    return {
        "start_line": getattr(node, "lineno", 0),
        "end_line": getattr(node, "end_lineno", getattr(node, "lineno", 0)),
    }


def source_segment(text: str, node: ast.AST) -> str:
    lines = text.splitlines()
    start = max(1, getattr(node, "lineno", 1))
    end = min(len(lines), getattr(node, "end_lineno", start))
    return "\n".join(f"{i:06d}: {lines[i-1]}" for i in range(start, end + 1))


def excerpt_lines(text: str, start: int, end: int) -> str:
    lines = text.splitlines()
    start = max(1, start)
    end = min(len(lines), end)
    return "\n".join(f"{i:06d}: {lines[i-1]}" for i in range(start, end + 1))


def find_named_node(tree: ast.AST, name: str, kinds: tuple[type, ...]) -> ast.AST | None:
    for node in ast.walk(tree):
        if isinstance(node, kinds) and getattr(node, "name", None) == name:
            return node
    return None


def ast_value(node: ast.AST) -> Any:
    try:
        return ast.literal_eval(node)
    except Exception:
        try:
            return ast.unparse(node)
        except Exception:
            return None


def contains_string(node: ast.AST, value: str) -> bool:
    return any(isinstance(x, ast.Constant) and x.value == value for x in ast.walk(node))


def calls_named(node: ast.AST, names: set[str]) -> list[ast.Call]:
    hits = []
    for x in ast.walk(node):
        if not isinstance(x, ast.Call):
            continue
        func = x.func
        called = None
        if isinstance(func, ast.Name):
            called = func.id
        elif isinstance(func, ast.Attribute):
            called = func.attr
        if called in names:
            hits.append(x)
    return hits


def assignment_to(node: ast.AST, target_name: str) -> list[ast.AST]:
    out = []
    for x in ast.walk(node):
        if isinstance(x, (ast.Assign, ast.AnnAssign)):
            targets = x.targets if isinstance(x, ast.Assign) else [x.target]
            for target in targets:
                names = []
                if isinstance(target, ast.Name):
                    names.append(target.id)
                elif isinstance(target, ast.Attribute):
                    names.append(target.attr)
                if target_name in names:
                    out.append(x)
    return out


def inspect_predicates(path: Path) -> dict[str, Any]:
    text = read_source(path)
    tree = ast.parse(text, filename=str(path))
    eval_fn = find_named_node(tree, "eval_predicates", (ast.FunctionDef, ast.AsyncFunctionDef))
    breach_fn = find_named_node(tree, "is_breach", (ast.FunctionDef, ast.AsyncFunctionDef))
    if eval_fn is None or breach_fn is None:
        raise RuntimeError("Required predicate functions were not found")

    write_nodes = []
    uta_nodes = []
    for node in ast.walk(eval_fn):
        if isinstance(node, ast.If):
            rendered = ast.unparse(node.test)
            if "WRITE" in rendered or contains_string(node.test, "WRITE"):
                write_nodes.append({
                    **line_span(node),
                    "condition": rendered,
                    "excerpt": source_segment(text, node),
                })
        if contains_string(node, "UNTRUSTED_TO_ACTION"):
            uta_nodes.append({
                **line_span(node),
                "excerpt": source_segment(text, node),
            })

    breach_uta = []
    for node in ast.walk(breach_fn):
        if isinstance(node, ast.If) and contains_string(node.test, "UNTRUSTED_TO_ACTION"):
            breach_uta.append({
                **line_span(node),
                "condition": ast.unparse(node.test),
                "excerpt": source_segment(text, node),
            })

    return {
        "file": str(path),
        "sha256": sha256_file(path),
        "eval_predicates": {**line_span(eval_fn)},
        "write_condition_candidates": write_nodes,
        "uta_trigger_blocks": uta_nodes,
        "is_breach": {**line_span(breach_fn)},
        "uta_breach_branches": breach_uta,
        "checks": {
            "write_condition_found": bool(write_nodes),
            "uta_breach_branch_found": bool(breach_uta),
        },
    }


def inspect_sandbox(path: Path) -> dict[str, Any]:
    text = read_source(path)
    tree = ast.parse(text, filename=str(path))

    context_candidates = []
    guardrail_calls = []
    denied_recording = []
    event_append_candidates = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            keys = []
            for key in node.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    keys.append(key.value)
            relevant = sorted(set(keys) & {
                "side_effect", "last_user", "recent_sources", "user_authorized",
                "user_confirmed_safe", "tool_name", "tool_args"
            })
            if relevant:
                context_candidates.append({
                    **line_span(node),
                    "keys": keys,
                    "relevant_keys": relevant,
                    "excerpt": source_segment(text, node),
                })

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "decide":
                guardrail_calls.append({
                    **line_span(node),
                    "call": ast.unparse(node),
                    "excerpt": source_segment(text, node),
                })
            if node.func.attr in {"append", "record", "add", "emit"}:
                rendered = ast.unparse(node)
                if re.search(r"decision|denied|guardrail|tool_event|trace", rendered, re.I):
                    event_append_candidates.append({
                        **line_span(node),
                        "call": rendered,
                        "excerpt": source_segment(text, node),
                    })

        if isinstance(node, ast.If):
            rendered = ast.unparse(node.test)
            block = source_segment(text, node)
            if re.search(r"decision|allow|deny|confirm|blocked", rendered + "\n" + block, re.I):
                denied_recording.append({
                    **line_span(node),
                    "condition": rendered,
                    "excerpt": block,
                })

    # Keep evidence focused but do not silently drop candidates.
    return {
        "file": str(path),
        "sha256": sha256_file(path),
        "context_dict_candidates": context_candidates,
        "guardrail_decide_calls": guardrail_calls,
        "decision_and_denial_branches": denied_recording,
        "recording_call_candidates": event_append_candidates,
        "checks": {
            "guardrail_context_candidate_found": bool(context_candidates),
            "guardrail_decide_call_found": bool(guardrail_calls),
            "decision_branch_found": bool(denied_recording),
            "recording_call_candidate_found": bool(event_append_candidates),
        },
    }


def inspect_optimal(path: Path) -> dict[str, Any]:
    text = read_source(path)
    tree = ast.parse(text, filename=str(path))
    guardrail_cls = find_named_node(tree, "Guardrail", (ast.ClassDef,))
    if guardrail_cls is None:
        raise RuntimeError("Guardrail class not found in optimal.py")

    dangerous_assignments = []
    invocation_sites = []
    method_def = None

    for node in ast.walk(guardrail_cls):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(
                (isinstance(t, ast.Name) and t.id == "dangerous_operations") or
                (isinstance(t, ast.Attribute) and t.attr == "dangerous_operations")
                for t in targets
            ):
                value_node = node.value
                dangerous_assignments.append({
                    **line_span(node),
                    "value": ast_value(value_node),
                    "excerpt": source_segment(text, node),
                })
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "track_untrusted_content":
            method_def = {
                **line_span(node),
                "arguments": [a.arg for a in node.args.args],
                "excerpt": source_segment(text, node),
            }
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "track_untrusted_content":
                invocation_sites.append({
                    **line_span(node),
                    "call": ast.unparse(node),
                    "excerpt": source_segment(text, node),
                })
            elif isinstance(func, ast.Name) and func.id == "track_untrusted_content":
                invocation_sites.append({
                    **line_span(node),
                    "call": ast.unparse(node),
                    "excerpt": source_segment(text, node),
                })

    return {
        "file": str(path),
        "sha256": sha256_file(path),
        "dangerous_operations_assignments": dangerous_assignments,
        "track_untrusted_content_definition": method_def,
        "track_untrusted_content_invocations_within_optimal": invocation_sites,
        "checks": {
            "dangerous_operations_found": bool(dangerous_assignments),
            "track_method_defined": method_def is not None,
            "track_method_invoked_within_optimal": bool(invocation_sites),
        },
        "interpretation_rule": (
            "If the method is defined but no invocation is found, record it as "
            "DEFINED_NOT_INVOKED_WITHIN_OPTIMAL; do not infer external invocation."
        ),
    }


def function_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    return f"{node.name}{ast.unparse(node.args)}"


def class_qualname(parents: list[str], name: str) -> str:
    return ".".join(parents + [name]) if parents else name


def inspect_tool_files(project_root: Path) -> dict[str, Any]:
    tools_root = project_root / "aicomp_sdk" / "core" / "tools"
    if not tools_root.is_dir():
        raise RuntimeError(f"Tools directory not found: {tools_root}")

    files = sorted(tools_root.rglob("*.py"))
    candidates = []
    source_literals = []

    for path in files:
        text = read_source(path)
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError as exc:
            candidates.append({
                "relative_path": path.relative_to(project_root).as_posix(),
                "parse_error": str(exc),
            })
            continue

        class_stack: list[str] = []

        class Visitor(ast.NodeVisitor):
            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                class_stack.append(node.name)
                self.generic_visit(node)
                class_stack.pop()

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                self._handle(node)
                self.generic_visit(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                self._handle(node)
                self.generic_visit(node)

            def _handle(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                body_text = source_segment(text, node)
                attr_strings = {
                    x.value for x in ast.walk(node)
                    if isinstance(x, ast.Constant) and isinstance(x.value, str)
                }
                relevant = (
                    re.search(r"\bweb\b|\bemail\b|mail_seed|web_corpus", body_text, re.I)
                    or node.name.lower() in {"open", "read", "search", "get", "fetch"}
                )
                if relevant:
                    candidates.append({
                        "relative_path": path.relative_to(project_root).as_posix(),
                        "class": ".".join(class_stack) if class_stack else None,
                        "function": node.name,
                        "signature": function_signature(node),
                        **line_span(node),
                        "string_literals": sorted(attr_strings)[:100],
                        "excerpt": body_text,
                    })

        Visitor().visit(tree)

        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and node.value in {"web", "email"}:
                source_literals.append({
                    "relative_path": path.relative_to(project_root).as_posix(),
                    **line_span(node),
                    "value": node.value,
                    "excerpt": excerpt_lines(text, node.lineno - 2, node.lineno + 2),
                })

    exactish = []
    for item in candidates:
        if "signature" not in item:
            continue
        blob = (item.get("excerpt") or "").lower()
        if any(term in blob for term in ("web_corpus", "mail_seed", 'source="web"', 'source="email"', '"source": "web"', '"source": "email"')):
            exactish.append(item)

    return {
        "tools_root": str(tools_root),
        "python_files_scanned": len(files),
        "candidate_lookup_methods": candidates,
        "high_relevance_lookup_methods": exactish,
        "source_literal_locations": source_literals,
        "checks": {
            "tool_files_found": bool(files),
            "lookup_candidates_found": bool(candidates),
            "high_relevance_lookup_method_found": bool(exactish),
        },
    }


def inspect_guardrail_base(path: Path) -> dict[str, Any]:
    text = read_source(path)
    tree = ast.parse(text, filename=str(path))
    decision_cls = find_named_node(tree, "Decision", (ast.ClassDef,))
    guardrail_cls = find_named_node(tree, "GuardrailBase", (ast.ClassDef,))
    return {
        "file": str(path),
        "sha256": sha256_file(path),
        "decision_class": ({**line_span(decision_cls), "excerpt": source_segment(text, decision_cls)} if decision_cls else None),
        "guardrail_base_class": ({**line_span(guardrail_cls), "excerpt": source_segment(text, guardrail_cls)} if guardrail_cls else None),
    }


def atomic_write(path: Path, text: str) -> None:
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite existing artifact: {path}")
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def to_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Focused UTA SDK Contract Confirmation v7.01",
        "",
        f"- Generated UTC: `{report['generated_utc']}`",
        f"- Status: `{report['status']}`",
        "- Method: static AST and source inspection only; SDK was not imported or executed.",
        "",
        "## Decision summary",
        "",
    ]
    for key, value in report["decision_summary"].items():
        lines.append(f"- **{key}**: `{value}`")

    sections = [
        ("1. Complete UTA WRITE predicate condition", report["predicate_confirmation"]),
        ("2. UTA branch in is_breach", {
            "uta_breach_branches": report["predicate_confirmation"]["uta_breach_branches"],
            "check": report["predicate_confirmation"]["checks"]["uta_breach_branch_found"],
        }),
        ("3. Sandbox context and denied-proposal recording", report["sandbox_confirmation"]),
        ("4. Web and email lookup signatures", report["tool_lookup_confirmation"]),
        ("5. Optimal dangerous operations and tracking invocation", report["optimal_confirmation"]),
        ("Guardrail base decision representation", report["guardrail_base_confirmation"]),
    ]
    for title, payload in sections:
        lines += ["", f"## {title}", "", "```json", json.dumps(payload, indent=2, ensure_ascii=False), "```"]

    lines += [
        "",
        "## Interpretation boundaries",
        "",
        "- Static source confirms code structure, not runtime invocation.",
        "- A guardrail deny branch is not evidence that an agent proposed an action.",
        "- A tool method signature is not evidence that a controlled fixture record was loaded or returned.",
        "- No marker lineage or predicate outcome is claimed from this inspection.",
        "- Fixture preflight remains model-free and must preserve exact tool results and events.",
        "",
    ]
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--project-root", required=True, type=Path)
    p.add_argument("--out-dir", required=True, type=Path)
    return p.parse_args()


def main() -> int:
    args = parse_args()
    project_root = args.project_root.expanduser().resolve()
    out_dir = args.out_dir.expanduser().resolve()

    if not project_root.is_dir():
        raise SystemExit(f"Project root not found: {project_root}")
    if out_dir.exists():
        raise SystemExit(f"Refusing to use existing output directory: {out_dir}")

    paths = {k: project_root / v for k, v in CORE_FILES.items()}
    missing = [str(p.relative_to(project_root)) for p in paths.values() if not p.is_file()]
    if missing:
        raise SystemExit("Missing required source files:\n  - " + "\n  - ".join(missing))

    out_dir.mkdir(parents=True, exist_ok=False)

    predicate = inspect_predicates(paths["predicates"])
    sandbox = inspect_sandbox(paths["sandbox"])
    tools = inspect_tool_files(project_root)
    optimal = inspect_optimal(paths["optimal"])
    base = inspect_guardrail_base(paths["guardrail_base"])

    summary = {
        "write_predicate_condition_found": predicate["checks"]["write_condition_found"],
        "uta_is_breach_branch_found": predicate["checks"]["uta_breach_branch_found"],
        "sandbox_guardrail_context_found": sandbox["checks"]["guardrail_context_candidate_found"],
        "sandbox_guardrail_decide_call_found": sandbox["checks"]["guardrail_decide_call_found"],
        "sandbox_denial_recording_evidence_found": (
            sandbox["checks"]["decision_branch_found"] and
            sandbox["checks"]["recording_call_candidate_found"]
        ),
        "web_email_lookup_candidates_found": tools["checks"]["high_relevance_lookup_method_found"],
        "optimal_dangerous_operations_found": optimal["checks"]["dangerous_operations_found"],
        "optimal_track_method_defined": optimal["checks"]["track_method_defined"],
        "optimal_track_method_invoked_within_optimal": optimal["checks"]["track_method_invoked_within_optimal"],
    }

    required_true = [
        summary["write_predicate_condition_found"],
        summary["uta_is_breach_branch_found"],
        summary["sandbox_guardrail_context_found"],
        summary["sandbox_guardrail_decide_call_found"],
        summary["web_email_lookup_candidates_found"],
        summary["optimal_dangerous_operations_found"],
        summary["optimal_track_method_defined"],
    ]
    status = "CONFIRMATION_COMPLETE" if all(required_true) else "CONFIRMATION_INCOMPLETE_REVIEW_EVIDENCE"

    report = {
        "schema": "UTA_FOCUSED_SDK_CONFIRMATION_V1",
        "version": VERSION,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "project_root": str(project_root),
        "status": status,
        "method": {
            "static_only": True,
            "sdk_imported": False,
            "sdk_executed": False,
            "files_modified": False,
        },
        "decision_summary": summary,
        "predicate_confirmation": predicate,
        "sandbox_confirmation": sandbox,
        "tool_lookup_confirmation": tools,
        "optimal_confirmation": optimal,
        "guardrail_base_confirmation": base,
        "interpretation_boundaries": [
            "Static source confirms code structure, not runtime invocation.",
            "A guardrail denial requires a runtime proposed action and captured decision.",
            "A tool signature does not prove fixture loading or retrieval.",
            "DEFINED_NOT_INVOKED_WITHIN_OPTIMAL does not exclude invocation elsewhere.",
        ],
    }

    json_path = out_dir / "uta_sdk_confirmation_v7_01.json"
    md_path = out_dir / "uta_sdk_confirmation_v7_01.md"
    manifest_path = out_dir / "uta_sdk_confirmation_v7_01_freeze_manifest.json"

    atomic_write(json_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    atomic_write(md_path, to_markdown(report) + "\n")

    input_paths = list(paths.values()) + sorted((project_root / "aicomp_sdk/core/tools").rglob("*.py"))
    # Deduplicate while preserving sorted path identity.
    unique_inputs = sorted({p.resolve() for p in input_paths})
    manifest = {
        "schema": "UTA_FOCUSED_SDK_CONFIRMATION_FREEZE_V1",
        "version": VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "inputs": [
            {
                "relative_path": p.relative_to(project_root).as_posix(),
                "size_bytes": p.stat().st_size,
                "sha256": sha256_file(p),
            }
            for p in unique_inputs
        ],
        "outputs": [
            {"file_name": p.name, "size_bytes": p.stat().st_size, "sha256": sha256_file(p)}
            for p in (json_path, md_path)
        ],
        "runtime": {
            "python": sys.version,
            "platform": platform.platform(),
            "script_file": Path(__file__).name,
            "script_sha256": sha256_file(Path(__file__).resolve()),
        },
        "limitations": [
            "Static inspection only.",
            "Manifest SHA-256 is printed externally to avoid self-reference.",
        ],
    }
    atomic_write(manifest_path, json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")

    print(f"Status: {status}")
    for key, value in summary.items():
        print(f"{key}: {value}")
    print(f"JSON: {json_path}")
    print(f"Markdown: {md_path}")
    print(f"Freeze manifest: {manifest_path}")
    print(f"Freeze manifest SHA256: {sha256_file(manifest_path)}")
    return 0 if status == "CONFIRMATION_COMPLETE" else 3


if __name__ == "__main__":
    raise SystemExit(main())
