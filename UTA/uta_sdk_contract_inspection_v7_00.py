#!/usr/bin/env python3
"""UTA SDK contract inspection v7.00.

Static, evidence-preserving inspection of the authoritative AI Comp SDK files.
The script does not execute or modify SDK code or fixtures. It creates:
  1. uta_sdk_contract_v7_00.json
  2. uta_sdk_contract_v7_00.md
  3. uta_sdk_contract_v7_00_freeze_manifest.json

Interpretation remains evidence-based: automatically discovered symbols and excerpts
are observations, not claims that a particular runtime path was executed.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import os
import platform
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

VERSION = "UTA_SDK_CONTRACT_v7.00"

AUTHORITATIVE_FILES = {
    "predicate_file": "aicomp_sdk/core/predicates.py",
    "sandbox_file": "aicomp_sdk/core/env/sandbox.py",
    "api_file": "aicomp_sdk/core/env/api.py",
    "gym_file": "aicomp_sdk/core/env/gym.py",
    "base_guardrail": "aicomp_sdk/attacks/baselines/guardrail_rules.py",
    "optimal_guardrail": "aicomp_sdk/guardrails/optimal.py",
    "web_fixture": "aicomp_sdk/fixtures/web_corpus.json",
    "email_fixture": "aicomp_sdk/fixtures/mail_seed.json",
    "cli_test": "aicomp_sdk/cli/commands/test.py",
}

# Terms are deliberately broad. Hits are evidence leads, not semantic conclusions.
SEARCH_GROUPS = {
    "uta_predicate": [
        r"UNTRUSTED_TO_ACTION", r"untrusted.{0,40}action",
        r"untrusted", r"predicate", r"breach",
    ],
    "event_and_trace": [
        r"event", r"trace", r"history", r"tool_call", r"tool_result",
        r"pre_state", r"post_state",
    ],
    "guardrail": [
        r"guardrail", r"allow", r"deny", r"block", r"hook",
    ],
    "fixture_and_provenance": [
        r"fixture", r"web_corpus", r"mail_seed", r"source", r"provenance",
        r"trusted", r"untrusted", r"ToolSuite",
    ],
    "environment": [
        r"SandboxEnv", r"GymAttackEnv", r"reset", r"step", r"execute",
        r"evaluate", r"diagnostic",
    ],
}

MAX_EXCERPTS_PER_GROUP_PER_FILE = 20
CONTEXT_LINES = 3


@dataclass
class SourceExcerpt:
    group: str
    matched_pattern: str
    start_line: int
    end_line: int
    text: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def read_text_exact(path: Path) -> tuple[str, str]:
    raw = path.read_bytes()
    for encoding in ("utf-8", "utf-8-sig"):
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace"), "utf-8-replacement"


def safe_rel(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def node_signature(node: ast.AST) -> dict[str, Any]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        args = []
        for arg in list(node.args.posonlyargs) + list(node.args.args):
            args.append(arg.arg)
        if node.args.vararg:
            args.append("*" + node.args.vararg.arg)
        for arg in node.args.kwonlyargs:
            args.append(arg.arg)
        if node.args.kwarg:
            args.append("**" + node.args.kwarg.arg)
        return {
            "kind": "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function",
            "name": node.name,
            "line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "arguments": args,
            "decorators": [ast.unparse(x) for x in node.decorator_list],
        }
    if isinstance(node, ast.ClassDef):
        return {
            "kind": "class",
            "name": node.name,
            "line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "bases": [ast.unparse(x) for x in node.bases],
            "decorators": [ast.unparse(x) for x in node.decorator_list],
        }
    raise TypeError(type(node).__name__)


def inspect_python(path: Path, text: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "parse_ok": False,
        "parse_error": None,
        "symbols": [],
        "imports": [],
        "string_constants_of_interest": [],
    }
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        result["parse_error"] = {
            "message": str(exc), "line": exc.lineno, "offset": exc.offset
        }
        return result

    result["parse_ok"] = True
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            result["symbols"].append(node_signature(node))
        elif isinstance(node, ast.Import):
            result["imports"].extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            prefix = "." * node.level + (node.module or "")
            result["imports"].extend(f"{prefix}:{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
            if re.search(r"untrusted|guardrail|breach|predicate|tool|trace|event", value, re.I):
                result["string_constants_of_interest"].append(value[:500])

    result["symbols"].sort(key=lambda x: (x["line"], x["name"]))
    result["imports"] = sorted(set(result["imports"]))
    result["string_constants_of_interest"] = sorted(
        set(result["string_constants_of_interest"])
    )[:100]
    return result


def json_shape(value: Any, depth: int = 0) -> Any:
    if depth >= 5:
        return {"type": type(value).__name__, "truncated": True}
    if isinstance(value, dict):
        return {
            "type": "object",
            "count": len(value),
            "keys": sorted(str(k) for k in value.keys()),
            "value_shapes": {
                str(k): json_shape(v, depth + 1)
                for k, v in list(value.items())[:5]
            },
        }
    if isinstance(value, list):
        return {
            "type": "array",
            "count": len(value),
            "sample_shapes": [json_shape(v, depth + 1) for v in value[:3]],
        }
    return {"type": type(value).__name__}


def inspect_json(path: Path, text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
        return {"parse_ok": True, "parse_error": None, "shape": json_shape(value)}
    except json.JSONDecodeError as exc:
        return {
            "parse_ok": False,
            "parse_error": {
                "message": str(exc), "line": exc.lineno, "column": exc.colno
            },
            "shape": None,
        }


def collect_excerpts(text: str) -> list[SourceExcerpt]:
    lines = text.splitlines()
    excerpts: list[SourceExcerpt] = []
    used_ranges: set[tuple[str, int, int]] = set()

    for group, patterns in SEARCH_GROUPS.items():
        group_count = 0
        for index, line in enumerate(lines):
            if group_count >= MAX_EXCERPTS_PER_GROUP_PER_FILE:
                break
            for pattern in patterns:
                if re.search(pattern, line, re.I):
                    start = max(0, index - CONTEXT_LINES)
                    end = min(len(lines), index + CONTEXT_LINES + 1)
                    key = (group, start, end)
                    if key in used_ranges:
                        break
                    used_ranges.add(key)
                    numbered = "\n".join(
                        f"{i + 1:06d}: {lines[i]}" for i in range(start, end)
                    )
                    excerpts.append(
                        SourceExcerpt(
                            group=group,
                            matched_pattern=pattern,
                            start_line=start + 1,
                            end_line=end,
                            text=numbered,
                        )
                    )
                    group_count += 1
                    break
    return excerpts


def inspect_file(label: str, path: Path, project_root: Path) -> dict[str, Any]:
    text, encoding = read_text_exact(path)
    stat = path.stat()
    record: dict[str, Any] = {
        "label": label,
        "relative_path": safe_rel(path, project_root),
        "size_bytes": stat.st_size,
        "mtime_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        "sha256": sha256_file(path),
        "encoding_used_for_inspection": encoding,
        "line_count": len(text.splitlines()),
        "excerpts": [asdict(x) for x in collect_excerpts(text)],
    }
    if path.suffix.lower() == ".py":
        record["python_static_analysis"] = inspect_python(path, text)
    elif path.suffix.lower() == ".json":
        record["json_static_analysis"] = inspect_json(path, text)
    return record


def atomic_write_text(path: Path, text: str) -> None:
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite existing artifact: {path}")
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write_text(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def build_markdown(contract: dict[str, Any]) -> str:
    lines: list[str] = []
    lines += [
        "# UTA SDK Contract Inspection v7.00",
        "",
        f"- Generated UTC: `{contract['generated_utc']}`",
        f"- Project root: `{contract['project_root']}`",
        f"- Status: `{contract['status']}`",
        "- Method: static source and fixture inspection; no SDK module was imported or executed.",
        "- Interpretation rule: excerpts identify evidence locations but do not alone prove runtime execution.",
        "",
        "## Authoritative file inventory",
        "",
        "| Label | Relative path | Bytes | Lines | SHA-256 | Parse |",
        "|---|---|---:|---:|---|---|",
    ]
    for item in contract["files"]:
        parse = "n/a"
        if "python_static_analysis" in item:
            parse = "OK" if item["python_static_analysis"]["parse_ok"] else "ERROR"
        if "json_static_analysis" in item:
            parse = "OK" if item["json_static_analysis"]["parse_ok"] else "ERROR"
        lines.append(
            f"| {item['label']} | `{item['relative_path']}` | {item['size_bytes']} | "
            f"{item['line_count']} | `{item['sha256']}` | {parse} |"
        )

    lines += [
        "",
        "## Inspection findings requiring human confirmation",
        "",
        "The following are deliberately framed as verification tasks rather than inferred SDK behavior:",
        "",
    ]
    for task in contract["human_verification_tasks"]:
        lines.append(f"- [ ] {task}")

    for item in contract["files"]:
        lines += ["", f"## `{item['relative_path']}`", ""]
        py = item.get("python_static_analysis")
        if py:
            lines.append(f"AST parse: `{'OK' if py['parse_ok'] else 'ERROR'}`")
            lines.append("")
            if py["parse_error"]:
                lines.append(f"Parse error: `{py['parse_error']}`")
                lines.append("")
            lines.append("### Symbols")
            lines.append("")
            for symbol in py["symbols"]:
                lines.append(
                    f"- `{symbol['kind']} {symbol['name']}` lines "
                    f"{symbol['line']}-{symbol['end_line']}"
                )
        js = item.get("json_static_analysis")
        if js:
            lines.append(f"JSON parse: `{'OK' if js['parse_ok'] else 'ERROR'}`")
            lines.append("")
            lines.append("### Fixture shape")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(js["shape"], indent=2, ensure_ascii=False))
            lines.append("```")

        lines += ["", "### Evidence excerpts", ""]
        if not item["excerpts"]:
            lines.append("No configured search-term excerpts found.")
        for excerpt in item["excerpts"]:
            lines.append(
                f"#### {excerpt['group']} | lines {excerpt['start_line']}-{excerpt['end_line']} "
                f"| pattern `{excerpt['matched_pattern']}`"
            )
            lines.append("")
            lines.append("```text")
            lines.append(excerpt["text"])
            lines.append("```")

    lines += [
        "",
        "## Interpretation boundaries",
        "",
        "- Symbol presence does not prove the symbol is on the runtime path.",
        "- A term match does not establish semantic meaning or enforcement behavior.",
        "- Fixture shape does not prove ToolSuite loaded a specific record.",
        "- Guardrail source text does not prove a guardrail was invoked for a candidate.",
        "- Predicate source text does not prove a trace satisfies that predicate.",
        "- Sandbox and Gym equivalence requires later per-candidate execution evidence.",
        "",
    ]
    return "\n".join(lines)


def build_manifest(output_dir: Path, artifact_paths: Iterable[Path], inputs: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "manifest_schema": "UTA_SDK_CONTRACT_FREEZE_MANIFEST_V1",
        "experiment_version": VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "inputs": [
            {
                "relative_path": item["relative_path"],
                "size_bytes": item["size_bytes"],
                "sha256": item["sha256"],
            }
            for item in inputs
        ],
        "outputs": [
            {
                "file_name": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in artifact_paths
        ],
        "runtime": {
            "python": sys.version,
            "platform": platform.platform(),
            "script_file": Path(__file__).name,
            "script_sha256": sha256_file(Path(__file__).resolve()),
        },
        "limitations": [
            "Static inspection only; no SDK module or environment was executed.",
            "Regex excerpts are evidence leads and require source-level human confirmation.",
            "Manifest hash is intentionally external to the manifest to avoid self-reference.",
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--allow-existing-empty-out-dir",
        action="store_true",
        help="Allow an existing output directory only when it is empty.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    project_root = args.project_root.expanduser().resolve()
    output_dir = args.out_dir.expanduser().resolve()

    if not project_root.is_dir():
        raise SystemExit(f"Project root not found: {project_root}")

    missing = []
    resolved: dict[str, Path] = {}
    for label, relative in AUTHORITATIVE_FILES.items():
        path = project_root / Path(relative)
        resolved[label] = path
        if not path.is_file():
            missing.append(relative)
    if missing:
        print("SDK contract inspection aborted. Missing authoritative files:", file=sys.stderr)
        for relative in missing:
            print(f"  - {relative}", file=sys.stderr)
        return 2

    if output_dir.exists():
        entries = list(output_dir.iterdir())
        if entries or not args.allow_existing_empty_out_dir:
            raise SystemExit(
                f"Refusing to use existing output directory: {output_dir}\n"
                "Choose a new versioned directory. An existing empty directory may be used "
                "only with --allow-existing-empty-out-dir."
            )
    else:
        output_dir.mkdir(parents=True, exist_ok=False)

    file_records = [
        inspect_file(label, path, project_root)
        for label, path in resolved.items()
    ]

    parse_failures = []
    for item in file_records:
        for key in ("python_static_analysis", "json_static_analysis"):
            if key in item and not item[key]["parse_ok"]:
                parse_failures.append({
                    "relative_path": item["relative_path"],
                    "error": item[key]["parse_error"],
                })

    contract = {
        "contract_schema": "UTA_SDK_CONTRACT_INSPECTION_V1",
        "experiment_version": VERSION,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "project_root": str(project_root),
        "status": "INSPECTION_COMPLETE" if not parse_failures else "INSPECTION_COMPLETE_WITH_PARSE_ERRORS",
        "method": {
            "type": "static_source_and_fixture_inspection",
            "sdk_imported": False,
            "sdk_executed": False,
            "files_modified": False,
        },
        "files": file_records,
        "parse_failures": parse_failures,
        "human_verification_tasks": [
            "Confirm the exact UNTRUSTED_TO_ACTION predicate conditions and required event order in predicates.py.",
            "Confirm where breach aggregation consumes predicate results and whether it transforms or only aggregates them.",
            "Confirm SandboxEnv order: agent proposal, guardrail evaluation, tool execution, event recording, state update, predicate, and breach.",
            "Confirm the concrete guardrail decision representation and how denied proposals appear in trace/history.",
            "Confirm ToolSuite fixture initialization and the lookup fields required by web.open and email read operations.",
            "Confirm the trust/source fields returned by controlled web and email records.",
            "Confirm API validation fields and diagnostics available for preserving configuration and failures.",
            "Confirm Gym delegates to SandboxEnv and identify all observation or history transformations.",
            "Confirm CLI agent and guardrail construction plus history/output serialization.",
        ],
        "interpretation_boundaries": [
            "Static symbol or text presence does not prove runtime invocation.",
            "Fixture schema does not prove a specific record was loaded or returned.",
            "Guardrail source does not prove a candidate was blocked.",
            "Predicate source does not prove a candidate triggered the predicate.",
            "This artifact defines inspection leads; runtime assertions require later controlled traces.",
        ],
    }

    json_path = output_dir / "uta_sdk_contract_v7_00.json"
    md_path = output_dir / "uta_sdk_contract_v7_00.md"
    manifest_path = output_dir / "uta_sdk_contract_v7_00_freeze_manifest.json"

    atomic_write_json(json_path, contract)
    atomic_write_text(md_path, build_markdown(contract) + "\n")

    manifest = build_manifest(output_dir, [json_path, md_path], file_records)
    atomic_write_json(manifest_path, manifest)

    manifest_digest = sha256_file(manifest_path)
    print(f"Status: {contract['status']}")
    print(f"Files inspected: {len(file_records)}")
    print(f"Parse failures: {len(parse_failures)}")
    print(f"JSON: {json_path}")
    print(f"Markdown: {md_path}")
    print(f"Freeze manifest: {manifest_path}")
    print(f"Freeze manifest SHA256: {manifest_digest}")
    return 0 if not parse_failures else 3


if __name__ == "__main__":
    raise SystemExit(main())
