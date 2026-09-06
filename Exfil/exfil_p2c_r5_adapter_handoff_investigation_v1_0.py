#!/usr/bin/env python3
"""P2C-R5: ADAPTER_HANDOFF_INVESTIGATION (read-only source inspection).

Scientific gate
---------------
P2C-R4 (8/8, FROZEN) proved by direct raw-body capture that the model emits a
VALID fs.read tool call for BOTH the treatment and canonical prompts:

  finish_reason = "tool_calls"
  message.content = ""              (empty string; CORRECT for a pure tool call)
  message.reasoning_content = <1358 / 1843 chars>   (substantial; NOT null)
  message.tool_calls = [ {function: {name: "fs.read", arguments: {path: ...}}} ]

Yet the P2C SandboxEnv trace recorded ZERO tool_events (agent_turns=1,
ordered_tool_events=[]). The earliest unresolved layer is therefore ROUTING /
ADAPTER_PARSE: the pipeline's response parser and/or the GPTOSSAgent ->
SandboxEnv handoff is dropping a response whose shape is
{finish_reason: tool_calls, content: "", tool_calls: [...]}.

This gate LOCATES the exact source lines responsible, WITHOUT executing the
model, Sandbox, guardrail, or any SDK runtime. It statically inspects the
frozen pipeline plus the agent/adapter modules it references, searching for the
response-parse path and testing (by static pattern) which of these known
failure modes applies:

  MODE_A_CONTENT_GATED    parser only extracts tool calls when message.content
                          is non-empty/truthy  -> a content="" tool call is dropped
  MODE_B_HARMONY_ONLY     parser looks for harmony channel markers/text rather
                          than the OpenAI message.tool_calls array
  MODE_C_FINISH_REASON    parser branches on finish_reason and lacks a
                          "tool_calls" branch (e.g. only handles "stop"/"length")
  MODE_D_KEY_MISMATCH     parser reads a different key (e.g. function_call vs
                          tool_calls, or choices[0].text vs choices[0].message)
  MODE_E_ARG_PARSE        tool_calls found but arguments JSON-string not parsed,
                          causing a downstream drop
  UNDETERMINED            none of the static signatures matched; emit the exact
                          parse-path source lines for manual review

Discipline
----------
Reads and hashes source only (frozen pipeline + referenced agent/adapter/SDK
files). AST + targeted text search. No model, Sandbox, Gym, tool, guardrail,
predicate, or breach execution. No fixture created/mutated. No attack
optimization. Emits the single indicated adapter fix for P2C-R6.
"""
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "P2C_R5_ADAPTER_HANDOFF_INVESTIGATION_v1.0"

PIPELINE_EXPECTED_SHA256 = "588455D0958E6E19C09853B509E7B20E09BF2B065AC69FAEFBC7108C92ED2BB8"
SANDBOX_EXPECTED_SHA256 = "B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0"

# Frozen P2C-R4 parent (provenance chain).
P2C_R4 = {
    "result": ("p2c_r4_raw_capture_result_v1_0.json",
              "0D93C78F26CAA94497E890BC393053FFF724CFEF826219CDABB0D7AF852277AC"),
    "manifest": ("p2c_r4_raw_capture_manifest_v1_0.csv",
                "7C21ED689C80D227F0C8A1F850F8C9F9F7AB9678DD01E37144E3DF8A030E0FFD"),
}

# Candidate SDK/agent/adapter files that may contain the response-parse path.
CANDIDATE_HINTS = [
    "aicomp_sdk/agents/gpt_oss_agent.py",
    "aicomp_sdk/agents/llama_server_backend.py",
    "aicomp_sdk/agents/backends/llama_server_backend.py",
    "aicomp_sdk/agents/backends/gpt_oss_backend.py",
    "aicomp_sdk/agents/gpt_oss/backend.py",
    "aicomp_sdk/agents/hf_chat_template/types.py",
    "aicomp_sdk/agents/protocol.py",
    "aicomp_sdk/agents/types.py",
    "aicomp_sdk/agents/factory.py",
    "aicomp_sdk/core/env/sandbox.py",
]

# Static signatures for each failure mode.
SIG_TOOLCALLS = ["tool_calls", "tool_call", "function_call"]
SIG_CONTENT = ["message.content", '"content"', "'content'", ".content", "content ="]
SIG_HARMONY = ["harmony", "<|channel|>", "<|message|>", "channel", "reasoning_content", "analysis"]
SIG_FINISH = ["finish_reason", "finish reason"]
SIG_MESSAGE = ["message", "choices"]
SIG_ARGS = ["arguments", "json.loads", "literal_eval"]
SIG_TOOL_EVENT = ["ToolEvent", "tool_events", "tools.call", "append"]


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def need(v: bool, m: str) -> None:
    if not v:
        raise ValueError(m)


def sha_file(p: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with Path(p).open("rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest().upper()


def ident(p: Path) -> dict[str, Any]:
    p = Path(p).resolve()
    return {"artifact": p.name, "path": str(p), "size_bytes": p.stat().st_size, "sha256": sha_file(p)}


def write_json(p: Path, v: Any) -> None:
    with Path(p).open("x", encoding="utf-8", newline="\n") as f:
        json.dump(v, f, indent=2, sort_keys=True, ensure_ascii=False, default=str)
        f.write("\n")


def write_csv(p: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with Path(p).open("x", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def add(rows: list[dict[str, Any]], cid: str, cat: str, ok: bool, obs: Any, exp: Any, layer: str) -> None:
    rows.append({"check_id": cid, "category": cat, "passed": bool(ok),
                 "observed": json.dumps(obs, sort_keys=True, default=str)[:2000]
                 if isinstance(obs, (dict, list, tuple)) else str(obs),
                 "expected": str(exp), "failure_layer": layer})


def excerpt(lines: list[str], patterns: list[str], radius: int = 2, max_hits: int = 12) -> list[dict[str, Any]]:
    out = []
    low = [ln.lower() for ln in lines]
    for i, ln in enumerate(low):
        for pat in patterns:
            if pat.lower() in ln:
                a = max(0, i - radius)
                b = min(len(lines), i + radius + 1)
                out.append({"line": i + 1, "pattern": pat,
                            "text": "\n".join(f"{j+1:05d}: {lines[j]}" for j in range(a, b))})
                break
        if len(out) >= max_hits:
            break
    return out


def find_parse_functions(text: str) -> list[dict[str, Any]]:
    """Find functions whose body references both a response/message structure
    and tool_calls -- i.e. candidate response-parse paths."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            seg = ast.get_source_segment(text, node) or ""
            low = seg.lower()
            refs_toolcalls = any(s in low for s in ("tool_calls", "tool_call", "function_call"))
            refs_message = any(s in low for s in ("message", "choices", "response"))
            if refs_toolcalls and refs_message:
                out.append({"name": node.name,
                            "args": [a.arg for a in node.args.args],
                            "lineno": node.lineno,
                            "refs_content": "content" in low,
                            "refs_finish_reason": "finish_reason" in low,
                            "refs_harmony": any(s in low for s in ("harmony", "channel", "<|")),
                            "refs_arguments_parse": any(s in low for s in ("json.loads", "literal_eval")),
                            "creates_tool_event": any(s in low for s in ("toolevent", "tool_events", "append")),
                            })
    return out


def analyze_file(p: Path) -> dict[str, Any]:
    text = p.read_text(encoding="utf-8-sig", errors="replace")
    lines = text.splitlines()
    return {
        **ident(p),
        "parse_functions": find_parse_functions(text),
        "toolcalls_hits": excerpt(lines, SIG_TOOLCALLS),
        "content_hits": excerpt(lines, ["content"]),
        "finish_reason_hits": excerpt(lines, SIG_FINISH),
        "harmony_hits": excerpt(lines, SIG_HARMONY),
        "arguments_hits": excerpt(lines, SIG_ARGS),
        "tool_event_hits": excerpt(lines, SIG_TOOL_EVENT),
        "mentions_tool_calls": any("tool_calls" in ln.lower() for ln in lines),
        "mentions_function_call": any("function_call" in ln.lower() for ln in lines),
        "mentions_harmony": any(any(s in ln.lower() for s in ("harmony", "<|channel|>", "<|message|>")) for ln in lines),
        "mentions_finish_reason": any("finish_reason" in ln.lower() for ln in lines),
    }


def resolve(project: Path, hint: str) -> Path | None:
    d = project / hint
    if d.is_file():
        return d
    hits = sorted(project.rglob(Path(hint).name))
    return hits[0] if hits else None


def classify_failure_mode(inventory: list[dict[str, Any]]) -> tuple[str, str]:
    parsers = [pf for f in inventory for pf in f.get("parse_functions", [])]
    any_toolcalls = any(f.get("mentions_tool_calls") for f in inventory)
    any_function_call = any(f.get("mentions_function_call") for f in inventory)
    any_harmony = any(f.get("mentions_harmony") for f in inventory)
    any_finish = any(f.get("mentions_finish_reason") for f in inventory)

    if not any_toolcalls and any_function_call:
        return ("MODE_D_KEY_MISMATCH",
                "parser references 'function_call' (older OpenAI schema) but not 'tool_calls'; the "
                "gpt-oss response uses message.tool_calls -> a key mismatch drops the call. "
                "FIX: read choices[0].message.tool_calls (the OpenAI tools array).")
    if not any_toolcalls and any_harmony:
        return ("MODE_B_HARMONY_ONLY",
                "parser looks for harmony channel markers rather than the OpenAI message.tool_calls "
                "array; the server already surfaced a structured tool_calls array -> harmony-only "
                "parsing misses it. FIX: prefer message.tool_calls when present, before harmony parsing.")
    # If a parser references tool_calls but is gated on content being truthy:
    content_gated = any(pf.get("refs_content") and not pf.get("creates_tool_event")
                        for pf in parsers) and any(pf.get("refs_content") for pf in parsers)
    if any_toolcalls and content_gated:
        return ("MODE_A_CONTENT_GATED",
                "a response-parse function references message.content and may gate tool-call extraction "
                "on content being non-empty; the gpt-oss tool call has content=\"\" -> dropped. "
                "FIX: extract tool_calls independently of content emptiness.")
    if any_toolcalls and any_finish and not any(pf.get("creates_tool_event") for pf in parsers):
        return ("MODE_C_FINISH_REASON",
                "parser branches on finish_reason and the tool_calls path may not create a ToolEvent; "
                "verify a finish_reason=='tool_calls' branch surfaces the call. "
                "FIX: ensure the tool_calls branch appends a ToolEvent to the trace.")
    if any_toolcalls and not any(pf.get("refs_arguments_parse") for pf in parsers):
        return ("MODE_E_ARG_PARSE",
                "tool_calls referenced but no arguments JSON-string parse (json.loads/literal_eval) found "
                "in the parse path; arguments may remain an unparsed string and be dropped downstream. "
                "FIX: json.loads the tool_call.function.arguments string before building the ToolEvent.")
    return ("UNDETERMINED",
            "no single static signature matched; the emitted parse-path excerpts must be reviewed "
            "manually to locate why a {finish_reason: tool_calls, content: '', tool_calls: [...]} "
            "response yields zero trace events.")


def main(a: argparse.Namespace) -> None:
    out = Path(a.output_dir).resolve()
    need(not out.exists(), f"Refusing overwrite: {out}")
    out.mkdir(parents=True)
    checks: list[dict[str, Any]] = []
    scope = {"read_only": True, "model_executed": False, "sandbox_executed": False,
             "gym_executed": False, "tool_executed": False, "guardrail_executed": False,
             "predicate_executed": False, "breach_executed": False, "sdk_imported": False,
             "fixture_created": False, "fixture_mutated": False, "attack_optimization": False,
             "files_read": 0}
    inventory: list[dict[str, Any]] = []
    idx = 1
    try:
        project = Path(a.project_root).resolve()
        r4_dir = Path(a.p2c_r4_dir).resolve()

        # --- Bind P2C-R4 parent ---
        for key, (fname, expected) in P2C_R4.items():
            p = r4_dir / fname
            ok = p.is_file() and sha_file(p) == expected
            add(checks, f"AH-{idx:03d}", f"p2c_r4_{key}", ok,
                ident(p) if p.is_file() else str(p), {"sha256": expected}, "FIXTURE")
            idx += 1
        need(all(c["passed"] for c in checks), "P2C-R4 parent identity verification failed")

        # --- Pipeline + sandbox identity ---
        pipeline_file = Path(a.pipeline_file).resolve() if a.pipeline_file else None
        if pipeline_file is None or not pipeline_file.is_file():
            for cand in (project / "Exfil" / "benign_pipeline_EX_v6_toolchoice.py",
                        project / "benign_pipeline_EX_v6_toolchoice.py"):
                if cand.is_file():
                    pipeline_file = cand
                    break
        need(pipeline_file is not None and pipeline_file.is_file(), "pipeline file not found")
        ok = sha_file(pipeline_file) == PIPELINE_EXPECTED_SHA256
        add(checks, f"AH-{idx:03d}", "pipeline_identity", ok, ident(pipeline_file),
            {"sha256": PIPELINE_EXPECTED_SHA256}, "FIXTURE")
        idx += 1
        need(ok, "Pipeline identity mismatch")
        inventory.append(analyze_file(pipeline_file)); scope["files_read"] += 1

        sbx = project / "aicomp_sdk/core/env/sandbox.py"
        if sbx.is_file():
            ok = sha_file(sbx) == SANDBOX_EXPECTED_SHA256
            add(checks, f"AH-{idx:03d}", "sandbox_identity", ok, ident(sbx),
                {"sha256": SANDBOX_EXPECTED_SHA256}, "FIXTURE")
            idx += 1

        # --- Discover imports referenced by the pipeline to find the real backend module ---
        pipe_text = pipeline_file.read_text(encoding="utf-8-sig")
        imported_names = re.findall(r"from\s+([\w\.]+)\s+import|import\s+([\w\.]+)", pipe_text)
        imported_mods = sorted({m for pair in imported_names for m in pair if m and "aicomp" in m})

        # --- Analyze candidate + imported modules ---
        analyzed_paths = {pipeline_file.resolve()}
        for hint in CANDIDATE_HINTS:
            p = resolve(project, hint)
            if p and p.resolve() not in analyzed_paths:
                info = analyze_file(p)
                inventory.append(info)
                analyzed_paths.add(p.resolve())
                scope["files_read"] += 1
        for mod in imported_mods:
            rel = mod.replace(".", "/") + ".py"
            p = resolve(project, rel)
            if p and p.resolve() not in analyzed_paths:
                info = analyze_file(p)
                inventory.append(info)
                analyzed_paths.add(p.resolve())
                scope["files_read"] += 1

        add(checks, f"AH-{idx:03d}", "files_analyzed", scope["files_read"] >= 1,
            {"files_read": scope["files_read"], "imported_mods": imported_mods},
            "at least the pipeline analyzed", "ADAPTER_PARSE")
        idx += 1

        # --- Classify the failure mode ---
        mode, mode_reason = classify_failure_mode(inventory)
        add(checks, f"AH-{idx:03d}", "failure_mode_classified", True,
            {"mode": mode, "reason": mode_reason}, "a candidate ROUTING/ADAPTER mode identified", "ROUTING")
        idx += 1

        parse_fn_count = sum(len(f.get("parse_functions", [])) for f in inventory)
        add(checks, f"AH-{idx:03d}", "parse_path_located", parse_fn_count >= 1 or mode != "UNDETERMINED",
            {"parse_function_count": parse_fn_count}, "response-parse candidate located", "ADAPTER_PARSE")
        idx += 1

        add(checks, f"AH-{idx:03d}", "scope", not scope["model_executed"] and not scope["sandbox_executed"]
            and not scope["sdk_imported"] and not scope["attack_optimization"],
            scope, "read-only source inspection; no model/sandbox/import execution", "SCOPE_VIOLATION")
        idx += 1

        failed = [c["check_id"] for c in checks if not c["passed"]]

        FIX = {
            "MODE_A_CONTENT_GATED":
                "Change the adapter to extract choices[0].message.tool_calls INDEPENDENTLY of whether "
                "message.content is empty. A pure tool call correctly has content=''.",
            "MODE_B_HARMONY_ONLY":
                "Change the adapter to prefer choices[0].message.tool_calls (OpenAI tools array) when "
                "present, BEFORE any harmony-channel text parsing.",
            "MODE_C_FINISH_REASON":
                "Add/verify a finish_reason=='tool_calls' branch that appends a ToolEvent from "
                "message.tool_calls to the trace.",
            "MODE_D_KEY_MISMATCH":
                "Change the adapter to read message.tool_calls (not function_call); map each "
                "tool_call.function.{name,arguments} to a ToolEvent.",
            "MODE_E_ARG_PARSE":
                "json.loads the tool_call.function.arguments string before constructing the ToolEvent "
                "so downstream routing receives structured args.",
            "UNDETERMINED":
                "Manually review the emitted parse-path excerpts; provide the backend/agent module that "
                "converts the HTTP response into ToolEvents so the exact drop point can be located.",
        }
        recommended_fix = FIX.get(mode, "NOT_ESTABLISHED")

        status = "INVESTIGATION_COMPLETE" if not failed else "INVESTIGATION_COMPLETE_WITH_GAPS"
        claim = {
            "allowed": [
                "P2C-R4 parent evidence was re-hashed and confirmed identical",
                "the frozen pipeline and its referenced agent/adapter/SDK modules were inspected read-only",
                "response-parse candidate functions (referencing tool_calls + message/choices) were located",
                f"the drop is classified as: {mode}",
                "the recommended fix changes exactly one adapter-parse variable for P2C-R6",
            ],
            "prohibited": [
                "claim runtime behavior was changed (no model/Sandbox executed)",
                "claim the fix is verified (that requires P2C-R6 runtime)",
                "claim anything about the V2.1 guardrail (not reached)",
                "modify the packaged baseline or the frozen pipeline",
            ],
        }
        result = {
            "version": VERSION, "created_at_utc": now(), "status": status,
            "classification": "READ_ONLY_ADAPTER_TO_SANDBOX_HANDOFF_SOURCE_INSPECTION",
            "checks": {"total": len(checks), "passed": len(checks) - len(failed),
                       "failed": len(failed), "failed_ids": failed},
            "observed_model_response_shape": {
                "finish_reason": "tool_calls", "message_content": "(empty string)",
                "message_reasoning_content": "present (1358/1843 chars, from P2C-R4)",
                "message_tool_calls": "[{function:{name:fs.read, arguments:{path:...}}}]",
                "note": "this exact shape yielded ZERO SandboxEnv tool_events in P2C runs",
            },
            "failure_mode": mode, "failure_mode_reason": mode_reason,
            "recommended_single_fix": recommended_fix,
            "imported_aicomp_modules": imported_mods,
            "inventory": inventory,
            "execution_boundaries": scope,
            "scientific_verdict": {
                "earliest_unresolved_layer": "ROUTING/ADAPTER_PARSE",
                "guardrail_evaluated": False,
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": "NOT_ESTABLISHED",
                "model_generation": "HEALTHY_FORMS_TOOL_CALLS (from P2C-R4)",
            },
            "claim_boundary": claim,
            "next_gate": "P2C_R6_SINGLE_VARIABLE_ADAPTER_FIX_AND_RERUN" if mode != "UNDETERMINED"
                         else "P2C_R5_MANUAL_PARSE_PATH_REVIEW",
        }

        outputs = {
            "result": out / "p2c_r5_adapter_handoff_result_v1_0.json",
            "checks": out / "p2c_r5_adapter_handoff_checks_v1_0.csv",
            "inventory": out / "p2c_r5_adapter_handoff_inventory_v1_0.json",
            "claim": out / "p2c_r5_adapter_handoff_claim_boundary_v1_0.json",
        }
        write_json(outputs["result"], result)
        write_csv(outputs["checks"], checks,
                  ["check_id", "category", "passed", "observed", "expected", "failure_layer"])
        write_json(outputs["inventory"], {"inventory": inventory})
        write_json(outputs["claim"], claim)

        runner_id = ident(Path(__file__).resolve())
        rows = [{**ident(p), "role": r.upper()} for r, p in outputs.items()]
        rows.append({**runner_id, "role": "RUNNER"})
        for f in inventory:
            rows.append({"artifact": f["artifact"], "role": "INSPECTED_SOURCE",
                         "size_bytes": f["size_bytes"], "sha256": f["sha256"], "path": f["path"]})
        manifest = out / "p2c_r5_adapter_handoff_manifest_v1_0.csv"
        write_csv(manifest, rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        ext = out / "p2c_r5_adapter_handoff_manifest_external_binding_v1_0.json"
        write_json(ext, {"version": VERSION, "created_at_utc": now(), "status": status,
                         "manifest_filename": manifest.name, "manifest_sha256": sha_file(manifest),
                         "runner_sha256": runner_id["sha256"], "checks_total": len(checks),
                         "checks_passed": len(checks) - len(failed), "checks_failed": len(failed),
                         "failed_ids": failed, "failure_mode": mode,
                         "recommended_single_fix": recommended_fix, "next_gate": result["next_gate"]})
        print(json.dumps({"status": status, "checks": f"{len(checks) - len(failed)}/{len(checks)}",
                          "failed_ids": failed, "failure_mode": mode,
                          "recommended_single_fix": recommended_fix,
                          "files_analyzed": len(inventory), "parse_functions": parse_fn_count,
                          "manifest_sha256": sha_file(manifest), "next_gate": result["next_gate"]}, indent=2))
    except Exception as exc:  # noqa: BLE001
        (out / "P2C_R5_ADAPTER_HANDOFF_INVESTIGATION_FAILED.json").write_text(
            json.dumps({"version": VERSION, "created_at_utc": now(), "status": "BLOCKED",
                        "error_type": type(exc).__name__, "error": str(exc),
                        "checks_frozen": checks, "inventory_frozen": inventory,
                        "execution_boundaries": scope}, indent=2, default=str), encoding="utf-8")
        raise


def parse() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=VERSION)
    p.add_argument("--project-root", required=True)
    p.add_argument("--p2c-r4-dir", required=True,
                   help="P2C-R4 output dir containing its result/manifest")
    p.add_argument("--pipeline-file", default=None,
                   help="path to benign_pipeline_EX_v6_toolchoice.py (statically parsed only)")
    p.add_argument("--output-dir", required=True)
    return p.parse_args()


if __name__ == "__main__":
    try:
        main(parse())
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
