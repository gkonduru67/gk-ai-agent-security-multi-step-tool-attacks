#!/usr/bin/env python3
"""PIPELINE_TOOL_REQUEST_REVIEW_v1_0

READ-ONLY source inspection to explain the corrected root cause from
RAW_RESPONSE_CAPTURE_PROBE_v1_0:

  Direct probe (tools=[fs.read,http.post], tool_choice=auto):
      finish_reason=tool_calls, 38 tokens, valid fs.read tool call in 3.7s.
  M3B / v1.1 pipeline runs:
      finish_reason=length, 2048 tokens, 89s, NO tool call.

Same model, same server -> the difference is in how the EX pipeline BUILDS the
chat-completions request. This runner inspects the pipeline source to find the
exact one-field difference (does it send an OpenAI 'tools' array + 'tool_choice'?
or does it rely on a chat template / free-text protocol that doesn't elicit
structured tool calls?).

Discipline: reads and hashes source only. AST + targeted text search. No model,
no Sandbox, no baseline change, no request is actually sent. Emits the exact
single change for MODEL_GENERATION_EXFILTRATION_v1_2.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "PIPELINE_TOOL_REQUEST_REVIEW_v1.0"

# The working-probe request that DID elicit a tool call (for contrast, not executed).
WORKING_PROBE_REQUEST_KEYS = ["model", "messages", "temperature", "max_tokens", "tools", "tool_choice"]
WORKING_PROBE_BODY_SHA256 = "1A4E6A7C502CF9183FC5240A890AD9D7C28F9F7975C6A2B0C134922F10B7E45C"

# Candidate pipeline / backend files to inspect (resolved under project root; any
# missing file is recorded NOT_FOUND rather than failing the whole run).
CANDIDATE_HINTS = [
    "benign_pipeline_EX_v6.py",
    "benign_pipeline_v6.py",
    "Exfil/benign_pipeline_EX_v6.py",
    "aicomp_sdk/agents/gpt_oss_agent.py",
    "aicomp_sdk/agents/hf_chat_template/types.py",
    "aicomp_sdk/agents/tool_specs.py",
    "aicomp_sdk/agents/factory.py",
    "aicomp_sdk/agents/protocol.py",
    "aicomp_sdk/agents/types.py",
]

# Signals that the request DOES advertise OpenAI-style tools.
TOOLS_ADVERTISE_SIGNALS = [
    '"tools"', "'tools'", "tools=", "tool_choice", '"function"',
    "chat/completions", "/v1/chat/completions",
]
# Signals of a text/harmony free-form protocol (no structured tool array).
FREEFORM_SIGNALS = [
    "chat_template", "apply_chat_template", "harmony", "<|channel|>",
    "reasoning_effort", "completions", "prompt=", "raw_prompt",
]
# Signals the backend posts to the server and reads the response.
BACKEND_SIGNALS = [
    "urlopen", "requests.post", "http", "server_url", "127.0.0.1",
    "LlamaServerBackend", "chat/completions", "max_new_tokens", "max_tokens",
]


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


def sha_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest().upper()


def ident(p: Path) -> dict[str, Any]:
    p = Path(p).resolve()
    return {"artifact": p.name, "path": str(p), "size_bytes": p.stat().st_size, "sha256": sha_file(p)}


def write_json(p: Path, v: Any) -> None:
    with Path(p).open("x", encoding="utf-8", newline="\n") as f:
        json.dump(v, f, indent=2, sort_keys=True, ensure_ascii=False, default=str)
        f.write("\n")


def write_csv(p: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    import csv
    with Path(p).open("x", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        w.writeheader(); w.writerows(rows)


def add(rows, cid, cat, ok, obs, exp, layer):
    rows.append({"check_id": cid, "category": cat, "passed": bool(ok),
                 "observed": json.dumps(obs, default=str)[:2000],
                 "expected": str(exp), "failure_layer": layer})


def signal_lines(text: str, signals: list[str], max_hits: int = 12) -> list[dict[str, Any]]:
    lines = text.splitlines()
    out = []
    low = [ln.lower() for ln in lines]
    for i, ln in enumerate(low):
        for sig in signals:
            if sig.lower() in ln:
                out.append({"line": i + 1, "signal": sig,
                            "excerpt": lines[i].strip()[:200]})
                break
        if len(out) >= max_hits:
            break
    return out


def ast_functions(text: str) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    out = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = [a.arg for a in n.args.args]
            out.append(f"{n.name}({', '.join(args)})")
    return sorted(set(out))


def analyze_file(p: Path) -> dict[str, Any]:
    text = p.read_text(encoding="utf-8-sig", errors="replace")
    tools_hits = signal_lines(text, TOOLS_ADVERTISE_SIGNALS)
    freeform_hits = signal_lines(text, FREEFORM_SIGNALS)
    backend_hits = signal_lines(text, BACKEND_SIGNALS)
    # Does the file build a request dict with a 'tools' key?
    builds_tools_array = bool(re.search(r'["\']tools["\']\s*:', text)) or "tool_choice" in text
    posts_chat_completions = "chat/completions" in text
    uses_chat_template = ("apply_chat_template" in text) or ("chat_template" in text)
    mentions_max_new_tokens = "max_new_tokens" in text
    mentions_max_tokens = "max_tokens" in text
    return {
        **ident(p),
        "functions": ast_functions(text)[:40],
        "builds_tools_array": builds_tools_array,
        "posts_chat_completions": posts_chat_completions,
        "uses_chat_template": uses_chat_template,
        "mentions_max_new_tokens": mentions_max_new_tokens,
        "mentions_max_tokens": mentions_max_tokens,
        "tools_advertise_hits": tools_hits,
        "freeform_hits": freeform_hits,
        "backend_hits": backend_hits,
    }


def resolve(project: Path, hint: str) -> Path | None:
    d = project / hint
    if d.is_file():
        return d
    hits = sorted(project.rglob(Path(hint).name))
    return hits[0] if hits else None


def main(a: argparse.Namespace) -> None:
    out = Path(a.output_dir).resolve()
    need(not out.exists(), f"Refusing overwrite: {out}")
    out.mkdir(parents=True)
    checks: list[dict[str, Any]] = []
    scope = {"model_executed": False, "sandbox_instantiated": False, "baseline_modified": False,
             "attack_optimization": False, "request_sent": False, "read_only": True, "files_read": 0}
    inventory: list[dict[str, Any]] = []
    try:
        project = Path(a.project_root).resolve()
        need(project.is_dir(), f"project_root missing: {project}")

        # --- Optionally bind the capture-probe result as parent (hash) ---
        if a.capture_result and Path(a.capture_result).is_file():
            cid = ident(Path(a.capture_result))
            add(checks, "PT-001", "parent_capture", cid["sha256"] ==
                "3F055F4CE9B51B5006D9508CD51F1A5BDD763DEA64DA37EA09537816EA09B014",
                cid, {"expected": "capture result sha (if provided)"}, "FIXTURE")
        else:
            add(checks, "PT-001", "parent_capture", True,
                {"status": "NOT_PROVIDED"}, "optional", "FIXTURE")

        # --- Resolve + analyze candidate files ---
        idx = 2
        found_any = False
        pipeline_file = None
        backend_file = None
        for hint in CANDIDATE_HINTS:
            p = resolve(project, hint)
            if p is None:
                add(checks, f"PT-{idx:03d}", "file_presence", True,
                    {"hint": hint, "status": "NOT_FOUND"}, "optional", "FIXTURE")
                idx += 1
                continue
            info = analyze_file(p)
            inventory.append(info)
            scope["files_read"] += 1
            found_any = True
            add(checks, f"PT-{idx:03d}", "file_analyzed", True,
                {"file": info["artifact"], "builds_tools_array": info["builds_tools_array"],
                 "posts_chat_completions": info["posts_chat_completions"],
                 "uses_chat_template": info["uses_chat_template"]},
                "file analyzed", "ADAPTER_PARSE")
            idx += 1
            name = p.name.lower()
            if "benign_pipeline" in name and pipeline_file is None:
                pipeline_file = info
            if info["posts_chat_completions"] or "backend" in name or "gpt_oss" in name:
                backend_file = backend_file or info
        need(found_any, "No candidate pipeline/backend files found under project root")

        # --- Diagnose: does ANY inspected file advertise a tools array to chat/completions? ---
        any_tools_array = any(f["builds_tools_array"] for f in inventory)
        any_chat_completions = any(f["posts_chat_completions"] for f in inventory)
        any_chat_template = any(f["uses_chat_template"] for f in inventory)
        request_builder = next((f for f in inventory if f["builds_tools_array"] or f["posts_chat_completions"]), None)

        add(checks, f"PT-{idx:03d}", "tools_advertising_present", True,
            {"any_tools_array": any_tools_array,
             "any_chat_completions": any_chat_completions,
             "any_chat_template": any_chat_template,
             "request_builder_file": (request_builder["artifact"] if request_builder else None)},
            "diagnosis recorded (tools array vs chat template)", "ROUTING"); idx += 1

        add(checks, f"PT-{idx:03d}", "read_only_scope",
            not scope["model_executed"] and not scope["sandbox_instantiated"]
            and not scope["baseline_modified"] and not scope["request_sent"],
            scope, "source inspection only; no model/sandbox/request", "SCOPE_VIOLATION"); idx += 1

        failed = [c["check_id"] for c in checks if not c["passed"]]

        # --- Determine outcome + the single indicated fix ---
        if any_tools_array and any_chat_completions:
            outcome = "PIPELINE_ADVERTISES_TOOLS_INVESTIGATE_WHY_M3B_DID_NOT_ELICIT"
            fix = ("The pipeline DOES build a tools array and posts to chat/completions, yet M3B "
                   "showed finish=length with no tool call. Compare the EXACT request the pipeline "
                   "sent in M3B (request_shape had 183 items) against the working probe. Likely the "
                   "M3B run used prompt_mode/tool_choice that suppressed tool calls, OR a chat_template "
                   "path bypassed the tools array. v1.2: force tool_choice='auto' with the tools array "
                   "on the chat/completions path, EX5 prompt frozen.")
            layer = "ROUTING"
        elif any_chat_template and not any_tools_array:
            outcome = "PIPELINE_USES_CHAT_TEMPLATE_NOT_OPENAI_TOOLS_ARRAY"
            fix = ("The pipeline renders a chat_template / free-form prompt and does NOT send an OpenAI "
                   "'tools' array, so gpt-oss free-runs text to the length cap (exactly M3B's 2048/length). "
                   "SINGLE FIX for v1.2: send the OpenAI tools=[fs.read,http.post] array with "
                   "tool_choice='auto' to /v1/chat/completions (as the working probe did). Keep EX5 prompt frozen.")
            layer = "TOOL_CALL_SERIALIZATION"
        elif not any_chat_completions:
            outcome = "PIPELINE_REQUEST_PATH_NOT_LOCATED_IN_INSPECTED_FILES"
            fix = ("Could not locate the chat/completions request construction in the inspected files. "
                   "Provide the LlamaServerBackend source (or the module that posts to the server) so the "
                   "exact tools/chat-template decision can be read. Read-only follow-up.")
            layer = "ADAPTER_PARSE"
        else:
            outcome = "NOT_ESTABLISHED"
            fix = "Inspected files are ambiguous; provide the backend request-builder source."
            layer = "ADAPTER_PARSE"

        status = "PIPELINE_TOOL_REQUEST_REVIEW_COMPLETE" if not failed else "PIPELINE_TOOL_REQUEST_REVIEW_WITH_GAPS"
        claim = {
            "allowed": [
                "the pipeline/backend source was inspected read-only for tool-request construction",
                "signal lines for tools-array vs chat-template vs backend posting were recorded",
                f"diagnosis: {outcome}",
                "the recommended fix changes exactly one request-construction variable for v1.2",
            ],
            "prohibited": [
                "treat this as evidence about the guardrail or model behavior",
                "claim the model cannot form tool calls (the capture probe proved it can)",
                "modify the baseline or run attack optimization",
            ],
        }
        result = {
            "version": VERSION, "created_at_utc": now(), "status": status,
            "classification": "READ_ONLY_PIPELINE_TOOL_REQUEST_CONSTRUCTION_REVIEW",
            "checks": {"total": len(checks), "passed": len(checks) - len(failed),
                       "failed": len(failed), "failed_ids": failed},
            "outcome": outcome, "recommended_single_fix": fix, "fix_layer": layer,
            "working_probe_reference": {
                "request_keys_that_worked": WORKING_PROBE_REQUEST_KEYS,
                "captured_body_sha256": WORKING_PROBE_BODY_SHA256,
                "note": "the probe sent tools=[fs.read,http.post] + tool_choice=auto and got finish=tool_calls",
            },
            "diagnosis_signals": {
                "any_tools_array": any_tools_array,
                "any_chat_completions": any_chat_completions,
                "any_chat_template": any_chat_template,
            },
            "inventory": inventory,
            "execution_boundaries": scope,
            "scientific_verdict": {
                "model_generation": "HEALTHY_FORMS_TOOL_CALLS (from capture probe)",
                "earliest_unresolved_layer": layer,
                "guardrail_evaluated": False,
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": "NOT_ESTABLISHED",
            },
            "claim_boundary": claim,
            "next_gate": "MODEL_GENERATION_EXFILTRATION_v1_2",
        }
        outputs = {
            "result": out / "pipeline_tool_request_review_result.json",
            "checks": out / "pipeline_tool_request_review_checks.csv",
            "inventory": out / "pipeline_tool_request_review_inventory.json",
            "claim": out / "pipeline_tool_request_review_claim_boundary.json",
            "binding": out / "pipeline_tool_request_review_binding.json",
        }
        write_json(outputs["result"], result)
        write_csv(outputs["checks"], checks,
                  ["check_id", "category", "passed", "observed", "expected", "failure_layer"])
        write_json(outputs["inventory"], {"inventory": inventory})
        write_json(outputs["claim"], claim)
        write_json(outputs["binding"], {"version": VERSION, "created_at_utc": now(),
                                        "runner": ident(Path(__file__).resolve()),
                                        "project_root": str(project),
                                        "files_inspected": [f["path"] for f in inventory],
                                        "execution_boundaries": scope})
        rows = [{**ident(p), "role": "TOOL_REQUEST_REVIEW_DERIVED"} for p in outputs.values()]
        for f in inventory:
            rows.append({"artifact": f["artifact"], "role": "TOOL_REQUEST_REVIEW_SOURCE",
                         "size_bytes": f["size_bytes"], "sha256": f["sha256"], "path": f["path"]})
        manifest = out / "pipeline_tool_request_review_manifest.csv"
        write_csv(manifest, rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        ext = out / "pipeline_tool_request_review_manifest_external_binding.json"
        write_json(ext, {"version": VERSION, "created_at_utc": now(), "status": status,
                         "manifest_filename": manifest.name, "manifest_sha256": sha_file(manifest),
                         "runner_sha256": sha_file(Path(__file__).resolve()),
                         "checks_total": len(checks), "checks_passed": len(checks) - len(failed),
                         "checks_failed": len(failed), "failed_ids": failed,
                         "outcome": outcome, "fix_layer": layer,
                         "next_gate": result["next_gate"]})
        print(json.dumps({"status": status, "checks": f"{len(checks) - len(failed)}/{len(checks)}",
                          "failed_ids": failed, "outcome": outcome, "fix_layer": layer,
                          "any_tools_array": any_tools_array,
                          "any_chat_completions": any_chat_completions,
                          "any_chat_template": any_chat_template,
                          "files_inspected": len(inventory),
                          "manifest_sha256": sha_file(manifest),
                          "next_gate": result["next_gate"]}, indent=2))
    except Exception as exc:  # noqa: BLE001
        (out / "PIPELINE_TOOL_REQUEST_REVIEW_FAILED.json").write_text(
            json.dumps({"version": VERSION, "created_at_utc": now(), "status": "BLOCKED",
                        "error_type": type(exc).__name__, "error": str(exc),
                        "checks_frozen": checks, "inventory_frozen": inventory,
                        "execution_boundaries": scope}, indent=2, default=str), encoding="utf-8")
        raise


def parse() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=VERSION)
    p.add_argument("--project-root", required=True)
    p.add_argument("--capture-result", default=None,
                   help="optional path to raw_response_capture_result.json (hash-bound if provided)")
    p.add_argument("--output-dir", required=True)
    return p.parse_args()


if __name__ == "__main__":
    try:
        main(parse())
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
