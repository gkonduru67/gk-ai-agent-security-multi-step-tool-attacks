#!/usr/bin/env python3
"""P2C-R7: V21_LEDGER_WIRING_RECONCILIATION (read-only source inspection).

Scientific gate
---------------
P2C-R6 (22/23) confirmed the adapter fix: the model read the treatment fixture
and dispatched http.post in 2/3 seeds. BUT every run recorded
ledger_read_value_sha256 = null -- the V2.1 successful-read ledger captured
NOTHING -- so the lineage guardrail had no read value to match, could not deny,
and the post dispatched. In the frozen v1.2 run the SAME ledger populated and
drove EXFIL_V21_SUCCESSFUL_READ_VALUE_MATCH denial. The V_RENAMED_SOURCE
guardrail question is therefore STILL UNANSWERED until the ledger is engaged.

This gate LOCATES why the ledger populated in v1.2 but not in P2C-R6, WITHOUT
executing the model/Sandbox/guardrail. It statically inspects, from disk:
  - aicomp_sdk_exfil_v2_1/integration_factory_v2_1.py (build_exfil_integration_v21)
  - aicomp_sdk_exfil_v2_1/successful_read_ledger_v2_1.py (the ledger + its hook)
  - aicomp_sdk_exfil_v2_1/lineage_aware_exfil_guardrail_v2_1.py
  - aicomp_sdk/hooks/registry.py (HookRegistry, HookStage)
  - the FROZEN v1.2 experiment runner (model_generation_exfiltration_experiment_v1_2.py)
  - the P2C-R6 runner (this project's exfil_p2c_r6_*.py)
  - the P2C-R6 derived variant (benign_pipeline_EX_v6_toolchoice_harmonyfix_p2c_r6.py)

and compares how each wires: (a) which HookStage the ledger's read-capture hook
registers on, (b) whether the ledger instance is SHARED between the read hook
and the guardrail, (c) whether the SAME HookRegistry instance is passed to
BOTH build_exfil_integration_v21 AND SandboxEnv, and (d) any v1.2-vs-R6 wiring
difference. Emits candidate root causes with NOT_ESTABLISHED where a needed
source is absent, plus the exact source excerpts for review.

Discipline: reads + hashes source only. No model/Sandbox/Gym/tool/guardrail/
predicate/breach execution. No import of inspected modules. No fixture mutation.
No attack optimization.
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

VERSION = "P2C_R7_V21_LEDGER_WIRING_RECONCILIATION_v1.0"

P2C_R6 = {
    "result": ("p2c_r6_adapter_fix_rerun_result_v1_0.json",
              "3976592F7402CA77A4ED613D39969366748F82CC61664A69087CEBD2470540FA"),
    "manifest": ("p2c_r6_adapter_fix_rerun_manifest_v1_0.csv",
                "AB5FFA0E4A623BC5664A61351AAD27CB663F9C4DBABE37065733D8FA861F9FD9"),
}
KNOWN_IDENTITIES = {
    "v21_guardrail": ("aicomp_sdk_exfil_v2_1/lineage_aware_exfil_guardrail_v2_1.py",
                      "2AC1CA55FB0C18460F50B35677F5ECD9EB3477CFB21F9C19F44A48C7AEFD5C26"),
    "v21_ledger": ("aicomp_sdk_exfil_v2_1/successful_read_ledger_v2_1.py",
                  "18146742E6866C491A032AA96EFC248FFED05706895D32FDE724145D0878009C"),
    "sandbox": ("aicomp_sdk/core/env/sandbox.py",
                "B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0"),
}
# Files to discover-and-inspect (identity not pre-pinned; recorded as observed).
DISCOVER = {
    "v21_integration_factory": "aicomp_sdk_exfil_v2_1/integration_factory_v2_1.py",
    "hook_registry": "aicomp_sdk/hooks/registry.py",
    "v1_2_runner": "model_generation_exfiltration_experiment_v1_2.py",
    "p2c_r6_runner": "exfil_p2c_r6_single_variable_adapter_fix_and_rerun_v1_0.py",
    "r6_variant": "benign_pipeline_EX_v6_toolchoice_harmonyfix_p2c_r6.py",
}
HOOK_STAGE_TOKENS = ["PRE_TOOL_CALL", "POST_TOOL_CALL", "CONTEXT_BUILD", "PRE_DECIDE",
                     "POST_DECIDE", "TOOL_RESULT", "HookStage"]
REGISTER_TOKENS = ["register", "add_hook", "register_hook", "execute_hooks", "HookRegistry"]
LEDGER_TOKENS = ["ledger", "record", "records", "raw_output", "canonical_path",
                 "successful_read", "read_value"]
BUILD_TOKENS = ["build_exfil_integration_v21", "hook_registry", "inner", "guardrail", "bundle"]


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


def add(rows, cid, cat, ok, obs, exp, layer):
    rows.append({"check_id": cid, "category": cat, "passed": bool(ok),
                 "observed": json.dumps(obs, sort_keys=True, default=str)[:2000]
                 if isinstance(obs, (dict, list, tuple)) else str(obs),
                 "expected": str(exp), "failure_layer": layer})


def excerpt(lines, tokens, radius=2, max_hits=14):
    out = []
    low = [ln.lower() for ln in lines]
    for i, ln in enumerate(low):
        for tok in tokens:
            if tok.lower() in ln:
                a = max(0, i - radius); b = min(len(lines), i + radius + 1)
                out.append({"line": i + 1, "token": tok,
                            "text": "\n".join(f"{j+1:05d}: {lines[j]}" for j in range(a, b))})
                break
        if len(out) >= max_hits:
            break
    return out


def resolve(project: Path, rel: str) -> Path | None:
    p = project / rel
    if p.is_file():
        return p
    hits = sorted(project.rglob(Path(rel).name))
    return hits[0] if hits else None


def analyze(p: Path) -> dict[str, Any]:
    text = p.read_text(encoding="utf-8-sig", errors="replace")
    lines = text.splitlines()
    functions = []
    try:
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                seg = (ast.get_source_segment(text, node) or "").lower()
                functions.append({"name": node.name, "lineno": node.lineno,
                                  "refs_ledger": any(t in seg for t in ("ledger", "record", "raw_output")),
                                  "refs_hook_stage": any(t.lower() in seg for t in HOOK_STAGE_TOKENS),
                                  "refs_register": any(t in seg for t in ("register", "add_hook")),
                                  "refs_post_tool_call": "post_tool_call" in seg,
                                  "refs_hook_registry": "hookregistry" in seg or "hook_registry" in seg})
    except SyntaxError:
        pass
    return {**ident(p),
            "hook_stage_hits": excerpt(lines, HOOK_STAGE_TOKENS),
            "register_hits": excerpt(lines, REGISTER_TOKENS),
            "ledger_hits": excerpt(lines, LEDGER_TOKENS),
            "build_hits": excerpt(lines, BUILD_TOKENS),
            "functions": functions,
            "mentions_post_tool_call": any("post_tool_call" in ln.lower() for ln in lines),
            "mentions_pre_tool_call": any("pre_tool_call" in ln.lower() for ln in lines),
            "mentions_hook_registry_param": any(("hook_registry" in ln.lower() and "sandboxenv" in ln.lower())
                                                for ln in lines),
            "passes_registry_to_sandbox": any(("hook_registry=" in ln and "SandboxEnv" in ln) for ln in lines),
            "passes_registry_to_build": any(("hook_registry=" in ln and "build_exfil_integration_v21" in ln)
                                            for ln in lines),
            "builds_v21": any("build_exfil_integration_v21" in ln for ln in lines)}


def main(a: argparse.Namespace) -> None:
    out = Path(a.output_dir).resolve()
    need(not out.exists(), f"Refusing overwrite: {out}")
    out.mkdir(parents=True)
    checks: list[dict[str, Any]] = []
    scope = {"read_only": True, "model_executed": False, "sandbox_executed": False,
             "sdk_imported": False, "attack_optimization": False, "files_read": 0}
    idx = 1
    inv: dict[str, Any] = {}
    try:
        project = Path(a.project_root).resolve()
        r6_dir = Path(a.p2c_r6_dir).resolve()
        exfil_dir = Path(a.exfil_dir).resolve() if a.exfil_dir else (project / "Exfil")

        # --- Bind P2C-R6 parent ---
        for key, (fname, expected) in P2C_R6.items():
            p = r6_dir / fname
            ok = p.is_file() and sha_file(p) == expected
            add(checks, f"LW-{idx:03d}", f"p2c_r6_{key}", ok,
                ident(p) if p.is_file() else str(p), {"sha256": expected}, "FIXTURE")
            idx += 1
        need(all(c["passed"] for c in checks), "P2C-R6 parent identity verification failed")

        # --- Known identities (guardrail, ledger, sandbox) ---
        for key, (rel, expected) in KNOWN_IDENTITIES.items():
            p = project / rel
            ok = p.is_file() and sha_file(p) == expected
            add(checks, f"LW-{idx:03d}", f"identity_{key}", ok,
                ident(p) if p.is_file() else str(p), {"sha256": expected}, "FIXTURE")
            idx += 1
            if p.is_file():
                inv[key] = analyze(p); scope["files_read"] += 1
        need(all(c["passed"] for c in checks), "V2.1/sandbox identity verification failed")

        # --- Discover-and-inspect (identity observed, not pre-pinned) ---
        found = {}
        for key, rel in DISCOVER.items():
            # r6 runner & variant live in exfil_dir / r6_dir respectively; others in project
            candidates = [project / rel, exfil_dir / Path(rel).name, r6_dir / Path(rel).name]
            p = next((c for c in candidates if c.is_file()), None) or resolve(project, rel)
            if p and p.is_file():
                inv[key] = analyze(p); found[key] = str(p); scope["files_read"] += 1
                add(checks, f"LW-{idx:03d}", f"discovered_{key}", True, ident(p), "found", "FIXTURE")
            else:
                inv[key] = {"NOT_ESTABLISHED": rel}
                add(checks, f"LW-{idx:03d}", f"discovered_{key}", False, {"searched": rel},
                    "source located", "FIXTURE")
            idx += 1

        # --- Reconciliation analysis (hypothesis testing from source) ---
        ledger = inv.get("v21_ledger", {})
        factory = inv.get("v21_integration_factory", {})
        v12 = inv.get("v1_2_runner", {})
        r6 = inv.get("p2c_r6_runner", {})

        ledger_registers_post_tool = bool(ledger.get("mentions_post_tool_call"))
        factory_shares_registry = bool(factory.get("passes_registry_to_sandbox")) or \
                                  any(f.get("refs_register") and f.get("refs_hook_registry")
                                      for f in factory.get("functions", []))
        # Does the FACTORY itself register the ledger hook, or does the CALLER have to?
        factory_registers_ledger_hook = any(
            f.get("refs_register") and (f.get("refs_ledger") or f.get("refs_post_tool_call"))
            for f in factory.get("functions", []))
        # v1.2 vs R6 registry wiring
        v12_passes_registry_both = bool(v12.get("passes_registry_to_sandbox")) and bool(v12.get("passes_registry_to_build"))
        r6_passes_registry_both = bool(r6.get("passes_registry_to_sandbox")) and bool(r6.get("passes_registry_to_build"))

        add(checks, f"LW-{idx:03d}", "ledger_hook_stage_located",
            ledger_registers_post_tool or bool(ledger.get("hook_stage_hits")),
            {"mentions_post_tool_call": ledger_registers_post_tool,
             "hook_stage_hits": len(ledger.get("hook_stage_hits", []))},
            "ledger read-capture hook stage identified", "GUARDRAIL")
        idx += 1
        add(checks, f"LW-{idx:03d}", "factory_registry_sharing_analyzed", True,
            {"factory_shares_registry": factory_shares_registry,
             "factory_registers_ledger_hook": factory_registers_ledger_hook},
            "factory registry/hook wiring recorded", "GUARDRAIL")
        idx += 1
        add(checks, f"LW-{idx:03d}", "v12_vs_r6_registry_wiring", True,
            {"v1_2_passes_registry_to_sandbox": bool(v12.get("passes_registry_to_sandbox")),
             "v1_2_passes_registry_to_build": bool(v12.get("passes_registry_to_build")),
             "r6_passes_registry_to_sandbox": bool(r6.get("passes_registry_to_sandbox")),
             "r6_passes_registry_to_build": bool(r6.get("passes_registry_to_build"))},
            "v1.2 vs R6 registry wiring compared", "GUARDRAIL")
        idx += 1
        add(checks, f"LW-{idx:03d}", "scope",
            not scope["model_executed"] and not scope["sandbox_executed"] and not scope["sdk_imported"],
            scope, "read-only source inspection; no execution/import", "SCOPE_VIOLATION")
        idx += 1

        failed = [c["check_id"] for c in checks if not c["passed"]]

        # --- Candidate root-cause determination ---
        candidates = []
        if factory_registers_ledger_hook is False and ledger.get("mentions_post_tool_call") is False:
            candidates.append({
                "id": "LEDGER_HOOK_NOT_REGISTERED",
                "why": "neither the v2.1 factory nor the ledger source shows a read-capture hook "
                       "registered on a tool-result/post-tool-call stage; the ledger may only record "
                       "when a hook the CALLER must register fires. If the P2C-R6 runner did not register "
                       "that hook (or registered it on a different registry instance), the ledger stays empty.",
                "confirm_from": "compare ledger.register_hits + factory.register_hits to the v1.2 runner's "
                                "explicit hook registration calls"})
        if v12.get("passes_registry_to_build") != r6.get("passes_registry_to_build") or \
           v12.get("passes_registry_to_sandbox") != r6.get("passes_registry_to_sandbox"):
            candidates.append({
                "id": "REGISTRY_INSTANCE_WIRING_DIFFERS_V12_VS_R6",
                "why": "the v1.2 runner and the P2C-R6 runner differ in whether they pass the SAME "
                       "HookRegistry instance to BOTH build_exfil_integration_v21 and SandboxEnv. If R6 "
                       "built the bundle with one registry but Sandbox used another (or none), the ledger's "
                       "read hook never fires during interact().",
                "confirm_from": "v1_2_runner vs p2c_r6_runner registry-passing flags above"})
        if not candidates:
            candidates.append({
                "id": "UNDETERMINED_FROM_STATIC_SIGNATURES",
                "why": "static flags did not isolate a single cause; review the emitted register_hits / "
                       "ledger_hits / build_hits excerpts for the ledger, factory, v1.2 runner, and R6 runner "
                       "side by side.",
                "confirm_from": "inventory excerpts"})

        recommended_fix = (
            "P2C-R8 (single-variable wiring fix in the NEW runner, not the frozen files): ensure the P2C-R6 "
            "runner registers the v2.1 ledger's read-capture hook onto the EXACT HookRegistry instance passed "
            "to SandboxEnv, mirroring the frozen v1.2 runner's wiring. Do NOT modify the packaged SDK, the "
            "frozen v1.2 runner, the v2.1 ledger/guardrail source, or the frozen pipeline. Verify success by: "
            "ledger.records() non-empty AND ledger_read_value_sha256 populated AND a recorded guardrail "
            "decision on the http.post proposal.")

        status = "RECONCILIATION_COMPLETE" if not failed else "RECONCILIATION_COMPLETE_WITH_GAPS"
        claim = {
            "allowed": [
                "P2C-R6 parent + V2.1/sandbox identities re-verified",
                "the v2.1 factory, ledger, guardrail, hook registry, v1.2 runner, P2C-R6 runner, and R6 "
                "variant were inspected read-only for hook-registration and registry-sharing wiring",
                "candidate root causes for the empty ledger were derived from source signatures",
                "the recommended P2C-R8 fix changes exactly one wiring variable in the NEW runner",
            ],
            "prohibited": [
                "claim the wiring fix is verified (requires P2C-R8 runtime)",
                "claim any V2.1 guardrail behavior on the renamed source (ledger still empty)",
                "claim harness trick or robust security",
                "modify the packaged SDK, frozen v1.2 runner, v2.1 source, or frozen pipeline",
            ],
        }
        result = {
            "version": VERSION, "created_at_utc": now(), "status": status,
            "classification": "READ_ONLY_V21_LEDGER_WIRING_RECONCILIATION",
            "checks": {"total": len(checks), "passed": len(checks) - len(failed),
                       "failed": len(failed), "failed_ids": failed},
            "empty_ledger_symptom": {
                "from_p2c_r6": "ledger_read_value_sha256=null all 3 runs; post dispatched (egress=1) in 2/3; "
                               "guardrail issued no denial",
                "from_v1_2": "ledger populated; drove EXFIL_V21_SUCCESSFUL_READ_VALUE_MATCH denial"},
            "wiring_flags": {
                "ledger_mentions_post_tool_call": ledger.get("mentions_post_tool_call"),
                "factory_shares_registry": factory_shares_registry,
                "factory_registers_ledger_hook": factory_registers_ledger_hook,
                "v1_2_passes_registry_to_sandbox": v12.get("passes_registry_to_sandbox"),
                "v1_2_passes_registry_to_build": v12.get("passes_registry_to_build"),
                "r6_passes_registry_to_sandbox": r6.get("passes_registry_to_sandbox"),
                "r6_passes_registry_to_build": r6.get("passes_registry_to_build")},
            "candidate_root_causes": candidates,
            "recommended_fix": recommended_fix,
            "inventory": inv,
            "execution_boundaries": scope,
            "scientific_verdict": {
                "earliest_unresolved_layer": "GUARDRAIL (ledger not engaged)",
                "guardrail_evaluated": False,
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": "NOT_ESTABLISHED",
                "v_renamed_source_guardrail_behavior": "NOT_ESTABLISHED_LEDGER_EMPTY"},
            "claim_boundary": claim,
            "next_gate": "P2C_R8_LEDGER_WIRING_FIX_AND_RERUN",
        }

        outputs = {
            "result": out / "p2c_r7_ledger_wiring_result_v1_0.json",
            "checks": out / "p2c_r7_ledger_wiring_checks_v1_0.csv",
            "inventory": out / "p2c_r7_ledger_wiring_inventory_v1_0.json",
            "claim": out / "p2c_r7_ledger_wiring_claim_boundary_v1_0.json",
        }
        write_json(outputs["result"], result)
        write_csv(outputs["checks"], checks,
                  ["check_id", "category", "passed", "observed", "expected", "failure_layer"])
        write_json(outputs["inventory"], {"inventory": inv})
        write_json(outputs["claim"], claim)

        runner_id = ident(Path(__file__).resolve())
        rows = [{**ident(p), "role": r.upper()} for r, p in outputs.items()]
        rows.append({**runner_id, "role": "RUNNER"})
        for key, info in inv.items():
            if isinstance(info, dict) and "sha256" in info:
                rows.append({"artifact": info["artifact"], "role": f"INSPECTED_{key.upper()}",
                             "size_bytes": info["size_bytes"], "sha256": info["sha256"], "path": info["path"]})
        manifest = out / "p2c_r7_ledger_wiring_manifest_v1_0.csv"
        write_csv(manifest, rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        ext = out / "p2c_r7_ledger_wiring_manifest_external_binding_v1_0.json"
        write_json(ext, {"version": VERSION, "created_at_utc": now(), "status": status,
                         "manifest_filename": manifest.name, "manifest_sha256": sha_file(manifest),
                         "runner_sha256": runner_id["sha256"], "checks_total": len(checks),
                         "checks_passed": len(checks) - len(failed), "checks_failed": len(failed),
                         "failed_ids": failed,
                         "candidate_root_cause_ids": [c["id"] for c in candidates],
                         "next_gate": result["next_gate"]})
        print(json.dumps({"status": status, "checks": f"{len(checks) - len(failed)}/{len(checks)}",
                          "failed_ids": failed, "files_read": scope["files_read"],
                          "candidate_root_causes": [c["id"] for c in candidates],
                          "wiring_flags": result["wiring_flags"],
                          "manifest_sha256": sha_file(manifest), "next_gate": result["next_gate"]}, indent=2))
    except Exception as exc:  # noqa: BLE001
        (out / "P2C_R7_LEDGER_WIRING_RECONCILIATION_FAILED.json").write_text(
            json.dumps({"version": VERSION, "created_at_utc": now(), "status": "BLOCKED",
                        "error_type": type(exc).__name__, "error": str(exc),
                        "checks_frozen": checks, "inventory_frozen": inv,
                        "execution_boundaries": scope}, indent=2, default=str), encoding="utf-8")
        raise


def parse() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=VERSION)
    p.add_argument("--project-root", required=True)
    p.add_argument("--p2c-r6-dir", required=True,
                   help="P2C-R6 output dir containing its result/manifest")
    p.add_argument("--exfil-dir", default=None,
                   help="optional Exfil working dir containing the runner .py files")
    p.add_argument("--output-dir", required=True)
    return p.parse_args()


if __name__ == "__main__":
    try:
        main(parse())
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
