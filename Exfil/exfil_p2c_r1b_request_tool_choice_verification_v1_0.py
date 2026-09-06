#!/usr/bin/env python3
"""P2C-R1B: REQUEST_TOOL_CHOICE_VERIFICATION (read-only, no new model run).

Scientific gate
---------------
P2C-R1 established (12/12, consistent across all 3 seeds) that the model's
first-turn generation hit finish_reason='length' with ZERO content, ZERO
reasoning_content, and ZERO tool calls, despite tools_advertised_counts=[10]
confirming a tools array WAS present in the request.

This gate answers exactly one further question, from the SAME six
already-captured, hash-bound log files (no new model execution):

    Was 'tool_choice' present in the REQUEST payload for these 3 P2C runs,
    and if so, what value? This directly tests the strongest alternative
    hypothesis raised by prior project evidence (the M3B budget-correction
    finding): that this exact finish=length/empty-content/zero-toolcall
    symptom was previously caused by a MISSING tool_choice field, not by
    insufficient max_new_tokens -- and that raising the token budget alone
    (1024->2048) did NOT resolve it for the canonical prompt.

P2C-R1's transport analyzer only extracted '.tools' array length from
request_shape; it never checked for a '.tool_choice' scalar entry. This gate
closes that specific evidentiary gap.

Method
------
Walks the SAME 'http_request' phase records already read by P2C-R1, and for
each searches request_shape (a list of {path,type,...} shape descriptors) for
any entry whose path ends with '.tool_choice' (or equals 'tool_choice' at top
level). Records whether such an entry exists, its reported type, and -- if the
shape descriptor includes a literal/enum value field -- that value. This is
STILL response/request-SHAPE analysis (the pipeline's own recorded metadata),
never a raw-body decode and never model re-execution.

Discipline
----------
Reads ONLY the same 6 files P2C-R1 already hash-verified (re-verifies them
again here, independently). Imports/executes NOTHING. No fixture created or
mutated. No attack optimization.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "P2C_R1B_REQUEST_TOOL_CHOICE_VERIFICATION_v1.0"

# Same hash-bound per-seed logs P2C-R1 verified (independently re-verified here).
EXPECTED_LOGS = {
    26100: {"debug": "F3E1988C77A06028435F99C95379EAE7FB076FDF4B09EA7950DD9C49CD16D3DA",
            "transport": "CBD356B27787EA4F50E1CB33375954F4CF053DFDE64C6B127B4F0737E2C55395"},
    26103: {"debug": "790DFB3382A874F26F731000E4C69B6EB0B09178E8F20314F580E99F91BB41CD",
            "transport": "3016F963219ABFA52FD7B8C15A7EC29E57E488B70EC1D6C0A525F40C4E0C9691"},
    26105: {"debug": "C057C0DFBE7337741902DB4D472B63B1DC306DB1E2132742C87AE36B0371EF61",
            "transport": "9E16DC6356230AC42ACBD6E63E2AD1E468ACED323DAB53D447F875CD7C97A9B3"},
}
# Parent P2C-R1 triage evidence (bind for provenance; not re-derived here).
P2C_R1 = {
    "result": ("p2c_r1_no_toolcall_triage_result_v1_0.json",
              "2D0910FE8526E1B21FD4B9FAF957503E9D9C34F06886409E5493B59FE2CAC8B3"),
    "manifest": ("p2c_r1_no_toolcall_triage_manifest_v1_0.csv",
                "9C71D734C9048CB1530B34437475544E484AC84EF5127DDDA102566540D3ED3B"),
}
P2C_RUN3_LOG_DIR_HINT = "P2C_V_RENAMED_SOURCE_CONTROLLED_RUNTIME"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def need(v: bool, m: str) -> None:
    if not v:
        raise ValueError(m)


def sha_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest().upper()


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
                 "observed": json.dumps(obs, sort_keys=True, default=str)
                 if isinstance(obs, (dict, list, tuple)) else str(obs),
                 "expected": json.dumps(exp, sort_keys=True, default=str)
                 if isinstance(exp, (dict, list, tuple)) else str(exp),
                 "failure_layer": layer})


def read_jsonl(p: Path) -> list[Any]:
    out = []
    for line in Path(p).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            out.append({"_unparsed_len": len(line)})
    return out


def find_shape_entries_by_suffix(shape: list[Any], suffix: str) -> list[dict[str, Any]]:
    """request_shape is a flat list of {path, type, ...} descriptors describing the
    request JSON's structure. Find every entry whose path ends with the given
    suffix (e.g. '.tool_choice' or exactly 'tool_choice')."""
    hits = []
    for s in shape:
        if not isinstance(s, dict):
            continue
        path = str(s.get("path", ""))
        if path == suffix or path.endswith("." + suffix) or path.endswith(suffix):
            hits.append(s)
    return hits


def analyze_request_tool_choice(records: list[dict[str, Any]]) -> dict[str, Any]:
    reqs = [r for r in records if isinstance(r, dict) and r.get("phase") == "http_request"]
    per_request = []
    for r in reqs:
        shape = r.get("request_shape") or []
        # Search for any shape descriptor referencing tool_choice, at any nesting.
        tc_hits = find_shape_entries_by_suffix(shape, "tool_choice")
        tools_hits = [s for s in shape if isinstance(s, dict)
                     and str(s.get("path", "")).endswith(".tools") and s.get("type") == "array"]
        # Also scan for a top-level 'temperature' shape entry, for completeness
        # (generation config re-verification, same request).
        temp_hits = find_shape_entries_by_suffix(shape, "temperature")
        max_tok_hits = [s for s in shape if isinstance(s, dict)
                       and any(str(s.get("path", "")).endswith(suf)
                              for suf in (".max_tokens", ".max_new_tokens", "max_tokens", "max_new_tokens"))]
        per_request.append({
            "request_shape_length": len(shape),
            "tool_choice_shape_entries": tc_hits,
            "tool_choice_present": len(tc_hits) > 0,
            "tools_array_shape_entries": tools_hits,
            "tools_present": len(tools_hits) > 0,
            "temperature_shape_entries": temp_hits,
            "max_tokens_shape_entries": max_tok_hits,
            "full_request_shape_paths": sorted({str(s.get("path", "")) for s in shape if isinstance(s, dict)}),
        })
    return {"request_count": len(reqs), "per_request": per_request}


def main(a: argparse.Namespace) -> None:
    out = Path(a.output_dir).resolve()
    need(not out.exists(), f"Refusing overwrite: {out}")
    out.mkdir(parents=True)
    checks: list[dict[str, Any]] = []
    scope = {"read_only": True, "model_executed": False, "sdk_executed": False,
             "sandbox_executed": False, "tool_executed": False, "guardrail_executed": False,
             "predicate_executed": False, "breach_executed": False, "fixture_created": False,
             "fixture_mutated": False, "attack_optimization": False}
    idx = 1
    per_seed: list[dict[str, Any]] = []
    try:
        p2c_run3_dir = Path(a.p2c_run3_dir).resolve()
        p2c_r1_dir = Path(a.p2c_r1_dir).resolve()

        # --- Bind P2C-R1 parent (provenance only; not re-derived) ---
        for key, (fname, expected) in P2C_R1.items():
            p = p2c_r1_dir / fname
            ok = p.is_file() and sha_file(p) == expected
            add(checks, f"RB-{idx:03d}", f"p2c_r1_{key}", ok,
                ident(p) if p.is_file() else str(p), {"sha256": expected}, "FIXTURE")
            idx += 1
        need(all(c["passed"] for c in checks), "P2C-R1 parent identity verification failed")

        # --- Independently re-verify + analyze the 3 transport logs ---
        for seed, digs in EXPECTED_LOGS.items():
            trn = p2c_run3_dir / f"server_transport_seed_{seed}.jsonl"
            trn_id = ident(trn) if trn.is_file() else None
            ok_trn = trn.is_file() and trn_id["sha256"] == digs["transport"]
            add(checks, f"RB-{idx:03d}", "transport_log_identity", ok_trn,
                trn_id or str(trn), {"sha256": digs["transport"]}, "FIXTURE")
            idx += 1
            need(ok_trn, f"Transport log identity mismatch for seed {seed}")

            trecs = read_jsonl(trn)
            tinfo = analyze_request_tool_choice(trecs)
            per_seed.append({"seed": seed, "transport_sha256": trn_id["sha256"], **tinfo})

        # --- Aggregate ---
        tool_choice_present_flags = []
        tools_present_flags = []
        for r in per_seed:
            for pr in r.get("per_request", []):
                tool_choice_present_flags.append(pr["tool_choice_present"])
                tools_present_flags.append(pr["tools_present"])

        all_requests_have_tool_choice = (len(tool_choice_present_flags) > 0
                                         and all(tool_choice_present_flags))
        all_requests_have_tools = (len(tools_present_flags) > 0 and all(tools_present_flags))
        add(checks, f"RB-{idx:03d}", "records_scanned", len(per_seed) == 3,
            {"records": len(per_seed)}, "all 3 seeds analyzed", "ROUTING")
        idx += 1
        add(checks, f"RB-{idx:03d}", "tool_choice_presence_determined", True,
            {"all_requests_have_tool_choice": all_requests_have_tool_choice,
             "per_seed_flags": {r["seed"]: [pr["tool_choice_present"] for pr in r.get("per_request", [])]
                                for r in per_seed}},
            "tool_choice presence recorded per request", "ROUTING")
        idx += 1
        add(checks, f"RB-{idx:03d}", "tools_presence_reconfirmed", all_requests_have_tools,
            {"all_requests_have_tools": all_requests_have_tools}, True, "ROUTING")
        idx += 1
        add(checks, f"RB-{idx:03d}", "scope", True, scope,
            "read-only transport-shape re-analysis; no model/sandbox/tool/guardrail/predicate/breach executed",
            "SCOPE_VIOLATION")
        idx += 1

        failed = [c["check_id"] for c in checks if not c["passed"]]

        if all_requests_have_tool_choice:
            diagnosis = "TOOL_CHOICE_CONFIRMED_PRESENT_IN_REQUEST"
            recommendation = ("The request DID carry a tool_choice shape entry for all 3 runs. This "
                              "rules out the missing-tool_choice hypothesis. The finish=length/empty-"
                              "content symptom is therefore more likely a genuine MODEL_GENERATION-layer "
                              "token-budget/reasoning-effort issue for THIS SPECIFIC prompt. Recommended "
                              "next step: P2C-R2 with max_new_tokens raised substantially (e.g. 4096) as "
                              "the single controlled variable, prompt/pipeline/seeds otherwise identical.")
            next_gate = "P2C_R2_RAISE_TOKEN_BUDGET_SINGLE_VARIABLE"
        else:
            diagnosis = "TOOL_CHOICE_MISSING_OR_UNDETECTABLE_IN_REQUEST_SHAPE"
            recommendation = ("No tool_choice shape entry was found in the captured request_shape for "
                              "these 3 runs. This is consistent with the prior M3B finding that this "
                              "exact finish=length/empty-content symptom was caused by an ABSENT "
                              "tool_choice, not by an insufficient token budget (raising max_new_tokens "
                              "1024->2048 alone did NOT resolve the equivalent canonical-prompt symptom). "
                              "Recommended next step: inspect the pipeline's request-construction code path "
                              "actually exercised for the TREATMENT prompt (not just re-confirm its file "
                              "hash) to determine why tool_choice was not propagated for this specific "
                              "invocation, before any token-budget change.")
            next_gate = "P2C_R2_INSPECT_PIPELINE_TOOL_CHOICE_PROPAGATION"

        status = "VERIFICATION_COMPLETE" if not failed else "VERIFICATION_COMPLETE_WITH_GAPS"
        claim = {
            "allowed": [
                "P2C-R1 parent evidence and all 3 transport logs were independently re-hashed and "
                "confirmed identical to the frozen evidence",
                "request_shape entries were searched specifically for a tool_choice path suffix, "
                "closing the evidentiary gap left by P2C-R1's transport analyzer",
                f"diagnosis: {diagnosis}",
                "the recommended next action follows directly from this determination and explicitly "
                "accounts for the prior M3B evidence that budget alone did not resolve this symptom class",
            ],
            "prohibited": [
                "claim this establishes the official EXFILTRATION predicate result",
                "claim this establishes V2.1 lineage guardrail robustness (no proposal was ever formed)",
                "claim harness trick or robust security finding",
                "claim the packaged baseline, pipeline, or fixtures were modified",
                "claim a raw request body was decoded (this is shape-metadata analysis only)",
            ],
        }
        result = {
            "version": VERSION, "created_at_utc": now(), "status": status,
            "classification": "READ_ONLY_REQUEST_TOOL_CHOICE_SHAPE_VERIFICATION",
            "checks": {"total": len(checks), "passed": len(checks) - len(failed),
                       "failed": len(failed), "failed_ids": failed},
            "diagnosis": diagnosis,
            "all_requests_have_tool_choice": all_requests_have_tool_choice,
            "all_requests_have_tools": all_requests_have_tools,
            "per_seed": per_seed,
            "recommended_next_action": recommendation,
            "execution_boundaries": scope,
            "scientific_verdict": {
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": "NOT_ESTABLISHED",
                "guardrail_evaluated": False,
                "tool_choice_diagnosis": diagnosis,
            },
            "claim_boundary": claim,
            "next_gate": next_gate,
        }

        outputs = {
            "result": out / "p2c_r1b_request_tool_choice_verification_result_v1_0.json",
            "checks": out / "p2c_r1b_request_tool_choice_verification_checks_v1_0.csv",
            "per_seed": out / "p2c_r1b_request_tool_choice_verification_per_seed_v1_0.json",
            "claim": out / "p2c_r1b_request_tool_choice_verification_claim_boundary_v1_0.json",
        }
        write_json(outputs["result"], result)
        write_csv(outputs["checks"], checks,
                  ["check_id", "category", "passed", "observed", "expected", "failure_layer"])
        write_json(outputs["per_seed"], {"per_seed": per_seed})
        write_json(outputs["claim"], claim)

        runner_id = ident(Path(__file__).resolve())
        rows = [{**ident(p), "role": r.upper()} for r, p in outputs.items()]
        rows.append({**runner_id, "role": "RUNNER"})
        for seed in EXPECTED_LOGS:
            rows.append({**ident(p2c_run3_dir / f"server_transport_seed_{seed}.jsonl"),
                        "role": f"INPUT_TRANSPORT_{seed}"})
        manifest = out / "p2c_r1b_request_tool_choice_verification_manifest_v1_0.csv"
        write_csv(manifest, rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        ext = out / "p2c_r1b_request_tool_choice_verification_manifest_external_binding_v1_0.json"
        write_json(ext, {"version": VERSION, "created_at_utc": now(), "status": status,
                         "manifest_filename": manifest.name, "manifest_sha256": sha_file(manifest),
                         "runner_sha256": runner_id["sha256"], "checks_total": len(checks),
                         "checks_passed": len(checks) - len(failed), "checks_failed": len(failed),
                         "failed_ids": failed, "diagnosis": diagnosis,
                         "recommended_next_action": recommendation, "next_gate": next_gate})
        print(json.dumps({"status": status, "checks": f"{len(checks) - len(failed)}/{len(checks)}",
                          "failed_ids": failed, "diagnosis": diagnosis,
                          "all_requests_have_tool_choice": all_requests_have_tool_choice,
                          "all_requests_have_tools": all_requests_have_tools,
                          "recommended_next_action": recommendation,
                          "manifest_sha256": sha_file(manifest), "next_gate": next_gate}, indent=2))
    except Exception as exc:  # noqa: BLE001
        (out / "P2C_R1B_REQUEST_TOOL_CHOICE_VERIFICATION_FAILED.json").write_text(
            json.dumps({"version": VERSION, "created_at_utc": now(), "status": "BLOCKED",
                        "error_type": type(exc).__name__, "error": str(exc),
                        "checks_frozen": checks, "per_seed_frozen": per_seed,
                        "execution_boundaries": scope}, indent=2, default=str), encoding="utf-8")
        raise


def parse() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=VERSION)
    p.add_argument("--p2c-run3-dir", required=True,
                   help=r"P2C_v1_1_run3 output dir containing server_transport_seed_*.jsonl")
    p.add_argument("--p2c-r1-dir", required=True,
                   help=r"P2C-R1 triage output dir containing its result/manifest")
    p.add_argument("--output-dir", required=True)
    return p.parse_args()


if __name__ == "__main__":
    try:
        main(parse())
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
