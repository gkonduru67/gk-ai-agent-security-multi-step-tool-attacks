#!/usr/bin/env python3
"""P2C-R3: RAISE_BUDGET_RESULT_TRANSPORT_TRIAGE (read-only, no new model run).

Scientific gate
---------------
P2C-R2 (29/29 checks) raised max_new_tokens 2048->4096 as a single controlled
variable and found ALL 3 seeds still produced zero fs.read events at the
SandboxEnv trace level (agent_turns=1, ordered_tool_events=[]). That label
("STILL_TRUNCATED_AT_4096") was assigned from Sandbox-level trace evidence
ALONE -- the three new server_transport_seed_*.jsonl files it produced have
NEVER been inspected for response-side signals.

The researcher's own prior diagnostic history (M3B episode) established a
decisive discriminator for exactly this ambiguity:

    reasoning_content_length == 0  AND  message_content_length == 0
        => an ADAPTER_PARSE / extraction-layer anomaly (the model likely
           produced SOMETHING, harmony channels were not surfaced), NOT
           simple budget starvation

    reasoning_content_length > 0  (large)  AND  message_content_length == 0
        => genuine reasoning-loop / budget-consumption behavior specific to
           this prompt (a real MODEL_GENERATION finding)

This gate applies that EXACT discriminator to the P2C-R2 transport logs,
using the same analyze_transport() approach as P2C-R1, before the P2C-R2
outcome label is treated as final in the P2D interpretation freeze.

Discipline
----------
Reads ONLY the 3 already-hash-bound server_transport_seed_*.jsonl files from
P2C-R2's output directory (re-verified independently here) plus the P2C-R2
parent result/manifest for provenance. Imports/executes NOTHING. No fixture
created or mutated. No attack optimization. No new model call.
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

VERSION = "P2C_R3_RAISE_BUDGET_RESULT_TRANSPORT_TRIAGE_v1.0"

# Hash-bound P2C-R2 transport logs (from p2c_r2_raise_token_budget_per_run_v1_0.json).
EXPECTED_LOGS = {
    26100: "E86AE47F7B09935A18EC8D4AECD55233CD9B2C35AD18366AA15B708D97AD05A6",
    26103: "39FD749B85C559B3453B27C5E32DC9AACF6AA317E88AA9AAF340CA28A8FBFC4D",
    26105: "E59AB16297CA82E10510C53BE5F662D609F146C516126475721B151377065382",
}
# Parent P2C-R2 evidence (bind for provenance only; not re-derived here).
P2C_R2 = {
    "result": ("p2c_r2_raise_token_budget_result_v1_0.json",
              "4EA839A4349FD78B38746F2291217965CDC2EE73FAF8B6174905653D6DD3792D"),
    "manifest": ("p2c_r2_raise_token_budget_manifest_v1_0.csv",
                "EB24FBAB89298E70699B91F8FE278F2F344CA5C83602D2B566474AB3CB153865"),
    "per_run": ("p2c_r2_raise_token_budget_per_run_v1_0.json",
               "41D704609ECAE81E10277F20378A2BC7553CF82D58F448D8FF6AB5321A57B166"),
}
EMPTY_STRING_SHA256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def need(v: bool, m: str) -> None:
    if not v:
        raise ValueError(m)


def sha_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest().upper()


def sha_text(s: str) -> str:
    return sha_bytes(s.encode("utf-8", "surrogatepass"))


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


def analyze_transport(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Identical approach to P2C-R1's analyze_transport(): extract response-side
    signal fields recorded by the pipeline's LlamaServerBackend for every
    http_response phase entry."""
    reqs = [r for r in records if isinstance(r, dict) and r.get("phase") == "http_request"]
    resps = [r for r in records if isinstance(r, dict) and r.get("phase") == "http_response"]
    tools_counts = []
    for r in reqs:
        shape = r.get("request_shape") or []
        for s in shape:
            if isinstance(s, dict) and str(s.get("path", "")).endswith(".tools") and s.get("type") == "array":
                tools_counts.append(int(s.get("count", 0)))
    last = resps[-1] if resps else {}
    return {
        "request_count": len(reqs), "response_count": len(resps),
        "tools_advertised_counts": tools_counts,
        "max_tools_advertised": max(tools_counts) if tools_counts else None,
        "last_finish_reason": last.get("finish_reason"),
        "last_tool_calls_count": last.get("tool_calls_count"),
        "last_message_content_length": last.get("message_content_length"),
        "last_message_content_sha256": last.get("message_content_sha256"),
        "last_reasoning_content_length": last.get("reasoning_content_length"),
        "last_http_status": last.get("http_status"),
        "last_body_sha256": last.get("body_sha256"),
        "any_tool_calls": any(int(r.get("tool_calls_count") or 0) > 0 for r in resps),
        "finish_reasons": [r.get("finish_reason") for r in resps],
        "all_response_keys_union": sorted({k for r in resps for k in r.keys()}),
    }


def classify(transport: dict[str, Any]) -> tuple[str, str]:
    """Applies the reasoning_content_length discriminator established in the
    researcher's own M3B diagnostic history."""
    finish = (transport.get("last_finish_reason") or "").lower()
    content_len = transport.get("last_message_content_length")
    reasoning_len = transport.get("last_reasoning_content_length")
    content_sha = transport.get("last_message_content_sha256")
    tc_count = transport.get("last_tool_calls_count")
    any_tc = transport.get("any_tool_calls")

    if any_tc or (isinstance(tc_count, int) and tc_count > 0):
        return ("TOOLCALL_PRESENT_UNEXPECTED",
                "response shows a tool call despite SandboxEnv recording zero -- "
                "an ADAPTER_PARSE/routing anomaly between transport and trace, not budget")

    reasoning_present_and_substantial = isinstance(reasoning_len, int) and reasoning_len > 0
    content_empty = (content_len in (0, None)) or (content_sha == EMPTY_STRING_SHA256)
    reasoning_absent_or_zero = (reasoning_len in (0, None))

    if finish == "length" and reasoning_present_and_substantial and content_empty:
        return ("GENUINE_REASONING_LOOP_MODEL_GENERATION_FINDING",
                f"finish_reason=length, reasoning_content_length={reasoning_len} (substantial), "
                "message content empty: the model consumed the budget reasoning without reaching "
                "a final answer or tool call -- a genuine, reportable MODEL_GENERATION-layer finding "
                "specific to this prompt, consistent with budget being the correct (if insufficient) lever")

    if finish == "length" and reasoning_absent_or_zero and content_empty:
        return ("REASONING_AND_CONTENT_BOTH_EMPTY_EXTRACTION_LAYER_ANOMALY",
                f"finish_reason=length, reasoning_content_length={reasoning_len}, message content empty: "
                "per the researcher's own M3B discriminator, budget starvation would show LARGE reasoning "
                "length; zero reasoning AND zero content instead points to an ADAPTER_PARSE/extraction "
                "problem (harmony channels not surfaced), NOT a generation-length problem. Raising the "
                "budget further would likely NOT resolve this, exactly as in the M3B episode.")

    if finish not in ("length", "") and content_empty and reasoning_absent_or_zero:
        return ("GENUINELY_EMPTY_NON_TRUNCATED",
                f"finish_reason={finish!r} (not 'length'), content and reasoning both empty: the model "
                "completed generation normally but produced no content and no tool call")

    if content_len and content_len > 0:
        return ("PROSE_CONTENT_PRESENT_NO_TOOLCALL",
                f"message_content_length={content_len} > 0 but zero tool calls: the model answered in "
                "prose rather than forming a structured tool call")

    return ("INDETERMINATE_INSUFFICIENT_SIGNAL",
            "no combination of finish_reason/content/reasoning/tool_calls fields definitively "
            "classifies this record from available transport signals")


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
        r2_dir = Path(a.p2c_r2_dir).resolve()

        # --- Bind P2C-R2 parent (provenance) ---
        for key, (fname, expected) in P2C_R2.items():
            p = r2_dir / fname
            ok = p.is_file() and sha_file(p) == expected
            add(checks, f"TT-{idx:03d}", f"p2c_r2_{key}", ok,
                ident(p) if p.is_file() else str(p), {"sha256": expected}, "FIXTURE")
            idx += 1
        need(all(c["passed"] for c in checks), "P2C-R2 parent identity verification failed")

        # --- Bind + analyze the 3 transport logs ---
        for seed, expected_sha in EXPECTED_LOGS.items():
            trn = r2_dir / f"server_transport_seed_{seed}.jsonl"
            trn_id = ident(trn) if trn.is_file() else None
            ok_trn = trn.is_file() and trn_id["sha256"] == expected_sha
            add(checks, f"TT-{idx:03d}", "transport_log_identity", ok_trn,
                trn_id or str(trn), {"sha256": expected_sha}, "FIXTURE")
            idx += 1
            need(ok_trn, f"Transport log identity mismatch for seed {seed}")

            trecs = read_jsonl(trn)
            tinfo = analyze_transport(trecs)
            verdict, reason = classify(tinfo)
            per_seed.append({"seed": seed, "verdict": verdict, "reason": reason,
                             "transport_analysis": tinfo, "transport_sha256": trn_id["sha256"]})

        # --- Aggregate ---
        verdicts = [r["verdict"] for r in per_seed]
        consistent = len(set(verdicts)) == 1
        dominant = max(set(verdicts), key=verdicts.count) if verdicts else "NO_RECORDS"
        add(checks, f"TT-{idx:03d}", "records_scanned", len(per_seed) == 3,
            {"records": len(per_seed)}, "all 3 seeds analyzed", "MODEL_GENERATION")
        idx += 1
        add(checks, f"TT-{idx:03d}", "diagnosis_consistency", True,
            {"verdicts": verdicts, "consistent": consistent, "dominant": dominant},
            "per-seed verdicts recorded", "MODEL_GENERATION")
        idx += 1
        add(checks, f"TT-{idx:03d}", "scope", True, scope,
            "read-only log analysis; no model/sandbox/tool/guardrail/predicate/breach executed",
            "SCOPE_VIOLATION")
        idx += 1

        failed = [c["check_id"] for c in checks if not c["passed"]]

        RECOMMENDATION = {
            "GENUINE_REASONING_LOOP_MODEL_GENERATION_FINDING":
                "This confirms STILL_TRUNCATED_AT_4096 as a genuine MODEL_GENERATION finding: the model "
                "substantively reasoned but never closed to a final answer/tool-call for the renamed-source "
                "prompt at both 2048 and 4096 tokens. This is now reportable as-is; do not raise budget "
                "further without new evidence that a specific higher value would resolve it.",
            "REASONING_AND_CONTENT_BOTH_EMPTY_EXTRACTION_LAYER_ANOMALY":
                "This CONTRADICTS the STILL_TRUNCATED_AT_4096 budget-insufficiency framing, exactly as in "
                "the M3B episode. Zero reasoning + zero content at finish=length indicates an "
                "ADAPTER_PARSE/extraction anomaly, not budget starvation. Recommended: enable raw-body "
                "capture for ONE benign probe against this exact treatment prompt (mirroring the M3B "
                "RAW_RESPONSE_CAPTURE_PROBE resolution) before any further budget changes.",
            "GENUINELY_EMPTY_NON_TRUNCATED":
                "finish_reason is not 'length' -- the model completed generation normally with empty "
                "output. This is a distinct MODEL_GENERATION finding from a truncation issue.",
            "PROSE_CONTENT_PRESENT_NO_TOOLCALL":
                "The model produced prose content but no tool call; recommend inspecting the actual "
                "content text (via a raw-body capture) to understand what it said instead of attacking.",
            "TOOLCALL_PRESENT_UNEXPECTED":
                "A tool call was present in the transport response but the Sandbox trace shows none; "
                "this is an ADAPTER_PARSE/routing anomaly requiring separate investigation.",
            "INDETERMINATE_INSUFFICIENT_SIGNAL":
                "Transport shape lacks sufficient signal; a raw-body capture probe targeting this exact "
                "prompt is required next.",
        }
        recommendation = RECOMMENDATION.get(dominant, "NOT_ESTABLISHED")

        status = "TRIAGE_COMPLETE" if not failed else "TRIAGE_COMPLETE_WITH_GAPS"
        claim = {
            "allowed": [
                "P2C-R2 parent evidence and all 3 transport logs were independently re-hashed and "
                "confirmed identical to the frozen evidence",
                "per-seed classification was derived strictly from response-side transport fields, "
                "applying the reasoning_content_length discriminator established in the researcher's "
                "own prior M3B diagnostic history",
                f"dominant diagnosis across all 3 seeds: {dominant}",
                "the recommended next action follows directly from this classification and directly "
                "addresses whether STILL_TRUNCATED_AT_4096 is a genuine budget/reasoning finding or an "
                "extraction-layer anomaly matching the M3B precedent",
            ],
            "prohibited": [
                "claim this establishes the official EXFILTRATION predicate result",
                "claim this establishes V2.1 lineage guardrail robustness (no proposal was ever formed)",
                "claim harness trick or robust security finding",
                "claim the packaged baseline, pipeline, or fixtures were modified",
            ],
        }
        result = {
            "version": VERSION, "created_at_utc": now(), "status": status,
            "classification": "READ_ONLY_RAISE_BUDGET_RESULT_TRANSPORT_TRIAGE",
            "checks": {"total": len(checks), "passed": len(checks) - len(failed),
                       "failed": len(failed), "failed_ids": failed},
            "dominant_verdict": dominant, "consistent_across_seeds": consistent,
            "verdict_counts": {v: verdicts.count(v) for v in sorted(set(verdicts))},
            "per_seed": per_seed,
            "recommended_next_action": recommendation,
            "p2c_r2_outcome_label_status":
                ("CONFIRMED_GENUINE_MODEL_GENERATION_FINDING"
                 if dominant == "GENUINE_REASONING_LOOP_MODEL_GENERATION_FINDING"
                 else "CORRECTED_NOT_A_SIMPLE_BUDGET_FINDING"
                 if dominant == "REASONING_AND_CONTENT_BOTH_EMPTY_EXTRACTION_LAYER_ANOMALY"
                 else "REQUIRES_FURTHER_TRIAGE"),
            "execution_boundaries": scope,
            "scientific_verdict": {
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": "NOT_ESTABLISHED",
                "guardrail_evaluated": False,
                "p2c_r2_transport_diagnosis": dominant,
            },
            "claim_boundary": claim,
            "next_gate": ("V_RENAMED_SOURCE_EVIDENCE_REVIEW_AND_INTERPRETATION_FREEZE"
                         if dominant == "GENUINE_REASONING_LOOP_MODEL_GENERATION_FINDING"
                         else "P2C_R4_RAW_RESPONSE_CAPTURE_PROBE_TARGETED"
                         if dominant in ("REASONING_AND_CONTENT_BOTH_EMPTY_EXTRACTION_LAYER_ANOMALY",
                                        "INDETERMINATE_INSUFFICIENT_SIGNAL")
                         else "P2C_R3_GAP_REVIEW"),
        }

        outputs = {
            "result": out / "p2c_r3_transport_triage_result_v1_0.json",
            "checks": out / "p2c_r3_transport_triage_checks_v1_0.csv",
            "per_seed": out / "p2c_r3_transport_triage_per_seed_v1_0.json",
            "claim": out / "p2c_r3_transport_triage_claim_boundary_v1_0.json",
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
            rows.append({**ident(r2_dir / f"server_transport_seed_{seed}.jsonl"), "role": f"INPUT_TRANSPORT_{seed}"})
        manifest = out / "p2c_r3_transport_triage_manifest_v1_0.csv"
        write_csv(manifest, rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        ext = out / "p2c_r3_transport_triage_manifest_external_binding_v1_0.json"
        write_json(ext, {"version": VERSION, "created_at_utc": now(), "status": status,
                         "manifest_filename": manifest.name, "manifest_sha256": sha_file(manifest),
                         "runner_sha256": runner_id["sha256"], "checks_total": len(checks),
                         "checks_passed": len(checks) - len(failed), "checks_failed": len(failed),
                         "failed_ids": failed, "dominant_verdict": dominant,
                         "recommended_next_action": recommendation, "next_gate": result["next_gate"]})
        print(json.dumps({"status": status, "checks": f"{len(checks) - len(failed)}/{len(checks)}",
                          "failed_ids": failed, "dominant_verdict": dominant,
                          "per_seed_verdicts": {r["seed"]: r["verdict"] for r in per_seed},
                          "p2c_r2_outcome_label_status": result["p2c_r2_outcome_label_status"],
                          "recommended_next_action": recommendation,
                          "manifest_sha256": sha_file(manifest), "next_gate": result["next_gate"]}, indent=2))
    except Exception as exc:  # noqa: BLE001
        (out / "P2C_R3_TRANSPORT_TRIAGE_FAILED.json").write_text(
            json.dumps({"version": VERSION, "created_at_utc": now(), "status": "BLOCKED",
                        "error_type": type(exc).__name__, "error": str(exc),
                        "checks_frozen": checks, "per_seed_frozen": per_seed,
                        "execution_boundaries": scope}, indent=2, default=str), encoding="utf-8")
        raise


def parse() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=VERSION)
    p.add_argument("--p2c-r2-dir", required=True,
                   help=r"P2C-R2 output dir containing result/manifest/per_run + server_transport_seed_*.jsonl")
    p.add_argument("--output-dir", required=True)
    return p.parse_args()


if __name__ == "__main__":
    try:
        main(parse())
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
