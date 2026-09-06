#!/usr/bin/env python3
"""RAW_HARMONY_BODY_INSPECTION_v1_0

READ-ONLY diagnosis of the GPT-OSS MODEL_GENERATION stall.

Question: the M3B run (max_new_tokens=2048) and the three v1.1 runs all showed
finish_reason=length with reasoning_content_length=0, assistant_content_length=0,
tool_calls_count=0 -- yet 89s of generation elapsed. The corrected hypothesis is
a HARMONY_CHANNEL_EXTRACTION_FAILURE, not a token-budget shortfall. This runner
decodes the RAW response bodies already captured in the server_transport logs and
classifies WHY nothing was extracted, using response-side evidence only (per the
research rule 'do not infer parser failure without response-side candidate
evidence').

It reads ONLY existing hash-bound artifacts. It does NOT run the model, Sandbox,
tools, guardrail, predicates, or baseline. It forms no attack payload and uses no
token-forging. The harmony channel GRAMMAR is used solely to DECODE the model's
own genuine output for defensive diagnosis.

Per-record classification (one of):
  HARMONY_CHANNELS_PRESENT_BUT_UNPARSED
      raw body contains harmony channel markers (analysis/commentary/final) and/or
      tool-call syntax that the pipeline's canonical extractor did not surface
      -> fix is an ADAPTER_PARSE change (read the harmony channels), NOT a budget change
  MODEL_LOOPS_NO_CHANNEL_CLOSE
      generation ran to the length cap with an OPEN channel never closed by <|end|>
      or <|return|> -> fix is stop-token / reasoning_effort tuning
  EMPTY_ASSISTANT_NO_CHANNELS
      body parsed but assistant text and channels are genuinely empty
      -> server/config or prompt-format issue
  RAW_BODY_UNAVAILABLE
      the transport record did not persist a decodable raw body
      -> capture-config gap; a follow-up raw-capture probe is required
  PARSED_TOOLCALL_PRESENT
      the raw body DID contain a usable tool call (would contradict the stall)

The runner never edits inputs; it only reads, hashes, and reports.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "RAW_HARMONY_BODY_INSPECTION_v1.0"

# Hash-bound parents (from prior frozen state). Presence of a file whose digest
# does not match is a fail-closed FIXTURE stop; a file that is simply absent is
# recorded as NOT_PROVIDED so the runner still reports on whatever is available.
EXPECTED = {
    "m3b_result": {
        "hint": "ex6f_m3b_result.json",
        "sha256": "7CF4160B49A66D15A35703EBA0CEF27B4B9228550FA7F77EB0AC3799DBB7430A",
    },
    "m3b_response_qualification": {
        "hint": "ex6f_m3b_response_qualification.json",
        "sha256": "1FA349D320B2CAA3C47630A6A908CB8C4FA58C775299AA3A2FCACFE6DDF68502",
    },
    "m3b_transport": {
        "hint": "server_transport.jsonl",
        "sha256": "D8A03069427CCDD441AF53BCD9B660B58C323F38F6E19007B8FACA0D2F135CE1",
    },
    "m3b_debug": {
        "hint": "agent_debug.jsonl",
        "sha256": "1304E07B60D38C4E992837E27DC39A78F1CAF6AFF5883BF43D566CF2971689E6",
    },
}
# v1.1 per-seed transport digests (recorded in v1.1 per_run).
V1_1_TRANSPORTS = {
    26100: "39486442DECC930144008AB369A1A891D317468AE1AD6F0CD94949AA33306B15",
    26103: "C51843E43AFD2634BA5D856F0D4824761872CEA582029772C03C76897B8911D3",
    26105: "BF49BB74BA456BCEE803A2517A0D3A627ED99520E728CBAC37BD1DD833ADA7CB",
}

# Harmony control-token grammar (decode-only; used to READ the model's own output).
HARMONY_MARKERS = ["<|start|>", "<|end|>", "<|return|>", "<|channel|>", "<|message|>",
                   "<|constrain|>", "<|call|>"]
HARMONY_CHANNELS = ["analysis", "commentary", "final"]
# Body-side signals that a tool call was present in the raw text even if unparsed.
TOOLCALL_SIGNALS = ['"tool_calls"', '"function"', '"arguments"', "http.post", "fs.read",
                    "recipient_of=", "to=assistant", "<|call|>"]


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


def read_jsonl(p: Path) -> list[Any]:
    out = []
    for line in Path(p).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            out.append({"_unparsed_len": len(line), "_sha256": sha_text(line)})
    return out


def deep_find_body_strings(obj: Any, out: list[str], depth: int = 0) -> None:
    """Collect candidate raw-body strings from a transport record without assuming
    an exact schema: any string value under keys hinting at body/content/raw/text,
    plus any long string that itself contains harmony markers."""
    if depth > 8:
        return
    if isinstance(obj, str):
        if any(m in obj for m in HARMONY_MARKERS) or len(obj) > 200:
            out.append(obj)
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            lk = str(k).lower()
            if isinstance(v, str) and any(t in lk for t in
                                          ("body", "content", "raw", "text", "response", "message", "delta")):
                out.append(v)
            else:
                deep_find_body_strings(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            deep_find_body_strings(v, out, depth + 1)


def try_decode_b64(s: str) -> str | None:
    """Some transports store the body base64-encoded; attempt a reversible decode."""
    t = s.strip()
    if len(t) < 16 or re.search(r"[^A-Za-z0-9+/=\r\n]", t):
        return None
    try:
        raw = base64.b64decode(t, validate=True)
        txt = raw.decode("utf-8", "replace")
        return txt if any(m in txt for m in HARMONY_MARKERS) or txt.strip().startswith("{") else None
    except Exception:
        return None


def analyze_body(text: str) -> dict[str, Any]:
    """Classify a single raw body string using harmony grammar + tool-call signals."""
    markers_present = {m: text.count(m) for m in HARMONY_MARKERS if m in text}
    channels_present = {c: text.count("<|channel|>" + c) for c in HARMONY_CHANNELS
                        if ("<|channel|>" + c) in text}
    # channel open/close accounting
    opens = text.count("<|channel|>")
    closes = text.count("<|end|>") + text.count("<|return|>")
    open_channel_unclosed = opens > closes
    # tool-call signals in raw text
    toolcall_signals = sorted({t for t in TOOLCALL_SIGNALS if t in text})
    # extract the 'final' channel content if present (decode-only)
    final_text = None
    m = re.search(r"<\|channel\|>final<\|message\|>(.*?)(?:<\|end\|>|<\|return\|>|$)", text, re.S)
    if m:
        final_text = m.group(1)
    analysis_text = None
    m2 = re.search(r"<\|channel\|>analysis<\|message\|>(.*?)(?:<\|end\|>|<\|channel\|>|<\|return\|>|$)", text, re.S)
    if m2:
        analysis_text = m2.group(1)
    return {
        "len": len(text),
        "harmony_markers": markers_present,
        "harmony_channels": channels_present,
        "channel_opens": opens,
        "channel_closes": closes,
        "open_channel_unclosed": open_channel_unclosed,
        "toolcall_signals": toolcall_signals,
        "final_channel_len": (len(final_text) if final_text is not None else None),
        "analysis_channel_len": (len(analysis_text) if analysis_text is not None else None),
        "body_sha256": sha_text(text),
    }


def classify_record(bodies: list[dict[str, Any]]) -> tuple[str, str]:
    """Aggregate per-body analyses of one transport record into a single verdict."""
    if not bodies:
        return "RAW_BODY_UNAVAILABLE", "no decodable raw body string found in the transport record"
    any_toolcall = any(b["toolcall_signals"] for b in bodies)
    any_channels = any(b["harmony_channels"] or b["harmony_markers"] for b in bodies)
    any_open_unclosed = any(b["open_channel_unclosed"] for b in bodies)
    any_content = any((b.get("final_channel_len") or 0) > 0 or (b.get("analysis_channel_len") or 0) > 0
                      or b["len"] > 0 for b in bodies)
    if any_toolcall and any_channels:
        return ("PARSED_TOOLCALL_PRESENT",
                "raw body contains tool-call signals inside harmony channels; pipeline should have surfaced it")
    if any_channels and any_content and not any_toolcall:
        return ("HARMONY_CHANNELS_PRESENT_BUT_UNPARSED",
                "raw body contains harmony channel text the canonical extractor did not surface (analysis/final present); ADAPTER_PARSE fix")
    if any_open_unclosed:
        return ("MODEL_LOOPS_NO_CHANNEL_CLOSE",
                "an open harmony channel was never closed before the length cap; stop-token/reasoning_effort fix")
    if any_channels and not any_content:
        return ("EMPTY_ASSISTANT_NO_CHANNELS",
                "harmony markers present but channels empty; server/config or prompt-format issue")
    return ("EMPTY_ASSISTANT_NO_CHANNELS",
            "no harmony channels and no assistant content decoded; server/config or prompt-format issue")


def resolve(run_dir: Path, key: str, hint: str) -> Path | None:
    direct = run_dir / hint
    if direct.is_file():
        return direct
    hits = sorted(run_dir.rglob(hint))
    return hits[0] if hits else None


def main(a: argparse.Namespace) -> None:
    out = Path(a.output_dir).resolve()
    need(not out.exists(), f"Refusing overwrite: {out}")
    out.mkdir(parents=True)
    checks: list[dict[str, Any]] = []
    scope = {"model_executed": False, "sandbox_instantiated": False, "baseline_modified": False,
             "attack_optimization": False, "token_forging_used": False, "read_only": True,
             "files_read": 0}
    per_record: list[dict[str, Any]] = []
    try:
        m3b_dir = Path(a.m3b_dir).resolve()
        v11_dir = Path(a.v1_1_dir).resolve() if a.v1_1_dir else None
        need(m3b_dir.is_dir(), f"m3b_dir missing: {m3b_dir}")

        # --- Bind M3B parents (fail-closed on digest mismatch; NOT_PROVIDED if absent) ---
        idx = 1
        transports_to_scan: list[tuple[str, Path]] = []
        for key, meta in EXPECTED.items():
            p = resolve(m3b_dir, key, meta["hint"])
            if p is None:
                add(checks, f"HB-{idx:03d}", "parent_presence", True,
                    {"key": key, "status": "NOT_PROVIDED"}, "optional", "FIXTURE")
                idx += 1
                continue
            x = ident(p)
            match = x["sha256"] == meta["sha256"]
            add(checks, f"HB-{idx:03d}", "parent_identity", match, x, {"sha256": meta["sha256"]}, "FIXTURE")
            need(match, f"Digest mismatch for {key}: {p}")
            scope["files_read"] += 1
            idx += 1
            if key.endswith("transport"):
                transports_to_scan.append(("M3B", p))

        # --- Bind v1.1 transports if provided ---
        if v11_dir and v11_dir.is_dir():
            for seed, digest in V1_1_TRANSPORTS.items():
                p = resolve(v11_dir, f"seed_{seed}", f"server_transport_seed_{seed}.jsonl")
                if p is None:
                    add(checks, f"HB-{idx:03d}", "v1_1_presence", True,
                        {"seed": seed, "status": "NOT_PROVIDED"}, "optional", "FIXTURE")
                    idx += 1
                    continue
                x = ident(p)
                match = x["sha256"] == digest
                add(checks, f"HB-{idx:03d}", "v1_1_transport_identity", match, x, {"sha256": digest}, "FIXTURE")
                need(match, f"Digest mismatch for v1.1 seed {seed}: {p}")
                scope["files_read"] += 1
                idx += 1
                transports_to_scan.append((f"v1_1_seed_{seed}", p))

        need(transports_to_scan, "No transport logs available to inspect")

        # --- Decode + classify every response record in every transport ---
        for label, tpath in transports_to_scan:
            records = read_jsonl(tpath)
            resp_records = [r for r in records if isinstance(r, dict)
                            and (r.get("phase") in (None, "http_response") or "response" in json.dumps(r).lower())]
            scan = resp_records if resp_records else [r for r in records if isinstance(r, dict)]
            for ri, rec in enumerate(scan):
                raw_strings: list[str] = []
                deep_find_body_strings(rec, raw_strings)
                # attempt base64 recovery on any candidate that isn't already harmony/JSON text
                decoded_extra = []
                for s in raw_strings:
                    d = try_decode_b64(s)
                    if d:
                        decoded_extra.append(d)
                all_bodies = raw_strings + decoded_extra
                analyses = [analyze_body(s) for s in all_bodies if isinstance(s, str) and s]
                verdict, reason = classify_record(analyses)
                per_record.append({
                    "transport": label, "record_index": ri,
                    "verdict": verdict, "reason": reason,
                    "n_body_candidates": len(all_bodies),
                    "b64_recovered": len(decoded_extra),
                    "body_analyses": analyses,
                })

        # --- Aggregate ---
        verdicts = [r["verdict"] for r in per_record]
        n = len(verdicts)
        dominant = max(set(verdicts), key=verdicts.count) if verdicts else "RAW_BODY_UNAVAILABLE"
        consistent = len(set(verdicts)) == 1
        add(checks, f"HB-{idx:03d}", "records_scanned", n > 0,
            {"records": n, "verdicts": {v: verdicts.count(v) for v in sorted(set(verdicts))}},
            "at least one response record decoded", "MODEL_GENERATION"); idx += 1
        add(checks, f"HB-{idx:03d}", "read_only_scope",
            not scope["model_executed"] and not scope["sandbox_instantiated"]
            and not scope["baseline_modified"] and not scope["token_forging_used"],
            scope, "no model/sandbox/baseline/forging", "SCOPE_VIOLATION"); idx += 1

        failed = [c["check_id"] for c in checks if not c["passed"]]

        FIX = {
            "HARMONY_CHANNELS_PRESENT_BUT_UNPARSED":
                "ADAPTER_PARSE fix: make the EX pipeline read gpt-oss harmony channels "
                "(analysis/commentary/final) and the <|call|> tool-call channel, instead of "
                "only a plain OpenAI message.content. Single variable; frozen EX5 prompt stays frozen.",
            "MODEL_LOOPS_NO_CHANNEL_CLOSE":
                "GENERATION fix: add harmony stop tokens (<|end|>, <|return|>) and/or lower "
                "reasoning_effort so a channel closes before the length cap. Not a raw max_tokens increase.",
            "EMPTY_ASSISTANT_NO_CHANNELS":
                "CONFIG/PROMPT fix: verify the chat template renders the harmony format for gpt-oss and "
                "that the server returns channel content; a one-shot benign raw-capture probe confirms.",
            "RAW_BODY_UNAVAILABLE":
                "CAPTURE fix: enable full raw-body persistence in the transport logger, then re-inspect. "
                "No model rerun needed beyond one benign capture probe.",
            "PARSED_TOOLCALL_PRESENT":
                "INVESTIGATE: raw body already carried a tool call; the stall is downstream of parsing "
                "(routing/serialization). Re-examine the adapter->sandbox boundary.",
        }
        outcome = ("RAW_HARMONY_" + dominant) if verdicts else "RAW_HARMONY_NO_RECORDS"
        status = ("RAW_HARMONY_BODY_INSPECTION_COMPLETE" if not failed
                  else "RAW_HARMONY_BODY_INSPECTION_COMPLETE_WITH_GAPS")

        claim = {
            "allowed": [
                "the raw gpt-oss response bodies were decoded read-only from existing transport logs",
                "the harmony channel grammar was used only to READ the model's genuine output",
                f"dominant diagnosis across {n} response records: {dominant}",
                "the recommended fix changes exactly one MODEL_GENERATION/ADAPTER variable",
            ],
            "prohibited": [
                "treat this as evidence about the guardrail (no proposal was routed)",
                "treat the diagnosis as an attack result",
                "claim the model would or would not attack from a parse-layer stall",
                "use harmony control tokens to force or optimize any model behavior",
            ],
        }
        result = {
            "version": VERSION, "created_at_utc": now(), "status": status,
            "classification": "READ_ONLY_RAW_HARMONY_BODY_DECODE_DIAGNOSIS",
            "checks": {"total": len(checks), "passed": len(checks) - len(failed),
                       "failed": len(failed), "failed_ids": failed},
            "outcome": outcome, "dominant_verdict": dominant, "consistent": consistent,
            "records_scanned": n,
            "verdict_counts": {v: verdicts.count(v) for v in sorted(set(verdicts))},
            "recommended_single_fix": FIX.get(dominant),
            "per_record": per_record,
            "execution_boundaries": scope,
            "scientific_verdict": {
                "guardrail_evaluated": False,
                "earliest_unresolved_layer":
                    ("ADAPTER_PARSE" if dominant == "HARMONY_CHANNELS_PRESENT_BUT_UNPARSED"
                     else "MODEL_GENERATION"),
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": "NOT_ESTABLISHED",
                "attack_optimization": False,
                "token_forging_used": False,
            },
            "claim_boundary": claim,
            "next_gate": ("MODEL_GENERATION_EXFILTRATION_v1_2_ADAPTER_PARSE_FIX"
                          if dominant == "HARMONY_CHANNELS_PRESENT_BUT_UNPARSED"
                          else "MODEL_GENERATION_EXFILTRATION_v1_2_GENERATION_FIX"
                          if dominant == "MODEL_LOOPS_NO_CHANNEL_CLOSE"
                          else "RAW_RESPONSE_CAPTURE_PROBE"),
        }

        outputs = {
            "result": out / "raw_harmony_body_inspection_result.json",
            "checks": out / "raw_harmony_body_inspection_checks.csv",
            "per_record": out / "raw_harmony_body_inspection_per_record.json",
            "claim": out / "raw_harmony_body_inspection_claim_boundary.json",
            "binding": out / "raw_harmony_body_inspection_binding.json",
        }
        write_json(outputs["result"], result)
        write_csv(outputs["checks"], checks,
                  ["check_id", "category", "passed", "observed", "expected", "failure_layer"])
        write_json(outputs["per_record"], {"per_record": per_record})
        write_json(outputs["claim"], claim)
        write_json(outputs["binding"], {"version": VERSION, "created_at_utc": now(),
                                        "runner": ident(Path(__file__).resolve()),
                                        "m3b_dir": str(m3b_dir),
                                        "v1_1_dir": (str(v11_dir) if v11_dir else None),
                                        "transports_scanned": [t[0] for t in transports_to_scan],
                                        "execution_boundaries": scope})
        rows = [{**ident(p), "role": "RAW_HARMONY_DERIVED"} for p in outputs.values()]
        for _, tp in transports_to_scan:
            rows.append({**ident(tp), "role": "RAW_HARMONY_INPUT_TRANSPORT"})
        manifest = out / "raw_harmony_body_inspection_manifest.csv"
        write_csv(manifest, rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        ext = out / "raw_harmony_body_inspection_manifest_external_binding.json"
        write_json(ext, {"version": VERSION, "created_at_utc": now(), "status": status,
                         "manifest_filename": manifest.name, "manifest_sha256": sha_file(manifest),
                         "runner_sha256": sha_file(Path(__file__).resolve()),
                         "checks_total": len(checks), "checks_passed": len(checks) - len(failed),
                         "checks_failed": len(failed), "failed_ids": failed,
                         "outcome": outcome, "dominant_verdict": dominant,
                         "next_gate": result["next_gate"]})
        print(json.dumps({"status": status, "checks": f"{len(checks) - len(failed)}/{len(checks)}",
                          "failed_ids": failed, "outcome": outcome, "dominant_verdict": dominant,
                          "records_scanned": n,
                          "verdict_counts": result["verdict_counts"],
                          "manifest_sha256": sha_file(manifest),
                          "next_gate": result["next_gate"]}, indent=2))
    except Exception as exc:  # noqa: BLE001
        (out / "RAW_HARMONY_BODY_INSPECTION_FAILED.json").write_text(
            json.dumps({"version": VERSION, "created_at_utc": now(), "status": "BLOCKED",
                        "error_type": type(exc).__name__, "error": str(exc),
                        "checks_frozen": checks, "per_record_frozen": per_record,
                        "execution_boundaries": scope}, indent=2, default=str), encoding="utf-8")
        raise


def parse() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=VERSION)
    p.add_argument("--m3b-dir", required=True,
                   help="dir containing ex6f_m3b_* (result, response_qualification, server_transport.jsonl, agent_debug.jsonl)")
    p.add_argument("--v1-1-dir", default=None,
                   help="optional dir containing v1.1 server_transport_seed_*.jsonl")
    p.add_argument("--output-dir", required=True)
    return p.parse_args()


if __name__ == "__main__":
    try:
        main(parse())
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
