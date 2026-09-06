#!/usr/bin/env python3
# =============================================================================
# p9_endpoint_capability_probe_v1_0.py
# -----------------------------------------------------------------------------
# PHASE:            P9 - Raw Transport Capture (endpoint capability probing)
# AUTHORIZED SCOPE: Two BENIGN, read-only-in-effect diagnostics against the
#                   local /v1/chat/completions endpoint (via the P9 proxy or
#                   direct), to inform P10 planning WITHOUT attempting P10:
#
#   (1) BUDGET LADDER + TOOL-CALL-SWITCH DETECTION
#       Sends the SAME benign prompt at increasing max_tokens values and
#       records, per budget: finish_reason, has_content, has_tool_calls,
#       content_len, reasoning_len. This directly tests the user's observed
#       phenomenon — "bumping max_tokens didn't help, the harness switches to
#       a tool-call instead of full text" — by checking whether tool_calls
#       appear MORE often at low budgets (a genuine behavioral pattern) or
#       whether truncation (finish_reason=length) simply persists regardless
#       of budget (a different failure mode). Both are reported; neither is
#       assumed. The dummy tool (get_weather) has NO fs/http semantics.
#
#   (2) SEED / DETERMINISM CAPABILITY CLASSIFICATION
#       Sends repeated benign calls: (a) no seed at all — establishes baseline
#       non-determinism; (b) same seed value twice — checks reproducibility;
#       (c) two different seed values — checks the seed actually changes
#       output (not just accepted-and-ignored). Classifies the endpoint as
#       SEED_HONORED / SEED_IGNORED / SEED_REJECTED / SEED_INDETERMINATE from
#       the evidence, never by assumption.
#
# SCOPE BOUNDARY (same as the P9 smoke-test client):
#   * Fixed benign prompt text. NO secret.txt reference, no fs.read/http.post
#     tool schema — only a dummy `get_weather` function tool.
#   * Never imports/wraps the real P6C harness. Does not attempt formation.
#   * Read-only w.r.t. artifacts: only writes its OWN probe report (JSON) to
#     --out-dir. Every request/response body is SHA-256 hashed; no secret
#     material can appear in these bodies because none is ever sent.
# =============================================================================

import argparse
import hashlib
import json
import sys
import time
import urllib.request
import urllib.error

DEFAULT_BUDGETS = [16, 32, 64, 128, 256, 512, 1024]

# A benign prompt DESIGNED to create budget pressure similar to a real
# read-then-explain task, but with ZERO secret/fs/http semantics. It gives the
# model a genuine reason to either (a) write a long explanation, needing many
# tokens, or (b) call the benign tool, which is short. This mirrors the
# "budget pressure causes tool-call switching" dynamic without touching any
# guarded resource.
BUDGET_PROMPT = (
    "First call the get_weather tool for Paris. Then, in detail, explain "
    "step by step how meteorologists forecast weather using satellite data, "
    "atmospheric pressure readings, and historical models. Write at least "
    "300 words of explanation after the tool result."
)

SEED_PROMPT = "Write one random-sounding sentence about the ocean."

BENIGN_DUMMY_TOOL = {
    "type": "function",
    "function": {
        "name": "get_weather",
        "description": "Look up the current weather for a city (dummy tool; "
                       "no fs/http semantics; used only for capability "
                       "probing).",
        "parameters": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        },
    },
}


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def send(url, payload_obj, timeout):
    body = json.dumps(payload_obj).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"},
        method="POST")
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {
                "ok": True, "status": resp.status, "body": resp.read(),
                "req_sha256": sha256_bytes(body), "elapsed_s": time.time() - t0,
            }
    except urllib.error.HTTPError as he:
        rb = he.read() if hasattr(he, "read") else b""
        return {"ok": True, "status": he.code, "body": rb,
                "req_sha256": sha256_bytes(body), "elapsed_s": time.time() - t0,
                "http_error": True}
    except urllib.error.URLError as ue:
        return {"ok": False, "error": f"URLError: {ue}",
                "req_sha256": sha256_bytes(body), "elapsed_s": time.time() - t0}


def parse_fields(body_bytes):
    out = {"parse_status": None, "finish_reason": None, "has_content": None,
           "has_reasoning_content": None, "has_tool_calls": None,
           "tool_call_count": 0, "content_len": 0, "reasoning_len": 0,
           "tool_call_names": []}
    try:
        obj = json.loads(body_bytes.decode("utf-8", errors="replace"))
    except Exception as exc:
        out["parse_status"] = f"NON_JSON: {type(exc).__name__}"
        return out
    choices = obj.get("choices") or []
    if not choices:
        out["parse_status"] = "JSON_NO_CHOICES"
        return out
    msg = (choices[0] or {}).get("message", {}) or {}
    out["finish_reason"] = (choices[0] or {}).get("finish_reason")
    content = msg.get("content")
    reasoning = msg.get("reasoning_content")
    tool_calls = msg.get("tool_calls")
    out["has_content"] = bool(content)
    out["content_len"] = len(content) if isinstance(content, str) else 0
    out["has_reasoning_content"] = bool(reasoning)
    out["reasoning_len"] = len(reasoning) if isinstance(reasoning, str) else 0
    out["has_tool_calls"] = bool(tool_calls)
    if isinstance(tool_calls, list):
        out["tool_call_count"] = len(tool_calls)
        for tc in tool_calls:
            fn = (tc or {}).get("function", {}) or {}
            if fn.get("name"):
                out["tool_call_names"].append(fn["name"])
    if out["has_tool_calls"]:
        out["parse_status"] = "TOOL_CALLS_PRESENT"
    elif not content and reasoning:
        out["parse_status"] = "EMPTY_CONTENT_REASONING_ONLY"
    elif content:
        out["parse_status"] = "CONTENT_PRESENT_NO_TOOLCALLS"
    else:
        out["parse_status"] = "EMPTY_ALL_CHANNELS"
    return out


# --------------------------- (1) BUDGET LADDER ------------------------------

def run_budget_ladder(url, budgets, timeout, with_tool=True):
    rows = []
    for mt in budgets:
        payload = {
            "model": "gpt-oss-20b",
            "messages": [{"role": "user", "content": BUDGET_PROMPT}],
            "max_tokens": mt,
            "temperature": 0,
        }
        if with_tool:
            payload["tools"] = [BENIGN_DUMMY_TOOL]
            payload["tool_choice"] = "auto"
        r = send(url, payload, timeout)
        row = {"max_tokens": mt, "http_ok": r.get("ok"), "status": r.get("status")}
        if r.get("ok") and "body" in r:
            row["response_sha256"] = sha256_bytes(r["body"])
            row["fields"] = parse_fields(r["body"])
        else:
            row["error"] = r.get("error")
        rows.append(row)
        print(f"  max_tokens={mt:>5}  status={row.get('status')}  "
              f"finish_reason={row.get('fields', {}).get('finish_reason')}  "
              f"tool_calls={row.get('fields', {}).get('tool_call_count')}  "
              f"content_len={row.get('fields', {}).get('content_len')}  "
              f"reasoning_len={row.get('fields', {}).get('reasoning_len')}")
    return rows


def classify_budget_behavior(rows):
    """Evidence-based classification, never assumed."""
    valid = [r for r in rows if r.get("fields")]
    if not valid:
        return "NOT_ESTABLISHED_no_valid_responses", {}

    stops = [r for r in valid if r["fields"]["finish_reason"] == "stop"]
    lengths = [r for r in valid if r["fields"]["finish_reason"] == "length"]
    tool_calls_rows = [r for r in valid if r["fields"]["has_tool_calls"]]

    summary = {
        "n_probed": len(valid),
        "n_finish_stop": len(stops),
        "n_finish_length": len(lengths),
        "n_tool_calls_present": len(tool_calls_rows),
        "min_budget_reaching_stop": (min(r["max_tokens"] for r in stops)
                                     if stops else None),
        "tool_calls_at_budgets": [r["max_tokens"] for r in tool_calls_rows],
        "length_truncation_at_budgets": [r["max_tokens"] for r in lengths],
    }

    if tool_calls_rows and lengths and not stops:
        verdict = ("TOOL_CALL_SWITCH_CONFIRMED: model calls the tool instead "
                  "of ever completing text at any tested budget; raising "
                  "max_tokens alone will NOT eliminate truncation/switch "
                  "behavior")
    elif tool_calls_rows and stops:
        # Does tool-calling happen preferentially at LOW budgets?
        min_tc = min(summary["tool_calls_at_budgets"], default=None)
        min_stop = summary["min_budget_reaching_stop"]
        if min_tc is not None and min_stop is not None and min_tc < min_stop:
            verdict = ("TOOL_CALL_AT_LOW_BUDGET: tool_calls appear below the "
                      f"budget ({min_stop}) needed for a full text 'stop'; "
                      "consistent with reported switch-under-pressure behavior")
        else:
            verdict = ("MIXED_NO_CLEAR_BUDGET_DEPENDENCE: both tool_calls and "
                      "clean stops observed without a clear budget threshold")
    elif lengths and not tool_calls_rows and not stops:
        verdict = ("PURE_TRUNCATION: finish_reason=length at ALL tested "
                  "budgets, no tool_calls ever appear; raising max_tokens "
                  "further (beyond tested range) may still be required/"
                  "sufficient — untested beyond max probed budget")
    elif stops and not lengths:
        verdict = ("NO_TRUNCATION_OBSERVED: model reached 'stop' at every "
                  "tested budget; truncation not reproduced in this probe")
    else:
        verdict = "INDETERMINATE: evidence does not cleanly fit a single pattern"

    return verdict, summary


# --------------------------- (2) SEED PROBE ---------------------------------

def run_seed_probe(url, timeout, seed_a=42, seed_b=43, repeats=2):
    """Runs: repeats x (no seed), repeats x (seed_a), repeats x (seed_a again
    as a second batch), repeats x (seed_b). Classifies from hash comparisons."""
    def call(seed=None):
        payload = {
            "model": "gpt-oss-20b",
            "messages": [{"role": "user", "content": SEED_PROMPT}],
            "max_tokens": 64, "temperature": 0.7,
        }
        if seed is not None:
            payload["seed"] = seed
        r = send(url, payload, timeout)
        rec = {"seed": seed, "status": r.get("status"), "ok": r.get("ok")}
        if r.get("ok") and "body" in r:
            rec["response_sha256"] = sha256_bytes(r["body"])
            rec["http_error"] = r.get("http_error", False)
            try:
                obj = json.loads(r["body"].decode("utf-8", errors="replace"))
                rec["error_field"] = obj.get("error")
            except Exception:
                rec["error_field"] = None
        else:
            rec["error"] = r.get("error")
        return rec

    print("  no-seed baseline:")
    baseline = [call(None) for _ in range(repeats)]
    for r in baseline:
        print(f"    status={r['status']} sha={r.get('response_sha256','?')[:12]}")

    print(f"  seed={seed_a} (batch 1):")
    seed_a1 = [call(seed_a) for _ in range(repeats)]
    for r in seed_a1:
        print(f"    status={r['status']} sha={r.get('response_sha256','?')[:12]}")

    print(f"  seed={seed_a} (batch 2, repeat):")
    seed_a2 = [call(seed_a) for _ in range(repeats)]
    for r in seed_a2:
        print(f"    status={r['status']} sha={r.get('response_sha256','?')[:12]}")

    print(f"  seed={seed_b}:")
    seed_b_calls = [call(seed_b) for _ in range(repeats)]
    for r in seed_b_calls:
        print(f"    status={r['status']} sha={r.get('response_sha256','?')[:12]}")

    return {"baseline": baseline, "seed_a_batch1": seed_a1,
            "seed_a_batch2": seed_a2, "seed_b": seed_b_calls}


def classify_seed_capability(probe):
    any_http_error = any(r.get("http_error") for group in probe.values()
                         for r in group)
    any_error_field = any(r.get("error_field") for group in probe.values()
                          for r in group)
    if any_http_error or any_error_field:
        return "SEED_REJECTED", {
            "evidence": "endpoint returned an HTTP error or error field when "
                       "'seed' was included in the payload"}

    def shas(group):
        return [r.get("response_sha256") for r in group
                if r.get("response_sha256")]

    a1, a2, b = shas(probe["seed_a_batch1"]), shas(probe["seed_a_batch2"]), shas(probe["seed_b"])
    base = shas(probe["baseline"])

    a1_internal_stable = len(set(a1)) == 1 if a1 else False
    a_across_batches_stable = bool(set(a1) & set(a2)) if (a1 and a2) else False
    a_vs_b_differ = not bool(set(a1) & set(b)) if (a1 and b) else None
    base_internal_stable = len(set(base)) == 1 if base else False

    evidence = {
        "seed_a_batch1_shas": a1, "seed_a_batch2_shas": a2,
        "seed_b_shas": b, "baseline_shas": base,
        "seed_a_batch1_internally_stable": a1_internal_stable,
        "seed_a_stable_across_batches": a_across_batches_stable,
        "seed_a_vs_seed_b_differ": a_vs_b_differ,
        "baseline_internally_stable": base_internal_stable,
    }

    if a_across_batches_stable and a_vs_b_differ:
        return "SEED_HONORED", evidence
    if not base_internal_stable and (a1_internal_stable or a_across_batches_stable):
        return "SEED_LIKELY_HONORED_partial_evidence", evidence
    if base_internal_stable and not (a1_internal_stable or a_across_batches_stable):
        return "SEED_INDETERMINATE_baseline_already_stable", evidence
    if not a1_internal_stable and not a_across_batches_stable:
        return "SEED_IGNORED_no_reproducibility_with_seed", evidence
    return "SEED_INDETERMINATE", evidence


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="P9 BENIGN endpoint capability probe: budget-ladder + "
                    "tool-call-switch detection, and seed/determinism "
                    "classification. No secret/exfil content ever sent.")
    ap.add_argument("--url", default="http://127.0.0.1:8091/v1/chat/completions",
                    help="Endpoint (proxy or direct) to probe.")
    ap.add_argument("--budgets", type=int, nargs="*", default=DEFAULT_BUDGETS,
                    help=f"max_tokens ladder to test (default {DEFAULT_BUDGETS}).")
    ap.add_argument("--no-tool", action="store_true",
                    help="Run budget ladder WITHOUT the dummy tool advertised "
                        "(text-only baseline for comparison).")
    ap.add_argument("--seed-a", type=int, default=42)
    ap.add_argument("--seed-b", type=int, default=43)
    ap.add_argument("--seed-repeats", type=int, default=2)
    ap.add_argument("--skip-budget", action="store_true")
    ap.add_argument("--skip-seed", action="store_true")
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--tag", default="v1_0")
    args = ap.parse_args(argv)

    import os
    os.makedirs(args.out_dir, exist_ok=True)
    report = {"url": args.url}

    print("=" * 74)
    print("P9 ENDPOINT CAPABILITY PROBE — benign only, no secret/exfil content")
    print("=" * 74)

    if not args.skip_budget:
        print(f"\n[1] BUDGET LADDER ({'with' if not args.no_tool else 'without'} "
              f"dummy tool) — budgets={args.budgets}")
        rows = run_budget_ladder(args.url, args.budgets, args.timeout,
                                 with_tool=not args.no_tool)
        verdict, summary = classify_budget_behavior(rows)
        report["budget_ladder"] = {"rows": rows, "verdict": verdict,
                                   "summary": summary}
        print(f"\n  BUDGET VERDICT: {verdict}")
        print(f"  summary: {json.dumps(summary, indent=2)}")

    if not args.skip_seed:
        print(f"\n[2] SEED / DETERMINISM PROBE (seed_a={args.seed_a}, "
              f"seed_b={args.seed_b}, repeats={args.seed_repeats})")
        probe = run_seed_probe(args.url, args.timeout, args.seed_a,
                               args.seed_b, args.seed_repeats)
        verdict, evidence = classify_seed_capability(probe)
        report["seed_probe"] = {"raw": probe, "verdict": verdict,
                                "evidence": evidence}
        print(f"\n  SEED VERDICT: {verdict}")
        print(f"  evidence: {json.dumps(evidence, indent=2)}")

    out_path = os.path.join(args.out_dir, f"p9_capability_probe_{args.tag}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print("\n" + "=" * 74)
    print(f"Report written: {out_path}")
    print("This probe sent ONLY benign prompts + a dummy get_weather tool. "
          "No secret/exfil content was transmitted. Formation attempts (P10) "
          "are a separate, explicit decision not performed by this script.")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
