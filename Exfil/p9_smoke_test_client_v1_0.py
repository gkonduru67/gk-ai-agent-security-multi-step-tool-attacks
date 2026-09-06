#!/usr/bin/env python3
# =============================================================================
# p9_smoke_test_client_v1_0.py
# -----------------------------------------------------------------------------
# PHASE:            P9 - Raw Transport Capture (BENIGN smoke test only)
# AUTHORIZED SCOPE: Send ONE (or a few) minimal, harmless chat-completions
#                   request(s) THROUGH the P9 recording proxy, purely to prove
#                   the capture pipe works end-to-end (real bytes flow, get
#                   recorded, get hashed, get parsed) — NOT to attempt any
#                   secret read/exfiltration formation.
#
# CRITICAL SCOPE BOUNDARY (why this is NOT a P10 attempt):
#   * The prompt sent here is a fixed, benign string (default: "Reply with
#     exactly the single word: PONG"). It contains NO reference to secret.txt,
#     no fs.read/http.post tool schema, no exfiltration framing.
#   * No tools are advertised to the model by default (--with-benign-tools
#     optionally adds an UNRELATED dummy tool, e.g. get_weather, to exercise
#     the tool_calls capture path without touching fs/http semantics).
#   * This script NEVER imports, calls, or wraps the real P6C harness
#     (p6c_real_agent_formation_test_v1_0.py or similar). It is a standalone,
#     minimal HTTP client with its own fixed payload.
#   * If you want to run the REAL P6C harness through the proxy, that is a
#     separate, explicit P10 decision — this script deliberately cannot do it.
#
# READ-ONLY / FAIL-CLOSED CONTRACT:
#   * This script only SENDS requests and READS the proxy's capture file to
#     verify the round trip. It does not write to fixtures, SDK code, or the
#     proxy's config. It does not touch secret.txt.
#   * Every response is hashed and its parse_status is surfaced so ambiguity
#     (e.g. non-JSON, empty channels) is reported, never hidden.
# =============================================================================

import argparse
import hashlib
import json
import sys
import time
import urllib.request
import urllib.error

DEFAULT_PROMPT = "Reply with exactly the single word: PONG"

BENIGN_DUMMY_TOOL = {
    "type": "function",
    "function": {
        "name": "get_weather",
        "description": "Look up the current weather for a city (UNRELATED "
                       "dummy tool, used only to exercise the tool_calls "
                       "parsing path in the P9 capture pipe).",
        "parameters": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        },
    },
}


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def build_payload(prompt, model, with_tools):
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 32,
        "temperature": 0,
    }
    if with_tools:
        payload["tools"] = [BENIGN_DUMMY_TOOL]
        payload["tool_choice"] = "auto"
    return json.dumps(payload).encode("utf-8")


def send_one(proxy_url, payload_bytes, timeout):
    req = urllib.request.Request(
        proxy_url, data=payload_bytes,
        headers={"Content-Type": "application/json"}, method="POST")
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            status = resp.status
    except urllib.error.HTTPError as he:
        body = he.read() if hasattr(he, "read") else b""
        status = he.code
    except urllib.error.URLError as ue:
        return {"ok": False, "error": f"URLError: {ue}", "elapsed_s": time.time() - t0}
    return {"ok": True, "status": status, "body": body,
            "elapsed_s": time.time() - t0}


def summarize_response(body_bytes):
    try:
        obj = json.loads(body_bytes.decode("utf-8", errors="replace"))
    except Exception as exc:
        return {"parse_status": f"NON_JSON: {type(exc).__name__}"}
    choices = obj.get("choices") or []
    if not choices:
        return {"parse_status": "JSON_NO_CHOICES", "raw_keys": list(obj.keys())}
    msg = (choices[0] or {}).get("message", {}) or {}
    return {
        "parse_status": "OK",
        "finish_reason": (choices[0] or {}).get("finish_reason"),
        "content_preview": (msg.get("content") or "")[:80],
        "has_tool_calls": bool(msg.get("tool_calls")),
    }


def tail_jsonl(path, n=1):
    """Read-only: return the last n JSON records from the capture log."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
    except OSError as exc:
        return None, f"cannot read capture log: {exc}"
    if not lines:
        return [], None
    out = []
    for ln in lines[-n:]:
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            out.append({"parse_error": "malformed jsonl line"})
    return out, None


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="P9 BENIGN smoke test: send minimal harmless chat-"
                    "completions call(s) through the recording proxy to "
                    "verify the capture pipe. NOT the real P6C attack "
                    "harness; contains no secret/exfil content.")
    ap.add_argument("--proxy-url", default="http://127.0.0.1:8091/v1/chat/completions",
                    help="URL of the P9 recording proxy (NOT the raw upstream).")
    ap.add_argument("--capture-log", default=None,
                    help="Path to p9_transport_capture.jsonl to verify against "
                         "after sending (optional but recommended).")
    ap.add_argument("--prompt", default=DEFAULT_PROMPT,
                    help="Benign prompt text to send (default: a fixed, "
                         "harmless echo request).")
    ap.add_argument("--model", default="gpt-oss-20b",
                    help="Model name field to include in the payload.")
    ap.add_argument("--count", type=int, default=1,
                    help="How many benign calls to send (default 1).")
    ap.add_argument("--with-benign-tools", action="store_true",
                    help="Include an UNRELATED dummy tool (get_weather) to "
                         "exercise tool_calls parsing, without any fs/http "
                         "semantics.")
    ap.add_argument("--timeout", type=float, default=60.0)
    args = ap.parse_args(argv)

    print("=" * 72)
    print("P9 SMOKE TEST CLIENT — BENIGN traffic only, not the P6C harness")
    print("=" * 72)
    print(f"Proxy URL : {args.proxy_url}")
    print(f"Prompt    : {args.prompt!r}")
    print(f"Tools     : {'benign dummy get_weather' if args.with_benign_tools else 'none'}")
    print(f"Count     : {args.count}")
    print("-" * 72)

    results = []
    for i in range(1, args.count + 1):
        payload = build_payload(args.prompt, args.model, args.with_benign_tools)
        req_sha = sha256_bytes(payload)
        r = send_one(args.proxy_url, payload, args.timeout)
        entry = {"call": i, "request_sha256": req_sha, **r}
        if r.get("ok"):
            resp_body = r.pop("body")
            entry["response_sha256"] = sha256_bytes(resp_body)
            entry["response_bytes"] = len(resp_body)
            entry["summary"] = summarize_response(resp_body)
            print(f"[call {i}] HTTP {r['status']}  req_sha={req_sha[:12]}…  "
                  f"resp_sha={entry['response_sha256'][:12]}…  "
                  f"{entry['summary']}")
        else:
            print(f"[call {i}] FAILED: {r.get('error')}")
        results.append(entry)

    print("-" * 72)
    if args.capture_log:
        recs, err = tail_jsonl(args.capture_log, n=args.count)
        if err:
            print(f"CAPTURE LOG CHECK: NOT_ESTABLISHED — {err}")
        elif recs is None or len(recs) == 0:
            print("CAPTURE LOG CHECK: NOT_ESTABLISHED — log is empty; "
                  "proxy may not have received/logged this traffic.")
        else:
            print(f"CAPTURE LOG CHECK: found {len(recs)} record(s) in "
                  f"{args.capture_log}")
            for rec in recs:
                req_match = any(rec.get("request", {}).get("sha256_raw") == e["request_sha256"]
                                for e in results if e.get("ok"))
                print(f"  seq={rec.get('seq')} status={rec.get('response', {}).get('http_status')}"
                      f" parse_status={rec.get('response', {}).get('fields', {}).get('parse_status')}"
                      f" request_sha_matches_a_sent_call={req_match}")
    else:
        print("CAPTURE LOG CHECK: skipped (--capture-log not provided).")

    print("=" * 72)
    ok_count = sum(1 for e in results if e.get("ok"))
    print(f"RESULT: {ok_count}/{len(results)} benign calls succeeded.")
    print("This is a P9 pipe smoke test ONLY. No secret/exfil content was "
          "sent. Running the real P6C harness through the proxy is a "
          "separate P10 decision, not performed by this script.")
    print("=" * 72)
    return 0 if ok_count == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
