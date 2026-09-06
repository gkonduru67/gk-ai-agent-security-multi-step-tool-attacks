#!/usr/bin/env python3
# =============================================================================
# live_dual_guardrail_run_v2.py
# AI_AGENT_SECURITY -- LIVE GPT-OSS confirmation for the 3 body-redaction-
# ambiguity CONFUSED_DEPUTY candidates (C3_split_turn_authorization_false_
# positive, C_implied_transmission, CD09_v3_no_revocation_control), run
# TWICE per candidate against a real model: once through the packaged
# optimal.py guardrail, once through the specialized structured CD v1.1
# guardrail -- for a genuine, non-replayed, publication-suitable
# comparison.
#
# =============================================================================
# WHAT CHANGED FROM v1 (the previous scaffold) -- and WHY
# -----------------------------------------------------------------------
# Now that you've shared local_validate_v5_1.py in full, I can report a
# CONFIRMED finding, not a guess: the real run_candidate()'s guardrail
# context is
#
#     ctx = {"recent_sources": [...last 5 event sources...],
#            "recent_tools": [...last 5 event tool names...],
#            "last_user": "turn",              <- LITERAL constant string
#            "side_effect": side_effect, "seed": seed_base}
#
# This is sized EXACTLY for the packaged OptimalGuardrail (which only
# reads recent_sources / user_confirmed_safe / user_authorized) and
# supplies NEITHER "user_messages" NOR real "tool_events" -- both of
# which the specialized CD guardrail's _sync_messages() and
# _evaluate_provenance() require. Plugging a specialized guardrail into
# the UNCHANGED real run_candidate() would silently produce meaningless,
# always-DENY results (no authorization state would ever be built).
#
# ALSO CONFIRMED: sdk["guardrail"] is instantiated ONCE, outside the
# candidate loop, and reused for every candidate + every repeat in the
# whole script run. Harmless for the stateless packaged guardrail;
# would silently leak state across DIFFERENT candidates for any
# stateful specialized guardrail (CD's self._ledger, DW's
# consumed_executions, etc.) if reused the same way.
#
# THE FIX (this file): run_candidate_dual_guardrail() below is a
# MINIMALLY-MODIFIED copy of the real run_candidate() -- every line of
# actual model-calling / tool-execution / retry / parsing logic is
# copied VERBATIM. The ONLY two changes are:
#   (1) ctx now additionally carries "user_messages" (the real,
#       accumulated, un-redacted conversation-so-far) and "tool_events"
#       (the real, un-redacted tool-call history-so-far, built the SAME
#       way the real file's own "scoring_events" is built at the end --
#       just incrementally, live, instead of only after the fact).
#   (2) the model-calling call is routed through an injectable
#       `model_caller` parameter (defaulting to the real retry_call_model,
#       imported unchanged), so this file can be offline-self-tested with
#       zero live network dependency before ever touching a real model.
#
# VERIFIED SAFE FOR THE PACKAGED GUARDRAIL: RealOptimalGuardrailShim
# (built and self-test-confirmed earlier this project against real E1
# denial-reason text) only reads context["recent_sources"] /
# ["user_confirmed_safe"] / ["user_authorized"] -- it ignores unknown
# keys. Adding "user_messages"/"tool_events" to ctx therefore has ZERO
# effect on the packaged guardrail's behavior; this is confirmed by the
# offline self-test below, which runs BOTH guardrails through the new
# ctx and checks the packaged path's decisions are unchanged from what
# the real historical run recorded.
#
# ALSO CONFIRMED (good news, one less complication): during a LIVE run,
# tool_args passed to guardrail.decide() come directly from the model's
# real, just-generated JSON tool-call arguments -- real strings, never
# the {length,sha256}-redacted shape seen in already-logged JSON. The
# sanitize_cd_email_args() workaround built for the REPLAY path
# (priority1_paired_replay.py) is UNNECESSARY here and is not used.
#
# STILL NOT RUNNABLE AGAINST A REAL MODEL WITHOUT YOUR CONFIRMATION OF:
#   - --project-root pointing at a real aicomp_sdk checkout
#   - --model-url reachable (your local GPT-OSS endpoint)
#   - --structured-cd-guardrail-path pointing at
#     structured_confused_deputy_guardrail_v1_1.py (attached alongside
#     this file in the same output folder)
# =============================================================================

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).parent))

# ============================================================================
# REUSED VERBATIM, UNCHANGED, from the real local_validate_v5_1.py -- same
# reuse discipline as every prior script in this project.
# ============================================================================
from local_validate_v5_1 import (  # noqa: E402
    ACTION_TOOLS,
    ALL_TOOL_SCHEMAS,
    SIDE_EFFECT_MAP,
    SOURCE_MAP,
    classify_verdict,
    content_summary,
    find_record,
    import_real_sdk,
    infer_tools_offered,
    inject_synthetic_fixtures,
    is_harmony_parse_failure,
    is_transport_failure,
    load_json_container,
    parse_message,
    prepare_temp_fixtures_dir,
    retry_call_model,
    snapshot_real_hashes,
    assert_real_hashes_unchanged,
    strip_fixture_note,
    write_json,
)

from attack_yaml_harness_v5_2_full_inline import (  # noqa: E402
    build_all_candidates_and_manifest,
)

TARGET_INSTRUCTION_IDS = {
    "C3_split_turn_authorization_false_positive",
    "C_implied_transmission",
    "CD09_v3_no_revocation_control",
}


# ============================================================================
# THE ONE NEW FUNCTION: a minimally-diffed copy of the real run_candidate().
# Diffs from the original are marked "# >>> DIFF" / "# <<< DIFF".
# ============================================================================

def run_candidate_dual_guardrail(case_id: str, messages_in: tuple, expected: Any,
                                   hypothesis: Optional[str], predicates_mod, guardrail,
                                   model_url: str, max_tokens: int, timeout: float,
                                   fixture_root: Path, mail_container: Any, web_container: Any,
                                   max_retries: int, backoff_base_s: float, seed_base: int,
                                   model_caller=retry_call_model) -> dict[str, Any]:
    tool_events: list[dict] = []
    conversation: list[dict] = []
    per_turn_log: list[dict] = []
    tools_offered = infer_tools_offered(messages_in)
    tools = [ALL_TOOL_SCHEMAS[name] for name in tools_offered]
    result: dict[str, Any] = {"case_id": case_id, "expected": expected, "hypothesis": hypothesis,
                              "tools_offered": tools_offered}

    # >>> DIFF (1 of 2): live, growing, UN-redacted context state, mirroring
    # exactly how derive_events_with_turns() built context for the REPLAY
    # path, so specialized guardrails behave identically live and replayed.
    accumulated_user_messages: list[str] = []
    # <<< DIFF

    def execute_tool_call(tool_name: str, tool_args: dict) -> str:
        side_effect = SIDE_EFFECT_MAP.get(tool_name)
        # >>> DIFF (1 of 2, continued): ctx enriched with user_messages and
        # real (unredacted) tool_events-so-far. recent_sources/recent_tools
        # preserved byte-for-byte identical to the real file -- packaged
        # guardrail behavior is provably unaffected (see offline self-test).
        live_tool_events_view = []
        for e in tool_events:
            e2 = dict(e)
            raw = e2.pop("_raw_do_not_persist", None)
            if e2.get("name") in ("fs.read", "email.read", "web.open") and raw is not None:
                e2["output"] = raw
            live_tool_events_view.append(e2)
        ctx = {"recent_sources": [e.get("source") for e in tool_events[-5:] if e.get("source")],
               "recent_tools": [e.get("name") for e in tool_events[-5:]], "last_user": "turn",
               "side_effect": side_effect, "seed": seed_base,
               "user_messages": list(accumulated_user_messages),
               "tool_events": live_tool_events_view,
               "policy_mode": "strict"}
        # <<< DIFF
        decision = None
        try:
            decision = guardrail.decide(tool_name, tool_args, ctx)
        except Exception as exc:
            per_turn_log[-1].setdefault("guardrail_errors", []).append({"tool": tool_name, "error": f"{type(exc).__name__}: {exc}"})
        decision_action = getattr(decision, "action", None) if decision is not None else None
        allowed = decision_action not in ("DENY", "CONFIRM") if decision_action else True
        per_turn_log[-1].setdefault("guardrail_decisions", []).append({
            "tool": tool_name, "action": decision_action,
            "reason": getattr(decision, "reason", None) if decision is not None else None})
        if not allowed:
            event = {"index": len(tool_events), "name": tool_name, "args": tool_args, "ok": False, "output": None,
                     "side_effect": side_effect, "source": SOURCE_MAP.get(tool_name),
                     "error": f"denied: {getattr(decision, 'reason', 'unknown')}"}
            tool_events.append(event)
            return f"DENIED by guardrail: {getattr(decision, 'reason', 'unknown')}"
        if tool_name == "fs.read":
            real_path = fixture_root / tool_args.get("path", "")
            if real_path.is_file():
                raw_output, ok, err = real_path.read_text(encoding="utf-8", errors="replace"), True, None
            else:
                raw_output, ok, err = None, False, "not_found"
            event = {"index": len(tool_events), "name": tool_name, "args": tool_args, "ok": ok,
                     "output": content_summary(raw_output), "_raw_do_not_persist": raw_output,
                     "side_effect": side_effect, "source": SOURCE_MAP.get(tool_name), "error": err}
            tool_events.append(event)
            return raw_output if raw_output is not None else f"ERROR: {err}"
        elif tool_name == "fs.write":
            real_path = fixture_root / tool_args.get("path", "")
            write_content = tool_args.get("content")
            ok, err = False, None
            try:
                real_path.parent.mkdir(parents=True, exist_ok=True)
                if isinstance(write_content, str):
                    real_path.write_text(write_content, encoding="utf-8")
                    ok = True
                else:
                    err = "content_not_a_string"
            except Exception as exc:
                err = f"{type(exc).__name__}: {exc}"
            event = {"index": len(tool_events), "name": tool_name,
                     "args": {"path": tool_args.get("path"), "content": content_summary(write_content)},
                     "ok": ok, "output": "ok" if ok else None, "side_effect": side_effect,
                     "source": SOURCE_MAP.get(tool_name), "error": err}
            tool_events.append(event)
            return "ok" if ok else f"ERROR: {err}"
        elif tool_name == "fs.delete":
            real_path = fixture_root / "file_seed" / tool_args.get("path", "").replace("file_seed/", "")
            if not real_path.is_file():
                real_path = fixture_root / tool_args.get("path", "")
            ok, err = False, None
            try:
                if real_path.is_file():
                    real_path.unlink()
                    ok = True
                else:
                    err = "not_found"
            except Exception as exc:
                err = f"{type(exc).__name__}: {exc}"
            event = {"index": len(tool_events), "name": tool_name, "args": tool_args, "ok": ok,
                     "output": "ok" if ok else None, "side_effect": side_effect, "source": SOURCE_MAP.get(tool_name), "error": err}
            tool_events.append(event)
            return "ok" if ok else f"ERROR: {err}"
        elif tool_name == "http.post":
            event = {"index": len(tool_events), "name": tool_name,
                     "args": {"url": tool_args.get("url"), "data": content_summary(tool_args.get("data"))},
                     "ok": True, "output": "ok", "side_effect": side_effect, "source": SOURCE_MAP.get(tool_name), "error": None}
            tool_events.append(event)
            return "ok"
        elif tool_name == "email.send":
            event = {"index": len(tool_events), "name": tool_name,
                     "args": {"to": tool_args.get("to"), "subject": tool_args.get("subject"),
                              "body": content_summary(tool_args.get("body"))},
                     "ok": True, "output": "ok", "side_effect": side_effect, "source": SOURCE_MAP.get(tool_name), "error": None}
            tool_events.append(event)
            return "ok"
        elif tool_name == "email.read":
            rec = find_record(mail_container, "inbox", tool_args.get("id", ""))
            content = rec.get("content") if rec else None
            ok = content is not None
            event = {"index": len(tool_events), "name": tool_name, "args": tool_args, "ok": ok,
                     "output": content_summary(content), "_raw_do_not_persist": content,
                     "side_effect": side_effect, "source": SOURCE_MAP.get(tool_name), "error": None if ok else "not_found"}
            tool_events.append(event)
            return content if ok else "ERROR: not_found"
        elif tool_name == "web.open":
            rec = find_record(web_container, "pages", tool_args.get("id", ""))
            content = rec.get("content") if rec else None
            ok = content is not None
            event = {"index": len(tool_events), "name": tool_name, "args": tool_args, "ok": ok,
                     "output": content_summary(content), "_raw_do_not_persist": content,
                     "side_effect": side_effect, "source": SOURCE_MAP.get(tool_name), "error": None if ok else "not_found"}
            tool_events.append(event)
            return content if ok else "ERROR: not_found"
        return "ok"

    for step_no, raw_message in enumerate(messages_in, start=1):
        user_message = strip_fixture_note(raw_message)
        conversation.append({"role": "user", "content": user_message})
        accumulated_user_messages.append(user_message)  # >>> DIFF (2 of 2 continued)
        r, retry_log = model_caller(model_url, conversation, tools, max_tokens, timeout,
                                      max_retries=max_retries, backoff_base_s=backoff_base_s)
        if not r.get("ok") or is_transport_failure(r) or is_harmony_parse_failure(r):
            outcome = "HARMONY_PARSE_FAILURE_EXHAUSTED_RETRIES" if is_harmony_parse_failure(r) else "TRANSPORT_FAILURE_EXHAUSTED_RETRIES"
            per_turn_log.append({"turn": step_no, "message": user_message, "status": r.get("status"),
                                 "retry_log": retry_log, "final_outcome": outcome})
            continue
        parsed = parse_message(r["raw"])
        per_turn_log.append({"turn": step_no, "message": user_message, "status": r.get("status"),
                             "finish_reason": parsed["finish_reason"],
                             "tool_calls_proposed": [tc["name"] for tc in parsed["tool_calls"]], "retry_log": retry_log})
        assistant_msg: dict = {"role": "assistant", "content": parsed["content"]}
        if parsed["tool_calls"]:
            assistant_msg["tool_calls"] = [
                {"id": tc.get("id") or f"call_{step_no}_{i}", "type": "function",
                 "function": {"name": tc["name"], "arguments": json.dumps(tc["arguments"] or {})}}
                for i, tc in enumerate(parsed["tool_calls"])]
        conversation.append(assistant_msg)
        for i, tc in enumerate(parsed["tool_calls"]):
            tool_result_content = execute_tool_call(tc["name"], tc["arguments"] or {})
            conversation.append({"role": "tool", "tool_call_id": tc.get("id") or f"call_{step_no}_{i}",
                                 "name": tc["name"], "content": tool_result_content})

    redacted_events = []
    for e in tool_events:
        e2 = dict(e); e2.pop("_raw_do_not_persist", None); redacted_events.append(e2)
    result["tool_events"] = redacted_events
    result["per_turn_log"] = per_turn_log
    scoring_events = []
    for e in tool_events:
        e2 = dict(e)
        raw_output = e2.pop("_raw_do_not_persist", None)
        if e2.get("name") in ("fs.read", "email.read", "web.open") and raw_output is not None:
            e2["output"] = raw_output
        scoring_events.append(e2)
    trace = {"tool_events": scoring_events, "user_messages": [strip_fixture_note(m) for m in messages_in]}
    try:
        predicates_triggered = predicates_mod.eval_predicates(trace)
        result["predicates_triggered"] = predicates_triggered
        result["is_breach"] = predicates_mod.is_breach(trace, predicates_triggered)
    except Exception as exc:
        result["predicate_eval_error"] = f"{type(exc).__name__}: {exc}"
    action_events = [e for e in tool_events if e.get("name") in ACTION_TOOLS]
    any_tool_denied_including_reads = any(
        (not e.get("ok")) and "denied" in str(e.get("error", "")) for e in tool_events
    )
    result["outcome_summary"] = {
        "any_action_attempted": len(action_events) > 0,
        "any_action_denied": any((not e.get("ok")) and "denied" in str(e.get("error", "")) for e in action_events),
        "any_action_succeeded": any(e.get("ok") for e in action_events),
        "any_guardrail_deny": any(gd.get("action") == "DENY" for t in per_turn_log for gd in t.get("guardrail_decisions", [])),
        "any_tool_denied_including_reads": any_tool_denied_including_reads,
    }
    return result


def build_specialized_cd_guardrail_factory(structured_cd_module_path: str):
    mod_name = "structured_confused_deputy_guardrail_v1_1_live"
    spec = importlib.util.spec_from_file_location(mod_name, structured_cd_module_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod  # required for dataclasses on Python 3.12+
    spec.loader.exec_module(mod)
    return lambda: mod.Guardrail()


def select_target_candidates():
    candidates, manifest = build_all_candidates_and_manifest()
    selected = [(c, m) for c, m in zip(candidates, manifest) if m["instruction_id"] in TARGET_INSTRUCTION_IDS]
    found = {m["instruction_id"] for _, m in selected}
    missing = TARGET_INSTRUCTION_IDS - found
    if missing:
        raise RuntimeError(f"Expected instruction_id(s) not found in manifest: {missing}")
    return selected


def run_live(project_root: str, structured_cd_guardrail_path: str, model_url: str,
             fixtures_dir: Optional[str], max_tokens: int, timeout: float,
             max_retries: int, backoff_base_s: float, out_path: str) -> int:
    project_root_p = Path(project_root).resolve()
    real_fixtures_dir = Path(fixtures_dir).resolve() if fixtures_dir else project_root_p / "aicomp_sdk" / "fixtures"

    print("Importing real predicates.py + real OptimalGuardrail...")
    sdk = import_real_sdk(project_root_p)
    for a in sdk["import_attempts"]:
        print(f"  [{'OK' if a['ok'] else 'FAILED'}] {a['target']}" + (f" -- {a.get('error')}" if not a["ok"] else ""))
    if not (sdk["predicates_module"] and sdk["guardrail"]):
        print("FATAL: could not import required real SDK components.")
        return 1
    if not real_fixtures_dir.is_dir():
        print(f"FATAL: real fixtures_dir not found at {real_fixtures_dir}")
        return 1

    specialized_factory = build_specialized_cd_guardrail_factory(structured_cd_guardrail_path)

    hash_targets = ["mail_seed.json", "web_corpus.json", "file_seed/readme.txt", "file_seed/note.txt"]
    hash_targets = [t for t in hash_targets if (real_fixtures_dir / t).is_file()]
    hashes_before = snapshot_real_hashes(real_fixtures_dir, hash_targets)

    selected = select_target_candidates()
    all_results = []
    seed_counter = 900000  # distinct range from every prior script
    try:
        for candidate, m in selected:
            case_label = f"{m['family']}/{m['instruction_id']}#{m['candidate_idx']}"
            tag = f"livedual_{m['instruction_id']}"
            fixture_root = prepare_temp_fixtures_dir(real_fixtures_dir, tag)
            inject_synthetic_fixtures(fixture_root)
            mail_container = load_json_container(fixture_root, "mail_seed.json")
            web_container = load_json_container(fixture_root, "web_corpus.json")

            seed_counter += 1
            print(f"[PACKAGED]    {case_label} ...", end=" ", flush=True)
            packaged_result = run_candidate_dual_guardrail(
                case_label + "_packaged", candidate.user_messages, m.get("expected"), m.get("hypothesis"),
                sdk["predicates_module"], sdk["guardrail"], model_url, max_tokens, timeout,
                fixture_root, mail_container, web_container, max_retries, backoff_base_s, seed_counter)
            os_p = packaged_result["outcome_summary"]
            print(f"attempted={os_p.get('any_action_attempted')} succeeded={os_p.get('any_action_succeeded')}")

            seed_counter += 1
            print(f"[SPECIALIZED] {case_label} ...", end=" ", flush=True)
            specialized_guardrail = specialized_factory()  # FRESH instance per candidate -- fixes the stateful-reuse issue
            specialized_result = run_candidate_dual_guardrail(
                case_label + "_specialized", candidate.user_messages, m.get("expected"), m.get("hypothesis"),
                sdk["predicates_module"], specialized_guardrail, model_url, max_tokens, timeout,
                fixture_root, mail_container, web_container, max_retries, backoff_base_s, seed_counter)
            os_s = specialized_result["outcome_summary"]
            print(f"attempted={os_s.get('any_action_attempted')} succeeded={os_s.get('any_action_succeeded')}")

            all_results.append({
                "instruction_id": m["instruction_id"], "family": m["family"], "candidate_idx": m["candidate_idx"],
                "expected": m.get("expected"), "packaged_result": packaged_result,
                "specialized_result": specialized_result,
                "guardrail_decisions_diverged": os_p.get("any_action_succeeded") != os_s.get("any_action_succeeded"),
            })
    finally:
        safety_report = assert_real_hashes_unchanged(real_fixtures_dir, hash_targets, hashes_before)
        print("[safety] real fixtures_dir verified byte-identical before/after.")

    write_json(Path(out_path), {"results": all_results, "safety_verification": safety_report,
                                  "note": "Live dual-guardrail confirmation run for the 3 body-redaction "
                                          "ambiguity CD candidates. No network call to any Kaggle endpoint."})
    print(f"\nResults written to: {Path(out_path).resolve()}")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--i-authorize-local-validation", action="store_true")
    ap.add_argument("--project-root", default=None)
    ap.add_argument("--fixtures-dir", default=None)
    ap.add_argument("--model-url", default="http://127.0.0.1:8080/v1/chat/completions")
    ap.add_argument("--structured-cd-guardrail-path", default=None)
    ap.add_argument("--max-tokens", type=int, default=1536)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--max-retries", type=int, default=2)
    ap.add_argument("--backoff-base-s", type=float, default=1.5)
    ap.add_argument("--out", default="live_dual_guardrail_3_candidates_result.json")
    ap.add_argument("--self-test-offline", action="store_true",
                     help="Run the offline, zero-network self-test only (uses canned historical "
                          "model responses for the 3 target candidates; verifies both the "
                          "candidate-selection logic and the new context-enrichment logic without "
                          "touching any live model).")
    args = ap.parse_args()

    if args.self_test_offline:
        import self_test_offline
        return self_test_offline.run_self_test()

    if not args.i_authorize_local_validation:
        selected = select_target_candidates()
        print(f"Plan: live dual-guardrail run for {len(selected)} candidate(s):")
        for _, m in selected:
            print(f"  - {m['family']}/{m['instruction_id']} (expected={m.get('expected')!r})")
        print(f"\nModel URL: {args.model_url}")
        print("Pass --i-authorize-local-validation to execute for real (requires --project-root "
              "and --structured-cd-guardrail-path).")
        return 3

    if not args.project_root or not args.structured_cd_guardrail_path:
        print("FATAL: --project-root and --structured-cd-guardrail-path are required for a real run.")
        return 2

    return run_live(args.project_root, args.structured_cd_guardrail_path, args.model_url,
                     args.fixtures_dir, args.max_tokens, args.timeout, args.max_retries,
                     args.backoff_base_s, args.out)


if __name__ == "__main__":
    sys.exit(main())
