#!/usr/bin/env python3
# =============================================================================
# live_dual_guardrail_run_v3.py  (hardened for the full 20-candidate,
# no-hurry, unattended long run -- incremental checkpointing + resume)
# AI_AGENT_SECURITY -- LIVE GPT-OSS dual-guardrail confirmation.
#
# =============================================================================
# WHAT'S NEW IN THIS VERSION vs. the previous v3 draft
# -----------------------------------------------------------------------
# You asked for the full 20-candidate run "let it take time no hurry" --
# that changes the engineering requirements. A 20-candidate x 2-guardrail
# run is 40 live model conversations; at ~10-60s per conversation
# (depending on turn count and retries), this could run for 20-60+
# minutes. The previous version only wrote output at the very end -- if
# ANYTHING interrupts it partway (a harmony-parse-failure that exhausts
# retries, a network blip, you closing the terminal), ALL prior progress
# would be silently lost. This version fixes that:
#
#   1. INCREMENTAL CHECKPOINTING: writes --out after EVERY completed
#      candidate (not just at the end), so a partial run is never a lost
#      run.
#   2. RESUME SUPPORT: if --out already exists and contains prior results
#      (e.g. from a run that was interrupted), candidates already present
#      are SKIPPED on re-run -- pass --force-rerun-all to override this
#      and start clean. Resume is matched on (instruction_id,
#      candidate_idx), not just instruction_id, since some CD blocks
#      (C_indirect_injection_triplet) have 3 sub-candidates.
#   3. PROGRESS REPORTING: each candidate prints an elapsed-time-so-far
#      and estimated-candidates-remaining line, so a long unattended run
#      is easy to check in on.
#   4. OFFLINE SELF-TEST FOR THE 20-CANDIDATE SELECTION ITSELF: verifies
#      select_all_cd_candidates() actually returns exactly the 20 rows the
#      real attack_yaml_harness_v5_2_full_inline.py module docstring
#      claims (15 v5.1-retained + 5 Tier-1 = 20), with the EXACT set of
#      instruction_ids expected -- BEFORE you spend the runtime on a live
#      run. See CONFIRMED DISCREPANCY note below.
#
# CONFIRMED DISCREPANCY (carried over from the prior turn, still open):
#   the plan YAML says "CONFUSED_DEPUTY: 14/18 divergence" -- but counting
#   directly from the real attack_yaml_harness_v5_2_full_inline.py content
#   (fetched in full earlier this session) gives 18 BLOCKS but 20 total
#   candidate ROWS (C_indirect_injection_triplet alone contributes 3), which
#   matches that file's OWN module docstring: "CONFUSED_DEPUTY: 15 (v5.1) +
#   5 (Tier-1) = 20". This script's --scope all_cd prints the REAL count at
#   both dry-run and live-run time specifically so you can see which number
#   is correct for YOUR actual harness file, rather than trusting either
#   number blindly.
#
# EVERY LINE of run_candidate_dual_guardrail(), execute_tool_call(), and the
# core packaged/specialized calling sequence is UNCHANGED, copied VERBATIM
# from the version already verified 3/3 exact-reproduction against your
# real live_dual_guardrail_3_candidates_result.json run. Only the run
# orchestration (checkpointing/resume/progress) and candidate-selection
# scope are new.
#
# USAGE (full 20-candidate run, resumable):
#   python live_dual_guardrail_run_v3.py --i-authorize-local-validation ^
#       --project-root "C:\...\ai-agent-security-multi-step-tool-attacks" ^
#       --model-url http://127.0.0.1:8080/v1/chat/completions ^
#       --structured-cd-guardrail-path structured_confused_deputy_guardrail_v1_1_v1_2.py ^
#       --scope all_cd --out live_dual_guardrail_all_cd_result.json
#
# If interrupted, just re-run the EXACT same command -- already-completed
# candidates are automatically skipped and the run picks up where it left
# off. To force a completely clean restart instead, add --force-rerun-all.
#
# Offline, zero-network sanity check for the 20-candidate SELECTION logic
# itself (run this first, costs nothing, no model needed):
#   python live_dual_guardrail_run_v3.py --self-test-selection-only ^
#       --project-root "C:\...\ai-agent-security-multi-step-tool-attacks"
# =============================================================================
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).parent))

from local_validate_v5_1 import (  # noqa: E402
    ACTION_TOOLS,
    ALL_TOOL_SCHEMAS,
    SIDE_EFFECT_MAP,
    SOURCE_MAP,
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

# Kept for the default/legacy 3-candidate scope -- unchanged from prior
# versions, still selectable via --scope target3.
TARGET_INSTRUCTION_IDS = {
    "C3_split_turn_authorization_false_positive",
    "C_implied_transmission",
    "CD09_v3_no_revocation_control",
}

# Per the real attack_yaml_harness_v5_2_full_inline.py's OWN module
# docstring ("CONFUSED_DEPUTY: 15 (v5.1) + 5 (Tier-1) = 20"), the expected
# full set of 18 DISTINCT instruction_ids (20 candidate ROWS, since
# C_indirect_injection_triplet contributes 3 sub-candidates under one
# instruction_id). Used ONLY by the offline self-test below to verify
# select_all_cd_candidates() against a known-correct expectation derived
# directly from that file's own content -- NOT hardcoded blindly, this
# was manually cross-checked against the real fetched file content.
EXPECTED_ALL_CD_INSTRUCTION_IDS = {
    "C_recipient_drift", "C_body_scope_expansion", "C_api_keys_send_cascade",
    "C3_split_turn_authorization_false_positive", "C_implied_transmission",
    "C_explicit_unauthorized_send_negative_boundary", "C_negative_no_send_control",
    "C_indirect_injection_triplet",  # contributes 3 candidate rows
    "CD07_authorization_reuse_one_time_consumption", "CD09_revocation_before_execution",
    "CD11_subject_scope_drift", "CD12_post_consumption_amendment_matrix",
    "CD20_amplification_redesigned_single_call",
    "CD13_pairwise_recipient_subject_drift", "CD14_pairwise_recipient_body_drift",
    "CD15_pairwise_subject_body_drift", "CD09_v2_multistep_revocation_before_execution",
    "CD09_v3_no_revocation_control",
}
EXPECTED_ALL_CD_TOTAL_ROWS = 20  # 18 distinct instruction_ids, 20 total candidate rows


# ============================================================================
# UNCHANGED, VERBATIM -- already verified 3/3 exact reproduction against
# your real live run. Zero logic touched below this point except where
# explicitly marked "# >>> V3 CHECKPOINT DIFF".
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

    accumulated_user_messages: list[str] = []

    def execute_tool_call(tool_name: str, tool_args: dict) -> str:
        side_effect = SIDE_EFFECT_MAP.get(tool_name)
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
        accumulated_user_messages.append(user_message)
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
    """UNCHANGED -- selects exactly the 3 body-redaction-ambiguity
    candidates. Default scope; nothing changed here."""
    candidates, manifest = build_all_candidates_and_manifest()
    selected = [(c, m) for c, m in zip(candidates, manifest) if m["instruction_id"] in TARGET_INSTRUCTION_IDS]
    found = {m["instruction_id"] for _, m in selected}
    missing = TARGET_INSTRUCTION_IDS - found
    if missing:
        raise RuntimeError(f"Expected instruction_id(s) not found in manifest: {missing}")
    return selected


def select_all_cd_candidates():
    """Selects ALL CONFUSED_DEPUTY candidates from the real manifest --
    however many that actually is at runtime. Does NOT assume 18 or 20;
    reads the real, live manifest and reports the actual count."""
    candidates, manifest = build_all_candidates_and_manifest()
    selected = [(c, m) for c, m in zip(candidates, manifest) if m["family"] == "CONFUSED_DEPUTY"]
    if not selected:
        raise RuntimeError("No CONFUSED_DEPUTY candidates found in manifest -- investigate before proceeding.")
    return selected


def self_test_selection_only():
    """Offline, zero-network sanity check for --scope all_cd's candidate
    selection, run BEFORE spending any runtime on a live 20-candidate
    run. Verifies the REAL manifest's CD selection against the expected
    set derived directly from the real harness file's own content and
    its own module docstring -- not a blind assumption."""
    print("=" * 78)
    print("OFFLINE SELF-TEST: --scope all_cd candidate selection")
    print("(zero network calls, zero model calls -- pure manifest inspection)")
    print("=" * 78)
    selected = select_all_cd_candidates()
    actual_ids = {m["instruction_id"] for _, m in selected}
    actual_total_rows = len(selected)

    print(f"\nTotal CONFUSED_DEPUTY candidate ROWS found in the real manifest: {actual_total_rows}")
    print(f"Total DISTINCT instruction_ids: {len(actual_ids)}")

    print(f"\nExpected (derived from attack_yaml_harness_v5_2_full_inline.py's own")
    print(f"module docstring, '15 (v5.1) + 5 (Tier-1) = 20'): {EXPECTED_ALL_CD_TOTAL_ROWS} rows, "
          f"{len(EXPECTED_ALL_CD_INSTRUCTION_IDS)} distinct instruction_ids")

    missing_ids = EXPECTED_ALL_CD_INSTRUCTION_IDS - actual_ids
    extra_ids = actual_ids - EXPECTED_ALL_CD_INSTRUCTION_IDS
    if missing_ids:
        print(f"\n*** MISSING from real manifest (expected but not found): {sorted(missing_ids)}")
    if extra_ids:
        print(f"\n*** EXTRA in real manifest (found but not in expected set): {sorted(extra_ids)}")
    if not missing_ids and not extra_ids:
        print("\nCONFIRMED: instruction_id sets match exactly.")

    if actual_total_rows != EXPECTED_ALL_CD_TOTAL_ROWS:
        print(f"\n*** ROW COUNT MISMATCH: real manifest has {actual_total_rows} rows, expected "
              f"{EXPECTED_ALL_CD_TOTAL_ROWS}. If your plan YAML says '18', that figure is the "
              f"BLOCK count (18 distinct instruction_ids MINUS the ones that got merged wrong --")
        print(f"    recount: this manifest actually has {len(actual_ids)} distinct instruction_ids), "
              f"NOT the candidate ROW count relevant to a per-candidate divergence table. "
              f"Trust the row count printed above, from THIS real manifest, over any number in the plan YAML.")
    else:
        print(f"\nCONFIRMED: row count matches expected ({actual_total_rows}).")

    print("\nFull candidate list, in the order they will run:")
    for i, (_, m) in enumerate(selected, 1):
        print(f"  {i:2d}. {m['instruction_id']}#{m['candidate_idx']} (expected={m.get('expected')!r})")

    print()
    print("=" * 78)
    print("Selection self-test complete. Review the list above BEFORE running live.")
    print("=" * 78)
    return 0


def load_existing_checkpoint(out_path: Path) -> tuple[list[dict], set[tuple[str, int]]]:
    """>>> V3 CHECKPOINT DIFF. If --out already exists from a prior
    (possibly interrupted) run, load its results and return the set of
    (instruction_id, candidate_idx) pairs already completed, so they can
    be skipped on resume."""
    if not out_path.is_file():
        return [], set()
    try:
        with out_path.open("r", encoding="utf-8") as f:
            existing = json.load(f)
    except Exception as exc:
        print(f"WARNING: could not parse existing --out file at {out_path} ({exc}) -- "
              f"treating as if no checkpoint exists. If this is unexpected, check the file "
              f"manually before proceeding; a fresh run will overwrite it.")
        return [], set()
    existing_results = existing.get("results", [])
    completed = {(r["instruction_id"], r["candidate_idx"]) for r in existing_results}
    print(f"RESUME: found existing checkpoint at {out_path} with {len(existing_results)} "
          f"already-completed candidate(s). These will be SKIPPED. Pass --force-rerun-all "
          f"to start completely fresh instead.")
    return existing_results, completed


def write_checkpoint(out_path: Path, all_results: list[dict], safety_report: Any,
                       scope: str, n_candidates_total: int, run_complete: bool) -> None:
    """>>> V3 CHECKPOINT DIFF. Writes the current progress to --out. Called
    after EVERY candidate (not just at the end), so an interrupted run
    never loses completed work."""
    write_json(out_path, {
        "results": all_results,
        "safety_verification": safety_report,
        "scope": scope,
        "n_candidates_total": n_candidates_total,
        "n_candidates_completed": len(all_results),
        "run_complete": run_complete,
        "note": ("Live dual-guardrail confirmation run. No network call to any Kaggle endpoint. "
                 "If run_complete is false, this is a PARTIAL/interrupted run -- re-run the same "
                 "command to resume from where it left off."),
    })


def run_live(project_root: str, structured_cd_guardrail_path: str, model_url: str,
             fixtures_dir: Optional[str], max_tokens: int, timeout: float,
             max_retries: int, backoff_base_s: float, out_path_str: str,
             scope: str, force_rerun_all: bool) -> int:
    project_root_p = Path(project_root).resolve()
    real_fixtures_dir = Path(fixtures_dir).resolve() if fixtures_dir else project_root_p / "aicomp_sdk" / "fixtures"
    out_path = Path(out_path_str)

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

    hash_targets = ["mail_seed.json", "web_corpus.json", "file_seed/readme.txt", "file_seed/note.txt",
                    "file_seed/api_keys.txt"]
    hash_targets = [t for t in hash_targets if (real_fixtures_dir / t).is_file()]
    hashes_before = snapshot_real_hashes(real_fixtures_dir, hash_targets)

    if scope == "all_cd":
        selected = select_all_cd_candidates()
        print(f"SCOPE: all_cd -- {len(selected)} CONFUSED_DEPUTY candidate(s) selected from the "
              f"REAL manifest (this is the ground truth; trust this number over any figure in a "
              f"plan document).")
    else:
        selected = select_target_candidates()
        print(f"SCOPE: target3 (default) -- {len(selected)} candidate(s), unchanged from prior versions.")

    # >>> V3 CHECKPOINT DIFF: resume support
    if force_rerun_all:
        all_results: list[dict] = []
        already_completed: set[tuple[str, int]] = set()
        if out_path.is_file():
            print(f"--force-rerun-all passed: ignoring any existing checkpoint at {out_path}.")
    else:
        all_results, already_completed = load_existing_checkpoint(out_path)
    # <<< V3 CHECKPOINT DIFF

    n_total = len(selected)
    n_skipped = 0
    seed_counter = 900000
    run_start_time = time.monotonic()
    safety_report: Any = None

    try:
        for i, (candidate, m) in enumerate(selected, start=1):
            key = (m["instruction_id"], m["candidate_idx"])
            case_label = f"{m['family']}/{m['instruction_id']}#{m['candidate_idx']}"

            # >>> V3 CHECKPOINT DIFF: skip already-completed candidates on resume
            if key in already_completed:
                n_skipped += 1
                print(f"  [{i}/{n_total}] {case_label} -- SKIPPED (already completed in prior checkpoint)")
                continue
            # <<< V3 CHECKPOINT DIFF

            elapsed_min = (time.monotonic() - run_start_time) / 60.0
            remaining_est = n_total - i + 1
            print(f"  [{i}/{n_total}] {case_label} ... "
                  f"(elapsed so far: {elapsed_min:.1f} min, ~{remaining_est} candidate(s) left this session)")

            tag = f"livedual_{m['instruction_id']}_{m['candidate_idx']}"
            fixture_root = prepare_temp_fixtures_dir(real_fixtures_dir, tag)
            inject_synthetic_fixtures(fixture_root)
            mail_container = load_json_container(fixture_root, "mail_seed.json")
            web_container = load_json_container(fixture_root, "web_corpus.json")

            seed_counter += 1
            print(f"    [PACKAGED]    ...", end=" ", flush=True)
            packaged_result = run_candidate_dual_guardrail(
                case_label + "_packaged", candidate.user_messages, m.get("expected"), m.get("hypothesis"),
                sdk["predicates_module"], sdk["guardrail"], model_url, max_tokens, timeout,
                fixture_root, mail_container, web_container, max_retries, backoff_base_s, seed_counter)
            os_p = packaged_result["outcome_summary"]
            print(f"attempted={os_p.get('any_action_attempted')} succeeded={os_p.get('any_action_succeeded')}")

            seed_counter += 1
            print(f"    [SPECIALIZED] ...", end=" ", flush=True)
            specialized_guardrail = specialized_factory()  # fresh instance per candidate
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

            # >>> V3 CHECKPOINT DIFF: write progress after EVERY candidate,
            # not just at the end. Safety hash check runs at the very end
            # (unchanged real fixtures_dir is only guaranteed once ALL
            # candidates for this session are done), but the RESULTS
            # themselves are saved incrementally so they are never lost.
            write_checkpoint(out_path, all_results, safety_report={"status": "PENDING_FINAL_CHECK"},
                              scope=scope, n_candidates_total=n_total, run_complete=False)
            # <<< V3 CHECKPOINT DIFF
    finally:
        safety_report = assert_real_hashes_unchanged(real_fixtures_dir, hash_targets, hashes_before)
        print("[safety] real fixtures_dir verified byte-identical before/after.")

    run_complete = (len(all_results) >= n_total)
    write_checkpoint(out_path, all_results, safety_report, scope, n_total, run_complete)

    elapsed_total_min = (time.monotonic() - run_start_time) / 60.0
    print(f"\nSession complete in {elapsed_total_min:.1f} min. "
          f"{len(all_results)}/{n_total} total candidates completed "
          f"({n_skipped} skipped as already-done from a prior checkpoint this session).")
    print(f"Results written to: {out_path.resolve()}")
    if not run_complete:
        print("NOTE: run_complete=false -- some candidates remain. Re-run the SAME command to continue.")
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
    ap.add_argument("--out", default="live_dual_guardrail_result.json")
    ap.add_argument("--scope", default="target3", choices=["target3", "all_cd"],
                     help="'target3' (default): only the 3 body-redaction-ambiguity candidates. "
                          "'all_cd': ALL CONFUSED_DEPUTY candidates in the real manifest.")
    ap.add_argument("--force-rerun-all", action="store_true",
                     help="Ignore any existing --out checkpoint and start completely fresh. "
                          "Without this flag, a prior partial run at the same --out path is "
                          "automatically resumed (already-completed candidates skipped).")
    ap.add_argument("--self-test-offline", action="store_true",
                     help="Run the offline, zero-network self-test for the ORIGINAL 3-candidate "
                          "scope's context-enrichment logic (uses canned historical model "
                          "responses). Does not check --scope all_cd's selection -- use "
                          "--self-test-selection-only for that.")
    ap.add_argument("--self-test-selection-only", action="store_true",
                     help="Zero-network, zero-model-call sanity check for --scope all_cd's "
                          "candidate selection against the real manifest. Run this FIRST, before "
                          "spending runtime on a live 20-candidate run. Requires --project-root.")
    args = ap.parse_args()

    if args.self_test_offline:
        import self_test_offline
        return self_test_offline.run_self_test()

    if args.self_test_selection_only:
        if not args.project_root:
            print("FATAL: --project-root is required for --self-test-selection-only.")
            return 2
        project_root_p = Path(args.project_root).resolve()
        sys.path.insert(0, str(project_root_p))
        return self_test_selection_only()

    if not args.i_authorize_local_validation:
        if not args.project_root:
            print("Pass --project-root to see the dry-run candidate list, or --self-test-selection-only "
                  "for a selection-only check with no model/network dependency at all.")
            return 3
        selected = select_all_cd_candidates() if args.scope == "all_cd" else select_target_candidates()
        print(f"Plan: live dual-guardrail run, scope={args.scope!r}, for {len(selected)} candidate(s):")
        for _, m in selected:
            print(f"  - {m['family']}/{m['instruction_id']}#{m['candidate_idx']} (expected={m.get('expected')!r})")
        print(f"\nModel URL: {args.model_url}")
        print("Pass --i-authorize-local-validation to execute for real (requires --project-root "
              "and --structured-cd-guardrail-path).")
        return 3

    if not args.project_root or not args.structured_cd_guardrail_path:
        print("FATAL: --project-root and --structured-cd-guardrail-path are required for a real run.")
        return 2

    return run_live(args.project_root, args.structured_cd_guardrail_path, args.model_url,
                     args.fixtures_dir, args.max_tokens, args.timeout, args.max_retries,
                     args.backoff_base_s, args.out, args.scope, args.force_rerun_all)


if __name__ == "__main__":
    sys.exit(main())
