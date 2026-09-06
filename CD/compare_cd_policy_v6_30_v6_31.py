
"""Regenerate CONFUSED_DEPUTY v6.30 vs v6.31 comparisons.

This is an offline comparison utility. It does not rerun GPT-OSS, SandboxEnv,
base rules, optimal guardrail, or attack.py.

Comparison levels
-----------------
1. Scenario level: final proposed decision per case/guardrail.
2. Event level: each email.send, aligned by case + guardrail + email ordinal.
3. Control level: structured intent, exact parameters, provenance,
   one-time consumption, duplicate prevention, and final decision.
4. Reason level: explanation strings added/removed between versions.

Default inputs
--------------
C:\\x_ai_logs\\cd_policy_eval\\policy_eval_rows.json
C:\\x_ai_logs\\cd_policy_eval_v6_31\\policy_eval_rows_v6_31.json

Default output
--------------
C:\\x_ai_logs\\cd_policy_compare_v6_30_v6_31
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CONTROL_KEYS = [
    "structured_intent_binding",
    "exact_parameter_authorization",
    "provenance_policy",
    "one_time_consumption",
    "duplicate_prevention",
    "final_decision",
]

DECISION_RANK = {"ALLOW": 0, "CONFIRM": 1, "DENY": 2, "MISSING": -1}


def load_rows(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("rows"), list):
        return data["rows"]
    raise ValueError(f"Unsupported row structure in {path}")


def case_id(row: dict[str, Any]) -> str:
    return str(row.get("id") or row.get("source_row_id") or "UNKNOWN")


def row_key(row: dict[str, Any]) -> tuple[str, str]:
    return case_id(row), str(row.get("guardrail") or "UNKNOWN")


def normalized_policy(policy: dict[str, Any] | None) -> dict[str, str]:
    policy = policy or {}
    return {key: str(policy.get(key, "MISSING")) for key in CONTROL_KEYS}


def email_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    return list(row.get("email_policy_evaluations") or [])


def expected_event_identity(row: dict[str, Any], event: dict[str, Any], ordinal: int) -> dict[str, Any]:
    args = event.get("email_args") or {}
    return {
        "case_id": case_id(row),
        "guardrail": str(row.get("guardrail") or "UNKNOWN"),
        "email_ordinal": ordinal,
        "event_index": event.get("event_index"),
        "event_turn": event.get("event_turn"),
        "recipient": args.get("to"),
        "subject": args.get("subject"),
        "body": args.get("body"),
        "tool_ok": event.get("tool_ok"),
        "actual_error": event.get("actual_error"),
    }


def compare_scenarios(old_rows: list[dict[str, Any]], new_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    old_map = {row_key(r): r for r in old_rows}
    new_map = {row_key(r): r for r in new_rows}
    output = []
    for key in sorted(set(old_map) | set(new_map)):
        old, new = old_map.get(key), new_map.get(key)
        old_final = str((old or {}).get("final_proposed_decision", "MISSING"))
        new_final = str((new or {}).get("final_proposed_decision", "MISSING"))
        output.append({
            "case_id": key[0],
            "guardrail": key[1],
            "actual_stage_v6_30": (old or {}).get("actual_stage"),
            "actual_stage_v6_31": (new or {}).get("actual_stage"),
            "actual_cd_v6_30": (old or {}).get("actual_cd_triggered"),
            "actual_cd_v6_31": (new or {}).get("actual_cd_triggered"),
            "email_event_count_v6_30": len(email_events(old or {})),
            "email_event_count_v6_31": len(email_events(new or {})),
            "final_v6_30": old_final,
            "final_v6_31": new_final,
            "final_changed": old_final != new_final,
            "event_count_changed": len(email_events(old or {})) != len(email_events(new or {})),
        })
    return output


def compare_events(old_rows: list[dict[str, Any]], new_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Align email events by scenario, guardrail, and email ordinal.

    Email ordinal is preferred over raw tool event_index because non-email tool
    calls can shift indices between frozen traces. Alignment confidence is
    reported and argument changes are not hidden.
    """
    old_map = {row_key(r): r for r in old_rows}
    new_map = {row_key(r): r for r in new_rows}
    events_out: list[dict[str, Any]] = []
    controls_out: list[dict[str, Any]] = []

    for key in sorted(set(old_map) | set(new_map)):
        old_row, new_row = old_map.get(key, {}), new_map.get(key, {})
        old_events, new_events = email_events(old_row), email_events(new_row)
        for ordinal in range(max(len(old_events), len(new_events))):
            old_event = old_events[ordinal] if ordinal < len(old_events) else None
            new_event = new_events[ordinal] if ordinal < len(new_events) else None
            old_id = expected_event_identity(old_row, old_event or {}, ordinal)
            new_id = expected_event_identity(new_row, new_event or {}, ordinal)
            old_args = (old_event or {}).get("email_args") or {}
            new_args = (new_event or {}).get("email_args") or {}
            args_equal = old_args == new_args if old_event and new_event else False
            recipient_equal = old_args.get("to") == new_args.get("to") if old_event and new_event else False
            subject_equal = old_args.get("subject") == new_args.get("subject") if old_event and new_event else False
            body_equal = old_args.get("body") == new_args.get("body") if old_event and new_event else False

            if old_event and new_event and args_equal:
                confidence = "HIGH"
            elif old_event and new_event and recipient_equal and subject_equal:
                confidence = "MEDIUM"
            elif old_event and new_event:
                confidence = "LOW"
            else:
                confidence = "UNPAIRED"

            old_policy = normalized_policy((old_event or {}).get("proposed_policy"))
            new_policy = normalized_policy((new_event or {}).get("proposed_policy"))
            old_expl = list(((old_event or {}).get("proposed_policy") or {}).get("explanation") or [])
            new_expl = list(((new_event or {}).get("proposed_policy") or {}).get("explanation") or [])

            event_record = {
                "case_id": key[0],
                "guardrail": key[1],
                "email_ordinal": ordinal,
                "alignment_confidence": confidence,
                "present_v6_30": old_event is not None,
                "present_v6_31": new_event is not None,
                "event_index_v6_30": old_id.get("event_index"),
                "event_index_v6_31": new_id.get("event_index"),
                "event_turn_v6_30": old_id.get("event_turn"),
                "event_turn_v6_31": new_id.get("event_turn"),
                "recipient_v6_30": old_args.get("to"),
                "recipient_v6_31": new_args.get("to"),
                "subject_v6_30": old_args.get("subject"),
                "subject_v6_31": new_args.get("subject"),
                "body_v6_30": old_args.get("body"),
                "body_v6_31": new_args.get("body"),
                "arguments_equal": args_equal,
                "tool_ok_v6_30": (old_event or {}).get("tool_ok"),
                "tool_ok_v6_31": (new_event or {}).get("tool_ok"),
                "actual_error_v6_30": (old_event or {}).get("actual_error"),
                "actual_error_v6_31": (new_event or {}).get("actual_error"),
                "final_v6_30": old_policy["final_decision"],
                "final_v6_31": new_policy["final_decision"],
                "final_changed": old_policy["final_decision"] != new_policy["final_decision"],
                "controls_changed": [k for k in CONTROL_KEYS if old_policy[k] != new_policy[k]],
                "explanations_added": [x for x in new_expl if x not in old_expl],
                "explanations_removed": [x for x in old_expl if x not in new_expl],
            }
            events_out.append(event_record)

            for control in CONTROL_KEYS:
                old_decision, new_decision = old_policy[control], new_policy[control]
                controls_out.append({
                    "case_id": key[0],
                    "guardrail": key[1],
                    "email_ordinal": ordinal,
                    "alignment_confidence": confidence,
                    "control": control,
                    "v6_30": old_decision,
                    "v6_31": new_decision,
                    "changed": old_decision != new_decision,
                    "direction": decision_direction(old_decision, new_decision),
                })

    return events_out, controls_out


def decision_direction(old: str, new: str) -> str:
    if old == new:
        return "UNCHANGED"
    if old == "MISSING":
        return "ADDED"
    if new == "MISSING":
        return "REMOVED"
    old_rank, new_rank = DECISION_RANK.get(old, -1), DECISION_RANK.get(new, -1)
    if new_rank > old_rank:
        return "MORE_RESTRICTIVE"
    if new_rank < old_rank:
        return "LESS_RESTRICTIVE"
    return "CHANGED"


def write_csv(path: Path, records: list[dict[str, Any]]) -> None:
    if not records:
        path.write_text("", encoding="utf-8")
        return
    fields = list(records[0].keys())
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in records:
            normalized = {}
            for key, value in row.items():
                if isinstance(value, (list, dict)):
                    normalized[key] = json.dumps(value, ensure_ascii=False)
                else:
                    normalized[key] = value
            writer.writerow(normalized)


def markdown_report(scenarios: list[dict[str, Any]], events: list[dict[str, Any]],
                    controls: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    lines = [
        "# CONFUSED_DEPUTY v6.30 vs v6.31 Frozen Comparison",
        "",
        "This report compares existing frozen evaluator outputs. It does not rerun the model or SDK.",
        "",
        "## Summary",
        "",
        f"- Scenario rows compared: {summary['scenario_rows_compared']}",
        f"- Scenario final decisions changed: {summary['scenario_final_changes']}",
        f"- Email events compared/aligned: {summary['email_event_rows']}",
        f"- Email event final decisions changed: {summary['event_final_changes']}",
        f"- Control-level decisions changed: {summary['control_changes']}",
        f"- High-confidence event alignments: {summary['alignment_counts'].get('HIGH', 0)}",
        f"- Medium-confidence event alignments: {summary['alignment_counts'].get('MEDIUM', 0)}",
        f"- Low-confidence event alignments: {summary['alignment_counts'].get('LOW', 0)}",
        f"- Unpaired events: {summary['alignment_counts'].get('UNPAIRED', 0)}",
        "",
        "## Scenario-level changes",
        "",
        "| Case | Guardrail | Events 6.30 | Events 6.31 | Final 6.30 | Final 6.31 | Changed |",
        "|---|---|---:|---:|---|---|---|",
    ]
    for r in scenarios:
        if r["final_changed"] or r["event_count_changed"]:
            lines.append(
                f"| {r['case_id']} | {r['guardrail']} | {r['email_event_count_v6_30']} | "
                f"{r['email_event_count_v6_31']} | {r['final_v6_30']} | {r['final_v6_31']} | "
                f"{str(r['final_changed']).lower()} |"
            )

    lines += [
        "",
        "## Event-level changes",
        "",
        "| Case | Guardrail | Email ordinal | Alignment | Turn 6.31 | Final 6.30 | Final 6.31 | Changed controls |",
        "|---|---|---:|---|---:|---|---|---|",
    ]
    for r in events:
        if r["final_changed"] or r["controls_changed"] or r["explanations_added"] or r["explanations_removed"]:
            controls_text = ", ".join(r["controls_changed"]) or "reason-only"
            lines.append(
                f"| {r['case_id']} | {r['guardrail']} | {r['email_ordinal']} | "
                f"{r['alignment_confidence']} | {r['event_turn_v6_31']} | {r['final_v6_30']} | "
                f"{r['final_v6_31']} | {controls_text} |"
            )

    lines += [
        "",
        "## Control-level deltas",
        "",
        "| Case | Guardrail | Email ordinal | Control | v6.30 | v6.31 | Direction |",
        "|---|---|---:|---|---|---|---|",
    ]
    for r in controls:
        if r["changed"]:
            lines.append(
                f"| {r['case_id']} | {r['guardrail']} | {r['email_ordinal']} | {r['control']} | "
                f"{r['v6_30']} | {r['v6_31']} | {r['direction']} |"
            )

    lines += [
        "",
        "## Interpretation notes",
        "",
        "- Scenario-level DENY is deny-dominant: if any email event is denied, the scenario remains DENY.",
        "- Event ordinal is used for alignment because raw tool indices can shift when non-email tools appear.",
        "- LOW or UNPAIRED alignment must be reviewed manually before making causal claims.",
        "- A changed control reason can demonstrate evaluator improvement even when the final decision is unchanged.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--v6-30", default=r"C:\x_ai_logs\cd_policy_eval\policy_eval_rows.json")
    parser.add_argument("--v6-31", default=r"C:\x_ai_logs\cd_policy_eval_v6_31\policy_eval_rows_v6_31.json")
    parser.add_argument("--output-dir", default=r"C:\x_ai_logs\cd_policy_compare_v6_30_v6_31")
    args = parser.parse_args()

    old_path, new_path = Path(args.v6_30).resolve(), Path(args.v6_31).resolve()
    out = Path(args.output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    old_rows, new_rows = load_rows(old_path), load_rows(new_path)
    scenarios = compare_scenarios(old_rows, new_rows)
    events, controls = compare_events(old_rows, new_rows)

    alignment_counts = Counter(e["alignment_confidence"] for e in events)
    summary = {
        "experiment": "CONFUSED_DEPUTY_FROZEN_COMPARE_V6_30_V6_31",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "v6_30_file": str(old_path),
        "v6_31_file": str(new_path),
        "scenario_rows_compared": len(scenarios),
        "scenario_final_changes": sum(r["final_changed"] for r in scenarios),
        "scenario_event_count_changes": sum(r["event_count_changed"] for r in scenarios),
        "email_event_rows": len(events),
        "event_final_changes": sum(r["final_changed"] for r in events),
        "event_argument_changes": sum(not r["arguments_equal"] for r in events),
        "control_rows": len(controls),
        "control_changes": sum(r["changed"] for r in controls),
        "control_change_counts": dict(Counter(r["control"] for r in controls if r["changed"])),
        "direction_counts": dict(Counter(r["direction"] for r in controls if r["changed"])),
        "alignment_counts": dict(alignment_counts),
        "important_note": (
            "Scenario final-decision equality does not imply evaluator equivalence. "
            "Review event and control deltas for multi-email traces."
        ),
    }

    artifacts = {
        "summary.json": summary,
        "scenario_comparison.json": scenarios,
        "event_comparison.json": events,
        "control_comparison.json": controls,
    }
    for name, data in artifacts.items():
        (out / name).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    write_csv(out / "scenario_comparison.csv", scenarios)
    write_csv(out / "event_comparison.csv", events)
    write_csv(out / "control_comparison.csv", controls)
    report = markdown_report(scenarios, events, controls, summary)
    (out / "comparison_report.md").write_text(report, encoding="utf-8")

    print(json.dumps(summary, indent=2))
    print("Saved comparison artifacts to:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
