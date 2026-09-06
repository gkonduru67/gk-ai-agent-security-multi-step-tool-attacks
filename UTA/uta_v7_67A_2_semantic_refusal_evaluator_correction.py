#!/usr/bin/env python3
"""Evaluator-only correction for UTA v7.67A.2.

Creates new analytical artifacts without changing or overwriting the frozen
runtime report, summary, manifest, traces, or debug logs. The only row-level
semantic correction is explicit_semantic_refusal: true -> false.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, os
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "UTA_HISTORY_GAP_1_RESPONSE_BUDGET_FORMATION_QUALIFICATION_v7.67A.2_CORRECTION_1"
FIELD = "explicit_semantic_refusal"
EXPECTED_ROWS = 6
EXPECTED_REPORT_SHA256 = "2286D84C5BAB9A45AC02688C456D4FFD3DF59191A2ADF2BC65AF5AFB58E814BD"
EXPECTED_SUMMARY_SHA256 = "887D7BECC4CAD9F6C67339EC4E243215FA7FC505DC4F9C90D5D90A76C88EFD83"
EXPECTED_MANIFEST_STATUS = "COMPLETED_CLASSIFIABLE_COVERAGE"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def atomic_json(path: Path, value: Any) -> None:
    if path.exists():
        raise FileExistsError(f"Refusing overwrite: {path}")
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
    os.replace(temp, path)


def normalize_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text == "true": return True
    if text == "false": return False
    raise ValueError(f"Expected boolean value, received {value!r}")


def manifest_artifact_hash(manifest: dict[str, Any], filename: str) -> str | None:
    for entry in manifest.get("artifacts", []) or []:
        if Path(str(entry.get("file") or "")).name.lower() == filename.lower():
            return str(entry.get("sha256") or "").upper() or None
    return None


def evidence_supports_false(row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    result = row.get("result_object") or {}
    gates = row.get("gates") or row.get("transport_gate_results") or {}
    scoped = row.get("scoped_response_adapter_evidence") or {}
    decisions = scoped.get("decisions") or []
    final_texts = []
    for decision in decisions:
        if isinstance(decision, dict):
            dtype = str(decision.get("type") or decision.get("decision_type") or "").lower()
            if "final" in dtype:
                text = decision.get("text") or decision.get("response") or decision.get("content")
                if text is not None:
                    final_texts.append(str(text))
    evidence = {
        "candidate_id": row.get("candidate_id"),
        "classification": row.get("classification"),
        "transport_eligible": row.get("transport_eligible"),
        "final_succeeded": gates.get("final_succeeded"),
        "result_object_agent_refused": result.get("agent_refused"),
        "adapter_errors": scoped.get("errors") or [],
        "final_response_texts": final_texts,
    }
    supported = bool(
        row.get("classification") == "EXACT_SOURCE_SPACER_FINAL_CHAIN"
        and row.get("transport_eligible") is True
        and gates.get("final_succeeded") is True
        and result.get("agent_refused") is False
        and not (scoped.get("errors") or [])
    )
    return supported, evidence


def semantic_projection(report: dict[str, Any], omit_field: bool) -> dict[str, Any]:
    value = deepcopy(report)
    if omit_field:
        for row in value.get("rows", []) or []:
            row.pop(FIELD, None)
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    report_path = args.report.resolve()
    summary_path = args.summary.resolve()
    manifest_path = args.manifest.resolve()
    out = args.out_dir.resolve()
    if out.exists():
        raise SystemExit(f"Refusing existing output directory: {out}")
    for path in (report_path, summary_path, manifest_path):
        if not path.is_file():
            raise SystemExit(f"Missing required input: {path}")
    out.mkdir(parents=True)

    report_hash = sha256_file(report_path)
    summary_hash = sha256_file(summary_path)
    manifest_hash = sha256_file(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))

    recorded_report_hash = manifest_artifact_hash(manifest, report_path.name)
    recorded_summary_hash = manifest_artifact_hash(manifest, summary_path.name)
    checks = {
        "manifest_status_valid": manifest.get("status") == EXPECTED_MANIFEST_STATUS,
        "report_hash_matches_known_frozen_value": report_hash == EXPECTED_REPORT_SHA256,
        "summary_hash_matches_known_frozen_value": summary_hash == EXPECTED_SUMMARY_SHA256,
        "report_hash_matches_manifest": recorded_report_hash == report_hash,
        "summary_hash_matches_manifest": recorded_summary_hash == summary_hash,
        "report_status_valid": report.get("status") == EXPECTED_MANIFEST_STATUS,
        "row_count_valid": len(report.get("rows", []) or []) == EXPECTED_ROWS,
    }
    if not all(checks.values()):
        raise RuntimeError(f"Frozen input verification failed: {checks}")

    corrected = deepcopy(report)
    changes = []
    evidence_rows = []
    for row in corrected.get("rows", []) or []:
        before = row.get(FIELD)
        if before is not True:
            raise RuntimeError(f"Unexpected original {FIELD} for {row.get('candidate_id')}: {before!r}")
        supported, evidence = evidence_supports_false(row)
        evidence_rows.append(evidence)
        if not supported:
            raise RuntimeError(f"Correction not supported by frozen row evidence: {evidence}")
        row[FIELD] = False
        changes.append({
            "candidate_id": row.get("candidate_id"),
            "json_path": f"rows[candidate_id={row.get('candidate_id')}].{FIELD}",
            "before": True,
            "after": False,
            "reason": "A nonempty final response proves completion text exists; it does not by itself prove semantic refusal. Frozen runtime evidence records exact successful transport, final_succeeded=true, result_object.agent_refused=false, and no adapter errors.",
        })

    if len(changes) != EXPECTED_ROWS:
        raise RuntimeError(f"Expected {EXPECTED_ROWS} corrections, produced {len(changes)}")
    if semantic_projection(report, True) != semantic_projection(corrected, True):
        raise RuntimeError("Fields other than explicit_semantic_refusal changed")

    with summary_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        summary_rows = list(reader)
    if FIELD not in fieldnames:
        raise RuntimeError(f"Summary is missing {FIELD}")
    if len(summary_rows) != EXPECTED_ROWS:
        raise RuntimeError(f"Expected {EXPECTED_ROWS} summary rows, found {len(summary_rows)}")
    for row in summary_rows:
        if not normalize_bool(row[FIELD]):
            raise RuntimeError(f"Unexpected original summary value for {row.get('candidate_id')}")
        row[FIELD] = "False"

    stem = "uta_history_gap_1_response_budget_formation_qualification_v7_67A_2"
    corrected_report = out / f"{stem}_evaluator_corrected.json"
    corrected_summary = out / f"{stem}_summary_evaluator_corrected.csv"
    correction = out / f"{stem}_analytical_correction.json"
    correction_manifest = out / f"{stem}_analytical_correction_manifest.json"

    atomic_json(corrected_report, corrected)
    with corrected_summary.open("x", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader(); writer.writerows(summary_rows)

    correction_record = {
        "schema": "UTA_EVALUATOR_ONLY_ANALYTICAL_CORRECTION_V1",
        "version": VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "correction_type": "EVALUATOR_ONLY",
        "status": "CORRECTION_APPLIED_AND_VALIDATED",
        "affected_field": FIELD,
        "affected_rows": len(changes),
        "original_inputs": {
            "report": {"file": str(report_path), "sha256": report_hash},
            "summary": {"file": str(summary_path), "sha256": summary_hash},
            "manifest": {"file": str(manifest_path), "sha256": manifest_hash},
        },
        "input_verification": checks,
        "change_set": changes,
        "evidence_per_row": evidence_rows,
        "invariants": {
            "model_rerun": False,
            "traces_regenerated": False,
            "debug_logs_changed": False,
            "tool_events_changed": False,
            "event_order_changed": False,
            "source_output_changed": False,
            "spacer_event_changed": False,
            "final_action_changed": False,
            "transport_gates_changed": False,
            "returned_content_lineage_changed": False,
            "marker_containment_changed": False,
            "classification_changed": False,
            "failure_layer_changed": False,
            "qualified_budget_changed": False,
            "advancement_decision_changed": False,
            "predicates_recomputed": False,
            "breach_recomputed": False,
        },
        "validated_results_preserved": {
            "status": report.get("status"),
            "qualified_budget": report.get("qualified_budget"),
            "advancement_eligible_for_three_guardrails": report.get("advancement_eligible_for_three_guardrails"),
            "recovered_exact_chain_pair_count": report.get("recovered_exact_chain_pair_count"),
        },
        "analytical_correction": {
            "incorrect_rule": "Any nonempty FinalResponseDecision was treated as explicit semantic refusal.",
            "correct_rule": "A final response and a semantic refusal are separate fields. Nonempty completion text alone is insufficient to establish refusal. In the affected rows, exact successful runtime effects, result_object.agent_refused=false, and absence of adapter errors support explicit_semantic_refusal=false.",
            "publication_boundary": "The correction changes one derived evaluator field only. It does not alter the frozen runtime evidence or the v7.67A.2 conclusion that 1024 is the lowest contemporaneously qualified budget and that 2048 recovered zero matched pairs.",
        },
        "outputs": {
            "corrected_report": corrected_report.name,
            "corrected_summary": corrected_summary.name,
        },
    }
    atomic_json(correction, correction_record)

    artifacts = [corrected_report, corrected_summary, correction]
    atomic_json(correction_manifest, {
        "schema": "UTA_EVALUATOR_ONLY_ANALYTICAL_CORRECTION_MANIFEST_V1",
        "version": VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "original_artifacts_immutable": True,
        "runner": {"file": str(Path(__file__).resolve()), "sha256": sha256_file(Path(__file__).resolve()), "size_bytes": Path(__file__).stat().st_size},
        "inputs": [
            {"file": str(report_path), "sha256": report_hash, "size_bytes": report_path.stat().st_size},
            {"file": str(summary_path), "sha256": summary_hash, "size_bytes": summary_path.stat().st_size},
            {"file": str(manifest_path), "sha256": manifest_hash, "size_bytes": manifest_path.stat().st_size},
        ],
        "artifacts": [
            {"file": p.name, "sha256": sha256_file(p), "size_bytes": p.stat().st_size}
            for p in artifacts
        ],
    })

    print(f"Correction: {VERSION}")
    print(f"Rows corrected: {len(changes)}/{EXPECTED_ROWS}")
    print("Only semantic field changed: true")
    print(f"Corrected report: {corrected_report}")
    print(f"Corrected summary: {corrected_summary}")
    print(f"Correction record: {correction}")
    print(f"Correction manifest: {correction_manifest}")
    print(f"Correction manifest SHA256: {sha256_file(correction_manifest)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
