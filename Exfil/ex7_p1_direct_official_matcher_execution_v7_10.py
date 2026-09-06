#!/usr/bin/env python3
"""EX7 P1 direct deterministic execution of the official public matcher.

Unit under test: payload_exfiltrates_secret from a SHA-256-bound predicates.py.
Executes only scheduled rows from the frozen P0B R2 control matrix. It does not
use GPT-OSS, guardrails, Sandbox, Gym, tools, SDK fixtures, effects, full
predicates, breach evaluation, or real runtime lineage.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import sys
import time
import traceback
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX7_P1_DIRECT_OFFICIAL_MATCHER_EXECUTION_v7.10"
EXPECTED_PARENT_MANIFEST_SHA256 = "A348D8A3E39DB6B027BD01D1B745909909CB6F8502440357A65BED292EA44053"
EXPECTED_PARENT_STATUS = "EX7_P0B_DETERMINISTIC_CONTROL_FIXTURE_AND_EXPECTATION_FREEZE_COMPLETE"
EXPECTED_MATRIX_SHA256 = "2169E21D01177D85BFAC2ABA056703B82C53E08768A76A15C741EB3E91F675C5"
EXPECTED_PREDICATES_SHA256 = "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
EXPECTED_ROWS = 17
EXPECTED_SCHEDULED = 15
EXPECTED_WITHHELD = 2
TARGET_FUNCTION = "payload_exfiltrates_secret"
REQUIRED_PARENT_ARTIFACTS = {
    "ex7_v7_00B_parent_verification.csv",
    "ex7_v7_00B_scope_aware_dependency_inventory.csv",
    "ex7_v7_00B_authoritative_global_dependencies.json",
    "ex7_v7_00B_concrete_control_matrix.csv",
    "ex7_v7_00B_fixture_preflight.csv",
    "ex7_v7_00B_execution_schedule.csv",
    "ex7_v7_00B_claim_boundary.json",
    "ex7_v7_00B_result.json",
    "ex7_v7_00B_binding.json",
    "ex7_p0b_deterministic_control_fixture_freeze_v7_00B_R2.py",
    "predicates.py",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest().upper()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest().upper()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def parse_bool(value: str) -> bool | None:
    text = (value or "").strip().lower()
    if text == "true":
        return True
    if text == "false":
        return False
    if text == "":
        return None
    raise ValueError(f"Invalid Boolean field: {value!r}")


def index_manifest(path: Path) -> dict[str, dict[str, str]]:
    rows = load_csv(path)
    required = {"artifact", "role", "size_bytes", "sha256", "source_path"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError(f"Parent manifest requires columns: {sorted(required)}")
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        name = (row.get("artifact") or "").strip()
        if name in indexed:
            prior = indexed[name]
            if any((prior.get(field) or "").strip() != (row.get(field) or "").strip() for field in ("size_bytes", "sha256", "source_path")):
                raise ValueError(f"Conflicting duplicate parent artifact: {name}")
            continue
        indexed[name] = row
    missing = sorted(REQUIRED_PARENT_ARTIFACTS - set(indexed))
    if missing:
        raise ValueError(f"Missing required P0B artifacts: {missing}")
    return indexed


def verify_manifest_row(row: dict[str, str]) -> dict[str, Any]:
    path = Path(row["source_path"])
    exists = path.is_file()
    size = path.stat().st_size if exists else None
    observed = sha256_file(path) if exists else None
    expected_size = int(row["size_bytes"])
    expected_sha = row["sha256"].upper()
    passed = exists and size == expected_size and observed == expected_sha
    return {
        "artifact": row["artifact"], "path": str(path), "exists": exists,
        "expected_size_bytes": expected_size, "observed_size_bytes": size,
        "size_match": exists and size == expected_size,
        "expected_sha256": expected_sha, "observed_sha256": observed,
        "sha256_match": exists and observed == expected_sha, "passed": passed,
    }


def import_public_matcher(source: Path):
    spec = importlib.util.spec_from_file_location("_ex7_official_predicates_v710", source)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot create module specification for {source}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    matcher = getattr(module, TARGET_FUNCTION, None)
    if not callable(matcher):
        raise TypeError(f"{TARGET_FUNCTION} is not callable in {source}")
    return matcher


def main() -> int:
    parser = argparse.ArgumentParser(description=VERSION)
    parser.add_argument("--v7-00b-manifest", required=True)
    parser.add_argument("--v7-00b-binding", required=True)
    parser.add_argument("--predicates-source", required=True)
    parser.add_argument("--out-root", required=True)
    args = parser.parse_args()

    runner = Path(__file__).resolve()
    parent_manifest = Path(args.v7_00b_manifest)
    parent_binding = Path(args.v7_00b_binding)
    predicates = Path(args.predicates_source).resolve()
    out = Path(args.out_root)

    if out.exists():
        raise FileExistsError(f"Refusing to overwrite existing output directory: {out}")
    for path in (runner, parent_manifest, parent_binding, predicates):
        if not path.is_file():
            raise FileNotFoundError(path)
    if sha256_file(parent_manifest) != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("P0B manifest identity mismatch")
    binding = load_json(parent_binding)
    if binding.get("manifest_sha256") != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("P0B external-binding manifest mismatch")
    if binding.get("status") != EXPECTED_PARENT_STATUS:
        raise ValueError("P0B parent status mismatch")
    if binding.get("control_matrix_sha256") != EXPECTED_MATRIX_SHA256:
        raise ValueError("P0B external-binding control matrix mismatch")
    if binding.get("predicates_sha256") != EXPECTED_PREDICATES_SHA256:
        raise ValueError("P0B external-binding predicates mismatch")
    if sha256_file(predicates) != EXPECTED_PREDICATES_SHA256:
        raise ValueError("predicates.py identity mismatch")

    indexed = index_manifest(parent_manifest)
    checks = [verify_manifest_row(indexed[name]) for name in sorted(REQUIRED_PARENT_ARTIFACTS)]
    failures = [row for row in checks if not row["passed"]]
    if failures:
        raise ValueError("P0B parent verification failed: " + ", ".join(row["artifact"] for row in failures))

    matrix_path = Path(indexed["ex7_v7_00B_concrete_control_matrix.csv"]["source_path"])
    preflight_path = Path(indexed["ex7_v7_00B_fixture_preflight.csv"]["source_path"])
    schedule_path = Path(indexed["ex7_v7_00B_execution_schedule.csv"]["source_path"])
    if sha256_file(matrix_path) != EXPECTED_MATRIX_SHA256:
        raise ValueError("Concrete control matrix identity mismatch")
    matrix = load_csv(matrix_path)
    preflight = load_csv(preflight_path)
    schedule = load_csv(schedule_path)
    if len(matrix) != EXPECTED_ROWS or len(preflight) != EXPECTED_ROWS or len(schedule) != EXPECTED_ROWS:
        raise ValueError("Expected 17 rows in matrix, preflight, and schedule")

    matrix_ids = [row["control_id"] for row in matrix]
    if len(set(matrix_ids)) != EXPECTED_ROWS:
        raise ValueError("Control IDs are not unique")
    if set(matrix_ids) != {row["control_id"] for row in preflight} or set(matrix_ids) != {row["control_id"] for row in schedule}:
        raise ValueError("Matrix, preflight, and schedule control populations differ")
    scheduled = [row for row in matrix if row["schedule_status"] == "SCHEDULED"]
    withheld = [row for row in matrix if row["schedule_status"] != "SCHEDULED"]
    if len(scheduled) != EXPECTED_SCHEDULED or len(withheld) != EXPECTED_WITHHELD:
        raise ValueError("Expected 15 scheduled and 2 withheld controls")
    preflight_index = {row["control_id"]: row for row in preflight}
    schedule_index = {row["control_id"]: row for row in schedule}
    for row in scheduled:
        cid = row["control_id"]
        if preflight_index[cid]["fixture_preconditions_pass"].strip().lower() != "true":
            raise ValueError(f"Scheduled fixture preflight is not true: {cid}")
        if schedule_index[cid]["schedule_status"] != "SCHEDULED":
            raise ValueError(f"Schedule mismatch: {cid}")
    for row in withheld:
        cid = row["control_id"]
        if schedule_index[cid]["schedule_status"] != "WITHHELD_UNSUPPORTED_BY_SOURCE_CONTRACT":
            raise ValueError(f"Withheld schedule mismatch: {cid}")

    # Validate every serialized input before importing the matcher.
    deserialized: dict[str, tuple[Any, list[Any] | tuple[Any, ...] | set[Any]]] = {}
    for row in scheduled:
        cid = row["control_id"]
        payload = json.loads(row["payload_json"])
        read_secrets = json.loads(row["read_secrets_json"])
        if sha256_text(canonical_json(payload)) != row["payload_sha256"]:
            raise ValueError(f"Payload hash mismatch after deserialization: {cid}")
        if sha256_text(canonical_json(read_secrets)) != row["read_secrets_sha256"]:
            raise ValueError(f"read_secrets hash mismatch after deserialization: {cid}")
        if not isinstance(read_secrets, list):
            raise TypeError(f"read_secrets must deserialize to list: {cid}")
        if cid == "EX7A-C005" and not isinstance(payload, dict):
            raise TypeError("EX7A-C005 must deserialize to a mapping")
        deserialized[cid] = (payload, read_secrets)

    out.mkdir(parents=True)
    paths = {
        "parent": out / "ex7_v7_10_parent_verification.csv",
        "preflight": out / "ex7_v7_10_execution_preflight.json",
        "raw": out / "ex7_v7_10_raw_results.jsonl",
        "canonical": out / "ex7_v7_10_canonical_results.csv",
        "summary": out / "ex7_v7_10_summary.json",
        "result": out / "ex7_v7_10_result.json",
        "binding": out / "ex7_v7_10_binding.json",
        "manifest": out / "ex7_v7_10_manifest.csv",
        "external": out / "ex7_v7_10_manifest_external_binding.json",
    }
    write_csv(paths["parent"], checks, ["artifact","path","exists","expected_size_bytes","observed_size_bytes","size_match","expected_sha256","observed_sha256","sha256_match","passed"])
    preflight_record = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "version": VERSION,
        "parent_manifest_sha256": sha256_file(parent_manifest),
        "control_matrix_sha256": sha256_file(matrix_path),
        "predicates_sha256": sha256_file(predicates),
        "runner_sha256": sha256_file(runner),
        "matrix_rows": len(matrix), "scheduled_rows": len(scheduled), "withheld_rows": len(withheld),
        "scheduled_preconditions_pass": True,
        "scheduled_input_hashes_revalidated": True,
        "C005_runtime_type": type(deserialized["EX7A-C005"][0]).__name__,
        "matcher_imported_after_all_identity_and_input_gates": True,
        "model": False, "guardrail": False, "sandbox": False, "gym": False,
        "tools": False, "effects": False, "full_predicates": False, "breach": False,
    }
    write_json(paths["preflight"], preflight_record)

    try:
        matcher = import_public_matcher(predicates)
    except Exception:
        preflight_record["matcher_import_status"] = "FAILED"
        preflight_record["matcher_import_traceback"] = traceback.format_exc()
        write_json(paths["preflight"], preflight_record)
        raise

    raw_rows: list[dict[str, Any]] = []
    for row in matrix:
        cid = row["control_id"]
        base = {
            "experiment_version": VERSION,
            "control_id": cid, "family": row["family"], "transformation": row["transformation"],
            "schedule_status": row["schedule_status"],
            "predicates_source_sha256": EXPECTED_PREDICATES_SHA256,
            "control_matrix_sha256": EXPECTED_MATRIX_SHA256,
            "payload_json": row["payload_json"], "payload_sha256": row["payload_sha256"],
            "read_secrets_json": row["read_secrets_json"], "read_secrets_sha256": row["read_secrets_sha256"],
            "expected_match": parse_bool(row["expected_match"]),
            "fixture_preconditions_pass": row["fixture_preconditions_pass"].strip().lower() == "true",
            "matcher_layer_only": True, "real_lineage_claim": False, "effect_claim": False,
            "predicate_claim": False, "breach_claim": False, "guardrail_claim": False,
            "superiority_claim": False, "hosted_parity_claim": False,
        }
        if row["schedule_status"] != "SCHEDULED":
            raw_rows.append({**base,
                "payload_runtime_type": None, "read_secrets_runtime_type": None,
                "invocation_status": "NOT_EXECUTED_WITHHELD", "observed_match": None,
                "observed_return_type": None, "exception_type": None,
                "exception_message_raw": None, "exception_message_sha256": None,
                "exception_traceback_raw": None, "expectation_match": None,
                "execution_duration_ns": None, "matcher_call_count": 0,
            })
            continue
        payload, read_secrets = deserialized[cid]
        start = time.perf_counter_ns()
        observed = None
        exception_type = exception_message = exception_traceback = None
        try:
            returned = matcher(payload, read_secrets=read_secrets)
            duration = time.perf_counter_ns() - start
            observed = returned if isinstance(returned, bool) else None
            status = "EXECUTED_BOOLEAN_RETURNED" if isinstance(returned, bool) else "EXECUTED_INVALID_RETURN_TYPE"
            return_type = type(returned).__name__
        except Exception as exc:
            duration = time.perf_counter_ns() - start
            status = "EXECUTED_EXCEPTION_RAISED"
            return_type = None
            exception_type = type(exc).__name__
            exception_message = str(exc)
            exception_traceback = traceback.format_exc()
        raw_rows.append({**base,
            "payload_runtime_type": type(payload).__name__,
            "read_secrets_runtime_type": type(read_secrets).__name__,
            "invocation_status": status, "observed_match": observed,
            "observed_return_type": return_type, "exception_type": exception_type,
            "exception_message_raw": exception_message,
            "exception_message_sha256": sha256_text(exception_message) if exception_message is not None else None,
            "exception_traceback_raw": exception_traceback,
            "expectation_match": observed == base["expected_match"] if status == "EXECUTED_BOOLEAN_RETURNED" else False,
            "execution_duration_ns": duration, "matcher_call_count": 1,
        })

    write_jsonl(paths["raw"], raw_rows)
    canonical_fields = [
        "experiment_version","control_id","family","transformation","schedule_status","predicates_source_sha256","control_matrix_sha256",
        "payload_json","payload_sha256","payload_runtime_type","read_secrets_json","read_secrets_sha256","read_secrets_runtime_type",
        "expected_match","fixture_preconditions_pass","invocation_status","observed_match","observed_return_type","exception_type",
        "exception_message_sha256","expectation_match","execution_duration_ns","matcher_call_count","matcher_layer_only","real_lineage_claim",
        "effect_claim","predicate_claim","breach_claim","guardrail_claim","superiority_claim","hosted_parity_claim",
    ]
    write_csv(paths["canonical"], raw_rows, canonical_fields)

    executed = [row for row in raw_rows if row["schedule_status"] == "SCHEDULED"]
    withheld_results = [row for row in raw_rows if row["schedule_status"] != "SCHEDULED"]
    status_counts = Counter(row["invocation_status"] for row in raw_rows)
    observed_counts = Counter(str(row["observed_match"]) for row in executed if row["observed_match"] is not None)
    agreement_count = sum(row["expectation_match"] is True for row in executed)
    mismatch_ids = [row["control_id"] for row in executed if row["expectation_match"] is not True]
    summary = {
        "matrix_rows": len(raw_rows), "scheduled_rows": len(executed), "withheld_rows": len(withheld_results),
        "matcher_call_count": sum(row["matcher_call_count"] for row in raw_rows),
        "invocation_status_counts": dict(status_counts), "observed_boolean_counts": dict(observed_counts),
        "expectation_agreement_count": agreement_count,
        "expectation_nonagreement_count": len(executed) - agreement_count,
        "nonagreement_control_ids": mismatch_ids,
        "claim_boundary": "SYNTHETIC_OFFICIAL_MATCHER_UNIT_RESULTS_ONLY_NO_LINEAGE_EFFECT_PREDICATE_BREACH_OR_DEFENSE_CLAIM",
    }
    write_json(paths["summary"], summary)
    result = {
        "version": VERSION, "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "EX7_P1_DIRECT_OFFICIAL_MATCHER_EXECUTION_COMPLETE",
        "classification": "OFFICIAL_PUBLIC_MATCHER_SYNTHETIC_CONTROL_RESULTS_FROZEN_SECURITY_EFFECT_CLAIMS_WITHHELD",
        "execution_type": "DIRECT_PUBLIC_MATCHER_ONLY",
        "required_parent_artifacts_verified": len(checks),
        "matrix_rows": len(raw_rows), "scheduled_rows": len(executed), "withheld_rows": len(withheld_results),
        "matcher_call_count": summary["matcher_call_count"],
        "expectation_agreement_count": agreement_count,
        "expectation_nonagreement_count": len(executed) - agreement_count,
        "nonagreement_control_ids": mismatch_ids,
        "predicates_sha256": EXPECTED_PREDICATES_SHA256,
        "control_matrix_sha256": EXPECTED_MATRIX_SHA256,
        "runner_sha256": sha256_file(runner),
        "matcher_executed": True, "controls_executed": True,
        "model_used": False, "guardrail_used": False, "sandbox_used": False, "gym_used": False,
        "tools_executed": False, "effects_observed": False,
        "full_predicates_recomputed": False, "breach_recomputed": False,
        "harness_trick": "NOT_DEMONSTRATED",
        "robust_finding": "OFFICIAL_MATCHER_BEHAVIOR_ESTABLISHED_FOR_FROZEN_SYNTHETIC_CONTROLS",
        "security_finding": "END_TO_END_SECURITY_EFFECT_NOT_ESTABLISHED",
        "real_lineage_claim": False, "superiority_claim": False, "hosted_parity_claim": False,
        "next_gate": "INDEPENDENT_P1_RESULT_QUALIFICATION_BEFORE_ANY_AGENT_OR_GUARDRAIL_PIPELINE_USE",
        "summary": summary,
    }
    write_json(paths["result"], result)
    bind = {
        "version": VERSION, "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "parent_manifest": {"path":str(parent_manifest),"size_bytes":parent_manifest.stat().st_size,"sha256":sha256_file(parent_manifest)},
        "parent_binding": {"path":str(parent_binding),"size_bytes":parent_binding.stat().st_size,"sha256":sha256_file(parent_binding)},
        "control_matrix": {"path":str(matrix_path),"size_bytes":matrix_path.stat().st_size,"sha256":sha256_file(matrix_path)},
        "predicates": {"path":str(predicates),"size_bytes":predicates.stat().st_size,"sha256":sha256_file(predicates)},
        "runner": {"path":str(runner),"size_bytes":runner.stat().st_size,"sha256":sha256_file(runner)},
        "verified_parent_artifacts": checks,
        "source_modified": False, "parent_artifacts_modified": False,
    }
    write_json(paths["binding"], bind)

    generated = ["parent","preflight","raw","canonical","summary","result","binding"]
    manifest_rows = [{"artifact":paths[key].name,"role":"DERIVED_EX7_P1_MATCHER_EXECUTION","size_bytes":paths[key].stat().st_size,"sha256":sha256_file(paths[key]),"source_path":str(paths[key])} for key in generated]
    for path, role in ((runner,"CURRENT_RUNNER"),(parent_manifest,"SOURCE_OR_PARENT"),(parent_binding,"SOURCE_OR_PARENT"),(matrix_path,"EXECUTED_CONTROL_MATRIX"),(predicates,"AUTHORITATIVE_MATCHER_SOURCE")):
        manifest_rows.append({"artifact":path.name,"role":role,"size_bytes":path.stat().st_size,"sha256":sha256_file(path),"source_path":str(path)})
    for row in checks:
        manifest_rows.append({"artifact":row["artifact"],"role":"VERIFIED_PARENT_EVIDENCE","size_bytes":row["observed_size_bytes"],"sha256":row["observed_sha256"],"source_path":row["path"]})
    write_csv(paths["manifest"], manifest_rows, ["artifact","role","size_bytes","sha256","source_path"])
    external = {
        "version": VERSION, "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "manifest_filename": paths["manifest"].name, "manifest_size_bytes": paths["manifest"].stat().st_size,
        "manifest_sha256": sha256_file(paths["manifest"]), "status": result["status"], "classification": result["classification"],
        "parent_v7_00B_manifest_sha256": EXPECTED_PARENT_MANIFEST_SHA256,
        "control_matrix_sha256": EXPECTED_MATRIX_SHA256, "predicates_sha256": EXPECTED_PREDICATES_SHA256,
        "runner_sha256": sha256_file(runner), "scheduled_rows": len(executed), "withheld_rows": len(withheld_results),
        "matcher_call_count": summary["matcher_call_count"],
    }
    write_json(paths["external"], external)
    print(json.dumps({
        "status": result["status"], "matrix_rows": len(raw_rows), "scheduled_rows": len(executed),
        "withheld_rows": len(withheld_results), "matcher_call_count": summary["matcher_call_count"],
        "expectation_agreement_count": agreement_count,
        "expectation_nonagreement_count": len(executed)-agreement_count,
        "nonagreement_control_ids": mismatch_ids,
        "runner_sha256": sha256_file(runner), "manifest_sha256": external["manifest_sha256"],
        "output_directory": str(out),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
