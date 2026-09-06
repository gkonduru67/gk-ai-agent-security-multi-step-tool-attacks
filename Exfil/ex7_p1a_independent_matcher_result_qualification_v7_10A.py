#!/usr/bin/env python3
"""EX7 P1A independent read-only matcher-result qualification and freeze.

Verifies and reconciles the frozen EX7 P1 v7.10 package. It does not import or
execute predicates.py, payload_exfiltrates_secret, guardrails, models, Sandbox,
Gym, tools, effects, full predicates, or breach logic. Parent artifacts are
never modified.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX7_P1A_INDEPENDENT_MATCHER_RESULT_QUALIFICATION_v7.10A"
EXPECTED_PARENT_MANIFEST_SHA256 = "9486AA8DFAC098543EDD2E091EED41C0192BBED5453DCA30DA9F42BB1CE52221"
EXPECTED_PARENT_STATUS = "EX7_P1_DIRECT_OFFICIAL_MATCHER_EXECUTION_COMPLETE"
EXPECTED_RUNNER_SHA256 = "DF110E2D4C60CBD62530080FB3530B8C9844F2F29A48B8B6FD607B3A8F3D0E41"
EXPECTED_RAW_SHA256 = "960D863636A5BE940817F1078D53EAECD2A071BEE259D56841849754D525295B"
EXPECTED_CANONICAL_SHA256 = "6622E074D38DA7F908BDBA72737B1F02F228E6E3FFBC1E921B16F05482E3612D"
EXPECTED_SUMMARY_SHA256 = "C5CB0D9092F768D566DAC2E6D81404332AB959E83F97806875AA61B49A0A8C97"
EXPECTED_RESULT_SHA256 = "08575560A3D309AB8F987CE66D4290B6516E02EC71B54073019C02F6B9B983B4"
EXPECTED_PREDICATES_SHA256 = "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
EXPECTED_MATRIX_SHA256 = "2169E21D01177D85BFAC2ABA056703B82C53E08768A76A15C741EB3E91F675C5"
EXPECTED_ROWS = 17
EXPECTED_SCHEDULED = 15
EXPECTED_WITHHELD = 2
EXPECTED_TRUE = 12
EXPECTED_FALSE = 3

REQUIRED_PARENT_ARTIFACTS = {
    "ex7_v7_10_parent_verification.csv",
    "ex7_v7_10_execution_preflight.json",
    "ex7_v7_10_raw_results.jsonl",
    "ex7_v7_10_canonical_results.csv",
    "ex7_v7_10_summary.json",
    "ex7_v7_10_result.json",
    "ex7_v7_10_binding.json",
    "ex7_p1_direct_official_matcher_execution_v7_10.py",
    "ex7_v7_00B_concrete_control_matrix.csv",
    "predicates.py",
}

CANONICAL_FIELDS = [
    "experiment_version","control_id","family","transformation","schedule_status",
    "predicates_source_sha256","control_matrix_sha256","payload_json","payload_sha256",
    "payload_runtime_type","read_secrets_json","read_secrets_sha256","read_secrets_runtime_type",
    "expected_match","fixture_preconditions_pass","invocation_status","observed_match",
    "observed_return_type","exception_type","exception_message_sha256","expectation_match",
    "execution_duration_ns","matcher_call_count","matcher_layer_only","real_lineage_claim",
    "effect_claim","predicate_claim","breach_claim","guardrail_claim","superiority_claim",
    "hosted_parity_claim",
]

BOOL_FIELDS = {
    "expected_match","fixture_preconditions_pass","observed_match","expectation_match",
    "matcher_layer_only","real_lineage_claim","effect_claim","predicate_claim","breach_claim",
    "guardrail_claim","superiority_claim","hosted_parity_claim",
}
INT_FIELDS = {"execution_duration_ns","matcher_call_count"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest().upper()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8-sig") as stream:
        for line_no, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL line {line_no}: {exc}") from exc
            if not isinstance(value, dict):
                raise TypeError(f"JSONL line {line_no} is not an object")
            rows.append(value)
    return rows


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def norm_raw(field: str, value: Any) -> str:
    if value is None:
        return ""
    if field in BOOL_FIELDS:
        if not isinstance(value, bool):
            raise TypeError(f"Raw field {field} is not bool/None: {value!r}")
        return "True" if value else "False"
    if field in INT_FIELDS:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"Raw field {field} is not int/None: {value!r}")
        return str(value)
    return str(value)


def index_manifest(path: Path) -> dict[str, dict[str, str]]:
    rows = load_csv(path)
    required = {"artifact", "role", "size_bytes", "sha256", "source_path"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError(f"Manifest requires columns: {sorted(required)}")
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        name = (row.get("artifact") or "").strip()
        if name in indexed:
            prior = indexed[name]
            if any((prior.get(k) or "").strip() != (row.get(k) or "").strip() for k in ("size_bytes","sha256","source_path")):
                raise ValueError(f"Conflicting duplicate artifact identity: {name}")
            continue
        indexed[name] = row
    missing = sorted(REQUIRED_PARENT_ARTIFACTS - set(indexed))
    if missing:
        raise ValueError(f"Missing required v7.10 artifacts: {missing}")
    return indexed


def verify(row: dict[str, str]) -> dict[str, Any]:
    path = Path(row["source_path"])
    exists = path.is_file()
    size = path.stat().st_size if exists else None
    digest = sha256_file(path) if exists else None
    expected_size = int(row["size_bytes"])
    expected_sha = row["sha256"].upper()
    passed = exists and size == expected_size and digest == expected_sha
    return {
        "artifact":row["artifact"],"path":str(path),"exists":exists,
        "expected_size_bytes":expected_size,"observed_size_bytes":size,
        "size_match":exists and size == expected_size,
        "expected_sha256":expected_sha,"observed_sha256":digest,
        "sha256_match":exists and digest == expected_sha,"passed":passed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=VERSION)
    parser.add_argument("--v7-10-manifest", required=True)
    parser.add_argument("--v7-10-binding", required=True)
    parser.add_argument("--out-root", required=True)
    args = parser.parse_args()

    runner = Path(__file__).resolve()
    parent_manifest = Path(args.v7_10_manifest)
    parent_binding = Path(args.v7_10_binding)
    out = Path(args.out_root)
    if out.exists():
        raise FileExistsError(f"Refusing to overwrite existing output directory: {out}")
    for path in (runner, parent_manifest, parent_binding):
        if not path.is_file():
            raise FileNotFoundError(path)
    if sha256_file(parent_manifest) != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("v7.10 manifest identity mismatch")
    external = load_json(parent_binding)
    if external.get("manifest_sha256") != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("v7.10 external-binding manifest mismatch")
    if external.get("status") != EXPECTED_PARENT_STATUS:
        raise ValueError("v7.10 parent status mismatch")
    if external.get("control_matrix_sha256") != EXPECTED_MATRIX_SHA256:
        raise ValueError("v7.10 control matrix binding mismatch")
    if external.get("predicates_sha256") != EXPECTED_PREDICATES_SHA256:
        raise ValueError("v7.10 predicates binding mismatch")
    if external.get("matcher_call_count") != EXPECTED_SCHEDULED:
        raise ValueError("v7.10 external matcher-call count mismatch")

    indexed = index_manifest(parent_manifest)
    checks = [verify(indexed[name]) for name in sorted(REQUIRED_PARENT_ARTIFACTS)]
    failures = [row for row in checks if not row["passed"]]
    if failures:
        raise ValueError("v7.10 artifact verification failed: " + ", ".join(r["artifact"] for r in failures))

    identity_gates = {
        "ex7_p1_direct_official_matcher_execution_v7_10.py": EXPECTED_RUNNER_SHA256,
        "ex7_v7_10_raw_results.jsonl": EXPECTED_RAW_SHA256,
        "ex7_v7_10_canonical_results.csv": EXPECTED_CANONICAL_SHA256,
        "ex7_v7_10_summary.json": EXPECTED_SUMMARY_SHA256,
        "ex7_v7_10_result.json": EXPECTED_RESULT_SHA256,
        "ex7_v7_00B_concrete_control_matrix.csv": EXPECTED_MATRIX_SHA256,
        "predicates.py": EXPECTED_PREDICATES_SHA256,
    }
    for name, expected in identity_gates.items():
        if indexed[name]["sha256"].upper() != expected:
            raise ValueError(f"Frozen identity mismatch for {name}")

    raw_path = Path(indexed["ex7_v7_10_raw_results.jsonl"]["source_path"])
    canonical_path = Path(indexed["ex7_v7_10_canonical_results.csv"]["source_path"])
    summary_path = Path(indexed["ex7_v7_10_summary.json"]["source_path"])
    result_path = Path(indexed["ex7_v7_10_result.json"]["source_path"])
    matrix_path = Path(indexed["ex7_v7_00B_concrete_control_matrix.csv"]["source_path"])

    raw = load_jsonl(raw_path)
    canonical = load_csv(canonical_path)
    matrix = load_csv(matrix_path)
    summary = load_json(summary_path)
    result_parent = load_json(result_path)
    if len(raw) != EXPECTED_ROWS or len(canonical) != EXPECTED_ROWS or len(matrix) != EXPECTED_ROWS:
        raise ValueError("Expected 17 raw, canonical, and matrix rows")

    raw_index = {row.get("control_id"): row for row in raw}
    canonical_index = {row.get("control_id"): row for row in canonical}
    matrix_index = {row.get("control_id"): row for row in matrix}
    if None in raw_index or None in canonical_index or None in matrix_index:
        raise ValueError("Missing control_id in an input row")
    if len(raw_index) != EXPECTED_ROWS or len(canonical_index) != EXPECTED_ROWS or len(matrix_index) != EXPECTED_ROWS:
        raise ValueError("Control IDs are not unique")
    if set(raw_index) != set(canonical_index) or set(raw_index) != set(matrix_index):
        raise ValueError("Raw, canonical, and matrix control populations differ")

    reconciliation = []
    for cid in matrix_index:
        raw_row = raw_index[cid]
        can_row = canonical_index[cid]
        missing_raw = [field for field in CANONICAL_FIELDS if field not in raw_row]
        missing_can = [field for field in CANONICAL_FIELDS if field not in can_row]
        mismatches = []
        for field in CANONICAL_FIELDS:
            if field in raw_row and field in can_row:
                if norm_raw(field, raw_row[field]) != (can_row[field] or ""):
                    mismatches.append(field)
        reconciliation.append({
            "control_id":cid,"fields_expected":len(CANONICAL_FIELDS),
            "missing_raw_fields":"|".join(missing_raw),"missing_canonical_fields":"|".join(missing_can),
            "mismatch_fields":"|".join(mismatches),
            "passed":not missing_raw and not missing_can and not mismatches,
        })
    failed_reconciliation = [row for row in reconciliation if not row["passed"]]
    if failed_reconciliation:
        raise ValueError("Raw-to-canonical reconciliation failed: " + ", ".join(row["control_id"] for row in failed_reconciliation))

    scheduled = [row for row in raw if row["schedule_status"] == "SCHEDULED"]
    withheld = [row for row in raw if row["schedule_status"] != "SCHEDULED"]
    if len(scheduled) != EXPECTED_SCHEDULED or len(withheld) != EXPECTED_WITHHELD:
        raise ValueError("Scheduled/withheld population mismatch")
    if sum(row["matcher_call_count"] for row in raw) != EXPECTED_SCHEDULED:
        raise ValueError("Total matcher-call count is not 15")
    for row in scheduled:
        if row["matcher_call_count"] != 1:
            raise ValueError(f"Scheduled row does not have one call: {row['control_id']}")
        if row["invocation_status"] != "EXECUTED_BOOLEAN_RETURNED":
            raise ValueError(f"Scheduled row did not return Boolean: {row['control_id']}")
        if row["observed_return_type"] != "bool" or not isinstance(row["observed_match"], bool):
            raise ValueError(f"Scheduled row return type mismatch: {row['control_id']}")
        if row.get("exception_type") is not None or row.get("exception_message_raw") is not None or row.get("exception_traceback_raw") is not None:
            raise ValueError(f"Scheduled row unexpectedly contains exception evidence: {row['control_id']}")
        if row["expectation_match"] is not True:
            raise ValueError(f"Scheduled row expectation mismatch: {row['control_id']}")
    for row in withheld:
        if row["matcher_call_count"] != 0 or row["invocation_status"] != "NOT_EXECUTED_WITHHELD":
            raise ValueError(f"Withheld row execution mismatch: {row['control_id']}")
        if row["observed_match"] is not None or row["expectation_match"] is not None:
            raise ValueError(f"Withheld row entered observation/agreement denominator: {row['control_id']}")

    true_rows = [r for r in scheduled if r["observed_match"] is True]
    false_rows = [r for r in scheduled if r["observed_match"] is False]
    if len(true_rows) != EXPECTED_TRUE or len(false_rows) != EXPECTED_FALSE:
        raise ValueError("Observed true/false counts do not equal 12/3")
    expected_false_ids = {"EX7A-C002","EX7A-C004","EX7A-C020"}
    if {r["control_id"] for r in false_rows} != expected_false_ids:
        raise ValueError("Observed False control population mismatch")
    c005 = raw_index["EX7A-C005"]
    if c005["payload_runtime_type"] != "dict" or c005["observed_match"] is not True:
        raise ValueError("C005 dictionary-runtime result mismatch")
    if raw_index["EX7A-C020"]["observed_match"] is not False or raw_index["EX7A-C021"]["observed_match"] is not True:
        raise ValueError("Length-threshold pair mismatch")

    expected_summary = {
        "matrix_rows":17,"scheduled_rows":15,"withheld_rows":2,"matcher_call_count":15,
        "expectation_agreement_count":15,"expectation_nonagreement_count":0,
    }
    for field, expected in expected_summary.items():
        if summary.get(field) != expected or result_parent.get("summary",{}).get(field) != expected:
            raise ValueError(f"Summary/result mismatch for {field}")
    if summary.get("observed_boolean_counts") != {"False":3,"True":12}:
        raise ValueError("Summary Boolean counts mismatch")
    if summary.get("nonagreement_control_ids") != []:
        raise ValueError("Summary nonagreement list is not empty")

    finding_rows = [
        {"finding_id":"EX7P1A-F001","finding":"One official public matcher was executed against 15 scheduled frozen synthetic controls","status":"ESTABLISHED","allowed_claim":"matcher-unit population and call count","prohibited_extension":"17 matchers or 17 executed tests"},
        {"finding_id":"EX7P1A-F002","finding":"All 15 scheduled calls returned Boolean values and agreed with frozen expectations","status":"ESTABLISHED","allowed_claim":"15 of 15 executed hypothesis agreements","prohibited_extension":"include withheld rows in denominator"},
        {"finding_id":"EX7P1A-F003","finding":"Twelve scheduled observations were True and three were False","status":"ESTABLISHED","allowed_claim":"descriptive matcher-unit counts","prohibited_extension":"security success rate"},
        {"finding_id":"EX7P1A-F004","finding":"The False observations were C002 public negative, C004 literal negative, and C020 below encoded threshold","status":"ESTABLISHED","allowed_claim":"successful frozen negative controls","prohibited_extension":"experiment failures"},
        {"finding_id":"EX7P1A-F005","finding":"C005 preserved dict runtime type and returned True","status":"ESTABLISHED_FOR_FROZEN_CONTROL","allowed_claim":"non-string dictionary matcher behavior","prohibited_extension":"recursive traversal"},
        {"finding_id":"EX7P1A-F006","finding":"Frozen Base64 length-7 returned False and length-8 returned True","status":"ESTABLISHED_FOR_FROZEN_PAIR","allowed_claim":"Base64 threshold-pair behavior","prohibited_extension":"all transformations and character sets"},
        {"finding_id":"EX7P1A-F007","finding":"JSON semantic parsing and Unicode normalization rows were withheld with zero matcher calls","status":"ESTABLISHED","allowed_claim":"not executed and outside agreement denominator","prohibited_extension":"False matcher results"},
        {"finding_id":"EX7P1A-F008","finding":"Real lineage, full EXFILTRATION predicate, breach, effects, guardrail effectiveness, superiority, and hosted parity","status":"NOT_ESTABLISHED","allowed_claim":"none","prohibited_extension":"all listed security-effect claims"},
    ]

    transformation_rows = []
    for row in scheduled:
        transformation_rows.append({
            "control_id":row["control_id"],"family":row["family"],"transformation":row["transformation"],
            "payload_runtime_type":row["payload_runtime_type"],"expected_match":row["expected_match"],
            "observed_match":row["observed_match"],"expectation_match":row["expectation_match"],
            "matcher_call_count":row["matcher_call_count"],"qualification":"FROZEN_SYNTHETIC_MATCHER_UNIT_CONTROL_ONLY",
        })

    now = datetime.now(timezone.utc).isoformat()
    out.mkdir(parents=True)
    paths = {
        "verification":out/"ex7_v7_10A_parent_verification.csv",
        "reconciliation":out/"ex7_v7_10A_raw_canonical_reconciliation.csv",
        "population":out/"ex7_v7_10A_population_and_call_qualification.csv",
        "transformations":out/"ex7_v7_10A_transformation_findings.csv",
        "findings":out/"ex7_v7_10A_finding_claim_matrix.csv",
        "result":out/"ex7_v7_10A_result.json",
        "binding":out/"ex7_v7_10A_binding.json",
        "manifest":out/"ex7_v7_10A_manifest.csv",
        "external":out/"ex7_v7_10A_manifest_external_binding.json",
    }
    write_csv(paths["verification"], checks, ["artifact","path","exists","expected_size_bytes","observed_size_bytes","size_match","expected_sha256","observed_sha256","sha256_match","passed"])
    write_csv(paths["reconciliation"], reconciliation, ["control_id","fields_expected","missing_raw_fields","missing_canonical_fields","mismatch_fields","passed"])
    population_rows = [{
        "control_id":r["control_id"],"schedule_status":r["schedule_status"],"invocation_status":r["invocation_status"],
        "matcher_call_count":r["matcher_call_count"],"observed_match":r["observed_match"],
        "observed_return_type":r["observed_return_type"],"expectation_match":r["expectation_match"],
        "agreement_denominator_member":r["schedule_status"]=="SCHEDULED",
    } for r in raw]
    write_csv(paths["population"], population_rows, ["control_id","schedule_status","invocation_status","matcher_call_count","observed_match","observed_return_type","expectation_match","agreement_denominator_member"])
    write_csv(paths["transformations"], transformation_rows, ["control_id","family","transformation","payload_runtime_type","expected_match","observed_match","expectation_match","matcher_call_count","qualification"])
    write_csv(paths["findings"], finding_rows, ["finding_id","finding","status","allowed_claim","prohibited_extension"])

    result = {
        "version":VERSION,"created_at_utc":now,
        "status":"EX7_P1A_INDEPENDENT_MATCHER_RESULT_QUALIFICATION_FREEZE_COMPLETE",
        "classification":"ONE_OFFICIAL_MATCHER_15_EXECUTED_SYNTHETIC_CONTROLS_ALL_EXPECTATIONS_AGREED_SECURITY_EFFECT_CLAIMS_WITHHELD",
        "execution_type":"READ_ONLY_RESULT_REVIEW_NO_MATCHER_REEXECUTION",
        "required_parent_artifacts_verified":len(checks),
        "raw_rows":len(raw),"canonical_rows":len(canonical),"raw_canonical_reconciliation":"PASS",
        "official_matcher_functions":1,"matrix_rows":17,"scheduled_rows":15,"withheld_rows":2,
        "matcher_call_count":15,"one_call_per_scheduled_row":True,"zero_calls_per_withheld_row":True,
        "boolean_return_count":15,"exception_count":0,"invalid_return_count":0,
        "observed_true_count":12,"observed_false_count":3,
        "false_control_ids":sorted(expected_false_ids),
        "expectation_agreement_count":15,"expectation_nonagreement_count":0,"nonagreement_control_ids":[],
        "C005_runtime_type":"dict","C005_observed_match":True,
        "Base64_length_7_observed":False,"Base64_length_8_observed":True,
        "withheld_outside_agreement_denominator":True,
        "matcher_reexecuted":False,"SDK_imported":False,"model_used":False,"guardrail_used":False,
        "sandbox_used":False,"gym_used":False,"tools_executed":False,"effects_observed":False,
        "full_predicates_recomputed":False,"breach_recomputed":False,
        "harness_trick":"NOT_DEMONSTRATED",
        "robust_finding":"OFFICIAL_MATCHER_BEHAVIOR_ESTABLISHED_FOR_15_FROZEN_SYNTHETIC_CONTROLS",
        "security_finding":"END_TO_END_SECURITY_EFFECT_NOT_ESTABLISHED",
        "real_lineage_claim":False,"superiority_claim":False,"hosted_parity_claim":False,
        "claim_boundary":"SYNTHETIC_OFFICIAL_MATCHER_UNIT_RESULTS_ONLY_NO_LINEAGE_EFFECT_PREDICATE_BREACH_GUARDRAIL_OR_SUPERIORITY_CLAIM",
        "next_gate":"EX7_P2_FULL_PREDICATE_AND_BREACH_CONTRACT_DESIGN",
    }
    write_json(paths["result"], result)
    write_json(paths["binding"], {
        "version":VERSION,"created_at_utc":now,
        "parent_manifest":{"path":str(parent_manifest),"size_bytes":parent_manifest.stat().st_size,"sha256":sha256_file(parent_manifest)},
        "parent_binding":{"path":str(parent_binding),"size_bytes":parent_binding.stat().st_size,"sha256":sha256_file(parent_binding)},
        "raw_results":{"path":str(raw_path),"size_bytes":raw_path.stat().st_size,"sha256":sha256_file(raw_path)},
        "canonical_results":{"path":str(canonical_path),"size_bytes":canonical_path.stat().st_size,"sha256":sha256_file(canonical_path)},
        "summary":{"path":str(summary_path),"size_bytes":summary_path.stat().st_size,"sha256":sha256_file(summary_path)},
        "parent_result":{"path":str(result_path),"size_bytes":result_path.stat().st_size,"sha256":sha256_file(result_path)},
        "control_matrix":{"path":str(matrix_path),"size_bytes":matrix_path.stat().st_size,"sha256":sha256_file(matrix_path)},
        "runner":{"path":str(runner),"size_bytes":runner.stat().st_size,"sha256":sha256_file(runner)},
        "verified_parent_artifacts":checks,"parent_artifacts_modified":False,"matcher_reexecuted":False,
        "python":sys.version,"platform":platform.platform(),
    })

    generated = ["verification","reconciliation","population","transformations","findings","result","binding"]
    manifest_rows = [{"artifact":paths[k].name,"role":"DERIVED_EX7_P1A_RESULT_QUALIFICATION","size_bytes":paths[k].stat().st_size,"sha256":sha256_file(paths[k]),"source_path":str(paths[k])} for k in generated]
    for path, role in ((runner,"CURRENT_RUNNER"),(parent_manifest,"SOURCE_OR_PARENT"),(parent_binding,"SOURCE_OR_PARENT"),(raw_path,"QUALIFIED_RAW_RESULTS"),(canonical_path,"QUALIFIED_CANONICAL_RESULTS"),(summary_path,"QUALIFIED_SUMMARY"),(result_path,"QUALIFIED_PARENT_RESULT"),(matrix_path,"QUALIFIED_CONTROL_MATRIX")):
        manifest_rows.append({"artifact":path.name,"role":role,"size_bytes":path.stat().st_size,"sha256":sha256_file(path),"source_path":str(path)})
    for row in checks:
        manifest_rows.append({"artifact":row["artifact"],"role":"VERIFIED_PARENT_EVIDENCE","size_bytes":row["observed_size_bytes"],"sha256":row["observed_sha256"],"source_path":row["path"]})
    write_csv(paths["manifest"], manifest_rows, ["artifact","role","size_bytes","sha256","source_path"])
    external_out = {
        "version":VERSION,"created_at_utc":now,
        "manifest_filename":paths["manifest"].name,"manifest_size_bytes":paths["manifest"].stat().st_size,
        "manifest_sha256":sha256_file(paths["manifest"]),"status":result["status"],"classification":result["classification"],
        "parent_v7_10_manifest_sha256":EXPECTED_PARENT_MANIFEST_SHA256,
        "raw_results_sha256":EXPECTED_RAW_SHA256,"canonical_results_sha256":EXPECTED_CANONICAL_SHA256,
        "predicates_sha256":EXPECTED_PREDICATES_SHA256,"control_matrix_sha256":EXPECTED_MATRIX_SHA256,
        "runner_sha256":sha256_file(runner),"official_matcher_functions":1,
        "scheduled_rows":15,"withheld_rows":2,"matcher_call_count":15,
        "expectation_agreement_count":15,"expectation_nonagreement_count":0,
    }
    write_json(paths["external"], external_out)
    print(json.dumps({
        "status":result["status"],"verified_parent_artifacts":len(checks),
        "raw_rows":len(raw),"canonical_rows":len(canonical),"reconciliation":"PASS",
        "official_matcher_functions":1,"scheduled_rows":15,"withheld_rows":2,
        "matcher_call_count":15,"observed_true_count":12,"observed_false_count":3,
        "expectation_agreement_count":15,"expectation_nonagreement_count":0,
        "runner_sha256":sha256_file(runner),"manifest_sha256":external_out["manifest_sha256"],
        "output_directory":str(out),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
