#!/usr/bin/env python3
"""EX9 v6.88B read-only reviewed qualification and optional ancestor closure.

This runner never modifies v6.88A or earlier evidence. It verifies the frozen
v6.88A manifest and all v6.88A package-local files, freezes the reviewed scope
qualification, records the missing v6.84 experiment version in a supplemental
mapping, and preserves every external reference as HASH_BOUND_NOT_BYTE_REVERIFIED.

Optional ancestor byte closure is supported only through an explicit locator
CSV supplied by the researcher. No paths are inferred, and no files are copied.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX9_CONTROL_MATRIX_REVIEWED_QUALIFICATION_AND_ANCESTOR_CLOSURE_v6.88B"
SCHEMA = "EX9_REVIEWED_QUALIFICATION_AND_ANCESTOR_CLOSURE_V1"
PARENT_MANIFEST_SHA256 = "9130DEFA2830AF935D7B57471D7EDEC1E814122E4BF3929999971E3ACD690ED4"
PARENT_RESULT_SHA256 = "AB6410499E026FD2645775CB79561EA969DC0BE45C4951D4C3CD6DE79DC9AF25"
PARENT_CANONICAL_MATRIX_SHA256 = "88B15AC2993120E5AC66F3A87718CB39C8E537EE7FBEB04A649586493B079B94"
PARENT_VALIDATION_REPORT_SHA256 = "E58FEEC6448E02CC1216277DC65176E87471626A78FC07E5788937DCB37066B3"
EVALUATOR_EPOCH_SHA256 = "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
CORRECT_V684_VERSION = "EX6F_FAILED_SOURCE_ATTRIBUTION_OFFICIAL_PREDICATE_CONTROL_v6.84"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest().upper()


def write_json_x(path: Path, obj: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True, ensure_ascii=False)
        fh.write("\n")


def write_csv_x(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("x", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def verify_exact(path: Path, expected_sha: str, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Missing {label}: {path}")
    observed = sha256_file(path)
    if observed != expected_sha:
        raise ValueError(f"{label} SHA-256 mismatch: expected {expected_sha}, observed {observed}")


def normalize_locator_rows(path: Path | None) -> list[dict[str, str]]:
    if path is None:
        return []
    if not path.is_file():
        raise FileNotFoundError(f"Locator CSV not found: {path}")
    rows = load_csv(path)
    required = {"package", "artifact", "absolute_path"}
    if rows and not required.issubset(rows[0]):
        raise ValueError(f"Locator CSV requires columns: {sorted(required)}")
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ex9-dir", required=True, type=Path)
    ap.add_argument("--out-root", required=True, type=Path)
    ap.add_argument("--ancestor-locator-csv", type=Path)
    args = ap.parse_args()

    parent = args.ex9_dir.resolve()
    out = args.out_root.resolve()
    locator_path = args.ancestor_locator_csv.resolve() if args.ancestor_locator_csv else None
    if out.exists():
        ap.error(f"Refusing to overwrite existing output directory: {out}")

    manifest = parent / "ex9_qualification_manifest.csv"
    manifest_binding = parent / "ex9_qualification_manifest_external_binding.json"
    result_path = parent / "ex9_qualification_result.json"
    canonical_path = parent / "ex9_canonical_control_matrix.csv"
    validation_path = parent / "ex9_sha256_validation_report.csv"
    synthesis_binding_path = parent / "ex9_synthesis_binding.json"

    verify_exact(manifest, PARENT_MANIFEST_SHA256, "v6.88A qualification manifest")
    verify_exact(result_path, PARENT_RESULT_SHA256, "v6.88A qualification result")
    verify_exact(canonical_path, PARENT_CANONICAL_MATRIX_SHA256, "v6.88A canonical matrix")
    verify_exact(validation_path, PARENT_VALIDATION_REPORT_SHA256, "v6.88A validation report")

    parent_binding = load_json(manifest_binding)
    if str(parent_binding.get("manifest_sha256", "")).upper() != PARENT_MANIFEST_SHA256:
        raise ValueError("v6.88A external binding does not bind the expected manifest")
    if str(parent_binding.get("evaluator_epoch_sha256", "")).upper() != EVALUATOR_EPOCH_SHA256:
        raise ValueError("v6.88A external binding evaluator epoch mismatch")

    parent_result = load_json(result_path)
    if parent_result.get("status") != "PASS":
        raise ValueError("v6.88A generated status is not PASS")
    if parent_result.get("classification") != "EX9_CONTROL_MATRIX_INDEPENDENTLY_QUALIFIED":
        raise ValueError("v6.88A generated classification mismatch")
    if int(parent_result.get("external_reference_rows_not_byte_reverified", -1)) != 16:
        raise ValueError("Expected exactly 16 external references not byte-reverified")

    canonical_rows = load_csv(canonical_path)
    if len(canonical_rows) != 9:
        raise ValueError(f"Expected 9 canonical rows, observed {len(canonical_rows)}")
    v684 = [r for r in canonical_rows if r.get("case_id") == "FAILED_SOURCE_ATTRIBUTION"]
    if len(v684) != 1:
        raise ValueError("Canonical matrix must contain exactly one FAILED_SOURCE_ATTRIBUTION row")
    observed_v684_version = v684[0].get("experiment_version", "")
    if observed_v684_version not in ("", None):
        raise ValueError("v6.84 experiment_version is no longer blank; qualification assumptions changed")

    validation_rows = load_csv(validation_path)
    external_rows = [r for r in validation_rows if r.get("verification_status") == "EXTERNAL_REFERENCE_BOUND_BY_PACKAGE_MANIFEST_NOT_BYTE_REVERIFIED"]
    if len(external_rows) != 16:
        raise ValueError(f"Expected 16 external-reference rows, observed {len(external_rows)}")

    locator_rows = normalize_locator_rows(locator_path)
    locator = {(r["package"], r["artifact"]): Path(r["absolute_path"]).expanduser() for r in locator_rows}
    closure_rows: list[dict[str, Any]] = []
    for r in external_rows:
        key = (r["package"], r["artifact"])
        p = locator.get(key)
        located = p is not None
        exists = bool(p and p.is_file())
        observed_size = p.stat().st_size if exists else None
        observed_sha = sha256_file(p) if exists else None
        size_match = exists and observed_size == int(r["expected_size"])
        sha_match = exists and observed_sha == r["expected_sha256"].upper()
        byte_verified = bool(size_match and sha_match)
        if not located:
            status = "HASH_BOUND_NOT_BYTE_REVERIFIED_NO_LOCATOR"
        elif not exists:
            status = "LOCATOR_PROVIDED_FILE_NOT_FOUND"
        elif byte_verified:
            status = "BYTE_VERIFIED_AT_EXPLICIT_LOCATION"
        else:
            status = "LOCATED_IDENTITY_MISMATCH"
        closure_rows.append({
            "package": r["package"],
            "artifact": r["artifact"],
            "expected_size": int(r["expected_size"]),
            "expected_sha256": r["expected_sha256"].upper(),
            "locator_provided": located,
            "absolute_path": str(p) if p else "",
            "file_exists": exists,
            "observed_size": observed_size,
            "observed_sha256": observed_sha,
            "size_match": size_match,
            "sha256_match": sha_match,
            "byte_verified": byte_verified,
            "closure_status": status,
        })

    mismatches = [r for r in closure_rows if r["closure_status"] in {"LOCATOR_PROVIDED_FILE_NOT_FOUND", "LOCATED_IDENTITY_MISMATCH"}]
    if mismatches:
        raise ValueError(f"Explicit ancestor locator validation failed for {len(mismatches)} row(s)")
    verified_count = sum(1 for r in closure_rows if r["byte_verified"])
    unverified_count = len(closure_rows) - verified_count
    full_closure = verified_count == 16

    reviewed_status = "PASS_FULL_TRANSITIVE_BYTE_VERIFICATION" if full_closure else "PASS_WITH_VERIFICATION_SCOPE_QUALIFICATION"
    reviewed_classification = (
        "EX9_CONTROL_MATRIX_QUALIFIED_WITH_COMPLETE_ANCESTOR_BYTE_CLOSURE"
        if full_closure else
        "EX9_CONTROL_MATRIX_LOGICALLY_QUALIFIED_WITH_PACKAGE_LOCAL_BYTE_VERIFICATION_AND_HASH_BOUND_EXTERNAL_REFERENCES"
    )

    out.mkdir(parents=True)
    metadata_rows = [{
        "package": "v6_84",
        "case_id": "FAILED_SOURCE_ATTRIBUTION",
        "field": "experiment_version",
        "parent_value": observed_v684_version or "",
        "qualified_value": CORRECT_V684_VERSION,
        "qualification_type": "SUPPLEMENTAL_METADATA_MAPPING_ONLY",
        "outcome_impact": "NONE",
        "parent_artifact_modified": False,
    }]
    write_csv_x(out / "ex9_v6_88B_metadata_qualification.csv", list(metadata_rows[0].keys()), metadata_rows)
    write_csv_x(out / "ex9_v6_88B_ancestor_closure_report.csv", list(closure_rows[0].keys()), closure_rows)

    reviewed = {
        "schema": SCHEMA,
        "version": VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "execution_type": "READ_ONLY_REVIEWED_QUALIFICATION",
        "generated_v6_88A_status": "PASS",
        "generated_v6_88A_classification": "EX9_CONTROL_MATRIX_INDEPENDENTLY_QUALIFIED",
        "reviewed_status": reviewed_status,
        "reviewed_classification": reviewed_classification,
        "parent_ex9_manifest_sha256": PARENT_MANIFEST_SHA256,
        "evaluator_epoch_sha256": EVALUATOR_EPOCH_SHA256,
        "expected_case_count": 9,
        "observed_case_count": 9,
        "v6_84_experiment_version_parent_value": None,
        "v6_84_experiment_version_qualified_value": CORRECT_V684_VERSION,
        "metadata_outcome_impact": "NONE",
        "external_reference_count": 16,
        "external_reference_byte_verified_count": verified_count,
        "external_reference_not_byte_reverified_count": unverified_count,
        "complete_transitive_byte_verification": full_closure,
        "external_reference_default_status": "HASH_BOUND_NOT_BYTE_REVERIFIED",
        "ancestor_locator_supplied": locator_path is not None,
        "locator_path_inferred": False,
        "parent_artifacts_modified": False,
        "generated_EX9_artifacts_modified": False,
        "runtime_controls_rerun": False,
        "model_called": False,
        "sdk_imported": False,
        "predicates_recomputed": False,
        "harness_trick": "NOT_DEMONSTRATED",
        "security_finding": "NOT_ESTABLISHED_READ_ONLY_QUALIFICATION_OF_SYNTHETIC_CONTROL_MATRIX",
        "methodological_finding": "EX9_MATRIX_LOGIC_REMAINS_QUALIFIED_WHILE_VERIFICATION_SCOPE_AND_V6_84_METADATA_CORRECTION_ARE_EXPLICITLY_FROZEN",
        "claim_boundaries": [
            "Synthetic controls are not live-agent results.",
            "Predicate findings are not guardrail findings.",
            "Breach findings are not authorization findings.",
            "Local evaluator findings are not hosted parity.",
            "Hash-bound external references are not byte-verified unless explicit locators pass size and SHA-256 validation.",
            "The v6.84 experiment-version value is a supplemental metadata qualification and does not modify v6.88A.",
        ],
    }
    write_json_x(out / "ex9_v6_88B_reviewed_qualification.json", reviewed)
    write_json_x(out / "ex9_v6_88B_binding.json", {
        "schema": SCHEMA,
        "version": VERSION,
        "created_utc": reviewed["created_utc"],
        "parent_ex9_manifest_sha256": PARENT_MANIFEST_SHA256,
        "parent_ex9_result_sha256": PARENT_RESULT_SHA256,
        "parent_canonical_matrix_sha256": PARENT_CANONICAL_MATRIX_SHA256,
        "parent_validation_report_sha256": PARENT_VALIDATION_REPORT_SHA256,
        "evaluator_epoch_sha256": EVALUATOR_EPOCH_SHA256,
        "parent_artifacts_modified": False,
        "locator_path_inferred": False,
    })

    source_files = [manifest, manifest_binding, result_path, canonical_path, validation_path, synthesis_binding_path, Path(__file__).resolve()]
    if locator_path:
        source_files.append(locator_path)
    manifest_rows = [{
        "artifact": p.name,
        "role": "SOURCE_OR_PARENT",
        "size_bytes": p.stat().st_size,
        "sha256": sha256_file(p),
    } for p in source_files]
    for p in sorted(out.iterdir()):
        if p.is_file():
            manifest_rows.append({
                "artifact": p.name,
                "role": "DERIVED_READ_ONLY_QUALIFICATION",
                "size_bytes": p.stat().st_size,
                "sha256": sha256_file(p),
            })
    out_manifest = out / "ex9_v6_88B_manifest.csv"
    write_csv_x(out_manifest, ["artifact", "role", "size_bytes", "sha256"], manifest_rows)
    write_json_x(out / "ex9_v6_88B_manifest_external_binding.json", {
        "manifest_filename": out_manifest.name,
        "manifest_size_bytes": out_manifest.stat().st_size,
        "manifest_sha256": sha256_file(out_manifest),
        "parent_ex9_manifest_sha256": PARENT_MANIFEST_SHA256,
        "evaluator_epoch_sha256": EVALUATOR_EPOCH_SHA256,
        "reviewed_status": reviewed_status,
        "runtime": {"python": sys.version, "platform": platform.platform()},
    })

    print(json.dumps({
        "version": VERSION,
        "reviewed_status": reviewed_status,
        "reviewed_classification": reviewed_classification,
        "external_reference_count": 16,
        "byte_verified_count": verified_count,
        "not_byte_reverified_count": unverified_count,
        "v6_84_experiment_version": CORRECT_V684_VERSION,
        "manifest_sha256": sha256_file(out_manifest),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
