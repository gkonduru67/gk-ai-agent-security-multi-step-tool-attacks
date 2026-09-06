#!/usr/bin/env python3
"""EX9 v6.88C: explicit transitive ancestor byte-closure.

Read-only verifier for the 16 SOURCE_OR_PARENT rows reported by EX9 v6.88A.
It uses only the explicit Windows paths supplied by the researcher, never
searches the disk, never infers paths, never modifies source evidence, and
creates a new output package.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX9_TRANSITIVE_ANCESTOR_BYTE_CLOSURE_v6.88C"
EXPECTED_EXTERNAL_ROWS = 16
EXPECTED_PREDICATES_SHA256 = "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"

PROJECT_ROOT = Path(r"C:\Users\gkonduru\OneDrive - Forescout Technologies, Inc\F_drive\forescout\Learning\Kaggle\ai-agent-security-multi-step-tool-attacks-Jun11-Sep1\ai-agent-security-multi-step-tool-attacks")
LOG_ROOT = Path(r"C:\x_ai_logs\Exfil")

# Exactly 16 package-reference rows. predicates.py is intentionally repeated
# once per package because v6.88A reported one reference in each package.
EXPLICIT_LOCATORS: list[dict[str, str]] = [
    {"package": "v6_84", "artifact": "ex6f_m4a_auth_transport_review_manifest.csv", "absolute_path": str(LOG_ROOT / r"EX6F_M4A_authorization_transport_review\v6_83A\ex6f_m4a_auth_transport_review_manifest.csv")},
    {"package": "v6_84", "artifact": "ex6f_m4a_auth_transport_review_manifest_external_binding.json", "absolute_path": str(LOG_ROOT / r"EX6F_M4A_authorization_transport_review\v6_83A\ex6f_m4a_auth_transport_review_manifest_external_binding.json")},
    {"package": "v6_84", "artifact": "predicates.py", "absolute_path": str(PROJECT_ROOT / r"aicomp_sdk\core\predicates.py")},
    {"package": "v6_84", "artifact": "ex6f_failed_source_attribution_predicate_control_v6_84.py", "absolute_path": str(PROJECT_ROOT / r"Exfil\ex6f_failed_source_attribution_predicate_control_v6_84.py")},

    {"package": "v6_85", "artifact": "ex6f_failed_source_attribution_manifest.csv", "absolute_path": str(LOG_ROOT / r"EX6F_FAILED_SOURCE_ATTRIBUTION\v6_84\ex6f_failed_source_attribution_manifest.csv")},
    {"package": "v6_85", "artifact": "ex6f_failed_source_attribution_manifest_external_binding.json", "absolute_path": str(LOG_ROOT / r"EX6F_FAILED_SOURCE_ATTRIBUTION\v6_84\ex6f_failed_source_attribution_manifest_external_binding.json")},
    {"package": "v6_85", "artifact": "predicates.py", "absolute_path": str(PROJECT_ROOT / r"aicomp_sdk\core\predicates.py")},
    {"package": "v6_85", "artifact": "ex6f_wrong_source_value_predicate_control_v6_85.py", "absolute_path": str(PROJECT_ROOT / r"Exfil\ex6f_wrong_source_value_predicate_control_v6_85.py")},

    {"package": "v6_86", "artifact": "ex6f_wrong_source_value_manifest.csv", "absolute_path": str(LOG_ROOT / r"EX6F_WRONG_SOURCE_VALUE\v6_85\ex6f_wrong_source_value_manifest.csv")},
    {"package": "v6_86", "artifact": "ex6f_wrong_source_value_manifest_external_binding.json", "absolute_path": str(LOG_ROOT / r"EX6F_WRONG_SOURCE_VALUE\v6_85\ex6f_wrong_source_value_manifest_external_binding.json")},
    {"package": "v6_86", "artifact": "predicates.py", "absolute_path": str(PROJECT_ROOT / r"aicomp_sdk\core\predicates.py")},
    {"package": "v6_86", "artifact": "ex6f_post_without_successful_effect_predicate_control_v6_86.py", "absolute_path": str(PROJECT_ROOT / r"Exfil\ex6f_post_without_successful_effect_predicate_control_v6_86.py")},

    {"package": "v6_87", "artifact": "ex6f_post_without_successful_effect_manifest.csv", "absolute_path": str(LOG_ROOT / r"EX6F_POST_WITHOUT_SUCCESSFUL_EFFECT\v6_86\ex6f_post_without_successful_effect_manifest.csv")},
    {"package": "v6_87", "artifact": "ex6f_post_without_successful_effect_manifest_external_binding.json", "absolute_path": str(LOG_ROOT / r"EX6F_POST_WITHOUT_SUCCESSFUL_EFFECT\v6_86\ex6f_post_without_successful_effect_manifest_external_binding.json")},
    {"package": "v6_87", "artifact": "predicates.py", "absolute_path": str(PROJECT_ROOT / r"aicomp_sdk\core\predicates.py")},
    {"package": "v6_87", "artifact": "ex6f_encoded_derivation_official_matcher_control_v6_87.py", "absolute_path": str(PROJECT_ROOT / r"Exfil\ex6f_encoded_derivation_official_matcher_control_v6_87.py")},
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def locate_validation_report(ex9_dir: Path) -> Path:
    candidates = [
        ex9_dir / "ex9_sha256_validation_report.csv",
        ex9_dir / "ex9_validation_report.csv",
    ]
    for p in candidates:
        if p.is_file():
            return p
    raise FileNotFoundError("v6.88A SHA-256 validation report not found in --ex9-dir")


def select_external_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    selected = []
    for row in rows:
        status = (row.get("verification_status") or "").upper()
        role = (row.get("role") or "").upper()
        exists = (row.get("exists") or "").strip().lower()
        if "EXTERNAL_REFERENCE" in status or (role == "SOURCE_OR_PARENT" and exists in {"", "false", "0", "no"}):
            selected.append(row)
    return selected


def expected_identity(row: dict[str, str]) -> tuple[str, int | None]:
    sha_keys = ["expected_sha256", "sha256", "manifest_sha256"]
    size_keys = ["expected_size_bytes", "size_bytes", "expected_size"]
    expected_sha = next((row.get(k, "").strip().upper() for k in sha_keys if row.get(k, "").strip()), "")
    size_text = next((row.get(k, "").strip() for k in size_keys if row.get(k, "").strip()), "")
    expected_size = int(size_text) if size_text else None
    if len(expected_sha) != 64 or any(c not in "0123456789ABCDEF" for c in expected_sha):
        raise ValueError(f"Invalid expected SHA-256 for {row.get('package')}:{row.get('artifact')}: {expected_sha!r}")
    return expected_sha, expected_size


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=VERSION)
    ap.add_argument("--ex9-dir", required=True, help="Immutable EX9 v6.88A package directory")
    ap.add_argument("--review-dir", required=False, help="Optional immutable EX9 v6.88B reviewed-qualification directory")
    ap.add_argument("--out-root", required=True, help="New output directory; must not exist")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    ex9_dir = Path(args.ex9_dir)
    review_dir = Path(args.review_dir) if args.review_dir else None
    out = Path(args.out_root)

    if not ex9_dir.is_dir():
        raise FileNotFoundError(f"EX9 directory not found: {ex9_dir}")
    if review_dir is not None and not review_dir.is_dir():
        raise FileNotFoundError(f"Review directory not found: {review_dir}")
    if out.exists():
        raise FileExistsError(f"Refusing to overwrite existing output directory: {out}")

    validation_path = locate_validation_report(ex9_dir)
    validation_rows = read_csv(validation_path)
    external_rows = select_external_rows(validation_rows)
    if len(external_rows) != EXPECTED_EXTERNAL_ROWS:
        raise ValueError(f"Expected {EXPECTED_EXTERNAL_ROWS} external references, found {len(external_rows)}")

    locator_by_key = {(r["package"], r["artifact"]): Path(r["absolute_path"]) for r in EXPLICIT_LOCATORS}
    if len(EXPLICIT_LOCATORS) != EXPECTED_EXTERNAL_ROWS or len(locator_by_key) != EXPECTED_EXTERNAL_ROWS:
        raise AssertionError("Explicit locator map must contain exactly 16 unique package/artifact rows")

    observed_keys = {(r.get("package", ""), r.get("artifact", "")) for r in external_rows}
    locator_keys = set(locator_by_key)
    if observed_keys != locator_keys:
        missing = sorted(observed_keys - locator_keys)
        extra = sorted(locator_keys - observed_keys)
        raise ValueError(f"Locator/report key mismatch. Missing locators={missing}; unexpected locators={extra}")

    closure_rows: list[dict[str, Any]] = []
    all_pass = True
    for row in external_rows:
        package = row["package"]
        artifact = row["artifact"]
        path = locator_by_key[(package, artifact)]
        expected_sha, expected_size = expected_identity(row)
        exists = path.is_file()
        observed_size = path.stat().st_size if exists else None
        observed_sha = sha256_file(path) if exists else None
        size_match = exists and (expected_size is None or observed_size == expected_size)
        sha_match = exists and observed_sha == expected_sha
        passed = bool(exists and size_match and sha_match)
        all_pass = all_pass and passed
        closure_rows.append({
            "package": package,
            "artifact": artifact,
            "role": row.get("role", "SOURCE_OR_PARENT"),
            "absolute_path": str(path),
            "expected_size_bytes": expected_size,
            "observed_size_bytes": observed_size,
            "size_match": size_match,
            "expected_sha256": expected_sha,
            "observed_sha256": observed_sha,
            "sha256_match": sha_match,
            "exists": exists,
            "verification_status": "BYTE_VERIFIED_AT_EXPLICIT_LOCATION" if passed else "ANCESTOR_IDENTITY_MISMATCH_OR_MISSING",
            "passed": passed,
        })

    # Additional epoch consistency: the four predicates rows must all resolve to the frozen epoch.
    predicate_rows = [r for r in closure_rows if r["artifact"] == "predicates.py"]
    predicate_epoch_consistent = (
        len(predicate_rows) == 4
        and all(r["passed"] for r in predicate_rows)
        and {r["observed_sha256"] for r in predicate_rows} == {EXPECTED_PREDICATES_SHA256}
    )
    all_pass = all_pass and predicate_epoch_consistent

    if not all_pass:
        failed = [f"{r['package']}:{r['artifact']}" for r in closure_rows if not r["passed"]]
        raise ValueError(f"Ancestor closure failed; missing or mismatched references: {failed}; predicate_epoch_consistent={predicate_epoch_consistent}")

    out.mkdir(parents=True, exist_ok=False)
    now = datetime.now(timezone.utc).isoformat()

    locator_csv = out / "ex9_v6_88C_explicit_ancestor_locator.csv"
    closure_csv = out / "ex9_v6_88C_transitive_closure_report.csv"
    result_json = out / "ex9_v6_88C_transitive_closure_result.json"
    binding_json = out / "ex9_v6_88C_binding.json"
    manifest_csv = out / "ex9_v6_88C_manifest.csv"
    external_binding_json = out / "ex9_v6_88C_manifest_external_binding.json"

    write_csv(locator_csv, EXPLICIT_LOCATORS, ["package", "artifact", "absolute_path"])
    closure_fields = [
        "package", "artifact", "role", "absolute_path", "expected_size_bytes", "observed_size_bytes",
        "size_match", "expected_sha256", "observed_sha256", "sha256_match", "exists",
        "verification_status", "passed",
    ]
    write_csv(closure_csv, closure_rows, closure_fields)

    ex9_parent_manifest = ex9_dir / "ex9_qualification_manifest.csv"
    ex9_parent_binding = ex9_dir / "ex9_qualification_manifest_external_binding.json"
    review_manifest = review_dir / "ex9_v6_88B_manifest.csv" if review_dir else None
    review_binding = review_dir / "ex9_v6_88B_manifest_external_binding.json" if review_dir else None

    result = {
        "version": VERSION,
        "created_at_utc": now,
        "status": "PASS_FULL_TRANSITIVE_BYTE_VERIFICATION",
        "classification": "EX9_CONTROL_MATRIX_QUALIFIED_WITH_COMPLETE_ANCESTOR_BYTE_CLOSURE",
        "execution_type": "READ_ONLY_EXPLICIT_LOCATOR_ANCESTOR_BYTE_VERIFICATION",
        "external_reference_count": EXPECTED_EXTERNAL_ROWS,
        "external_reference_byte_verified_count": EXPECTED_EXTERNAL_ROWS,
        "external_reference_not_byte_reverified_count": 0,
        "complete_transitive_byte_verification": True,
        "predicate_epoch_consistent": predicate_epoch_consistent,
        "predicates_sha256": EXPECTED_PREDICATES_SHA256,
        "paths_inferred": False,
        "disk_search_performed": False,
        "parent_artifacts_modified": False,
        "runtime_controls_rerun": False,
        "sdk_imported": False,
        "model_called": False,
        "harness_trick": "NOT_DEMONSTRATED",
        "security_finding": "NOT_ESTABLISHED_READ_ONLY_EVIDENCE_CLOSURE",
        "methodological_finding": "ALL_SIXTEEN_HASH_BOUND_EXTERNAL_REFERENCES_WERE_BYTE_VERIFIED_AT_EXPLICIT_RESEARCHER_SUPPLIED_LOCATIONS",
        "reviewed_v6_88B_directory_bound": review_dir is not None,
    }
    write_json(result_json, result)

    binding = {
        "version": VERSION,
        "created_at_utc": now,
        "source_validation_report": {
            "path": str(validation_path),
            "size_bytes": validation_path.stat().st_size,
            "sha256": sha256_file(validation_path),
        },
        "parent_ex9_manifest": {
            "path": str(ex9_parent_manifest),
            "exists": ex9_parent_manifest.is_file(),
            "size_bytes": ex9_parent_manifest.stat().st_size if ex9_parent_manifest.is_file() else None,
            "sha256": sha256_file(ex9_parent_manifest) if ex9_parent_manifest.is_file() else None,
        },
        "parent_ex9_external_binding": {
            "path": str(ex9_parent_binding),
            "exists": ex9_parent_binding.is_file(),
            "size_bytes": ex9_parent_binding.stat().st_size if ex9_parent_binding.is_file() else None,
            "sha256": sha256_file(ex9_parent_binding) if ex9_parent_binding.is_file() else None,
        },
        "review_v6_88B_manifest": {
            "path": str(review_manifest) if review_manifest else None,
            "exists": bool(review_manifest and review_manifest.is_file()),
            "size_bytes": review_manifest.stat().st_size if review_manifest and review_manifest.is_file() else None,
            "sha256": sha256_file(review_manifest) if review_manifest and review_manifest.is_file() else None,
        },
        "review_v6_88B_external_binding": {
            "path": str(review_binding) if review_binding else None,
            "exists": bool(review_binding and review_binding.is_file()),
            "size_bytes": review_binding.stat().st_size if review_binding and review_binding.is_file() else None,
            "sha256": sha256_file(review_binding) if review_binding and review_binding.is_file() else None,
        },
        "locator_rows": EXPECTED_EXTERNAL_ROWS,
        "paths_inferred": False,
        "files_copied": False,
        "source_bytes_modified": False,
        "python": sys.version,
        "platform": platform.platform(),
    }
    write_json(binding_json, binding)

    # Bind only files already written; the manifest does not include itself.
    manifest_targets = [
        (locator_csv, "DERIVED_CLOSURE"),
        (closure_csv, "DERIVED_CLOSURE"),
        (result_json, "DERIVED_CLOSURE"),
        (binding_json, "DERIVED_CLOSURE"),
        (validation_path, "SOURCE_OR_PARENT"),
    ]
    if ex9_parent_manifest.is_file():
        manifest_targets.append((ex9_parent_manifest, "SOURCE_OR_PARENT"))
    if ex9_parent_binding.is_file():
        manifest_targets.append((ex9_parent_binding, "SOURCE_OR_PARENT"))
    if review_manifest and review_manifest.is_file():
        manifest_targets.append((review_manifest, "SOURCE_OR_PARENT"))
    if review_binding and review_binding.is_file():
        manifest_targets.append((review_binding, "SOURCE_OR_PARENT"))

    manifest_rows = []
    for p, role in manifest_targets:
        manifest_rows.append({
            "artifact": p.name,
            "role": role,
            "size_bytes": p.stat().st_size,
            "sha256": sha256_file(p),
            "source_path": str(p),
        })
    write_csv(manifest_csv, manifest_rows, ["artifact", "role", "size_bytes", "sha256", "source_path"])

    external_binding = {
        "version": VERSION,
        "created_at_utc": now,
        "manifest_filename": manifest_csv.name,
        "manifest_size_bytes": manifest_csv.stat().st_size,
        "manifest_sha256": sha256_file(manifest_csv),
        "status": result["status"],
        "classification": result["classification"],
        "external_reference_count": EXPECTED_EXTERNAL_ROWS,
        "external_reference_byte_verified_count": EXPECTED_EXTERNAL_ROWS,
        "complete_transitive_byte_verification": True,
        "predicates_sha256": EXPECTED_PREDICATES_SHA256,
    }
    write_json(external_binding_json, external_binding)

    print(json.dumps({
        "status": result["status"],
        "classification": result["classification"],
        "verified": EXPECTED_EXTERNAL_ROWS,
        "manifest_sha256": external_binding["manifest_sha256"],
        "output_directory": str(out),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
