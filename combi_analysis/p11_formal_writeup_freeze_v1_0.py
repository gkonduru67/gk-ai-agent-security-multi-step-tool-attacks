#!/usr/bin/env python3
"""Freeze the evidence-bound P11 EXFILTRATION formal write-up.

This is a read-only validation and interpretation-freeze gate. It verifies the
P11 artifacts by SHA-256, confirms every source gate passed, validates the
required eight-layer separation, preserves the upstream claim boundary, and
emits a deterministic freeze package.

No model, SandboxEnv, tool, guardrail, predicate, detector, or network operation
is executed. Input evidence is never modified. P12 and four-family submission
construction remain deferred.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "P11_FORMAL_WRITEUP_FREEZE_v1.0"

EXPECTED = {
    "writeup": "F1070F42CABD69AEA6066D4564FF4A7E2DF9C0A96DA4A4C5D4826A3BB1D69571",
    "summary": "63F613A1D950BA7767B24535D81974518A19F14BD4DA1A599E0C2A34281DF6E5",
    "checks": "CE24DBDE7B52C8EEAFE8478A1BAE3D43040777084B9DB0603F3C0D4CD3C4218C",
    "claim_boundary": "4222CAA1C097AEC13EEC043B0A3DF44BCA96A2F7648993EEF7446CCFA12F947C",
    "generator": "1F895AF5922B82F75F4E00D56E9C2891AA2332F4567533182148335780DC5444",
}

EXPECTED_UPSTREAM = {
    "p10_freeze_result": "2A38AC3626B1036F38C7B2853C68FFC3731D5DC3183C8494285B6EF3584439C7",
    "p10_freeze_checks": "76DBB0ED61B24A2382D2CD07A1B6E19A54413E02ABEF915E95EC9C752CA8A1F1",
    "p10_freeze_claim": "4222CAA1C097AEC13EEC043B0A3DF44BCA96A2F7648993EEF7446CCFA12F947C",
}

REQUIRED_SECTIONS = {
    "GPTOSS model formation",
    "native SandboxEnv execution",
    "fixture-root configuration",
    "physical source versus logical path",
    "guardrail decision",
    "official predicate result",
    "research detector result",
    "hosted-parity limitations",
}

REQUIRED_PROHIBITED = {
    "claim implicit mapping from note.txt to file_seed/note.txt",
    "claim v5 path representation was bridge-only",
    "claim an official EXFILTRATION breach",
    "claim a security harness trick",
    "claim hosted parity or robust generalization",
    "construct four-family submission code from this freeze alone",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def identity(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    return {
        "artifact": resolved.name,
        "path": str(resolved),
        "size_bytes": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
    }


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fields,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def add_check(
    rows: list[dict[str, Any]],
    check_id: str,
    condition: str,
    passed: bool,
    observed: Any,
    expected: Any,
) -> None:
    def render(value: Any) -> str:
        if isinstance(value, (dict, list, set, tuple)):
            if isinstance(value, (set, tuple)):
                value = list(value)
            return json.dumps(value, sort_keys=True)
        return str(value)

    rows.append({
        "check_id": check_id,
        "condition": condition,
        "passed": bool(passed),
        "observed": render(observed),
        "expected": render(expected),
    })


def main() -> int:
    parser = argparse.ArgumentParser(description=VERSION)
    parser.add_argument("--p11-writeup", required=True)
    parser.add_argument("--p11-summary", required=True)
    parser.add_argument("--p11-checks", required=True)
    parser.add_argument("--p11-claim-boundary", required=True)
    parser.add_argument("--p11-manifest", required=True)
    parser.add_argument("--p11-generator", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    paths = {
        "writeup": Path(args.p11_writeup).resolve(),
        "summary": Path(args.p11_summary).resolve(),
        "checks": Path(args.p11_checks).resolve(),
        "claim_boundary": Path(args.p11_claim_boundary).resolve(),
        "manifest": Path(args.p11_manifest).resolve(),
        "generator": Path(args.p11_generator).resolve(),
    }
    output_dir = Path(args.output_dir).resolve()
    require(not output_dir.exists(), f"Refusing overwrite: {output_dir}")
    output_dir.mkdir(parents=True)

    for name, path in paths.items():
        require(path.is_file(), f"Missing {name}: {path}")

    checks: list[dict[str, Any]] = []

    for index, name in enumerate(
        ("writeup", "summary", "checks", "claim_boundary", "generator"),
        start=1,
    ):
        observed = sha256_file(paths[name])
        expected = EXPECTED[name]
        passed = observed == expected
        add_check(
            checks,
            f"P11-FRZ-{index:03d}",
            f"frozen P11 {name} identity",
            passed,
            observed,
            expected,
        )
        require(passed, f"P11 {name} SHA-256 mismatch")

    summary = json.loads(paths["summary"].read_text(encoding="utf-8-sig"))
    claim_boundary = json.loads(
        paths["claim_boundary"].read_text(encoding="utf-8-sig")
    )
    writeup = paths["writeup"].read_text(encoding="utf-8-sig")

    with paths["checks"].open("r", encoding="utf-8-sig", newline="") as handle:
        source_checks = list(csv.DictReader(handle))
    with paths["manifest"].open("r", encoding="utf-8-sig", newline="") as handle:
        source_manifest = list(csv.DictReader(handle))

    all_source_checks_passed = bool(source_checks) and all(
        str(row.get("passed", "")).lower() == "true" for row in source_checks
    )
    add_check(
        checks,
        "P11-FRZ-006",
        "all P11 source checks passed",
        all_source_checks_passed,
        [row.get("passed") for row in source_checks],
        "all True",
    )
    require(all_source_checks_passed, "Not all P11 source checks passed")

    status_ok = summary.get("status") == "P11_FORMAL_WRITEUP_GENERATED"
    add_check(
        checks,
        "P11-FRZ-007",
        "P11 generator terminal status",
        status_ok,
        summary.get("status"),
        "P11_FORMAL_WRITEUP_GENERATED",
    )
    require(status_ok, "Unexpected P11 summary status")

    observed_sections = set(summary.get("sections") or [])
    sections_ok = observed_sections == REQUIRED_SECTIONS
    add_check(
        checks,
        "P11-FRZ-008",
        "required eight-layer separation",
        sections_ok,
        sorted(observed_sections),
        sorted(REQUIRED_SECTIONS),
    )
    require(sections_ok, "Required P11 section separation is incomplete")

    prohibited = set(claim_boundary.get("prohibited") or [])
    boundary_ok = REQUIRED_PROHIBITED.issubset(prohibited)
    add_check(
        checks,
        "P11-FRZ-009",
        "required prohibited claims retained",
        boundary_ok,
        sorted(prohibited),
        sorted(REQUIRED_PROHIBITED),
    )
    require(boundary_ok, "P11 claim boundary is incomplete")

    disposition = summary.get("scientific_disposition") or {}
    expected_disposition = {
        "gptoss_native_execution": "CONFIRMED",
        "root_relative_path_success": "CONFIRMED_FOR_TESTED_ROOT_ALIAS",
        "implicit_file_seed_mapping": "NOT_ESTABLISHED",
        "v5_path_bridge_specificity": "NOT_ESTABLISHED",
        "security_harness_trick": "NOT_DEMONSTRATED",
        "new_robust_security_finding": "NOT_ESTABLISHED",
        "official_exfiltration_breach": "NOT_ESTABLISHED",
        "hosted_parity": "NOT_ESTABLISHED",
        "prior_harness_implementation_bugs": "CONFIRMED_AND_FIXED",
    }
    disposition_ok = all(
        disposition.get(key) == value for key, value in expected_disposition.items()
    )
    add_check(
        checks,
        "P11-FRZ-010",
        "scientific disposition matches frozen P10 interpretation",
        disposition_ok,
        disposition,
        expected_disposition,
    )
    require(disposition_ok, "P11 scientific disposition drifted")

    next_state = summary.get("next_state") or {}
    future_ok = (
        next_state.get("P11") == "WRITEUP_GENERATED_AWAITING_FREEZE"
        and next_state.get("P12") == "DEFERRED"
        and next_state.get("four_family_submission") == "NOT_YET_CREATED"
    )
    add_check(
        checks,
        "P11-FRZ-011",
        "future-state boundary retained",
        future_ok,
        next_state,
        {
            "P11": "WRITEUP_GENERATED_AWAITING_FREEZE",
            "P12": "DEFERRED",
            "four_family_submission": "NOT_YET_CREATED",
        },
    )
    require(future_ok, "P11/P12 future-state boundary changed")

    source_freeze = summary.get("source_freeze") or {}
    upstream_ok = source_freeze.get("sha256") == EXPECTED_UPSTREAM["p10_freeze_result"]
    add_check(
        checks,
        "P11-FRZ-012",
        "P10 freeze source binding retained",
        upstream_ok,
        source_freeze.get("sha256"),
        EXPECTED_UPSTREAM["p10_freeze_result"],
    )
    require(upstream_ok, "P11 source freeze binding mismatch")

    manifest_by_name = {row.get("artifact"): row for row in source_manifest}
    upstream_manifest_ok = all(
        any(row.get("sha256") == expected for row in source_manifest)
        for expected in EXPECTED_UPSTREAM.values()
    )
    add_check(
        checks,
        "P11-FRZ-013",
        "P11 manifest contains frozen P10 result/check/claim identities",
        upstream_manifest_ok,
        sorted(row.get("sha256", "") for row in source_manifest),
        sorted(EXPECTED_UPSTREAM.values()),
    )
    require(upstream_manifest_ok, "P11 manifest lacks required upstream identities")

    guardrail_caveat_ok = (
        "guardrail_decision_object: NOT_ESTABLISHED" in writeup
        and "runtime_read_permitted_in_effect: ESTABLISHED_BY_SUCCESSFUL_EXECUTION"
        in writeup
    )
    add_check(
        checks,
        "P11-FRZ-014",
        "guardrail evidence limitation explicitly retained",
        guardrail_caveat_ok,
        guardrail_caveat_ok,
        True,
    )
    require(guardrail_caveat_ok, "Guardrail limitation missing from write-up")

    no_upgrade_patterns = {
        "official breach established": r"official_exfiltration_breach:\s*(CONFIRMED|ESTABLISHED)",
        "security harness trick established": r"security_harness_trick:\s*(CONFIRMED|ESTABLISHED)",
        "hosted parity established": r"hosted_parity:\s*(CONFIRMED|ESTABLISHED)",
        "robust finding established": r"new_robust_security_finding:\s*(CONFIRMED|ESTABLISHED)",
    }
    upgrade_hits = [
        label for label, pattern in no_upgrade_patterns.items()
        if re.search(pattern, writeup, flags=re.IGNORECASE)
    ]
    no_upgrade_ok = not upgrade_hits
    add_check(
        checks,
        "P11-FRZ-015",
        "write-up contains no prohibited scientific upgrade",
        no_upgrade_ok,
        upgrade_hits,
        [],
    )
    require(no_upgrade_ok, "Prohibited scientific upgrade found in P11 write-up")

    freeze = {
        "version": VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "P11_FORMAL_WRITEUP_FROZEN",
        "classification": "EXFILTRATION_FORMAL_WRITEUP_INTERPRETATION_FREEZE",
        "frozen_inputs": {name: identity(path) for name, path in paths.items()},
        "upstream_p10_binding": {
            "freeze_result_sha256": EXPECTED_UPSTREAM["p10_freeze_result"],
            "freeze_checks_sha256": EXPECTED_UPSTREAM["p10_freeze_checks"],
            "freeze_claim_boundary_sha256": EXPECTED_UPSTREAM["p10_freeze_claim"],
        },
        "frozen_scientific_disposition": expected_disposition,
        "required_separation": {
            "gptoss_model_formation": "COMPLETE",
            "native_sandboxenv_execution": "COMPLETE",
            "fixture_root_configuration": "COMPLETE",
            "physical_source_vs_logical_path": "COMPLETE",
            "guardrail_layer": "COMPLETE_WITH_DECISION_OBJECT_NOT_ESTABLISHED",
            "official_predicate_layer": "COMPLETE",
            "research_detector_layer": "COMPLETE",
            "hosted_parity_boundary": "COMPLETE_WITH_PARITY_NOT_ESTABLISHED",
        },
        "frozen_claim_boundary": claim_boundary,
        "harness_assessment": {
            "prior_implementation_bugs": "CONFIRMED_AND_FIXED",
            "security_harness_trick": "NOT_DEMONSTRATED",
        },
        "security_assessment": {
            "new_robust_security_finding": "NOT_ESTABLISHED",
            "official_exfiltration_breach": "NOT_ESTABLISHED",
            "hosted_parity": "NOT_ESTABLISHED",
        },
        "future_state": {
            "P11": "COMPLETE_FROZEN",
            "P12": "DEFERRED",
            "four_family_submission": "NOT_YET_CREATED",
            "submission_prerequisite": "ALL_FAMILY_EVIDENCE_FROZEN",
            "model_evidence_requirement": "LOCAL_GPTOSS_OR_COMPETITION_MODEL_BACKED",
            "deterministic_agent_assumptions": "PROHIBITED_FOR_MODEL_CLAIMS",
        },
    }

    result_path = output_dir / "p11_exfiltration_formal_writeup_freeze_result_v1_0.json"
    checks_path = output_dir / "p11_exfiltration_formal_writeup_freeze_checks_v1_0.csv"
    claim_path = output_dir / "p11_exfiltration_formal_writeup_freeze_claim_boundary_v1_0.json"
    manifest_path = output_dir / "p11_exfiltration_formal_writeup_freeze_manifest_v1_0.csv"

    write_json(result_path, freeze)
    write_csv(
        checks_path,
        checks,
        ["check_id", "condition", "passed", "observed", "expected"],
    )
    write_json(claim_path, claim_boundary)

    manifest_rows = [identity(path) for path in paths.values()]
    manifest_rows.extend([
        identity(result_path),
        identity(checks_path),
        identity(claim_path),
        identity(Path(__file__).resolve()),
    ])
    write_csv(
        manifest_path,
        manifest_rows,
        ["artifact", "path", "size_bytes", "sha256"],
    )

    print(json.dumps({
        "status": freeze["status"],
        "checks_passed": len(checks),
        "P11": "COMPLETE_FROZEN",
        "P12": "DEFERRED",
        "four_family_submission": "NOT_YET_CREATED",
        "output_dir": str(output_dir),
        "manifest_sha256": sha256_file(manifest_path),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
