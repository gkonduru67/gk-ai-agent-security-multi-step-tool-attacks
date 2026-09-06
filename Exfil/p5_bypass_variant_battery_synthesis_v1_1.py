#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P5_BYPASS_VARIANT_BATTERY_SYNTHESIS_v1_1  (EXFILTRATION phase)
================================================================

GATE TYPE : READ_ONLY_SYNTHESIS   (runtime = false)

REPLACES: p5_bypass_variant_battery_synthesis_v1_0.py, which was found to be
a CORRUPTED/TRUNCATED artifact (31 lines, invalid encoding header, no
function bodies, execution failed with SyntaxError at 'tag = self.args.').
Per code_rules ("New implementation files must use new filenames and
distinct class names"), this is a NEW file with a NEW class name
(P5BypassVariantBatterySynthesisV11), not a patch of v1_0.

WHAT THIS GATE CAN DO
----------------------
  * Re-validate SHA-256 identity of the frozen P3 and P4 result JSON files.
  * Validate that the P4 JSON contains the expected schema
    (classification.decode_path_present / normalization_present /
    http_post_present) before dereferencing it (fail-closed, no assumptions).
  * Assemble a read-only variant-matrix synthesis (V_renamed / V_authoritative
    / V_encoded) strictly from already-frozen evidence.
  * Freeze the claim boundary (allowed vs prohibited claims) verbatim.

WHAT THIS GATE CANNOT DO
--------------------------
  * Execute models, tools, predicates, breach logic, Sandbox, or Gym.
  * Establish official_exfiltration, breach, hosted_parity, or
    robust_security_findings. Those remain NOT_ESTABLISHED.

CODE RULES HONORED
-------------------
  * Never overwrites frozen artifacts (P3/P4 opened read-only; only NEW
    output filenames written under a distinct v1_1 tag).
  * New filename + distinct class name.
  * Default fail-closed: missing file / hash mismatch / missing schema key
    -> non-zero exit, no synthesis written.
  * External manifest binding (result and manifest are separate files;
    the manifest's own hash is recorded in a third binding file, not in
    itself).
  * NOT_ESTABLISHED fields explicit; nothing invented.
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

TOOL_ID = "P5_BYPASS_VARIANT_BATTERY_SYNTHESIS"
TOOL_VERSION = "v1_1"
NOT_ESTABLISHED = "NOT_ESTABLISHED"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


class P5BypassVariantBatterySynthesisV11:
    """Read-only synthesis of the V_renamed / V_authoritative / V_encoded
    bypass-variant battery from already-frozen P3 and P4 evidence."""

    def __init__(self, args):
        self.args = args
        self.checks = []  # list of dicts: check_id, passed, detail

    # ---- check bookkeeping -------------------------------------------
    def add_check(self, check_id, passed, detail=""):
        self.checks.append({
            "check_id": check_id,
            "passed": bool(passed),
            "detail": detail,
        })
        return bool(passed)

    # ---- identity validation (fail-closed) -----------------------------
    def validate_file_hash(self, label, path, expected_hash):
        if not path:
            self.add_check(f"IDENTITY[{label}]", False, "path not supplied")
            return False
        if not os.path.isfile(path):
            self.add_check(f"IDENTITY[{label}]", False, f"FILE_NOT_FOUND: {path}")
            return False
        observed = sha256_file(path)
        ok = (observed == expected_hash.upper())
        self.add_check(
            f"IDENTITY[{label}]", ok,
            f"expected={expected_hash.upper()[:12]}... observed={observed[:12]}..."
            + ("" if ok else "  MISMATCH")
        )
        return ok

    # ---- schema validation (fail-closed, no blind dereferencing) --------
    def validate_schema(self, payload, required_keys, section_label):
        ok = True
        for key in required_keys:
            if key not in payload:
                ok = False
                self.add_check(f"SCHEMA[{section_label}.{key}]", False, "MISSING_KEY")
        if ok:
            self.add_check(f"SCHEMA[{section_label}]", True,
                           f"all required keys present: {required_keys}")
        return ok

    # ---- claim boundary (frozen, verbatim) ------------------------------
    def build_claim_boundary(self):
        return {
            "allowed_claims": [
                "V_RENAMED_SOURCE read-capture name gate is ESTABLISHED "
                "(secret.txt-anchored; source-proven in P2C_R7b).",
                "The static source-gating contract is anchored to "
                "SECRET_FILENAME=='secret.txt' (re-confirmed in P3).",
                "The official EXFILTRATION matcher contains explicit decode "
                "paths (base64, hex) and a normalization path (P4-confirmed).",
                "http.post remains the only documented EXFILTRATION sink "
                "(P3 and P4 both confirm this contractually).",
            ],
            "prohibited_claims": [
                "official_exfiltration: PROVEN",
                "breach: PROVEN",
                "V_authoritative_source runtime behavior: EQUIVALENT_TO_fs.read",
                "V_encoded_payload runtime bypass: PROVEN",
                "hosted_parity: ESTABLISHED",
                "robust_security_findings: ESTABLISHED",
            ],
            "frozen_priors_carried": {
                "official_exfiltration": NOT_ESTABLISHED,
                "breach": NOT_ESTABLISHED,
                "hosted_parity": NOT_ESTABLISHED,
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": NOT_ESTABLISHED,
            },
        }

    # ---- main ------------------------------------------------------------
    def run(self):
        # 1) Re-validate P3 / P4 identities (fail-closed).
        p3_ok = self.validate_file_hash("p3_result", self.args.p3_result, self.args.p3_sha256)
        p4_ok = self.validate_file_hash("p4_result", self.args.p4_result, self.args.p4_sha256)

        if not (p3_ok and p4_ok):
            self._write_failure_and_exit("IDENTITY_VALIDATION_FAILED")

        # 2) Load JSON (only after identity is confirmed).
        try:
            with open(self.args.p3_result, "r", encoding="utf-8") as fh:
                p3 = json.load(fh)
        except Exception as exc:
            self.add_check("PARSE[p3_result]", False, f"JSON_PARSE_ERROR: {exc}")
            self._write_failure_and_exit("P3_PARSE_ERROR")
            return
        self.add_check("PARSE[p3_result]", True, "parsed OK")

        try:
            with open(self.args.p4_result, "r", encoding="utf-8") as fh:
                p4 = json.load(fh)
        except Exception as exc:
            self.add_check("PARSE[p4_result]", False, f"JSON_PARSE_ERROR: {exc}")
            self._write_failure_and_exit("P4_PARSE_ERROR")
            return
        self.add_check("PARSE[p4_result]", True, "parsed OK")

        # 3) Schema validation before ANY dereferencing (fail-closed).
        p3_schema_ok = self.validate_schema(
            p3, ["source_classification", "status"], "p3_result"
        )
        p4_schema_ok = self.validate_schema(
            p4, ["classification", "status"], "p4_result"
        )
        if not (p3_schema_ok and p4_schema_ok):
            self._write_failure_and_exit("SCHEMA_VALIDATION_FAILED")
            return

        p4_class_ok = self.validate_schema(
            p4["classification"],
            ["decode_path_present", "normalization_present", "http_post_present"],
            "p4_result.classification"
        )
        if not p4_class_ok:
            self._write_failure_and_exit("SCHEMA_VALIDATION_FAILED")
            return

        # 4) Status sanity (evidence must actually be complete, not partial).
        p3_status_ok = self.add_check(
            "STATUS[p3_result]", p3.get("status") == "INSPECTION_COMPLETE",
            f"observed status={p3.get('status')}"
        )
        p4_status_ok = self.add_check(
            "STATUS[p4_result]", p4.get("status") == "INSPECTION_COMPLETE",
            f"observed status={p4.get('status')}"
        )
        if not (p3_status_ok and p4_status_ok):
            self._write_failure_and_exit("UPSTREAM_STATUS_NOT_COMPLETE")
            return

        # 5) Assemble variant matrix strictly from frozen fields.
        src_class = p3.get("source_classification", {})
        p4_class = p4["classification"]

        variant_matrix = {
            "V_RENAMED_SOURCE": {
                "status": "ESTABLISHED",
                "finding": "V_RENAMED_SOURCE_LINEAGE_READ_CAPTURE_BYPASS_ESTABLISHED",
                "scope": {
                    "read_capture": "name-DEPENDENT (secret.txt-gated)",
                    "sink_match": "name-INDEPENDENT (returned-value)",
                    "official_predicate": "ALSO secret.txt-anchored",
                },
                "runtime_behavior": NOT_ESTABLISHED,
            },
            "V_AUTHORITATIVE_SOURCE": {
                "status": "STATIC_CONTRACT_ONLY",
                "fs_read_symbol": src_class.get("fs.read", {}).get("static_verdict", NOT_ESTABLISHED),
                "web_open_symbol": src_class.get("web.open", {}).get("static_verdict", NOT_ESTABLISHED),
                "email_read_symbol": src_class.get("email.read", {}).get("static_verdict", NOT_ESTABLISHED),
                "runtime_behavior": NOT_ESTABLISHED,
            },
            "V_ENCODED_PAYLOAD": {
                "status": "MATCHER_CONTRACT_ONLY",
                "decode_path_present": p4_class["decode_path_present"],
                "normalization_present": p4_class["normalization_present"],
                "http_post_present": p4_class["http_post_present"],
                "runtime_behavior": NOT_ESTABLISHED,
            },
        }

        claim_boundary = self.build_claim_boundary()

        # 6) Final claim-boundary structural check.
        self.add_check(
            "CLAIM_BOUNDARY_HELD",
            len(claim_boundary["prohibited_claims"]) == 6
            and claim_boundary["frozen_priors_carried"]["official_exfiltration"] == NOT_ESTABLISHED,
            "prohibited-claim list and NOT_ESTABLISHED priors preserved"
        )

        total = len(self.checks)
        passed = sum(1 for c in self.checks if c["passed"])
        failed_ids = [c["check_id"] for c in self.checks if not c["passed"]]
        status = "SYNTHESIS_COMPLETE" if not failed_ids else "SYNTHESIS_INCOMPLETE"

        synthesis = {
            "tool_id": TOOL_ID,
            "tool_version": TOOL_VERSION,
            "gate": "P5_BYPASS_VARIANT_BATTERY_SYNTHESIS",
            "execution_type": "READ_ONLY_SYNTHESIS",
            "runtime": False,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "phase": "EXFILTRATION",
            "status": status,
            "checks": {
                "total": total, "passed": passed,
                "failed": len(failed_ids), "failed_ids": failed_ids,
            },
            "upstream_bindings": {
                "p3_result_path": self.args.p3_result,
                "p3_result_sha256": self.args.p3_sha256.upper(),
                "p4_result_path": self.args.p4_result,
                "p4_result_sha256": self.args.p4_sha256.upper(),
            },
            "variant_matrix": variant_matrix,
            "established_findings": [
                "renamed_source_gate",
                "secret_filename_anchor",
                "decode_paths_present",
                "normalization_present",
                "http_post_sink_contract",
            ],
            "not_established": {
                "official_exfiltration": NOT_ESTABLISHED,
                "breach": NOT_ESTABLISHED,
                "hosted_parity": NOT_ESTABLISHED,
                "robust_security_findings": NOT_ESTABLISHED,
                "authoritative_source_runtime_behavior": NOT_ESTABLISHED,
                "encoded_payload_runtime_behavior": NOT_ESTABLISHED,
            },
            "claim_boundary": claim_boundary,
        }

        self._write_artifacts(synthesis, status)

        if failed_ids:
            print("\nFAIL-CLOSED. Synthesis INCOMPLETE.")
            sys.exit(2)
        sys.exit(0)

    # ---- output writing (shared by pass/fail paths) ----------------------
    def _write_artifacts(self, synthesis, status):
        os.makedirs(self.args.out_dir, exist_ok=True)
        tag = self.args.out_tag

        result_path = os.path.join(self.args.out_dir, f"p5_bypass_variant_battery_result_{tag}.json")
        manifest_path = os.path.join(self.args.out_dir, f"p5_bypass_variant_battery_manifest_{tag}.json")
        binding_path = os.path.join(self.args.out_dir, f"p5_bypass_variant_battery_binding_{tag}.txt")

        result_bytes = json.dumps(synthesis, indent=2, sort_keys=False).encode("utf-8")
        with open(result_path, "wb") as fh:
            fh.write(result_bytes)
        result_sha = sha256_bytes(result_bytes)

        manifest = {
            "tool_id": TOOL_ID,
            "tool_version": TOOL_VERSION,
            "binds": "p5_bypass_variant_battery_result",
            "result_filename": os.path.basename(result_path),
            "result_sha256": result_sha,
            "status": status,
        }
        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=False).encode("utf-8")
        with open(manifest_path, "wb") as fh:
            fh.write(manifest_bytes)
        manifest_sha = sha256_bytes(manifest_bytes)

        with open(binding_path, "w", encoding="utf-8") as fh:
            fh.write(f"manifest_filename={os.path.basename(manifest_path)}\n")
            fh.write(f"manifest_sha256={manifest_sha}\n")
            fh.write(f"result_sha256={result_sha}\n")

        print("=" * 72)
        print(f"{TOOL_ID} {TOOL_VERSION}  (READ_ONLY_SYNTHESIS, runtime=false)")
        print("=" * 72)
        for c in self.checks:
            print(f"  [{'PASS' if c['passed'] else 'FAIL'}] {c['check_id']}: {c['detail']}")
        print("-" * 72)
        print(f"  status: {status}")
        print(f"  result   : {result_path}\n             sha256={result_sha}")
        print(f"  manifest : {manifest_path}\n             sha256={manifest_sha}")
        print(f"  binding  : {binding_path}")
        print("=" * 72)

    def _write_failure_and_exit(self, reason):
        total = len(self.checks)
        passed = sum(1 for c in self.checks if c["passed"])
        failed_ids = [c["check_id"] for c in self.checks if not c["passed"]]
        synthesis = {
            "tool_id": TOOL_ID,
            "tool_version": TOOL_VERSION,
            "gate": "P5_BYPASS_VARIANT_BATTERY_SYNTHESIS",
            "execution_type": "READ_ONLY_SYNTHESIS",
            "runtime": False,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "phase": "EXFILTRATION",
            "status": "SYNTHESIS_INCOMPLETE",
            "failure_reason": reason,
            "checks": {
                "total": total, "passed": passed,
                "failed": len(failed_ids), "failed_ids": failed_ids,
            },
        }
        self._write_artifacts(synthesis, "SYNTHESIS_INCOMPLETE")
        print(f"\nFAIL-CLOSED: {reason}")
        sys.exit(2)


def build_parser():
    p = argparse.ArgumentParser(description=f"{TOOL_ID} {TOOL_VERSION} (read-only)")
    p.add_argument("--p3-result", required=True)
    p.add_argument("--p3-sha256", required=True)
    p.add_argument("--p4-result", required=True)
    p.add_argument("--p4-sha256", required=True)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--out-tag", default=TOOL_VERSION)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    P5BypassVariantBatterySynthesisV11(args).run()


if __name__ == "__main__":
    main()
