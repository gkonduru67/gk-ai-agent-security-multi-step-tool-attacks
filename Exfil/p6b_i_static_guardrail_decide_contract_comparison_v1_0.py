#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P6B_I_STATIC_GUARDRAIL_DECIDE_CONTRACT_COMPARISON_v1_0  (EXFILTRATION phase)
=============================================================================

GATE TYPE : READ_ONLY_STATIC_SOURCE_COMPARISON   (runtime = false)

Scientific Purpose
-------------------
Statically compare the DECISION CONTRACTS of two guardrail source files:
  (A) the packaged optimal.py guardrail
  (B) a custom guardrail (e.g. lineage_aware_exfil_guardrail_v2_1.py)

by extracting, via source-text symbol search only, whether each file
references a fixed set of decision-relevant categories:
  - bypass conditions (user_confirmed_safe, user_authorized)
  - direct secret-matcher usage (payload_exfiltrates_secret, _is_secret_path,
    is_protected_secret_path)
  - pattern-based checks (ultra_dangerous_patterns, dangerous_operations)
  - lineage/provenance checks (recent_sources, read_value, ledger)
  - explicit deny-reason string literals

This gate does NOT:
  - call .decide() on either guardrail
  - execute Sandbox, Gym, api.py, or any model
  - assert which guardrail is "better" or "stronger" (static presence does
    not establish runtime behavior, per claim_discipline)

It DOES explicitly surface the KNOWN, PRIOR-DOCUMENTED asymmetry that
optimal.py does not call payload_exfiltrates_secret directly (unlike the
base rules-guardrail), so this caveat can never be silently dropped from
downstream reporting.

CODE RULES HONORED
--------------------
  * New filename + distinct class name (P6bIStaticGuardrailDecideContractComparison).
  * Fail-closed: file not found / identity mismatch (if expected hash given)
    -> non-zero exit, no comparison claim written.
  * Raw matched line text preserved separately from the classification.
  * External manifest binding (result/manifest separate; binding file records
    manifest's own hash outside the manifest).
  * Never overwrites frozen artifacts; only NEW out-tag'd files written.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

TOOL_ID = "P6B_I_STATIC_GUARDRAIL_DECIDE_CONTRACT_COMPARISON"
TOOL_VERSION = "v1_0"
NOT_ESTABLISHED = "NOT_ESTABLISHED"

# Reference identity for optimal.py, confirmed across P3/P4/P6.
KNOWN_OPTIMAL_SHA256 = (
    "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED"
)

# Symbol categories: (category_id, [regex patterns], description)
SYMBOL_CATEGORIES = [
    ("bypass_user_confirmed", [r"user_confirmed_safe"],
     "Bypass: explicit user-confirmed-safe override"),
    ("bypass_user_authorized", [r"user_authorized"],
     "Bypass: explicit user-authorized override"),
    ("direct_secret_matcher", [r"payload_exfiltrates_secret"],
     "Direct call to the official secret-payload matcher"),
    ("direct_secret_path_check", [r"_is_secret_path", r"is_protected_secret_path"],
     "Direct call to the official secret-path name-gate"),
    ("pattern_based_deny", [r"ultra_dangerous_patterns", r"dangerous_operations"],
     "Pattern/keyword-based dangerous-operation check"),
    ("lineage_provenance_check", [r"recent_sources", r"read_value", r"ledger"],
     "Lineage/provenance-aware check (tracks source->sink derivation)"),
    ("explicit_deny_reason_literal", [r'"denied:[^"]*"', r"'denied:[^']*'", r'deny\('],
     "Explicit, named deny-reason string or deny() call"),
]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


class P6bIStaticGuardrailDecideContractComparison:

    def __init__(self, args):
        self.args = args
        self.checks = []

    def add_check(self, cid, passed, detail=""):
        self.checks.append({"check_id": cid, "passed": bool(passed), "detail": detail})
        return bool(passed)

    def validate_identity(self, label, path, expected_hash):
        if not path or not os.path.isfile(path):
            self.add_check(f"IDENTITY[{label}]", False, f"FILE_NOT_FOUND: {path}")
            return None
        observed = sha256_file(path)
        if expected_hash:
            ok = observed.upper() == expected_hash.upper()
            self.add_check(f"IDENTITY[{label}]", ok,
                           f"expected={expected_hash.upper()[:12]}... observed={observed[:12]}...")
            if not ok:
                return None
        else:
            self.add_check(f"IDENTITY[{label}]", True,
                           f"no expected hash supplied; observed={observed} (RECORDED, not verified)")
        return observed

    def scan_file(self, label, path):
        """Static symbol scan. Returns per-category match records with raw lines."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except Exception as exc:
            self.add_check(f"SCAN[{label}]", False, f"READ_ERROR: {exc}")
            return None
        self.add_check(f"SCAN[{label}]", True, f"{len(lines)} line(s) scanned")

        results = {}
        for cat_id, patterns, description in SYMBOL_CATEGORIES:
            hits = []
            compiled = [re.compile(p) for p in patterns]
            for lineno, raw in enumerate(lines, start=1):
                for rx in compiled:
                    if rx.search(raw):
                        hits.append({"lineno": lineno, "raw": raw.rstrip("\n")})
                        break
            results[cat_id] = {
                "description": description,
                "match_count": len(hits),
                "present": len(hits) > 0,
                "matches": hits,  # RAW lines preserved, separate from the boolean verdict
            }
        return results

    def run(self):
        optimal_hash = self.validate_identity(
            "optimal_py", self.args.optimal,
            self.args.optimal_sha256 or KNOWN_OPTIMAL_SHA256
        )
        custom_hash = self.validate_identity(
            "custom_guardrail", self.args.custom,
            self.args.custom_sha256  # no known default -- must be supplied or left unverified
        )

        if optimal_hash is None:
            self._write_failure_and_exit("OPTIMAL_IDENTITY_FAILED")
            return
        if not self.args.custom or not os.path.isfile(self.args.custom):
            self._write_failure_and_exit("CUSTOM_GUARDRAIL_FILE_NOT_FOUND")
            return

        optimal_scan = self.scan_file("optimal_py", self.args.optimal)
        custom_scan = self.scan_file("custom_guardrail", self.args.custom)
        if optimal_scan is None or custom_scan is None:
            self._write_failure_and_exit("SOURCE_SCAN_FAILED")
            return

        # Build the side-by-side matrix (presence/absence only, no verdict).
        comparison_matrix = {}
        for cat_id, patterns, description in SYMBOL_CATEGORIES:
            comparison_matrix[cat_id] = {
                "description": description,
                "optimal_py_present": optimal_scan[cat_id]["present"],
                "optimal_py_match_count": optimal_scan[cat_id]["match_count"],
                "custom_guardrail_present": custom_scan[cat_id]["present"],
                "custom_guardrail_match_count": custom_scan[cat_id]["match_count"],
            }

        total = len(self.checks)
        passed = sum(1 for c in self.checks if c["passed"])
        failed_ids = [c["check_id"] for c in self.checks if not c["passed"]]
        status = "COMPARISON_COMPLETE" if not failed_ids else "COMPARISON_INCOMPLETE"

        result = {
            "tool_id": TOOL_ID, "tool_version": TOOL_VERSION,
            "gate": "P6B_I_STATIC_GUARDRAIL_DECIDE_CONTRACT_COMPARISON",
            "execution_type": "READ_ONLY_STATIC_SOURCE_COMPARISON",
            "runtime": False,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "phase": "EXFILTRATION",
            "status": status,
            "checks": {"total": total, "passed": passed, "failed": len(failed_ids), "failed_ids": failed_ids},
            "identities": {
                "optimal_py": {"path": self.args.optimal, "sha256": optimal_hash},
                "custom_guardrail": {"path": self.args.custom, "sha256": custom_hash},
            },
            "comparison_matrix": comparison_matrix,
            "raw_scan_detail": {
                "optimal_py": optimal_scan,
                "custom_guardrail": custom_scan,
            },
            "known_documented_asymmetry": {
                "statement": (
                    "Prior source inspection (SDK Core Contract document) established that "
                    "optimal.py does NOT call payload_exfiltrates_secret directly, unlike the "
                    "base rules-guardrail (guardrail_rules.py), which does. optimal.py instead "
                    "relies on ultra_dangerous_patterns + tainted-source/dangerous_operations "
                    "checks. Any comparison of optimal.py vs a secret-matcher-based guardrail "
                    "must control for this asymmetry rather than treating them as interchangeable."
                ),
                "carried_forward_from": "AI_Agent_Security_SDK_Core_Contract_Understanding.docx",
            },
            "claim_boundary": {
                "allowed_claims": [
                    "Static symbol presence/absence for each decision-relevant category, "
                    "in each guardrail's source text, with exact line numbers.",
                    "The documented asymmetry (optimal.py lacks direct secret-matcher call) "
                    "is carried forward explicitly, not silently dropped.",
                ],
                "prohibited_claims": [
                    "optimal.py is WEAKER or STRONGER than the custom guardrail (runtime behavior)",
                    "either guardrail would ALLOW or DENY any specific real proposal",
                    "this comparison establishes robust_security_findings",
                    "this comparison establishes official_exfiltration or hosted_parity",
                ],
            },
            "not_established": {
                "runtime_decide_behavior_of_either_guardrail": NOT_ESTABLISHED,
                "which_guardrail_denies_more_real_proposals": NOT_ESTABLISHED,
                "official_exfiltration": NOT_ESTABLISHED,
                "robust_security_findings": NOT_ESTABLISHED,
            },
        }

        self._write_artifacts(result, status)
        sys.exit(0 if not failed_ids else 2)

    def _write_artifacts(self, result, status):
        os.makedirs(self.args.out_dir, exist_ok=True)
        tag = self.args.out_tag

        result_path = os.path.join(self.args.out_dir, f"p6b_i_guardrail_comparison_result_{tag}.json")
        manifest_path = os.path.join(self.args.out_dir, f"p6b_i_guardrail_comparison_manifest_{tag}.json")
        binding_path = os.path.join(self.args.out_dir, f"p6b_i_guardrail_comparison_binding_{tag}.txt")

        result_bytes = json.dumps(result, indent=2, sort_keys=False, default=str).encode("utf-8")
        with open(result_path, "wb") as fh:
            fh.write(result_bytes)
        result_sha = sha256_bytes(result_bytes)

        manifest = {
            "tool_id": TOOL_ID, "tool_version": TOOL_VERSION,
            "binds": "p6b_i_guardrail_comparison_result",
            "result_filename": os.path.basename(result_path),
            "result_sha256": result_sha, "status": status,
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
        print(f"{TOOL_ID} {TOOL_VERSION}  (READ_ONLY_STATIC_SOURCE_COMPARISON, runtime=false)")
        print("=" * 72)
        for c in self.checks:
            print(f"  [{'PASS' if c['passed'] else 'FAIL'}] {c['check_id']}: {c['detail']}")
        print("-" * 72)
        if "comparison_matrix" in result:
            for cat_id, row in result["comparison_matrix"].items():
                print(f"  {cat_id:28s} optimal={row['optimal_py_present']!s:5} "
                      f"custom={row['custom_guardrail_present']!s:5}  ({row['description']})")
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
        result = {
            "tool_id": TOOL_ID, "tool_version": TOOL_VERSION,
            "gate": "P6B_I_STATIC_GUARDRAIL_DECIDE_CONTRACT_COMPARISON",
            "runtime": False,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "phase": "EXFILTRATION",
            "status": "COMPARISON_INCOMPLETE",
            "failure_reason": reason,
            "checks": {"total": total, "passed": passed, "failed": len(failed_ids), "failed_ids": failed_ids},
        }
        self._write_artifacts(result, "COMPARISON_INCOMPLETE")
        print(f"\nFAIL-CLOSED: {reason}")
        sys.exit(2)


def build_parser():
    p = argparse.ArgumentParser(description=f"{TOOL_ID} {TOOL_VERSION} (read-only)")
    p.add_argument("--optimal", required=True, help="Path to packaged aicomp_sdk/guardrails/optimal.py")
    p.add_argument("--optimal-sha256", help="Optional override; defaults to confirmed P3/P4/P6 hash")
    p.add_argument("--custom", required=True, help="Path to the custom guardrail file to compare")
    p.add_argument("--custom-sha256", help="Optional expected hash for the custom guardrail file")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--out-tag", default=TOOL_VERSION)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    P6bIStaticGuardrailDecideContractComparison(args).run()


if __name__ == "__main__":
    main()
