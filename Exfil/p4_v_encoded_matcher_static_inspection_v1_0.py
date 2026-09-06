#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
P4_V_ENCODED_PAYLOAD_MATCHER_STATIC_INSPECTION_v1_0

READ ONLY
RUNTIME = FALSE

Scientific Purpose
------------------
Inspect predicates.py and related EXFILTRATION matcher contract source
for evidence of:

- encoded payload handling
- decode paths
- normalization paths
- SECRET_MARKER handling
- SECRET_FILENAME handling
- http.post sink matching

This gate DOES NOT:
- execute models
- execute predicates
- execute Sandbox
- execute Gym
- execute tools
- establish EXFILTRATION
- establish BREACH
- establish hosted parity

Static source evidence only.
"""

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone

TOOL_ID = "P4_V_ENCODED_PAYLOAD_MATCHER_STATIC_INSPECTION"
TOOL_VERSION = "v1_0"

EXPECTED_PREDICATES_SHA256 = (
    "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
)

NOT_ESTABLISHED = "NOT_ESTABLISHED"

SEARCH_PATTERNS = [
    "SECRET_MARKER",
    "SECRET_FILENAME",
    "base64",
    "b64decode",
    "urlsafe_b64decode",
    "decode(",
    "encode(",
    "hex(",
    ".hex(",
    "fromhex",
    "unhexlify",
    "normalize",
    "normalized",
    "payload",
    "http.post",
    "marker",
]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest().upper()


class P4EncodedPayloadMatcherInspection:

    def __init__(self, args):
        self.args = args
        self.checks = []

    def check(self, cid, passed, detail):
        self.checks.append({
            "check_id": cid,
            "passed": bool(passed),
            "detail": detail
        })

    def run(self):

        actual_sha = sha256_file(self.args.predicates)

        self.check(
            "IDENTITY_PREDICATES",
            actual_sha == EXPECTED_PREDICATES_SHA256,
            f"expected={EXPECTED_PREDICATES_SHA256} observed={actual_sha}"
        )

        if actual_sha != EXPECTED_PREDICATES_SHA256:
            raise SystemExit(
                "FAIL_CLOSED: predicates.py identity mismatch"
            )

        findings = []

        with open(
            self.args.predicates,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as f:
            lines = f.readlines()

        for lineno, raw_line in enumerate(lines, start=1):

            for pattern in SEARCH_PATTERNS:

                if pattern in raw_line:

                    findings.append({
                        "pattern": pattern,
                        "line_number": lineno,
                        "raw_line": raw_line.rstrip("\n")
                    })

        classification = {

            "decode_path_present":
                any(
                    x["pattern"] in (
                        "base64",
                        "b64decode",
                        "urlsafe_b64decode",
                        "decode(",
                        "fromhex",
                        "unhexlify"
                    )
                    for x in findings
                ),

            "normalization_present":
                any(
                    x["pattern"] in (
                        "normalize",
                        "normalized"
                    )
                    for x in findings
                ),

            "secret_marker_present":
                any(
                    x["pattern"] == "SECRET_MARKER"
                    for x in findings
                ),

            "secret_filename_present":
                any(
                    x["pattern"] == "SECRET_FILENAME"
                    for x in findings
                ),

            "http_post_present":
                any(
                    x["pattern"] == "http.post"
                    for x in findings
                ),
        }

        total_checks = len(self.checks)
        passed_checks = sum(
            1 for c in self.checks if c["passed"]
        )
        failed_checks = total_checks - passed_checks

        result = {

            "tool_id": TOOL_ID,
            "tool_version": TOOL_VERSION,
            "generated_utc":
                datetime.now(
                    timezone.utc
                ).isoformat(),

            "phase": "EXFILTRATION",
            "runtime": False,
            "execution_type":
                "READ_ONLY_STATIC_INSPECTION",

            "status": "INSPECTION_COMPLETE",

            "identity": {
                "predicates_sha256": actual_sha
            },

            "checks": {
                "total": total_checks,
                "passed": passed_checks,
                "failed": failed_checks,
                "failed_ids": [
                    c["check_id"]
                    for c in self.checks
                    if not c["passed"]
                ]
            },

            "raw_findings": findings,

            "classification": classification,

            "claim_boundary": {

                "allowed_claims": [

                    "decode logic present",

                    "decode logic absent",

                    "normalization present",

                    "normalization absent",

                    "secret marker present",

                    "secret marker absent",

                    "http.post matcher reference present",

                    "http.post matcher reference absent"
                ],

                "prohibited_claims": [

                    "encoded payload bypass proven",

                    "official exfiltration proven",

                    "breach proven",

                    "runtime bypass proven",

                    "hosted parity proven"
                ]
            },

            "not_established": {

                "official_exfiltration":
                    NOT_ESTABLISHED,

                "breach":
                    NOT_ESTABLISHED,

                "hosted_parity":
                    NOT_ESTABLISHED,

                "runtime_behavior":
                    NOT_ESTABLISHED
            }
        }

        os.makedirs(
            self.args.out_dir,
            exist_ok=True
        )

        tag = self.args.out_tag

        result_file = os.path.join(
            self.args.out_dir,
            f"p4_v_encoded_payload_result_{tag}.json"
        )

        with open(
            result_file,
            "w",
            encoding="utf-8"
        ) as f:
            json.dump(
                result,
                f,
                indent=2
            )

        result_sha = sha256_file(result_file)

        manifest = {

            "tool_id": TOOL_ID,

            "tool_version": TOOL_VERSION,

            "result_filename":
                os.path.basename(result_file),

            "result_sha256":
                result_sha,

            "status":
                result["status"]
        }

        manifest_file = os.path.join(
            self.args.out_dir,
            f"p4_v_encoded_payload_manifest_{tag}.json"
        )

        with open(
            manifest_file,
            "w",
            encoding="utf-8"
        ) as f:
            json.dump(
                manifest,
                f,
                indent=2
            )

        manifest_sha = sha256_file(
            manifest_file
        )

        binding_file = os.path.join(
            self.args.out_dir,
            f"p4_v_encoded_payload_binding_{tag}.txt"
        )

        with open(
            binding_file,
            "w",
            encoding="utf-8"
        ) as f:

            f.write(
                f"manifest_filename={os.path.basename(manifest_file)}\n"
            )

            f.write(
                f"manifest_sha256={manifest_sha}\n"
            )

            f.write(
                f"result_sha256={result_sha}\n"
            )

        print("INSPECTION_COMPLETE")
        print(f"result_sha256={result_sha}")
        print(f"manifest_sha256={manifest_sha}")


def main():

    ap = argparse.ArgumentParser()

    ap.add_argument(
        "--predicates",
        required=True
    )

    ap.add_argument(
        "--out-dir",
        required=True
    )

    ap.add_argument(
        "--out-tag",
        default="v1_0"
    )

    args = ap.parse_args()

    runner = P4EncodedPayloadMatcherInspection(
        args
    )

    runner.run()


if __name__ == "__main__":
    main()