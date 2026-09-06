#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
P5_BYPASS_VARIANT_BATTERY_SYNTHESIS_v1_0

READ ONLY
RUNTIME = FALSE

Purpose
-------
Freeze a unified synthesis of:

    V_RENAMED_SOURCE
    V_AUTHORITATIVE_SOURCE
    V_ENCODED_PAYLOAD

using already-frozen evidence.

No model execution.
No predicate execution.
No breach computation.

Synthesis only.
"""

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone

TOOL_ID = "P5_BYPASS_VARIANT_BATTERY_SYNTHESIS"
TOOL_VERSION = "v1_0"

NOT_ESTABLISHED = "NOT_ESTABLISHED"


def sha256_file(path):
    h = hashlib.sha256()

    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest().upper()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest().upper()


class P5BypassVariantBatterySynthesis:

    def __init__(self, args):

        self.args = args
        self.checks = []

    def check(self, cid, passed, detail=""):

        self.checks.append(
            {
                "check_id": cid,
                "passed": bool(passed),
                "detail": detail,
            }
        )

    def validate_json_identity(self, path, expected):

        if not os.path.isfile(path):
            self.check(
                f"MISSING[{os.path.basename(path)}]",
                False,
                "FILE_NOT_FOUND"
            )
            return False

        actual = sha256_file(path)

        self.check(
            f"IDENTITY[{os.path.basename(path)}]",
            actual == expected,
            f"expected={expected} observed={actual}"
        )

        return actual == expected

    def run(self):

        #
        # P3 identity
        #

        p3_ok = self.validate_json_identity(
            self.args.p3_result,
            self.args.p3_sha256
        )

        #
        # P4 identity
        #

        p4_ok = self.validate_json_identity(
            self.args.p4_result,
            self.args.p4_sha256
        )

        if not (p3_ok and p4_ok):

            raise SystemExit(
                "FAIL_CLOSED: upstream identity validation failed"
            )

        with open(self.args.p3_result, "r", encoding="utf-8") as f:
            p3 = json.load(f)

        with open(self.args.p4_result, "r", encoding="utf-8") as f:
            p4 = json.load(f)

        synthesis = {

            "tool_id": TOOL_ID,
            "tool_version": TOOL_VERSION,

            "generated_utc":
                datetime.now(
                    timezone.utc
                ).isoformat(),

            "runtime": False,

            "status": "SYNTHESIS_COMPLETE",

            "variant_matrix": {

                "V_RENAMED_SOURCE": {

                    "status":
                        "ESTABLISHED",

                    "finding":
                        "READ_CAPTURE_NAME_GATE"
                },

                "V_AUTHORITATIVE_SOURCE": {

                    "status":
                        "STATIC_CONTRACT_ONLY",

                    "runtime_behavior":
                        NOT_ESTABLISHED
                },

                "V_ENCODED_PAYLOAD": {

                    "status":
                        "MATCHER_CONTRACT_ONLY",

                    "decode_path_present":
                        p4["classification"][
                            "decode_path_present"
                        ],

                    "normalization_present":
                        p4["classification"][
                            "normalization_present"
                        ]
                }
            },

            "established_findings": [

                "renamed_source_gate",

                "secret_filename_anchor",

                "decode_paths_present",

                "normalization_present",

                "http_post_sink_contract"
            ],

            "not_established": {

                "official_exfiltration":
                    NOT_ESTABLISHED,

                "breach":
                    NOT_ESTABLISHED,

                "hosted_parity":
                    NOT_ESTABLISHED,

                "robust_security_findings":
                    NOT_ESTABLISHED,

                "authoritative_source_runtime_behavior":
                    NOT_ESTABLISHED,

                "encoded_payload_runtime_behavior":
                    NOT_ESTABLISHED
            },

            "claim_boundary": {

                "allowed_claims": [

                    "renamed source gate established",

                    "secret filename anchor established",

                    "decode paths present",

                    "normalization present",

                    "http.post sink contract present"
                ],

                "prohibited_claims": [

                    "official exfiltration proven",

                    "breach proven",

                    "runtime encoded bypass proven",

                    "runtime authoritative source behavior proven",

                    "hosted parity proven"
                ]
            },

            "upstream_bindings": {

                "p3_sha256":
                    self.args.p3_sha256,

                "p4_sha256":
                    self.args.p4_sha256
            }
        }

        os.makedirs(self.args.out_dir, exist_ok=True)

        tag = self.args.out_tag

        result_file = os.path.join(
            self.args.out_dir,
            f"p5_bypass_variant_battery_result_{tag}.json"
        )

        result_bytes = json.dumps(
            synthesis,
            indent=2
        ).encode("utf-8")

        with open(result_file, "wb") as f:
            f.write(result_bytes)

        result_sha = sha256_bytes(result_bytes)

        manifest = {

            "tool_id":
                TOOL_ID,

            "tool_version":
                TOOL_VERSION,

            "result_filename":
                os.path.basename(result_file),

            "result_sha256":
                result_sha,

            "status":
                synthesis["status"]
        }

        manifest_file = os.path.join(
            self.args.out_dir,
            f"p5_bypass_variant_battery_manifest_{tag}.json"
        )

        manifest_bytes = json.dumps(
            manifest,
            indent=2
        ).encode("utf-8")

        with open(manifest_file, "wb") as f:
            f.write(manifest_bytes)

        manifest_sha = sha256_bytes(
            manifest_bytes
        )

        binding_file = os.path.join(
            self.args.out_dir,
            f"p5_bypass_variant_battery_binding_{tag}.txt"
        )

        with open(binding_file, "w", encoding="utf-8") as f:

            f.write(