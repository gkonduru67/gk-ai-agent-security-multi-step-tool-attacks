#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P3_V_AUTHORITATIVE_SOURCE_STATIC_INSPECTION  (EXFILTRATION phase)
================================================================

GATE TYPE      : READ_ONLY_STATIC_SOURCE_INSPECTION   (runtime = false)
WHAT IT CAN DO : Re-hash the SDK source files (REHASH_AND_REINSPECT), then
                 STATICALLY locate the symbols that define the EXFILTRATION
                 source-gating contract, and record for each candidate source
                 class (fs.read/secret.txt, web.open, email.read) whether the
                 symbol is PRESENT in the source-capture / predicate path.
WHAT IT CANNOT : Establish that any source "behaves the same" at runtime, prove
                 official exfiltration, or run any model/tool/predicate/sandbox/
                 gym. Static symbol presence != runtime behavior.

CODE RULES HONORED
------------------
  * Never overwrites frozen artifacts (SDK files opened read-only; only NEW
    output filenames are written).
  * New filename + distinct class name (P3VAuthoritativeSourceStaticInspection).
  * Default fail-closed: missing file / hash mismatch / unbound expected -> exit != 0.
  * Raw matched line text preserved separately from any classification note.
  * External manifest binding (result and manifest separate; no self-hashing).
  * NOT_ESTABLISHED left explicit; unknown hashes never invented.
"""

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import sys

TOOL_ID = "P3_V_AUTHORITATIVE_SOURCE_STATIC_INSPECTION"
TOOL_VERSION = "v1_0"
NOT_ESTABLISHED = "NOT_ESTABLISHED"

# ---------------------------------------------------------------------------
# SDK expected hashes recoverable from the FROZEN R2 identity-check CSV.
# Treat as REFERENCE DEFAULTS the user must re-confirm; api.py / gym.py absent
# from that snippet -> NOT_ESTABLISHED (must be supplied on CLI).
# ---------------------------------------------------------------------------
KNOWN_SDK = {
    "predicates": "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37",
    "sandbox":    "B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0",
    "optimal":    "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED",
    "api":        None,   # NOT_ESTABLISHED
    "gym":        None,   # NOT_ESTABLISHED
}

# Symbol pattern set. Each entry: (probe_id, regex, source_class_or_None).
# source_class marks patterns whose presence/absence maps to a candidate source.
PROBES = [
    ("SECRET_FILENAME",         r"\bSECRET_FILENAME\b",                   None),
    ("_is_secret_path",         r"\b_is_secret_path\b",                   None),
    ("is_protected_secret_path",r"\bis_protected_secret_path\b",          None),
    ("read_capture_hook",       r"HookResult|read[_-]?capture|append.*ledger", None),
    ("SRC_fs_read",             r"\bfs\.read\b|\bfs_read\b|['\"]fs\.read['\"]",   "fs.read"),
    ("SRC_web_open",            r"\bweb\.open\b|\bweb_open\b|['\"]web\.open['\"]", "web.open"),
    ("SRC_email_read",          r"\bemail\.read\b|\bemail_read\b|['\"]email\.read['\"]", "email.read"),
    ("SINK_http_post",          r"\bhttp\.post\b|\bhttp_post\b|['\"]http\.post['\"]",    None),
]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


class P3VAuthoritativeSourceStaticInspection:
    def __init__(self, args):
        self.args = args
        self.checks = []            # (check_id, passed, detail)
        self.identity_records = []  # per SDK file identity binding
        self.scan_records = []      # per (file, probe) raw matches

    def _check(self, cid, passed, detail=""):
        self.checks.append((cid, bool(passed), detail))
        return bool(passed)

    def _bind_identity(self, label, path, expected):
        rec = {"label": label, "path": path,
               "expected_sha256": expected.upper() if expected else NOT_ESTABLISHED,
               "computed_sha256": NOT_ESTABLISHED, "match": False, "status": NOT_ESTABLISHED}
        if not path:
            rec["status"] = "INPUT_ABSENT"
            self._check(f"IDENTITY[{label}]", False, "path not supplied")
            self.identity_records.append(rec); return rec
        if not os.path.isfile(path):
            rec["status"] = "FILE_NOT_FOUND"
            self._check(f"IDENTITY[{label}]", False, f"not found: {path}")
            self.identity_records.append(rec); return rec
        computed = sha256_file(path)
        rec["computed_sha256"] = computed
        if not expected:
            rec["status"] = "EXPECTED_HASH_NOT_ESTABLISHED"
            self._check(f"IDENTITY[{label}]", False,
                        "expected SHA-256 NOT_ESTABLISHED — supply it to inspect")
            self.identity_records.append(rec); return rec
        rec["match"] = (computed == expected.upper())
        rec["status"] = "MATCH" if rec["match"] else "IDENTITY_MISMATCH"
        self._check(f"IDENTITY[{label}]", rec["match"],
                    rec["status"] + f" (exp {expected.upper()[:12]}…, got {computed[:12]}…)")
        self.identity_records.append(rec); return rec

    def _scan_file(self, label, path):
        """Static grep. Records raw matched lines; performs NO interpretation."""
        if not path or not os.path.isfile(path):
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except Exception as exc:
            self._check(f"SCAN[{label}]", False, f"read error: {exc}")
            return
        for probe_id, pattern, src_class in PROBES:
            rx = re.compile(pattern)
            hits = []
            for i, raw in enumerate(lines, start=1):
                if rx.search(raw):
                    hits.append({"lineno": i, "raw": raw.rstrip("\n")})  # RAW preserved
            self.scan_records.append({
                "file": label, "probe_id": probe_id, "source_class": src_class,
                "match_count": len(hits), "matches": hits,
            })

    def _classify_sources(self):
        """Presence/absence ONLY. Never asserts behavior."""
        classes = {}
        for rec in self.scan_records:
            sc = rec["source_class"]
            if sc is None:
                continue
            present = rec["match_count"] > 0
            entry = classes.setdefault(sc, {"present_in_files": [], "total_matches": 0})
            if present:
                entry["present_in_files"].append(rec["file"])
                entry["total_matches"] += rec["match_count"]
        # Finalize verdicts (static presence, not behavior).
        out = {}
        for sc in ("fs.read", "web.open", "email.read"):
            e = classes.get(sc, {"present_in_files": [], "total_matches": 0})
            if e["total_matches"] > 0:
                verdict = "SYMBOL_PRESENT_IN_INSPECTED_SOURCE"
            else:
                verdict = "SYMBOL_NOT_FOUND_IN_INSPECTED_SOURCE"
            out[sc] = {
                "present_in_files": e["present_in_files"],
                "total_matches": e["total_matches"],
                "static_verdict": verdict,
                "runtime_behavior": NOT_ESTABLISHED,   # explicit: static != runtime
            }
        return out

    def _claim_boundary(self):
        return {
            "allowed_claims": [
                "Static presence/absence of source symbols (fs.read/web.open/email.read) "
                "in the inspected SDK files.",
                "The read-capture name gate anchors on SECRET_FILENAME=='secret.txt' "
                "(re-confirmed by symbol location).",
            ],
            "prohibited_claims": [
                "web.open source behaves the same as secret.txt fs.read",   # runtime
                "email.read is an in-contract EXFILTRATION source",          # runtime/contract
                "official_exfiltration via an authoritative source: PROVEN",
                "hosted_parity: ESTABLISHED",
            ],
            "frozen_priors_carried": {
                "expected_source_requirement": "Successful fs.read in the same trace",
                "email_boundary": "email.send belongs to CONFUSED_DEPUTY, not EXFILTRATION",
                "official_exfiltration": "NOT_ESTABLISHED",
                "hosted_parity": "NOT_ESTABLISHED",
            },
        }

    def run(self):
        sdk = [
            ("predicates", self.args.predicates, self.args.predicates_sha256 or KNOWN_SDK["predicates"]),
            ("sandbox",    self.args.sandbox,    self.args.sandbox_sha256    or KNOWN_SDK["sandbox"]),
            ("api",        self.args.api,        self.args.api_sha256        or KNOWN_SDK["api"]),
            ("gym",        self.args.gym,        self.args.gym_sha256        or KNOWN_SDK["gym"]),
            ("optimal",    self.args.optimal,    self.args.optimal_sha256    or KNOWN_SDK["optimal"]),
        ]
        # 1) Rehash-and-reinspect (fail-closed).
        for label, path, expected in sdk:
            self._bind_identity(label, path, expected)
        # 2) Static scan ONLY on identity-MATCHED files (do not scan unverified bytes).
        matched = {r["label"] for r in self.identity_records if r["match"]}
        for label, path, _ in sdk:
            if label in matched:
                self._scan_file(label, path)
            else:
                self._check(f"SCAN[{label}]", False, "skipped — identity not MATCHED")

        source_classification = self._classify_sources()
        # 3) Contract sanity: secret.txt anchor must still be present somewhere.
        anchor_present = any(r["probe_id"] == "SECRET_FILENAME" and r["match_count"] > 0
                             for r in self.scan_records)
        self._check("SECRET_TXT_ANCHOR_PRESENT", anchor_present,
                    "SECRET_FILENAME symbol located in inspected source" if anchor_present
                    else "SECRET_FILENAME not located (unexpected)")

        cb = self._claim_boundary()
        self._check("CLAIM_BOUNDARY_HELD",
                    len(cb["prohibited_claims"]) == 4 and
                    cb["frozen_priors_carried"]["official_exfiltration"] == "NOT_ESTABLISHED",
                    "prohibited-claim list and NOT_ESTABLISHED priors preserved")

        total = len(self.checks)
        passed = sum(1 for _, ok, _ in self.checks if ok)
        failed_ids = [cid for cid, ok, _ in self.checks if not ok]
        status = "INSPECTION_COMPLETE" if not failed_ids else "INSPECTION_INCOMPLETE"

        synthesis = {
            "tool_id": TOOL_ID, "tool_version": TOOL_VERSION,
            "gate": "P3_V_AUTHORITATIVE_SOURCE_STATIC_INSPECTION",
            "execution_type": "READ_ONLY_STATIC_SOURCE_INSPECTION", "runtime": False,
            "generated_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "phase": "EXFILTRATION", "status": status,
            "checks": {"total": total, "passed": passed,
                       "failed": len(failed_ids), "failed_ids": failed_ids},
            "identity_bindings": self.identity_records,
            "source_symbol_scan": self.scan_records,
            "source_classification": source_classification,
            "claim_boundary": cb,
            "not_established": {
                "api_expected_sha256": "SUPPLIED" if self.args.api_sha256 else NOT_ESTABLISHED,
                "gym_expected_sha256": "SUPPLIED" if self.args.gym_sha256 else NOT_ESTABLISHED,
                "authoritative_source_runtime_behavior": NOT_ESTABLISHED,
                "official_exfiltration": NOT_ESTABLISHED,
                "hosted_parity": NOT_ESTABLISHED,
            },
        }

        os.makedirs(self.args.out_dir, exist_ok=True)
        tag = self.args.out_tag or TOOL_VERSION
        result_path = os.path.join(self.args.out_dir, f"p3_v_authoritative_source_result_{tag}.json")
        manifest_path = os.path.join(self.args.out_dir, f"p3_v_authoritative_source_manifest_{tag}.json")
        binding_path = os.path.join(self.args.out_dir, f"p3_v_authoritative_source_binding_{tag}.txt")

        result_bytes = json.dumps(synthesis, indent=2, sort_keys=False).encode("utf-8")
        with open(result_path, "wb") as fh:
            fh.write(result_bytes)
        result_hash = sha256_bytes(result_bytes)

        manifest = {"tool_id": TOOL_ID, "tool_version": TOOL_VERSION,
                    "binds": "p3_v_authoritative_source_result",
                    "result_filename": os.path.basename(result_path),
                    "result_sha256": result_hash, "status": status}
        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=False).encode("utf-8")
        with open(manifest_path, "wb") as fh:
            fh.write(manifest_bytes)
        manifest_hash = sha256_bytes(manifest_bytes)

        with open(binding_path, "w", encoding="utf-8") as fh:
            fh.write(f"manifest_filename={os.path.basename(manifest_path)}\n")
            fh.write(f"manifest_sha256={manifest_hash}\n")
            fh.write(f"result_sha256={result_hash}\n")

        print("=" * 72)
        print(f"{TOOL_ID} {TOOL_VERSION}  (READ_ONLY_STATIC_SOURCE_INSPECTION, runtime=false)")
        print("=" * 72)
        for cid, ok, detail in self.checks:
            print(f"  [{'PASS' if ok else 'FAIL'}] {cid}: {detail}")
        print("-" * 72)
        for sc, info in source_classification.items():
            print(f"  SOURCE {sc:12s}: {info['static_verdict']} "
                  f"(matches={info['total_matches']}, runtime={info['runtime_behavior']})")
        print("-" * 72)
        print(f"  checks: total={total} passed={passed} failed={len(failed_ids)}")
        print(f"  failed_ids: {failed_ids}")
        print(f"  status: {status}")
        print("-" * 72)
        print(f"  result   : {result_path}\n             sha256={result_hash}")
        print(f"  manifest : {manifest_path}\n             sha256={manifest_hash}")
        print(f"  binding  : {binding_path}")
        print("=" * 72)

        if failed_ids:
            print("\nFAIL-CLOSED. Inspection INCOMPLETE. Read-only discovery for unbound inputs:")
            if not (self.args.api and self.args.api_sha256):
                print('  Get-FileHash -Algorithm SHA256 "<...>\\aicomp_sdk\\core\\env\\api.py"')
            if not (self.args.gym and self.args.gym_sha256):
                print('  Get-FileHash -Algorithm SHA256 "<...>\\aicomp_sdk\\core\\env\\gym.py"')
            return 2
        return 0


def build_parser():
    p = argparse.ArgumentParser(description=f"{TOOL_ID} {TOOL_VERSION} (read-only)")
    p.add_argument("--predicates"); p.add_argument("--predicates-sha256")
    p.add_argument("--sandbox");    p.add_argument("--sandbox-sha256")
    p.add_argument("--api");        p.add_argument("--api-sha256")
    p.add_argument("--gym");        p.add_argument("--gym-sha256")
    p.add_argument("--optimal");    p.add_argument("--optimal-sha256")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--out-tag", default=TOOL_VERSION)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return P3VAuthoritativeSourceStaticInspection(args).run()


if __name__ == "__main__":
    sys.exit(main())
