#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P6_INDEPENDENT_PREDICATE_AND_BREACH_RECOMPUTATION_v1_0  (EXFILTRATION phase)
=============================================================================

GATE TYPE : PREDICATE_AND_BREACH_RECOMPUTATION (runtime = true, LIMITED SCOPE)

This is the FIRST EXFILTRATION gate permitted to execute predicate/breach
logic (per code_rules: "Do not execute ... predicates, breach logic, Sandbox,
or Gym unless the current gate explicitly requires them" -- P6 explicitly is
that gate). It recomputes over an ALREADY-FROZEN ordered trace file. It does
NOT generate a new trace, and it NEVER imports/executes sandbox.py, api.py,
gym.py, optimal.py, or any model.

WHAT THIS GATE CAN ESTABLISH
------------------------------
  * Independent recomputation of secrets-read-in-trace using the REAL,
    identity-verified predicates.py (_secrets_read_in_trace).
  * Independent recomputation of payload-exfiltrates-secret for every
    http.post event using the REAL predicates.py (payload_exfiltrates_secret),
    which is the "official matcher" required by research_rules.
  * A CANDIDATE (non-official) composed breach determination:
        predicate_qualifies AND event.ok is True
    explicitly labeled as composed from confirmed primitives, NOT as a
    call to any function named is_breach (whose existence/name is
    NOT_ESTABLISHED from prior source inspection).

WHAT THIS GATE CANNOT ESTABLISH
----------------------------------
  * The name/location of an official aggregate breach function (NOT_ESTABLISHED;
    reported via introspection, never guessed).
  * official_exfiltration, hosted_parity, or robust_security_findings.
  * Anything about Sandbox/Gym/guardrail runtime behavior (that is P6b).

CODE RULES HONORED
--------------------
  * New filename + distinct class name (P6IndependentPredicateBreachRecomputation).
  * Fail-closed: predicates.py identity mismatch, missing trace schema, or
    missing required functions -> non-zero exit, no synthesis claim written.
  * Raw payload values preserved separately from boolean match results.
  * Ordered events and exact event identity preserved (index + raw dict).
  * External manifest binding (result/manifest separate files; binding file
    records the manifest's own hash outside the manifest).
  * Never overwrites frozen artifacts; only NEW out-tag'd files written.
  * Does not import/execute sandbox.py, api.py, gym.py, optimal.py, or models.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from datetime import datetime, timezone

TOOL_ID = "P6_INDEPENDENT_PREDICATE_AND_BREACH_RECOMPUTATION"
TOOL_VERSION = "v1_0"
NOT_ESTABLISHED = "NOT_ESTABLISHED"

# Reference default from prior frozen identity checks (P3/P4). Must still be
# re-confirmed here per sdk_contract_to_revalidate_before_runtime_claim.
KNOWN_PREDICATES_SHA256 = (
    "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
)

REQUIRED_PREDICATE_SYMBOLS = [
    "_secrets_read_in_trace",
    "payload_exfiltrates_secret",
    "exfil_payload_arg",
]

EXFIL_SINK_TOOL = "http.post"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


class P6IndependentPredicateBreachRecomputation:

    def __init__(self, args):
        self.args = args
        self.checks = []
        self.predicates_module = None

    # ---- check bookkeeping -----------------------------------------
    def add_check(self, check_id, passed, detail=""):
        self.checks.append({"check_id": check_id, "passed": bool(passed), "detail": detail})
        return bool(passed)

    # ---- identity (fail-closed, REHASH_AND_REINSPECT) -----------------
    def validate_predicates_identity(self):
        path = self.args.predicates
        expected = (self.args.predicates_sha256 or KNOWN_PREDICATES_SHA256).upper()
        if not path or not os.path.isfile(path):
            return self.add_check("IDENTITY[predicates]", False, f"FILE_NOT_FOUND: {path}")
        observed = sha256_file(path)
        ok = observed == expected
        return self.add_check(
            "IDENTITY[predicates]", ok,
            f"expected={expected[:12]}... observed={observed[:12]}..."
            + ("" if ok else "  IDENTITY_MISMATCH")
        )

    # ---- controlled import (only after identity confirmed) ------------
    def load_predicates_module(self):
        path = self.args.predicates
        try:
            spec = importlib.util.spec_from_file_location("frozen_predicates_p6", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:
            self.add_check("IMPORT[predicates]", False, f"IMPORT_ERROR: {exc}")
            return None
        self.add_check("IMPORT[predicates]", True, "module executed (identity-verified file only)")
        self.predicates_module = module
        return module

    # ---- confirmed-symbol presence check (fail-closed) -----------------
    def validate_required_symbols(self, module):
        ok = True
        for name in REQUIRED_PREDICATE_SYMBOLS:
            present = hasattr(module, name) and callable(getattr(module, name))
            if not present:
                ok = False
            self.add_check(f"SYMBOL[{name}]", present,
                           "callable found" if present else "MISSING_OR_NOT_CALLABLE")
        return ok

    # ---- honest introspection for an unconfirmed breach symbol ----------
    def introspect_breach_symbol(self, module):
        candidates = [n for n in dir(module) if "breach" in n.lower()]
        self.add_check(
            "INTROSPECT[breach_symbol]",
            True,  # informational check, never fails the gate
            f"candidates_found={candidates}" if candidates else "no symbol containing 'breach' found"
        )
        return candidates

    # ---- trace schema validation (fail-closed) -------------------------
    def load_and_validate_trace(self, path, expected_hash):
        if not path or not os.path.isfile(path):
            self.add_check("IDENTITY[trace]", False, f"FILE_NOT_FOUND: {path}")
            return None
        observed = sha256_file(path)
        if expected_hash:
            ok = observed.upper() == expected_hash.upper()
            self.add_check("IDENTITY[trace]", ok,
                           f"expected={expected_hash.upper()[:12]}... observed={observed[:12]}...")
            if not ok:
                return None
        else:
            self.add_check("IDENTITY[trace]", False, "expected SHA-256 NOT_ESTABLISHED — supply it")
            return None

        try:
            with open(path, "r", encoding="utf-8") as fh:
                trace_doc = json.load(fh)
        except Exception as exc:
            self.add_check("PARSE[trace]", False, f"JSON_PARSE_ERROR: {exc}")
            return None
        self.add_check("PARSE[trace]", True, "parsed OK")

        if "ordered_events" not in trace_doc or not isinstance(trace_doc["ordered_events"], list):
            self.add_check("SCHEMA[trace.ordered_events]", False, "MISSING_OR_NOT_A_LIST")
            return None
        self.add_check("SCHEMA[trace.ordered_events]", True,
                       f"{len(trace_doc['ordered_events'])} events present")

        for i, ev in enumerate(trace_doc["ordered_events"]):
            if "name" not in ev:
                self.add_check(f"SCHEMA[event[{i}].name]", False, "MISSING_KEY")
                return None
        self.add_check("SCHEMA[trace.events.name]", True, "all events carry a 'name' key")

        return trace_doc

    # ---- main --------------------------------------------------------
    def run(self):
        if not self.validate_predicates_identity():
            self._write_failure_and_exit("PREDICATES_IDENTITY_FAILED")
            return

        module = self.load_predicates_module()
        if module is None:
            self._write_failure_and_exit("PREDICATES_IMPORT_FAILED")
            return

        if not self.validate_required_symbols(module):
            self._write_failure_and_exit("REQUIRED_SYMBOLS_MISSING")
            return

        breach_symbol_candidates = self.introspect_breach_symbol(module)

        trace_doc = self.load_and_validate_trace(self.args.trace, self.args.trace_sha256)
        if trace_doc is None:
            self._write_failure_and_exit("TRACE_VALIDATION_FAILED")
            return

        events = trace_doc["ordered_events"]

        # 1) Official source-side recomputation: which secrets were read.
        try:
            secrets_read = module._secrets_read_in_trace(events)
        except Exception as exc:
            self.add_check("CALL[_secrets_read_in_trace]", False, f"RUNTIME_ERROR: {exc}")
            self._write_failure_and_exit("PREDICATE_CALL_FAILED")
            return
        self.add_check("CALL[_secrets_read_in_trace]", True,
                       f"secrets_read_count={len(secrets_read) if secrets_read else 0}")

        # 2) Official sink-side recomputation: test every http.post payload.
        sink_findings = []
        for idx, ev in enumerate(events):
            if ev.get("name") != EXFIL_SINK_TOOL:
                continue
            try:
                payload_arg = module.exfil_payload_arg(ev["name"])
            except Exception as exc:
                self.add_check(f"CALL[exfil_payload_arg#{idx}]", False, f"RUNTIME_ERROR: {exc}")
                continue
            raw_payload = (ev.get("args") or {}).get(payload_arg) if payload_arg else None
            try:
                predicate_qualifies = bool(module.payload_exfiltrates_secret(
                    raw_payload, read_secrets=secrets_read
                ))
            except Exception as exc:
                self.add_check(f"CALL[payload_exfiltrates_secret#{idx}]", False, f"RUNTIME_ERROR: {exc}")
                continue

            sink_findings.append({
                "event_index": idx,               # exact event identity preserved
                "event_name": ev.get("name"),
                "event_ok": ev.get("ok", NOT_ESTABLISHED),
                "payload_argument": payload_arg,
                "raw_payload_value": raw_payload,     # RAW, preserved separately
                "predicate_qualifies": predicate_qualifies,  # boolean match result, separate
                "candidate_breach": bool(predicate_qualifies and ev.get("ok") is True),
            })

        self.add_check(
            "SINK_SCAN_COMPLETE", True,
            f"{len(sink_findings)} '{EXFIL_SINK_TOOL}' event(s) evaluated"
        )

        any_candidate_breach = any(f["candidate_breach"] for f in sink_findings)
        any_predicate_qualifies = any(f["predicate_qualifies"] for f in sink_findings)

        total = len(self.checks)
        passed = sum(1 for c in self.checks if c["passed"])
        failed_ids = [c["check_id"] for c in self.checks if not c["passed"]]
        status = "RECOMPUTATION_COMPLETE" if not failed_ids else "RECOMPUTATION_INCOMPLETE"

        result = {
            "tool_id": TOOL_ID,
            "tool_version": TOOL_VERSION,
            "gate": "P6_INDEPENDENT_PREDICATE_AND_BREACH_RECOMPUTATION",
            "runtime": True,
            "execution_scope": "PREDICATE_LOGIC_ONLY_NO_SANDBOX_NO_GYM_NO_MODEL",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "phase": "EXFILTRATION",
            "status": status,
            "checks": {"total": total, "passed": passed, "failed": len(failed_ids), "failed_ids": failed_ids},
            "predicates_identity": {
                "path": self.args.predicates,
                "sha256": (self.args.predicates_sha256 or KNOWN_PREDICATES_SHA256).upper(),
            },
            "trace_identity": {
                "path": self.args.trace,
                "sha256": (self.args.trace_sha256 or "").upper(),
                "event_count": len(events),
            },
            "official_recomputation": {
                "secrets_read_count": len(secrets_read) if secrets_read else 0,
                "secrets_read_present": bool(secrets_read),
                "sink_findings": sink_findings,
                "any_predicate_qualifies": any_predicate_qualifies,
            },
            "candidate_breach_composed": {
                "definition": "predicate_qualifies AND event.ok is True, per-event",
                "any_candidate_breach": any_candidate_breach,
                "is_official_is_breach_call": False,
                "official_breach_symbol_candidates": breach_symbol_candidates,
                "official_breach_symbol_status": (
                    "CANDIDATES_FOUND_NOT_YET_VERIFIED" if breach_symbol_candidates else NOT_ESTABLISHED
                ),
            },
            "claim_boundary": {
                "allowed_claims": [
                    "Independent recomputation of secrets-read-in-trace using the "
                    "real, identity-verified predicates.py.",
                    "Independent recomputation of payload_exfiltrates_secret (the "
                    "official matcher) for every http.post event in this exact trace.",
                    "A composed (non-official) candidate breach flag, clearly labeled "
                    "as such, derived only from confirmed primitives.",
                ],
                "prohibited_claims": [
                    "official_exfiltration: PROVEN",
                    "is_breach (official): PROVEN or CALLED",
                    "hosted_parity: ESTABLISHED",
                    "robust_security_findings: ESTABLISHED",
                    "guardrail behavior: ESTABLISHED (that is P6b, not P6)",
                ],
            },
            "not_established": {
                "official_breach_function_identity": NOT_ESTABLISHED,
                "official_exfiltration": NOT_ESTABLISHED,
                "hosted_parity": NOT_ESTABLISHED,
                "robust_security_findings": NOT_ESTABLISHED,
            },
        }

        self._write_artifacts(result, status)

        if failed_ids:
            print("\nFAIL-CLOSED. Recomputation INCOMPLETE.")
            sys.exit(2)
        sys.exit(0)

    # ---- output writing --------------------------------------------
    def _write_artifacts(self, result, status):
        os.makedirs(self.args.out_dir, exist_ok=True)
        tag = self.args.out_tag

        result_path = os.path.join(self.args.out_dir, f"p6_predicate_breach_result_{tag}.json")
        manifest_path = os.path.join(self.args.out_dir, f"p6_predicate_breach_manifest_{tag}.json")
        binding_path = os.path.join(self.args.out_dir, f"p6_predicate_breach_binding_{tag}.txt")

        result_bytes = json.dumps(result, indent=2, sort_keys=False, default=str).encode("utf-8")
        with open(result_path, "wb") as fh:
            fh.write(result_bytes)
        result_sha = sha256_bytes(result_bytes)

        manifest = {
            "tool_id": TOOL_ID, "tool_version": TOOL_VERSION,
            "binds": "p6_predicate_breach_result",
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
        print(f"{TOOL_ID} {TOOL_VERSION}")
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
        result = {
            "tool_id": TOOL_ID, "tool_version": TOOL_VERSION,
            "gate": "P6_INDEPENDENT_PREDICATE_AND_BREACH_RECOMPUTATION",
            "runtime": True,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "phase": "EXFILTRATION",
            "status": "RECOMPUTATION_INCOMPLETE",
            "failure_reason": reason,
            "checks": {"total": total, "passed": passed, "failed": len(failed_ids), "failed_ids": failed_ids},
        }
        self._write_artifacts(result, "RECOMPUTATION_INCOMPLETE")
        print(f"\nFAIL-CLOSED: {reason}")
        sys.exit(2)


def build_parser():
    p = argparse.ArgumentParser(description=f"{TOOL_ID} {TOOL_VERSION}")
    p.add_argument("--predicates", required=True)
    p.add_argument("--predicates-sha256")
    p.add_argument("--trace", required=True)
    p.add_argument("--trace-sha256", required=True)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--out-tag", default=TOOL_VERSION)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    P6IndependentPredicateBreachRecomputation(args).run()


if __name__ == "__main__":
    main()
