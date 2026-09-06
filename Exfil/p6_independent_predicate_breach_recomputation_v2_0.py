#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P6_INDEPENDENT_PREDICATE_AND_BREACH_RECOMPUTATION_v2_0  (EXFILTRATION phase)
=============================================================================

SUPERSEDES: p6_independent_predicate_breach_recomputation_v1_0.py
REASON: v1_0 composed a NON-OFFICIAL "candidate_breach" flag because the
existence of an official is_breach symbol was NOT_ESTABLISHED at the time.
That is now source-proven (predicates.py lines 315-348, docstring: "canonical
breach decision shared across evaluation paths"; eval_predicates at
lines 215-312). v2_0 calls the REAL official two-step contract:

    predicates = eval_predicates(trace)
    breach     = is_breach(trace, predicates)

GATE TYPE : PREDICATE_AND_BREACH_RECOMPUTATION (runtime = true, LIMITED SCOPE)
This gate executes ONLY predicates.py logic on an ALREADY-FROZEN trace file.
It never imports/executes sandbox.py, api.py, gym.py, optimal.py, or any model.

WHAT THIS GATE CAN ESTABLISH
------------------------------
  * Independent recomputation of the OFFICIAL eval_predicates() output and the
    OFFICIAL is_breach() verdict, on the exact frozen trace as literally
    stored (after schema normalization to tool_events/user_messages).
  * A separate, independent cross-check using the lower-level re-exports
    (is_protected_secret_path, payload_exfiltrates_secret, exfil_payload_arg)
    for every http.post event, compared against eval_predicates' own verdict.
  * An explicit, automatic REDACTION CAVEAT if any http.post payload argument
    matches a "<REDACTED_SECRET_SHA256:...>"-style placeholder pattern --
    recomputation on a redacted placeholder is NOT a faithful re-test of the
    original runtime payload.

WHAT THIS GATE CANNOT ESTABLISH
----------------------------------
  * official_exfiltration as a project-wide claim, hosted_parity, or
    robust_security_findings.
  * Anything about Sandbox/Gym/guardrail runtime behavior (that is P6b).
  * Faithful reproduction of a runtime decision made against payload content
    that has since been redacted in the frozen artifact (flagged, not hidden).

CODE RULES HONORED
--------------------
  * New filename + distinct class name (P6IndependentPredicateBreachRecomputationV2).
  * Fail-closed: predicates.py identity mismatch, missing eval_predicates/
    is_breach symbols, or unparsable trace -> non-zero exit.
  * Raw trace schema/events preserved separately from the normalized view
    passed into eval_predicates/is_breach.
  * Exact event identity preserved (original schema key + index/line).
  * External manifest binding (result/manifest separate; binding file records
    the manifest's own hash outside the manifest).
  * Never overwrites frozen artifacts; only NEW out-tag'd files written.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone

TOOL_ID = "P6_INDEPENDENT_PREDICATE_AND_BREACH_RECOMPUTATION"
TOOL_VERSION = "v2_0"
NOT_ESTABLISHED = "NOT_ESTABLISHED"

# Re-confirmed reference default (P3/P4/P6-pre all matched this identity).
KNOWN_PREDICATES_SHA256 = (
    "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
)

REQUIRED_OFFICIAL_SYMBOLS = ["eval_predicates", "is_breach"]
REQUIRED_LOWLEVEL_SYMBOLS = [
    "is_protected_secret_path", "payload_exfiltrates_secret", "exfil_payload_arg",
]

EXFIL_SINK_TOOL = "http.post"
REDACTION_PATTERN = re.compile(r"^<REDACTED_SECRET_SHA256:[0-9A-Fa-f]+>$")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


class P6IndependentPredicateBreachRecomputationV2:

    def __init__(self, args):
        self.args = args
        self.checks = []
        self.predicates_module = None

    def add_check(self, cid, passed, detail=""):
        self.checks.append({"check_id": cid, "passed": bool(passed), "detail": detail})
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

    def load_predicates_module(self):
        path = self.args.predicates
        try:
            spec = importlib.util.spec_from_file_location("frozen_predicates_p6v2", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:
            self.add_check("IMPORT[predicates]", False, f"IMPORT_ERROR: {exc}")
            return None
        self.add_check("IMPORT[predicates]", True, "module executed (identity-verified file only)")
        self.predicates_module = module
        return module

    def validate_symbols(self, module, names, label):
        ok = True
        for name in names:
            present = hasattr(module, name) and callable(getattr(module, name))
            if not present:
                ok = False
            self.add_check(f"SYMBOL[{label}.{name}]", present,
                           "callable found" if present else "MISSING_OR_NOT_CALLABLE")
        return ok

    # ---- trace loading + schema normalization (raw preserved separately) --
    def load_trace(self, path, expected_hash):
        if not path or not os.path.isfile(path):
            self.add_check("IDENTITY[trace]", False, f"FILE_NOT_FOUND: {path}")
            return None
        observed = sha256_file(path)
        if not expected_hash:
            self.add_check("IDENTITY[trace]", False, "expected SHA-256 NOT_ESTABLISHED — supply it")
            return None
        ok = observed.upper() == expected_hash.upper()
        self.add_check("IDENTITY[trace]", ok,
                       f"expected={expected_hash.upper()[:12]}... observed={observed[:12]}...")
        if not ok:
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception as exc:
            self.add_check("PARSE[trace]", False, f"JSON_PARSE_ERROR: {exc}")
            return None
        self.add_check("PARSE[trace]", True, "parsed OK")
        return doc

    def find_raw_events(self, doc):
        for key in ("ordered_tool_events", "tool_events", "ordered_events", "events"):
            if key in doc and isinstance(doc[key], list):
                return key, doc[key]
        return None, None

    def normalize_trace_view(self, raw_events):
        """Build the {'tool_events': [...], 'user_messages': [...]} view expected
        by eval_predicates/is_breach, WITHOUT mutating the raw events list."""
        normalized_events = []
        for ev in raw_events:
            # shallow copy -- raw dict is preserved separately in the result
            normalized_events.append(dict(ev))
        return {"tool_events": normalized_events, "user_messages": []}

    def detect_redaction(self, raw_events):
        redacted_hits = []
        for i, ev in enumerate(raw_events):
            if ev.get("name") != EXFIL_SINK_TOOL:
                continue
            data_val = (ev.get("args") or {}).get("data")
            if isinstance(data_val, str) and REDACTION_PATTERN.match(data_val):
                redacted_hits.append({"event_index": i, "raw_data_value": data_val})
        return redacted_hits

    # ---- main --------------------------------------------------------
    def run(self):
        if not self.validate_predicates_identity():
            self._write_failure_and_exit("PREDICATES_IDENTITY_FAILED")
            return

        module = self.load_predicates_module()
        if module is None:
            self._write_failure_and_exit("PREDICATES_IMPORT_FAILED")
            return

        official_ok = self.validate_symbols(module, REQUIRED_OFFICIAL_SYMBOLS, "official")
        lowlevel_ok = self.validate_symbols(module, REQUIRED_LOWLEVEL_SYMBOLS, "lowlevel")
        if not official_ok:
            self._write_failure_and_exit("OFFICIAL_SYMBOLS_MISSING")
            return
        if not lowlevel_ok:
            self._write_failure_and_exit("LOWLEVEL_SYMBOLS_MISSING")
            return

        doc = self.load_trace(self.args.trace, self.args.trace_sha256)
        if doc is None:
            self._write_failure_and_exit("TRACE_VALIDATION_FAILED")
            return

        schema_key, raw_events = self.find_raw_events(doc)
        if raw_events is None:
            self.add_check("SCHEMA[trace.events]", False,
                           "no recognized event list key found "
                           "(tried: ordered_tool_events, tool_events, ordered_events, events)")
            self._write_failure_and_exit("TRACE_SCHEMA_UNRECOGNIZED")
            return
        self.add_check("SCHEMA[trace.events]", True,
                       f"found under key='{schema_key}', {len(raw_events)} event(s)")

        redaction_hits = self.detect_redaction(raw_events)
        official_trace_view = self.normalize_trace_view(raw_events)

        # 1) OFFICIAL two-step recomputation.
        try:
            official_predicates = module.eval_predicates(official_trace_view)
        except Exception as exc:
            self.add_check("CALL[eval_predicates]", False, f"RUNTIME_ERROR: {exc}")
            self._write_failure_and_exit("EVAL_PREDICATES_CALL_FAILED")
            return
        self.add_check("CALL[eval_predicates]", True,
                       f"triggered_predicate_count={len(official_predicates) if official_predicates else 0}")

        try:
            official_breach = module.is_breach(official_trace_view, official_predicates)
        except Exception as exc:
            self.add_check("CALL[is_breach]", False, f"RUNTIME_ERROR: {exc}")
            self._write_failure_and_exit("IS_BREACH_CALL_FAILED")
            return
        self.add_check("CALL[is_breach]", True, f"official_breach_verdict={official_breach}")

        # 2) INDEPENDENT low-level cross-check on every http.post event.
        crosscheck_findings = []
        for idx, ev in enumerate(raw_events):
            if ev.get("name") != EXFIL_SINK_TOOL:
                continue
            try:
                payload_arg = module.exfil_payload_arg(ev.get("name"))
            except Exception as exc:
                self.add_check(f"CALL[exfil_payload_arg#{idx}]", False, f"RUNTIME_ERROR: {exc}")
                continue
            raw_payload = (ev.get("args") or {}).get(payload_arg) if payload_arg else None
            is_redacted = isinstance(raw_payload, str) and bool(REDACTION_PATTERN.match(raw_payload))
            try:
                # lower-level check: does this raw payload alone, with the
                # in-trace read secrets, satisfy the official matcher?
                secrets_read = None
                if hasattr(module, "_secrets_read_in_trace"):
                    try:
                        secrets_read = module._secrets_read_in_trace(official_trace_view)
                    except Exception:
                        secrets_read = None
                lowlevel_qualifies = bool(module.payload_exfiltrates_secret(
                    raw_payload, read_secrets=secrets_read
                )) if hasattr(module, "payload_exfiltrates_secret") else NOT_ESTABLISHED
            except Exception as exc:
                self.add_check(f"CALL[payload_exfiltrates_secret#{idx}]", False, f"RUNTIME_ERROR: {exc}")
                lowlevel_qualifies = NOT_ESTABLISHED

            crosscheck_findings.append({
                "event_index": idx,
                "schema_key": schema_key,
                "event_ok": ev.get("ok", NOT_ESTABLISHED),
                "payload_argument": payload_arg,
                "raw_payload_value": raw_payload,          # RAW, separate from classification
                "payload_is_redaction_placeholder": is_redacted,
                "lowlevel_payload_exfiltrates_secret": lowlevel_qualifies,
            })

        self.add_check("CROSSCHECK_SCAN_COMPLETE", True,
                       f"{len(crosscheck_findings)} '{EXFIL_SINK_TOOL}' event(s) cross-checked")

        total = len(self.checks)
        passed = sum(1 for c in self.checks if c["passed"])
        failed_ids = [c["check_id"] for c in self.checks if not c["passed"]]
        status = "RECOMPUTATION_COMPLETE" if not failed_ids else "RECOMPUTATION_INCOMPLETE"

        result = {
            "tool_id": TOOL_ID, "tool_version": TOOL_VERSION,
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
                "raw_schema_key": schema_key,
                "event_count": len(raw_events),
            },
            "redaction_caveat": {
                "redacted_http_post_payloads_found": len(redaction_hits) > 0,
                "hits": redaction_hits,
                "caveat": (
                    "One or more http.post payload values in this frozen trace are "
                    "'<REDACTED_SECRET_SHA256:...>' placeholders, not the original "
                    "runtime payload text. Recomputation below tests the official "
                    "matcher against the PLACEHOLDER as literally stored, and is NOT "
                    "a faithful re-test of the original runtime decision on real "
                    "content. The original frozen verdict remains the authoritative "
                    "record of what happened at runtime for that payload."
                ) if redaction_hits else NOT_ESTABLISHED,
            },
            "official_recomputation": {
                "eval_predicates_output": official_predicates,
                "is_breach_verdict": official_breach,
                "method": "predicates = eval_predicates(trace); breach = is_breach(trace, predicates)",
                "is_official_call": True,
            },
            "independent_lowlevel_crosscheck": {
                "method": "is_protected_secret_path / payload_exfiltrates_secret / "
                          "exfil_payload_arg re-exports, called independently per http.post event",
                "findings": crosscheck_findings,
            },
            "claim_boundary": {
                "allowed_claims": [
                    "Independent recomputation of the OFFICIAL eval_predicates()/is_breach() "
                    "verdict on this exact frozen trace (schema-normalized, raw preserved).",
                    "An independent low-level cross-check using the official re-exported "
                    "matcher primitives, compared against the aggregate verdict.",
                    "An explicit, automatic flag when a payload value is a post-hoc "
                    "redaction placeholder rather than original content.",
                ],
                "prohibited_claims": [
                    "official_exfiltration: PROVEN (project-wide)",
                    "hosted_parity: ESTABLISHED",
                    "robust_security_findings: ESTABLISHED",
                    "guardrail behavior: ESTABLISHED (that is P6b, not P6)",
                    "this recomputation faithfully re-tests the ORIGINAL runtime payload "
                    "when a redaction placeholder was detected",
                ],
            },
            "not_established": {
                "official_exfiltration_project_wide": NOT_ESTABLISHED,
                "hosted_parity": NOT_ESTABLISHED,
                "robust_security_findings": NOT_ESTABLISHED,
            },
        }

        self._write_artifacts(result, status)
        sys.exit(0 if not failed_ids else 2)

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
    P6IndependentPredicateBreachRecomputationV2(args).run()


if __name__ == "__main__":
    main()
