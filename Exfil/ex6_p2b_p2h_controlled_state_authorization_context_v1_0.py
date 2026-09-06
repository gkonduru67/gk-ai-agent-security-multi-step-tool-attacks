#!/usr/bin/env python3
"""EX6 P2B P2H controlled state-transition and authorization-context wiring.

Permitted: package import, one adapter instance, snapshot/restore/reset, and one
trusted grant registration through the public registration interface.
Prohibited: decide, before_decide, after_tool, models, tools, Sandbox, Gym,
predicates, breach, effects, and attack optimization.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib
import json
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX6_P2B_P2H_CONTROLLED_STATE_TRANSITION_AND_AUTHORIZATION_CONTEXT_WIRING_v1.0"
EXPECTED_PARENT_VERSION = "EX6_P2B_P2G_R2_CONTROLLED_CONSTRUCTOR_AND_STATE_PREFLIGHT_WITH_GUARDRAILBASE_STUB_v1.0"
EXPECTED_SOURCE_SHA256 = "BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"
EXPECTED_BASE_SHA256 = "EC95F45A9BF4202514725690617C91E88F3F1AE889AC7828D423DAAFEA527708"
EXPECTED_CLASS = "TrustedGuardrailContextAdapterV1_1"
ADAPTER_MODULE = "aicomp_sdk.guardrails.trusted_context_adapter_v1_1"
BASE_MODULE = "aicomp_sdk.guardrails.base"
CAPABILITY = b"P2H_DETERMINISTIC_OUT_OF_BAND_CAPABILITY_V1"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def identity(path: Path) -> dict[str, Any]:
    path = path.resolve()
    return {
        "artifact": path.name,
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "sha256": sha256(path),
    }


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest().upper()


def json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"type": "bytes", "sha256": hashlib.sha256(value).hexdigest().upper(), "length": len(value)}
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, set):
        return sorted(json_safe(item) for item in value)
    return value


def state_digest(snapshot: Any) -> str:
    return canonical_digest(json_safe(snapshot))


def contains_raw_capability(value: Any) -> bool:
    if isinstance(value, bytes):
        return value == CAPABILITY
    if isinstance(value, dict):
        return any(contains_raw_capability(k) or contains_raw_capability(v) for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return any(contains_raw_capability(item) for item in value)
    return False


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir).resolve()
    require(not output_dir.exists(), f"Refusing overwrite: {output_dir}")
    output_dir.mkdir(parents=True)
    original_sys_path = list(sys.path)

    try:
        parent_result_path = Path(args.p2g_r2_result).resolve()
        project_root = Path(args.project_root).resolve()
        repaired_source = Path(args.repaired_source).resolve()
        base_source = project_root / "aicomp_sdk" / "guardrails" / "base.py"

        for label, path in (
            ("P2G-R2 result", parent_result_path),
            ("repaired adapter source", repaired_source),
            ("GuardrailBase source", base_source),
        ):
            require(path.is_file(), f"Missing {label}: {path}")

        parent = json.loads(parent_result_path.read_text(encoding="utf-8-sig"))
        require(parent.get("version") == EXPECTED_PARENT_VERSION, "Unexpected P2G-R2 parent version")
        require(parent.get("adapter_instantiated") is True, "P2G-R2 did not instantiate adapter")
        require(parent.get("snapshot_state_called") is True, "P2G-R2 snapshot gate did not pass")
        require(parent.get("restore_state_called") is True, "P2G-R2 restore gate did not pass")
        require(parent.get("reset_state_called") is True, "P2G-R2 reset gate did not pass")
        require(parent.get("error") is None, "P2G-R2 contains an error")
        require(parent.get("execution_boundaries", {}).get("decide_executed") is False, "P2G-R2 crossed decision boundary")
        require(sha256(repaired_source) == EXPECTED_SOURCE_SHA256, "Repaired adapter source identity mismatch")
        require(sha256(base_source) == EXPECTED_BASE_SHA256, "GuardrailBase source identity mismatch")
        require((project_root / "aicomp_sdk").is_dir(), "Project root does not contain aicomp_sdk")

        sys.path.insert(0, str(project_root))
        importlib.invalidate_caches()
        base_module = importlib.import_module(BASE_MODULE)
        adapter_module = importlib.import_module(ADAPTER_MODULE)
        GuardrailBase = getattr(base_module, "GuardrailBase")
        Adapter = getattr(adapter_module, EXPECTED_CLASS)

        class P2HGuardrailBaseStub(GuardrailBase):
            def decide(self, *unused_args: Any, **unused_kwargs: Any) -> Any:
                raise RuntimeError("DECISION_EXECUTION_PROHIBITED_IN_P2H")

        stub = P2HGuardrailBaseStub()
        adapter = Adapter(stub, {("issuer-p2h", "domain-p2h"): CAPABILITY})

        transitions: list[dict[str, Any]] = []
        snapshot_s0 = deepcopy(adapter.snapshot_state())
        digest_s0 = state_digest(snapshot_s0)
        transitions.append({"step": "S0_INITIAL", "operation": "snapshot_state", "state_digest": digest_s0, "passed": True})

        grant = {
            "grant_id": "P2H-GRANT-0001",
            "issuer_id": "issuer-p2h",
            "issuer_trust_domain": "domain-p2h",
            "issued_at_or_sequence": 10,
            "expires_at_or_sequence": 20,
            "authorized_tool": "http.post",
            "authorized_target_digest": "P2H-TARGET-DIGEST-0001",
            "authorized_proposal_digest": "P2H-PROPOSAL-DIGEST-0001",
            "nonce": "P2H-NONCE-0001",
            "trace_identity": "P2H-TRACE-0001",
        }
        returned_grant_id = adapter.register_trusted_grant(grant, CAPABILITY)
        require(returned_grant_id == grant["grant_id"], "register_trusted_grant returned unexpected identity")
        snapshot_s1 = deepcopy(adapter.snapshot_state())
        digest_s1 = state_digest(snapshot_s1)
        require(digest_s1 != digest_s0, "Grant registration did not change state")
        require(grant["grant_id"] in snapshot_s1.get("trusted_grants_by_id", {}), "Registered grant absent from state")
        require(not contains_raw_capability(snapshot_s1), "Raw issuer capability leaked into snapshot state")
        transitions.append({"step": "S1_GRANT_REGISTERED", "operation": "register_trusted_grant", "state_digest": digest_s1, "passed": True})

        adapter.restore_state(deepcopy(snapshot_s0))
        digest_restored_s0 = state_digest(adapter.snapshot_state())
        require(digest_restored_s0 == digest_s0, "Restore to S0 was not deterministic")
        transitions.append({"step": "S2_RESTORE_S0", "operation": "restore_state", "state_digest": digest_restored_s0, "passed": True})

        adapter.restore_state(deepcopy(snapshot_s1))
        digest_restored_s1 = state_digest(adapter.snapshot_state())
        require(digest_restored_s1 == digest_s1, "Restore to S1 was not deterministic")
        transitions.append({"step": "S3_RESTORE_S1", "operation": "restore_state", "state_digest": digest_restored_s1, "passed": True})

        adapter.reset_state()
        digest_reset = state_digest(adapter.snapshot_state())
        require(digest_reset == digest_s0, "Reset did not return adapter to initial state")
        transitions.append({"step": "S4_RESET", "operation": "reset_state", "state_digest": digest_reset, "passed": True})

        result = {
            "version": VERSION,
            "created_at_utc": now(),
            "status": "P2H_CONTROLLED_STATE_TRANSITION_AND_AUTHORIZATION_CONTEXT_WIRING_COMPLETE_PASS",
            "classification": "CONTROLLED_STATE_ONLY_PUBLIC_GRANT_REGISTRATION_PREFLIGHT",
            "P2G_R2_parent_verified": True,
            "repaired_source_identity": identity(repaired_source),
            "guardrail_base_identity": identity(base_source),
            "adapter_instantiated": True,
            "authorization_context_registration": {
                "trusted_grant_registered": True,
                "returned_grant_identity_matched": True,
                "registered_grant_visible_in_snapshot": True,
                "raw_capability_absent_from_snapshot": True,
            },
            "state_transition_results": {
                "initial_snapshot": "PASS",
                "registration_changed_state": "PASS",
                "restore_initial_deterministic": "PASS",
                "restore_registered_deterministic": "PASS",
                "reset_to_initial_deterministic": "PASS",
            },
            "execution_boundaries": {
                "adapter_instantiated": True,
                "register_trusted_grant_executed": True,
                "snapshot_state_executed": True,
                "restore_state_executed": True,
                "reset_state_executed": True,
                "decide_executed": False,
                "before_decide_executed": False,
                "after_tool_executed": False,
                "tools_executed": False,
                "sandbox_executed": False,
                "gym_executed": False,
                "predicates_executed": False,
                "breach_executed": False,
                "effects_observed": False,
            },
            "scientific_verdict": {
                "controlled_state_transition_compatibility": "ESTABLISHED_WITHIN_P2H_FIXTURE_SCOPE",
                "trusted_grant_registration_wiring": "ESTABLISHED_WITHIN_P2H_FIXTURE_SCOPE",
                "deterministic_snapshot_restore_reset": "ESTABLISHED_WITHIN_P2H_FIXTURE_SCOPE",
                "raw_capability_snapshot_non_disclosure": "ESTABLISHED_WITHIN_P2H_FIXTURE_SCOPE",
                "authorization_transport_correctness": "NOT_ESTABLISHED",
                "proposal_binding_behavior": "NOT_EVALUATED",
                "grant_consumption_behavior": "NOT_EVALUATED",
                "runtime_compatibility": "NOT_ESTABLISHED",
                "requirement_satisfaction": "NOT_ESTABLISHED",
                "guardrail_effectiveness": "NOT_EVALUATED",
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": "NOT_ESTABLISHED",
            },
            "claim_boundary": {
                "allowed": [
                    "controlled trusted-grant registration wiring",
                    "deterministic snapshot/restore/reset within the exact P2H fixture",
                    "raw capability absence from snapshot within the exact P2H fixture",
                ],
                "prohibited": [
                    "authorization transport correctness",
                    "proposal authorization correctness",
                    "grant consumption correctness",
                    "runtime compatibility",
                    "requirement satisfaction",
                    "guardrail effectiveness",
                    "security improvement",
                    "real exfiltration prevention",
                    "Sandbox parity",
                    "Gym parity",
                    "hosted parity",
                ],
            },
            "next_gate": "EX6_P2B_P2I_CONTROLLED_PROPOSAL_BINDING_AND_FAIL_CLOSED_DECISION_PREFLIGHT",
        }

        result_path = output_dir / "ex6_p2b_p2h_result.json"
        transitions_path = output_dir / "ex6_p2b_p2h_state_transitions.csv"
        binding_path = output_dir / "ex6_p2b_p2h_binding.json"
        claim_path = output_dir / "ex6_p2b_p2h_claim_boundary.json"
        write_json(result_path, result)
        write_csv(transitions_path, transitions, ["step", "operation", "state_digest", "passed"])
        write_json(claim_path, result["claim_boundary"])
        write_json(binding_path, {
            "version": VERSION,
            "created_at_utc": now(),
            "runner": identity(Path(__file__).resolve()),
            "inputs": {
                "p2g_r2_result": identity(parent_result_path),
                "repaired_source": identity(repaired_source),
                "guardrail_base": identity(base_source),
            },
            "source_modified": False,
        })

        manifest_rows = [
            {**identity(path), "role": "P2H_DERIVED"}
            for path in (result_path, transitions_path, binding_path, claim_path)
        ] + [
            {**identity(path), "role": "P2H_BOUND"}
            for path in (parent_result_path, repaired_source, base_source)
        ]
        manifest_path = output_dir / "ex6_p2b_p2h_manifest.csv"
        write_csv(manifest_path, manifest_rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        external_path = output_dir / "ex6_p2b_p2h_manifest_external_binding.json"
        write_json(external_path, {
            "version": VERSION,
            "created_at_utc": now(),
            "status": result["status"],
            "manifest_filename": manifest_path.name,
            "manifest_size_bytes": manifest_path.stat().st_size,
            "manifest_sha256": sha256(manifest_path),
            "runner_sha256": sha256(Path(__file__).resolve()),
            "repaired_source_sha256": sha256(repaired_source),
            "decide_executed": False,
            "runtime_validated": False,
            "requirements_satisfied": False,
            "next_gate": result["next_gate"],
        })

        print(json.dumps({
            "status": result["status"],
            "state_transitions_passed": len(transitions),
            "trusted_grant_registered": True,
            "raw_capability_absent_from_snapshot": True,
            "manifest_sha256": sha256(manifest_path),
            "decide_executed": False,
            "runtime_validated": False,
            "requirements_satisfied": False,
            "next_gate": result["next_gate"],
        }, indent=2))

    except Exception as exc:
        failure_path = output_dir / "P2H_FAILED.json"
        failure_path.write_text(json.dumps({
            "version": VERSION,
            "created_at_utc": now(),
            "status": "P2H_CONTROLLED_STATE_TRANSITION_PREFLIGHT_BLOCKED",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "decide_executed": False,
            "runtime_validated": False,
            "requirements_satisfied": False,
        }, indent=2), encoding="utf-8")
        raise
    finally:
        sys.path[:] = original_sys_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=VERSION)
    parser.add_argument("--p2g-r2-result", required=True)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--repaired-source", required=True)
    parser.add_argument("--output-dir", required=True)
    return parser.parse_args()


if __name__ == "__main__":
    try:
        main(parse_args())
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
