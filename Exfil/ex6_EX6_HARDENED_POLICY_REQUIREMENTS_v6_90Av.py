#!/usr/bin/env python3
"""EX6 v6.90 P1 hardened-policy requirements specification.

Consumes only the frozen v6.89B evidence package. Generates a normative,
read-only requirements and feasibility freeze. It does not inspect or import
the SDK, execute runtime behavior, open fixtures, write the hardened policy,
or perform a packaged-versus-hardened comparison.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX6_ACTION_TARGET_BOUND_OPTIMAL_REQUIREMENTS_SPECIFICATION_v6.90"
EXPECTED_PARENT_MANIFEST_SHA256 = "55DC1815C688BFA9F3B8A0E301EEC332B31A5B7F4A635653416B1339B814C11C"
EXPECTED_PARENT_STATUS = "FINAL_CORRECTION_FREEZE_COMPLETE"
EXPECTED_OPTIMAL_SHA256 = "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED"
EXPECTED_PREDICATES_SHA256 = "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"

LABELS = {
    "CURRENT": "IMPLEMENTABLE_WITH_CURRENT_DECIDE_INPUTS",
    "TRANSPORT": "REQUIRES_TRUSTED_CONTEXT_TRANSPORT",
    "SANDBOX": "REQUIRES_SANDBOX_CHANGE",
    "WITHHELD": "WITHHELD_NOT_CURRENTLY_TESTABLE",
    "DESIGN": "DESIGN_AND_DOCUMENTATION_ONLY",
}

REQUIRED_PARENT_ARTIFACTS = {
    "ex6_v6_89B_parent_verification.csv",
    "ex6_v6_89B_correction_matrix.csv",
    "ex6_v6_89B_final_contract.json",
    "ex6_v6_89B_result.json",
    "ex6_v6_89B_binding.json",
}

REQUIREMENTS: list[dict[str, Any]] = [
    # Identity and immutability
    {"id":"ID-001","section":"policy_identity","requirement":"Use the distinct class name ActionTargetBoundOptimalGuardrail.","priority":"MUST","feasibility":LABELS["DESIGN"],"available_inputs":"none","missing_inputs":"none","verification":"static class-name and source review","claim_boundary":"identity requirement only"},
    {"id":"ID-002","section":"policy_identity","requirement":"Place the hardened class in a separate mutable source file aicomp_sdk/guardrails/action_target_bound_optimal.py.","priority":"MUST","feasibility":LABELS["DESIGN"],"available_inputs":"none","missing_inputs":"none","verification":"path and manifest review after implementation","claim_boundary":"does not authorize SDK package modification"},
    {"id":"ID-003","section":"policy_identity","requirement":"Do not modify packaged aicomp_sdk/guardrails/optimal.py; retain parent SHA-256 6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED.","priority":"MUST","feasibility":LABELS["DESIGN"],"available_inputs":"frozen parent identity","missing_inputs":"none","verification":"pre/post SHA-256","claim_boundary":"local artifact identity only"},
    {"id":"ID-004","section":"policy_identity","requirement":"After implementation, freeze hardened source SHA-256 and a line-level change manifest against the packaged behavioral baseline.","priority":"MUST","feasibility":LABELS["DESIGN"],"available_inputs":"future hardened source","missing_inputs":"hardened source not yet written","verification":"SHA-256 and line-level manifest","claim_boundary":"withheld until P2"},

    # Generic interface and rule order
    {"id":"IF-001","section":"decision_interface","requirement":"Implement GuardrailBase-compatible decide(self, tool_name, tool_args, context) and return Decision values only.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"tool_name|tool_args|context","missing_inputs":"none","verification":"static signature and policy-unit tests","claim_boundary":"local interface compatibility only"},
    {"id":"RO-001","section":"rule_order","requirement":"Parse and validate tool-specific security arguments before considering authorization.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"tool_name|tool_args","missing_inputs":"none","verification":"ordered branch unit controls","claim_boundary":"proposal-level policy behavior"},
    {"id":"RO-002","section":"rule_order","requirement":"Evaluate protected-source and external-sink rules before any generic allow path.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"tool_name|tool_args|recent_sources","missing_inputs":"successful read values for lineage","verification":"ordered branch unit controls","claim_boundary":"full lineage enforcement not implied"},
    {"id":"RO-003","section":"rule_order","requirement":"Prohibit generic user_authorized or user_confirmed_safe Boolean values from causing unconditional early ALLOW.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"existing Boolean fields may be ignored","missing_inputs":"none to prohibit fallback","verification":"Boolean-bypass negative controls","claim_boundary":"does not create trusted authorization transport"},
    {"id":"RO-004","section":"rule_order","requirement":"Default to DENY or CONFIRM only for explicitly specified sensitive cases; retain ALLOW for matched benign controls.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"tool_name|tool_args|context","missing_inputs":"none for proposal-level controls","verification":"positive and benign matched policy-unit rows","claim_boundary":"utility evaluated only on frozen controls"},

    # Authorization
    {"id":"AZ-001","section":"authorization","requirement":"A valid authorization grant must identify a trusted issuer independent of model and prompt content.","priority":"MUST","feasibility":LABELS["TRANSPORT"],"available_inputs":"none in frozen guardrail context","missing_inputs":"trusted issuer identity and provenance","verification":"trusted transport contract then negative/positive controls","claim_boundary":"not implementable from current context"},
    {"id":"AZ-002","section":"authorization","requirement":"Bind authorization to the exact tool action.","priority":"MUST","feasibility":LABELS["TRANSPORT"],"available_inputs":"current tool_name","missing_inputs":"trusted authorized action","verification":"cross-action rejection control","claim_boundary":"requirement valid; transport unavailable"},
    {"id":"AZ-003","section":"authorization","requirement":"Bind authorization to a canonical target identity.","priority":"MUST","feasibility":LABELS["TRANSPORT"],"available_inputs":"current path or URL can be parsed","missing_inputs":"trusted authorized target","verification":"cross-target rejection control","claim_boundary":"requirement valid; transport unavailable"},
    {"id":"AZ-004","section":"authorization","requirement":"Bind authorization to a canonical proposal digest derived from action and security-relevant arguments.","priority":"MUST","feasibility":LABELS["TRANSPORT"],"available_inputs":"current proposal can be canonicalized","missing_inputs":"trusted authorized proposal digest","verification":"proposal mutation rejection control","claim_boundary":"requirement valid; transport unavailable"},
    {"id":"AZ-005","section":"authorization","requirement":"Authorization must expire at a defined turn, timestamp, or interaction boundary.","priority":"MUST","feasibility":LABELS["TRANSPORT"],"available_inputs":"seed only; no trusted time or grant lifetime","missing_inputs":"trusted expiry boundary","verification":"expired-grant rejection control","claim_boundary":"not implementable from generic Boolean"},
    {"id":"AZ-006","section":"authorization","requirement":"Authorization must be consumable at most once for one successful matched action.","priority":"MUST","feasibility":LABELS["SANDBOX"],"available_inputs":"stateful guardrail can track local consumption","missing_inputs":"trusted success acknowledgement after tool effect","verification":"success/failure consumption controls","claim_boundary":"decide occurs before tool outcome"},
    {"id":"AZ-007","section":"authorization","requirement":"A failed or denied action must not silently authorize a later action or target.","priority":"MUST","feasibility":LABELS["SANDBOX"],"available_inputs":"guardrail sees proposal only","missing_inputs":"post-tool success/failure feedback to policy state","verification":"failed-action reuse controls","claim_boundary":"requires outcome transport"},
    {"id":"AZ-008","section":"authorization","requirement":"Model output, user prompt text, recent_sources, and recent_tools must never act as trusted grant setters.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"these fields can be treated as untrusted","missing_inputs":"none","verification":"prompt/model-influence negative controls","claim_boundary":"trusted grant remains unavailable"},

    # Tool-specific arguments
    {"id":"TS-001","section":"tool_specific_handling","requirement":"Do not use a generic first-present-key extractor for security decisions.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"tool_name|tool_args","missing_inputs":"none","verification":"multi-argument controls","claim_boundary":"proposal parsing only"},
    {"id":"TS-002","section":"tool_specific_handling","requirement":"For fs.read, fs.write, and fs.delete, evaluate the path argument with is_protected_secret_path.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"tool_name|tool_args.path|public helper","missing_inputs":"none","verification":"canonical and look-alike path controls","claim_boundary":"helper behavior tied to frozen predicates SHA-256"},
    {"id":"TS-003","section":"tool_specific_handling","requirement":"For http.post, inspect URL and data independently.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"tool_args.url|tool_args.data","missing_inputs":"none for independent inspection","verification":"URL-only, data-only-invalid, and URL-plus-data controls","claim_boundary":"payload lineage not implied"},
    {"id":"TS-004","section":"tool_specific_handling","requirement":"Use exfil_payload_arg(tool_name) to identify the official EXFILTRATION payload channel.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"tool_name|public helper","missing_inputs":"none","verification":"official sink mapping unit test","claim_boundary":"frozen evaluator epoch only"},
    {"id":"TS-005","section":"tool_specific_handling","requirement":"Keep email.send outside EXFILTRATION and evaluate it only under its separate policy boundary.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"tool_name","missing_inputs":"none","verification":"email boundary negative control","claim_boundary":"does not revalidate CONFUSED_DEPUTY phase"},
    {"id":"TS-006","section":"tool_specific_handling","requirement":"Reject missing or malformed security-relevant arguments before payload or authorization evaluation.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"tool_args","missing_inputs":"tool schema metadata not required for explicit supported tools","verification":"missing/wrong-type argument controls","claim_boundary":"policy validation, not tool execution validation"},

    # Matcher and provenance
    {"id":"MH-001","section":"canonical_helper_reuse","requirement":"Use only public canonical helpers is_protected_secret_path, exfil_payload_arg, and payload_exfiltrates_secret for scorer-aligned matching.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"public helper functions","missing_inputs":"read_secrets for real lineage","verification":"import and helper-call static review","claim_boundary":"helper reuse does not establish lineage"},
    {"id":"MH-002","section":"canonical_helper_reuse","requirement":"Do not directly import or duplicate private _contains_secret or _decode_candidates logic.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"public helper alternatives","missing_inputs":"none","verification":"AST import and duplication review","claim_boundary":"code-structure requirement"},
    {"id":"PV-001","section":"provenance","requirement":"Treat recent_sources labels as insufficient evidence of protected-value capture or derivation.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"recent_sources","missing_inputs":"exact successful read values","verification":"source-label-only negative control","claim_boundary":"no lineage claim from labels"},
    {"id":"PV-002","section":"provenance","requirement":"A real exfiltration payload decision must use values returned by successful same-session protected fs.read events.","priority":"MUST","feasibility":LABELS["SANDBOX"],"available_inputs":"current context lacks event outputs","missing_inputs":"ordered successful read events and outputs","verification":"same-session read-then-post controls","claim_boundary":"requires trusted runtime-event transport"},
    {"id":"PV-003","section":"provenance","requirement":"Failed reads, path mentions, synthetic substitutions, and wrong-source values must not populate read_secrets.","priority":"MUST","feasibility":LABELS["SANDBOX"],"available_inputs":"none in current decide context","missing_inputs":"trusted event success and value transport","verification":"required negative controls","claim_boundary":"requires runtime-event transport"},
    {"id":"PV-004","section":"provenance","requirement":"When qualifying read_secrets are available, evaluate exact and encoded derivation through payload_exfiltrates_secret.","priority":"MUST","feasibility":LABELS["TRANSPORT"],"available_inputs":"data payload|public helper","missing_inputs":"trusted read_secrets","verification":"plaintext and official encoded controls","claim_boundary":"matcher control until real transport exists"},
    {"id":"PV-005","section":"provenance","requirement":"Preserve raw payload separately from any normalized or decoded decision evidence.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"raw tool_args.data","missing_inputs":"none","verification":"evidence-field inspection","claim_boundary":"logging specification; no payload disclosure"},

    # State and reset
    {"id":"ST-001","section":"state_and_reset","requirement":"Declare every mutable hardened-policy field and its security purpose.","priority":"MUST","feasibility":LABELS["DESIGN"],"available_inputs":"future implementation design","missing_inputs":"implementation not yet written","verification":"state manifest","claim_boundary":"P2 requirement"},
    {"id":"ST-002","section":"state_and_reset","requirement":"If stateful, implement deterministic snapshot_state returning all security-relevant mutable state.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"GuardrailBase state interface","missing_inputs":"none after state design","verification":"snapshot round-trip unit controls","claim_boundary":"local state fidelity"},
    {"id":"ST-003","section":"state_and_reset","requirement":"If stateful, implement restore_state to reconstruct exactly the captured security state without aliasing.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"GuardrailBase state interface","missing_inputs":"none after state design","verification":"snapshot mutation isolation controls","claim_boundary":"local state fidelity"},
    {"id":"ST-004","section":"state_and_reset","requirement":"Reset must restore the hardened policy to its frozen initial state on the same Sandbox guardrail instance.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"Sandbox reset calls restore_state","missing_inputs":"none if state methods are correct","verification":"reset determinism unit control","claim_boundary":"within one SandboxEnv"},

    # Matched comparison
    {"id":"MC-001","section":"matched_comparison","requirement":"Use identical frozen tool_name, tool_args, and context inputs for packaged and hardened policy-unit rows.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"direct decide inputs","missing_inputs":"none","verification":"input digest equality","claim_boundary":"policy-unit comparison only"},
    {"id":"MC-002","section":"matched_comparison","requirement":"Use identical empty HookRegistry state for the initial comparison.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"empty hooks","missing_inputs":"none","verification":"hook-state digest equality","claim_boundary":"no compromised-environment claim"},
    {"id":"MC-003","section":"matched_comparison","requirement":"Use the same evaluator epoch, fixture identity, seed, environment, and ordered proposals; change only guardrail class.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"frozen experiment controls","missing_inputs":"future hardened source identity","verification":"matched-row invariants","claim_boundary":"local matched comparison"},
    {"id":"MC-004","section":"matched_comparison","requirement":"Compare proposal-level policy decisions before Sandbox or Gym execution.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"direct decide calls","missing_inputs":"none","verification":"policy-unit matrix","claim_boundary":"not live defense"},
    {"id":"MC-005","section":"matched_comparison","requirement":"Withhold rows requiring unavailable trusted authorization or read-secret transport rather than simulating them as real-chain evidence.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"feasibility labels","missing_inputs":"trusted runtime transport","verification":"row eligibility gate","claim_boundary":"synthetic controls remain scorer controls"},

    # Benign utility
    {"id":"BU-001","section":"benign_utility","requirement":"Allow benign public fs.read paths that do not match the official protected-path helper.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"path|public helper","missing_inputs":"none","verification":"public and look-alike path controls","claim_boundary":"frozen fixtures only"},
    {"id":"BU-002","section":"benign_utility","requirement":"Allow benign http.post payloads unrelated to qualifying read secrets when no other policy rule denies them.","priority":"MUST","feasibility":LABELS["TRANSPORT"],"available_inputs":"url|data|matcher","missing_inputs":"trusted read_secrets or an explicitly empty qualified set","verification":"unrelated-post controls","claim_boundary":"requires explicit provenance state"},
    {"id":"BU-003","section":"benign_utility","requirement":"Do not deny benign values solely because their text contains broad substrings such as key, token, private, or secret when official helpers do not classify the action as protected or exfiltrating.","priority":"SHOULD","feasibility":LABELS["CURRENT"],"available_inputs":"tool-specific args|official helpers","missing_inputs":"none for protected-path and sentinel controls","verification":"substring false-positive controls","claim_boundary":"benign matrix defines accepted scope"},
    {"id":"BU-004","section":"benign_utility","requirement":"Record packaged and hardened decisions and reasons for every benign and security control row.","priority":"MUST","feasibility":LABELS["CURRENT"],"available_inputs":"Decision action|reason","missing_inputs":"none","verification":"canonical comparison CSV completeness","claim_boundary":"decision comparison only"},

    # Claim discipline
    {"id":"CB-001","section":"claim_boundary","requirement":"Do not claim hardened effectiveness before P2 identity freeze and P3 matched comparison.","priority":"MUST","feasibility":LABELS["DESIGN"],"available_inputs":"project phase state","missing_inputs":"implementation and results","verification":"publication claim audit","claim_boundary":"methodological governance"},
    {"id":"CB-002","section":"claim_boundary","requirement":"Do not claim action-target-proposal authorization enforcement while trusted grant transport is unavailable.","priority":"MUST","feasibility":LABELS["DESIGN"],"available_inputs":"feasibility matrix","missing_inputs":"trusted grant transport","verification":"claim-to-evidence audit","claim_boundary":"requirement may be specified but implementation withheld"},
    {"id":"CB-003","section":"claim_boundary","requirement":"Do not classify synthetic marker controls as real protected-source exfiltration prevention.","priority":"MUST","feasibility":LABELS["DESIGN"],"available_inputs":"scenario classification","missing_inputs":"real-chain runtime evidence","verification":"scenario label audit","claim_boundary":"synthetic scorer controls only"},
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def index_manifest(path: Path) -> dict[str, dict[str, str]]:
    rows = load_csv(path)
    required = {"artifact", "role", "size_bytes", "sha256", "source_path"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError(f"Parent manifest requires columns: {sorted(required)}")
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        name = row["artifact"].strip()
        if name in indexed:
            raise ValueError(f"Duplicate parent artifact: {name}")
        indexed[name] = row
    missing = sorted(REQUIRED_PARENT_ARTIFACTS - set(indexed))
    if missing:
        raise ValueError(f"Missing required v6.89B artifacts: {missing}")
    return indexed


def verify(row: dict[str, str]) -> dict[str, Any]:
    path = Path(row["source_path"])
    exists = path.is_file()
    observed_size = path.stat().st_size if exists else None
    observed_sha = sha256(path) if exists else None
    expected_size = int(row["size_bytes"])
    expected_sha = row["sha256"].upper()
    passed = exists and observed_size == expected_size and observed_sha == expected_sha
    return {
        "artifact": row["artifact"], "path": str(path), "exists": exists,
        "expected_size_bytes": expected_size, "observed_size_bytes": observed_size,
        "size_match": exists and observed_size == expected_size,
        "expected_sha256": expected_sha, "observed_sha256": observed_sha,
        "sha256_match": exists and observed_sha == expected_sha, "passed": passed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=VERSION)
    parser.add_argument("--v6-89b-manifest", required=True)
    parser.add_argument("--v6-89b-binding", required=True)
    parser.add_argument("--out-root", required=True)
    args = parser.parse_args()

    parent_manifest = Path(args.v6_89b_manifest)
    parent_binding = Path(args.v6_89b_binding)
    out = Path(args.out_root)
    if out.exists():
        raise FileExistsError(f"Refusing to overwrite existing output directory: {out}")
    for path in [parent_manifest, parent_binding]:
        if not path.is_file():
            raise FileNotFoundError(path)
    if sha256(parent_manifest) != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("v6.89B parent manifest identity mismatch")
    external = load_json(parent_binding)
    if external.get("manifest_sha256") != EXPECTED_PARENT_MANIFEST_SHA256:
        raise ValueError("v6.89B external binding manifest mismatch")
    if external.get("status") != EXPECTED_PARENT_STATUS:
        raise ValueError("v6.89B parent status mismatch")
    if external.get("optimal_sha256") != EXPECTED_OPTIMAL_SHA256:
        raise ValueError("v6.89B Optimal identity mismatch")
    if external.get("predicates_sha256") != EXPECTED_PREDICATES_SHA256:
        raise ValueError("v6.89B predicates identity mismatch")

    indexed = index_manifest(parent_manifest)
    verifications = [verify(indexed[name]) for name in sorted(REQUIRED_PARENT_ARTIFACTS)]
    failed = [row for row in verifications if not row["passed"]]
    if failed:
        raise ValueError("Parent evidence verification failed: " + ", ".join(row["artifact"] for row in failed))

    parent_contract = load_json(Path(indexed["ex6_v6_89B_final_contract.json"]["source_path"]))
    parent_result = load_json(Path(indexed["ex6_v6_89B_result.json"]["source_path"]))
    if parent_result.get("status") != EXPECTED_PARENT_STATUS:
        raise ValueError("v6.89B canonical result is not freeze complete")
    if parent_contract.get("http_post", {}).get("data_payload_inspected_by_packaged_optimal_in_normal_shape") is not False:
        raise ValueError("v6.89B corrected HTTP POST contract missing")

    now = datetime.now(timezone.utc).isoformat()
    out.mkdir(parents=True)
    paths = {
        "verification": out / "ex6_v6_90_parent_verification.csv",
        "requirements": out / "ex6_v6_90_requirements_matrix.csv",
        "authorization": out / "ex6_v6_90_authorization_grant_schema.json",
        "tool_matrix": out / "ex6_v6_90_tool_specific_handling.csv",
        "rule_order": out / "ex6_v6_90_rule_order_specification.json",
        "helpers": out / "ex6_v6_90_canonical_helper_reuse.json",
        "state": out / "ex6_v6_90_state_reset_contract.json",
        "capability": out / "ex6_v6_90_current_context_capability.csv",
        "unavailable": out / "ex6_v6_90_unavailable_input_matrix.csv",
        "comparison": out / "ex6_v6_90_matched_comparison_invariants.csv",
        "benign": out / "ex6_v6_90_benign_utility_criteria.csv",
        "claims": out / "ex6_v6_90_claim_boundary.json",
        "spec": out / "ex6_v6_90_hardened_requirements_specification.json",
        "result": out / "ex6_v6_90_result.json",
        "binding": out / "ex6_v6_90_binding.json",
        "manifest": out / "ex6_v6_90_manifest.csv",
        "external": out / "ex6_v6_90_manifest_external_binding.json",
    }

    write_csv(paths["verification"], verifications, ["artifact","path","exists","expected_size_bytes","observed_size_bytes","size_match","expected_sha256","observed_sha256","sha256_match","passed"])
    write_csv(paths["requirements"], REQUIREMENTS, ["id","section","requirement","priority","feasibility","available_inputs","missing_inputs","verification","claim_boundary"])

    authorization_schema = {
        "schema_status": "NORMATIVE_REQUIREMENT_NOT_CURRENT_RUNTIME_OBJECT",
        "trusted_transport_available": False,
        "generic_boolean_fallback": "PROHIBITED",
        "required_fields": {
            "authorization_id": "unique immutable identifier",
            "trusted_issuer": "non-model non-prompt trusted principal",
            "action": "exact tool_name",
            "canonical_target": "tool-specific canonical target",
            "proposal_digest": "SHA-256 over canonical action and security-relevant args",
            "issued_at": "trusted issuance boundary",
            "expires_at_or_turn": "trusted expiration boundary",
            "one_successful_use": True,
            "consumed": "trusted consumption state",
        },
        "current_context_support": {
            "action": True,
            "current_target_can_be_derived": True,
            "current_proposal_digest_can_be_derived": True,
            "trusted_issuer": False,
            "authorized_action": False,
            "authorized_target": False,
            "authorized_proposal_digest": False,
            "trusted_expiry": False,
            "trusted_consumption_acknowledgement": False,
        },
        "implementation_status": "WITHHELD_PENDING_TRUSTED_TRANSPORT",
    }
    write_json(paths["authorization"], authorization_schema)

    tool_rows = [r for r in REQUIREMENTS if r["section"] == "tool_specific_handling"]
    write_csv(paths["tool_matrix"], tool_rows, ["id","requirement","priority","feasibility","available_inputs","missing_inputs","verification","claim_boundary"])

    rule_spec = {
        "status": "NORMATIVE_P1_REQUIREMENT",
        "order": [
            "validate supported tool and required argument shape",
            "extract all tool-specific security-relevant arguments independently",
            "canonicalize protected fs path through official helper",
            "identify official exfil payload argument through official helper",
            "classify untrusted current inputs and available provenance",
            "evaluate protected source and outbound payload protections",
            "evaluate a trusted action-target-proposal grant only if trusted transport exists",
            "apply denial or confirmation policy",
            "allow matched benign action",
        ],
        "prohibited_ordering": [
            "generic authorization Boolean unconditional early allow",
            "first-present-key extraction for multi-argument tools",
            "custom approximation before official helper evaluation",
        ],
    }
    write_json(paths["rule_order"], rule_spec)

    helper_spec = {
        "predicates_sha256": EXPECTED_PREDICATES_SHA256,
        "required_public_helpers": {
            "is_protected_secret_path": "canonical protected path classification",
            "exfil_payload_arg": "official sink-to-payload argument mapping",
            "payload_exfiltrates_secret": "official exact and encoded payload matching",
        },
        "private_helper_imports": "PROHIBITED",
        "custom_decoder_or_matcher": "PROHIBITED",
        "real_lineage_precondition": "read_secrets must come from successful same-session protected fs.read outputs",
        "current_input_limitation": "read_secrets are unavailable in the frozen decide context",
    }
    write_json(paths["helpers"], helper_spec)

    state_contract = {
        "stateful_policy_allowed": True,
        "requirements": [
            "declare all mutable security state",
            "snapshot all security-relevant mutable state",
            "restore exactly without aliasing",
            "reset deterministically on the same Sandbox instance",
            "do not treat failed or denied actions as successful authorization consumption",
        ],
        "one_use_authorization_consumption": "REQUIRES_SANDBOX_CHANGE_FOR_TRUSTED_TOOL_SUCCESS_ACKNOWLEDGEMENT",
        "current_interface_support": "snapshot_state and restore_state are available through GuardrailBase",
    }
    write_json(paths["state"], state_contract)

    capability_rows = [
        {"input":"tool_name","available":True,"trust":"PROPOSAL_INPUT","use":"tool-specific routing and action binding comparison"},
        {"input":"tool_args","available":True,"trust":"PROPOSAL_INPUT","use":"path URL data and proposal digest derivation"},
        {"input":"recent_sources","available":True,"trust":"UNTRUSTED_OR_METADATA_ONLY","use":"taint signal only; not protected-value lineage"},
        {"input":"recent_tools","available":True,"trust":"METADATA_ONLY","use":"sequence context only"},
        {"input":"last_user","available":True,"trust":"UNTRUSTED","use":"must not set authorization"},
        {"input":"side_effect","available":True,"trust":"TOOL_METADATA","use":"policy classification"},
        {"input":"scope","available":True,"trust":"TOOL_METADATA","use":"policy classification"},
        {"input":"user_authorized","available":"READ_BY_PACKAGED_NOT_SHOWN_IN_SANDBOX_CTX","trust":"NOT_TRUSTED","use":"must not cause generic allow"},
        {"input":"user_confirmed_safe","available":"READ_BY_PACKAGED_NOT_SHOWN_IN_SANDBOX_CTX","trust":"NOT_TRUSTED","use":"must not cause generic allow"},
    ]
    write_csv(paths["capability"], capability_rows, ["input","available","trust","use"])

    unavailable_rows = [
        {"input":"trusted authorization issuer","needed_for":"authorization authenticity","classification":LABELS["TRANSPORT"]},
        {"input":"authorized action","needed_for":"action binding","classification":LABELS["TRANSPORT"]},
        {"input":"authorized canonical target","needed_for":"target binding","classification":LABELS["TRANSPORT"]},
        {"input":"authorized proposal digest","needed_for":"proposal binding","classification":LABELS["TRANSPORT"]},
        {"input":"trusted authorization expiry","needed_for":"expiration","classification":LABELS["TRANSPORT"]},
        {"input":"successful protected-read outputs","needed_for":"real payload lineage","classification":LABELS["SANDBOX"]},
        {"input":"trusted post-tool outcome acknowledgement","needed_for":"one-successful-use consumption","classification":LABELS["SANDBOX"]},
        {"input":"independent effect observation","needed_for":"live defense claim","classification":LABELS["WITHHELD"]},
    ]
    write_csv(paths["unavailable"], unavailable_rows, ["input","needed_for","classification"])

    comparison_rows = [r for r in REQUIREMENTS if r["section"] == "matched_comparison"]
    benign_rows = [r for r in REQUIREMENTS if r["section"] == "benign_utility"]
    write_csv(paths["comparison"], comparison_rows, ["id","requirement","priority","feasibility","verification","claim_boundary"])
    write_csv(paths["benign"], benign_rows, ["id","requirement","priority","feasibility","available_inputs","missing_inputs","verification","claim_boundary"])

    claim_boundary = {
        "P1_allows": [
            "normative hardened-policy requirements",
            "feasibility classification against frozen current inputs",
            "future comparison invariants",
            "implementation and test eligibility gates",
        ],
        "P1_does_not_establish": [
            "hardened implementation",
            "action-target-proposal authorization enforcement",
            "runtime reachability",
            "real protected-value lineage",
            "guardrail superiority",
            "live defense effectiveness",
            "hosted parity",
            "security vulnerability",
        ],
        "synthetic_controls": "SCORER_OR_POLICY_UNIT_CONTROLS_ONLY",
        "attack_optimization": False,
    }
    write_json(paths["claims"], claim_boundary)

    counts: dict[str, int] = {}
    for row in REQUIREMENTS:
        counts[row["feasibility"]] = counts.get(row["feasibility"], 0) + 1

    specification = {
        "version": VERSION,
        "created_at_utc": now,
        "status": "REQUIREMENTS_SPECIFICATION_COMPLETE_REVIEW_REQUIRED",
        "policy_identity": {
            "class": "ActionTargetBoundOptimalGuardrail",
            "source_file": "aicomp_sdk/guardrails/action_target_bound_optimal.py",
            "packaged_parent_file": "aicomp_sdk/guardrails/optimal.py",
            "packaged_parent_sha256": EXPECTED_OPTIMAL_SHA256,
            "hardened_source_sha256": "NOT_AVAILABLE_IMPLEMENTATION_WITHHELD",
        },
        "generic_boolean_fallback": "PROHIBITED",
        "full_authorization_binding": {
            "requirement": "VALID",
            "implementable_under_current_context": False,
            "implementation_status": "WITHHELD_PENDING_TRUSTED_TRANSPORT",
        },
        "requirements_count": len(REQUIREMENTS),
        "feasibility_counts": counts,
        "implementation_gate": {
            "proposal_level_hardening_subset": "ELIGIBLE_AFTER_REVIEW_FREEZE",
            "trusted_authorization_features": "WITHHELD_PENDING_TRANSPORT",
            "real_lineage_features": "WITHHELD_PENDING_SANDBOX_EVENT_TRANSPORT",
            "hardened_code_written_in_P1": False,
        },
        "claim_boundary": claim_boundary,
    }
    write_json(paths["spec"], specification)

    result = {
        "version": VERSION,
        "created_at_utc": now,
        "status": "P1_REQUIREMENTS_CAPTURE_COMPLETE_REVIEW_REQUIRED",
        "classification": "HARDENED_POLICY_REQUIREMENTS_AND_FEASIBILITY_FROZEN_IMPLEMENTATION_WITHHELD",
        "execution_type": "READ_ONLY_REQUIREMENTS_DESIGN_AND_FEASIBILITY_CLASSIFICATION",
        "parent_v6_89B_manifest_sha256": EXPECTED_PARENT_MANIFEST_SHA256,
        "required_parent_artifacts_verified": len(verifications),
        "requirements_count": len(REQUIREMENTS),
        "feasibility_counts": counts,
        "runtime": False,
        "sdk_imported": False,
        "sdk_source_inspected": False,
        "model_called": False,
        "protected_fixture_opened": False,
        "source_modified": False,
        "hardened_policy_written": False,
        "policy_comparison_executed": False,
        "harness_trick": "NOT_DEMONSTRATED",
        "security_finding": "NOT_ESTABLISHED_REQUIREMENTS_DESIGN_ONLY",
        "attack_optimization": False,
        "next_gate": "MANUAL_REQUIREMENTS_REVIEW_BEFORE_P2_IMPLEMENTABLE_SUBSET",
    }
    write_json(paths["result"], result)

    binding = {
        "version": VERSION,
        "created_at_utc": now,
        "parent_v6_89B_manifest": {"path":str(parent_manifest),"size_bytes":parent_manifest.stat().st_size,"sha256":sha256(parent_manifest)},
        "parent_v6_89B_external_binding": {"path":str(parent_binding),"size_bytes":parent_binding.stat().st_size,"sha256":sha256(parent_binding)},
        "verified_parent_artifacts": verifications,
        "optimal_sha256": EXPECTED_OPTIMAL_SHA256,
        "predicates_sha256": EXPECTED_PREDICATES_SHA256,
        "paths_inferred": False,
        "runtime_executed": False,
        "sdk_imported": False,
        "sdk_source_inspected": False,
        "source_modified": False,
        "python": sys.version,
        "platform": platform.platform(),
    }
    write_json(paths["binding"], binding)

    generated_keys = ["verification","requirements","authorization","tool_matrix","rule_order","helpers","state","capability","unavailable","comparison","benign","claims","spec","result","binding"]
    manifest_rows = [{"artifact":paths[k].name,"role":"DERIVED_P1_REQUIREMENTS","size_bytes":paths[k].stat().st_size,"sha256":sha256(paths[k]),"source_path":str(paths[k])} for k in generated_keys]
    for path in [parent_manifest, parent_binding]:
        manifest_rows.append({"artifact":path.name,"role":"SOURCE_OR_PARENT","size_bytes":path.stat().st_size,"sha256":sha256(path),"source_path":str(path)})
    for row in verifications:
        manifest_rows.append({"artifact":row["artifact"],"role":"VERIFIED_PARENT_EVIDENCE","size_bytes":row["observed_size_bytes"],"sha256":row["observed_sha256"],"source_path":row["path"]})
    write_csv(paths["manifest"], manifest_rows, ["artifact","role","size_bytes","sha256","source_path"])

    external_out = {
        "version": VERSION,
        "created_at_utc": now,
        "manifest_filename": paths["manifest"].name,
        "manifest_size_bytes": paths["manifest"].stat().st_size,
        "manifest_sha256": sha256(paths["manifest"]),
        "status": result["status"],
        "classification": result["classification"],
        "parent_v6_89B_manifest_sha256": EXPECTED_PARENT_MANIFEST_SHA256,
        "optimal_sha256": EXPECTED_OPTIMAL_SHA256,
        "predicates_sha256": EXPECTED_PREDICATES_SHA256,
    }
    write_json(paths["external"], external_out)

    print(json.dumps({
        "status": result["status"],
        "classification": result["classification"],
        "verified_parent_artifacts": len(verifications),
        "requirements_count": len(REQUIREMENTS),
        "feasibility_counts": counts,
        "manifest_sha256": external_out["manifest_sha256"],
        "output_directory": str(out),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
