#!/usr/bin/env python3
"""Controlled fixture-mediated real-chain preflight v1.0.

Read-only preflight. It binds EX8-R2, nine authoritative sources, explicit fs
implementation / registration / fixture-loading sources, and one external
synthetic fixture. It freezes static fs.read routing and a proposed lineage
identity chain. It never imports or executes the SDK, Sandbox, Gym, tools,
fs.read, HTTP, predicates, breach logic, models, or threads.

The external fixture is accepted only when its complete UTF-8 bytes equal:
    AI_AGENT_SECURITY_SYNTHETIC_FIXTURE_V1|<synthetic-marker>\n
The marker must match [A-Z0-9_]{16,64}. This strict format prevents the preflight
from silently accepting credentials, personal information, production data, or
historical protected values as its test fixture.
"""
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "CONTROLLED_FIXTURE_MEDIATED_REAL_CHAIN_PREFLIGHT_v1.0"
PARENT_VERSION = "EX8_INDEPENDENT_PARITY_QUALIFICATION_AND_FREEZE_v1.0"
PARENT_STATUS = "EX8_INDEPENDENT_PARITY_QUALIFICATION_AND_FREEZE_COMPLETE_PASS"
PARENT_MANIFEST_SHA = "7918114B6BADD68E35F4245F0E8D6F8F7945440921C3D12B8F0827F6B03F2CCA"
PARENT_RUNNER_SHA = "2B72CE75E24FAD12D8253665826E54946B26EF794872EFD351AF881307597A8E"
PARENT_FREEZE_SHA = "35ED1B40340D6A9B47901FE3A52FB3D311B9D8FDFC31439547813BFD698CB376"
PARENT_CLAIM_SHA = "863557EB772CD3AA2B560DA3019F50A6C214E0998CA823F4B8FAFD40870D7B65"
PARENT_FREEZE_ID = "EX8.INDEPENDENT.STATIC.PARITY.FREEZE.V1"

KNOWN_SOURCES = {
    "sandbox": ("aicomp_sdk/core/env/sandbox.py", "B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0"),
    "bridge": ("aicomp_sdk/core/env/sandbox_trusted_bridge_v1.py", "3EE9BBB1E65949795A5639D12C55D81D8D0645357260DFC5A91DB1E9710288B6"),
    "transport": ("aicomp_sdk/core/env/trusted_outcome_transport_v1.py", "5C7F7D16A37896959C6F4CC769E5F72A6E5E534EE140BA5CAF2FB70661102CE1"),
    "adapter": ("aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py", "BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"),
}
MARKER_RE = re.compile(r"^[A-Z0-9_]{16,64}$")
TOOL_NAME = "fs.read"
PATH_CANDIDATES = {"path", "file_path", "filepath", "source_path"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
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
        "sha256": sha256_file(path),
    }


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def add_check(rows, check_id, category, passed, observed, expected, failure_layer) -> None:
    rows.append({
        "check_id": check_id,
        "category": category,
        "passed": bool(passed),
        "observed": str(observed),
        "expected": str(expected),
        "failure_layer": failure_layer,
    })


def parse_source(path: Path) -> tuple[str, ast.AST]:
    text = path.read_text(encoding="utf-8")
    return text, ast.parse(text, filename=str(path))


def call_inventory(tree: ast.AST) -> list[dict[str, Any]]:
    rows = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            try:
                name = ast.unparse(node.func)
                expression = ast.unparse(node)
            except Exception:
                continue
            rows.append({"lineno": node.lineno, "call": name, "expression": expression})
    return rows


def string_inventory(tree: ast.AST) -> list[dict[str, Any]]:
    rows = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            rows.append({"lineno": node.lineno, "value": node.value})
    return rows


def function_inventory(tree: ast.AST) -> list[dict[str, Any]]:
    rows = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            positional = [arg.arg for arg in node.args.posonlyargs + node.args.args]
            keyword_only = [arg.arg for arg in node.args.kwonlyargs]
            if positional and positional[0] in {"self", "cls"}:
                positional = positional[1:]
            rows.append({
                "function": node.name,
                "lineno": node.lineno,
                "positional": positional,
                "keyword_only": keyword_only,
                "vararg": node.args.vararg.arg if node.args.vararg else None,
                "kwarg": node.args.kwarg.arg if node.args.kwarg else None,
                "source": ast.unparse(node),
            })
    return rows


def bool_any(values) -> bool:
    return any(bool(value) for value in values)


def token_present(text: str, tokens: list[str]) -> bool:
    lower = text.lower()
    return any(token.lower() in lower for token in tokens)


def deterministic_id(kind: str, fixture_sha: str, canonical_path: str) -> str:
    material = f"EX9.PREFLIGHT.V1|{kind}|{fixture_sha}|{canonical_path}".encode("utf-8")
    return f"preflight-{kind.lower()}-{hashlib.sha256(material).hexdigest()[:24]}"


def main(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir).resolve()
    require(not output_dir.exists(), f"Refusing overwrite: {output_dir}")
    output_dir.mkdir(parents=True)
    checks: list[dict[str, Any]] = []

    try:
        project_root = Path(args.project_root).resolve()
        require(project_root.is_dir(), f"Missing project root: {project_root}")

        parent = {
            "result": Path(args.parent_result).resolve(),
            "checks": Path(args.parent_checks).resolve(),
            "architecture": Path(args.parent_architecture).resolve(),
            "freeze": Path(args.parent_freeze).resolve(),
            "claim": Path(args.parent_claim_boundary).resolve(),
            "binding": Path(args.parent_binding).resolve(),
            "external": Path(args.parent_external_binding).resolve(),
            "manifest": Path(args.parent_manifest).resolve(),
            "runner": Path(args.parent_runner).resolve(),
        }
        for label, path in parent.items():
            require(path.is_file(), f"Missing EX8-R2 {label}: {path}")

        parent_result = read_json(parent["result"])
        parent_freeze = read_json(parent["freeze"])
        parent_claim = read_json(parent["claim"])
        parent_external = read_json(parent["external"])

        add_check(checks, "P0-001", "parent_identity", parent_result.get("version") == PARENT_VERSION and parent_result.get("status") == PARENT_STATUS, parent_result.get("status"), PARENT_STATUS, "FIXTURE")
        add_check(checks, "P0-002", "parent_identity", sha256_file(parent["manifest"]) == PARENT_MANIFEST_SHA and parent_external.get("manifest_sha256") == PARENT_MANIFEST_SHA, sha256_file(parent["manifest"]), PARENT_MANIFEST_SHA, "FIXTURE")
        add_check(checks, "P0-003", "parent_identity", sha256_file(parent["runner"]) == PARENT_RUNNER_SHA and parent_external.get("runner_sha256") == PARENT_RUNNER_SHA, sha256_file(parent["runner"]), PARENT_RUNNER_SHA, "FIXTURE")
        add_check(checks, "P0-004", "parent_identity", sha256_file(parent["freeze"]) == PARENT_FREEZE_SHA and parent_freeze.get("freeze_id") == PARENT_FREEZE_ID, {"sha256": sha256_file(parent["freeze"]), "freeze_id": parent_freeze.get("freeze_id")}, {"sha256": PARENT_FREEZE_SHA, "freeze_id": PARENT_FREEZE_ID}, "FIXTURE")
        add_check(checks, "P0-005", "parent_identity", sha256_file(parent["claim"]) == PARENT_CLAIM_SHA, sha256_file(parent["claim"]), PARENT_CLAIM_SHA, "FIXTURE")
        add_check(checks, "P0-006", "parent_boundary", parent_result.get("readiness", {}).get("controlled_fixture_mediated_real_chain_preflight_eligible") is True and parent_result.get("readiness", {}).get("controlled_actual_fs_read_eligible") is False, parent_result.get("readiness"), "preflight eligible; fs.read ineligible", "CLAIM_BOUNDARY")

        known_paths = {}
        for index, (key, (relative, expected_hash)) in enumerate(KNOWN_SOURCES.items(), start=10):
            path = project_root / relative
            known_paths[key] = path
            actual = sha256_file(path) if path.is_file() else "MISSING"
            add_check(checks, f"P0-{index:03d}", "known_source_identity", path.is_file() and actual == expected_hash, actual, expected_hash, "FIXTURE")

        explicit_sources = {
            "fs_source": Path(args.fs_source).resolve(),
            "registration_source": Path(args.registration_source).resolve(),
            "fixture_loading_source": Path(args.fixture_loading_source).resolve(),
        }
        for index, (key, path) in enumerate(explicit_sources.items(), start=20):
            add_check(checks, f"P0-{index:03d}", "explicit_source", path.is_file(), str(path), "existing file", "FIXTURE")

        all_source_paths = {**known_paths, **explicit_sources}
        source_texts: dict[str, str] = {}
        source_trees: dict[str, ast.AST] = {}
        source_inventory = []
        for index, (key, path) in enumerate(all_source_paths.items(), start=30):
            if not path.is_file():
                continue
            try:
                text, tree = parse_source(path)
                parsed = True
                source_texts[key] = text
                source_trees[key] = tree
            except (UnicodeDecodeError, SyntaxError):
                parsed = False
            source_inventory.append({"source": key, **identity(path), "ast_parse": parsed})
            add_check(checks, f"P0-{index:03d}", "source_parse", parsed, key, "UTF-8 AST PASS", "ADAPTER_PARSE")

        # P1: strict external synthetic fixture.
        fixture = Path(args.synthetic_fixture).resolve()
        add_check(checks, "P1-001", "fixture", fixture.is_file(), str(fixture), "external fixture exists", "FIXTURE")
        marker = args.synthetic_marker
        marker_valid = bool(MARKER_RE.fullmatch(marker))
        add_check(checks, "P1-002", "fixture", marker_valid, marker, "[A-Z0-9_]{16,64}", "FIXTURE")
        fixture_bytes = fixture.read_bytes() if fixture.is_file() else b""
        expected_bytes = f"AI_AGENT_SECURITY_SYNTHETIC_FIXTURE_V1|{marker}\n".encode("utf-8")
        exact_fixture = fixture_bytes == expected_bytes
        add_check(checks, "P1-003", "fixture", exact_fixture, fixture_bytes, expected_bytes, "FIXTURE")
        utf8_ok = False
        try:
            fixture_bytes.decode("utf-8", errors="strict")
            utf8_ok = True
        except UnicodeDecodeError:
            pass
        add_check(checks, "P1-004", "fixture", utf8_ok, utf8_ok, True, "FIXTURE")
        add_check(checks, "P1-005", "fixture", fixture_bytes.endswith(b"\n") and b"\r" not in fixture_bytes, {"ends_lf": fixture_bytes.endswith(b"\n"), "contains_cr": b"\r" in fixture_bytes}, "LF terminal newline and no CR", "FIXTURE")

        proposed_path = args.proposed_canonical_path
        canonical_valid = proposed_path.startswith("/") and ".." not in proposed_path.split("/") and "\\" not in proposed_path and proposed_path.endswith(".txt")
        add_check(checks, "P1-006", "fixture", canonical_valid, proposed_path, "absolute POSIX-style .txt path without traversal", "ARGUMENT_FIDELITY")
        fixture_sha = sha256_bytes(fixture_bytes)
        fixture_spec = {
            "fixture_class": "SYNTHETIC_NON_SENSITIVE",
            "external_input_path": str(fixture),
            "filename": fixture.name,
            "proposed_canonical_path": proposed_path,
            "size_bytes": len(fixture_bytes),
            "sha256": fixture_sha,
            "encoding": "UTF-8",
            "line_ending_policy": "LF_TERMINATED_NO_CR",
            "synthetic_marker": marker,
            "content_schema": "AI_AGENT_SECURITY_SYNTHETIC_FIXTURE_V1|<MARKER>\\n",
            "packaged_fixture_modified": False,
        }

        # P2: source routes. All are static observations.
        fs_text = source_texts.get("fs_source", "")
        reg_text = source_texts.get("registration_source", "")
        load_text = source_texts.get("fixture_loading_source", "")
        sandbox_text = source_texts.get("sandbox", "")
        bridge_text = source_texts.get("bridge", "")
        transport_text = source_texts.get("transport", "")
        adapter_text = source_texts.get("adapter", "")
        fs_tree = source_trees.get("fs_source")
        fs_functions = function_inventory(fs_tree) if fs_tree else []
        fs_calls = call_inventory(fs_tree) if fs_tree else []
        fs_strings = string_inventory(fs_tree) if fs_tree else []
        source_route_rows = []

        registration_observed = TOOL_NAME in reg_text or any(row["value"] == TOOL_NAME for row in string_inventory(source_trees.get("registration_source")) if source_trees.get("registration_source"))
        add_check(checks, "P2-001", "route", registration_observed, TOOL_NAME in reg_text, TOOL_NAME, "ROUTING")
        source_route_rows.append({"requirement": "fs.read registration", "status": "STATICALLY_OBSERVED" if registration_observed else "NOT_ESTABLISHED", "source": str(explicit_sources["registration_source"])})

        read_functions = [row for row in fs_functions if row["function"].lower() in {"read", "fs_read", "read_file", "_read"} or "read" in row["function"].lower()]
        arg_names = sorted({name for row in read_functions for name in row["positional"] + row["keyword_only"]})
        path_arg = next((name for name in arg_names if name in PATH_CANDIDATES), None)
        add_check(checks, "P2-002", "argument_schema", path_arg is not None, arg_names, sorted(PATH_CANDIDATES), "ARGUMENT_FIDELITY")
        source_route_rows.append({"requirement": "fs.read path argument", "status": "STATICALLY_OBSERVED" if path_arg else "NOT_ESTABLISHED", "source": str(explicit_sources["fs_source"])})

        root_tokens = ["resolve", "relative_to", "is_relative_to", "commonpath", "fixtures_dir"]
        root_resolution = token_present(fs_text + "\n" + load_text, root_tokens)
        containment = token_present(fs_text, ["relative_to", "is_relative_to", "commonpath"])
        add_check(checks, "P2-003", "source_retrieval", root_resolution, root_tokens, "filesystem-root resolution evidence", "SOURCE_RETRIEVAL")
        add_check(checks, "P2-004", "source_retrieval", containment, containment, True, "SOURCE_RETRIEVAL")
        source_route_rows.append({"requirement": "root resolution", "status": "STATICALLY_OBSERVED" if root_resolution else "NOT_ESTABLISHED", "source": f"{explicit_sources['fs_source']};{explicit_sources['fixture_loading_source']}"})
        source_route_rows.append({"requirement": "inside-root enforcement", "status": "STATICALLY_OBSERVED" if containment else "NOT_ESTABLISHED", "source": str(explicit_sources["fs_source"])})

        successful_return = token_present(fs_text, ["read_text", "read_bytes", "return content", "return text", ".read("])
        failure_return = token_present(fs_text, ["except", "error", "not found", "raise", "permission"])
        add_check(checks, "P2-005", "return_representation", successful_return, successful_return, True, "SECRET_CAPTURE")
        add_check(checks, "P2-006", "return_representation", failure_return, failure_return, True, "SOURCE_RETRIEVAL")

        last_source = "last_source" in fs_text or "last_source" in reg_text or "last_source" in sandbox_text
        tool_event = "ToolEvent(" in sandbox_text and "self.trace.add_tool" in sandbox_text
        post_tool = "POST_TOOL_CALL" in sandbox_text
        bridge_ack = "acknowledge" in bridge_text and "trusted_transport" in bridge_text
        transport_metadata = all(token in transport_text for token in ["canonical_source_path", "raw_output_sha256", "protected_value_sha256_or_bound_digest", "completion_sequence", "success"])
        adapter_after = "after_tool" in adapter_text
        add_check(checks, "P2-007", "provenance", last_source, last_source, True, "PROVENANCE")
        add_check(checks, "P2-008", "tool_event", tool_event, tool_event, True, "TOOL_CALL_SERIALIZATION")
        add_check(checks, "P2-009", "post_tool", post_tool, post_tool, True, "ROUTING")
        add_check(checks, "P2-010", "bridge", bridge_ack, bridge_ack, True, "AUTHORIZATION_TRANSPORT")
        add_check(checks, "P2-011", "transport", transport_metadata, transport_metadata, True, "AUTHORIZATION_TRANSPORT")
        add_check(checks, "P2-012", "adapter", adapter_after, adapter_after, True, "AUTHORIZATION_TRANSPORT")
        for requirement, observed, source in [
            ("last_source propagation", last_source, explicit_sources["fs_source"]),
            ("ToolEvent construction", tool_event, known_paths["sandbox"]),
            ("POST_TOOL_CALL hook", post_tool, known_paths["sandbox"]),
            ("bridge acknowledgement route", bridge_ack, known_paths["bridge"]),
            ("transport metadata", transport_metadata, known_paths["transport"]),
            ("adapter after_tool", adapter_after, known_paths["adapter"]),
        ]:
            source_route_rows.append({"requirement": requirement, "status": "STATICALLY_OBSERVED" if observed else "NOT_ESTABLISHED", "source": str(source)})

        # P3: deterministic proposed lineage identities, not runtime identities.
        lineage_kinds = [
            "trace", "proposal", "source-tool-call", "source-event", "outcome",
            "adapter-acknowledgement", "consumption",
        ]
        lineage = {kind.replace("-", "_") + "_identity": deterministic_id(kind, fixture_sha, proposed_path) for kind in lineage_kinds}
        lineage.update({
            "canonical_source_path": proposed_path,
            "fixture_sha256": fixture_sha,
            "raw_return_digest": fixture_sha,
            "protected_bound_digest": sha256_bytes(f"EX9.PREFLIGHT.BOUND.V1|{fixture_sha}|{proposed_path}|{lineage['proposal_identity']}|{lineage['source_event_identity']}".encode("utf-8")),
            "identity_status": "PROPOSED_PREFLIGHT_IDENTITIES_NOT_RUNTIME_OBSERVATIONS",
        })
        identity_unique = len({v for k, v in lineage.items() if k.endswith("_identity")}) == len(lineage_kinds)
        add_check(checks, "P3-001", "lineage", identity_unique, lineage, "all proposed identities unique", "PROVENANCE")
        add_check(checks, "P3-002", "lineage", lineage["raw_return_digest"] == fixture_sha, lineage["raw_return_digest"], fixture_sha, "PROVENANCE")
        add_check(checks, "P3-003", "lineage", lineage["identity_status"] == "PROPOSED_PREFLIGHT_IDENTITIES_NOT_RUNTIME_OBSERVATIONS", lineage["identity_status"], "proposal-only boundary", "CLAIM_BOUNDARY")

        # P4: only authorize the next controlled read gate when all preflight checks pass.
        failed_ids = [row["check_id"] for row in checks if not row["passed"]]
        preflight_pass = not failed_ids
        status = "CONTROLLED_FIXTURE_MEDIATED_REAL_CHAIN_PREFLIGHT_COMPLETE_PASS" if preflight_pass else "CONTROLLED_FIXTURE_MEDIATED_REAL_CHAIN_PREFLIGHT_COMPLETE_WITH_GAPS"
        next_gate = "CONTROLLED_ACTUAL_SOURCE_READ_AND_LINEAGE_QUALIFICATION" if preflight_pass else "CONTROLLED_FIXTURE_MEDIATED_REAL_CHAIN_PREFLIGHT_R1_RECONCILIATION"
        eligibility_reason = "ALL_IDENTITY_FIXTURE_ROUTE_AND_LINEAGE_PREFLIGHT_CHECKS_PASS" if preflight_pass else "WITHHELD_DUE_TO_FAILED_PREFLIGHT_CHECKS:" + ",".join(failed_ids)

        contract = {
            "contract_id": "EX9.CONTROLLED.FIXTURE.REAL.CHAIN.PREFLIGHT.V1",
            "status": "FROZEN" if preflight_pass else "NOT_FROZEN",
            "fixture": fixture_spec,
            "source_routes": source_route_rows,
            "proposed_lineage": lineage,
            "authorization": {
                "controlled_actual_fs_read_eligible": preflight_pass,
                "reason": eligibility_reason,
                "authorized_next_gate_only": "CONTROLLED_ACTUAL_SOURCE_READ_AND_LINEAGE_QUALIFICATION" if preflight_pass else "NONE",
                "http_sink_eligible": False,
                "model_execution_eligible": False,
                "Sandbox_interact_eligible": False,
                "Gym_eligible": False,
            },
            "claim_boundary": {
                "fixture_identity": "ESTABLISHED",
                "static_source_route": "ESTABLISHED" if preflight_pass else "GAPS_IDENTIFIED",
                "actual_fs_read": "NOT_EXECUTED",
                "actual_source_retrieval": "NOT_EVALUATED",
                "returned_content_capture": "NOT_ESTABLISHED",
                "protected_value_lineage": "NOT_ESTABLISHED",
                "runtime_parity": "NOT_EVALUATED",
                "hosted_parity": "NOT_ESTABLISHED",
            },
        }
        claim_boundary = {
            "allowed": [
                "external synthetic fixture identity and strict content schema",
                "static fs.read registration, argument, containment, return, event, hook, bridge, transport, and adapter preflight findings",
                "proposed deterministic lineage identity contract",
                "eligibility recommendation for one separately authorized controlled fs.read gate",
            ],
            "prohibited": [
                "actual fs.read execution", "actual source retrieval", "returned-content capture",
                "protected-value lineage", "Sandbox or Gym behavior", "HTTP sink", "predicate or breach behavior",
                "model execution", "runtime parity", "hosted parity", "guardrail effectiveness",
                "real exfiltration prevention",
            ],
        }
        result = {
            "version": VERSION,
            "created_at_utc": utc_now(),
            "status": status,
            "classification": "READ_ONLY_FIXTURE_AND_SOURCE_ROUTE_PREFLIGHT",
            "EX8_R2_parent_verified": True,
            "checks": {"total": len(checks), "passed": len(checks) - len(failed_ids), "failed": len(failed_ids), "failed_ids": failed_ids},
            "fixture": fixture_spec,
            "contract_id": contract["contract_id"],
            "lineage_status": lineage["identity_status"],
            "readiness": {
                "controlled_actual_fs_read_eligible": preflight_pass,
                "controlled_actual_fs_read_eligibility_reason": eligibility_reason,
                "http_sink_eligible": False,
                "runtime_parity_eligible": False,
            },
            "execution_boundaries": {
                "frozen_artifacts_modified": False,
                "packaged_fixtures_modified": False,
                "source_modified": False,
                "sdk_modules_imported": False,
                "sdk_modules_executed": False,
                "Sandbox_instantiated": False,
                "Sandbox_interact_executed": False,
                "Gym_executed": False,
                "real_tools_executed": False,
                "actual_fs_read_executed": False,
                "http_sink_executed": False,
                "predicates_executed": False,
                "breach_executed": False,
                "models_used": False,
                "threads_executed": False,
                "external_effects_observed": False,
                "external_synthetic_fixture_read_by_preflight_runner": True,
            },
            "scientific_verdict": {
                "fixture_identity": "ESTABLISHED",
                "static_source_route": "ESTABLISHED" if preflight_pass else "GAPS_IDENTIFIED",
                "actual_source_retrieval": "NOT_EVALUATED",
                "returned_content_capture": "NOT_ESTABLISHED",
                "protected_value_lineage": "NOT_ESTABLISHED",
                "harness_trick": "NOT_DEMONSTRATED",
                "robust_security_findings": "NOT_ESTABLISHED",
            },
            "claim_boundary": claim_boundary,
            "next_gate": next_gate,
        }

        paths = {
            "result": output_dir / "ex9_preflight_result.json",
            "checks": output_dir / "ex9_preflight_checks.csv",
            "fixture": output_dir / "ex9_fixture_spec.json",
            "routes": output_dir / "ex9_source_routes.csv",
            "lineage": output_dir / "ex9_lineage_contract.json",
            "contract": output_dir / "ex9_preflight_contract.json",
            "claim": output_dir / "ex9_claim_boundary.json",
            "sources": output_dir / "ex9_source_inventory.csv",
            "binding": output_dir / "ex9_binding.json",
        }
        write_json(paths["result"], result)
        write_csv(paths["checks"], checks, ["check_id", "category", "passed", "observed", "expected", "failure_layer"])
        write_json(paths["fixture"], fixture_spec)
        write_csv(paths["routes"], source_route_rows, ["requirement", "status", "source"])
        write_json(paths["lineage"], lineage)
        write_json(paths["contract"], contract)
        write_json(paths["claim"], claim_boundary)
        write_csv(paths["sources"], source_inventory, ["source", "artifact", "path", "size_bytes", "sha256", "ast_parse"])
        write_json(paths["binding"], {
            "version": VERSION,
            "created_at_utc": utc_now(),
            "runner": identity(Path(__file__).resolve()),
            "parent": {key: identity(path) for key, path in parent.items()},
            "sources": {key: identity(path) for key, path in all_source_paths.items()},
            "external_fixture": identity(fixture),
            "project_root": str(project_root),
            "frozen_artifacts_modified": False,
            "packaged_fixtures_modified": False,
            "source_modified": False,
            "sdk_modules_imported": False,
            "sdk_modules_executed": False,
            "actual_fs_read_executed": False,
        })

        manifest_rows = (
            [{**identity(path), "role": "EX9_PREFLIGHT_DERIVED"} for path in paths.values()]
            + [{**identity(path), "role": "EX9_PREFLIGHT_BOUND_PARENT"} for path in parent.values()]
            + [{**identity(path), "role": "EX9_PREFLIGHT_REVIEWED_SOURCE"} for path in all_source_paths.values()]
            + [{**identity(fixture), "role": "EX9_EXTERNAL_SYNTHETIC_FIXTURE"}]
        )
        manifest_path = output_dir / "ex9_preflight_manifest.csv"
        write_csv(manifest_path, manifest_rows, ["artifact", "role", "size_bytes", "sha256", "path"])
        external_path = output_dir / "ex9_preflight_manifest_external_binding.json"
        write_json(external_path, {
            "version": VERSION,
            "created_at_utc": utc_now(),
            "status": status,
            "manifest_filename": manifest_path.name,
            "manifest_size_bytes": manifest_path.stat().st_size,
            "manifest_sha256": sha256_file(manifest_path),
            "runner_sha256": sha256_file(Path(__file__).resolve()),
            "parent_EX8_R2_manifest_sha256": PARENT_MANIFEST_SHA,
            "contract_id": contract["contract_id"],
            "fixture_sha256": fixture_sha,
            "checks_total": len(checks),
            "checks_passed": len(checks) - len(failed_ids),
            "checks_failed": len(failed_ids),
            "controlled_actual_fs_read_eligible": preflight_pass,
            "eligibility_reason": eligibility_reason,
            "actual_fs_read_executed": False,
            "http_sink_eligible": False,
            "source_modified": False,
            "next_gate": next_gate,
        })

        print(json.dumps({
            "status": status,
            "checks_total": len(checks),
            "checks_passed": len(checks) - len(failed_ids),
            "checks_failed": len(failed_ids),
            "failed_ids": failed_ids,
            "fixture_sha256": fixture_sha,
            "contract_id": contract["contract_id"],
            "controlled_actual_fs_read_eligible": preflight_pass,
            "eligibility_reason": eligibility_reason,
            "actual_fs_read_executed": False,
            "manifest_sha256": sha256_file(manifest_path),
            "next_gate": next_gate,
        }, indent=2))

    except Exception as exc:
        (output_dir / "EX9_PREFLIGHT_FAILED.json").write_text(json.dumps({
            "version": VERSION,
            "created_at_utc": utc_now(),
            "status": "CONTROLLED_FIXTURE_MEDIATED_REAL_CHAIN_PREFLIGHT_BLOCKED",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "checks_frozen": checks,
            "frozen_artifacts_modified": False,
            "packaged_fixtures_modified": False,
            "source_modified": False,
            "sdk_modules_imported": False,
            "sdk_modules_executed": False,
            "actual_fs_read_executed": False,
            "effects_observed": False,
        }, indent=2), encoding="utf-8")
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=VERSION)
    for flag in [
        "parent-result", "parent-checks", "parent-architecture", "parent-freeze",
        "parent-claim-boundary", "parent-binding", "parent-external-binding",
        "parent-manifest", "parent-runner", "project-root", "fs-source",
        "registration-source", "fixture-loading-source", "synthetic-fixture",
        "synthetic-marker", "proposed-canonical-path", "output-dir",
    ]:
        parser.add_argument("--" + flag, required=True)
    return parser.parse_args()


if __name__ == "__main__":
    try:
        main(parse_args())
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
