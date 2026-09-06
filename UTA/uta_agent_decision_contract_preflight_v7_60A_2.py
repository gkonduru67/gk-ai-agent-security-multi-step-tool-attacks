#!/usr/bin/env python3
"""UTA preflight 1: inspect and validate the running SDK agent decision contract.

This script performs no Sandbox interaction and invokes no tools. It records the
runtime representation of AgentDecision, enumerates concrete union members,
resolves ToolCall plus concrete call/completion decision classes, constructs one
instance of each outside Sandbox, and tests union isinstance support.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import os
import platform
import sys
import traceback
import types as py_types
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, get_args, get_origin

VERSION = "UTA_GUARDRAIL_BOUNDARY_PREFLIGHT_1_v7.60A.2"
SCHEMA = "UTA_AGENT_DECISION_CONTRACT_PREFLIGHT_V1"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [safe(v) for v in value]
    if hasattr(value, "model_dump"):
        try:
            return safe(value.model_dump())
        except Exception:
            pass
    if hasattr(value, "to_dict"):
        try:
            return safe(value.to_dict())
        except Exception:
            pass
    if hasattr(value, "__dict__"):
        try:
            return {k: safe(v) for k, v in vars(value).items() if not k.startswith("_")}
        except Exception:
            pass
    return repr(value)


def write_json_exclusive(path: Path, payload: Any) -> None:
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite: {path}")
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(
        json.dumps(safe(payload), indent=2, ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    os.replace(temp, path)


def qualified_name(obj: Any) -> str:
    module = getattr(obj, "__module__", None)
    name = getattr(obj, "__qualname__", getattr(obj, "__name__", None))
    if module and name:
        return f"{module}.{name}"
    return repr(obj)


def signature_text(obj: Any) -> str | None:
    try:
        return str(inspect.signature(obj))
    except (TypeError, ValueError):
        return None


def parameter_summary(candidate: Any) -> dict[str, Any]:
    try:
        sig = inspect.signature(candidate)
    except (TypeError, ValueError) as exc:
        return {"signature": None, "signature_error": f"{type(exc).__name__}: {exc}"}
    return {
        "signature": str(sig),
        "parameters": {
            name: {
                "kind": str(param.kind),
                "required": param.default is inspect.Parameter.empty,
                "default": None if param.default is inspect.Parameter.empty else repr(param.default),
                "annotation": repr(param.annotation),
            }
            for name, param in sig.parameters.items()
        },
    }


def union_members(alias: Any) -> list[Any]:
    members = list(get_args(alias))
    if members:
        return members
    if isinstance(alias, py_types.UnionType):
        return list(getattr(alias, "__args__", ()))
    return []


def can_supply(candidate: Any, supplied: set[str]) -> bool:
    """True when all required named parameters can be supplied by this set."""
    try:
        sig = inspect.signature(candidate)
    except (TypeError, ValueError):
        return False
    for name, param in sig.parameters.items():
        if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        if param.default is inspect.Parameter.empty and name not in supplied:
            return False
    return True


def resolve_call_decision(members: list[Any]) -> tuple[Any, dict[str, Any]]:
    attempts = []
    for candidate in members:
        record = {
            "candidate": qualified_name(candidate),
            "is_class": inspect.isclass(candidate),
            **parameter_summary(candidate),
        }
        attempts.append(record)
        if not inspect.isclass(candidate):
            continue
        try:
            params = inspect.signature(candidate).parameters
        except (TypeError, ValueError):
            continue
        if "call" in params and can_supply(candidate, {"call", "assistant_message"}):
            return candidate, {
                "strategy": "concrete union member accepting call",
                "selected": qualified_name(candidate),
                "signature": str(inspect.signature(candidate)),
                "attempts": attempts,
            }
    raise RuntimeError("No concrete AgentDecision union member accepting 'call' was resolved")


def resolve_completion_decision(members: list[Any], call_type: Any) -> tuple[Any, dict[str, Any], dict[str, Any]]:
    """Resolve and construct a no-tool completion using evidence-driven templates."""
    attempts = []
    templates = [
        ("assistant_message_only", {"assistant_message": "Contract preflight complete"}),
        ("call_none_and_assistant_message", {"call": None, "assistant_message": "Contract preflight complete"}),
        ("message_only", {"message": "Contract preflight complete"}),
        ("text_only", {"text": "Contract preflight complete"}),
        ("content_only", {"content": "Contract preflight complete"}),
    ]
    for candidate in members:
        if not inspect.isclass(candidate):
            attempts.append({"candidate": qualified_name(candidate), "is_class": False})
            continue
        sig = signature_text(candidate)
        for template_name, kwargs in templates:
            try:
                instance = candidate(**kwargs)
                return candidate, {
                    "strategy": "first concrete union member constructible as no-tool completion",
                    "selected": qualified_name(candidate),
                    "signature": sig,
                    "template": template_name,
                    "kwargs": kwargs,
                    "attempts": attempts,
                }, {"instance": instance, "template": template_name, "kwargs": kwargs}
            except Exception as exc:
                attempts.append({
                    "candidate": qualified_name(candidate),
                    "signature": sig,
                    "template": template_name,
                    "exception_type": type(exc).__name__,
                    "exception": str(exc),
                })
    raise RuntimeError("No concrete AgentDecision union member could construct a no-tool completion")


def construct_call_decision(decision_type: Any, call: Any) -> tuple[Any, dict[str, Any]]:
    templates = [
        ("call_and_message", {"call": call, "assistant_message": None}),
        ("call_only", {"call": call}),
    ]
    attempts = []
    for name, kwargs in templates:
        try:
            return decision_type(**kwargs), {
                "template": name,
                "kwargs_keys": list(kwargs),
                "attempts": attempts,
            }
        except Exception as exc:
            attempts.append({
                "template": name,
                "exception_type": type(exc).__name__,
                "exception": str(exc),
            })
    raise RuntimeError(f"Resolved call-decision type could not be constructed: {attempts!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    root = args.project_root.resolve()
    out = args.out_dir.resolve()
    if out.exists():
        raise SystemExit(f"Refusing existing output directory: {out}")

    sdk_types_path = root / "aicomp_sdk" / "agents" / "types.py"
    if not sdk_types_path.is_file():
        raise SystemExit(f"SDK types source not found: {sdk_types_path}")

    sys.path.insert(0, str(root))
    out.mkdir(parents=True)
    stage = "IMPORT_AGENT_TYPES"
    report_path = out / "uta_agent_decision_contract_preflight_v7_60A_2.json"
    failure_path = out / "uta_agent_decision_contract_preflight_v7_60A_2_failure.json"

    try:
        agent_types = importlib.import_module("aicomp_sdk.agents.types")
        stage = "INSPECT_AGENT_DECISION"
        alias = getattr(agent_types, "AgentDecision")
        members = union_members(alias)
        if not members:
            raise RuntimeError(f"AgentDecision has no discoverable union members: {alias!r}")

        member_records = [
            {
                "qualified_name": qualified_name(member),
                "repr": repr(member),
                "runtime_type": qualified_name(type(member)),
                "is_class": inspect.isclass(member),
                **parameter_summary(member),
            }
            for member in members
        ]

        stage = "RESOLVE_TOOL_CALL"
        tool_call_type = getattr(agent_types, "ToolCall")
        if not inspect.isclass(tool_call_type):
            raise RuntimeError(f"ToolCall is not a concrete class: {tool_call_type!r}")
        tool_call_signature = signature_text(tool_call_type)
        call = tool_call_type(
            call_id="uta-boundary-preflight-call",
            tool_name="fs.write",
            arguments={"path": "uta_boundary_preflight.txt", "content": "UTA_BOUNDARY_PREFLIGHT_SYNTHETIC"},
        )

        stage = "RESOLVE_CALL_DECISION"
        call_decision_type, call_resolution = resolve_call_decision(members)
        call_decision, call_construction = construct_call_decision(call_decision_type, call)

        stage = "RESOLVE_COMPLETION_DECISION"
        completion_type, completion_resolution, completion_construction = resolve_completion_decision(members, tool_call_type)
        completion_decision = completion_construction["instance"]

        stage = "ISINSTANCE_UNION_CHECK"
        isinstance_supported = True
        isinstance_error = None
        try:
            call_is_union_member = isinstance(call_decision, alias)
            completion_is_union_member = isinstance(completion_decision, alias)
        except TypeError as exc:
            isinstance_supported = False
            isinstance_error = f"{type(exc).__name__}: {exc}"
            call_is_union_member = None
            completion_is_union_member = None

        checks = {
            "agent_decision_runtime_representation_recorded": True,
            "concrete_union_members_recorded": len(member_records) > 0,
            "concrete_call_decision_type_resolved": inspect.isclass(call_decision_type),
            "concrete_completion_decision_type_resolved": inspect.isclass(completion_type),
            "tool_call_type_resolved": inspect.isclass(tool_call_type),
            "call_decision_constructed_outside_sandbox": call_decision is not None,
            "completion_decision_constructed_outside_sandbox": completion_decision is not None,
            "isinstance_against_union_supported": isinstance_supported,
            "call_decision_isinstance_union": call_is_union_member,
            "completion_decision_isinstance_union": completion_is_union_member,
        }
        required_pass = all([
            checks["agent_decision_runtime_representation_recorded"],
            checks["concrete_union_members_recorded"],
            checks["concrete_call_decision_type_resolved"],
            checks["concrete_completion_decision_type_resolved"],
            checks["tool_call_type_resolved"],
            checks["call_decision_constructed_outside_sandbox"],
            checks["completion_decision_constructed_outside_sandbox"],
        ])
        # isinstance is informational where Python/runtime typing does not support it.
        if isinstance_supported:
            required_pass = required_pass and bool(call_is_union_member) and bool(completion_is_union_member)

        payload = {
            "schema": SCHEMA,
            "version": VERSION,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "status": "PASS" if required_pass else "FAIL",
            "scientific_scope": "SDK agent decision contract only; no Sandbox or guardrail behavior tested",
            "project_root": str(root),
            "sdk_types_source": {
                "path": str(sdk_types_path),
                "sha256": sha256_file(sdk_types_path),
            },
            "runtime": {
                "python": sys.version,
                "platform": platform.platform(),
            },
            "agent_decision": {
                "repr": repr(alias),
                "runtime_type": qualified_name(type(alias)),
                "origin": repr(get_origin(alias)),
                "member_count": len(members),
                "members": member_records,
            },
            "tool_call": {
                "qualified_name": qualified_name(tool_call_type),
                "signature": tool_call_signature,
                "constructed_instance_type": qualified_name(type(call)),
                "constructed_instance": call,
            },
            "call_decision": {
                "resolution": call_resolution,
                "construction": call_construction,
                "instance_type": qualified_name(type(call_decision)),
                "instance": call_decision,
            },
            "completion_decision": {
                "resolution": completion_resolution,
                "construction": {
                    "template": completion_construction["template"],
                    "kwargs": completion_construction["kwargs"],
                },
                "instance_type": qualified_name(type(completion_decision)),
                "instance": completion_decision,
            },
            "union_isinstance": {
                "supported": isinstance_supported,
                "error": isinstance_error,
                "call_decision_result": call_is_union_member,
                "completion_decision_result": completion_is_union_member,
                "interpretation": "Required when supported; informational when runtime union isinstance raises TypeError",
            },
            "checks": checks,
            "next_gate": "Run preflight_2_sandbox only if status is PASS",
        }
        write_json_exclusive(report_path, payload)
        report_hash = sha256_file(report_path)
        print(f"Experiment: {VERSION}")
        print(f"Status: {payload['status']}")
        print(f"AgentDecision: {alias!r}")
        print(f"Call decision: {qualified_name(call_decision_type)}")
        print(f"Completion decision: {qualified_name(completion_type)}")
        print(f"ToolCall: {qualified_name(tool_call_type)}")
        print(f"Union isinstance supported: {isinstance_supported}")
        print(f"Report: {report_path}")
        print(f"Report SHA256: {report_hash}")
        return 0 if required_pass else 3

    except Exception as exc:
        write_json_exclusive(failure_path, {
            "schema": SCHEMA,
            "version": VERSION,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "status": "FAIL",
            "stage": stage,
            "exception_type": type(exc).__name__,
            "exception": str(exc),
            "traceback": traceback.format_exc(),
            "scientific_result": None,
            "next_gate": "Do not run preflight_2_sandbox",
        })
        print(f"Failed stage: {stage}", file=sys.stderr)
        print(f"Diagnostic: {failure_path}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
