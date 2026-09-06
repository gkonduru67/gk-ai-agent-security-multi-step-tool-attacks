from __future__ import annotations
import copy, hashlib
from collections.abc import Mapping
from typing import Any
from aicomp_sdk.guardrails.base import Decision, GuardrailBase

POLICY_VERSION = "UTA_OPTIMAL_PLUS_v7.71A"
DANGEROUS_OPERATIONS = {"fs.delete", "fs.write", "shell.run", "http.post", "email.send"}
SENSITIVE_PATTERNS = {"secret", "password", "token", "key", "credential", "private", "confidential", "api_key"}
CONTENT_KEYS = ("content", "data", "body", "cmd")
TARGET_KEYS = ("path", "url")

def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest().upper()

def _target(args: Mapping[str, Any]) -> str:
    for key in TARGET_KEYS:
        if key in args:
            return str(args[key])
    return ""

def _content(args: Mapping[str, Any]) -> str | None:
    for key in CONTENT_KEYS:
        if key in args:
            return str(args[key])
    return None

class Guardrail(GuardrailBase):
    """Research Optimal+ policy. Not the packaged Kaggle optimal guardrail."""
    def __init__(self) -> None:
        super().__init__()
        self.successful_provenance: dict[str, dict[str, Any]] = {}
        self.authorizations: dict[str, dict[str, Any]] = {}
        self.event_index = 0
        self.decision_audit: list[dict[str, Any]] = []
        self._pending_allow: dict[str, Any] | None = None
        self._initial_state = self._state()

    def _state(self) -> dict[str, Any]:
        return {"successful_provenance": copy.deepcopy(self.successful_provenance), "authorizations": copy.deepcopy(self.authorizations), "event_index": self.event_index, "decision_audit": copy.deepcopy(self.decision_audit), "pending_allow": copy.deepcopy(self._pending_allow)}

    def snapshot_state(self) -> dict[str, Any]:
        return self._state()

    def restore_state(self, state: Any) -> None:
        state = copy.deepcopy(state if state is not None else self._initial_state)
        self.successful_provenance = state.get("successful_provenance", {})
        self.authorizations = state.get("authorizations", {})
        self.event_index = int(state.get("event_index", 0))
        self.decision_audit = state.get("decision_audit", [])
        self._pending_allow = state.get("pending_allow")

    def register_source_result(self, *, source_event_id: str, source_tool: str, source_identifier: str, output: str, succeeded: bool, event_index: int | None = None) -> bool:
        if not succeeded or not output or source_tool not in {"web.open", "email.read"}:
            return False
        record = {"source_event_id": source_event_id, "source_tool": source_tool, "source_identifier": source_identifier, "source_output": output, "source_output_sha256": _sha(output), "event_index": self.event_index if event_index is None else int(event_index), "succeeded": True}
        self.successful_provenance[source_event_id] = record
        return True

    def register_authorization(self, authorization: Mapping[str, Any]) -> None:
        data = copy.deepcopy(dict(authorization))
        auth_id = str(data.get("authorization_id") or "")
        if not auth_id:
            raise ValueError("authorization_id is required")
        self.authorizations[auth_id] = data

    def _lineage(self, content: str | None) -> tuple[str, dict[str, Any] | None]:
        if content is None:
            return "UNKNOWN", None
        exact = [r for r in self.successful_provenance.values() if content == r["source_output"]]
        if exact:
            return "EXACT_SOURCE_OUTPUT", sorted(exact, key=lambda r: r["event_index"], reverse=True)[0]
        transformed = [r for r in self.successful_provenance.values() if r["source_output"] and r["source_output"] in content]
        if transformed:
            return "TRANSFORMED_SOURCE_OUTPUT", sorted(transformed, key=lambda r: r["event_index"], reverse=True)[0]
        return "UNRELATED", None

    def _deny(self, code: str, detail: str) -> Decision:
        return Decision.deny(f"{code}:{detail}")

    def decide(self, tool_name: str, tool_args: Mapping[str, Any], context: Mapping[str, Any]) -> Decision:
        self.event_index += 1
        target = _target(tool_args)
        content = _content(tool_args)
        if target and any(p in target.lower() for p in SENSITIVE_PATTERNS):
            decision = self._deny("DENY_SENSITIVE_TARGET", target)
            self._audit(tool_name, tool_args, context, "NOT_EVALUATED", None, decision)
            return decision
        if tool_name not in DANGEROUS_OPERATIONS:
            decision = Decision.allow("ALLOW_ORDINARY_NON_DANGEROUS")
            self._audit(tool_name, tool_args, context, "NOT_APPLICABLE", None, decision)
            return decision
        lineage, source = self._lineage(content)
        if lineage == "UNRELATED":
            decision = Decision.allow("ALLOW_ORDINARY_UNRELATED")
            self._audit(tool_name, tool_args, context, lineage, None, decision)
            return decision
        if lineage == "UNKNOWN":
            decision = self._deny("DENY_UNKNOWN_LINEAGE", "content-bearing argument missing")
            self._audit(tool_name, tool_args, context, lineage, None, decision)
            return decision
        supplied = context.get("structured_authorization")
        if supplied is None:
            decision = self._deny("DENY_MISSING_AUTHORIZATION", lineage)
            self._audit(tool_name, tool_args, context, lineage, source, decision)
            return decision
        if not isinstance(supplied, Mapping):
            decision = self._deny("DENY_UNSTRUCTURED_AUTHORIZATION", type(supplied).__name__)
            self._audit(tool_name, tool_args, context, lineage, source, decision)
            return decision
        auth_id = str(supplied.get("authorization_id") or "")
        auth = self.authorizations.get(auth_id)
        if auth is None or dict(supplied) != auth:
            decision = self._deny("DENY_UNSTRUCTURED_AUTHORIZATION", "authorization not registered by trusted transport")
            self._audit(tool_name, tool_args, context, lineage, source, decision)
            return decision
        checks = [
            (auth.get("status") == "ACTIVE", "DENY_INVALID_STATUS", str(auth.get("status"))),
            (auth.get("revoked") is False, "DENY_REVOKED", auth_id),
            (self.event_index >= int(auth.get("valid_from_event", 0)), "DENY_NOT_YET_VALID", auth_id),
            (self.event_index <= int(auth.get("expires_after_event", -1)), "DENY_EXPIRED", auth_id),
            (int(auth.get("consumed_execution_count", 0)) < int(auth.get("allowed_execution_count", 0)), "DENY_ALREADY_CONSUMED", auth_id),
            (auth.get("tool_name") == tool_name, "DENY_TOOL_SCOPE_MISMATCH", tool_name),
            (auth.get("target") == target, "DENY_TARGET_SCOPE_MISMATCH", target),
            (auth.get("source_event_id") == source["source_event_id"], "DENY_SOURCE_BINDING_MISMATCH", source["source_event_id"]),
            (auth.get("source_output_sha256") == source["source_output_sha256"], "DENY_SOURCE_HASH_MISMATCH", source["source_output_sha256"]),
            (auth.get("authorized_argument_sha256") == _sha(content or ""), "DENY_CONTENT_BINDING_MISMATCH", _sha(content or "")),
            (auth.get("derivation_mode") == lineage, "DENY_DERIVATION_MODE_MISMATCH", lineage),
        ]
        for passed, code, detail in checks:
            if not passed:
                decision = self._deny(code, detail)
                self._audit(tool_name, tool_args, context, lineage, source, decision)
                return decision
        self._pending_allow = {"authorization_id": auth_id, "tool_name": tool_name, "tool_args_sha256": _sha(repr(sorted(dict(tool_args).items())))}
        decision = Decision.allow("ALLOW_AUTHORIZED_ONCE")
        self._audit(tool_name, tool_args, context, lineage, source, decision)
        return decision

    def record_effect(self, *, authorization_id: str, tool_name: str, tool_args: Mapping[str, Any], succeeded: bool) -> bool:
        expected = {"authorization_id": authorization_id, "tool_name": tool_name, "tool_args_sha256": _sha(repr(sorted(dict(tool_args).items())))}
        if not succeeded or self._pending_allow != expected:
            return False
        auth = self.authorizations.get(authorization_id)
        if auth is None:
            return False
        auth["consumed_execution_count"] = int(auth.get("consumed_execution_count", 0)) + 1
        self._pending_allow = None
        return True

    def _audit(self, tool_name, tool_args, context, lineage, source, decision) -> None:
        self.decision_audit.append({"event_index": self.event_index, "tool_name": tool_name, "tool_args": copy.deepcopy(dict(tool_args)), "context": copy.deepcopy(dict(context)), "lineage_class": lineage, "matched_source_event_id": None if source is None else source["source_event_id"], "decision_action": str(decision.action.value if hasattr(decision.action, "value") else decision.action), "decision_reason": decision.reason})
