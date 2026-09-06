"""Trusted transport and lineage adapter for the EX6 P2B defense track.

Source-implementation scope only. The class exposes explicit trusted-channel
methods, but the current Sandbox runtime is not claimed to invoke them.
Security effectiveness, requirement satisfaction, and runtime compatibility
remain unestablished until separately qualified.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import hmac
import json
import math
import unicodedata
from typing import Any

from aicomp_sdk.guardrails.base import Decision, DecisionAction, GuardrailBase


_SCHEMA_TAG = "aicomp.trusted-context.v1"
_PROTECTED_ACTION_TOOLS = frozenset(
    {"fs.write", "fs.delete", "shell.run", "http.post", "email.send"}
)


class TrustedGuardrailContextAdapter(GuardrailBase):
    """Fail-closed trusted-channel wrapper around an existing guardrail.

    `before_decide` and `after_tool` are explicit host-only APIs. They are not
    read from model output, prompt text, or generic context dictionaries.
    """

    REASON_DIRECT_DECIDE = "P2B_TRUSTED_BEFORE_DECIDE_REQUIRED"
    REASON_MALFORMED = "P2B_MALFORMED_TRUSTED_CHANNEL_INPUT"
    REASON_ISSUER = "P2B_UNTRUSTED_OR_UNKNOWN_ISSUER"
    REASON_GRANT = "P2B_NO_MATCHING_ELIGIBLE_GRANT"
    REASON_REPLAY = "P2B_REPLAY_OR_EVENT_IDENTITY_REJECTED"
    REASON_INNER = "P2B_INNER_GUARDRAIL_REJECTED"

    def __init__(
        self,
        inner_guardrail: GuardrailBase,
        issuer_capabilities: Mapping[tuple[str, str], bytes],
    ) -> None:
        if not isinstance(inner_guardrail, GuardrailBase):
            raise TypeError("inner_guardrail must implement GuardrailBase")
        if not isinstance(issuer_capabilities, Mapping) or not issuer_capabilities:
            raise ValueError("issuer_capabilities must be a non-empty mapping")
        capabilities: dict[tuple[str, str], bytes] = {}
        for key, value in issuer_capabilities.items():
            if (
                not isinstance(key, tuple)
                or len(key) != 2
                or not all(isinstance(part, str) and part for part in key)
                or not isinstance(value, bytes)
                or not value
            ):
                raise ValueError("invalid issuer capability entry")
            capabilities[(key[0], key[1])] = bytes(value)
        self._inner = inner_guardrail
        self._issuer_capabilities = capabilities
        self.reset_state()

    def register_trusted_grant(
        self, record: Mapping[str, Any], issuer_capability: bytes
    ) -> str:
        grant = self._validate_grant(record, issuer_capability)
        grant_id = grant["grant_id"]
        if grant_id in self._trusted_grants_by_id or grant_id in self._consumed_grant_ids:
            raise ValueError("duplicate or consumed grant_id")
        self._trusted_grants_by_id[grant_id] = grant
        return grant_id

    def before_decide(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
        context: Mapping[str, Any],
        *,
        trace_identity: str,
        proposal_event_identity: Mapping[str, Any],
    ) -> Decision:
        if (
            not isinstance(tool_name, str)
            or not tool_name
            or not isinstance(tool_args, Mapping)
            or not isinstance(context, Mapping)
            or not isinstance(trace_identity, str)
            or not trace_identity
        ):
            return Decision.deny(self.REASON_MALFORMED)
        try:
            event_key = self._validate_event_identity(
                proposal_event_identity, trace_identity, expected_kind="proposal"
            )
            proposal_record = {
                "schema_tag": _SCHEMA_TAG,
                "tool_name": tool_name,
                "canonical_tool_args": dict(tool_args),
                "trace_identity": trace_identity,
                "proposal_event_identity": dict(proposal_event_identity),
            }
            proposal_digest = self._digest_v1(proposal_record)
        except (TypeError, ValueError):
            return Decision.deny(self.REASON_MALFORMED)

        inner_decision = self._inner.decide(tool_name, tool_args, context)
        if inner_decision.action != DecisionAction.ALLOW:
            return inner_decision

        if tool_name not in _PROTECTED_ACTION_TOOLS:
            self._pending_proposals_by_digest[proposal_digest] = {
                "trace_identity": trace_identity,
                "event_key": event_key,
                "tool_name": tool_name,
                "grant_id": None,
            }
            return inner_decision

        target_digest = self._target_digest(tool_name, tool_args)
        grant_id = self._find_eligible_grant(
            tool_name, target_digest, proposal_digest, trace_identity
        )
        if grant_id is None:
            return Decision.deny(self.REASON_GRANT)

        self._consume_grant(grant_id)
        self._pending_proposals_by_digest[proposal_digest] = {
            "trace_identity": trace_identity,
            "event_key": event_key,
            "tool_name": tool_name,
            "grant_id": grant_id,
        }
        return inner_decision

    def decide(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> Decision:
        del tool_name, tool_args, context
        return Decision.deny(self.REASON_DIRECT_DECIDE)

    def after_tool(
        self,
        *,
        proposal_digest: str,
        event_identity: Mapping[str, Any],
        trace_identity: str,
        tool_name: str,
        tool_args_digest: str,
        trusted_tool_outcome: Mapping[str, Any],
    ) -> None:
        if not all(
            isinstance(value, str) and value
            for value in (proposal_digest, trace_identity, tool_name, tool_args_digest)
        ) or not isinstance(trusted_tool_outcome, Mapping):
            raise ValueError(self.REASON_MALFORMED)
        pending = self._pending_proposals_by_digest.get(proposal_digest)
        if not pending or pending["trace_identity"] != trace_identity:
            raise ValueError(self.REASON_REPLAY)
        event_key = self._validate_event_identity(
            event_identity, trace_identity, expected_kind="outcome"
        )
        if event_key in self._seen_event_identities:
            raise ValueError(self.REASON_REPLAY)
        success = trusted_tool_outcome.get("success")
        completion_sequence = trusted_tool_outcome.get("completion_sequence")
        if not isinstance(success, bool) or not isinstance(completion_sequence, int):
            raise ValueError(self.REASON_MALFORMED)
        if completion_sequence != event_key[1]:
            raise ValueError(self.REASON_MALFORMED)
        self._seen_event_identities.add(event_key)
        self._monotonic_sequence_by_trace[trace_identity] = event_key[1]

        if tool_name == "fs.read" and success:
            record = self._qualify_protected_read(
                trace_identity, event_identity, trusted_tool_outcome
            )
            if record is not None:
                self._protected_read_records.append(record)
        del self._pending_proposals_by_digest[proposal_digest]

    def snapshot_state(self) -> Any:
        return deepcopy(
            {
                "schema_version": 1,
                "trusted_grants_by_id": self._trusted_grants_by_id,
                "consumed_grant_ids": sorted(self._consumed_grant_ids),
                "protected_read_records": self._protected_read_records,
                "seen_event_identities": [list(x) for x in sorted(self._seen_event_identities)],
                "pending_proposals_by_digest": self._pending_proposals_by_digest,
                "monotonic_sequence_by_trace": self._monotonic_sequence_by_trace,
                "inner_guardrail_state": self._inner.snapshot_state(),
            }
        )

    def restore_state(self, snapshot: Any) -> None:
        validated = self._validate_snapshot(snapshot)
        self._inner.restore_state(validated.pop("inner_guardrail_state"))
        self._trusted_grants_by_id = validated["trusted_grants_by_id"]
        self._consumed_grant_ids = set(validated["consumed_grant_ids"])
        self._protected_read_records = validated["protected_read_records"]
        self._seen_event_identities = {
            tuple(x) for x in validated["seen_event_identities"]
        }
        self._pending_proposals_by_digest = validated["pending_proposals_by_digest"]
        self._monotonic_sequence_by_trace = validated["monotonic_sequence_by_trace"]

    def reset_state(self) -> None:
        self._trusted_grants_by_id: dict[str, dict[str, Any]] = {}
        self._consumed_grant_ids: set[str] = set()
        self._protected_read_records: list[dict[str, Any]] = []
        self._seen_event_identities: set[tuple[str, int, str]] = set()
        self._pending_proposals_by_digest: dict[str, dict[str, Any]] = {}
        self._monotonic_sequence_by_trace: dict[str, int] = {}

    @classmethod
    def _canonicalize_v1(cls, value: Any) -> bytes:
        normalized = cls._normalize_json_value(value)
        text = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return text.encode("utf-8")

    @classmethod
    def _normalize_json_value(cls, value: Any) -> Any:
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError("non-finite numbers prohibited")
            raise ValueError("floating point prohibited")
        if isinstance(value, str):
            return unicodedata.normalize("NFC", value)
        if isinstance(value, Mapping):
            result: dict[str, Any] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TypeError("object keys must be strings")
                normalized_key = unicodedata.normalize("NFC", key)
                if normalized_key in result:
                    raise ValueError("duplicate normalized object key")
                result[normalized_key] = cls._normalize_json_value(item)
            return result
        if isinstance(value, (list, tuple)):
            return [cls._normalize_json_value(item) for item in value]
        raise TypeError("unsupported canonical value")

    @classmethod
    def _digest_v1(cls, value: Any) -> str:
        envelope = {"schema_tag": _SCHEMA_TAG, "value": value}
        return hashlib.sha256(cls._canonicalize_v1(envelope)).hexdigest().upper()

    def _validate_grant(
        self, record: Mapping[str, Any], issuer_capability: bytes
    ) -> dict[str, Any]:
        if not isinstance(record, Mapping) or not isinstance(issuer_capability, bytes):
            raise TypeError("invalid grant input")
        required = {
            "grant_id", "issuer_id", "issuer_trust_domain", "issued_at_or_sequence",
            "expires_at_or_sequence", "authorized_tool", "authorized_target_digest",
            "authorized_proposal_digest", "nonce", "trace_identity",
        }
        if set(record) != required:
            raise ValueError("grant fields differ from frozen schema")
        grant = dict(record)
        if not all(
            isinstance(grant[name], str) and grant[name]
            for name in required - {"issued_at_or_sequence", "expires_at_or_sequence"}
        ):
            raise ValueError("invalid grant string field")
        issued = grant["issued_at_or_sequence"]
        expires = grant["expires_at_or_sequence"]
        if not isinstance(issued, int) or not isinstance(expires, int) or issued < 0 or expires <= issued:
            raise ValueError("invalid grant lifetime")
        key = (grant["issuer_id"], grant["issuer_trust_domain"])
        expected = self._issuer_capabilities.get(key)
        if expected is None or not hmac.compare_digest(expected, issuer_capability):
            raise ValueError(self.REASON_ISSUER)
        grant["record_digest"] = self._digest_v1(grant)
        return grant

    def _validate_event_identity(
        self,
        value: Mapping[str, Any],
        trace_identity: str,
        *,
        expected_kind: str,
    ) -> tuple[str, int, str]:
        if not isinstance(value, Mapping) or set(value) != {
            "trace_identity", "event_sequence", "event_kind"
        }:
            raise ValueError("invalid event identity schema")
        sequence = value["event_sequence"]
        if (
            value["trace_identity"] != trace_identity
            or value["event_kind"] != expected_kind
            or not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence < 0
        ):
            raise ValueError("invalid event identity")
        last = self._monotonic_sequence_by_trace.get(trace_identity, -1)
        if sequence <= last:
            raise ValueError(self.REASON_REPLAY)
        return (trace_identity, sequence, expected_kind)

    def _find_eligible_grant(
        self, tool_name: str, target_digest: str, proposal_digest: str, trace_identity: str
    ) -> str | None:
        for grant_id in sorted(self._trusted_grants_by_id):
            grant = self._trusted_grants_by_id[grant_id]
            if (
                grant_id not in self._consumed_grant_ids
                and grant["authorized_tool"] == tool_name
                and grant["authorized_target_digest"] == target_digest
                and grant["authorized_proposal_digest"] == proposal_digest
                and grant["trace_identity"] == trace_identity
            ):
                return grant_id
        return None

    def _target_digest(self, tool_name: str, tool_args: Mapping[str, Any]) -> str:
        if tool_name == "http.post":
            target = {"tool_name": tool_name, "url": tool_args.get("url")}
        elif tool_name in {"fs.write", "fs.delete"}:
            target = {"tool_name": tool_name, "path": tool_args.get("path")}
        else:
            target = {"tool_name": tool_name, "tool_args": dict(tool_args)}
        return self._digest_v1(target)

    def _consume_grant(self, grant_id: str) -> None:
        if grant_id in self._consumed_grant_ids:
            raise ValueError(self.REASON_REPLAY)
        self._consumed_grant_ids.add(grant_id)

    def _qualify_protected_read(
        self,
        trace_identity: str,
        event_identity: Mapping[str, Any],
        outcome: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        path = outcome.get("canonical_source_path")
        raw_output_sha256 = outcome.get("raw_output_sha256")
        protected_digest = outcome.get("protected_value_sha256_or_bound_digest")
        if not all(isinstance(x, str) and x for x in (path, raw_output_sha256, protected_digest)):
            return None
        return {
            "event_identity": dict(event_identity),
            "trace_identity": trace_identity,
            "tool_name": "fs.read",
            "canonical_source_path": path,
            "tool_success": True,
            "raw_output_sha256": raw_output_sha256,
            "protected_value_sha256_or_bound_digest": protected_digest,
            "completion_sequence": outcome["completion_sequence"],
        }

    def _validate_snapshot(self, snapshot: Any) -> dict[str, Any]:
        if not isinstance(snapshot, Mapping):
            raise TypeError("snapshot must be a mapping")
        required = {
            "schema_version", "trusted_grants_by_id", "consumed_grant_ids",
            "protected_read_records", "seen_event_identities",
            "pending_proposals_by_digest", "monotonic_sequence_by_trace",
            "inner_guardrail_state",
        }
        if set(snapshot) != required or snapshot.get("schema_version") != 1:
            raise ValueError("snapshot schema mismatch")
        candidate = deepcopy(dict(snapshot))
        if not isinstance(candidate["trusted_grants_by_id"], dict):
            raise ValueError("invalid grant snapshot")
        if not isinstance(candidate["consumed_grant_ids"], list):
            raise ValueError("invalid consumed grant snapshot")
        if not isinstance(candidate["protected_read_records"], list):
            raise ValueError("invalid read record snapshot")
        if not isinstance(candidate["seen_event_identities"], list):
            raise ValueError("invalid event identity snapshot")
        if not isinstance(candidate["pending_proposals_by_digest"], dict):
            raise ValueError("invalid pending proposal snapshot")
        if not isinstance(candidate["monotonic_sequence_by_trace"], dict):
            raise ValueError("invalid sequence snapshot")
        return candidate
