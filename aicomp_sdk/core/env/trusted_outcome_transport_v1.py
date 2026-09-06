"""Trusted outcome transport v1. Static implementation; runtime not qualified."""
from __future__ import annotations
from dataclasses import dataclass, field
import hashlib
import json
import threading
import unicodedata
from typing import Any

_RAW_DOMAIN = b"P2N.RAW_OUTPUT.V1"
_PROTECTED_DOMAIN = b"P2N.PROTECTED_BINDING.V1"

def _frame(tag: bytes, payload: bytes) -> bytes:
    return tag + str(len(payload)).encode("ascii") + b":" + payload

def canonicalize_post_hook_output_v1(value: object) -> bytes:
    if value is None:
        return _frame(b"N", b"")
    if isinstance(value, bool):
        return _frame(b"B", b"1" if value else b"0")
    if isinstance(value, int) and not isinstance(value, bool):
        return _frame(b"I", str(value).encode("ascii"))
    if isinstance(value, float):
        raise TypeError("float prohibited")
    if isinstance(value, str):
        return _frame(b"S", unicodedata.normalize("NFC", value).encode("utf-8"))
    if isinstance(value, bytes):
        return _frame(b"Y", value)
    if isinstance(value, list):
        return _frame(b"L", b"".join(canonicalize_post_hook_output_v1(x) for x in value))
    if isinstance(value, tuple):
        raise TypeError("tuple prohibited")
    if isinstance(value, dict):
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("map keys must be strings")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise ValueError("duplicate key after NFC normalization")
            normalized[normalized_key] = item
        payload = b""
        for key in sorted(normalized, key=lambda x: x.encode("utf-8")):
            payload += _frame(b"K", key.encode("utf-8"))
            payload += canonicalize_post_hook_output_v1(normalized[key])
        return _frame(b"M", payload)
    raise TypeError(f"unsupported type: {type(value).__name__}")

def compute_raw_output_sha256_v1(value: object) -> str:
    canonical = canonicalize_post_hook_output_v1(value)
    return hashlib.sha256(_RAW_DOMAIN + b"\x00" + canonical).hexdigest().upper()

def compute_protected_value_bound_digest_v1(trace_identity: str, proposal_digest: str, outcome_event_identity: str, canonical_source_path: str, raw_output_sha256: str) -> str:
    fields = [trace_identity, proposal_digest, outcome_event_identity, canonical_source_path, raw_output_sha256]
    if not all(isinstance(x, str) and x for x in fields):
        raise ValueError("all binding fields must be nonempty strings")
    if len(raw_output_sha256) != 64 or any(c not in "0123456789ABCDEF" for c in raw_output_sha256):
        raise ValueError("raw_output_sha256 must be 64 uppercase hexadecimal characters")
    payload = b"".join(_frame(b"S", unicodedata.normalize("NFC", x).encode("utf-8")) for x in fields)
    return hashlib.sha256(_PROTECTED_DOMAIN + b"\x00" + payload).hexdigest().upper()

@dataclass
class TrustedEventSequenceStateV1:
    counter_by_trace: dict[str, int] = field(default_factory=dict)
    consumed_outcome_identities: set[str] = field(default_factory=set)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def allocate(self, trace_identity: str, event_kind: str) -> str:
        if not trace_identity or event_kind not in {"proposal", "outcome"}:
            raise ValueError("invalid event identity fields")
        with self._lock:
            sequence = self.counter_by_trace.get(trace_identity, 0) + 1
            self.counter_by_trace[trace_identity] = sequence
            return f"{trace_identity}:{event_kind}:{sequence}"

    def consume_outcome(self, outcome_event_identity: str) -> None:
        with self._lock:
            if outcome_event_identity in self.consumed_outcome_identities:
                raise ValueError("outcome identity already consumed")
            self.consumed_outcome_identities.add(outcome_event_identity)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {"schema": "P2N.TRANSPORT.STATE.V1", "counter_by_trace": dict(sorted(self.counter_by_trace.items())), "consumed_outcome_identities": sorted(self.consumed_outcome_identities)}

    def restore(self, snapshot: dict[str, object]) -> None:
        if snapshot.get("schema") != "P2N.TRANSPORT.STATE.V1":
            raise ValueError("unsupported snapshot schema")
        counters = snapshot.get("counter_by_trace")
        consumed = snapshot.get("consumed_outcome_identities")
        if not isinstance(counters, dict) or not isinstance(consumed, list):
            raise ValueError("malformed snapshot")
        with self._lock:
            self.counter_by_trace = {str(k): int(v) for k, v in counters.items()}
            self.consumed_outcome_identities = {str(x) for x in consumed}

    def reset(self) -> None:
        with self._lock:
            self.counter_by_trace.clear()
            self.consumed_outcome_identities.clear()

class TrustedOutcomeTransportV1:
    def __init__(self, adapter, sequence_state):
        self.adapter = adapter
        self.sequence_state = sequence_state

    def acknowledge(self, *, trace_identity: str, proposal_digest: str, tool_name: str, success: bool, canonical_source_path: str, post_hook_output: object) -> dict[str, object]:
        outcome_identity = self.sequence_state.allocate(trace_identity, "outcome")
        raw_digest = compute_raw_output_sha256_v1(post_hook_output)
        bound_digest = compute_protected_value_bound_digest_v1(trace_identity, proposal_digest, outcome_identity, canonical_source_path, raw_digest)
        outcome = {"success": bool(success), "completion_sequence": int(outcome_identity.rsplit(":", 1)[1]), "canonical_source_path": canonical_source_path, "raw_output_sha256": raw_digest, "protected_value_sha256_or_bound_digest": bound_digest}
        self.adapter.after_tool(outcome)
        self.sequence_state.consume_outcome(outcome_identity)
        return outcome

def snapshot_trusted_transport_state_v1(sequence_state: TrustedEventSequenceStateV1) -> dict[str, object]:
    return sequence_state.snapshot()
