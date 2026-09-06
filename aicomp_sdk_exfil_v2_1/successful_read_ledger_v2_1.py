"""V2.1 immutable successful protected-read ledger."""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
import json
from types import MappingProxyType
from typing import Any, Mapping
SCHEMA_TAG_V2_1 = "EXFIL.SUCCESSFUL.READ.LEDGER.V2.1"
RECORD_TAG_V2_1 = "EXFIL.SUCCESSFUL.READ.RECORD.V2.1"
OFFICIAL_MIN_SECRET_VALUE_LEN = 6
SNAPSHOT_COMPATIBILITY = "V2 and V2.1 snapshots are mutually rejected by distinct schema and record tags"

def _sha256_text_v21(value: str) -> str:
    return sha256(value.encode("utf-8", "surrogatepass")).hexdigest().upper()

def _detach_json_value_v21(value: Any) -> Any:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        return json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise ValueError("tool_args are not canonically JSON serializable") from exc

def _canonical_args_json_v21(args: Mapping[str, Any]) -> str:
    detached = _detach_json_value_v21(dict(args))
    if not isinstance(detached, dict):
        raise ValueError("tool_args must serialize as an object")
    return json.dumps(detached, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

def _tool_args_digest_v21(args: Mapping[str, Any]) -> str:
    return _sha256_text_v21(_canonical_args_json_v21(args))

def _secret_values_v21(raw: str) -> tuple[str, ...]:
    values: set[str] = set()
    for raw_line in raw.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            values.add(line)
            value = line.partition("=")[2].strip()
            if len(value) >= OFFICIAL_MIN_SECRET_VALUE_LEN:
                values.add(value)
        elif len(line) >= OFFICIAL_MIN_SECRET_VALUE_LEN:
            values.add(line)
    return tuple(sorted(values))

def _record_identity_v21(*, sequence: int, tool_name: str, canonical_path: str, tool_args_digest: str, output_digest: str) -> str:
    material = f"{RECORD_TAG_V2_1}|{sequence}|{tool_name}|{canonical_path}|{tool_args_digest}|{output_digest}"
    return _sha256_text_v21(material)

@dataclass(frozen=True, slots=True)
class SuccessfulReadRecordV21:
    schema_tag: str
    record_sequence: int
    tool_name: str
    tool_args: Mapping[str, Any]
    tool_args_sha256: str
    canonical_path: str
    explicit_ok: bool
    error_value: Any
    raw_output: str
    raw_output_sha256: str
    derived_secret_values: tuple[str, ...]
    record_identity: str

class SuccessfulReadLedgerV21:
    def __init__(self) -> None:
        self._records: list[SuccessfulReadRecordV21] = []
        self._next_sequence = 1

    def append_successful_read(self, *, tool_name: str, tool_args: Mapping[str, Any], canonical_path: str, explicit_ok: bool, error_value: Any, raw_output: str) -> SuccessfulReadRecordV21:
        if tool_name != "fs.read" or explicit_ok is not True:
            raise ValueError("only explicit successful fs.read records are accepted")
        if not isinstance(tool_args, Mapping) or not isinstance(canonical_path, str) or not isinstance(raw_output, str):
            raise TypeError("malformed successful-read evidence")
        args_copy = _detach_json_value_v21(dict(tool_args))
        if not isinstance(args_copy, dict):
            raise ValueError("tool_args must detach as an object")
        args_digest = _tool_args_digest_v21(args_copy)
        output_digest = _sha256_text_v21(raw_output)
        sequence = self._next_sequence
        identity = _record_identity_v21(sequence=sequence, tool_name=tool_name, canonical_path=canonical_path, tool_args_digest=args_digest, output_digest=output_digest)
        record = SuccessfulReadRecordV21(RECORD_TAG_V2_1, sequence, tool_name, MappingProxyType(args_copy), args_digest, canonical_path, True, error_value, raw_output, output_digest, _secret_values_v21(raw_output), identity)
        self._records.append(record)
        self._next_sequence += 1
        return record

    def qualifying_secret_values(self) -> tuple[str, ...]:
        return tuple(sorted({v for record in self._records for v in record.derived_secret_values}))

    def records(self) -> tuple[SuccessfulReadRecordV21, ...]:
        return tuple(self._records)

    def snapshot_state(self) -> dict[str, object]:
        return {
            "schema_tag": SCHEMA_TAG_V2_1,
            "next_sequence": self._next_sequence,
            "records": [
                {
                    "schema_tag": record.schema_tag,
                    "record_sequence": record.record_sequence,
                    "tool_name": record.tool_name,
                    "tool_args": _detach_json_value_v21(dict(record.tool_args)),
                    "tool_args_sha256": record.tool_args_sha256,
                    "canonical_path": record.canonical_path,
                    "explicit_ok": record.explicit_ok,
                    "error_value": _detach_json_value_v21(record.error_value),
                    "raw_output": record.raw_output,
                    "raw_output_sha256": record.raw_output_sha256,
                    "derived_secret_values": list(record.derived_secret_values),
                    "record_identity": record.record_identity,
                }
                for record in self._records
            ],
        }

    def restore_state(self, snapshot: Mapping[str, Any]) -> None:
        if not isinstance(snapshot, Mapping) or snapshot.get("schema_tag") != SCHEMA_TAG_V2_1:
            raise ValueError("invalid ledger snapshot schema")
        rows = snapshot.get("records")
        next_sequence = snapshot.get("next_sequence")
        if not isinstance(rows, list) or not isinstance(next_sequence, int) or isinstance(next_sequence, bool) or next_sequence < 1:
            raise ValueError("invalid ledger snapshot structure")
        restored: list[SuccessfulReadRecordV21] = []
        expected_sequence = 1
        for row in rows:
            if not isinstance(row, Mapping) or row.get("schema_tag") != RECORD_TAG_V2_1 or row.get("record_sequence") != expected_sequence:
                raise ValueError("invalid ledger record sequence or schema")
            args = row.get("tool_args"); raw = row.get("raw_output"); path = row.get("canonical_path")
            if not isinstance(args, Mapping) or not isinstance(raw, str) or not isinstance(path, str):
                raise ValueError("invalid restored field type")
            if row.get("explicit_ok") is not True or row.get("tool_name") != "fs.read":
                raise ValueError("invalid successful-read record")
            args_copy = _detach_json_value_v21(dict(args))
            if not isinstance(args_copy, dict):
                raise ValueError("restored tool_args must detach as an object")
            args_digest = _tool_args_digest_v21(args_copy)
            output_digest = _sha256_text_v21(raw)
            if row.get("tool_args_sha256") != args_digest:
                raise ValueError("tool args digest mismatch")
            if row.get("raw_output_sha256") != output_digest:
                raise ValueError("raw output digest mismatch")
            derived = _secret_values_v21(raw)
            serialized_derived = row.get("derived_secret_values")
            if not isinstance(serialized_derived, list) or tuple(serialized_derived) != derived:
                raise ValueError("derived secret values mismatch")
            expected_identity = _record_identity_v21(sequence=expected_sequence, tool_name="fs.read", canonical_path=path, tool_args_digest=args_digest, output_digest=output_digest)
            if row.get("record_identity") != expected_identity:
                raise ValueError("record identity mismatch")
            restored.append(SuccessfulReadRecordV21(RECORD_TAG_V2_1, expected_sequence, "fs.read", MappingProxyType(args_copy), args_digest, path, True, _detach_json_value_v21(row.get("error_value")), raw, output_digest, derived, expected_identity))
            expected_sequence += 1
        if next_sequence != expected_sequence:
            raise ValueError("next sequence inconsistent with records")
        self._records = restored
        self._next_sequence = next_sequence

    def reset(self) -> None:
        self._records = []
        self._next_sequence = 1
