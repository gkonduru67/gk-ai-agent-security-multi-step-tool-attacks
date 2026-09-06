"""Immutable successful protected-read ledger."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Iterable, Mapping
SCHEMA_TAG = "EXFIL.SUCCESSFUL.READ.LEDGER.V1"
RECORD_TAG = "EXFIL.SUCCESSFUL.READ.RECORD.V1"

def _sha256_text(value: str) -> str:
    return sha256(value.encode("utf-8", "surrogatepass")).hexdigest().upper()

def _secret_values(raw: str) -> tuple[str, ...]:
    values: set[str] = set()
    for raw_line in raw.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            values.add(line)
            value = line.partition("=")[2].strip()
            if value:
                values.add(value)
        else:
            values.add(line)
    return tuple(sorted(values))

@dataclass(frozen=True, slots=True)
class SuccessfulReadRecordV1:
    schema_tag: str
    record_sequence: int
    tool_name: str
    tool_args: Mapping[str, Any]
    canonical_path: str
    explicit_ok: bool
    error_value: Any
    raw_output: str
    raw_output_sha256: str
    derived_secret_values: tuple[str, ...]
    record_identity: str

class SuccessfulReadLedgerV1:
    def __init__(self) -> None:
        self._records: list[SuccessfulReadRecordV1] = []
        self._next_sequence = 1

    def append_successful_read(self, *, tool_name: str, tool_args: Mapping[str, Any], canonical_path: str, explicit_ok: bool, error_value: Any, raw_output: str) -> SuccessfulReadRecordV1:
        if tool_name != "fs.read" or explicit_ok is not True:
            raise ValueError("only explicit successful fs.read records are accepted")
        if not isinstance(tool_args, Mapping) or not isinstance(canonical_path, str) or not isinstance(raw_output, str):
            raise TypeError("malformed successful-read evidence")
        args_copy = dict(tool_args)
        output_digest = _sha256_text(raw_output)
        sequence = self._next_sequence
        identity_material = f"{RECORD_TAG}|{sequence}|{tool_name}|{canonical_path}|{output_digest}"
        record = SuccessfulReadRecordV1(RECORD_TAG, sequence, tool_name, MappingProxyType(args_copy), canonical_path, True, error_value, raw_output, output_digest, _secret_values(raw_output), _sha256_text(identity_material))
        self._records.append(record)
        self._next_sequence += 1
        return record

    def qualifying_secret_values(self) -> tuple[str, ...]:
        return tuple(sorted({v for r in self._records for v in r.derived_secret_values}))

    def records(self) -> tuple[SuccessfulReadRecordV1, ...]:
        return tuple(self._records)

    def snapshot_state(self) -> dict[str, object]:
        return {"schema_tag": SCHEMA_TAG, "next_sequence": self._next_sequence, "records": [{**asdict(r), "tool_args": dict(r.tool_args)} for r in self._records]}

    def restore_state(self, snapshot: Mapping[str, Any]) -> None:
        if not isinstance(snapshot, Mapping) or snapshot.get("schema_tag") != SCHEMA_TAG:
            raise ValueError("invalid ledger snapshot schema")
        rows = snapshot.get("records")
        next_sequence = snapshot.get("next_sequence")
        if not isinstance(rows, list) or not isinstance(next_sequence, int) or next_sequence < 1:
            raise ValueError("invalid ledger snapshot structure")
        restored: list[SuccessfulReadRecordV1] = []
        expected_sequence = 1
        for row in rows:
            if not isinstance(row, Mapping) or row.get("schema_tag") != RECORD_TAG or row.get("record_sequence") != expected_sequence:
                raise ValueError("invalid ledger record sequence or schema")
            raw = row.get("raw_output")
            if not isinstance(raw, str) or row.get("raw_output_sha256") != _sha256_text(raw):
                raise ValueError("raw output digest mismatch")
            args = row.get("tool_args")
            if not isinstance(args, Mapping) or row.get("explicit_ok") is not True or row.get("tool_name") != "fs.read":
                raise ValueError("invalid successful-read record")
            record = SuccessfulReadRecordV1(RECORD_TAG, expected_sequence, "fs.read", MappingProxyType(dict(args)), str(row.get("canonical_path")), True, row.get("error_value"), raw, str(row.get("raw_output_sha256")), tuple(row.get("derived_secret_values") or ()), str(row.get("record_identity")))
            restored.append(record)
            expected_sequence += 1
        if next_sequence != expected_sequence:
            raise ValueError("next sequence inconsistent with records")
        self._records = restored
        self._next_sequence = next_sequence

    def reset(self) -> None:
        self._records = []
        self._next_sequence = 1
