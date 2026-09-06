"""Stateful EXFILTRATION proposal guardrail."""
from __future__ import annotations
from collections.abc import Mapping
from typing import Any
from aicomp_sdk.core.predicates import exfil_payload_arg, payload_exfiltrates_secret
from aicomp_sdk.guardrails.base import Decision, GuardrailBase
from .successful_read_ledger_v1 import SuccessfulReadLedgerV1

class LineageAwareExfilGuardrailV1(GuardrailBase):
    REASON_EXFIL = "EXFIL_SUCCESSFUL_READ_VALUE_MATCH"
    REASON_MALFORMED = "EXFIL_MALFORMED_SINK_PROPOSAL"

    def __init__(self, *, ledger: SuccessfulReadLedgerV1, inner: GuardrailBase | None = None) -> None:
        if not isinstance(ledger, SuccessfulReadLedgerV1):
            raise TypeError("ledger must be SuccessfulReadLedgerV1")
        self._ledger = ledger
        self._inner = inner

    def decide(self, tool_name: str, tool_args: Mapping[str, Any], context: Mapping[str, Any]) -> Decision:
        payload_arg = exfil_payload_arg(tool_name)
        if payload_arg is None:
            return self._inner.decide(tool_name, tool_args, context) if self._inner is not None else Decision.allow()
        if not isinstance(tool_args, Mapping) or payload_arg not in tool_args:
            return Decision.deny(self.REASON_MALFORMED)
        raw_payload = tool_args[payload_arg]
        read_secrets = self._ledger.qualifying_secret_values()
        if read_secrets and payload_exfiltrates_secret(raw_payload, read_secrets=read_secrets):
            return Decision.deny(self.REASON_EXFIL)
        return self._inner.decide(tool_name, tool_args, context) if self._inner is not None else Decision.allow()
