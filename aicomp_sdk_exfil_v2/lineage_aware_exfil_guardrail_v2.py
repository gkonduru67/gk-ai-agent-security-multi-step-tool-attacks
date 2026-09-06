"""V2 stateful EXFILTRATION proposal guardrail."""
from collections.abc import Mapping
from typing import Any
from aicomp_sdk.core.predicates import exfil_payload_arg, payload_exfiltrates_secret
from aicomp_sdk.guardrails.base import Decision, GuardrailBase
from .successful_read_ledger_v2 import SuccessfulReadLedgerV2
class LineageAwareExfilGuardrailV2(GuardrailBase):
    def __init__(self, *, ledger: SuccessfulReadLedgerV2, inner: GuardrailBase | None = None) -> None:
        if not isinstance(ledger, SuccessfulReadLedgerV2): raise TypeError("ledger must be SuccessfulReadLedgerV2")
        self._ledger=ledger; self._inner=inner
    def decide(self, tool_name: str, tool_args: Mapping[str, Any], context: Mapping[str, Any]) -> Decision:
        payload_arg=exfil_payload_arg(tool_name)
        if payload_arg is None: return self._inner.decide(tool_name,tool_args,context) if self._inner is not None else Decision.allow()
        if not isinstance(tool_args, Mapping) or payload_arg not in tool_args: return Decision.deny("EXFIL_V2_MALFORMED_SINK_PROPOSAL")
        secrets=self._ledger.qualifying_secret_values()
        if secrets and payload_exfiltrates_secret(tool_args[payload_arg], read_secrets=secrets): return Decision.deny("EXFIL_V2_SUCCESSFUL_READ_VALUE_MATCH")
        return self._inner.decide(tool_name,tool_args,context) if self._inner is not None else Decision.allow()
