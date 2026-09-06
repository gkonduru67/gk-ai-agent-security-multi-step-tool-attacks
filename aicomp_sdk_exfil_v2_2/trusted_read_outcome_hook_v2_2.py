"""V2.2 POST_TOOL_CALL successful protected-read observation."""
from __future__ import annotations
from collections.abc import Mapping
from aicomp_sdk.core.predicates import is_protected_secret_path
from aicomp_sdk.hooks.types import HookContext, HookResult, HookStage
from aicomp_sdk_exfil_v2_1.successful_read_ledger_v2_1 import SuccessfulReadLedgerV21

REASON_MALFORMED_READ_OUTPUT_V22 = "EXFIL_V22_MALFORMED_READ_OUTPUT"

class TrustedReadOutcomeHookV22:
    def __init__(self, *, ledger: SuccessfulReadLedgerV21) -> None:
        if not isinstance(ledger, SuccessfulReadLedgerV21):
            raise TypeError("ledger must be SuccessfulReadLedgerV21")
        self._ledger = ledger

    def __call__(self, context: HookContext) -> HookResult:
        if context.stage != HookStage.POST_TOOL_CALL or context.tool_name != "fs.read":
            return HookResult()
        evidence = context.context
        if not isinstance(evidence, Mapping) or evidence.get("ok") is not True:
            return HookResult()
        args = context.tool_args
        if not isinstance(args, Mapping):
            return HookResult(metadata={"reason": REASON_MALFORMED_READ_OUTPUT_V22, "classification": "POST_TOOL_OBSERVATION_CONTRACT_VIOLATION", "reason_detail": "TOOL_ARGS_NOT_MAPPING"})
        path = args.get("path")
        if not isinstance(path, str) or not path.strip():
            return HookResult(metadata={"reason": REASON_MALFORMED_READ_OUTPUT_V22, "classification": "POST_TOOL_OBSERVATION_CONTRACT_VIOLATION", "reason_detail": "PATH_INVALID"})
        if not is_protected_secret_path(path):
            return HookResult()
        output = context.tool_output
        if not isinstance(output, str):
            return HookResult(metadata={"reason": REASON_MALFORMED_READ_OUTPUT_V22, "classification": "POST_TOOL_OBSERVATION_CONTRACT_VIOLATION", "reason_detail": "OUTPUT_NOT_STRING"})
        self._ledger.append_successful_read(
            tool_name="fs.read",
            tool_args=args,
            canonical_path=path,
            explicit_ok=True,
            error_value=evidence.get("error"),
            raw_output=output,
        )
        return HookResult(metadata={"successful_protected_read_recorded_v22": True})
