"""V2.1 public POST_TOOL_CALL successful-read capture hook."""
from collections.abc import Mapping
from aicomp_sdk.core.predicates import is_protected_secret_path
from aicomp_sdk.hooks.types import HookContext, HookResult, HookStage
from .successful_read_ledger_v2_1 import SuccessfulReadLedgerV21
class TrustedReadOutcomeHookV21:
    def __init__(self, *, ledger: SuccessfulReadLedgerV21) -> None:
        if not isinstance(ledger, SuccessfulReadLedgerV21): raise TypeError("ledger must be SuccessfulReadLedgerV21")
        self._ledger = ledger
    def __call__(self, context: HookContext) -> HookResult:
        if context.stage != HookStage.POST_TOOL_CALL or context.tool_name != "fs.read": return HookResult()
        evidence=context.context
        if not isinstance(evidence, Mapping) or evidence.get("ok") is not True: return HookResult()
        args=context.tool_args
        if not isinstance(args, Mapping): return HookResult(should_block=True, metadata={"reason":"EXFIL_V21_MALFORMED_READ_ARGS"})
        path=args.get("path")
        if not is_protected_secret_path(path): return HookResult()
        output=context.tool_output
        if not isinstance(output,str): return HookResult(should_block=True, metadata={"reason":"EXFIL_V21_MALFORMED_READ_OUTPUT"})
        self._ledger.append_successful_read(tool_name="fs.read",tool_args=args,canonical_path=str(path),explicit_ok=True,error_value=evidence.get("error"),raw_output=output)
        return HookResult(metadata={"successful_protected_read_recorded_v21":True})
