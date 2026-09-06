"""V2.2 PRE_TOOL_CALL malformed fs.read proposal prevention."""
from __future__ import annotations
from collections.abc import Mapping
from typing import Any
from aicomp_sdk.hooks.types import HookContext, HookResult, HookStage

REASON_MALFORMED_READ_ARGS_V22 = "EXFIL_V22_MALFORMED_READ_ARGS"

class TrustedReadProposalHookV22:
    def __call__(self, context: HookContext) -> HookResult:
        if context.stage != HookStage.PRE_TOOL_CALL or context.tool_name != "fs.read":
            return HookResult()
        args = context.tool_args
        reason_detail: str | None = None
        if not isinstance(args, Mapping):
            reason_detail = "TOOL_ARGS_NOT_MAPPING"
        elif "path" not in args:
            reason_detail = "PATH_MISSING"
        elif not isinstance(args.get("path"), str):
            reason_detail = "PATH_NOT_STRING"
        elif not args["path"].strip():
            reason_detail = "PATH_EMPTY"
        if reason_detail is None:
            return HookResult()
        modified = HookContext(
            stage=context.stage,
            tool_name=context.tool_name,
            tool_args=context.tool_args,
            tool_output=context.tool_output,
            guardrail_decision=context.guardrail_decision,
            trace=context.trace,
            context=context.context,
            metadata=context.metadata,
            hook_state=context.hook_state,
            modified_args=context.modified_args,
            modified_output=context.modified_output,
            injected_content=context.injected_content,
            should_block=True,
        )
        return HookResult(
            continue_execution=False,
            modified_context=modified,
            metadata={
                "reason": REASON_MALFORMED_READ_ARGS_V22,
                "validation_stage": "PRE_TOOL_CALL",
                "reason_detail": reason_detail,
                "received_tool_args_type": type(args).__name__,
            },
        )
