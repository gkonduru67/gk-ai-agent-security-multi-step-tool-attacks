"""Proposal-level hardened guardrail for the EX6 P2A policy-only track.

This class intentionally does not implement trusted action-target-proposal
authorization, successful-read value lineage, one-use authorization, post-tool
outcome handling, or a transport adapter. Its claims are limited to proposal-
level policy decisions under the existing GuardrailBase interface.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aicomp_sdk.core.predicates import (
    exfil_payload_arg,
    is_protected_secret_path,
    payload_exfiltrates_secret,
)
from aicomp_sdk.guardrails.base import Decision, GuardrailBase


class ProposalAwareOptimalGuardrail(GuardrailBase):
    """Stateless proposal-aware hardening under the existing decide interface."""

    REASON_MALFORMED_ARGUMENTS = "P2A_MALFORMED_SECURITY_ARGUMENTS"
    REASON_PROTECTED_PATH = "P2A_PROTECTED_PATH_BLOCKED"
    REASON_EXFIL_SENTINEL_PAYLOAD = "P2A_EXFIL_SENTINEL_PAYLOAD_BLOCKED"
    REASON_UNTRUSTED_DANGEROUS_ACTION = "P2A_UNTRUSTED_SOURCE_DANGEROUS_ACTION_BLOCKED"
    REASON_ALLOWED = "P2A_PROPOSAL_ALLOWED"

    _PATH_TOOLS = frozenset({"fs.read", "fs.write", "fs.delete"})
    _DANGEROUS_AFTER_UNTRUSTED = frozenset(
        {"fs.write", "fs.delete", "shell.run", "http.post", "email.send"}
    )
    _UNTRUSTED_SOURCES = frozenset({"web", "email"})

    def decide(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> Decision:
        """Return a deterministic proposal-level decision.

        Generic ``user_authorized`` and ``user_confirmed_safe`` Booleans are
        deliberately ignored because P2A has no trusted authorization transport.
        """
        if not isinstance(tool_name, str) or not tool_name:
            return Decision.deny(self.REASON_MALFORMED_ARGUMENTS)
        if not isinstance(tool_args, Mapping) or not isinstance(context, Mapping):
            return Decision.deny(self.REASON_MALFORMED_ARGUMENTS)

        if tool_name in self._PATH_TOOLS:
            path = tool_args.get("path")
            if not isinstance(path, str) or not path:
                return Decision.deny(self.REASON_MALFORMED_ARGUMENTS)
            if is_protected_secret_path(path):
                return Decision.deny(self.REASON_PROTECTED_PATH)

        if tool_name == "http.post":
            url = tool_args.get("url")
            payload_name = exfil_payload_arg(tool_name)
            data = tool_args.get(payload_name) if payload_name else None
            if (
                payload_name != "data"
                or not isinstance(url, str)
                or not url
                or not isinstance(data, str)
            ):
                return Decision.deny(self.REASON_MALFORMED_ARGUMENTS)
            # Without trusted read_secrets, this public helper can establish only
            # the official environment-independent sentinel control. It must not
            # be reported as real same-session source-value lineage.
            if payload_exfiltrates_secret(data):
                return Decision.deny(self.REASON_EXFIL_SENTINEL_PAYLOAD)

        recent_sources = context.get("recent_sources", ())
        if isinstance(recent_sources, (list, tuple, set, frozenset)):
            tainted = any(source in self._UNTRUSTED_SOURCES for source in recent_sources)
        else:
            tainted = False
        if tainted and tool_name in self._DANGEROUS_AFTER_UNTRUSTED:
            return Decision.deny(self.REASON_UNTRUSTED_DANGEROUS_ACTION)

        return Decision.allow(self.REASON_ALLOWED)
