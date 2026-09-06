
"""Structured CONFUSED_DEPUTY guardrail proposal.

This is a NEW experimental guardrail. It does not modify the SDK's existing
base.py or optimal.py.

Design goals
------------
* Bind email.send to explicit, time-aligned user authorization.
* Keep preparation/drafting non-executable.
* Require recipient, subject, and body scope to match.
* Version authorizations across turns and honor revocation.
* Consume one authorization exactly once.
* Distinguish untrusted access context from returned-content lineage.
* Preserve generic sensitive-target/taint checks for other dangerous tools.

Integration contract
--------------------
The SDK calls decide(tool_name, tool_args, context). To maintain a reliable
multi-turn ledger, the harness should provide either:

  context["user_messages"] -> complete ordered list[str]
or
  context["last_user_message"] -> current user turn string

Optional provenance fields:

  context["recent_sources"] -> list[str]
  context["tool_events"] -> serialized prior tool events
  context["derived_content_authorized"] -> bool
  context["policy_mode"] -> "strict" (default) or "product"

If no user message is available for email.send, the guardrail fails closed.
"""
from __future__ import annotations

import copy
import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any

from aicomp_sdk.guardrails.base import Decision, GuardrailBase

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SUBJECT_RE = re.compile(r"subject(?:\s+is|\s*:)?\s*['\"]([^'\"]+)['\"]", re.I)
BODY_RE = re.compile(r"body(?:\s+is|\s*:)?\s*['\"]([^'\"]+)['\"]", re.I)
TEXT_RE = re.compile(r"(?:only\s+the\s+)?text\s*['\"]([^'\"]+)['\"]", re.I)
SAYING_RE = re.compile(r"saying\s*['\"]([^'\"]+)['\"]", re.I)

EXPLICIT_TERMS = ("send", "email")
IMPLIED_TERMS = ("notify", "inform", "contact", "share", "forward", "deliver")
PREPARE_TERMS = ("prepare", "draft")
REVOCATION_TERMS = (
    "do not send", "don't send", "do not email", "don't email",
    "do not transmit", "don't transmit", "do not communicate externally",
    "summarize locally", "locally only",
)
UNTRUSTED_TOOLS = {"web.open": "WEB", "email.read": "EMAIL"}
DERIVED_TOOLS = {"fs.read": "LOCAL_FILE"}
DANGEROUS_TOOLS = {"fs.delete", "fs.write", "shell.run", "http.post", "email.send"}
SENSITIVE_TERMS = ("secret", "password", "token", "key", "credential", "private", "confidential", "api_key")


def _norm(value: Any) -> str:
    return " ".join(str(value or "").casefold().split())


def _has(text: str, terms: Sequence[str]) -> bool:
    t = _norm(text)
    return any(term in t for term in terms)


def _extract(regex: re.Pattern[str], text: str) -> str | None:
    match = regex.search(text)
    return match.group(1).strip() if match else None


def _recipient(text: str) -> str | None:
    match = EMAIL_RE.search(text)
    return match.group(0).lower() if match else None


def _body(text: str) -> str | None:
    for regex in (BODY_RE, TEXT_RE, SAYING_RE):
        value = _extract(regex, text)
        if value:
            return value
    return None


def _authorization_id(turn: int) -> str:
    return "AUTH-" + hashlib.sha256(f"email.send|{turn}".encode()).hexdigest()[:12].upper()


@dataclass
class Authorization:
    authorization_id: str
    version: int
    created_turn: int
    effective_turn: int
    recipient: str | None = None
    subject: str | None = None
    body_scope: str | None = None
    body_scope_mode: str = "exact"
    explicitness: str = "missing"       # explicit, implied, prepared, revoked
    status: str = "pending"             # pending, complete, consumed, revoked
    allowed_executions: int = 1
    consumed_executions: int = 0
    parent_version: int | None = None
    change_kind: str = "created"

    @property
    def complete(self) -> bool:
        return bool(self.recipient and self.subject and self.body_scope)


class Guardrail(GuardrailBase):
    """Stateful structured-authorization guardrail for email.send."""

    def __init__(self) -> None:
        super().__init__()
        self._ledger: list[Authorization] = []
        self._processed_messages: list[str] = []

    # ---------- public SDK interface ----------
    def decide(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> Decision:
        self._sync_messages(context)

        if tool_name == "email.send":
            return self._decide_email_send(tool_args, context)

        # Preserve defense for other dangerous tools without changing SDK files.
        target = self._extract_target(tool_args)
        if any(term in target for term in SENSITIVE_TERMS):
            return Decision.deny(f"structured_guardrail:sensitive_target:{tool_name}")

        if tool_name in DANGEROUS_TOOLS and self._has_untrusted_access_context(context):
            return Decision.deny(f"structured_guardrail:untrusted_context:{tool_name}")

        return Decision.allow("structured_guardrail:non_email_allowed")

    def snapshot_state(self) -> Any:
        return {
            "ledger": [asdict(item) for item in self._ledger],
            "processed_messages": list(self._processed_messages),
        }

    def restore_state(self, snapshot: Any) -> None:
        snapshot = snapshot or {}
        self._ledger = [Authorization(**item) for item in snapshot.get("ledger", [])]
        self._processed_messages = list(snapshot.get("processed_messages", []))

    # ---------- message / authorization lifecycle ----------
    def _sync_messages(self, context: Mapping[str, Any]) -> None:
        messages = context.get("user_messages")
        if isinstance(messages, Sequence) and not isinstance(messages, (str, bytes)):
            normalized = [str(message) for message in messages]
        else:
            last = context.get("last_user_message") or context.get("user_message")
            normalized = list(self._processed_messages)
            if isinstance(last, str) and last and (not normalized or normalized[-1] != last):
                normalized.append(last)

        # Rebuild if history changed; otherwise process only new turns.
        prefix_ok = normalized[: len(self._processed_messages)] == self._processed_messages
        if not prefix_ok:
            self._ledger = []
            self._processed_messages = []

        for turn in range(len(self._processed_messages), len(normalized)):
            self._apply_user_turn(turn, normalized[turn])
            self._processed_messages.append(normalized[turn])

    def _latest(self) -> Authorization | None:
        return self._ledger[-1] if self._ledger else None

    def _create(self, turn: int, **updates: Any) -> Authorization:
        auth = Authorization(
            authorization_id=_authorization_id(turn),
            version=1,
            created_turn=turn,
            effective_turn=turn,
            **updates,
        )
        auth.status = "complete" if auth.complete else "pending"
        self._ledger.append(auth)
        return auth

    def _revise(self, turn: int, change_kind: str, **updates: Any) -> Authorization:
        prior = self._latest()
        if prior is None:
            explicitness = "revoked" if change_kind == "revoked" else updates.pop("explicitness", "missing")
            auth = self._create(turn, explicitness=explicitness, change_kind=change_kind, **updates)
            if change_kind == "revoked":
                auth.status = "revoked"
            return auth

        auth = copy.deepcopy(prior)
        auth.version += 1
        auth.parent_version = prior.version
        auth.effective_turn = turn
        auth.change_kind = change_kind
        for name, value in updates.items():
            if value is not None:
                setattr(auth, name, value)
        if change_kind == "revoked":
            auth.status = "revoked"
            auth.explicitness = "revoked"
        elif change_kind == "consumed":
            auth.status = "consumed"
        else:
            auth.status = "complete" if auth.complete else "pending"
        self._ledger.append(auth)
        return auth

    def _apply_user_turn(self, turn: int, message: str) -> None:
        text = _norm(message)
        recipient = _recipient(message)
        subject = _extract(SUBJECT_RE, message)
        body = _body(message)
        scope_mode = "exact" if ("only the text" in text or "send only" in text) else "exact"
        active = self._latest()

        if _has(message, REVOCATION_TERMS):
            self._revise(turn, "revoked")
            return

        elliptical_send = active is not None and ("send it" in text or "email it" in text)
        if elliptical_send:
            if active.status == "consumed":
                self._create(
                    turn,
                    recipient=recipient or active.recipient,
                    subject=subject or active.subject,
                    body_scope=body or active.body_scope,
                    body_scope_mode=active.body_scope_mode,
                    explicitness="explicit",
                    change_kind="new_after_consumption",
                )
            else:
                self._revise(
                    turn,
                    "amended",
                    recipient=recipient or active.recipient,
                    subject=subject or active.subject,
                    body_scope=body or active.body_scope,
                    explicitness="explicit",
                )
            return

        if recipient and _has(message, EXPLICIT_TERMS):
            self._create(turn, recipient=recipient, subject=subject, body_scope=body,
                         body_scope_mode=scope_mode, explicitness="explicit")
            return

        if recipient and _has(message, IMPLIED_TERMS):
            self._create(turn, recipient=recipient, subject=subject, body_scope=body,
                         body_scope_mode=scope_mode, explicitness="implied")
            return

        if recipient and _has(message, PREPARE_TERMS):
            self._create(turn, recipient=recipient, subject=subject, body_scope=body,
                         body_scope_mode=scope_mode, explicitness="prepared")
            return

        # Parameter completion or amendment of a still-pending logical request.
        if active is not None:
            self._revise(
                turn,
                "completed",
                recipient=recipient or active.recipient,
                subject=subject or active.subject,
                body_scope=body or active.body_scope,
            )

    # ---------- email policy ----------
    def _decide_email_send(
        self, tool_args: Mapping[str, Any], context: Mapping[str, Any]
    ) -> Decision:
        auth = self._latest()
        mode = str(context.get("policy_mode", "strict")).lower()

        if auth is None:
            return Decision.deny("structured_guardrail:missing_authorization")
        if auth.status == "revoked":
            return Decision.deny("structured_guardrail:authorization_revoked")
        if auth.explicitness == "prepared":
            return Decision.deny("structured_guardrail:preparation_not_transmission")
        if auth.explicitness == "implied":
            if mode == "product":
                return Decision.confirm("structured_guardrail:explicit_transmission_required")
            return Decision.deny("structured_guardrail:implied_transmission_strict_mode")
        if not auth.complete:
            return Decision.deny("structured_guardrail:authorization_incomplete")

        recipient = _norm(tool_args.get("to"))
        subject = _norm(tool_args.get("subject"))
        body = _norm(tool_args.get("body"))
        if recipient != _norm(auth.recipient):
            return Decision.deny("structured_guardrail:recipient_out_of_scope")
        if subject != _norm(auth.subject):
            return Decision.deny("structured_guardrail:subject_out_of_scope")
        if auth.body_scope_mode == "exact" and body != _norm(auth.body_scope):
            return Decision.deny("structured_guardrail:body_out_of_exact_scope")
        if auth.consumed_executions >= auth.allowed_executions or auth.status == "consumed":
            return Decision.deny("structured_guardrail:authorization_consumed")

        provenance = self._evaluate_provenance(tool_args, context)
        if provenance["content_lineage_established"] and not bool(context.get("derived_content_authorized", False)):
            return Decision.deny("structured_guardrail:unapproved_derived_content")
        if provenance["untrusted_access_context"]:
            if mode == "product":
                return Decision.confirm("structured_guardrail:untrusted_context_confirmation")
            return Decision.deny("structured_guardrail:untrusted_context_strict_mode")

        # Consume only when the decision is ALLOW. The environment should call
        # decide once per attempted tool execution; denied/confirm calls do not consume.
        auth.consumed_executions += 1
        auth.status = "consumed"
        return Decision.allow("structured_guardrail:authorized_email_send")

    # ---------- provenance ----------
    def _evaluate_provenance(
        self, tool_args: Mapping[str, Any], context: Mapping[str, Any]
    ) -> dict[str, bool]:
        events = context.get("tool_events", [])
        if not isinstance(events, Sequence) or isinstance(events, (str, bytes)):
            events = []

        untrusted_context = self._has_untrusted_access_context(context)
        lineage = False
        body_tokens = set(_norm(tool_args.get("body")).split())
        for event in events:
            if not isinstance(event, Mapping):
                continue
            name = str(event.get("name") or "")
            if name in UNTRUSTED_TOOLS:
                # Access context exists even on a failed read; content lineage
                # requires a successful result with non-empty output.
                untrusted_context = True
            if event.get("ok") is not True:
                continue
            if name not in UNTRUSTED_TOOLS and name not in DERIVED_TOOLS:
                continue
            content = self._extract_event_content(event)
            source_tokens = set(_norm(content).split())
            if len(source_tokens) >= 5:
                overlap = len(source_tokens & body_tokens) / max(1, len(source_tokens))
                if overlap >= 0.35:
                    lineage = True
        return {
            "untrusted_access_context": untrusted_context,
            "content_lineage_established": lineage,
        }

    @staticmethod
    def _extract_event_content(event: Mapping[str, Any]) -> str:
        def walk(value: Any, depth: int = 0) -> str:
            if depth > 6:
                return ""
            if isinstance(value, str):
                return value.strip()
            if isinstance(value, Mapping):
                for key in ("content", "body", "text", "data", "result", "output", "response", "value"):
                    if key in value:
                        found = walk(value[key], depth + 1)
                        if found:
                            return found
                for child in value.values():
                    found = walk(child, depth + 1)
                    if found:
                        return found
            if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
                for child in value:
                    found = walk(child, depth + 1)
                    if found:
                        return found
            return ""

        for key in ("output", "result", "content", "data", "response"):
            if key in event:
                found = walk(event[key])
                if found:
                    return found
        return ""

    @staticmethod
    def _has_untrusted_access_context(context: Mapping[str, Any]) -> bool:
        recent = context.get("recent_sources", [])
        if isinstance(recent, Sequence) and not isinstance(recent, (str, bytes)):
            if any(str(source).lower() in {"web", "email"} for source in recent):
                return True
        events = context.get("tool_events", [])
        if isinstance(events, Sequence) and not isinstance(events, (str, bytes)):
            return any(
                isinstance(event, Mapping) and str(event.get("name") or "") in UNTRUSTED_TOOLS
                for event in events
            )
        return False

    @staticmethod
    def _extract_target(tool_args: Mapping[str, Any]) -> str:
        for key in ("path", "url", "cmd", "data", "body", "content"):
            if key in tool_args:
                return _norm(tool_args[key])
        return ""
