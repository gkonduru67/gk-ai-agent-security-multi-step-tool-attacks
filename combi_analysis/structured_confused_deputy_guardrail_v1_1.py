"""Structured CONFUSED_DEPUTY Guardrail v1.1.

Standalone experimental guardrail. This file does not modify the SDK's
base.py or optimal.py.
"""
from __future__ import annotations

import copy
import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any


class DecisionAction:
    ALLOW = "ALLOW"
    DENY = "DENY"
    CONFIRM = "CONFIRM"

class Decision:
    def __init__(self, action, reason):
        self.action, self.reason = action, reason
    @classmethod
    def allow(cls, reason="Operation allowed"):
        return cls(DecisionAction.ALLOW, reason)
    @classmethod
    def deny(cls, reason="DENIED"):
        return cls(DecisionAction.DENY, reason)
    @classmethod
    def confirm(cls, reason="CONFIRM"):
        return cls(DecisionAction.CONFIRM, reason)

class GuardrailBase:
    pass


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
NEW_ACTION_MARKERS = ("new email", "another email", "separate email", "new message")
UNTRUSTED_TOOLS = {"web.open": "WEB", "email.read": "EMAIL"}
DERIVED_TOOLS = {"fs.read": "LOCAL_FILE"}
DANGEROUS_TOOLS = {"fs.delete", "fs.write", "shell.run", "http.post", "email.send"}
SENSITIVE_TERMS = ("secret", "password", "token", "key", "credential", "private", "confidential", "api_key")


def _norm(value):
    return " ".join(str(value or "").casefold().split())

def _has(text, terms):
    normalized = _norm(text)
    return any(term in normalized for term in terms)

def _extract(regex, text):
    match = regex.search(text)
    return match.group(1).strip() if match else None

def _recipient(text):
    match = EMAIL_RE.search(text)
    return match.group(0).lower() if match else None

def _body(text):
    for regex in (BODY_RE, TEXT_RE, SAYING_RE):
        value = _extract(regex, text)
        if value:
            return value
    return None

def _authorization_id(turn, ordinal):
    raw = f"email.send|{turn}|{ordinal}"
    return "AUTH-" + hashlib.sha256(raw.encode()).hexdigest()[:12].upper()


@dataclass
class Authorization:
    authorization_id: str
    version: int
    created_turn: int
    effective_turn: int
    recipient: str = None
    subject: str = None
    body_scope: str = None
    body_scope_mode: str = "exact"
    explicitness: str = "missing"
    status: str = "pending"
    allowed_executions: int = 1
    consumed_executions: int = 0
    parent_version: int = None
    change_kind: str = "created"

    @property
    def complete(self):
        return bool(self.recipient and self.subject and self.body_scope)


class Guardrail(GuardrailBase):
    def __init__(self):
        self._ledger = []
        self._processed_messages = []
        self._authorization_ordinal = 0

    def decide(self, tool_name, tool_args, context):
        self._sync_messages(context)
        if tool_name == "email.send":
            return self._decide_email_send(tool_args, context)
        target = self._extract_target(tool_args)
        if any(term in target for term in SENSITIVE_TERMS):
            return Decision.deny(f"structured_guardrail:sensitive_target:{tool_name}")
        if tool_name in DANGEROUS_TOOLS and self._has_untrusted_access_context(context):
            return Decision.deny(f"structured_guardrail:untrusted_context:{tool_name}")
        return Decision.allow("structured_guardrail:non_email_allowed")

    def snapshot_state(self):
        return {"ledger": [asdict(item) for item in self._ledger],
                "processed_messages": list(self._processed_messages),
                "authorization_ordinal": self._authorization_ordinal}

    def restore_state(self, snapshot):
        snapshot = snapshot or {}
        self._ledger = [Authorization(**item) for item in snapshot.get("ledger", [])]
        self._processed_messages = list(snapshot.get("processed_messages", []))
        self._authorization_ordinal = int(snapshot.get("authorization_ordinal", 0))

    def _sync_messages(self, context):
        messages = context.get("user_messages")
        if isinstance(messages, Sequence) and not isinstance(messages, (str, bytes)):
            normalized = [str(message) for message in messages]
        else:
            last = context.get("last_user_message") or context.get("user_message")
            normalized = list(self._processed_messages)
            if isinstance(last, str) and last and (not normalized or normalized[-1] != last):
                normalized.append(last)

        if normalized[:len(self._processed_messages)] != self._processed_messages:
            self._ledger = []
            self._processed_messages = []
            self._authorization_ordinal = 0

        for turn in range(len(self._processed_messages), len(normalized)):
            self._apply_user_turn(turn, normalized[turn])
            self._processed_messages.append(normalized[turn])

    def _latest(self):
        return self._ledger[-1] if self._ledger else None

    def _current_turn(self):
        return max(0, len(self._processed_messages) - 1)

    def _create(self, turn, **updates):
        self._authorization_ordinal += 1
        auth = Authorization(
            authorization_id=_authorization_id(turn, self._authorization_ordinal),
            version=1, created_turn=turn, effective_turn=turn, **updates,
        )
        if auth.explicitness == "pending_reauthorization":
            auth.status = "pending_reauthorization"
        elif auth.explicitness == "revoked":
            auth.status = "revoked"
        else:
            auth.status = "complete" if auth.complete else "pending"
        self._ledger.append(auth)
        return auth

    def _revise(self, turn, change_kind, **updates):
        prior = self._latest()
        if prior is None:
            explicitness = "revoked" if change_kind == "revoked" else updates.pop("explicitness", "missing")
            return self._create(turn, explicitness=explicitness, change_kind=change_kind, **updates)

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
        elif auth.explicitness == "pending_reauthorization":
            auth.status = "pending_reauthorization"
        else:
            auth.status = "complete" if auth.complete else "pending"
        self._ledger.append(auth)
        return auth

    def _consume_current_authorization(self):
        active = self._latest()
        if active is None:
            raise RuntimeError("No authorization to consume")
        if active.status == "consumed":
            return active
        return self._revise(self._current_turn(), "consumed", consumed_executions=active.consumed_executions + 1)

    @staticmethod
    def _is_fully_specified_new_send(message, recipient, subject, body):
        normalized = _norm(message)
        return bool(any(marker in normalized for marker in NEW_ACTION_MARKERS) and _has(message, EXPLICIT_TERMS) and recipient and subject and body)

    def _start_reauthorization(self, turn, recipient=None):
        request = self._create(turn, recipient=recipient, subject=None, body_scope=None,
                                 body_scope_mode="exact", explicitness="pending_reauthorization",
                                 change_kind="new_request_after_consumption")
        request.status = "pending_reauthorization"

    def _apply_user_turn(self, turn, message):
        text = _norm(message)
        recipient = _recipient(message)
        subject = _extract(SUBJECT_RE, message)
        body = _body(message)
        active = self._latest()

        if _has(message, REVOCATION_TERMS):
            self._revise(turn, "revoked")
            return
        if self._is_fully_specified_new_send(message, recipient, subject, body):
            self._create(turn, recipient=recipient, subject=subject, body_scope=body,
                          body_scope_mode="exact", explicitness="explicit", change_kind="new_explicit_action")
            return
        elliptical_send = active is not None and ("send it" in text or "email it" in text)
        if elliptical_send:
            if active.status == "consumed":
                self._start_reauthorization(turn, recipient)
            else:
                self._revise(turn, "amended", recipient=recipient or active.recipient,
                             subject=subject or active.subject, body_scope=body or active.body_scope,
                             explicitness="explicit")
            return
        if recipient and _has(message, EXPLICIT_TERMS):
            if active is not None and active.status == "consumed":
                self._start_reauthorization(turn, recipient)
            else:
                self._create(turn, recipient=recipient, subject=subject, body_scope=body,
                              body_scope_mode="exact", explicitness="explicit")
            return
        if recipient and _has(message, IMPLIED_TERMS):
            self._create(turn, recipient=recipient, subject=subject, body_scope=body,
                          body_scope_mode="exact", explicitness="implied")
            return
        if recipient and _has(message, PREPARE_TERMS):
            self._create(turn, recipient=recipient, subject=subject, body_scope=body,
                          body_scope_mode="exact", explicitness="prepared")
            return
        if active is not None:
            if active.status == "consumed":
                self._start_reauthorization(turn, recipient)
            else:
                self._revise(turn, "completed", recipient=recipient or active.recipient,
                             subject=subject or active.subject, body_scope=body or active.body_scope)

    def _decide_email_send(self, tool_args, context):
        auth = self._latest()
        mode = str(context.get("policy_mode", "strict")).lower()
        deny_reasons, confirm_reasons = [], []
        provenance = self._evaluate_provenance(tool_args, context)

        if auth is None:
            deny_reasons.append("missing_authorization")
        else:
            if auth.status == "revoked":
                deny_reasons.append("authorization_revoked")
            if auth.status == "pending_reauthorization":
                (confirm_reasons if mode == "product" else deny_reasons).append("new_authorization_required_after_completed_action")
            if auth.explicitness == "prepared":
                deny_reasons.append("preparation_not_transmission")
            if auth.explicitness == "implied":
                (confirm_reasons if mode == "product" else deny_reasons).append("implied_transmission")
            if not auth.complete and auth.status != "pending_reauthorization":
                deny_reasons.append("authorization_incomplete")
            if auth.status not in {"pending_reauthorization", "revoked"}:
                if _norm(tool_args.get("to")) != _norm(auth.recipient):
                    deny_reasons.append("recipient_out_of_scope")
                if _norm(tool_args.get("subject")) != _norm(auth.subject):
                    deny_reasons.append("subject_out_of_scope")
                if auth.body_scope_mode == "exact" and _norm(tool_args.get("body")) != _norm(auth.body_scope):
                    deny_reasons.append("body_out_of_exact_scope")
                if auth.consumed_executions >= auth.allowed_executions or auth.status == "consumed":
                    deny_reasons.append("authorization_consumed")

        if provenance["content_lineage_established"] and not bool(context.get("derived_content_authorized", False)):
            deny_reasons.append("unapproved_derived_content")
        if provenance["untrusted_access_context"]:
            (confirm_reasons if mode == "product" else deny_reasons).append("untrusted_access_context")

        if deny_reasons:
            return Decision.deny("structured_guardrail:" + ",".join(sorted(set(deny_reasons))))
        if confirm_reasons:
            return Decision.confirm("structured_guardrail:" + ",".join(sorted(set(confirm_reasons))))
        self._consume_current_authorization()
        return Decision.allow("structured_guardrail:authorized_email_send")

    def _evaluate_provenance(self, tool_args, context):
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
                untrusted_context = True
            if event.get("ok") is not True or (name not in UNTRUSTED_TOOLS and name not in DERIVED_TOOLS):
                continue
            content = self._extract_event_content(event)
            source_tokens = set(_norm(content).split())
            if len(source_tokens) >= 5:
                overlap = len(source_tokens & body_tokens) / max(1, len(source_tokens))
                if overlap >= 0.35:
                    lineage = True
        return {"untrusted_access_context": untrusted_context, "content_lineage_established": lineage}

    @staticmethod
    def _extract_event_content(event):
        def walk(value, depth=0):
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
    def _has_untrusted_access_context(context):
        recent = context.get("recent_sources", [])
        if isinstance(recent, Sequence) and not isinstance(recent, (str, bytes)):
            if any(str(s).lower() in {"web", "email"} for s in recent):
                return True
        events = context.get("tool_events", [])
        if isinstance(events, Sequence) and not isinstance(events, (str, bytes)):
            return any(isinstance(e, Mapping) and str(e.get("name") or "") in UNTRUSTED_TOOLS for e in events)
        return False

    @staticmethod
    def _extract_target(tool_args):
        for key in ("path", "url", "cmd", "data", "body", "content"):
            if key in tool_args:
                return _norm(tool_args[key])
        return ""
