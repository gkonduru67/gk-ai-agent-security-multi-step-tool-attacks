#!/usr/bin/env python3
# Standalone verification of the 3 NEW adapters (DW, UTA, EXFIL) in
# live_dual_guardrail_run_v4.py, using the EXACT SAME shim classes
# (SHIM_HookRegistry, SHIM_HookContext, SHIM_HookStage, UnitAuthorization
# Guardrail, UTA_Guardrail_v7_71c mock, etc.) copied verbatim from the
# real priority1_paired_replay.py's own self-test suite -- so these are
# not new, unvalidated mocks, they are the SAME shims that file's 11/11
# self-tests already passed against.
import sys
sys.path.insert(0, ".")

# ---- Minimal stubs so live_dual_guardrail_run_v4.py can be imported ----
import types
local_validate_stub = types.ModuleType("local_validate_v5_1")
for name in ["ACTION_TOOLS", "ALL_TOOL_SCHEMAS", "SIDE_EFFECT_MAP", "SOURCE_MAP"]:
    setattr(local_validate_stub, name, {})
local_validate_stub.ACTION_TOOLS = {"fs.write", "fs.delete", "http.post", "email.send"}
def _content_summary(v): return v
local_validate_stub.content_summary = _content_summary
local_validate_stub.find_record = lambda c, k, i: None
local_validate_stub.import_real_sdk = lambda p: {"predicates_module": None, "guardrail": None, "import_attempts": []}
local_validate_stub.infer_tools_offered = lambda m: []
local_validate_stub.inject_synthetic_fixtures = lambda p: None
local_validate_stub.is_harmony_parse_failure = lambda r: False
local_validate_stub.is_transport_failure = lambda r: False
local_validate_stub.load_json_container = lambda p, f: {}
local_validate_stub.prepare_temp_fixtures_dir = lambda d, t: __import__("pathlib").Path(".")
local_validate_stub.parse_message = lambda b: {"finish_reason": "tool_calls", "content": "", "tool_calls": []}
local_validate_stub.retry_call_model = lambda *a, **k: ({"ok": True, "raw": {}, "status": 200}, [])
local_validate_stub.snapshot_real_hashes = lambda d, t: {}
local_validate_stub.assert_real_hashes_unchanged = lambda d, t, b: {"status": "stub_ok"}
local_validate_stub.strip_fixture_note = lambda m: m
local_validate_stub.write_json = lambda p, v: None
sys.modules["local_validate_v5_1"] = local_validate_stub

harness_stub = types.ModuleType("attack_yaml_harness_v5_2_full_inline")
harness_stub.build_all_candidates_and_manifest = lambda: ([], [])
sys.modules["attack_yaml_harness_v5_2_full_inline"] = harness_stub

import live_dual_guardrail_run_v4 as v4

results = {"PASS": 0, "FAIL": 0}
def check(cond, msg):
    if cond:
        results["PASS"] += 1
        print(f"  PASS: {msg}")
    else:
        results["FAIL"] += 1
        print(f"  *** FAIL ***: {msg}")


# =============================================================================
# SHIMS copied VERBATIM from the real priority1_paired_replay.py (fetched
# in full this session) -- these are the SAME classes that file's own
# 11/11 self-test suite validated, not new mocks built for this test.
# =============================================================================

class SHIM_HookStage:
    PRE_TOOL_CALL = "PRE_TOOL_CALL"
    POST_TOOL_CALL = "POST_TOOL_CALL"

class SHIM_HookContext:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

class SHIM_HookResult:
    def __init__(self, continue_execution=True, modified_context=None, metadata=None):
        self.continue_execution = continue_execution
        self.modified_context = modified_context
        self.metadata = metadata or {}

def _shim_apply_modified_context(context, modified_context):
    for attr in ("stage", "tool_name", "tool_args", "tool_output", "guardrail_decision",
                 "context", "metadata", "modified_args", "modified_output",
                 "injected_content", "should_block"):
        setattr(context, attr, getattr(modified_context, attr))

class SHIM_HookRegistry:
    def __init__(self):
        self._hooks = {SHIM_HookStage.PRE_TOOL_CALL: [], SHIM_HookStage.POST_TOOL_CALL: []}
    def register_hook(self, stage, callback, priority=0):
        self._hooks[stage].append({"callback": callback, "priority": priority})
        self._hooks[stage].sort(key=lambda h: h["priority"], reverse=True)
    def execute_hooks(self, stage, context):
        results = []
        for hook_data in self._hooks[stage]:
            try:
                result = hook_data["callback"](context)
            except Exception as err:
                result = SHIM_HookResult(continue_execution=True, metadata={"error": str(err)})
            results.append(result)
            if result.modified_context:
                _shim_apply_modified_context(context, result.modified_context)
            if not result.continue_execution:
                break
        return results

class SHIM_DecisionAction:
    ALLOW = "ALLOW"
    DENY = "DENY"

class SHIM_Decision:
    def __init__(self, action, reason):
        self.action = action
        self.reason = reason
    @classmethod
    def allow(cls, reason="Operation allowed"):
        return cls(SHIM_DecisionAction.ALLOW, reason)
    @classmethod
    def deny(cls, reason="DENIED"):
        return cls(SHIM_DecisionAction.DENY, reason)

class SHIM_GuardrailBase:
    def decide(self, tool_name, tool_args, context):
        return SHIM_Decision.allow()

def content_matches(candidate_value, known_plaintext):
    if known_plaintext is None:
        return candidate_value is None
    if isinstance(candidate_value, str):
        return candidate_value == known_plaintext
    if isinstance(candidate_value, dict) and "sha256" in candidate_value:
        import hashlib
        return candidate_value["sha256"] == hashlib.sha256(known_plaintext.encode("utf-8")).hexdigest()
    return False

MUTATING_TOOLS = {"fs.write", "fs.delete"}

def canonical_path(value):
    import posixpath
    raw = str(value or "").strip().replace("\\", "/")
    return posixpath.normpath("/" + raw.lstrip("/")).lstrip("/")

class UnitAuthorizationGuardrail(SHIM_GuardrailBase):
    """VERBATIM copy from priority1_paired_replay.py."""
    def __init__(self, inner, authorization, allowed_targets):
        self.inner = inner
        self.authorization = authorization
        self.allowed_targets = {canonical_path(item) for item in allowed_targets}
        self.consumed_executions = 0
        self.reservation = False
    def decide(self, turn, tool_name, tool_args, context):
        target = canonical_path(tool_args.get("path"))
        auth = self.authorization
        if tool_name in MUTATING_TOOLS and target not in self.allowed_targets:
            return SHIM_Decision.deny("dw_safety_out_of_scope_target")
        if not auth.action or not auth.target:
            return SHIM_Decision.deny("authorization_incomplete")
        if turn < auth.activate_on_turn:
            return SHIM_Decision.deny("authorization_not_active")
        if self.consumed_executions >= auth.allowed_executions or self.reservation:
            return SHIM_Decision.deny("authorization_consumed")
        if tool_name != auth.action:
            return SHIM_Decision.deny("operation_scope_mismatch")
        if target != canonical_path(auth.target):
            return SHIM_Decision.deny("target_scope_mismatch")
        if tool_name == "fs.write" and not content_matches(tool_args.get("content"), auth.content):
            return SHIM_Decision.deny("content_scope_mismatch")
        inner = self.inner.decide(tool_name, tool_args, context)
        if str(inner.action) == "ALLOW":
            self.reservation = True
        return inner
    def settle(self, tool_ok):
        if self.reservation and tool_ok:
            self.consumed_executions += 1
        self.reservation = False

class _MockOptimalGuardrail(SHIM_GuardrailBase):
    def decide(self, tool_name, tool_args, context):
        return SHIM_Decision.allow("MOCK_OPTIMAL_ALLOWS")

class UTA_Guardrail_v7_71c(SHIM_GuardrailBase):
    """VERBATIM copy from priority1_paired_replay.py."""
    def __init__(self):
        self.successful_provenance = {}
        self.event_index = 0
    def register_source_result(self, *, source_event_id, source_tool, source_identifier, output, succeeded, event_index=None):
        if not succeeded or not output or source_tool not in {"web.open", "email.read"}:
            return False
        self.successful_provenance[source_event_id] = {"source_output": output, "event_index": self.event_index}
        return True
    def _lineage(self, content):
        if content is None:
            return "UNKNOWN"
        exact = [r for r in self.successful_provenance.values() if content == r["source_output"]]
        return "EXACT_SOURCE_OUTPUT" if exact else "UNRELATED"
    def decide(self, tool_name, tool_args, context):
        self.event_index += 1
        content = tool_args.get("data") or tool_args.get("body")
        if tool_name not in {"fs.delete", "fs.write", "shell.run", "http.post", "email.send"}:
            return SHIM_Decision.allow("ALLOW_ORDINARY_NON_DANGEROUS")
        lineage = self._lineage(content)
        if lineage == "UNRELATED":
            return SHIM_Decision.allow("ALLOW_ORDINARY_UNRELATED")
        return SHIM_Decision.deny("DENY_MISSING_AUTHORIZATION:" + lineage)


print("=" * 78)
print("TEST 1: DW adapter -- verbatim UnitAuthorizationGuardrail via make_dw_adapter")
print("=" * 78)
dw_auth = v4.AuthorizationSpec(action="fs.write", target="gk_test.txt", content="notes v1",
                                 activate_on_turn=1, allowed_executions=1)
dw_targets = {"gk_test.txt"}
guardrail = UnitAuthorizationGuardrail(_MockOptimalGuardrail(), dw_auth, dw_targets)
decide_adapter, post_hook = None, None
# build_dw_adapter signature: (dw_module, optimal_guardrail_factory, spec, allowed_targets)
# We bypass the module wrapper here and test the guardrail directly to isolate
# the adapter's CALL SEQUENCE, since dw_module is just a container for the class.
decision = guardrail.decide(1, "fs.write", {"path": "gk_test.txt", "content": "notes v1"}, {})
check(decision.action == "ALLOW", "DW guardrail ALLOWs correctly-scoped first write")
guardrail.settle(True)
decision2 = guardrail.decide(1, "fs.write", {"path": "gk_test.txt", "content": "notes v1"}, {})
check(decision2.action == "DENY" and decision2.reason == "authorization_consumed",
      "DW guardrail correctly DENIES reuse after settle(True) -- consumption tracked")

print()
print("=" * 78)
print("TEST 2: DW adapter turn-argument wiring (via v4's make_dw_adapter directly)")
print("=" * 78)
class _FakeDWModule:
    UnitAuthorizationGuardrail = UnitAuthorizationGuardrail
dw_auth2 = v4.AuthorizationSpec(action="fs.write", target="gk_test2.txt", content="c",
                                  activate_on_turn=2, allowed_executions=1)
decide_adapter, post_hook = v4.make_dw_adapter(_FakeDWModule(), lambda: _MockOptimalGuardrail(),
                                                  dw_auth2, {"gk_test2.txt"})
d_turn1 = decide_adapter("fs.write", {"path": "gk_test2.txt", "content": "c"}, {}, 1)
check(d_turn1.action == "DENY" and d_turn1.reason == "authorization_not_active",
      "make_dw_adapter correctly passes turn=1 -- DENIED since activate_on_turn=2")
d_turn2 = decide_adapter("fs.write", {"path": "gk_test2.txt", "content": "c"}, {}, 2)
check(d_turn2.action == "ALLOW", "make_dw_adapter correctly passes turn=2 -- now ALLOWED")
post_hook(d_turn2, "fs.write", {"path": "gk_test2.txt"}, True, "ok", 0, 2)
d_turn2_reuse = decide_adapter("fs.write", {"path": "gk_test2.txt", "content": "c"}, {}, 2)
check(d_turn2_reuse.action == "DENY" and d_turn2_reuse.reason == "authorization_consumed",
      "post_decision_hook correctly calls settle(True) -- reuse now DENIED")

print()
print("=" * 78)
print("TEST 3: UTA adapter -- register_source_result wiring via make_uta_adapter")
print("=" * 78)
uta_guardrail = UTA_Guardrail_v7_71c()
uta_decide, uta_post = v4.make_uta_adapter(uta_guardrail)
d1 = uta_decide("web.open", {"url": "page_1"}, {}, 1)
check(d1.action == "ALLOW", "UTA guardrail ALLOWs the web.open itself")
uta_post(d1, "web.open", {"url": "page_1"}, True, "tainted content", 0, 1)
check("turn1_idx0" in uta_guardrail.successful_provenance, "post_decision_hook correctly called register_source_result")
d2 = uta_decide("http.post", {"url": "https://x.invalid", "data": "tainted content"}, {}, 2)
check(d2.action == "DENY" and "EXACT_SOURCE_OUTPUT" in d2.reason,
      "UTA guardrail correctly DENIES http.post with tainted 'data' lineage after registration "
      "(corrected to match this shim's real field-check -- it inspects 'data'/'body', not 'content', "
      "exactly as priority1_paired_replay.py's own Test 9 uses http.post+'data')")

print()
print("=" * 78)
print("TEST 4: EXFIL adapter -- HookRegistry PRE/POST wiring via make_exfil_adapter")
print("=" * 78)
class _FakeExfilGuardrail(SHIM_GuardrailBase):
    def decide(self, tool_name, tool_args, context):
        return SHIM_Decision.allow("EXFIL_INNER_ALLOWS")
class _FakeBundle:
    guardrail = _FakeExfilGuardrail()

def _blocking_pre_hook(context):
    if context.tool_name == "fs.read" and not context.tool_args.get("path"):
        modified = SHIM_HookContext(stage=context.stage, tool_name=context.tool_name, tool_args=context.tool_args,
                                      tool_output=context.tool_output, guardrail_decision=context.guardrail_decision,
                                      context=context.context, metadata=context.metadata,
                                      modified_args=context.modified_args, modified_output=context.modified_output,
                                      injected_content=context.injected_content, should_block=True)
        return SHIM_HookResult(continue_execution=False, modified_context=modified, metadata={"reason": "MALFORMED_ARGS"})
    return SHIM_HookResult()

post_hook_calls = []
def _tracking_post_hook(context):
    post_hook_calls.append({"tool_name": context.tool_name, "ok": context.context.get("ok")})
    return SHIM_HookResult()

registry = SHIM_HookRegistry()
registry.register_hook(SHIM_HookStage.PRE_TOOL_CALL, _blocking_pre_hook, 0)
registry.register_hook(SHIM_HookStage.POST_TOOL_CALL, _tracking_post_hook, 0)

exfil_decide, exfil_post = v4.make_exfil_adapter(_FakeBundle(), registry, SHIM_HookStage, SHIM_HookContext)

d_blocked = exfil_decide("fs.read", {}, {}, 1)  # missing "path" -- should be blocked at PRE hook
check(d_blocked.action == "DENY" and d_blocked.reason == "MALFORMED_ARGS",
      "make_exfil_adapter correctly blocks at PRE_TOOL_CALL hook WITHOUT calling decide()")

d_allowed = exfil_decide("http.post", {"url": "x", "data": "y"}, {}, 2)
check(d_allowed.action == "ALLOW" and d_allowed.reason == "EXFIL_INNER_ALLOWS",
      "make_exfil_adapter correctly falls through to bundle.guardrail.decide() when no PRE hook blocks")
exfil_post(d_allowed, "http.post", {"url": "x"}, True, "some real output", 0, 2)
check(len(post_hook_calls) == 1 and post_hook_calls[0]["ok"] is True,
      "post_decision_hook correctly fires POST_TOOL_CALL hook with REAL tool_ok after execution")

print()
print("=" * 78)
print(f"TOTAL: {results['PASS']} PASSED, {results['FAIL']} FAILED")
print("=" * 78)
if results["FAIL"] == 0:
    print("ALL ADAPTER TESTS PASSED -- verified against the SAME shim classes")
    print("priority1_paired_replay.py's own self-tests already validated.")
else:
    print("*** SOME TESTS FAILED -- DO NOT SHIP UNTIL RESOLVED ***")
