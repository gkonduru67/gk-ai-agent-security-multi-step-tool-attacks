# UTA_SANDBOX_CONTEXT_CONSTRUCTION_INSPECTION_v7.70B

- Status: INSPECTION_COMPLETE
- Sandbox SHA-256: `B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0`
- Gym SHA-256: `8BBC3479515C388717D76FE9964D957A7CBD9BFB97C28AA894E9C51E3051F8AF`

## Answers

### Q1. Where is guardrail context created?

Inside SandboxEnv.interact immediately before PRE_GUARDRAIL hooks and guardrail.decide. The local ctx mapping contains seed, recent_sources, recent_tools, last_user, side_effect, and scope. PRE_GUARDRAIL receives this mapping, but guardrail.decide is called with the original ctx variable.

Evidence: guardrail_context_creation, guardrail_decide_call

### Q2. How is recent_sources populated?

It is rebuilt for each proposed known tool as [event.source for event in self.trace.tool_events[-5:]]. It uses recorded ToolEvent.source values from the last five trace tool events.

Evidence: guardrail_context_creation

### Q3. Do only successful source events qualify?

No explicit ok filter is applied when recent_sources is constructed. Both successful and failed recorded tool events can contribute their source value if they are within the last five events. The exact source on a failed event is assigned from self.tools.last_source by _record_failed_tool_attempt.

Evidence: guardrail_context_creation, failed_event_construction

### Q4. What is the exact history window?

The guardrail context window is the last five recorded tool events for both recent_sources and recent_tools. Gym observation summaries use a separate last-eight tool/source window, compacted to four only if the JSON summary exceeds its size limit.

Evidence: guardrail_context_creation, gym_observation_summary

### Q5. How is user_authorized derived?

SandboxEnv.interact does not place user_authorized in ctx and sandbox.py contains no user_authorized token. The packaged optimal default therefore remains false through context.get unless a different caller or modification supplies the key. PRE_GUARDRAIL hooks receive ctx, but this file then calls decide with the original ctx variable; the source does not show replacement of ctx from the hook object.

Evidence: guardrail_context_creation, guardrail_decide_call

### Q6. How is user_confirmed_safe derived?

SandboxEnv.interact does not place user_confirmed_safe in ctx and sandbox.py contains no user_confirmed_safe token. The packaged optimal default therefore remains false through context.get unless another caller or mutation supplies the key.

Evidence: guardrail_context_creation, guardrail_decide_call

### Q7. What are reset and persistence behaviors?

Within an environment, trace tool events persist across interact calls until reset. reset replaces the trace, runtime history, last tool output, tool state, hook state, guardrail state, and agent state with initial/reset values. snapshot captures trace, runtime history, last output, tools, guardrail, agent, hooks, and filesystem; restore reinstates them.

Evidence: sandbox_reset, sandbox_snapshot, sandbox_restore

### Q8. What context is passed on denied events?

The proposed action is evaluated with ctx before the denial. If the guardrail returns DENY, Sandbox records a failed ToolEvent with ok false, the proposed arguments, side effect, scope, source equal to tools.last_source, and error prefixed denied:, then breaks. That failed event can enter the recent_sources/recent_tools window of a later interact call.

Evidence: guardrail_context_creation, guardrail_decide_call, denied_event_path, failed_event_construction

### Q9. What context is supplied to Gym?

GymAttackEnv constructs and owns a SandboxEnv with the same agent, guardrail, fixtures, and hook registry. step delegates the user action to self._sandbox.interact. It does not create a separate guardrail context. Gym observation summaries expose their own last-eight recent tool/source view, but that observation window is not the ctx passed to the guardrail.

Evidence: gym_wraps_sandbox, gym_step_delegation, gym_observation_summary

### Q10. Does it preserve provenance across intermediate events?

Sandbox preserves only coarse source labels for the last five recorded tool events in guardrail ctx. It does not place source event IDs, source success, source output hashes, or final-argument lineage in ctx. A web/email label therefore remains visible across at most four later recorded events and ages out once five newer events occupy the window. This is access-context persistence, not returned-content lineage.

Evidence: guardrail_context_creation, successful_event_construction, failed_event_construction

## Central conclusion

Sandbox constructs packaged-optimal context from the last five recorded ToolEvents without filtering by success and without adding user_authorized or user_confirmed_safe. Gym delegates execution to SandboxEnv and therefore uses Sandbox guardrail-context construction; Gym trace observations have a separate last-eight summary window. The guardrail context preserves coarse access labels, not returned-content lineage.

## Next gate

DETERMINISTIC_SANDBOX_OPTIMAL_CONTEXT_BOUNDARY_MATRIX
