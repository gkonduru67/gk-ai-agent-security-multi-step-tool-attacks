# UTA_PACKAGED_OPTIMAL_DECISION_SOURCE_INSPECTION_v7.70A

- Status: INSPECTION_COMPLETE
- optimal.py SHA-256: `6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED`
- Method: static AST/source inspection; no SDK import or execution.

## Answers

### Q1. What event state causes Blocked fs.write after accessing untrusted source?

The denial branch is reached when context.recent_sources contains web or email and tool_name is in dangerous_operations. fs.write is in that set. An earlier user_confirmed_safe or user_authorized truthy context value allows immediately, and an ultra-dangerous extracted target is checked before the recent-source branch.

Evidence: authorization_short_circuit, target_sensitive_branch, recent_source_taint_branch, dangerous_operations

### Q2. Is the rule based on source access, returned-content lineage, or both?

The inspected denial branch is based on source-domain presence in context.recent_sources, not equality between returned source content and proposed arguments. No returned-content comparison appears in decide.

Evidence: recent_source_taint_branch

### Q3. Does it read conversational messages?

The decide method does not directly read a messages or conversation field. It reads context keys user_confirmed_safe, user_authorized, and recent_sources. How Sandbox derives those context values is outside this file and must be inspected separately.

Evidence: authorization_short_circuit, recent_source_taint_branch

### Q4. Does it consume any structured authorization field?

The file consumes two boolean-like context values, user_confirmed_safe and user_authorized. It does not reference authorization_id, version, principal, status, allowed count, consumed count, source event identity, content hash, expiry, or revocation fields.

Evidence: authorization_short_circuit

### Q5. Does it bind authorization to the tool name?

The authorization short-circuit is not bound to tool_name. tool_name is used later for sensitive-target reason text and dangerous_operations membership.

Evidence: authorization_short_circuit, recent_source_taint_branch

### Q6. Does it bind authorization to the target path?

The authorization short-circuit is not bound to an extracted target. Target extraction and the ultra-dangerous target check occur only after the authorization allow branch.

Evidence: authorization_short_circuit, target_sensitive_branch, target_extraction

### Q7. Does it bind authorization to exact content or lineage?

The authorization short-circuit does not bind to exact content or returned-content lineage. The UTA denial branch uses recent source domains and dangerous operation membership. _extract_target scans the first present argument among path, url, cmd, data, body, and content for sensitive substrings, but this is not a lineage comparison.

Evidence: authorization_short_circuit, recent_source_taint_branch, target_extraction

### Q8. Does it enforce cardinality?

No cardinality or authorization-consumption field is referenced in the inspected file. No counter is updated in decide.

Evidence: authorization_short_circuit, recent_source_taint_branch

### Q9. Does it enforce expiry or revocation?

No expiry, validity interval, turn binding, or revocation field is referenced in the inspected file.

Evidence: authorization_short_circuit, recent_source_taint_branch

### Q10. Does it preserve provenance across intermediate events?

The file evaluates context.recent_sources supplied at each decision. It does not itself append to, age, or persist recent_sources. Therefore persistence across intermediate events is determined upstream by context construction. The file contains an untrusted_mentions set and track_untrusted_content method, but decide does not read untrusted_mentions.

Evidence: recent_source_taint_branch, untrusted_mentions_tracking

## Central conclusion

The packaged guardrail's UTA branch is a recent-source-domain plus dangerous-operation rule with unconditional context-boolean authorization short-circuits. This file does not implement exact returned-content lineage binding or structured authorization scope, identity, cardinality, expiry, or revocation checks. recent_sources persistence is upstream of this file.

## Next gate

SANDBOX_CONTEXT_CONSTRUCTION_AND_DETERMINISTIC_OPTIMAL_BOUNDARY_VALIDATION
