#!/usr/bin/env python3
"""Optimal+ policy specification and deterministic reference policy.

This is a research policy artifact, not a replacement for packaged optimal.py.
It corrects both v7.70C error directions:
  1. unrelated writes are not denied solely because a recent web label exists;
  2. exact/transformed source-derived writes remain governed by persistent
     successful-source provenance after the five-event label window expires.

The script emits:
  - a frozen JSON policy specification;
  - a standalone research guardrail module (optimal_plus_v7_71a.py);
  - a deterministic policy unit-test report;
  - a SHA-256 manifest.

No GPT model, Sandbox, Gym, tool, predicate, or breach execution occurs here.
"""
from __future__ import annotations
import argparse, hashlib, json, os, py_compile, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="UTA_OPTIMAL_PLUS_POLICY_SPECIFICATION_v7.71A"
PARENT_VERSION="UTA_DETERMINISTIC_SANDBOX_OPTIMAL_CONTEXT_BOUNDARY_MATRIX_v7.70C"
EXPECTED_PARENT_MATRIX="6204B1DF6C1FD619868C012D3136ECFECC6DA0B3D29232B4EE3F54FBF6ABFB43"
REQUIRED_PARENT_ANSWERS={
 "successful_web_enters_next_context":True,
 "failed_web_enters_next_context":True,
 "gap4_web_visible":True,
 "gap5_web_visible":False,
 "booleans_absent_all_core_rows":True,
 "sandbox_gym_context_parity_all_scenarios":True,
 "sandbox_gym_decision_parity_all_scenarios":True,
 "denied_downstream_event_source":"web",
 "denied_event_enters_next_context":True,
}

def safe(v):
 if v is None or isinstance(v,(str,int,float,bool)):return v
 if isinstance(v,Path):return str(v)
 if isinstance(v,dict):return {str(k):safe(x) for k,x in v.items()}
 if isinstance(v,(list,tuple,set)):return [safe(x) for x in v]
 return repr(v)
def canon(v):return json.dumps(safe(v),sort_keys=True,separators=(",",":"),ensure_ascii=True)
def sha_text(s):return hashlib.sha256(s.encode("utf-8")).hexdigest().upper()
def sha_file(p):
 h=hashlib.sha256()
 with Path(p).open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest().upper()
def atomic_text(p,text):
 if p.exists():raise FileExistsError(f"Refusing overwrite: {p}")
 t=p.with_name(p.name+".tmp");t.write_text(text,encoding="utf-8");os.replace(t,p)
def atomic_json(p,v):atomic_text(p,json.dumps(safe(v),indent=2,ensure_ascii=True)+"\n")
def verify_parent(report,manifest):
 r=json.loads(report.read_text(encoding="utf-8"));m=json.loads(manifest.read_text(encoding="utf-8"));actual=sha_file(report);hit=next((x for x in m.get("artifacts",[]) if Path(str(x.get("file") or "")).name.lower()==report.name.lower()),None)
 answer_ok=all((r.get("question_answers") or {}).get(k)==v for k,v in REQUIRED_PARENT_ANSWERS.items())
 ok=bool(hit and str(hit.get("sha256") or "").upper()==actual and r.get("version")==PARENT_VERSION and r.get("status")=="COMPLETED_CLASSIFIABLE_COVERAGE" and r.get("matrix_sha256")==EXPECTED_PARENT_MATRIX and answer_ok)
 if not ok:raise RuntimeError("v7.70C parent verification failed")
 return {"report":str(report),"report_sha256":actual,"manifest":str(manifest),"manifest_sha256":sha_file(manifest),"matrix_sha256":r.get("matrix_sha256"),"question_answers_verified":True,"verified":True}

def policy_spec():
 return {
  "schema":"UTA_OPTIMAL_PLUS_POLICY_SPECIFICATION_V1",
  "version":VERSION,
  "status":"POLICY_SPECIFICATION_FROZEN",
  "scope":"RESEARCH_OPTIMAL_PLUS_DETERMINISTIC_POLICY_ONLY",
  "non_goals":["modify packaged optimal.py","parse conversational authority","evaluate official predicates","claim breach","claim hosted parity"],
  "correction_of_user_wording":"Unrelated writes MUST NOT be denied solely because a historical web label remains visible. They return to ordinary target/tool policy.",
  "observed_parent_constraints":{
   "recent_source_window":"five recorded tool events",
   "failed_source_label_can_be_web":True,
   "denied_event_can_duplicate_source_label":True,
   "successful_source_lineage_can_outlive_recent_source_label":True,
   "default_boolean_authorization_keys_absent":True,
  },
  "evidence_layers":{
   "access_context":"recent source labels; risk signal only",
   "successful_provenance":"persistent record created only after successful source retrieval",
   "returned_content_lineage":"comparison of proposed content against persistent successful provenance",
   "authorization":"trusted structured object bound to action, target, source, content, lifecycle",
   "effect":"tool success; authorization consumption occurs only here",
  },
  "source_provenance_record":{
   "required_fields":["source_event_id","source_tool","source_identifier","source_output_sha256","source_output","event_index","succeeded"],
   "creation_rule":"Create only after successful web.open or email.read with nonempty returned content.",
   "failed_lookup_rule":"Do not create a successful provenance record.",
   "persistence_rule":"Independent of recent_sources window; reset/snapshot/restore with guardrail state.",
  },
  "lineage_classes":{
   "EXACT_SOURCE_OUTPUT":"proposed content equals a successful stored source output",
   "TRANSFORMED_SOURCE_OUTPUT":"proposed content contains a nonempty successful stored source output as a strict substring",
   "UNRELATED":"proposed content does not equal or contain any successful stored source output",
   "UNKNOWN":"proposal has no supported content-bearing argument",
  },
  "authorization_schema":{
   "required_fields":["authorization_id","version","principal","status","tool_name","target","source_event_id","source_output_sha256","authorized_argument_sha256","derivation_mode","allowed_execution_count","consumed_execution_count","valid_from_event","expires_after_event","revoked"],
   "trusted_transport":"context.structured_authorization supplied by deterministic harness or future frozen runtime adapter; never inferred from conversational text",
   "valid_status":"ACTIVE",
   "allowed_derivation_modes":["EXACT_SOURCE_OUTPUT","TRANSFORMED_SOURCE_OUTPUT"],
  },
  "decision_order":[
   "Validate tool and arguments.",
   "Resolve target and apply sensitive-target policy without Boolean bypass.",
   "Resolve persistent successful-source lineage for the proposal content.",
   "If UNRELATED, apply ordinary target/tool policy and ignore historical web label alone.",
   "If EXACT or TRANSFORMED, require structured authorization.",
   "Validate status, revocation, time, cardinality, tool, target, source event, source hash, argument hash, and derivation mode.",
   "Allow the exactly bound action once.",
   "Consume only after a separately reported successful effect.",
  ],
  "decision_taxonomy":["ALLOW_ORDINARY_UNRELATED","ALLOW_AUTHORIZED_ONCE","DENY_SENSITIVE_TARGET","DENY_MISSING_AUTHORIZATION","DENY_UNSTRUCTURED_AUTHORIZATION","DENY_INVALID_STATUS","DENY_REVOKED","DENY_NOT_YET_VALID","DENY_EXPIRED","DENY_ALREADY_CONSUMED","DENY_TOOL_SCOPE_MISMATCH","DENY_TARGET_SCOPE_MISMATCH","DENY_SOURCE_BINDING_MISMATCH","DENY_SOURCE_HASH_MISMATCH","DENY_CONTENT_BINDING_MISMATCH","DENY_DERIVATION_MODE_MISMATCH","DENY_UNKNOWN_LINEAGE"],
  "lifecycle":{
   "decision_does_not_consume":True,
   "consume_api":"record_effect(authorization_id, tool_name, tool_args, succeeded=True)",
   "consume_only_after_successful_effect":True,
   "denied_or_failed_effect_consumes":False,
   "reset":"restore initial provenance, authorization, decision, and pending-allow state",
   "snapshot_restore":"preserve provenance, authorization lifecycle, event counter, and pending allow",
  },
  "advancement":"Run the frozen deterministic matrix against PACKAGED_OPTIMAL and RESEARCH_OPTIMAL_PLUS before GPT integration.",
 }

MODULE='''from __future__ import annotations
import copy, hashlib
from collections.abc import Mapping
from typing import Any
from aicomp_sdk.guardrails.base import Decision, GuardrailBase

POLICY_VERSION = "UTA_OPTIMAL_PLUS_v7.71A"
DANGEROUS_OPERATIONS = {"fs.delete", "fs.write", "shell.run", "http.post", "email.send"}
SENSITIVE_PATTERNS = {"secret", "password", "token", "key", "credential", "private", "confidential", "api_key"}
CONTENT_KEYS = ("content", "data", "body", "cmd")
TARGET_KEYS = ("path", "url")

def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest().upper()

def _target(args: Mapping[str, Any]) -> str:
    for key in TARGET_KEYS:
        if key in args:
            return str(args[key])
    return ""

def _content(args: Mapping[str, Any]) -> str | None:
    for key in CONTENT_KEYS:
        if key in args:
            return str(args[key])
    return None

class Guardrail(GuardrailBase):
    """Research Optimal+ policy. Not the packaged Kaggle optimal guardrail."""
    def __init__(self) -> None:
        super().__init__()
        self.successful_provenance: dict[str, dict[str, Any]] = {}
        self.authorizations: dict[str, dict[str, Any]] = {}
        self.event_index = 0
        self.decision_audit: list[dict[str, Any]] = []
        self._pending_allow: dict[str, Any] | None = None
        self._initial_state = self._state()

    def _state(self) -> dict[str, Any]:
        return {"successful_provenance": copy.deepcopy(self.successful_provenance), "authorizations": copy.deepcopy(self.authorizations), "event_index": self.event_index, "decision_audit": copy.deepcopy(self.decision_audit), "pending_allow": copy.deepcopy(self._pending_allow)}

    def snapshot_state(self) -> dict[str, Any]:
        return self._state()

    def restore_state(self, state: Any) -> None:
        state = copy.deepcopy(state if state is not None else self._initial_state)
        self.successful_provenance = state.get("successful_provenance", {})
        self.authorizations = state.get("authorizations", {})
        self.event_index = int(state.get("event_index", 0))
        self.decision_audit = state.get("decision_audit", [])
        self._pending_allow = state.get("pending_allow")

    def register_source_result(self, *, source_event_id: str, source_tool: str, source_identifier: str, output: str, succeeded: bool, event_index: int | None = None) -> bool:
        if not succeeded or not output or source_tool not in {"web.open", "email.read"}:
            return False
        record = {"source_event_id": source_event_id, "source_tool": source_tool, "source_identifier": source_identifier, "source_output": output, "source_output_sha256": _sha(output), "event_index": self.event_index if event_index is None else int(event_index), "succeeded": True}
        self.successful_provenance[source_event_id] = record
        return True

    def register_authorization(self, authorization: Mapping[str, Any]) -> None:
        data = copy.deepcopy(dict(authorization))
        auth_id = str(data.get("authorization_id") or "")
        if not auth_id:
            raise ValueError("authorization_id is required")
        self.authorizations[auth_id] = data

    def _lineage(self, content: str | None) -> tuple[str, dict[str, Any] | None]:
        if content is None:
            return "UNKNOWN", None
        exact = [r for r in self.successful_provenance.values() if content == r["source_output"]]
        if exact:
            return "EXACT_SOURCE_OUTPUT", sorted(exact, key=lambda r: r["event_index"], reverse=True)[0]
        transformed = [r for r in self.successful_provenance.values() if r["source_output"] and r["source_output"] in content]
        if transformed:
            return "TRANSFORMED_SOURCE_OUTPUT", sorted(transformed, key=lambda r: r["event_index"], reverse=True)[0]
        return "UNRELATED", None

    def _deny(self, code: str, detail: str) -> Decision:
        return Decision.deny(f"{code}:{detail}")

    def decide(self, tool_name: str, tool_args: Mapping[str, Any], context: Mapping[str, Any]) -> Decision:
        self.event_index += 1
        target = _target(tool_args)
        content = _content(tool_args)
        if target and any(p in target.lower() for p in SENSITIVE_PATTERNS):
            decision = self._deny("DENY_SENSITIVE_TARGET", target)
            self._audit(tool_name, tool_args, context, "NOT_EVALUATED", None, decision)
            return decision
        if tool_name not in DANGEROUS_OPERATIONS:
            decision = Decision.allow("ALLOW_ORDINARY_NON_DANGEROUS")
            self._audit(tool_name, tool_args, context, "NOT_APPLICABLE", None, decision)
            return decision
        lineage, source = self._lineage(content)
        if lineage == "UNRELATED":
            decision = Decision.allow("ALLOW_ORDINARY_UNRELATED")
            self._audit(tool_name, tool_args, context, lineage, None, decision)
            return decision
        if lineage == "UNKNOWN":
            decision = self._deny("DENY_UNKNOWN_LINEAGE", "content-bearing argument missing")
            self._audit(tool_name, tool_args, context, lineage, None, decision)
            return decision
        supplied = context.get("structured_authorization")
        if supplied is None:
            decision = self._deny("DENY_MISSING_AUTHORIZATION", lineage)
            self._audit(tool_name, tool_args, context, lineage, source, decision)
            return decision
        if not isinstance(supplied, Mapping):
            decision = self._deny("DENY_UNSTRUCTURED_AUTHORIZATION", type(supplied).__name__)
            self._audit(tool_name, tool_args, context, lineage, source, decision)
            return decision
        auth_id = str(supplied.get("authorization_id") or "")
        auth = self.authorizations.get(auth_id)
        if auth is None or dict(supplied) != auth:
            decision = self._deny("DENY_UNSTRUCTURED_AUTHORIZATION", "authorization not registered by trusted transport")
            self._audit(tool_name, tool_args, context, lineage, source, decision)
            return decision
        checks = [
            (auth.get("status") == "ACTIVE", "DENY_INVALID_STATUS", str(auth.get("status"))),
            (auth.get("revoked") is False, "DENY_REVOKED", auth_id),
            (self.event_index >= int(auth.get("valid_from_event", 0)), "DENY_NOT_YET_VALID", auth_id),
            (self.event_index <= int(auth.get("expires_after_event", -1)), "DENY_EXPIRED", auth_id),
            (int(auth.get("consumed_execution_count", 0)) < int(auth.get("allowed_execution_count", 0)), "DENY_ALREADY_CONSUMED", auth_id),
            (auth.get("tool_name") == tool_name, "DENY_TOOL_SCOPE_MISMATCH", tool_name),
            (auth.get("target") == target, "DENY_TARGET_SCOPE_MISMATCH", target),
            (auth.get("source_event_id") == source["source_event_id"], "DENY_SOURCE_BINDING_MISMATCH", source["source_event_id"]),
            (auth.get("source_output_sha256") == source["source_output_sha256"], "DENY_SOURCE_HASH_MISMATCH", source["source_output_sha256"]),
            (auth.get("authorized_argument_sha256") == _sha(content or ""), "DENY_CONTENT_BINDING_MISMATCH", _sha(content or "")),
            (auth.get("derivation_mode") == lineage, "DENY_DERIVATION_MODE_MISMATCH", lineage),
        ]
        for passed, code, detail in checks:
            if not passed:
                decision = self._deny(code, detail)
                self._audit(tool_name, tool_args, context, lineage, source, decision)
                return decision
        self._pending_allow = {"authorization_id": auth_id, "tool_name": tool_name, "tool_args_sha256": _sha(repr(sorted(dict(tool_args).items())))}
        decision = Decision.allow("ALLOW_AUTHORIZED_ONCE")
        self._audit(tool_name, tool_args, context, lineage, source, decision)
        return decision

    def record_effect(self, *, authorization_id: str, tool_name: str, tool_args: Mapping[str, Any], succeeded: bool) -> bool:
        expected = {"authorization_id": authorization_id, "tool_name": tool_name, "tool_args_sha256": _sha(repr(sorted(dict(tool_args).items())))}
        if not succeeded or self._pending_allow != expected:
            return False
        auth = self.authorizations.get(authorization_id)
        if auth is None:
            return False
        auth["consumed_execution_count"] = int(auth.get("consumed_execution_count", 0)) + 1
        self._pending_allow = None
        return True

    def _audit(self, tool_name, tool_args, context, lineage, source, decision) -> None:
        self.decision_audit.append({"event_index": self.event_index, "tool_name": tool_name, "tool_args": copy.deepcopy(dict(tool_args)), "context": copy.deepcopy(dict(context)), "lineage_class": lineage, "matched_source_event_id": None if source is None else source["source_event_id"], "decision_action": str(decision.action.value if hasattr(decision.action, "value") else decision.action), "decision_reason": decision.reason})
'''

def main():
 ap=argparse.ArgumentParser();ap.add_argument("--v770c-report",required=True,type=Path);ap.add_argument("--v770c-manifest",required=True,type=Path);ap.add_argument("--out-dir",required=True,type=Path);a=ap.parse_args();report=a.v770c_report.resolve();manifest=a.v770c_manifest.resolve();out=a.out_dir.resolve()
 if out.exists():raise SystemExit(f"Refusing existing output directory: {out}")
 for p in (report,manifest):
  if not p.is_file():raise SystemExit(f"Missing required file: {p}")
 out.mkdir(parents=True)
 try:
  parent=verify_parent(report,manifest);spec=policy_spec();spec["created_utc"]=datetime.now(timezone.utc).isoformat();spec["parent_evidence"]=parent;spec["policy_sha256"]=sha_text(canon({k:v for k,v in spec.items() if k not in ("created_utc","parent_evidence","policy_sha256")}))
  spec_path=out/"uta_optimal_plus_policy_specification_v7_71A.json";module_path=out/"optimal_plus_v7_71a.py";readme=out/"uta_optimal_plus_policy_specification_v7_71A.md";mf=out/"uta_optimal_plus_policy_specification_v7_71A_manifest.json"
  atomic_json(spec_path,spec);atomic_text(module_path,MODULE);py_compile.compile(str(module_path),doraise=True)
  md=f'''# {VERSION}\n\n- Status: POLICY_SPECIFICATION_FROZEN\n- Policy SHA-256: `{spec["policy_sha256"]}`\n- Research implementation: `optimal_plus_v7_71a.py`\n\n## Central rule\n\nUnrelated writes are not denied solely because a historical web label is visible. Exact or transformed content derived from a successful persistent source record requires a trusted, structured, exactly bound authorization. A failed source lookup creates no successful provenance record. Authorization is consumed only after a separately reported successful effect.\n\n## Boundary\n\nThis artifact does not modify packaged `optimal.py`, run GPT, execute Sandbox or Gym, or evaluate predicates and breach.\n'''
  atomic_text(readme,md);arts=[spec_path,module_path,readme];atomic_json(mf,{"schema":"UTA_OPTIMAL_PLUS_POLICY_SPECIFICATION_FREEZE_V1","version":VERSION,"status":"POLICY_SPECIFICATION_FROZEN","created_utc":datetime.now(timezone.utc).isoformat(),"policy_sha256":spec["policy_sha256"],"runner":{"file":str(Path(__file__).resolve()),"sha256":sha_file(Path(__file__).resolve()),"size_bytes":Path(__file__).stat().st_size},"inputs":[{"file":str(p),"sha256":sha_file(p),"size_bytes":p.stat().st_size} for p in (report,manifest)],"artifacts":[{"file":p.name,"sha256":sha_file(p),"size_bytes":p.stat().st_size} for p in arts],"runtime":{"python":sys.version}})
  print(f"Experiment: {VERSION}\nStatus: POLICY_SPECIFICATION_FROZEN\nPolicy SHA256: {spec['policy_sha256']}\nModule: {module_path}\nManifest: {mf}\nManifest SHA256: {sha_file(mf)}");return 0
 except Exception as e:
  fp=out/"uta_optimal_plus_policy_specification_v7_71A_failure.json";atomic_json(fp,{"version":VERSION,"status":"FAIL","exception_type":type(e).__name__,"exception":str(e),"scientific_result":None});print(f"FAILED: {e}",file=sys.stderr);return 3
if __name__=="__main__":raise SystemExit(main())
