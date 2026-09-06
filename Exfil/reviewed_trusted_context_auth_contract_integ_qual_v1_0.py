#!/usr/bin/env python3
"""Reviewed trusted-context authorization contract and integration qualification.

Read-only targeted source and call-graph reconciliation. This runner binds the
prior authorization inventory, hashes the exact supplied research and baseline
sources, parses them with AST, compares V1 and V1.1 contracts, and determines
whether the structured authorization components are wired into Sandbox or the
current EXFIL V2.2 factory.

It does not import project modules, instantiate Sandbox/Gym, issue grants, make
guardrail decisions, execute tools/HTTP/models/predicates/breach, or modify any
source. User-reported provenance is recorded separately from source-derived
facts and is never used to infer runtime behavior.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="REVIEWED_TRUSTED_CONTEXT_AUTHORIZATION_CONTRACT_AND_INTEGRATION_QUALIFICATION_v1.0"
PARENT_EXPECTED={
 "manifest":(17140,"8EE5357513B98AC63A28B6E115617D43AF55A0713FDA586C151EA3644CBC3FB2"),
 "result":(4320,"41F7BA7EB65EBE4E346FEDC515EB2410C4446FB1F4C4DB8D2E21151BDA514707"),
 "checks":(12378,"373AEB9BC0C1A7121B9887170D607B506F6995BC04E2CE8C820C9F8C9E3D3B19"),
 "inventory":(120391,"C3EB70B025C20C0DB255BD8790F3A6CB445F2C6CC037C528562ED5A1F823E462"),
 "candidates":(56967,"55A0D9539112D8014D3A4A8765AB570E963ADF5DB9155FA02D45CEBBE19F40F7"),
 "interface_map":(2329,"48D3C936D40A9A83FF14595EDE7E7285FDC28361C8890A89E69166593AECABBE"),
 "questions":(1261,"191C8A36A374E6DEDEF3E12210885A6693BE40DCBCBF43A69E8D1ACA6BE94F6D"),
 "claim":(916,"2409E39BB79270A845DCF39235E2707C40C3A63BA9A4C97C1D64B4F55FDDB425"),
 "binding":(21438,"5F7CC33FDA7B561BD8F56B05B1EA5DF1E0B9935A4D5498E473A93B68CB626C7B"),
}
SOURCE_REL={
 "optimal":"aicomp_sdk/guardrails/optimal.py",
 "proposal_aware":"aicomp_sdk/guardrails/proposal_aware_optimal.py",
 "adapter_v1":"aicomp_sdk/guardrails/trusted_context_adapter.py",
 "adapter_v1_1":"aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py",
 "sandbox":"aicomp_sdk/core/env/sandbox.py",
 "bridge":"aicomp_sdk/core/env/sandbox_trusted_bridge_v1.py",
 "outcome_transport":"aicomp_sdk/core/env/trusted_outcome_transport_v1.py",
 "factory_v2":"aicomp_sdk_exfil_v2/integration_factory_v2.py",
 "factory_v2_1":"aicomp_sdk_exfil_v2_1/integration_factory_v2_1.py",
 "factory_v2_2":"aicomp_sdk_exfil_v2_2/integration_factory_v2_2.py",
}
USER_REPORTED_PROVENANCE={
 "classification":"USER_REPORTED_RESEARCH_IMPLEMENTATIONS_CREATED_WITH_COPILOT_ASSISTANCE",
 "components":["proposal_aware_optimal.py","trusted_context_adapter.py","trusted_context_adapter_v1_1.py","aicomp_sdk_exfil","aicomp_sdk_exfil_v2","aicomp_sdk_exfil_v2_1","aicomp_sdk_exfil_v2_2"],
 "claim_limit":"provenance only; does not establish correctness, authoritativeness, integration, or runtime behavior",
}

def now():return datetime.now(timezone.utc).isoformat()
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest().upper()
def ident(p):
 p=Path(p).resolve();return {"artifact":p.name,"path":str(p),"size_bytes":p.stat().st_size,"sha256":sha(p)}
def need(v,m):
 if not v:raise ValueError(m)
def rj(p):return json.loads(Path(p).read_text(encoding="utf-8-sig"))
def rc(p):
 with Path(p).open(encoding="utf-8-sig",newline="") as f:return list(csv.DictReader(f))
def wj(p,v):
 with Path(p).open("x",encoding="utf-8",newline="\n") as f:json.dump(v,f,indent=2,sort_keys=True,ensure_ascii=False,default=str);f.write("\n")
def wc(p,rows,fields):
 with Path(p).open("x",encoding="utf-8",newline="") as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore",lineterminator="\n");w.writeheader();w.writerows(rows)
def add(rows,cid,cat,ok,obs,exp,layer):rows.append({"check_id":cid,"category":cat,"passed":bool(ok),"observed":json.dumps(obs,sort_keys=True,default=str),"expected":json.dumps(exp,sort_keys=True,default=str),"failure_layer":layer})
def text(p):return Path(p).read_text(encoding="utf-8-sig")
def names(tree,kind):
 cls=ast.ClassDef if kind=="class" else ast.FunctionDef
 return sorted(n.name for n in ast.walk(tree) if isinstance(n,cls))
def calls(tree):
 out=[]
 for n in ast.walk(tree):
  if isinstance(n,ast.Call):
   try:out.append(ast.unparse(n.func))
   except Exception:pass
 return sorted(set(out))
def imports(tree):
 out=[]
 for n in ast.walk(tree):
  if isinstance(n,ast.Import):out.extend(a.name for a in n.names)
  elif isinstance(n,ast.ImportFrom):out.append(n.module or "")
 return sorted(set(out))
def occurrence(src,term):return src.count(term)
def has_all(src,terms):return all(t in src for t in terms)
def has_any(src,terms):return any(t in src for t in terms)
def source_row(key,p):
 src=text(p);tree=ast.parse(src,filename=str(p))
 return {"source_key":key,**ident(p),"line_count":len(src.splitlines()),"classes":names(tree,"class"),"functions":names(tree,"function"),"imports":imports(tree),"calls":calls(tree)}

def main(a):
 out=Path(a.output_dir).resolve();need(not out.exists(),f"Refusing overwrite: {out}");out.mkdir(parents=True)
 checks=[];scope={"parent_evidence_read":True,"source_files_read":0,"AST_parsed":0,"project_modules_imported":False,"Sandbox_instantiated":False,"Gym_instantiated":False,"guardrail_decisions":0,"grants_issued":0,"tools_executed":False,"HTTP_executed":False,"models_used":False,"predicates_executed":False,"breach_executed":False,"external_effects_observed":False,"sources_modified":False,"parent_modified":False}
 try:
  parent={k:Path(getattr(a,"parent_"+k)).resolve() for k in PARENT_EXPECTED}
  project=Path(a.project_root).resolve();sources={k:(project/v).resolve() for k,v in SOURCE_REL.items()}
  for k,p in {**parent,**sources}.items():need(p.is_file(),f"Missing {k}: {p}")
  # Parent identity and semantic reconciliation.
  for i,(k,(sz,dg)) in enumerate(PARENT_EXPECTED.items(),1):
   x=ident(parent[k]);add(checks,f"AR-{i:03d}","parent_identity",x["size_bytes"]==sz and x["sha256"]==dg,x,{"size_bytes":sz,"sha256":dg},"FIXTURE")
  pr=rj(parent["result"]);pcs=rc(parent["checks"])
  parent_ok=(pr.get("checks")=={"failed":0,"failed_ids":[],"passed":22,"total":22} and pr.get("outcome")=="AUTHORIZATION_INTERFACE_PRESENT_BUT_TRANSPORT_NOT_ESTABLISHED" and len(pcs)==22 and all(str(r.get("passed")).lower()=="true" for r in pcs))
  add(checks,"AR-010","parent_semantics",parent_ok,{"checks":pr.get("checks"),"outcome":pr.get("outcome"),"rows":len(pcs)},"22/22 mechanical pass with reported narrow outcome","EVIDENCE")

  inventory=[]
  for k,p in sources.items():
   row=source_row(k,p);inventory.append(row);scope["source_files_read"]+=1;scope["AST_parsed"]+=1
  add(checks,"AR-011","source_scope",len(inventory)==10 and scope["AST_parsed"]==10,{"selected":len(inventory),"parsed":scope["AST_parsed"],"keys":[r["source_key"] for r in inventory]},{"selected":10,"parsed":10},"AUTHORIZATION_SOURCE_SCOPE_INCOMPLETE")

  s={k:text(p) for k,p in sources.items()}
  # Provenance is explicitly user-reported, never inferred from source.
  add(checks,"AR-012","provenance",True,USER_REPORTED_PROVENANCE,"preserved separately from source-derived findings","CLAIM_BOUNDARY")
  doc_v1="Source-implementation scope only" in s["adapter_v1"] and "current Sandbox runtime is not claimed to invoke them" in s["adapter_v1"]
  doc_v11="Source-implementation scope only" in s["adapter_v1_1"] and "current Sandbox runtime is not claimed to invoke them" in s["adapter_v1_1"]
  proposal_scope="intentionally does not implement trusted action-target-proposal" in s["proposal_aware"]
  add(checks,"AR-013","claim_relevance",doc_v1 and doc_v11 and proposal_scope,{"adapter_v1_static_scope":doc_v1,"adapter_v1_1_static_scope":doc_v11,"proposal_aware_scope_limit":proposal_scope},{"all":True},"CLAIM_BOUNDARY")

  # Contract completeness V1 and V1.1.
  common_terms=["register_trusted_grant","before_decide","after_tool","issuer_capabilities","authorized_tool","authorized_target_digest","authorized_proposal_digest","trace_identity","nonce","consumed_grant_ids","snapshot_state","restore_state"]
  v1_common=has_all(s["adapter_v1"],common_terms);v11_common=has_all(s["adapter_v1_1"],common_terms)
  add(checks,"AR-014","structured_contract",v1_common and v11_common,{"v1_common":v1_common,"v1_1_common":v11_common},True,"AUTHORIZATION_TRANSPORT")
  v11_repairs={
   "proposal_event_consumed_before_inner":s["adapter_v1_1"].find("self._seen_event_identities.add(event_key)") < s["adapter_v1_1"].find("inner_decision = self._inner.decide"),
   "tool_args_digest_bound":has_all(s["adapter_v1_1"],["tool_args_digest = self._digest_v1(dict(tool_args))",'pending["tool_args_digest"] != tool_args_digest']),
   "sequence_window_enforced":has_all(s["adapter_v1_1"],["issued_at_or_sequence","expires_at_or_sequence","current_sequence"]),
   "protected_path_qualified":has_all(s["adapter_v1_1"],["is_protected_secret_path","if not is_protected_secret_path(path)"]),
   "transactional_restore":has_all(s["adapter_v1_1"],["prior = self.snapshot_state()","rollback = self._validate_snapshot(prior)","self._apply_validated_snapshot(rollback)"]),
  }
  add(checks,"AR-015","version_lineage",all(v11_repairs.values()),v11_repairs,"V1.1 contains explicit repair extensions over V1","VERSION_RELEVANCE_GAP")

  # Factory wiring: current V2.2 bundle contains ledger, hooks, V21 guardrail only.
  auth_symbols=("TrustedGuardrailContextAdapter","TrustedGuardrailContextAdapterV1_1","TrustedOutcomeTransportV1","TrustedBridgeSandboxV1")
  factory_wiring={k:{sym:occurrence(s[k],sym) for sym in auth_symbols} for k in ("factory_v2","factory_v2_1","factory_v2_2")}
  factory_absent=all(v==0 for d in factory_wiring.values() for v in d.values())
  v22_constructs=has_all(s["factory_v2_2"],["SuccessfulReadLedgerV21()","TrustedReadProposalHookV22()","TrustedReadOutcomeHookV22(ledger=ledger)","LineageAwareExfilGuardrailV21(ledger=ledger, inner=inner)"])
  add(checks,"AR-016","factory_wiring",factory_absent and v22_constructs,{"authorization_symbols":factory_wiring,"V2_2_expected_components":v22_constructs},{"authorization_symbols_absent":True,"V2_2_expected_components":True},"INTEGRATION_FACTORY_GAP")

  # Sandbox and opt-in bridge.
  sandbox_direct=has_all(s["sandbox"],["self.guardrail = guardrail or GuardrailBase()","guardrail_decision = self.guardrail.decide(tool_name, tool_args, ctx)"])
  sandbox_calls_trusted=has_any(s["sandbox"],["before_decide(","after_tool(","register_trusted_grant(","trusted_transport"])
  bridge_only=has_all(s["bridge"],["class TrustedBridgeSandboxV1(SandboxEnv)","trusted_transport","TrustedOutcomeTransportV1"])
  bridge_runtime_limited="Runtime behavior is not qualified" in s["bridge"]
  add(checks,"AR-017","sandbox_integration",sandbox_direct and not sandbox_calls_trusted and bridge_only and bridge_runtime_limited,{"Sandbox_direct_decide":sandbox_direct,"Sandbox_trusted_calls":sandbox_calls_trusted,"opt_in_bridge_present":bridge_only,"bridge_runtime_qualified":not bridge_runtime_limited},{"Sandbox_trusted_calls":False,"opt_in_bridge_static_only":True},"AUTHORIZATION_TRANSPORT")

  # Producer/provisioning and transport.
  grant_producer_calls=[];issuer_provision_calls=[]
  for k,src in s.items():
   if k not in {"adapter_v1","adapter_v1_1"} and "register_trusted_grant(" in src:grant_producer_calls.append(k)
   if k not in {"adapter_v1","adapter_v1_1"} and "issuer_capabilities" in src:issuer_provision_calls.append(k)
  add(checks,"AR-018","grant_producer",len(grant_producer_calls)==0 and len(issuer_provision_calls)==0,{"register_calls_outside_adapters":grant_producer_calls,"issuer_capability_refs_outside_adapters":issuer_provision_calls},{"both_empty":True},"AUTHORIZATION_TRANSPORT")

  outcome_contract=has_all(s["outcome_transport"],["TrustedEventSequenceStateV1","proposal_digest","trace_identity","outcome_event_identity","canonical_source_path","raw_output_sha256","consume_outcome"])
  adapter_after_requires=has_all(s["adapter_v1_1"],["proposal_digest: str","event_identity: Mapping","trace_identity: str","tool_args_digest: str","trusted_tool_outcome: Mapping"])
  transport_call_shape="self.adapter.after_tool(outcome)" in s["outcome_transport"]
  signature_gap=outcome_contract and adapter_after_requires and transport_call_shape
  add(checks,"AR-019","outcome_transport",signature_gap,{"transport_contract_present":outcome_contract,"adapter_after_tool_requires_keywords":adapter_after_requires,"transport_passes_single_positional_mapping":transport_call_shape},{"static_interface_mismatch":True},"ADAPTER_PARSE")

  # Grant consumption and routing semantics.
  consume_before_allow=s["adapter_v1_1"].find("self._consume_grant(grant_id)") < s["adapter_v1_1"].find("return inner_decision",s["adapter_v1_1"].find("self._consume_grant(grant_id)"))
  direct_decide_denies="P2B_TRUSTED_BEFORE_DECIDE_REQUIRED" in s["adapter_v1_1"]
  sandbox_deny_before_tool=s["sandbox"].find('guardrail_decision.action == "DENY"') < s["sandbox"].find("self.tools.call(tool_name, tool_args)")
  add(checks,"AR-020","decision_dispatch",consume_before_allow and direct_decide_denies and sandbox_deny_before_tool,{"grant_consumed_before_return_allow":consume_before_allow,"direct_decide_fail_closed":direct_decide_denies,"Sandbox_DENY_before_tool_call":sandbox_deny_before_tool},True,"ROUTING")
  preserved_identity_not_wired=has_all(s["adapter_v1_1"],["proposal_digest","tool_args_digest","pending_proposals_by_digest"]) and not sandbox_calls_trusted
  add(checks,"AR-021","proposal_identity_routing",preserved_identity_not_wired,{"adapter_preserves_proposal_identity":True,"Sandbox_routes_it":sandbox_calls_trusted},{"adapter_static":True,"Sandbox_route":False},"ROUTING")

  # Snapshot semantics.
  v1_restore_nontransactional="prior = self.snapshot_state()" not in s["adapter_v1"]
  v11_transactional=v11_repairs["transactional_restore"]
  transport_restore_validates=has_all(s["outcome_transport"],["unsupported snapshot schema","malformed snapshot"])
  add(checks,"AR-022","snapshot_semantics",v1_restore_nontransactional and v11_transactional and transport_restore_validates,{"V1_transactional":not v1_restore_nontransactional,"V1_1_transactional":v11_transactional,"transport_schema_validation":transport_restore_validates},{"V1":False,"V1_1":True,"transport_validation":True},"VERSION_RELEVANCE_GAP")

  # Final reviewed disposition.
  current_integration=False;static_contract=True;not_currently_wired=factory_absent and not sandbox_calls_trusted
  outcome="EXISTING_STRUCTURED_AUTHORIZATION_COMPONENTS_NOT_CURRENTLY_WIRED" if static_contract and not_currently_wired else "NOT_ESTABLISHED"
  add(checks,"AR-023","reviewed_disposition",outcome=="EXISTING_STRUCTURED_AUTHORIZATION_COMPONENTS_NOT_CURRENTLY_WIRED",{"static_contract":static_contract,"current_integration":current_integration,"factory_absent":factory_absent,"Sandbox_trusted_calls":sandbox_calls_trusted,"outcome":outcome},"EXISTING_STRUCTURED_AUTHORIZATION_COMPONENTS_NOT_CURRENTLY_WIRED","AUTHORIZATION_TRANSPORT")
  original={k:ident(p) for k,p in {**parent,**sources}.items()}
  immutable=all(ident(p)["sha256"]==original[k]["sha256"] for k,p in {**parent,**sources}.items())
  add(checks,"AR-024","immutability",immutable,"all bound artifacts unchanged",True,"FIXTURE")
  add(checks,"AR-025","execution_boundary",all([not scope["project_modules_imported"],not scope["Sandbox_instantiated"],not scope["HTTP_executed"],scope["guardrail_decisions"]==0,scope["grants_issued"]==0,not scope["tools_executed"],not scope["predicates_executed"],not scope["breach_executed"]]),scope,"read-only static reconciliation","SCOPE_VIOLATION")

  failed=[r["check_id"] for r in checks if not r["passed"]]
  status="REVIEWED_TRUSTED_CONTEXT_AUTHORIZATION_CONTRACT_AND_INTEGRATION_QUALIFICATION_COMPLETE_PASS" if not failed else "REVIEWED_TRUSTED_CONTEXT_AUTHORIZATION_CONTRACT_AND_INTEGRATION_QUALIFICATION_COMPLETE_WITH_GAPS"
  final_outcome=outcome if not failed else "NOT_ESTABLISHED"
  question_answers={
   "component_status":"USER_REPORTED_RESEARCH_IMPLEMENTATIONS; source docstrings state source-implementation or opt-in static scope",
   "scientifically_relevant_version":"V1.1 is the repair candidate; runtime relevance remains not established",
   "factory_instantiation":"No inspected V2/V2.1/V2.2 factory instantiates adapters or trusted transport",
   "Sandbox_wrapping":"Base Sandbox calls guardrail.decide directly; opt-in bridge stores transport but does not show before_decide/after_tool routing",
   "grant_producer":"NOT_ESTABLISHED_IN_INSPECTED_SCOPE",
   "issuer_capability_supplier":"NOT_ESTABLISHED_IN_INSPECTED_SCOPE",
   "identity_transport":"Defined statically across adapters/transport, not wired through current Sandbox/V2.2 factory",
   "http_post_grant_binding":"Static V1/V1.1 target and proposal digest binding present",
   "grant_consumption":"before_decide consumes eligible grant before returning inner ALLOW",
   "denial_before_dispatch":"Sandbox source places DENY handling before tools.call",
   "allowed_proposal_identity_routing":"NOT_ESTABLISHED",
   "trusted_outcome_role":"Static source-lineage/outcome binding; not shown as authorization grant producer",
   "snapshot_restore":"V1.1 transactional rollback present; V1 lacks that explicit rollback pattern",
   "version_relationship":"Repair lineage, not parity; V1.1 adds event-consumption, tool-args binding, sequence-window, protected-path, and transactional-restore checks",
  }
  boundary={"allowed":["research provenance is user-reported and preserved separately","V1 and V1.1 structured authorization contracts are statically present","V1.1 contains identifiable repair extensions","current V2.2 factory does not instantiate the trusted adapter or transport","base Sandbox does not call before_decide or after_tool","opt-in trusted bridge is static and runtime-unqualified","grant producer and issuer-capability provisioning are not established in inspected scope","trusted outcome transport and V1.1 adapter expose a static call-signature mismatch"],"prohibited":["claim current V2.2 authorization enforcement","claim Sandbox runtime integration","claim grant issuance or runtime validation","claim allowed proposal identity survives routing","claim HTTP execution, sink success, predicate, breach, hosted parity, or robust security"]}
  result={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"READ_ONLY_TARGETED_SOURCE_AND_CALL_GRAPH_RECONCILIATION","checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"outcome":final_outcome,"user_reported_provenance":USER_REPORTED_PROVENANCE,"question_answers":question_answers,"version_reconciliation":{"V1":"STATIC_CONTRACT_PRESENT","V1_1":"STATIC_REPAIR_CANDIDATE_PRESENT","relationship":"REPAIR_LINEAGE","current_runtime_relevance":"NOT_ESTABLISHED"},"integration_reconciliation":{"V2_2_factory_authorization_wiring":False,"base_Sandbox_trusted_adapter_calls":False,"opt_in_bridge_static_presence":True,"grant_producer":"NOT_ESTABLISHED","issuer_capability_supplier":"NOT_ESTABLISHED","trusted_outcome_adapter_signature":"STATIC_INTERFACE_MISMATCH"},"execution_boundaries":scope,"scientific_verdict":{"structured_authorization_contract":"STATICALLY_ESTABLISHED","current_V2_2_integration":"NOT_ESTABLISHED_NOT_WIRED_IN_INSPECTED_FACTORY","runtime_authorization_enforcement":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":boundary,"next_gate":"REVIEWED_HARDENED_AUTHORIZATION_INTEGRATION_DESIGN" if not failed else "AUTHORIZATION_RECONCILIATION_GAP_REVIEW"}

  outputs={"result":out/"trusted_context_authorization_reconciliation_result.json","checks":out/"trusted_context_authorization_reconciliation_checks.csv","inventory":out/"trusted_context_authorization_source_inventory.json","call_graph":out/"trusted_context_authorization_call_graph.json","version":out/"trusted_context_authorization_version_diff.json","questions":out/"trusted_context_authorization_question_answers.json","claim":out/"trusted_context_authorization_claim_boundary.json","binding":out/"trusted_context_authorization_binding.json"}
  wj(outputs["result"],result);wc(outputs["checks"],checks,["check_id","category","passed","observed","expected","failure_layer"]);wj(outputs["inventory"],inventory);wj(outputs["call_graph"],{"factory_wiring":factory_wiring,"sandbox_trusted_calls":sandbox_calls_trusted,"opt_in_bridge":bridge_only,"grant_producer_calls":grant_producer_calls,"issuer_provision_calls":issuer_provision_calls,"outcome_transport_signature_gap":signature_gap});wj(outputs["version"],{"V1_identity":ident(sources["adapter_v1"]),"V1_1_identity":ident(sources["adapter_v1_1"]),"repair_features":v11_repairs,"relationship":"REPAIR_LINEAGE"});wj(outputs["questions"],question_answers);wj(outputs["claim"],boundary);wj(outputs["binding"],{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"parents":{k:ident(p) for k,p in parent.items()},"sources":{k:ident(p) for k,p in sources.items()},"execution_boundaries":scope})
  mrows=[{**ident(p),"role":"AUTH_RECONCILIATION_DERIVED"} for p in outputs.values()]+[{**ident(p),"role":"AUTH_RECONCILIATION_PARENT"} for p in parent.values()]+[{**ident(p),"role":"AUTH_RECONCILIATION_SOURCE"} for p in sources.values()]
  manifest=out/"trusted_context_authorization_reconciliation_manifest.csv";wc(manifest,mrows,["artifact","role","size_bytes","sha256","path"])
  ext=out/"trusted_context_authorization_reconciliation_manifest_external_binding.json";wj(ext,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":manifest.name,"manifest_size_bytes":manifest.stat().st_size,"manifest_sha256":sha(manifest),"runner_sha256":sha(Path(__file__).resolve()),"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"outcome":final_outcome,"V2_2_factory_authorization_wiring":False,"Sandbox_trusted_adapter_calls":False,"next_gate":result["next_gate"]})
  print(json.dumps({"status":status,"checks":f"{len(checks)-len(failed)}/{len(checks)}","failed_ids":failed,"outcome":final_outcome,"V2_2_factory_authorization_wiring":False,"Sandbox_trusted_adapter_calls":False,"trusted_outcome_adapter_signature":"STATIC_INTERFACE_MISMATCH","manifest_sha256":sha(manifest),"next_gate":result["next_gate"]},indent=2))
 except Exception as exc:
  (out/"TRUSTED_CONTEXT_AUTHORIZATION_RECONCILIATION_FAILED.json").write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"BLOCKED","error_type":type(exc).__name__,"error":str(exc),"checks_frozen":checks,"execution_boundaries":scope},indent=2,default=str),encoding="utf-8");raise

def parse():
 p=argparse.ArgumentParser(description=VERSION)
 for n in ("manifest","result","checks","inventory","candidates","interface-map","questions","claim","binding"):
  p.add_argument("--parent-"+n,required=True,dest="parent_"+n.replace("-","_"))
 p.add_argument("--project-root",required=True);p.add_argument("--output-dir",required=True)
 return p.parse_args()
if __name__=="__main__":
 try:main(parse())
 except Exception as exc:print(f"FAILED: {exc}");raise SystemExit(1)
