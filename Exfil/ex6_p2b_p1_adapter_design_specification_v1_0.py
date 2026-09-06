#!/usr/bin/env python3
"""EX6 P2B P1 TrustedGuardrailContextAdapter design specification.

Read-only with respect to all parent and SDK artifacts. Generates a normative
DESIGN specification only. It does not create/import the adapter, import the
SDK, execute Sandbox/Gym/tools/models/guardrails/predicates/breach logic, or
claim effectiveness, requirement satisfaction, or runtime compatibility.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P1_ADAPTER_DESIGN_SPECIFICATION_v1.0"
STATUS="P2B_P1_ADAPTER_DESIGN_SPECIFICATION_COMPLETE_PASS"
P0_VERSION="EX6_P2B_P0_TRUSTED_TRANSPORT_CONTRACT_REINSPECTION_v1.1"
EXPECTED_CANDIDATES={"AZ-002","AZ-004","AZ-006","AZ-007","PV-002","PV-003","PV-004"}
EXPECTED_GAPS={"AZ-001","AZ-003","AZ-005"}
ALL_IDS=sorted(EXPECTED_CANDIDATES|EXPECTED_GAPS)
ALLOWED=[
 "normative adapter design specification",
 "P0 identity and result binding",
 "candidate-interface design usage",
 "explicit design treatment for P0 SDK gaps",
 "implementation eligibility recommendation",
]
PROHIBITED=[
 "adapter implementation exists","adapter imports successfully","runtime adapter behavior",
 "deferred requirement satisfaction","guardrail effectiveness","security improvement",
 "policy superiority","real exfiltration prevention","Sandbox parity","Gym parity",
 "hosted parity","attack success reduction",
]

def now(): return datetime.now(timezone.utc).isoformat()
def req(c:bool,m:str):
 if not c: raise ValueError(m)
def sha(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''): h.update(b)
 return h.hexdigest().upper()
def ident(p:Path)->dict[str,Any]:
 return {"artifact":p.name,"path":str(p.resolve()),"size_bytes":p.stat().st_size,"sha256":sha(p)}
def loadj(p:Path): return json.loads(p.read_text(encoding='utf-8-sig'))
def dumpx(p:Path,x:Any):
 with p.open('x',encoding='utf-8',newline='\n') as f: json.dump(x,f,indent=2,sort_keys=True);f.write('\n')
def csvx(p:Path,rows:list[dict[str,Any]],fields:list[str]):
 with p.open('x',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(rows)

def verify_p0(manifest:Path,external:Path,result_path:Path,matrix_path:Path)->tuple[dict[str,Any],dict[str,Any]]:
 ext=loadj(external); result=loadj(result_path); matrix=loadj(matrix_path)
 req(ext.get('version')==P0_VERSION,'Unexpected P0 external-binding version')
 req(ext.get('status')=='P2B_P0_CONTRACT_REINSPECTION_COMPLETE_PASS','P0 status is not PASS')
 req(ext.get('manifest_filename')==manifest.name,'P0 manifest filename mismatch')
 req(ext.get('manifest_sha256')==sha(manifest),'P0 manifest SHA-256 mismatch')
 req(int(ext.get('manifest_size_bytes',-1))==manifest.stat().st_size,'P0 manifest size mismatch')
 req(ext.get('P2B_P1_adapter_design_ready') is True,'P0 did not authorize P1 design readiness')
 req(ext.get('adapter_created') is False,'P0 unexpectedly reports adapter creation')
 req(result.get('version')==P0_VERSION,'Unexpected P0 result version')
 req(result.get('P2B_P1_adapter_design_ready') is True,'P0 result design_ready is not true')
 req(result.get('adapter_implementation_created') is False,'P0 result reports adapter creation')
 summary=result.get('mapping_summary',{})
 req(set(summary.get('candidate_ids',[]))==EXPECTED_CANDIDATES,'P0 candidate IDs differ')
 req(set(summary.get('gap_ids',[]))==EXPECTED_GAPS,'P0 gap IDs differ')
 rows=matrix.get('rows',[]); by_id={r.get('requirement_id'):r for r in rows}
 req(set(by_id)==set(ALL_IDS),'P0 matrix requirement IDs differ')
 req(all(r.get('satisfied') is False and r.get('runtime_validated') is False for r in rows),
     'P0 matrix crosses static claim boundary')
 return result,matrix

def design_contract()->dict[str,Any]:
 return {
  "component":{"proposed_class":"TrustedGuardrailContextAdapter","implementation_status":"NOT_IMPLEMENTED",
   "recommended_source_file":"aicomp_sdk/guardrails/trusted_context_adapter.py",
   "source_identity":"NOT_AVAILABLE_DESIGN_ONLY","role":"TRUSTED_TRANSPORT_AND_LINEAGE_ADAPTER"},
  "composition":{"pattern":"WRAP_GUARDRAIL_WITH_TRUSTED_TRANSPORT_BOUNDARY",
   "inner_guardrail":"ProposalAwareOptimalGuardrail_or_policy_under_test",
   "packaged_and_P2A_sources_modified":False,
   "rationale":"Design isolates trusted transport state from frozen policy sources; runtime compatibility remains untested."},
  "before_decide":{
   "inputs":["tool_name","tool_args","untrusted_or_general_context","trusted_authorization_grant_records","qualifying_successful_protected_read_records"],
   "trusted_authorization_grant":{"required_fields":["grant_id","issuer_id","issuer_trust_domain","issued_at_or_sequence","expires_at_or_sequence","authorized_tool","authorized_target_digest","authorized_proposal_digest","nonce"],
    "source_rule":"Only a separately configured trusted issuer channel may create a grant.",
    "prohibited_sources":["model output","prompt text","generic context booleans","recent_sources labels","arbitrary hook metadata"],
    "identity_rule":"grant_id plus canonical record digest","provenance_rule":"issuer identity and trust-domain binding required",
    "lifetime_rule":"bounded validity plus single-consumption state; expired or consumed grants fail closed"},
   "protected_read_record":{"required_fields":["event_identity","trace_identity","tool_name","canonical_source_path","tool_success","raw_output_sha256","protected_value_sha256_or_bound_digest","completion_sequence"],
    "qualification_rule":"tool_name is fs.read, exact protected path classification is qualifying, tool_success is true, and record originates from trusted post-tool acknowledgement",
    "raw_value_rule":"raw value is not copied into publication artifacts; hashes do not independently establish lineage"},
   "proposal_binding":{"canonical_fields":["tool_name","canonical_tool_args","trace_identity","proposal_event_identity"],
    "digest_algorithm":"SHA-256 over a versioned canonical serialization to be frozen in P2 implementation",
    "grant_match_rule":"authorized tool, target digest, and proposal digest must all match before the grant is eligible",
    "decision_rule":"adapter enriches a new trusted-context namespace and delegates once to inner.decide; absence, ambiguity, expiry, replay, or mismatch fails closed"}},
  "after_tool":{"inputs":["proposal_digest","event_identity","trace_identity","tool_name","tool_args_digest","trusted_tool_outcome"],
   "trusted_tool_outcome":{"required_fields":["success","error_class_or_none","raw_output_sha256_or_none","completion_sequence"],
    "source_rule":"must originate from the trusted tool-execution boundary, never agent prose"},
   "read_acknowledgement_rule":"only successful qualifying fs.read creates a protected-read record",
   "consumption_rule":"a successful or attempted bound action consumes the eligible one-use grant according to the frozen P2 design policy; exact attempt-versus-success semantics require a dedicated design decision before implementation",
   "event_binding_rule":"acknowledgement must bind the same trace, proposal digest, and unique event identity",
   "rejection_rule":"duplicate, out-of-order, unknown, or mismatched acknowledgements fail closed and do not create lineage"},
  "state_management":{"state_fields":["schema_version","trusted_grants_by_id","consumed_grant_ids","protected_read_records","seen_event_identities","pending_proposals_by_digest","monotonic_sequence"],
   "snapshot_state":"returns a deterministic deep-copy-compatible representation with sorted keys and no mutable aliases",
   "restore_state":"validates schema and invariants before atomically replacing state; malformed state fails closed",
   "reset_state":"clears all grants, lineage records, pending proposals, seen events, and sequence state",
   "determinism_rule":"equal validated state serializations restore to equal future adapter decisions under equal inputs; runtime proof deferred"},
  "non_goals":["modify Sandbox in P1","modify packaged OptimalGuardrail","modify ProposalAwareOptimalGuardrail","execute policy comparison","claim runtime effectiveness"]}

def mapping_rows()->list[dict[str,Any]]:
 rows=[]
 decisions={
  "AZ-001":("DESIGN_DEFINED_FOR_SDK_GAP","trusted_authorization_grant source, identity, provenance, and lifetime schema"),
  "AZ-002":("DESIGN_USES_P0_CANDIDATE","tool_name/tool_args canonical proposal binding"),
  "AZ-003":("DESIGN_DEFINED_FOR_SDK_GAP","versioned canonical proposal digest using SHA-256"),
  "AZ-004":("DESIGN_USES_P0_CANDIDATE","trace and unique event identity binding"),
  "AZ-005":("DESIGN_DEFINED_FOR_SDK_GAP","bounded lifetime, nonce, consumption, and replay rejection"),
  "AZ-006":("DESIGN_USES_P0_CANDIDATE","before_decide trusted-context enrichment and single inner delegation"),
  "AZ-007":("DESIGN_USES_P0_CANDIDATE","snapshot, restore, and reset state contract"),
  "PV-002":("DESIGN_USES_P0_CANDIDATE","successful protected fs.read acknowledgement record"),
  "PV-003":("DESIGN_USES_P0_CANDIDATE","after_tool trusted outcome channel"),
  "PV-004":("DESIGN_USES_P0_CANDIDATE","read-record to http.post proposal derivation binding"),
 }
 for rid in ALL_IDS:
  status,evidence=decisions[rid]
  rows.append({"requirement_id":rid,"P0_classification":"SDK_GAP" if rid in EXPECTED_GAPS else "CANDIDATE_INTERFACE_EVIDENCE",
   "P1_design_status":status,"design_evidence":evidence,"implemented":False,"runtime_validated":False,
   "satisfied":False,"claim_boundary":"normative design only"})
 return rows

def main(a):
 out=Path(a.output_dir).resolve();req(not out.exists(),f'Refusing overwrite: {out}');out.mkdir(parents=True)
 try:
  paths={k:Path(getattr(a,k)).resolve() for k in ('p0_manifest','p0_external_binding','p0_result','p0_matrix')}
  for k,p in paths.items(): req(p.is_file(),f'Missing {k}: {p}')
  p0_result,p0_matrix=verify_p0(paths['p0_manifest'],paths['p0_external_binding'],paths['p0_result'],paths['p0_matrix'])
  contract=design_contract(); rows=mapping_rows()
  review={"version":VERSION,"created_at_utc":now(),"status":STATUS,
   "classification":"NORMATIVE_DESIGN_SPECIFICATION_ONLY","P0_bound_and_verified":True,
   "adapter_implementation_created":False,"design_contract":contract,
   "requirement_mapping_summary":{"total":len(rows),"candidate_based":7,"gap_designs":3,
    "implemented":0,"runtime_validated":0,"satisfied":0},
   "implementation_eligibility":"ELIGIBLE_FOR_P2_SOURCE_IMPLEMENTATION_AFTER_INDEPENDENT_REVIEW_OF_THIS_DESIGN",
   "unresolved_design_decisions":[
    "authoritative trusted issuer provisioning mechanism",
    "canonical serialization byte specification",
    "event identity uniqueness authority",
    "grant consumption on attempted versus successful tool execution",
    "whether Sandbox can expose trusted before_decide and after_tool channels without direct source modification",
    "protected-value derivation comparison without exposing raw protected values in evidence artifacts"],
   "claim_boundary":{"allowed":ALLOWED,"prohibited":PROHIBITED},
   "execution_boundaries":{"sdk_imported":False,"adapter_created":False,"guardrail_executed":False,"sandbox_executed":False,"gym_executed":False,"tools_executed":False,"predicates_executed":False,"breach_executed":False,"effects_observed":False},
   "next_gate":"EX6_P2B_P1A_INDEPENDENT_DESIGN_QUALIFICATION"}
  rp=out/'ex6_p2b_p1_result.json';dp=out/'ex6_p2b_p1_adapter_design_contract.json';mp=out/'ex6_p2b_p1_requirement_design_mapping.csv';cp=out/'ex6_p2b_p1_claim_boundary.json';bp=out/'ex6_p2b_p1_binding.json'
  dumpx(rp,review);dumpx(dp,contract);csvx(mp,rows,["requirement_id","P0_classification","P1_design_status","design_evidence","implemented","runtime_validated","satisfied","claim_boundary"]);dumpx(cp,review['claim_boundary'])
  dumpx(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"P0_inputs":{k:ident(v) for k,v in paths.items()},"source_artifacts_modified":False,"adapter_created":False})
  content=[rp,dp,mp,cp,bp];manrows=[]
  for p in content: manrows.append({**ident(p),"role":"P2B_P1_DERIVED"})
  for k,p in paths.items(): manrows.append({**ident(p),"role":"P2B_P1_BOUND_"+k.upper()})
  man=out/'ex6_p2b_p1_manifest.csv';csvx(man,manrows,["artifact","role","size_bytes","sha256","path"])
  ext=out/'ex6_p2b_p1_manifest_external_binding.json';dumpx(ext,{"version":VERSION,"created_at_utc":now(),"status":STATUS,"manifest_filename":man.name,"manifest_size_bytes":man.stat().st_size,"manifest_sha256":sha(man),"runner_sha256":sha(Path(__file__).resolve()),"adapter_created":False,"requirements_satisfied":False,"next_gate":review['next_gate']})
  print(json.dumps({"status":STATUS,"manifest_sha256":sha(man),"adapter_created":False,"implemented":0,"runtime_validated":0,"satisfied":0,"unresolved_design_decisions":len(review['unresolved_design_decisions']),"next_gate":review['next_gate']},indent=2))
 except Exception:
  (out/'P2B_P1_FAILED.txt').write_text('P2B P1 failed. No design-complete, implementation, compatibility, effectiveness, or superiority claim is allowed.\n',encoding='utf-8')
  raise

def args():
 p=argparse.ArgumentParser(description=VERSION)
 p.add_argument('--p0-manifest',required=True);p.add_argument('--p0-external-binding',required=True)
 p.add_argument('--p0-result',required=True);p.add_argument('--p0-matrix',required=True);p.add_argument('--output-dir',required=True)
 return p.parse_args()
if __name__=='__main__':
 try: main(args())
 except Exception as e: print(f'FAILED: {e}',file=sys.stderr);raise SystemExit(1)
