#!/usr/bin/env python3
"""EX6 P2B P1A independent design qualification.

Read-only, fail-closed qualification of the frozen P1 normative adapter design.
This runner independently recomputes design coverage, trust-boundary controls,
state-contract completeness, unresolved decisions, and claim boundaries.
It does not import the SDK, create/import adapter source, execute a guardrail,
Sandbox/Gym/tools/models/predicates/breach logic, or claim security efficacy.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P1A_INDEPENDENT_DESIGN_QUALIFICATION_v1.0"
PARENT_VERSION="EX6_P2B_P1_ADAPTER_DESIGN_SPECIFICATION_v1.0"
STATUS="P2B_P1A_INDEPENDENT_DESIGN_QUALIFICATION_COMPLETE_PASS"
REQ_IDS={f"AZ-{i:03d}" for i in range(1,8)}|{f"PV-{i:03d}" for i in range(2,5)}
P0_GAPS={"AZ-001","AZ-003","AZ-005"}
P0_CANDIDATES=REQ_IDS-P0_GAPS
REQUIRED_UNRESOLVED={
 "authoritative trusted issuer provisioning mechanism",
 "canonical serialization byte specification",
 "event identity uniqueness authority",
 "grant consumption on attempted versus successful tool execution",
 "whether Sandbox can expose trusted before_decide and after_tool channels without direct source modification",
 "protected-value derivation comparison without exposing raw protected values in evidence artifacts",
}
REQUIRED_PROHIBITED={
 "adapter implementation exists","adapter imports successfully","runtime adapter behavior",
 "deferred requirement satisfaction","guardrail effectiveness","security improvement",
 "policy superiority","real exfiltration prevention","Sandbox parity","Gym parity",
 "hosted parity","attack success reduction",
}

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
def loadcsv(p:Path)->list[dict[str,str]]:
 with p.open('r',encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def dumpx(p:Path,x:Any):
 with p.open('x',encoding='utf-8',newline='\n') as f:json.dump(x,f,indent=2,sort_keys=True);f.write('\n')
def csvx(p:Path,rows:list[dict[str,Any]],fields:list[str]):
 with p.open('x',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(rows)

def verify_parent(paths:dict[str,Path])->tuple[dict[str,Any],dict[str,Any],list[dict[str,str]]]:
 ext=loadj(paths['p1_external_binding']); result=loadj(paths['p1_result']); design=loadj(paths['p1_design_contract']); mapping=loadcsv(paths['p1_mapping'])
 req(ext.get('version')==PARENT_VERSION,'Unexpected P1 external-binding version')
 req(ext.get('status')=='P2B_P1_ADAPTER_DESIGN_SPECIFICATION_COMPLETE_PASS','P1 status is not PASS')
 req(ext.get('manifest_filename')==paths['p1_manifest'].name,'P1 manifest filename mismatch')
 req(ext.get('manifest_sha256')==sha(paths['p1_manifest']),'P1 manifest SHA-256 mismatch')
 req(int(ext.get('manifest_size_bytes',-1))==paths['p1_manifest'].stat().st_size,'P1 manifest size mismatch')
 req(ext.get('adapter_created') is False,'P1 says adapter was created')
 req(ext.get('requirements_satisfied') is False,'P1 says requirements were satisfied')
 req(result.get('version')==PARENT_VERSION,'Unexpected P1 result version')
 req(result.get('classification')=='NORMATIVE_DESIGN_SPECIFICATION_ONLY','Unexpected P1 classification')
 req(result.get('adapter_implementation_created') is False,'P1 result says adapter created')
 req(result.get('P0_bound_and_verified') is True,'P1 did not verify P0')
 req(result.get('design_contract')==design,'Standalone design differs from result-embedded design')
 return result,design,mapping

def qualify_mapping(rows:list[dict[str,str]])->tuple[list[dict[str,Any]],dict[str,Any]]:
 req(len(rows)==10,f'Expected 10 mapping rows, found {len(rows)}')
 by={r.get('requirement_id'):r for r in rows};req(set(by)==REQ_IDS,'Requirement ID set differs')
 out=[]
 for rid in sorted(REQ_IDS):
  r=by[rid]; gap=rid in P0_GAPS
  expected_p0='SDK_GAP' if gap else 'CANDIDATE_INTERFACE_EVIDENCE'
  expected_p1='DESIGN_DEFINED_FOR_SDK_GAP' if gap else 'DESIGN_USES_P0_CANDIDATE'
  checks={
   'P0_classification_match':r.get('P0_classification')==expected_p0,
   'P1_design_status_match':r.get('P1_design_status')==expected_p1,
   'design_evidence_present':bool((r.get('design_evidence') or '').strip()),
   'implemented_false':str(r.get('implemented')).lower()=='false',
   'runtime_validated_false':str(r.get('runtime_validated')).lower()=='false',
   'satisfied_false':str(r.get('satisfied')).lower()=='false',
   'claim_boundary_exact':r.get('claim_boundary')=='normative design only',
  }
  out.append({'requirement_id':rid,**checks,'qualification_pass':all(checks.values())})
 req(all(r['qualification_pass'] for r in out),'One or more requirement design rows failed qualification')
 return out,{'total':10,'qualified':10,'gap_designs':3,'candidate_based':7,'implemented':0,'runtime_validated':0,'satisfied':0}

def qualify_design(d:dict[str,Any],result:dict[str,Any])->tuple[list[dict[str,Any]],dict[str,Any]]:
 checks=[]
 def add(cid,desc,ok,evidence):checks.append({'check_id':cid,'description':desc,'passed':bool(ok),'evidence':evidence})
 comp=d.get('component',{}); add('D-001','Proposed component remains unimplemented',comp.get('proposed_class')=='TrustedGuardrailContextAdapter' and comp.get('implementation_status')=='NOT_IMPLEMENTED' and comp.get('source_identity')=='NOT_AVAILABLE_DESIGN_ONLY',str(comp))
 composition=d.get('composition',{}); add('D-002','Frozen policy sources remain unmodified by design',composition.get('packaged_and_P2A_sources_modified') is False, str(composition))
 bd=d.get('before_decide',{}); grant=bd.get('trusted_authorization_grant',{}); read=bd.get('protected_read_record',{}); prop=bd.get('proposal_binding',{})
 grant_fields={'grant_id','issuer_id','issuer_trust_domain','issued_at_or_sequence','expires_at_or_sequence','authorized_tool','authorized_target_digest','authorized_proposal_digest','nonce'}
 add('D-003','Grant schema covers identity provenance scope lifetime and nonce',set(grant.get('required_fields',[]))==grant_fields,str(grant.get('required_fields')))
 prohibited={'model output','prompt text','generic context booleans','recent_sources labels','arbitrary hook metadata'}
 add('D-004','Untrusted authorization sources explicitly prohibited',set(grant.get('prohibited_sources',[]))==prohibited,str(grant.get('prohibited_sources')))
 read_fields={'event_identity','trace_identity','tool_name','canonical_source_path','tool_success','raw_output_sha256','protected_value_sha256_or_bound_digest','completion_sequence'}
 add('D-005','Protected-read record binds success source trace event and output identity',set(read.get('required_fields',[]))==read_fields,str(read.get('required_fields')))
 add('D-006','Protected-read rule requires trusted successful fs.read acknowledgement','fs.read' in read.get('qualification_rule','') and 'tool_success is true' in read.get('qualification_rule','') and 'trusted post-tool acknowledgement' in read.get('qualification_rule',''),read.get('qualification_rule'))
 prop_fields={'tool_name','canonical_tool_args','trace_identity','proposal_event_identity'}
 add('D-007','Proposal binding covers tool args trace and event',set(prop.get('canonical_fields',[]))==prop_fields,str(prop.get('canonical_fields')))
 add('D-008','Proposal binding is versioned SHA-256 design','SHA-256' in prop.get('digest_algorithm','') and 'versioned canonical serialization' in prop.get('digest_algorithm',''),prop.get('digest_algorithm'))
 aft=d.get('after_tool',{}); outcome=aft.get('trusted_tool_outcome',{})
 add('D-009','After-tool contract binds outcome proposal trace and event',{'proposal_digest','event_identity','trace_identity','trusted_tool_outcome'}.issubset(set(aft.get('inputs',[]))),str(aft.get('inputs')))
 add('D-010','Tool outcome source excludes agent prose','trusted tool-execution boundary' in outcome.get('source_rule','') and 'never agent prose' in outcome.get('source_rule',''),outcome.get('source_rule'))
 add('D-011','Duplicate and mismatched acknowledgements fail closed','fail closed' in aft.get('rejection_rule',''),aft.get('rejection_rule'))
 state=d.get('state_management',{}); state_fields={'schema_version','trusted_grants_by_id','consumed_grant_ids','protected_read_records','seen_event_identities','pending_proposals_by_digest','monotonic_sequence'}
 add('D-012','State schema covers grants consumption reads events proposals and sequence',set(state.get('state_fields',[]))==state_fields,str(state.get('state_fields')))
 add('D-013','Snapshot restore reset contracts are present',all(bool(state.get(k)) for k in ('snapshot_state','restore_state','reset_state')),str({k:state.get(k) for k in ('snapshot_state','restore_state','reset_state')}))
 add('D-014','Restore is fail closed before atomic replacement','fails closed' in state.get('restore_state','') and 'atomically' in state.get('restore_state',''),state.get('restore_state'))
 unresolved=set(result.get('unresolved_design_decisions',[]));add('D-015','All six unresolved design decisions preserved',unresolved==REQUIRED_UNRESOLVED,str(sorted(unresolved)))
 prohibited_claims=set(result.get('claim_boundary',{}).get('prohibited',[]));add('D-016','Prohibited claim boundary complete',REQUIRED_PROHIBITED.issubset(prohibited_claims),str(sorted(prohibited_claims)))
 ex=result.get('execution_boundaries',{});add('D-017','No execution or implementation layers crossed',all(ex.get(k) is False for k in ('adapter_created','sdk_imported','guardrail_executed','sandbox_executed','gym_executed','tools_executed','predicates_executed','breach_executed','effects_observed')),str(ex))
 req(all(c['passed'] for c in checks),'Independent design qualification checks failed')
 return checks,{'checks_total':len(checks),'checks_passed':sum(c['passed'] for c in checks),'unresolved_decisions':len(unresolved)}

def main(a):
 out=Path(a.output_dir).resolve();req(not out.exists(),f'Refusing overwrite: {out}');out.mkdir(parents=True)
 try:
  paths={k:Path(getattr(a,k)).resolve() for k in ('p1_manifest','p1_external_binding','p1_result','p1_design_contract','p1_mapping','p1_claim_boundary')}
  for k,p in paths.items():req(p.is_file(),f'Missing {k}: {p}')
  result,design,mapping=verify_parent(paths)
  independent_rows,map_summary=qualify_mapping(mapping)
  design_checks,design_summary=qualify_design(design,result)
  standalone_boundary=loadj(paths['p1_claim_boundary']);req(standalone_boundary==result.get('claim_boundary'),'Standalone claim boundary differs from result')
  qualification={
   'version':VERSION,'created_at_utc':now(),'status':STATUS,
   'classification':'READ_ONLY_INDEPENDENT_NORMATIVE_DESIGN_QUALIFICATION',
   'P1_parent_verified':True,'P1_source_artifacts_modified':False,
   'mapping_recomputation':map_summary,'design_recomputation':design_summary,
   'independent_verdict':{
    'normative_design_completeness':'QUALIFIED_WITH_UNRESOLVED_DECISIONS_PRESERVED',
    'trust_boundary_completeness':'QUALIFIED_AT_DESIGN_LEVEL',
    'fail_closed_design_semantics':'QUALIFIED_AT_DESIGN_LEVEL',
    'state_contract_completeness':'QUALIFIED_AT_DESIGN_LEVEL',
    'implementation_readiness':'READY_FOR_P2_IMPLEMENTATION_SPECIFIC_DECISIONS_AND_SOURCE_CREATION',
    'adapter_implementation':'NOT_CREATED','runtime_compatibility':'NOT_EVALUATED',
    'requirement_satisfaction':'NOT_ESTABLISHED','guardrail_effectiveness':'NOT_EVALUATED',
    'policy_superiority':'NOT_EVALUATED','real_exfiltration_prevention':'NOT_ESTABLISHED',
    'harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'},
   'unresolved_design_decisions':sorted(REQUIRED_UNRESOLVED),
   'claim_boundary':{'allowed':['independent normative design qualification','P1 identity verification','design completeness findings','implementation-readiness recommendation'],
    'prohibited':sorted(REQUIRED_PROHIBITED)},
   'execution_boundaries':{'adapter_created':False,'sdk_imported':False,'guardrail_executed':False,'sandbox_executed':False,'gym_executed':False,'tools_executed':False,'predicates_executed':False,'breach_executed':False,'effects_observed':False},
   'next_gate':'EX6_P2B_P2_ADAPTER_IMPLEMENTATION_PREFLIGHT'}
  rp=out/'ex6_p2b_p1a_result.json';dr=out/'ex6_p2b_p1a_design_checks.csv';mr=out/'ex6_p2b_p1a_requirement_qualification.csv';cp=out/'ex6_p2b_p1a_claim_boundary.json';bp=out/'ex6_p2b_p1a_binding.json'
  dumpx(rp,qualification);csvx(dr,design_checks,['check_id','description','passed','evidence']);csvx(mr,independent_rows,['requirement_id','P0_classification_match','P1_design_status_match','design_evidence_present','implemented_false','runtime_validated_false','satisfied_false','claim_boundary_exact','qualification_pass']);dumpx(cp,qualification['claim_boundary'])
  dumpx(bp,{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'P1_inputs':{k:ident(v) for k,v in paths.items()},'source_artifacts_modified':False,'adapter_created':False})
  content=[rp,dr,mr,cp,bp];rows=[]
  for p in content:rows.append({**ident(p),'role':'P2B_P1A_DERIVED'})
  for k,p in paths.items():rows.append({**ident(p),'role':'P2B_P1A_BOUND_'+k.upper()})
  man=out/'ex6_p2b_p1a_manifest.csv';csvx(man,rows,['artifact','role','size_bytes','sha256','path'])
  ext=out/'ex6_p2b_p1a_manifest_external_binding.json';dumpx(ext,{'version':VERSION,'created_at_utc':now(),'status':STATUS,'manifest_filename':man.name,'manifest_size_bytes':man.stat().st_size,'manifest_sha256':sha(man),'runner_sha256':sha(Path(__file__).resolve()),'adapter_created':False,'requirements_satisfied':False,'next_gate':qualification['next_gate']})
  print(json.dumps({'status':STATUS,'manifest_sha256':sha(man),'design_checks':design_summary,'requirement_rows':map_summary,'adapter_created':False,'requirements_satisfied':False,'next_gate':qualification['next_gate']},indent=2))
 except Exception:
  (out/'P2B_P1A_FAILED.txt').write_text('P2B P1A failed. No design-qualified, implementation-ready, compatibility, effectiveness, or superiority claim is allowed.\n',encoding='utf-8')
  raise

def args():
 p=argparse.ArgumentParser(description=VERSION)
 p.add_argument('--p1-manifest',required=True);p.add_argument('--p1-external-binding',required=True);p.add_argument('--p1-result',required=True);p.add_argument('--p1-design-contract',required=True);p.add_argument('--p1-mapping',required=True);p.add_argument('--p1-claim-boundary',required=True);p.add_argument('--output-dir',required=True)
 return p.parse_args()
if __name__=='__main__':
 try:main(args())
 except Exception as e:print(f'FAILED: {e}',file=sys.stderr);raise SystemExit(1)
