#!/usr/bin/env python3
"""EX6 P2B P2B independent adapter source qualification.

Read-only, fail-closed static qualification. Recomputes source identity, parent
bindings, AST structure, frozen-decision coverage, fail-closed paths, state
contracts, and known transport invariants. It does not import or instantiate the
adapter and does not execute SDK, Sandbox, Gym, tools, predicates, or breach.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2B_INDEPENDENT_ADAPTER_SOURCE_QUALIFICATION_v1.0"
PARENT_VERSION="EX6_P2B_P2A_ADAPTER_SOURCE_IMPLEMENTATION_v1.0"
EXPECTED_PARENT_MANIFEST="DD7067F2B5841A8715329F73F4B6E60A2DCED2AD2BDE25F0F5DA9BD49C8303E6"
EXPECTED_SOURCE_SHA="AAA1F40B9717D31A475550FC0F6E26A498942AE63B0AE645DFACB2950CEE405F"
EXPECTED_OPTIMAL_SHA="6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED"
EXPECTED_PROPOSAL_SHA="918FFD61CDB9A406C965F06CF2BEC34C297AB231E26B6FC083AE34B00C37D452"
REQ_IDS=[f"AZ-{i:03d}" for i in range(1,8)]+[f"PV-{i:03d}" for i in range(2,5)]
PUBLIC={"__init__","register_trusted_grant","before_decide","decide","after_tool","snapshot_state","restore_state","reset_state"}
PRIVATE={"_canonicalize_v1","_digest_v1","_validate_grant","_validate_event_identity","_qualify_protected_read","_consume_grant","_validate_snapshot"}
PROHIBITED_IMPORT_ROOTS={"subprocess","socket","requests","urllib","httpx","aiohttp"}
PROHIBITED_CALLS={"eval","exec","compile","open","__import__"}

def now():return datetime.now(timezone.utc).isoformat()
def req(c:bool,m:str):
 if not c:raise ValueError(m)
def sha(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def ident(p:Path)->dict[str,Any]:return {"artifact":p.name,"path":str(p.resolve()),"size_bytes":p.stat().st_size,"sha256":sha(p)}
def loadj(p:Path):return json.loads(p.read_text(encoding='utf-8-sig'))
def dumpx(p:Path,x:Any):
 with p.open('x',encoding='utf-8',newline='\n') as f:json.dump(x,f,indent=2,sort_keys=True);f.write('\n')
def csvx(p:Path,rows:list[dict[str,Any]],fields:list[str]):
 with p.open('x',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(rows)

def verify_parent(p:dict[str,Path])->dict[str,Any]:
 ext=loadj(p['p2a_external_binding']);res=loadj(p['p2a_result']);sid=loadj(p['p2a_source_identity'])
 req(ext.get('version')==PARENT_VERSION,'Unexpected P2A binding version')
 req(ext.get('status')=='P2B_P2A_ADAPTER_SOURCE_IMPLEMENTATION_COMPLETE_PASS','P2A status is not PASS')
 req(ext.get('manifest_filename')==p['p2a_manifest'].name,'P2A manifest filename mismatch')
 req(ext.get('manifest_sha256')==sha(p['p2a_manifest'])==EXPECTED_PARENT_MANIFEST,'P2A manifest SHA mismatch')
 req(int(ext.get('manifest_size_bytes',-1))==p['p2a_manifest'].stat().st_size,'P2A manifest size mismatch')
 req(ext.get('adapter_source_sha256')==EXPECTED_SOURCE_SHA,'P2A adapter identity differs')
 req(ext.get('runtime_validated') is False and ext.get('requirements_satisfied') is False,'P2A crossed runtime boundary')
 req(res.get('source_created') is True and res.get('parent_preflight_verified') is True,'P2A source or parent state invalid')
 req(res.get('adapter_identity',{}).get('sha256')==EXPECTED_SOURCE_SHA,'P2A result source SHA differs')
 req(sid.get('source',{}).get('sha256')==EXPECTED_SOURCE_SHA,'P2A source identity differs')
 return res

def source_model(path:Path)->tuple[str,ast.Module,ast.ClassDef,dict[str,ast.FunctionDef]]:
 text=path.read_text(encoding='utf-8');tree=ast.parse(text,filename=str(path));compile(text,str(path),'exec')
 classes={n.name:n for n in tree.body if isinstance(n,ast.ClassDef)}
 req('TrustedGuardrailContextAdapter' in classes,'Adapter class absent')
 cls=classes['TrustedGuardrailContextAdapter'];methods={n.name:n for n in cls.body if isinstance(n,ast.FunctionDef)}
 return text,tree,cls,methods

def calls_in(node:ast.AST)->set[str]:
 out=set()
 for n in ast.walk(node):
  if isinstance(n,ast.Call):
   if isinstance(n.func,ast.Name):out.add(n.func.id)
   elif isinstance(n.func,ast.Attribute):out.add(n.func.attr)
 return out

def names_and_strings(node:ast.AST)->set[str]:
 out=set()
 for n in ast.walk(node):
  if isinstance(n,ast.Name):out.add(n.id)
  elif isinstance(n,ast.Attribute):out.add(n.attr)
  elif isinstance(n,ast.Constant) and isinstance(n.value,str):out.add(n.value)
 return out

def add(rows,cid,area,desc,passed,evidence,severity='BLOCKING'):
 rows.append({'check_id':cid,'area':area,'description':desc,'passed':bool(passed),'severity':severity,'evidence':evidence})

def qualify_source(text:str,tree:ast.Module,cls:ast.ClassDef,methods:dict[str,ast.FunctionDef])->list[dict[str,Any]]:
 r=[]
 add(r,'S-001','IDENTITY','Required class inherits GuardrailBase',any(isinstance(b,ast.Name) and b.id=='GuardrailBase' for b in cls.bases),ast.unparse(cls.bases[0]) if cls.bases else '')
 add(r,'S-002','INTERFACE','All planned public methods present',PUBLIC.issubset(methods),str(sorted(PUBLIC-set(methods))))
 add(r,'S-003','INTERFACE','All planned private helpers present',PRIVATE.issubset(methods),str(sorted(PRIVATE-set(methods))))
 imported=set()
 for n in tree.body:
  if isinstance(n,ast.Import):imported|={a.name.split('.')[0] for a in n.names}
  elif isinstance(n,ast.ImportFrom) and n.module:imported.add(n.module.split('.')[0])
 add(r,'S-004','IMPORTS','No prohibited network/process import roots',not(imported&PROHIBITED_IMPORT_ROOTS),str(sorted(imported&PROHIBITED_IMPORT_ROOTS)))
 calls=set()
 for n in ast.walk(tree):
  if isinstance(n,ast.Call) and isinstance(n.func,ast.Name):calls.add(n.func.id)
 add(r,'S-005','EXECUTION','No prohibited dynamic/file execution calls',not(calls&PROHIBITED_CALLS),str(sorted(calls&PROHIBITED_CALLS)))
 decide=methods['decide'];tokens=names_and_strings(decide)
 add(r,'S-006','FAIL_CLOSED','Direct decide denies and requires trusted before_decide','P2B_TRUSTED_BEFORE_DECIDE_REQUIRED' in tokens and 'deny' in calls_in(decide),str(sorted(tokens&{'P2B_TRUSTED_BEFORE_DECIDE_REQUIRED','deny'})))
 grant=methods['_validate_grant'];gt=names_and_strings(grant)
 add(r,'S-007','ISSUER','Grant validation binds issuer identity/trust domain and constant-time capability',{'issuer_id','issuer_trust_domain','compare_digest'}.issubset(gt),str(sorted({'issuer_id','issuer_trust_domain','compare_digest'}&gt)))
 canon=methods['_canonicalize_v1'];norm=methods.get('_normalize_json_value');ct=names_and_strings(canon)|(names_and_strings(norm) if norm else set())
 add(r,'S-008','CANONICALIZATION','Canonicalization specifies NFC, sorted keys, compact separators, UTF-8 and rejects floats',{'NFC','sort_keys','utf-8','floating point prohibited'}.issubset(ct),str(sorted({'NFC','sort_keys','utf-8','floating point prohibited'}&ct)))
 event=methods['_validate_event_identity'];et=names_and_strings(event)
 add(r,'S-009','EVENT_IDENTITY','Event validation binds trace sequence kind and monotonic rejection',{'trace_identity','event_sequence','event_kind','P2B_REPLAY_OR_EVENT_IDENTITY_REJECTED'}.issubset(et),str(sorted({'trace_identity','event_sequence','event_kind','P2B_REPLAY_OR_EVENT_IDENTITY_REJECTED'}&et)))
 consume=methods['_consume_grant'];before=methods['before_decide']
 add(r,'S-010','ONE_USE','Grant consumed on authorization release before return', '_consume_grant' in calls_in(before) and 'consumed_grant_ids' in names_and_strings(consume),str(sorted(calls_in(before)&{'_consume_grant'})))
 snap=methods['snapshot_state'];restore=methods['restore_state'];reset=methods['reset_state']
 state_required={'trusted_grants_by_id','consumed_grant_ids','protected_read_records','seen_event_identities','pending_proposals_by_digest','monotonic_sequence_by_trace','inner_guardrail_state'}
 add(r,'S-011','STATE','Snapshot includes all frozen state domains',state_required.issubset(names_and_strings(snap)),str(sorted(state_required-names_and_strings(snap))))
 add(r,'S-012','STATE','Restore validates before replacing adapter state','_validate_snapshot' in calls_in(restore),str(sorted(calls_in(restore)&{'_validate_snapshot'})))
 add(r,'S-013','STATE','Reset clears all adapter-owned mutable domains',state_required-{'inner_guardrail_state'} <= names_and_strings(reset),str(sorted((state_required-{'inner_guardrail_state'})-names_and_strings(reset))))
 after=methods['after_tool'];at=names_and_strings(after)
 add(r,'S-014','AFTER_TOOL','After-tool binds proposal, trace, event, tool and tool-args digest fields',{'proposal_digest','trace_identity','event_identity','tool_name','tool_args_digest'}.issubset(at),str(sorted({'proposal_digest','trace_identity','event_identity','tool_name','tool_args_digest'}&at)))
 # Independent blocking semantic checks intentionally go beyond symbol presence.
 add(r,'Q-001','GRANT_LIFETIME','Grant lifetime is enforced at authorization decision, not only schema-validated',('issued_at_or_sequence' in names_and_strings(before) or 'expires_at_or_sequence' in names_and_strings(before)), 'before_decide does not reference issued_at_or_sequence or expires_at_or_sequence')
 add(r,'Q-002','PROPOSAL_REPLAY','Proposal event identity is committed or rejected before a second identical proposal can be accepted',('seen_event_identities' in names_and_strings(before) or 'monotonic_sequence_by_trace' in names_and_strings(before)), 'before_decide validates but does not commit proposal event identity')
 add(r,'Q-003','OUTCOME_BINDING','after_tool verifies pending tool_name equals acknowledged tool_name', 'tool_name' in names_and_strings(after) and any(isinstance(n,ast.Compare) and 'pending' in ast.unparse(n) and 'tool_name' in ast.unparse(n) for n in ast.walk(after)), 'no pending[tool_name] comparison found')
 add(r,'Q-004','ARGUMENT_BINDING','after_tool verifies tool_args_digest against the pending proposal', any(isinstance(n,ast.Compare) and 'tool_args_digest' in ast.unparse(n) for n in ast.walk(after)), 'tool_args_digest is type-checked but no equality comparison found')
 add(r,'Q-005','READ_QUALIFICATION','Protected read is independently classified as protected rather than accepted from supplied path/digests', any(x in calls_in(methods['_qualify_protected_read']) for x in {'is_protected_secret_path','is_protected_path'}), 'no protected-path classifier call found')
 add(r,'Q-006','RESTORE_ATOMICITY','Inner and adapter state restore is atomic or rolls back on adapter assignment failure', any(isinstance(n,ast.Try) for n in ast.walk(restore)), 'restore_state has no rollback/transaction try block')
 return r

def requirement_rows(checks:list[dict[str,Any]])->list[dict[str,Any]]:
 by={x['check_id']:x for x in checks}
 mapping={
 'AZ-001':['S-007'],'AZ-002':['S-014','Q-003','Q-004'],'AZ-003':['S-008'],'AZ-004':['S-009','Q-002'],
 'AZ-005':['S-010','Q-001'],'AZ-006':['S-006'],'AZ-007':['S-011','S-012','S-013','Q-006'],
 'PV-002':['S-014','Q-005'],'PV-003':['S-014','Q-003','Q-004'],'PV-004':['S-008','Q-004','Q-005']}
 rows=[]
 for rid in REQ_IDS:
  ids=mapping[rid];passed=all(by[x]['passed'] for x in ids)
  rows.append({'requirement_id':rid,'static_checks':';'.join(ids),'qualification_status':'STATICALLY_QUALIFIED' if passed else 'SOURCE_REPAIR_REQUIRED','implemented_identity':True,'runtime_validated':False,'satisfied':False,'claim_boundary':'independent static qualification only'})
 return rows

def main(a):
 out=Path(a.output_dir).resolve();req(not out.exists(),f'Refusing overwrite: {out}');out.mkdir(parents=True)
 try:
  keys=('p2a_manifest','p2a_external_binding','p2a_result','p2a_binding','p2a_source_identity','adapter_source','optimal','proposal_aware','frozen_decisions','implementation_plan')
  p={k:Path(getattr(a,k)).resolve() for k in keys}
  for k,x in p.items():req(x.is_file(),f'Missing {k}: {x}')
  verify_parent(p)
  req(sha(p['adapter_source'])==EXPECTED_SOURCE_SHA,'Adapter source SHA mismatch')
  req(sha(p['optimal'])==EXPECTED_OPTIMAL_SHA,'Frozen optimal.py mismatch')
  req(sha(p['proposal_aware'])==EXPECTED_PROPOSAL_SHA,'Frozen proposal-aware source mismatch')
  text,tree,cls,methods=source_model(p['adapter_source']);checks=qualify_source(text,tree,cls,methods);rrows=requirement_rows(checks)
  blocking=[x for x in checks if x['severity']=='BLOCKING' and not x['passed']]
  status='P2B_P2B_INDEPENDENT_ADAPTER_SOURCE_QUALIFICATION_COMPLETE_PASS' if not blocking else 'P2B_P2B_INDEPENDENT_ADAPTER_SOURCE_QUALIFICATION_COMPLETE_WITH_BLOCKING_GAPS'
  next_gate='EX6_P2B_P2C_ADAPTER_STATIC_REPAIR' if blocking else 'EX6_P2B_P2C_IMPORT_AND_INTERFACE_PREFLIGHT'
  result={'version':VERSION,'created_at_utc':now(),'status':status,'classification':'READ_ONLY_INDEPENDENT_STATIC_SOURCE_QUALIFICATION','P2A_parent_verified':True,'adapter_source_identity':ident(p['adapter_source']),'frozen_sources_modified':False,'checks':{'total':len(checks),'passed':sum(x['passed'] for x in checks),'failed':len(blocking),'blocking_gap_ids':[x['check_id'] for x in blocking]},'requirement_qualification':{'total':10,'statically_qualified':sum(x['qualification_status']=='STATICALLY_QUALIFIED' for x in rrows),'source_repair_required':sum(x['qualification_status']=='SOURCE_REPAIR_REQUIRED' for x in rrows),'runtime_validated':0,'satisfied':0},'scientific_verdict':{'implementation_identity':'INDEPENDENTLY_VERIFIED','static_source_qualification':'PASS' if not blocking else 'BLOCKING_GAPS_IDENTIFIED','runtime_compatibility':'NOT_EVALUATED','requirement_satisfaction':'NOT_ESTABLISHED','authorization_transport_correctness':'NOT_ESTABLISHED','guardrail_effectiveness':'NOT_EVALUATED','policy_superiority':'NOT_EVALUATED','real_exfiltration_prevention':'NOT_ESTABLISHED','harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'},'execution_boundaries':{'sdk_imported':False,'adapter_instantiated':False,'guardrail_executed':False,'sandbox_executed':False,'gym_executed':False,'tools_executed':False,'predicates_executed':False,'breach_executed':False,'effects_observed':False},'claim_boundary':{'allowed':['independent adapter source identity verification','independent static source qualification','blocking static gap findings','source repair recommendation'],'prohibited':['runtime compatibility','requirement satisfaction','guardrail effectiveness','security improvement','policy superiority','real exfiltration prevention','Sandbox parity','Gym parity','hosted parity','attack success reduction']},'next_gate':next_gate}
  rp=out/'ex6_p2b_p2b_result.json';cp=out/'ex6_p2b_p2b_source_checks.csv';qp=out/'ex6_p2b_p2b_requirement_qualification.csv';bp=out/'ex6_p2b_p2b_binding.json';cb=out/'ex6_p2b_p2b_claim_boundary.json'
  dumpx(rp,result);csvx(cp,checks,['check_id','area','description','passed','severity','evidence']);csvx(qp,rrows,['requirement_id','static_checks','qualification_status','implemented_identity','runtime_validated','satisfied','claim_boundary']);dumpx(cb,result['claim_boundary']);dumpx(bp,{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'inputs':{k:ident(v) for k,v in p.items()},'source_artifacts_modified':False})
  content=[rp,cp,qp,bp,cb];rows=[]
  for x in content:rows.append({**ident(x),'role':'P2B_P2B_DERIVED'})
  for k,x in p.items():rows.append({**ident(x),'role':'P2B_P2B_BOUND_'+k.upper()})
  man=out/'ex6_p2b_p2b_manifest.csv';csvx(man,rows,['artifact','role','size_bytes','sha256','path'])
  ext=out/'ex6_p2b_p2b_manifest_external_binding.json';dumpx(ext,{'version':VERSION,'created_at_utc':now(),'status':status,'manifest_filename':man.name,'manifest_size_bytes':man.stat().st_size,'manifest_sha256':sha(man),'runner_sha256':sha(Path(__file__).resolve()),'adapter_source_sha256':sha(p['adapter_source']),'runtime_validated':False,'requirements_satisfied':False,'blocking_gap_ids':[x['check_id'] for x in blocking],'next_gate':next_gate})
  print(json.dumps({'status':status,'manifest_sha256':sha(man),'checks_total':len(checks),'checks_passed':sum(x['passed'] for x in checks),'blocking_gap_ids':[x['check_id'] for x in blocking],'requirements_statically_qualified':result['requirement_qualification']['statically_qualified'],'runtime_validated':False,'requirements_satisfied':False,'next_gate':next_gate},indent=2))
 except Exception:
  (out/'P2B_P2B_FAILED.txt').write_text('P2B P2B failed before independent qualification completed. No source-qualified, runtime, requirement-satisfaction, effectiveness, or superiority claim is allowed.\n',encoding='utf-8')
  raise

def args():
 p=argparse.ArgumentParser(description=VERSION)
 for x in ('p2a-manifest','p2a-external-binding','p2a-result','p2a-binding','p2a-source-identity','adapter-source','optimal','proposal-aware','frozen-decisions','implementation-plan','output-dir'):
  p.add_argument('--'+x,required=True,dest=x.replace('-','_'))
 return p.parse_args()
if __name__=='__main__':
 try:main(args())
 except Exception as e:print(f'FAILED: {e}',file=sys.stderr);raise SystemExit(1)
