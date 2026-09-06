#!/usr/bin/env python3
"""EX6 P2B P2D independent repaired-source requalification.

Read-only and fail-closed. Independently verifies the P2C evidence chain and
recomputes the original eleven blocking static checks against the repaired v1.1
source. Does not import or instantiate the adapter or execute any runtime layer.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2D_INDEPENDENT_REPAIRED_SOURCE_REQUALIFICATION_v1.0"
PARENT_VERSION="EX6_P2B_P2C_ADAPTER_STATIC_REPAIR_v1.0"
EXPECTED_PARENT_MANIFEST="2D39A5D44051DEE93DC14F420887E93047913209F2751A6A145AE56673A6F314"
EXPECTED_ORIGINAL_SHA="AAA1F40B9717D31A475550FC0F6E26A498942AE63B0AE645DFACB2950CEE405F"
EXPECTED_REPAIRED_SHA="BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"
EXPECTED_CLASS="TrustedGuardrailContextAdapterV1_1"
GAPS=["S-006","S-008","S-009","S-010","S-013","Q-001","Q-002","Q-003","Q-004","Q-005","Q-006"]
REQ_MAP={
 "AZ-001":["S-007"],"AZ-002":["S-014","Q-003","Q-004"],"AZ-003":["S-008"],
 "AZ-004":["S-009","Q-002"],"AZ-005":["S-010","Q-001"],"AZ-006":["S-006"],
 "AZ-007":["S-011","S-012","S-013","Q-006"],"PV-002":["S-014","Q-005"],
 "PV-003":["S-014","Q-003","Q-004"],"PV-004":["S-008","Q-004","Q-005"]}
BASE_PASS={"S-001","S-002","S-003","S-004","S-005","S-007","S-011","S-012","S-014"}

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
def loadcsv(p:Path):
 with p.open('r',encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def dumpx(p:Path,x:Any):
 with p.open('x',encoding='utf-8',newline='\n') as f:json.dump(x,f,indent=2,sort_keys=True);f.write('\n')
def csvx(p:Path,rows:list[dict[str,Any]],fields:list[str]):
 with p.open('x',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(rows)
def names(node:ast.AST)->set[str]:
 out=set()
 for n in ast.walk(node):
  if isinstance(n,ast.Name):out.add(n.id)
  elif isinstance(n,ast.Attribute):out.add(n.attr)
  elif isinstance(n,ast.Constant) and isinstance(n.value,str):out.add(n.value)
 return out
def calls(node:ast.AST)->set[str]:
 out=set()
 for n in ast.walk(node):
  if isinstance(n,ast.Call):
   if isinstance(n.func,ast.Name):out.add(n.func.id)
   elif isinstance(n.func,ast.Attribute):out.add(n.func.attr)
 return out
def src(node:ast.AST)->str:return ast.unparse(node)
def add(rows,cid,area,description,passed,evidence):rows.append({'check_id':cid,'area':area,'description':description,'passed':bool(passed),'evidence':evidence})

def verify_parent(p:dict[str,Path]):
 ext=loadj(p['p2c_external_binding']);res=loadj(p['p2c_result']);sid=loadj(p['p2c_source_identity'])
 req(ext.get('version')==PARENT_VERSION,'Unexpected P2C version')
 req(ext.get('status')=='P2B_P2C_ADAPTER_STATIC_REPAIR_COMPLETE_PASS','P2C status not PASS')
 req(ext.get('manifest_filename')==p['p2c_manifest'].name,'P2C manifest filename mismatch')
 req(ext.get('manifest_sha256')==sha(p['p2c_manifest'])==EXPECTED_PARENT_MANIFEST,'P2C manifest SHA mismatch')
 req(int(ext.get('manifest_size_bytes',-1))==p['p2c_manifest'].stat().st_size,'P2C manifest size mismatch')
 req(ext.get('original_source_sha256')==EXPECTED_ORIGINAL_SHA,'Original source authority mismatch')
 req(ext.get('repaired_source_sha256')==EXPECTED_REPAIRED_SHA,'Repaired source authority mismatch')
 req(ext.get('runtime_validated') is False and ext.get('requirements_satisfied') is False,'P2C crossed runtime boundary')
 req(res.get('blocking_gaps_addressed') and set(res['blocking_gaps_addressed'])==set(GAPS),'P2C gap set differs')
 req(res.get('original_source_modified') is False,'Original source was modified')
 req(res.get('repaired_class')==EXPECTED_CLASS,'Repaired class differs')
 req(sid.get('repaired_source',{}).get('sha256')==EXPECTED_REPAIRED_SHA,'P2C source identity differs')

def model(path:Path):
 text=path.read_text(encoding='utf-8');tree=ast.parse(text,filename=str(path));compile(text,str(path),'exec')
 classes={n.name:n for n in tree.body if isinstance(n,ast.ClassDef)};req(EXPECTED_CLASS in classes,'Repaired class absent')
 cls=classes[EXPECTED_CLASS];methods={n.name:n for n in cls.body if isinstance(n,ast.FunctionDef)}
 return text,tree,methods

def requalify(text:str,tree:ast.Module,m:dict[str,ast.FunctionDef])->list[dict[str,Any]]:
 rows=[]
 # Baseline checks independently recomputed, not blindly inherited.
 add(rows,'S-001','IDENTITY','Distinct repaired class inherits GuardrailBase',EXPECTED_CLASS in text and 'GuardrailBase' in src(tree),EXPECTED_CLASS)
 required_public={"__init__","register_trusted_grant","before_decide","decide","after_tool","snapshot_state","restore_state","reset_state"}
 required_private={"_canonicalize_v1","_digest_v1","_validate_grant","_validate_event_identity","_qualify_protected_read","_consume_grant","_validate_snapshot"}
 add(rows,'S-002','INTERFACE','Required public methods present',required_public<=set(m),str(sorted(required_public-set(m))))
 add(rows,'S-003','INTERFACE','Required private methods present',required_private<=set(m),str(sorted(required_private-set(m))))
 imports={n.names[0].name.split('.')[0] for n in tree.body if isinstance(n,ast.Import)}|{n.module.split('.')[0] for n in tree.body if isinstance(n,ast.ImportFrom) and n.module}
 add(rows,'S-004','IMPORTS','No prohibited process/network imports',not(imports&{'subprocess','socket','requests','urllib','httpx','aiohttp'}),str(sorted(imports)))
 full_calls=calls(tree);add(rows,'S-005','EXECUTION','No prohibited dynamic or file execution calls',not(full_calls&{'eval','exec','compile','open','__import__'}),str(sorted(full_calls&{'eval','exec','compile','open','__import__'})))
 d=m['decide'];add(rows,'S-006','FAIL_CLOSED','Direct decide explicitly denies without delegation','Decision.deny("P2B_TRUSTED_BEFORE_DECIDE_REQUIRED")' in src(d) and '_inner.decide' not in src(d),src(d))
 vg=m['_validate_grant'];add(rows,'S-007','ISSUER','Issuer identity and capability comparison present',{'issuer_id','issuer_trust_domain','compare_digest'}<=names(vg),str(sorted({'issuer_id','issuer_trust_domain','compare_digest'}&names(vg))))
 can=src(m['_canonicalize_v1'])+'\n'+src(m['_normalize_json_value']);add(rows,'S-008','CANONICALIZATION','NFC UTF-8 compact sorted canonicalization and float rejection present',all(x in can for x in ['NFC','utf-8','sort_keys','separators','floating point prohibited']),can)
 ev=m['_validate_event_identity'];add(rows,'S-009','EVENT_IDENTITY','Trace sequence kind and replay rejection present',all(x in src(ev) for x in ['trace_identity','event_sequence','event_kind','P2B_REPLAY_OR_EVENT_IDENTITY_REJECTED']),src(ev))
 bd=m['before_decide'];add(rows,'S-010','ONE_USE','Grant consumption occurs before protected authorization return',src(bd).find('_consume_grant')!=-1 and src(bd).find('_consume_grant')<src(bd).rfind('return inner_decision'),src(bd))
 state={'trusted_grants_by_id','consumed_grant_ids','protected_read_records','seen_event_identities','pending_proposals_by_digest','monotonic_sequence_by_trace','inner_guardrail_state'}
 add(rows,'S-011','STATE','Snapshot covers frozen state domains',state<=names(m['snapshot_state']),str(sorted(state-names(m['snapshot_state']))))
 add(rows,'S-012','STATE','Restore validates candidate before state application','_validate_snapshot' in calls(m['restore_state']),src(m['restore_state']))
 add(rows,'S-013','STATE','Reset clears all adapter-owned mutable domains',(state-{'inner_guardrail_state'})<=names(m['reset_state']),str(sorted((state-{'inner_guardrail_state'})-names(m['reset_state']))))
 at=m['after_tool'];add(rows,'S-014','AFTER_TOOL','After-tool exposes proposal trace event tool and argument digest',{'proposal_digest','trace_identity','event_identity','tool_name','tool_args_digest'}<=names(at),str(sorted(names(at))))
 fe=m['_find_eligible_grant'];add(rows,'Q-001','GRANT_LIFETIME','Authorization enforces issued <= current < expiry',all(x in src(fe) for x in ['issued_at_or_sequence','expires_at_or_sequence','current_sequence']),src(fe))
 add(rows,'Q-002','PROPOSAL_REPLAY','Proposal identity is committed to seen and monotonic state before delegation',all(x in src(bd) for x in ['_seen_event_identities.add(event_key)','_monotonic_sequence_by_trace[trace_identity] = event_key[1]']) and src(bd).find('_seen_event_identities.add')<src(bd).find('_inner.decide'),src(bd))
 add(rows,'Q-003','OUTCOME_BINDING','Acknowledged tool name equals pending tool name','pending[\'tool_name\'] != tool_name' in src(at),src(at))
 add(rows,'Q-004','ARGUMENT_BINDING','Acknowledged argument digest equals pending digest and proposal stores it','pending[\'tool_args_digest\'] != tool_args_digest' in src(at) and '"tool_args_digest": tool_args_digest' in src(bd),src(at))
 qr=m['_qualify_protected_read'];add(rows,'Q-005','READ_QUALIFICATION','Protected path classifier gates read record','is_protected_secret_path' in calls(qr),src(qr))
 rs=m['restore_state'];add(rows,'Q-006','RESTORE_ATOMICITY','Restore has prior snapshot and rollback exception path',any(isinstance(n,ast.Try) for n in ast.walk(rs)) and all(x in src(rs) for x in ['prior = self.snapshot_state()','rollback = self._validate_snapshot(prior)','_apply_validated_snapshot(rollback)']),src(rs))
 return rows

def requirement_rows(checks):
 by={x['check_id']:x for x in checks};rows=[]
 for rid,ids in REQ_MAP.items():
  ok=all(by[x]['passed'] for x in ids)
  rows.append({'requirement_id':rid,'static_checks':';'.join(ids),'requalification_status':'STATICALLY_REQUALIFIED' if ok else 'BLOCKING_GAP_REMAINS','implemented_identity':True,'runtime_validated':False,'satisfied':False,'claim_boundary':'independent repaired-source static requalification only'})
 return rows

def main(a):
 out=Path(a.output_dir).resolve();req(not out.exists(),f'Refusing overwrite: {out}');out.mkdir(parents=True)
 try:
  keys=('p2c_manifest','p2c_external_binding','p2c_result','p2c_binding','p2c_source_identity','p2c_change_manifest','original_source','repaired_source')
  p={k:Path(getattr(a,k)).resolve() for k in keys}
  for k,x in p.items():req(x.is_file(),f'Missing {k}: {x}')
  verify_parent(p);req(sha(p['original_source'])==EXPECTED_ORIGINAL_SHA,'Original source SHA mismatch');req(sha(p['repaired_source'])==EXPECTED_REPAIRED_SHA,'Repaired source SHA mismatch')
  change_rows=loadcsv(p['p2c_change_manifest']);covered=set()
  for row in change_rows:
   covered|={x for x in row.get('gap_ids','').split(';') if x in set(GAPS)}
  req(covered==set(GAPS),'Change manifest does not cover all original gaps')
  text,tree,methods=model(p['repaired_source']);checks=requalify(text,tree,methods);rrows=requirement_rows(checks)
  failed=[x for x in checks if not x['passed']];original_gap_results={x['check_id']:x['passed'] for x in checks if x['check_id'] in set(GAPS)}
  gaps_closed=sorted([x for x,v in original_gap_results.items() if v]);gaps_remaining=sorted([x for x,v in original_gap_results.items() if not v])
  status='P2B_P2D_INDEPENDENT_REPAIRED_SOURCE_REQUALIFICATION_COMPLETE_PASS' if not failed else 'P2B_P2D_INDEPENDENT_REPAIRED_SOURCE_REQUALIFICATION_COMPLETE_WITH_BLOCKING_GAPS'
  next_gate='EX6_P2B_P2E_IMPORT_AND_INTERFACE_PREFLIGHT' if not failed else 'EX6_P2B_P2E_ADAPTER_STATIC_REPAIR_V1_2'
  result={'version':VERSION,'created_at_utc':now(),'status':status,'classification':'READ_ONLY_INDEPENDENT_REPAIRED_SOURCE_STATIC_REQUALIFICATION','P2C_parent_verified':True,'original_source_identity':ident(p['original_source']),'repaired_source_identity':ident(p['repaired_source']),'source_artifacts_modified':False,'checks':{'total':len(checks),'passed':sum(x['passed'] for x in checks),'failed':len(failed),'failed_ids':[x['check_id'] for x in failed]},'original_blocking_gaps':{'total':11,'closed':len(gaps_closed),'remaining':len(gaps_remaining),'closed_ids':gaps_closed,'remaining_ids':gaps_remaining},'requirement_requalification':{'total':10,'statically_requalified':sum(x['requalification_status']=='STATICALLY_REQUALIFIED' for x in rrows),'blocking_gap_remains':sum(x['requalification_status']=='BLOCKING_GAP_REMAINS' for x in rrows),'runtime_validated':0,'satisfied':0},'scientific_verdict':{'repaired_source_identity':'INDEPENDENTLY_VERIFIED','static_requalification':'PASS' if not failed else 'BLOCKING_GAPS_REMAIN','runtime_compatibility':'NOT_EVALUATED','authorization_transport_correctness':'NOT_ESTABLISHED','requirement_satisfaction':'NOT_ESTABLISHED','guardrail_effectiveness':'NOT_EVALUATED','policy_superiority':'NOT_EVALUATED','real_exfiltration_prevention':'NOT_ESTABLISHED','harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'},'execution_boundaries':{'sdk_imported':False,'adapter_instantiated':False,'guardrail_executed':False,'sandbox_executed':False,'gym_executed':False,'tools_executed':False,'predicates_executed':False,'breach_executed':False,'effects_observed':False},'claim_boundary':{'allowed':['independent repaired source identity verification','independent static requalification','original gap closure findings at static level','remaining static gap findings'],'prohibited':['runtime compatibility','requirement satisfaction','authorization transport correctness','guardrail effectiveness','security improvement','policy superiority','real exfiltration prevention','Sandbox parity','Gym parity','hosted parity']},'next_gate':next_gate}
  rp=out/'ex6_p2b_p2d_result.json';cp=out/'ex6_p2b_p2d_source_checks.csv';qp=out/'ex6_p2b_p2d_requirement_requalification.csv';bp=out/'ex6_p2b_p2d_binding.json';cb=out/'ex6_p2b_p2d_claim_boundary.json'
  dumpx(rp,result);csvx(cp,checks,['check_id','area','description','passed','evidence']);csvx(qp,rrows,['requirement_id','static_checks','requalification_status','implemented_identity','runtime_validated','satisfied','claim_boundary']);dumpx(cb,result['claim_boundary']);dumpx(bp,{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'inputs':{k:ident(v) for k,v in p.items()},'source_artifacts_modified':False})
  content=[rp,cp,qp,bp,cb];rows=[]
  for x in content:rows.append({**ident(x),'role':'P2B_P2D_DERIVED'})
  for k,x in p.items():rows.append({**ident(x),'role':'P2B_P2D_BOUND_'+k.upper()})
  man=out/'ex6_p2b_p2d_manifest.csv';csvx(man,rows,['artifact','role','size_bytes','sha256','path'])
  ext=out/'ex6_p2b_p2d_manifest_external_binding.json';dumpx(ext,{'version':VERSION,'created_at_utc':now(),'status':status,'manifest_filename':man.name,'manifest_size_bytes':man.stat().st_size,'manifest_sha256':sha(man),'runner_sha256':sha(Path(__file__).resolve()),'repaired_source_sha256':sha(p['repaired_source']),'original_gap_ids_closed':gaps_closed,'original_gap_ids_remaining':gaps_remaining,'runtime_validated':False,'requirements_satisfied':False,'next_gate':next_gate})
  print(json.dumps({'status':status,'manifest_sha256':sha(man),'checks_total':len(checks),'checks_passed':sum(x['passed'] for x in checks),'original_gap_ids_closed':gaps_closed,'original_gap_ids_remaining':gaps_remaining,'requirements_statically_requalified':result['requirement_requalification']['statically_requalified'],'runtime_validated':False,'requirements_satisfied':False,'next_gate':next_gate},indent=2))
 except Exception:
  (out/'P2B_P2D_FAILED.txt').write_text('P2B P2D failed before requalification completed. No repaired-source-qualified, runtime, requirement-satisfaction, effectiveness, or superiority claim is allowed.\n',encoding='utf-8')
  raise

def args():
 p=argparse.ArgumentParser(description=VERSION)
 for x in ('p2c-manifest','p2c-external-binding','p2c-result','p2c-binding','p2c-source-identity','p2c-change-manifest','original-source','repaired-source','output-dir'):
  p.add_argument('--'+x,required=True,dest=x.replace('-','_'))
 return p.parse_args()
if __name__=='__main__':
 try:main(args())
 except Exception as e:print(f'FAILED: {e}',file=sys.stderr);raise SystemExit(1)
