#!/usr/bin/env python3
"""EX6 P2B P2E corrected qualifier and targeted static requalification.

Read-only. Corrects the quote-sensitive S-006 and Q-004 detectors by using
AST-semantic predicates, then recomputes all 20 static checks and all 10
requirement rows against the unchanged repaired v1.1 source. No SDK import,
adapter instantiation, Sandbox, Gym, tool, predicate, breach, or effect occurs.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2E_QUALIFIER_CORRECTION_AND_TARGETED_REQUALIFICATION_v1.0"
PARENT_VERSION="EX6_P2B_P2D_INDEPENDENT_REPAIRED_SOURCE_REQUALIFICATION_v1.0"
EXPECTED_PARENT_MANIFEST="86F38CAEE575E8E333FFF4A62BD1B84E6E4F5C3B8150038498E534184CA35790"
EXPECTED_REPAIRED_SHA="BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"
EXPECTED_ORIGINAL_SHA="AAA1F40B9717D31A475550FC0F6E26A498942AE63B0AE645DFACB2950CEE405F"
EXPECTED_CLASS="TrustedGuardrailContextAdapterV1_1"
ORIGINAL_GAPS={"S-006","S-008","S-009","S-010","S-013","Q-001","Q-002","Q-003","Q-004","Q-005","Q-006"}
P2D_REPORTED_REMAINING={"S-006","Q-004"}
REQ_MAP={
 "AZ-001":["S-007"],"AZ-002":["S-014","Q-003","Q-004"],"AZ-003":["S-008"],
 "AZ-004":["S-009","Q-002"],"AZ-005":["S-010","Q-001"],"AZ-006":["S-006"],
 "AZ-007":["S-011","S-012","S-013","Q-006"],"PV-002":["S-014","Q-005"],
 "PV-003":["S-014","Q-003","Q-004"],"PV-004":["S-008","Q-004","Q-005"]}

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
def unparse(node:ast.AST)->str:return ast.unparse(node)
def add(rows,cid,area,desc,passed,evidence,detector="AST_SEMANTIC"):
 rows.append({'check_id':cid,'area':area,'description':desc,'passed':bool(passed),'detector':detector,'evidence':evidence})

def verify_parent(p:dict[str,Path]):
 ext=loadj(p['p2d_external_binding']);res=loadj(p['p2d_result'])
 req(ext.get('version')==PARENT_VERSION,'Unexpected P2D version')
 req(ext.get('status')=='P2B_P2D_INDEPENDENT_REPAIRED_SOURCE_REQUALIFICATION_COMPLETE_WITH_BLOCKING_GAPS','P2D status differs')
 req(ext.get('manifest_filename')==p['p2d_manifest'].name,'P2D manifest filename mismatch')
 req(ext.get('manifest_sha256')==sha(p['p2d_manifest'])==EXPECTED_PARENT_MANIFEST,'P2D manifest SHA mismatch')
 req(int(ext.get('manifest_size_bytes',-1))==p['p2d_manifest'].stat().st_size,'P2D manifest size mismatch')
 req(set(ext.get('original_gap_ids_remaining',[]))==P2D_REPORTED_REMAINING,'P2D remaining gap set differs')
 req(ext.get('repaired_source_sha256')==EXPECTED_REPAIRED_SHA,'P2D repaired source identity differs')
 req(ext.get('runtime_validated') is False and ext.get('requirements_satisfied') is False,'P2D crossed runtime boundary')
 req(res.get('checks',{}).get('failed_ids')==['S-006','Q-004'],'P2D failed IDs differ')
 req(res.get('source_artifacts_modified') is False,'P2D modified source artifacts')

def model(path:Path):
 text=path.read_text(encoding='utf-8');tree=ast.parse(text,filename=str(path));compile(text,str(path),'exec')
 classes={n.name:n for n in tree.body if isinstance(n,ast.ClassDef)};req(EXPECTED_CLASS in classes,'Expected repaired class absent')
 cls=classes[EXPECTED_CLASS];methods={n.name:n for n in cls.body if isinstance(n,ast.FunctionDef)}
 return text,tree,cls,methods

def is_attr(node:ast.AST,base:str,attr:str)->bool:
 return isinstance(node,ast.Attribute) and isinstance(node.value,ast.Name) and node.value.id==base and node.attr==attr

def is_pending_subscript(node:ast.AST,key:str)->bool:
 if not isinstance(node,ast.Subscript) or not isinstance(node.value,ast.Name) or node.value.id!='pending':return False
 sl=node.slice
 return isinstance(sl,ast.Constant) and sl.value==key

def corrected_s006(method:ast.FunctionDef)->tuple[bool,dict[str,Any]]:
 deny=False;constant=False;inner_delegate=False
 for n in ast.walk(method):
  if isinstance(n,ast.Call):
   if isinstance(n.func,ast.Attribute) and n.func.attr=='deny' and isinstance(n.func.value,ast.Name) and n.func.value.id=='Decision':
    deny=True
    if n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value=='P2B_TRUSTED_BEFORE_DECIDE_REQUIRED':constant=True
   if isinstance(n.func,ast.Attribute) and n.func.attr=='decide' and isinstance(n.func.value,ast.Attribute) and isinstance(n.func.value.value,ast.Name) and n.func.value.value.id=='self' and n.func.value.attr=='_inner':inner_delegate=True
 return deny and constant and not inner_delegate,{'Decision.deny_call':deny,'exact_reason_constant':constant,'inner_decide_call':inner_delegate}

def corrected_q004(before:ast.FunctionDef,after:ast.FunctionDef)->tuple[bool,dict[str,Any]]:
 assigned=False;stored=False;compared=False;raises=False
 for n in ast.walk(before):
  if isinstance(n,(ast.Assign,ast.AnnAssign)):
   targets=n.targets if isinstance(n,ast.Assign) else [n.target];value=n.value
   if any(isinstance(t,ast.Name) and t.id=='tool_args_digest' for t in targets) and isinstance(value,ast.Call) and isinstance(value.func,ast.Attribute) and value.func.attr=='_digest_v1':assigned=True
  if isinstance(n,ast.Dict):
   for k,v in zip(n.keys,n.values):
    if isinstance(k,ast.Constant) and k.value=='tool_args_digest' and isinstance(v,ast.Name) and v.id=='tool_args_digest':stored=True
 for n in ast.walk(after):
  if isinstance(n,ast.If) and isinstance(n.test,ast.Compare) and len(n.test.ops)==1 and isinstance(n.test.ops[0],ast.NotEq):
   left=n.test.left;right=n.test.comparators[0]
   if (is_pending_subscript(left,'tool_args_digest') and isinstance(right,ast.Name) and right.id=='tool_args_digest') or (is_pending_subscript(right,'tool_args_digest') and isinstance(left,ast.Name) and left.id=='tool_args_digest'):
    compared=True
    raises=any(isinstance(x,ast.Raise) and isinstance(x.exc,ast.Call) and ((isinstance(x.exc.func,ast.Name) and x.exc.func.id=='ValueError') or (isinstance(x.exc.func,ast.Attribute) and x.exc.func.attr=='ValueError')) for x in ast.walk(n))
 return assigned and stored and compared and raises,{'digest_assignment':assigned,'pending_dict_storage':stored,'pending_digest_inequality_comparison':compared,'mismatch_raises_ValueError':raises}

def recompute(tree:ast.Module,cls:ast.ClassDef,m:dict[str,ast.FunctionDef])->list[dict[str,Any]]:
 rows=[];text=unparse(tree)
 add(rows,'S-001','IDENTITY','Distinct repaired class inherits GuardrailBase',any(isinstance(b,ast.Name) and b.id=='GuardrailBase' for b in cls.bases),EXPECTED_CLASS)
 pub={"__init__","register_trusted_grant","before_decide","decide","after_tool","snapshot_state","restore_state","reset_state"};priv={"_canonicalize_v1","_digest_v1","_validate_grant","_validate_event_identity","_qualify_protected_read","_consume_grant","_validate_snapshot"}
 add(rows,'S-002','INTERFACE','Required public methods present',pub<=set(m),str(sorted(pub-set(m))))
 add(rows,'S-003','INTERFACE','Required private methods present',priv<=set(m),str(sorted(priv-set(m))))
 imports={n.names[0].name.split('.')[0] for n in tree.body if isinstance(n,ast.Import)}|{n.module.split('.')[0] for n in tree.body if isinstance(n,ast.ImportFrom) and n.module}
 add(rows,'S-004','IMPORTS','No prohibited process/network imports',not(imports&{'subprocess','socket','requests','urllib','httpx','aiohttp'}),str(sorted(imports)))
 add(rows,'S-005','EXECUTION','No prohibited dynamic/file execution calls',not(calls(tree)&{'eval','exec','compile','open','__import__'}),str(sorted(calls(tree)&{'eval','exec','compile','open','__import__'})))
 ok,e=corrected_s006(m['decide']);add(rows,'S-006','FAIL_CLOSED','Direct decide AST explicitly denies with exact reason and no inner delegation',ok,json.dumps(e,sort_keys=True),'CORRECTED_AST_SEMANTIC')
 add(rows,'S-007','ISSUER','Issuer identity and capability comparison present',{'issuer_id','issuer_trust_domain','compare_digest'}<=names(m['_validate_grant']),str(sorted(names(m['_validate_grant']))))
 can=unparse(m['_canonicalize_v1'])+'\n'+unparse(m['_normalize_json_value']);add(rows,'S-008','CANONICALIZATION','NFC UTF-8 compact sorted canonicalization and float rejection present',all(x in can for x in ['NFC','utf-8','sort_keys','separators','floating point prohibited']),can)
 ev=unparse(m['_validate_event_identity']);add(rows,'S-009','EVENT_IDENTITY','Trace sequence kind and replay rejection present',all(x in ev for x in ['trace_identity','event_sequence','event_kind','P2B_REPLAY_OR_EVENT_IDENTITY_REJECTED']),ev)
 bd=unparse(m['before_decide']);add(rows,'S-010','ONE_USE','Grant consumption occurs before protected authorization return',bd.find('_consume_grant')!=-1 and bd.find('_consume_grant')<bd.rfind('return inner_decision'),bd)
 state={'trusted_grants_by_id','consumed_grant_ids','protected_read_records','seen_event_identities','pending_proposals_by_digest','monotonic_sequence_by_trace','inner_guardrail_state'}
 add(rows,'S-011','STATE','Snapshot covers frozen state domains',state<=names(m['snapshot_state']),str(sorted(state-names(m['snapshot_state']))))
 add(rows,'S-012','STATE','Restore validates candidate before state application','_validate_snapshot' in calls(m['restore_state']),unparse(m['restore_state']))
 add(rows,'S-013','STATE','Reset clears all adapter-owned mutable domains',(state-{'inner_guardrail_state'})<=names(m['reset_state']),str(sorted((state-{'inner_guardrail_state'})-names(m['reset_state']))))
 add(rows,'S-014','AFTER_TOOL','After-tool exposes proposal trace event tool and argument digest',{'proposal_digest','trace_identity','event_identity','tool_name','tool_args_digest'}<=names(m['after_tool']),str(sorted(names(m['after_tool']))))
 fe=unparse(m['_find_eligible_grant']);add(rows,'Q-001','GRANT_LIFETIME','Authorization enforces issued <= current < expiry',all(x in fe for x in ['issued_at_or_sequence','expires_at_or_sequence','current_sequence']),fe)
 add(rows,'Q-002','PROPOSAL_REPLAY','Proposal identity committed before delegation',all(x in bd for x in ['_seen_event_identities.add(event_key)','_monotonic_sequence_by_trace[trace_identity] = event_key[1]']) and bd.find('_seen_event_identities.add')<bd.find('_inner.decide'),bd)
 at=unparse(m['after_tool']);add(rows,'Q-003','OUTCOME_BINDING','Acknowledged tool name equals pending tool name',"pending['tool_name'] != tool_name" in at,at)
 ok,e=corrected_q004(m['before_decide'],m['after_tool']);add(rows,'Q-004','ARGUMENT_BINDING','AST proves digest assignment, pending storage, mismatch comparison, and fail-closed raise',ok,json.dumps(e,sort_keys=True),'CORRECTED_AST_SEMANTIC')
 add(rows,'Q-005','READ_QUALIFICATION','Protected path classifier gates read record','is_protected_secret_path' in calls(m['_qualify_protected_read']),unparse(m['_qualify_protected_read']))
 rs=m['restore_state'];rst=unparse(rs);add(rows,'Q-006','RESTORE_ATOMICITY','Restore has prior snapshot and rollback exception path',any(isinstance(n,ast.Try) for n in ast.walk(rs)) and all(x in rst for x in ['prior = self.snapshot_state()','rollback = self._validate_snapshot(prior)','_apply_validated_snapshot(rollback)']),rst)
 return rows

def req_rows(checks):
 by={x['check_id']:x for x in checks};rows=[]
 for rid,ids in REQ_MAP.items():
  ok=all(by[x]['passed'] for x in ids)
  rows.append({'requirement_id':rid,'static_checks':';'.join(ids),'corrected_requalification_status':'STATICALLY_REQUALIFIED' if ok else 'BLOCKING_GAP_REMAINS','implemented_identity':True,'runtime_validated':False,'satisfied':False,'claim_boundary':'corrected independent static requalification only'})
 return rows

def main(a):
 out=Path(a.output_dir).resolve();req(not out.exists(),f'Refusing overwrite: {out}');out.mkdir(parents=True)
 try:
  keys=('p2d_manifest','p2d_external_binding','p2d_result','p2d_binding','p2d_source_checks','p2d_requirement_requalification','repaired_source')
  p={k:Path(getattr(a,k)).resolve() for k in keys}
  for k,x in p.items():req(x.is_file(),f'Missing {k}: {x}')
  verify_parent(p);req(sha(p['repaired_source'])==EXPECTED_REPAIRED_SHA,'Repaired source SHA mismatch')
  text,tree,cls,methods=model(p['repaired_source']);checks=recompute(tree,cls,methods);rows=req_rows(checks)
  failed=[x for x in checks if not x['passed']];remaining=sorted(x['check_id'] for x in failed if x['check_id'] in ORIGINAL_GAPS);closed=sorted(ORIGINAL_GAPS-set(remaining))
  status='P2B_P2E_CORRECTED_QUALIFIER_REQUALIFICATION_COMPLETE_PASS' if not failed else 'P2B_P2E_CORRECTED_QUALIFIER_REQUALIFICATION_COMPLETE_WITH_BLOCKING_GAPS'
  next_gate='EX6_P2B_P2F_IMPORT_AND_INTERFACE_PREFLIGHT' if not failed else 'EX6_P2B_P2F_EVIDENCE_BOUNDED_STATIC_REPAIR'
  result={'version':VERSION,'created_at_utc':now(),'status':status,'classification':'READ_ONLY_CORRECTED_AST_STATIC_REQUALIFICATION','P2D_parent_verified':True,'repaired_source_identity':ident(p['repaired_source']),'source_modified':False,'qualifier_corrections':{'S-006':'AST Decision.deny call, exact constant argument, and absence of self._inner.decide','Q-004':'AST digest assignment, dictionary storage, pending subscript inequality, and ValueError raise'},'checks':{'total':len(checks),'passed':sum(x['passed'] for x in checks),'failed':len(failed),'failed_ids':[x['check_id'] for x in failed]},'original_gap_disposition':{'total':11,'statically_closed':len(closed),'remaining':len(remaining),'closed_ids':closed,'remaining_ids':remaining},'requirement_requalification':{'total':10,'statically_requalified':sum(x['corrected_requalification_status']=='STATICALLY_REQUALIFIED' for x in rows),'blocking_gap_remains':sum(x['corrected_requalification_status']=='BLOCKING_GAP_REMAINS' for x in rows),'runtime_validated':0,'satisfied':0},'scientific_verdict':{'repaired_source_identity':'INDEPENDENTLY_VERIFIED','corrected_static_requalification':'PASS' if not failed else 'BLOCKING_GAPS_REMAIN','runtime_compatibility':'NOT_EVALUATED','authorization_transport_correctness':'NOT_ESTABLISHED','requirement_satisfaction':'NOT_ESTABLISHED','guardrail_effectiveness':'NOT_EVALUATED','policy_superiority':'NOT_EVALUATED','real_exfiltration_prevention':'NOT_ESTABLISHED','harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'},'execution_boundaries':{'sdk_imported':False,'adapter_instantiated':False,'guardrail_executed':False,'sandbox_executed':False,'gym_executed':False,'tools_executed':False,'predicates_executed':False,'breach_executed':False,'effects_observed':False},'claim_boundary':{'allowed':['corrected qualifier identity','corrected AST-semantic static requalification','static gap disposition','requirement static requalification'],'prohibited':['runtime compatibility','authorization transport correctness','requirement satisfaction','guardrail effectiveness','security improvement','policy superiority','real exfiltration prevention','Sandbox parity','Gym parity','hosted parity']},'next_gate':next_gate}
  rp=out/'ex6_p2b_p2e_result.json';cp=out/'ex6_p2b_p2e_source_checks.csv';qp=out/'ex6_p2b_p2e_requirement_requalification.csv';bp=out/'ex6_p2b_p2e_binding.json';cb=out/'ex6_p2b_p2e_claim_boundary.json'
  dumpx(rp,result);csvx(cp,checks,['check_id','area','description','passed','detector','evidence']);csvx(qp,rows,['requirement_id','static_checks','corrected_requalification_status','implemented_identity','runtime_validated','satisfied','claim_boundary']);dumpx(cb,result['claim_boundary']);dumpx(bp,{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'inputs':{k:ident(v) for k,v in p.items()},'source_modified':False})
  content=[rp,cp,qp,bp,cb];manifest=[]
  for x in content:manifest.append({**ident(x),'role':'P2B_P2E_DERIVED'})
  for k,x in p.items():manifest.append({**ident(x),'role':'P2B_P2E_BOUND_'+k.upper()})
  man=out/'ex6_p2b_p2e_manifest.csv';csvx(man,manifest,['artifact','role','size_bytes','sha256','path'])
  ext=out/'ex6_p2b_p2e_manifest_external_binding.json';dumpx(ext,{'version':VERSION,'created_at_utc':now(),'status':status,'manifest_filename':man.name,'manifest_size_bytes':man.stat().st_size,'manifest_sha256':sha(man),'runner_sha256':sha(Path(__file__).resolve()),'repaired_source_sha256':sha(p['repaired_source']),'original_gap_ids_statically_closed':closed,'original_gap_ids_remaining':remaining,'runtime_validated':False,'requirements_satisfied':False,'next_gate':next_gate})
  print(json.dumps({'status':status,'manifest_sha256':sha(man),'checks_total':len(checks),'checks_passed':sum(x['passed'] for x in checks),'original_gap_ids_statically_closed':closed,'original_gap_ids_remaining':remaining,'requirements_statically_requalified':result['requirement_requalification']['statically_requalified'],'runtime_validated':False,'requirements_satisfied':False,'next_gate':next_gate},indent=2))
 except Exception:
  (out/'P2B_P2E_FAILED.txt').write_text('P2B P2E failed before corrected requalification completed. No static-pass, runtime, requirement-satisfaction, effectiveness, or superiority claim is allowed.\n',encoding='utf-8')
  raise

def args():
 p=argparse.ArgumentParser(description=VERSION)
 for x in ('p2d-manifest','p2d-external-binding','p2d-result','p2d-binding','p2d-source-checks','p2d-requirement-requalification','repaired-source','output-dir'):
  p.add_argument('--'+x,required=True,dest=x.replace('-','_'))
 return p.parse_args()
if __name__=='__main__':
 try:main(args())
 except Exception as e:print(f'FAILED: {e}',file=sys.stderr);raise SystemExit(1)
