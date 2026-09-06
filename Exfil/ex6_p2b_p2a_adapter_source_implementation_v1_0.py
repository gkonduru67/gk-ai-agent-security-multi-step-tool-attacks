#!/usr/bin/env python3
"""EX6 P2B P2A adapter source implementation and identity freeze.

Creates exactly one new non-overwriting source file from a reviewed source
template, after verifying the P2 preflight authority and frozen policy bytes.
Performs AST and built-in compile validation only. It does not import the SDK,
instantiate the adapter, or execute runtime/security behavior.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, os, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2A_ADAPTER_SOURCE_IMPLEMENTATION_v1.0"
STATUS="P2B_P2A_ADAPTER_SOURCE_IMPLEMENTATION_COMPLETE_PASS"
PARENT_VERSION="EX6_P2B_P2_ADAPTER_IMPLEMENTATION_PREFLIGHT_v1.0"
EXPECTED_PARENT_MANIFEST="30381A1D0702662D4B0931BDDC90A61C4290E45504F55670FC78DB465E8EBD5C"
EXPECTED_TEMPLATE_SHA="AAA1F40B9717D31A475550FC0F6E26A498942AE63B0AE645DFACB2950CEE405F"
EXPECTED_OPTIMAL_SHA="6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED"
EXPECTED_PROPOSAL_SHA="918FFD61CDB9A406C965F06CF2BEC34C297AB231E26B6FC083AE34B00C37D452"
REQUIRED_PUBLIC={"__init__","register_trusted_grant","before_decide","decide","after_tool","snapshot_state","restore_state","reset_state"}
REQUIRED_PRIVATE={"_canonicalize_v1","_digest_v1","_validate_grant","_validate_event_identity","_qualify_protected_read","_consume_grant","_validate_snapshot"}
PROHIBITED_CLAIMS=["runtime compatibility","deferred requirement satisfaction","guardrail effectiveness","security improvement","policy superiority","real exfiltration prevention","Sandbox parity","Gym parity","hosted parity","attack success reduction"]

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
 ext=loadj(p['preflight_external_binding']);result=loadj(p['preflight_result']);plan=loadj(p['implementation_plan']);decisions=loadj(p['frozen_decisions'])
 req(ext.get('version')==PARENT_VERSION and ext.get('status')=='P2B_P2_ADAPTER_IMPLEMENTATION_PREFLIGHT_COMPLETE_PASS','P2 preflight authority invalid')
 req(ext.get('manifest_filename')==p['preflight_manifest'].name,'Preflight manifest name mismatch')
 req(ext.get('manifest_sha256')==sha(p['preflight_manifest'])==EXPECTED_PARENT_MANIFEST,'Preflight manifest SHA mismatch')
 req(int(ext.get('manifest_size_bytes',-1))==p['preflight_manifest'].stat().st_size,'Preflight manifest size mismatch')
 req(ext.get('adapter_source_created') is False and ext.get('requirements_satisfied') is False,'Preflight crossed source/runtime boundary')
 req(result.get('all_six_implementation_decisions_frozen') is True,'Six decisions not frozen')
 req(result.get('implementation_plan_distinct_and_non_overwriting') is True,'Implementation plan is not non-overwriting')
 req(result.get('next_gate')=='EX6_P2B_P2A_ADAPTER_SOURCE_IMPLEMENTATION','Unexpected preflight next gate')
 req(len(decisions)==6,'Frozen decision count differs')
 req(plan.get('class')=='TrustedGuardrailContextAdapter','Planned class differs')
 req(plan.get('source_file')=='aicomp_sdk/guardrails/trusted_context_adapter.py','Planned source path differs')
 req(plan.get('must_not_exist_before_creation') is True,'Non-overwrite requirement absent')
 return result

def inspect_template(p:Path)->dict[str,Any]:
 text=p.read_text(encoding='utf-8');tree=ast.parse(text,filename=str(p));compile(text,str(p),'exec')
 classes={n.name:n for n in tree.body if isinstance(n,ast.ClassDef)}
 req('TrustedGuardrailContextAdapter' in classes,'Required adapter class absent')
 cls=classes['TrustedGuardrailContextAdapter'];methods={n.name:n for n in cls.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
 req(REQUIRED_PUBLIC.issubset(methods),'Required public methods absent: '+str(sorted(REQUIRED_PUBLIC-set(methods))))
 req(REQUIRED_PRIVATE.issubset(methods),'Required private helpers absent: '+str(sorted(REQUIRED_PRIVATE-set(methods))))
 imports=[]
 for n in tree.body:
  if isinstance(n,ast.ImportFrom):imports.append((n.module,[a.name for a in n.names]))
 req(any(m=='aicomp_sdk.guardrails.base' and {'Decision','DecisionAction','GuardrailBase'}.issubset(set(names)) for m,names in imports),'Required GuardrailBase imports absent')
 prohibited_tokens=['subprocess','socket','requests','urllib.request','eval(','exec(']
 hits=[x for x in prohibited_tokens if x in text]
 req(not hits,'Prohibited source tokens: '+str(hits))
 return {"ast_parse":"PASS","compile":"PASS","class":"TrustedGuardrailContextAdapter","public_methods":sorted(REQUIRED_PUBLIC),"private_helpers":sorted(REQUIRED_PRIVATE),"line_count":len(text.splitlines())}

def main(a):
 out=Path(a.output_dir).resolve();target=Path(a.target_source).resolve();template=Path(a.source_template).resolve()
 req(not out.exists(),f'Refusing overwrite output: {out}');req(not target.exists(),f'Refusing overwrite target source: {target}')
 out.mkdir(parents=True)
 try:
  keys=('preflight_manifest','preflight_external_binding','preflight_result','frozen_decisions','implementation_plan','optimal','proposal_aware')
  paths={k:Path(getattr(a,k)).resolve() for k in keys};paths['source_template']=template
  for k,p in paths.items():req(p.is_file(),f'Missing {k}: {p}')
  verify_parent(paths)
  req(sha(template)==EXPECTED_TEMPLATE_SHA,'Source template SHA differs from reviewed implementation')
  req(sha(paths['optimal'])==EXPECTED_OPTIMAL_SHA,'Frozen optimal.py modified')
  req(sha(paths['proposal_aware'])==EXPECTED_PROPOSAL_SHA,'Frozen proposal_aware_optimal.py modified')
  source_validation=inspect_template(template)
  req(target.name=='trusted_context_adapter.py','Target filename must be trusted_context_adapter.py')
  target.parent.mkdir(parents=True,exist_ok=True)
  temp=target.with_name(target.name+'.p2a_tmp')
  req(not temp.exists(),'Temporary target already exists')
  data=template.read_bytes();temp.write_bytes(data)
  req(sha(temp)==EXPECTED_TEMPLATE_SHA,'Temporary write identity mismatch')
  os.replace(temp,target)
  req(sha(target)==EXPECTED_TEMPLATE_SHA,'Final target identity mismatch')
  result={"version":VERSION,"created_at_utc":now(),"status":STATUS,"classification":"SOURCE_CREATION_AST_COMPILE_AND_IDENTITY_FREEZE_ONLY","parent_preflight_verified":True,"source_created":True,"source_validation":source_validation,"adapter_identity":ident(target),"class":"TrustedGuardrailContextAdapter","frozen_optimal_identity":ident(paths['optimal']),"frozen_proposal_aware_identity":ident(paths['proposal_aware']),"frozen_sources_modified":False,"execution_boundaries":{"sdk_imported":False,"adapter_instantiated":False,"guardrail_executed":False,"sandbox_executed":False,"gym_executed":False,"tools_executed":False,"predicates_executed":False,"breach_executed":False,"effects_observed":False},"scientific_verdict":{"implementation_identity":"ESTABLISHED","static_interface_presence":"ESTABLISHED","runtime_compatibility":"NOT_EVALUATED","requirement_satisfaction":"NOT_ESTABLISHED","guardrail_effectiveness":"NOT_EVALUATED","policy_superiority":"NOT_EVALUATED","real_exfiltration_prevention":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":{"allowed":["adapter source identity","adapter class identity","static interface presence","AST parse and built-in compile validation","frozen policy non-modification"],"prohibited":PROHIBITED_CLAIMS},"next_gate":"EX6_P2B_P2B_INDEPENDENT_ADAPTER_SOURCE_QUALIFICATION"}
  rp=out/'ex6_p2b_p2a_result.json';bp=out/'ex6_p2b_p2a_binding.json';cp=out/'ex6_p2b_p2a_claim_boundary.json';sp=out/'ex6_p2b_p2a_source_identity.json'
  dumpx(rp,result);dumpx(sp,{"version":VERSION,"source":ident(target),"source_validation":source_validation});dumpx(cp,result['claim_boundary']);dumpx(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{k:ident(v) for k,v in paths.items()},"created_source":ident(target),"frozen_sources_modified":False})
  content=[rp,bp,cp,sp];rows=[]
  for p in content:rows.append({**ident(p),'role':'P2B_P2A_DERIVED'})
  for k,p in paths.items():rows.append({**ident(p),'role':'P2B_P2A_BOUND_'+k.upper()})
  rows.append({**ident(target),'role':'P2B_P2A_CREATED_ADAPTER_SOURCE'})
  man=out/'ex6_p2b_p2a_manifest.csv';csvx(man,rows,['artifact','role','size_bytes','sha256','path'])
  ext=out/'ex6_p2b_p2a_manifest_external_binding.json';dumpx(ext,{"version":VERSION,"created_at_utc":now(),"status":STATUS,"manifest_filename":man.name,"manifest_size_bytes":man.stat().st_size,"manifest_sha256":sha(man),"runner_sha256":sha(Path(__file__).resolve()),"adapter_source_sha256":sha(target),"adapter_source_created":True,"runtime_validated":False,"requirements_satisfied":False,"next_gate":result['next_gate']})
  print(json.dumps({"status":STATUS,"adapter_source":str(target),"adapter_source_sha256":sha(target),"manifest_sha256":sha(man),"runtime_validated":False,"requirements_satisfied":False,"next_gate":result['next_gate']},indent=2))
 except Exception:
  (out/'P2B_P2A_FAILED.txt').write_text('P2B P2A failed. No complete implementation, runtime compatibility, requirement satisfaction, effectiveness, or superiority claim is allowed. Inspect whether a target source was created before retrying with a new version.\n',encoding='utf-8')
  raise

def args():
 p=argparse.ArgumentParser(description=VERSION)
 for x in ('source-template','target-source','preflight-manifest','preflight-external-binding','preflight-result','frozen-decisions','implementation-plan','optimal','proposal-aware','output-dir'):
  p.add_argument('--'+x,required=True,dest=x.replace('-','_'))
 return p.parse_args()
if __name__=='__main__':
 try:main(args())
 except Exception as e:print(f'FAILED: {e}',file=sys.stderr);raise SystemExit(1)
