#!/usr/bin/env python3
"""Read-only parent-binding reconciliation for V_RENAMED_SOURCE P2A review.
No SDK/model/Sandbox/Gym/tool/guardrail/predicate/breach execution.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,sys
from datetime import datetime,timezone
from pathlib import Path

VERSION='V_RENAMED_SOURCE_DESIGN_REVIEW_PARENT_BINDING_RECONCILIATION_v1.0'
FAILED_P2A_RUNNER_SHA='4DE0521BA8C509FD82D4CA6A86CFE70CE084701BA7F3ABC50DA960E188A911D0'
FAILED_P2A_MANIFEST_SHA='9B45DDA0E3929412A8C6BA667F37E708C2D91947A10D22B68B2D47BFB199CB5A'
OBSERVED_STAGE0_BINDING_SHA='DDA1A3827A86B4297D444273A4F3554C166A77F65C131F6D81F6E9D654F46077'
EXPECTED_STAGE0_MANIFEST_SHA='1403DB377336AA3C608B8E656C854277362485ADF43CD8ED09AEE07B32E03A10'

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest().upper()
def ident(p):return {'artifact':p.name,'path':str(p.resolve()),'size_bytes':p.stat().st_size,'sha256':sha(p)}
def wj(p,x):
 with p.open('x',encoding='utf-8',newline='\n') as f:json.dump(x,f,indent=2,sort_keys=True);f.write('\n')
def main(a):
 s0=Path(a.stage0_dir).resolve(); p2a=Path(a.failed_p2a_dir).resolve(); out=Path(a.output_dir).resolve()
 if out.exists():raise ValueError(f'Refusing overwrite: {out}')
 out.mkdir(parents=True)
 checks=[]
 def ck(i,ok,obs,exp,layer):checks.append({'check_id':i,'passed':bool(ok),'observed':str(obs),'expected':str(exp),'failure_layer':layer})
 binding=s0/'exfil_stage0_manifest_external_binding_v1_0.json'; manifest=s0/'exfil_stage0_manifest_v1_0.csv'
 p2am=p2a/'v_renamed_source_design_manifest_v1_0.csv'; p2ae=p2a/'v_renamed_source_design_manifest_external_binding_v1_0.json'
 ck('VRR-001',binding.is_file(),str(binding),'Stage-0 external binding exists','FIXTURE')
 ck('VRR-002',manifest.is_file(),str(manifest),'Stage-0 manifest exists','FIXTURE')
 if not(binding.is_file() and manifest.is_file()): raise RuntimeError('Required Stage-0 parent artifacts missing')
 bid=ident(binding); mid=ident(manifest)
 ck('VRR-003',bid['sha256']==OBSERVED_STAGE0_BINDING_SHA,bid['sha256'],OBSERVED_STAGE0_BINDING_SHA,'FIXTURE')
 bj=json.loads(binding.read_text(encoding='utf-8-sig'))
 ck('VRR-004',bj.get('manifest_filename')==manifest.name,bj.get('manifest_filename'),manifest.name,'FIXTURE')
 ck('VRR-005',bj.get('manifest_sha256')==mid['sha256'],bj.get('manifest_sha256'),mid['sha256'],'FIXTURE')
 ck('VRR-006',mid['sha256']==EXPECTED_STAGE0_MANIFEST_SHA,mid['sha256'],EXPECTED_STAGE0_MANIFEST_SHA,'FIXTURE')
 ck('VRR-007',p2am.is_file() and sha(p2am)==FAILED_P2A_MANIFEST_SHA,ident(p2am) if p2am.is_file() else str(p2am),FAILED_P2A_MANIFEST_SHA,'FIXTURE')
 if p2ae.is_file():
  ej=json.loads(p2ae.read_text(encoding='utf-8-sig'))
  ck('VRR-008',ej.get('runner_sha256')==FAILED_P2A_RUNNER_SHA,ej.get('runner_sha256'),FAILED_P2A_RUNNER_SHA,'FIXTURE')
  ck('VRR-009',ej.get('failed_ids')==['VR-004'],ej.get('failed_ids'),['VR-004'],'FIXTURE')
 else:
  ck('VRR-008',False,str(p2ae),'failed P2A external binding exists','FIXTURE');ck('VRR-009',False,str(p2ae),'failed P2A external binding exists','FIXTURE')
 failed=[x['check_id'] for x in checks if not x['passed']]; status='COMPLETE_PASS' if not failed else 'BLOCKED'
 result={'version':VERSION,'created_at_utc':datetime.now(timezone.utc).isoformat(),'status':status,'checks':{'total':len(checks),'passed':len(checks)-len(failed),'failed':len(failed),'failed_ids':failed},'reconciliation':{'stage0_external_binding':bid,'stage0_manifest':mid,'binding_manifest_filename':bj.get('manifest_filename'),'binding_manifest_sha256':bj.get('manifest_sha256'),'identity_type_error_in_failed_p2a':'CONFIRMED' if status=='COMPLETE_PASS' else 'NOT_FULLY_RECONCILED'},'execution_boundaries':{'read_only':True,'model_executed':False,'sdk_executed':False,'sandbox_executed':False,'gym_executed':False,'tool_executed':False,'guardrail_executed':False,'predicate_executed':False,'breach_executed':False,'fixture_mutated':False,'attack_optimization':False},'claim_boundary':{'allowed':['Stage-0 external-binding identity independently established','Stage-0 manifest identity independently established','external binding filename and manifest SHA relationship verified','VR-004 classified as parent artifact identity-type comparison defect if all checks pass'],'prohibited':['failed P2A v1.0 becomes PASS','renamed-source treatment qualified','runtime behavior','model behavior','guardrail behavior','predicate or breach result','robust security','hosted parity']},'next_gate':'V_RENAMED_SOURCE_FIXTURE_AND_RUNTIME_PREFLIGHT' if status=='COMPLETE_PASS' else 'V_RENAMED_SOURCE_DESIGN_REVIEW_STOP'}
 paths={'result':out/'v_renamed_source_design_review_result_v1_0.json','checks':out/'v_renamed_source_design_review_checks_v1_0.csv'};wj(paths['result'],result)
 with paths['checks'].open('x',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=['check_id','passed','observed','expected','failure_layer']);w.writeheader();w.writerows(checks)
 rows=[]
 for role,p in paths.items():rows.append({**ident(p),'role':role.upper()})
 for role,p in [('STAGE0_EXTERNAL_BINDING',binding),('STAGE0_MANIFEST',manifest),('FAILED_P2A_MANIFEST',p2am),('FAILED_P2A_EXTERNAL_BINDING',p2ae)]:
  if p.is_file():rows.append({**ident(p),'role':role})
 runner=Path(__file__).resolve();rows.append({**ident(runner),'role':'RUNNER'})
 man=out/'v_renamed_source_design_review_manifest_v1_0.csv'
 with man.open('x',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=['artifact','role','size_bytes','sha256','path']);w.writeheader();w.writerows(rows)
 ext=out/'v_renamed_source_design_review_manifest_external_binding_v1_0.json';wj(ext,{'version':VERSION,'status':status,'manifest_filename':man.name,'manifest_sha256':sha(man),'runner_sha256':sha(runner),'failed_ids':failed,'next_gate':result['next_gate']})
 print(json.dumps({'status':status,'checks':f"{len(checks)-len(failed)}/{len(checks)}",'failed_ids':failed,'stage0_external_binding_sha256':bid['sha256'],'stage0_manifest_sha256':mid['sha256'],'manifest_sha256':sha(man),'next_gate':result['next_gate']},indent=2))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--stage0-dir',required=True);p.add_argument('--failed-p2a-dir',required=True);p.add_argument('--output-dir',required=True)
 try:main(p.parse_args())
 except Exception as e:print('FAILED:',e,file=sys.stderr);raise SystemExit(1)
