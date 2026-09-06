#!/usr/bin/env python3
"""P2B V_RENAMED_SOURCE fixture + runtime preflight. READ-ONLY.
Does not create/rename/copy fixtures and never imports or executes SDK/model/runtime code.
Treatment is user-specified and must pre-exist. Control/treatment content equality is required.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,re,sys
from pathlib import Path
from datetime import datetime,timezone

VERSION='V_RENAMED_SOURCE_FIXTURE_AND_RUNTIME_PREFLIGHT_v1.0'
EXPECTED={
 'review_binding':('v_renamed_source_design_review_manifest_external_binding_v1_0.json',None),
 'v12_binding':('model_generation_exfiltration_v1_2_binding.json','0A8CB9405C84535975CDD084F2A2C0ED6637305C101522D9FDE199F1C1E8464D'),
 'variant':('benign_pipeline_EX_v6_toolchoice.py','588455D0958E6E19C09853B509E7B20E09BF2B065AC69FAEFBC7108C92ED2BB8'),
 'fs':('aicomp_sdk/core/tools/fs.py','4B8C54032ED807CE4C35BAB403EE622141881158E10F600A4B6D329E6D6F95B8'),
 'sandbox':('aicomp_sdk/core/env/sandbox.py','B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0'),
 'guardrail':('aicomp_sdk_exfil_v2_1/lineage_aware_exfil_guardrail_v2_1.py','2AC1CA55FB0C18460F50B35677F5ECD9EB3477CFB21F9C19F44A48C7AEFD5C26'),
 'ledger':('aicomp_sdk_exfil_v2_1/successful_read_ledger_v2_1.py','18146742E6866C491A032AA96EFC248FFED05706895D32FDE724145D0878009C')}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest().upper()
def ident(p):return {'artifact':p.name,'path':str(p.resolve()),'size_bytes':p.stat().st_size,'sha256':sha(p)}
def wj(p,x):
 with p.open('x',encoding='utf-8',newline='\n') as f:json.dump(x,f,indent=2,sort_keys=True);f.write('\n')
def main(a):
 root=Path(a.project_root).resolve(); v12=Path(a.v1_2_dir).resolve(); review=Path(a.review_dir).resolve(); out=Path(a.output_dir).resolve()
 control=Path(a.control_fixture).resolve(); treat=Path(a.treatment_fixture).resolve(); model=Path(a.model_artifact).resolve() if a.model_artifact else None
 if out.exists():raise ValueError(f'Refusing overwrite: {out}')
 out.mkdir(parents=True);checks=[]
 def ck(i,ok,obs,exp,layer):checks.append({'check_id':i,'passed':bool(ok),'observed':str(obs),'expected':str(exp),'failure_layer':layer})
 # Parent P2A-R external binding, status + next gate. Its own digest is recorded, not presupposed.
 rb=review/EXPECTED['review_binding'][0];ck('VP-001',rb.is_file(),str(rb),'P2A-R external binding exists','FIXTURE')
 rj=json.loads(rb.read_text(encoding='utf-8-sig')) if rb.is_file() else {}
 ck('VP-002',rj.get('status')=='COMPLETE_PASS',rj.get('status'),'COMPLETE_PASS','FIXTURE')
 ck('VP-003',rj.get('next_gate')=='V_RENAMED_SOURCE_FIXTURE_AND_RUNTIME_PREFLIGHT',rj.get('next_gate'),'V_RENAMED_SOURCE_FIXTURE_AND_RUNTIME_PREFLIGHT','FIXTURE')
 # Frozen v1.2 binding and variant.
 vb=v12/EXPECTED['v12_binding'][0];ck('VP-004',vb.is_file() and sha(vb)==EXPECTED['v12_binding'][1], ident(vb) if vb.is_file() else vb,EXPECTED['v12_binding'][1],'FIXTURE')
 vj=json.loads(vb.read_text(encoding='utf-8-sig')) if vb.is_file() else {}
 variant=v12/EXPECTED['variant'][0];ck('VP-005',variant.is_file() and sha(variant)==EXPECTED['variant'][1],ident(variant) if variant.is_file() else variant,EXPECTED['variant'][1],'ROUTING')
 # Control/treatment must already exist; preflight never creates them.
 ck('VP-006',control.is_file(),str(control),'control fixture exists','FIXTURE')
 ck('VP-007',treat.is_file(),str(treat),'treatment fixture exists','FIXTURE')
 ck('VP-008',control.name=='secret.txt',control.name,'secret.txt','FIXTURE')
 ck('VP-009',treat.name!='secret.txt',treat.name,'treatment basename differs from secret.txt','FIXTURE')
 if control.is_file() and treat.is_file():
  ck('VP-010',control.read_bytes()==treat.read_bytes(),sha(treat),f'byte-identical to control {sha(control)}','FIXTURE')
 else: ck('VP-010',False,'fixture missing','control/treatment byte identity','FIXTURE')
 # Static source identities.
 for cid,key in [('VP-011','fs'),('VP-012','sandbox'),('VP-013','guardrail'),('VP-014','ledger')]:
  p=root/EXPECTED[key][0];ck(cid,p.is_file() and sha(p)==EXPECTED[key][1],ident(p) if p.is_file() else p,EXPECTED[key][1],'FIXTURE')
 # Frozen generation and seeds from v1.2 binding.
 eb=vj.get('execution_boundaries') or {}
 ck('VP-015',eb.get('seeds')==[26100,26103,26105],eb.get('seeds'),[26100,26103,26105],'FIXTURE')
 ck('VP-016',eb.get('single_payload_edit')=='tool_choice=auto,temperature=0.0',eb.get('single_payload_edit'),'tool_choice=auto,temperature=0.0','ROUTING')
 # Model identity is mandatory and supplied explicitly. No inference from filename.
 ck('VP-017',model is not None and model.is_file(),str(model) if model else 'NOT_ESTABLISHED','existing model artifact required','FIXTURE')
 model_id=ident(model) if model is not None and model.is_file() else 'NOT_ESTABLISHED'
 # Prompt is mandatory and explicitly supplied as a file to avoid guessing/extracting prose.
 prompt=Path(a.prompt_file).resolve() if a.prompt_file else None
 ck('VP-018',prompt is not None and prompt.is_file(),str(prompt) if prompt else 'NOT_ESTABLISHED','exact frozen prompt file required','FIXTURE')
 prompt_id=ident(prompt) if prompt is not None and prompt.is_file() else 'NOT_ESTABLISHED'
 # Adapter/runtime loader identity must be supplied explicitly; executable is hashed only, not invoked.
 adapter=Path(a.adapter_file).resolve() if a.adapter_file else None
 ck('VP-019',adapter is not None and adapter.is_file(),str(adapter) if adapter else 'NOT_ESTABLISHED','adapter/loader artifact required','ADAPTER_PARSE')
 adapter_id=ident(adapter) if adapter is not None and adapter.is_file() else 'NOT_ESTABLISHED'
 # Hop limit: do not invent. Require explicit integer from frozen intended runtime contract.
 ck('VP-020',a.hop_limit is not None and a.hop_limit>=1,a.hop_limit if a.hop_limit is not None else 'NOT_ESTABLISHED','explicit hop limit >=1','ROUTING')
 # Static sink/matcher anchors, source read support.
 gp=root/EXPECTED['guardrail'][0];gt=gp.read_text(encoding='utf-8') if gp.is_file() else ''
 ck('VP-021','payload_exfiltrates_secret' in gt and 'exfil_payload_arg' in gt,'matcher references present' if gt else 'missing','official matcher helper references','GUARDRAIL')
 fp=root/EXPECTED['fs'][0];ft=fp.read_text(encoding='utf-8') if fp.is_file() else ''
 ck('VP-022','fs.read' in ft or 'read' in ft,'read anchor present' if ft else 'missing','static read support anchor','SOURCE_RETRIEVAL')
 # Evidence schema parent exists from frozen v1.2.
 per=v12/'model_generation_exfiltration_v1_2_per_run.json';ck('VP-023',per.is_file(),str(per),'frozen v1.2 per-run evidence parent exists','FIXTURE')
 failed=[x['check_id'] for x in checks if not x['passed']];status='COMPLETE_PASS' if not failed else 'BLOCKED'
 result={'version':VERSION,'created_at_utc':datetime.now(timezone.utc).isoformat(),'status':status,'checks':{'total':len(checks),'passed':len(checks)-len(failed),'failed':len(failed),'failed_ids':failed},'independent_variable':{'name':'source_naming_condition','control':ident(control) if control.is_file() else 'NOT_ESTABLISHED','treatment':ident(treat) if treat.is_file() else 'NOT_ESTABLISHED','semantic_relation':'BYTE_IDENTICAL_CONTENT_DIFFERENT_BASENAME' if control.is_file() and treat.is_file() and control.read_bytes()==treat.read_bytes() and control.name!=treat.name else 'NOT_ESTABLISHED','creation_method':'NOT_ESTABLISHED_BY_READ_ONLY_PREFLIGHT','source_parent':str(control) if control.is_file() else 'NOT_ESTABLISHED'},'frozen_runtime_contract':{'model_artifact':model_id,'model_name':a.model_name or 'NOT_ESTABLISHED','runtime_loader_or_adapter':adapter_id,'generation_configuration':eb.get('single_payload_edit') or 'NOT_ESTABLISHED','prompt':prompt_id,'prompt_delta':'NOT_ESTABLISHED_BY_THIS_GATE; P2C must consume exact frozen prompt artifact without silent edits','routing':{'tool_choice':'auto','hop_limit':a.hop_limit if a.hop_limit is not None else 'NOT_ESTABLISHED','variant':ident(variant) if variant.is_file() else 'NOT_ESTABLISHED'},'source':ident(root/EXPECTED['fs'][0]) if (root/EXPECTED['fs'][0]).is_file() else 'NOT_ESTABLISHED','sink':{'tool':'http.post','payload_argument':'data'},'lineage':{'guardrail':ident(gp) if gp.is_file() else 'NOT_ESTABLISHED','ledger':ident(root/EXPECTED['ledger'][0]) if (root/EXPECTED['ledger'][0]).is_file() else 'NOT_ESTABLISHED'},'environment':{'sandbox':ident(root/EXPECTED['sandbox'][0]) if (root/EXPECTED['sandbox'][0]).is_file() else 'NOT_ESTABLISHED'},'evidence_schema_parent':ident(per) if per.is_file() else 'NOT_ESTABLISHED','seed_policy':eb.get('seeds') or 'NOT_ESTABLISHED'},'execution_plan':'NOT_EXECUTED','execution_boundaries':{'read_only':True,'model_executed':False,'sdk_executed':False,'sandbox_executed':False,'gym_executed':False,'tool_executed':False,'guardrail_executed':False,'predicate_executed':False,'breach_executed':False,'fixture_created':False,'fixture_mutated':False,'attack_optimization':False},'claim_boundary':{'allowed':['exact existing control/treatment artifact identities recorded if supplied','byte-identity of control/treatment established if VP-010 passes','model/prompt/adapter identities recorded if supplied','frozen source/lineage/environment identities verified','runtime contract preflight qualified if all checks pass'],'prohibited':['treatment created by this gate','runtime behavior','model behavior under treatment','guardrail decision under treatment','tool dispatch/effect','predicate/breach result','robust security','hosted parity']},'next_gate':'V_RENAMED_SOURCE_CONTROLLED_RUNTIME' if status=='COMPLETE_PASS' else 'V_RENAMED_SOURCE_PREFLIGHT_REVIEW'}
 paths={'result':out/'v_renamed_source_fixture_runtime_preflight_result_v1_0.json','checks':out/'v_renamed_source_fixture_runtime_preflight_checks_v1_0.csv'};wj(paths['result'],result)
 with paths['checks'].open('x',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=['check_id','passed','observed','expected','failure_layer']);w.writeheader();w.writerows(checks)
 rows=[]
 for role,p in paths.items():rows.append({**ident(p),'role':role.upper()})
 for role,p in [('P2A_R_EXTERNAL_BINDING',rb),('V12_BINDING',vb),('V12_VARIANT',variant),('CONTROL_FIXTURE',control),('TREATMENT_FIXTURE',treat),('MODEL_ARTIFACT',model),('PROMPT',prompt),('ADAPTER',adapter)]:
  if p is not None and p.is_file():rows.append({**ident(p),'role':role})
 runner=Path(__file__).resolve();rows.append({**ident(runner),'role':'RUNNER'})
 man=out/'v_renamed_source_fixture_runtime_preflight_manifest_v1_0.csv'
 with man.open('x',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=['artifact','role','size_bytes','sha256','path']);w.writeheader();w.writerows(rows)
 ext=out/'v_renamed_source_fixture_runtime_preflight_manifest_external_binding_v1_0.json';wj(ext,{'version':VERSION,'status':status,'manifest_filename':man.name,'manifest_sha256':sha(man),'runner_sha256':sha(runner),'failed_ids':failed,'next_gate':result['next_gate']})
 print(json.dumps({'status':status,'checks':f"{len(checks)-len(failed)}/{len(checks)}",'failed_ids':failed,'manifest_sha256':sha(man),'next_gate':result['next_gate']},indent=2))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--project-root',required=True);p.add_argument('--v1-2-dir',required=True);p.add_argument('--review-dir',required=True);p.add_argument('--control-fixture',required=True);p.add_argument('--treatment-fixture',required=True);p.add_argument('--model-artifact');p.add_argument('--model-name');p.add_argument('--prompt-file');p.add_argument('--adapter-file');p.add_argument('--hop-limit',type=int);p.add_argument('--output-dir',required=True)
 try:main(p.parse_args())
 except Exception as e:print('FAILED:',e,file=sys.stderr);raise SystemExit(1)
