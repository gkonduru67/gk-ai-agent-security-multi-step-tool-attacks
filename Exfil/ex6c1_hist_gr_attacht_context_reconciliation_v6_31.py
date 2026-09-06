#!/usr/bin/env python3
"""EX6C.1 read-only historical guardrail attachment/context reconciliation.

Inspects an exact historical runner, run directory, summary, exported trace, and
current SDK sources without importing or executing the historical runner or SDK.
It uses AST/source inspection plus artifact hashes to determine whether the
historical SandboxEnv constructor proves a guardrail attachment, which class can
be resolved, whether hooks/snapshot/restore/preloaded-trace paths are present,
and which conclusions remain unproven.
"""
from __future__ import annotations
import argparse,ast,csv,hashlib,json,re
from pathlib import Path
from typing import Any
VERSION='EX6C_1_HISTORICAL_GUARDRAIL_ATTACHMENT_CONTEXT_RECONCILIATION_v6.31'
TRACE_SHA='1E1C0E55DA94865EFDD32D175B59C196833F84423DEF3DBBC40126A1C405C522'
RUNNER_SHA='88970AC7329F6BB25351DEFF1FB6F3E81F2148EFEA20CEEE43AEC45B1C398DF9'
CURRENT={'sandbox.py':'B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0','optimal.py':'6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED','predicates.py':'9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37'}
def hf(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def hs(s:str)->str:return hashlib.sha256(s.encode()).hexdigest().upper()
def dumpx(p:Path,v:Any):
 with p.open('x',encoding='utf-8') as f:json.dump(v,f,indent=2,sort_keys=True,default=str);f.write('\n')
def csvout(p:Path,fields:list[str],rows:list[dict[str,Any]]):
 with p.open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='raise');w.writeheader();w.writerows(rows)
def srcseg(text:str,n:ast.AST)->dict[str,Any]:
 s=ast.get_source_segment(text,n) or ''
 return {'start_line':getattr(n,'lineno',None),'end_line':getattr(n,'end_lineno',None),'source_sha256':hs(s),'source':s}
def name_of(n:ast.AST|None)->str|None:
 if isinstance(n,ast.Name):return n.id
 if isinstance(n,ast.Attribute):
  p=name_of(n.value);return f'{p}.{n.attr}' if p else n.attr
 if isinstance(n,ast.Call):return name_of(n.func)
 return None
def inspect_runner(p:Path)->dict[str,Any]:
 text=p.read_text(encoding='utf-8');tree=ast.parse(text);imports=[];assigns={};sandbox=[];calls=[]
 for n in ast.walk(tree):
  if isinstance(n,ast.Import):
   for x in n.names:imports.append({'module':x.name,'alias':x.asname})
  elif isinstance(n,ast.ImportFrom):
   for x in n.names:imports.append({'module':n.module,'symbol':x.name,'alias':x.asname})
  elif isinstance(n,(ast.Assign,ast.AnnAssign)):
   targets=n.targets if isinstance(n,ast.Assign) else [n.target];value=n.value
   for t in targets:
    if isinstance(t,ast.Name):assigns[t.id]={'constructor':name_of(value),'segment':srcseg(text,n)}
  elif isinstance(n,ast.Call):
   fn=name_of(n.func);kw={k.arg:(name_of(k.value) or ast.get_source_segment(text,k.value) or '') for k in n.keywords if k.arg}
   item={'callee':fn,'keywords':kw,**srcseg(text,n)};calls.append(item)
   if fn and fn.endswith('SandboxEnv'):sandbox.append(item)
 tokens={t:[] for t in ('snapshot','restore','hook_registry','PRE_TOOL_CALL','trace.add_tool','ToolEvent','export_trace','guardrail','user_authorized','user_confirmed_safe','recent_sources')}
 for t in tokens:
  for m in re.finditer(re.escape(t),text,re.I):tokens[t].append(text.count('\n',0,m.start())+1)
 return {'sha256':hf(p),'size_bytes':p.stat().st_size,'imports':imports,'assignments':assigns,'sandbox_constructor_calls':sandbox,'relevant_calls':[x for x in calls if x['callee'] and any(k in x['callee'].lower() for k in ('sandbox','guardrail','hook','snapshot','restore','trace'))],'token_lines':tokens}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--historical-runner',required=True,type=Path);ap.add_argument('--historical-run-dir',required=True,type=Path);ap.add_argument('--historical-summary',required=True,type=Path);ap.add_argument('--historical-trace',required=True,type=Path);ap.add_argument('--current-sandbox',required=True,type=Path);ap.add_argument('--current-optimal',required=True,type=Path);ap.add_argument('--current-predicates',required=True,type=Path);ap.add_argument('--ex6c-manifest',required=True,type=Path);ap.add_argument('--ex6c-binding',required=True,type=Path);ap.add_argument('--launcher-record',type=Path);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 for p,n in [(a.historical_runner,'historical runner'),(a.historical_summary,'historical summary'),(a.historical_trace,'historical trace'),(a.current_sandbox,'current sandbox'),(a.current_optimal,'current optimal'),(a.current_predicates,'current predicates'),(a.ex6c_manifest,'EX6C manifest'),(a.ex6c_binding,'EX6C binding')]:
  if not p.is_file():ap.error(f'Missing {n}: {p}')
 if not a.historical_run_dir.is_dir():ap.error('Historical run directory missing')
 if hf(a.historical_runner)!=RUNNER_SHA:ap.error('Historical runner SHA-256 mismatch')
 if hf(a.historical_trace)!=TRACE_SHA:ap.error('Historical trace SHA-256 mismatch')
 for p in (a.current_sandbox,a.current_optimal,a.current_predicates):
  if hf(p)!=CURRENT[p.name]:ap.error(f'Current {p.name} SHA-256 mismatch')
 bind=json.loads(a.ex6c_binding.read_text(encoding='utf-8'))
 if bind.get('manifest_sha256')!=hf(a.ex6c_manifest):ap.error('EX6C manifest binding mismatch')
 summary=json.loads(a.historical_summary.read_text(encoding='utf-8'));trace=json.loads(a.historical_trace.read_text(encoding='utf-8'));ri=inspect_runner(a.historical_runner)
 constructor=ri['sandbox_constructor_calls'];guardrail_values=[x['keywords'].get('guardrail') for x in constructor if 'guardrail' in x['keywords']]
 guardrail_explicit=bool(guardrail_values);guardrail_expr=guardrail_values[0] if len(set(guardrail_values))==1 and guardrail_values else None
 resolved=None
 if guardrail_expr:
  root=guardrail_expr.split('.')[0];ass=ri['assignments'].get(root);resolved=ass.get('constructor') if ass else guardrail_expr
 imports=ri['imports'];resolved_import=[x for x in imports if (x.get('alias') or x.get('symbol')) in {guardrail_expr,resolved,guardrail_expr.split('.')[0] if guardrail_expr else None}]
 artifacts=[]
 for p in sorted(a.historical_run_dir.rglob('*')):
  if p.is_file():artifacts.append({'relative_path':str(p.relative_to(a.historical_run_dir)),'size_bytes':p.stat().st_size,'sha256':hf(p),'suffix':p.suffix.lower()})
 sdk_hash_rows=[r for r in artifacts if r['relative_path'].replace('\\','/').endswith(('sandbox.py','optimal.py','predicates.py'))]
 trace_events=trace.get('tool_events',[]);source=trace_events[0] if trace_events else {};sink=trace_events[1] if len(trace_events)>1 else {}
 findings={'historical_runner_identity_verified':True,'historical_trace_identity_verified':True,'historical_summary_runner_sha_matches':summary.get('runner_sha256')==RUNNER_SHA,'historical_summary_trace_sha_matches':summary.get('exported_trace_sha256')==TRACE_SHA,'SandboxEnv_constructor_found':bool(constructor),'guardrail_keyword_explicitly_supplied':guardrail_explicit,'guardrail_expression':guardrail_expr,'guardrail_constructor_or_symbol':resolved,'guardrail_import_resolution':resolved_import,'current_packaged_optimal_identity_claim_supported':bool(resolved and 'optimal' in str(resolved).lower() and 'guardrail' in str(resolved).lower()),'historical_SDK_hashes_found_in_run_directory':bool(sdk_hash_rows),'historical_successful_fs_read_present':source.get('name')=='fs.read' and source.get('ok') is True,'historical_successful_http_post_present':sink.get('name')=='http.post' and sink.get('ok') is True,'hook_or_snapshot_tokens_present':{k:v for k,v in ri['token_lines'].items() if k in ('snapshot','restore','hook_registry','PRE_TOOL_CALL','trace.add_tool','ToolEvent')},'authorization_flag_tokens_present':{k:v for k,v in ri['token_lines'].items() if k in ('user_authorized','user_confirmed_safe')},'raw_source_context_persisted':False}
 if not constructor:classification='HISTORICAL_RUNNER_SANDBOX_CONSTRUCTOR_NOT_FOUND'
 elif not guardrail_explicit:classification='HISTORICAL_SANDBOX_USED_DEFAULT_GUARDRAIL_PATH'
 elif findings['current_packaged_optimal_identity_claim_supported']:classification='HISTORICAL_PACKAGED_OPTIMAL_ATTACHMENT_SOURCE_SUPPORTED_RUNTIME_CONTEXT_UNRESOLVED'
 else:classification='HISTORICAL_GUARDRAIL_ATTACHMENT_PRESENT_CONCRETE_PACKAGED_IDENTITY_NOT_ESTABLISHED'
 report={'schema':'EX6C_1_RECONCILIATION_V1','version':VERSION,'execution_type':'READ_ONLY_STATIC_SOURCE_AND_ARTIFACT_INSPECTION','classification':classification,'findings':findings,'runner_inspection':ri,'historical_run_artifact_count':len(artifacts),'historical_sdk_hash_rows':sdk_hash_rows,'current_sdk_hashes':{p.name:hf(p) for p in (a.current_sandbox,a.current_optimal,a.current_predicates)},'historical_summary':{'experiment_version':summary.get('experiment_version'),'version':summary.get('version'),'mode':summary.get('mode'),'runner_sha256':summary.get('runner_sha256'),'exported_trace_sha256':summary.get('exported_trace_sha256'),'tool_event_count':summary.get('tool_event_count'),'breach':summary.get('breach')},'historical_trace_event_summary':[{'event_index':i,'name':e.get('name'),'args_sha256':hs(json.dumps(e.get('args',{}),sort_keys=True)),'ok':e.get('ok'),'source':e.get('source'),'scope':e.get('scope'),'side_effect':e.get('side_effect'),'error_present':e.get('error') is not None} for i,e in enumerate(trace_events)],'claim_boundaries':{'historical_guardrail_attached':guardrail_explicit,'historical_guardrail_concrete_class':resolved or 'NOT_ESTABLISHED','historical_guardrail_source_sha256':('SEE_HISTORICAL_SDK_HASH_ROWS' if sdk_hash_rows else 'NOT_ESTABLISHED'),'historical_source_guardrail_context':'NOT_PERSISTED_OR_NOT_IDENTIFIED','historical_trace_route_normal_execution':'NOT_ESTABLISHED_BY_TRACE_ALONE','historical_vs_current_SDK_epoch_parity':('COMPARE_HASH_ROWS' if sdk_hash_rows else 'NOT_ESTABLISHED'),'packaged_optimal_weakness':'NOT_ESTABLISHED'},'harness_trick':'NOT_DEMONSTRATED_BY_THIS_READ_ONLY_INSPECTION','new_security_finding':'NOT_TESTED','counterfactual_preseed_authorized':False,'hardened_policy_implementation_authorized':False,'attack_optimization_authorized':False}
 out.mkdir(parents=True);dumpx(out/'ex6c1_reconciliation.json',report);csvout(out/'ex6c1_historical_artifact_inventory.csv',['relative_path','size_bytes','sha256','suffix'],artifacts)
 evidence=[]
 for c in constructor:evidence.append({'evidence_type':'SandboxEnv_constructor','start_line':c['start_line'],'end_line':c['end_line'],'source_sha256':c['source_sha256'],'detail':json.dumps(c['keywords'],sort_keys=True)})
 for k,lines in ri['token_lines'].items():
  if lines:evidence.append({'evidence_type':f'token:{k}','start_line':min(lines),'end_line':max(lines),'source_sha256':'','detail':json.dumps(lines)})
 csvout(out/'ex6c1_source_evidence.csv',['evidence_type','start_line','end_line','source_sha256','detail'],evidence or [{'evidence_type':'NONE','start_line':'','end_line':'','source_sha256':'','detail':''}])
 sources=[a.historical_runner,a.historical_summary,a.historical_trace,a.current_sandbox,a.current_optimal,a.current_predicates,a.ex6c_manifest,a.ex6c_binding,Path(__file__).resolve()]
 if a.launcher_record:
  if not a.launcher_record.is_file():ap.error('Launcher record path supplied but missing')
  sources.append(a.launcher_record)
 mr=[{'artifact':p.name,'role':'SOURCE_OR_PARENT','size_bytes':p.stat().st_size,'sha256':hf(p)} for p in sources]
 for p in out.iterdir():
  if p.is_file():mr.append({'artifact':p.name,'role':'DERIVED','size_bytes':p.stat().st_size,'sha256':hf(p)})
 mp=out/'ex6c1_manifest.csv';csvout(mp,['artifact','role','size_bytes','sha256'],mr);dumpx(out/'ex6c1_manifest_external_binding.json',{'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':hf(mp),'binding_scope':'EXTERNAL_SELF_BINDING_RECORD'})
 print(json.dumps({'version':VERSION,'classification':classification,'guardrail_explicit':guardrail_explicit,'guardrail_symbol':resolved,'artifact_count':len(artifacts)},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
