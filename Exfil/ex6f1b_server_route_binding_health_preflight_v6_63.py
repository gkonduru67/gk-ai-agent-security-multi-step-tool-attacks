#!/usr/bin/env python3
"""EX6F.1B server-route binding and non-generative health preflight.

Validates frozen evidence and the server-backed EX pipeline, binds its source,
checks that the configured local endpoint responds to a non-generative health or
models request, and optionally verifies the endpoint's reported model identity.
It never sends a chat/completions request, constructs SandboxEnv, executes a
prompt/tool, or modifies the packaged SDK.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, urllib.error, urllib.request
from pathlib import Path
from typing import Any

VERSION='EX6F_1B_SERVER_ROUTE_BINDING_HEALTH_PREFLIGHT_v6.63'
EXPECTED_PARENT='BCB709724588F5F9ACFABC1073A83CFEB386C7B3C0D265E60AB4BFADEDBF4E0A'
EXPECTED_MODEL='C27536640E410032865DC68781D80A08B98F8DB5E93575919AF8CCC0568AEB4F'

def hf(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def hs(s:str)->str:return hashlib.sha256(s.encode('utf-8')).hexdigest().upper()
def dumpx(p:Path,v:Any):
 with p.open('x',encoding='utf-8') as f:json.dump(v,f,indent=2,sort_keys=True,default=str);f.write('\n')
def csvout(p:Path,fields:list[str],rows:list[dict[str,Any]]):
 with p.open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='raise');w.writeheader();w.writerows(rows)
def inspect_runner(p:Path)->dict[str,Any]:
 t=p.read_text(encoding='utf-8',errors='replace');tree=ast.parse(t);classes=[];funcs=[];urls=[];calls=[]
 for n in ast.walk(tree):
  if isinstance(n,ast.ClassDef):classes.append(n.name)
  elif isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):funcs.append(n.name)
  elif isinstance(n,ast.Constant) and isinstance(n.value,str) and ('/v1/' in n.value or '127.0.0.1' in n.value):urls.append(n.value)
  elif isinstance(n,ast.Call):
   src=ast.get_source_segment(t,n) or ''
   if any(k in src for k in ('LlamaServerBackend','GPTOSSAgent','HFGenerationResponse','chat/completions')):calls.append({'line':n.lineno,'source_sha256':hs(src)})
 return {'sha256':hf(p),'classes':sorted(set(classes)),'functions':sorted(set(funcs)),'url_literals':sorted(set(urls)),'relevant_calls':calls,'has_server_backend':'LlamaServerBackend' in classes,'has_agent_factory':'make_agent_factory' in funcs,'has_chat_completions':'/v1/chat/completions' in t,'has_transport_hash_capture':'body_sha256' in t and 'request_sha256' in t}
def get(url:str,timeout:float)->dict[str,Any]:
 req=urllib.request.Request(url,headers={'Accept':'application/json'},method='GET')
 try:
  with urllib.request.urlopen(req,timeout=timeout) as r:
   body=r.read();text=body.decode('utf-8','replace')
   try:obj=json.loads(text)
   except Exception:obj=None
   return {'url_path':'/'+url.split('/',3)[-1] if '/' in url[8:] else '/','ok':True,'status':r.status,'content_type':r.headers.get('Content-Type'),'body_size':len(body),'body_sha256':hashlib.sha256(body).hexdigest().upper(),'json':obj}
 except urllib.error.HTTPError as e:
  body=e.read();return {'url_path':'/'+url.split('/',3)[-1],'ok':False,'status':e.code,'body_size':len(body),'body_sha256':hashlib.sha256(body).hexdigest().upper(),'error_type':'HTTPError'}
 except Exception as e:return {'url_path':'/'+url.split('/',3)[-1],'ok':False,'status':None,'body_size':0,'body_sha256':None,'error_type':type(e).__name__,'error_sha256':hs(f'{type(e).__name__}:{e}')}
def model_ids(obj:Any)->list[str]:
 out=[]
 if isinstance(obj,dict):
  for k,v in obj.items():
   if k in ('id','model','model_id') and isinstance(v,str):out.append(v)
   else:out.extend(model_ids(v))
 elif isinstance(obj,list):
  for x in obj:out.extend(model_ids(x))
 return sorted(set(out))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--parent-manifest',required=True,type=Path);ap.add_argument('--parent-binding',required=True,type=Path);ap.add_argument('--pipeline-source',required=True,type=Path);ap.add_argument('--historical-pipeline-source',type=Path);ap.add_argument('--model-artifact',required=True,type=Path);ap.add_argument('--server-url',default='http://127.0.0.1:8080');ap.add_argument('--expected-server-model-id');ap.add_argument('--timeout-s',type=float,default=10.0);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 if not a.parent_manifest.is_file() or hf(a.parent_manifest)!=EXPECTED_PARENT:ap.error('Parent manifest mismatch')
 if not a.parent_binding.is_file() or json.loads(a.parent_binding.read_text(encoding='utf-8')).get('manifest_sha256')!=hf(a.parent_manifest):ap.error('Parent binding mismatch')
 if not a.pipeline_source.is_file():ap.error('Pipeline source missing')
 if a.historical_pipeline_source and not a.historical_pipeline_source.is_file():ap.error('Historical pipeline source missing')
 if not a.model_artifact.is_file() or hf(a.model_artifact)!=EXPECTED_MODEL:ap.error('Frozen model identity mismatch')
 report=inspect_runner(a.pipeline_source);historical=inspect_runner(a.historical_pipeline_source) if a.historical_pipeline_source else None
 base=a.server_url.rstrip('/');checks=[get(base+'/health',a.timeout_s),get(base+'/v1/models',a.timeout_s)]
 ids=model_ids(next((x['json'] for x in checks if x['url_path'].endswith('/v1/models') and x.get('json') is not None),None))
 endpoint_reachable=any(x['ok'] for x in checks);model_id_match=(a.expected_server_model_id in ids) if a.expected_server_model_id else None
 source_ready=report['has_server_backend'] and report['has_agent_factory'] and report['has_chat_completions'] and report['has_transport_hash_capture']
 if not source_ready:classification='SERVER_PIPELINE_SOURCE_CONTRACT_INCOMPLETE'
 elif not endpoint_reachable:classification='SERVER_PIPELINE_BOUND_ENDPOINT_NOT_REACHABLE'
 elif a.expected_server_model_id and not model_id_match:classification='SERVER_REACHABLE_REPORTED_MODEL_ID_MISMATCH'
 elif not a.expected_server_model_id:classification='SERVER_REACHABLE_MODEL_ID_NOT_BOUND'
 else:classification='SERVER_ROUTE_HEALTH_AND_REPORTED_MODEL_ID_PREFLIGHT_PASS'
 runtime_auth=classification=='SERVER_ROUTE_HEALTH_AND_REPORTED_MODEL_ID_PREFLIGHT_PASS'
 q={'schema':'EX6F_1B_V6_63','version':VERSION,'classification':classification,'execution_type':'NON_GENERATIVE_SERVER_HEALTH_AND_SOURCE_BINDING_PREFLIGHT','pipeline_source':{'filename':a.pipeline_source.name,'sha256':hf(a.pipeline_source),'contract':report},'historical_pipeline_source':None if not a.historical_pipeline_source else {'filename':a.historical_pipeline_source.name,'sha256':hf(a.historical_pipeline_source),'contract':historical},'model_artifact':{'filename':a.model_artifact.name,'size_bytes':a.model_artifact.stat().st_size,'sha256':hf(a.model_artifact)},'server':{'base_url_sha256':hs(base),'health_checks':[{k:v for k,v in x.items() if k!='json'} for x in checks],'reported_model_ids_sha256':[hs(x) for x in ids],'reported_model_id_count':len(ids),'expected_model_id_sha256':hs(a.expected_server_model_id) if a.expected_server_model_id else None,'expected_model_id_match':model_id_match},'claim_boundaries':{'server_process_identity':'NOT_ESTABLISHED_BY_HTTP_HEALTH','server_loaded_model_bytes_equal_frozen_GGUF':'NOT_ESTABLISHED_BY_REPORTED_MODEL_ID','server_transport_reachable':endpoint_reachable,'chat_generation':'NOT_TESTED','Sandbox':'NOT_CONSTRUCTED','EX6F_matrix':'NOT_EXECUTED'},'runtime_runner_development_authorized':runtime_auth,'chat_generation_authorized':False,'SDK_imported':False,'model_loaded_by_this_runner':False,'chat_completion_called':False,'Sandbox_constructed':False,'tool_execution':False,'harness_trick':'NOT_DEMONSTRATED','security_finding':'NOT_ESTABLISHED','attack_optimization_authorized':False,'hardened_policy_implementation_authorized':False}
 out.mkdir(parents=True);dumpx(out/'ex6f1b_preflight.json',q);csvout(out/'ex6f1b_health_checks.csv',['url_path','ok','status','content_type','body_size','body_sha256','error_type','error_sha256'],[{k:x.get(k) for k in ('url_path','ok','status','content_type','body_size','body_sha256','error_type','error_sha256')} for x in checks]);dumpx(out/'ex6f1b_pipeline_contract.json',{'current':report,'historical':historical})
 src=[a.parent_manifest,a.parent_binding,a.pipeline_source,a.model_artifact,Path(__file__).resolve()]+([a.historical_pipeline_source] if a.historical_pipeline_source else []);mr=[{'artifact':p.name,'role':'SOURCE_OR_PARENT','size_bytes':p.stat().st_size,'sha256':hf(p)} for p in src]
 for p in out.iterdir():
  if p.is_file():mr.append({'artifact':p.name,'role':'DERIVED','size_bytes':p.stat().st_size,'sha256':hf(p)})
 mp=out/'ex6f1b_manifest.csv';csvout(mp,['artifact','role','size_bytes','sha256'],mr);dumpx(out/'ex6f1b_manifest_external_binding.json',{'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':hf(mp),'binding_scope':'EXTERNAL_SELF_BINDING_RECORD'});print(json.dumps({'version':VERSION,'classification':classification,'runtime_runner_development_authorized':runtime_auth,'chat_generation_authorized':False,'manifest_sha256':hf(mp)},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
