#!/usr/bin/env python3
"""EX5.7C exact replication with trace and intervention persistence.

Loads the frozen benign_pipeline_EX_v6.py after SHA-256 verification. Applies the
single request intervention reasoning_effort='none', captures the exact object
passed to official predicate evaluation, and writes exported_trace.json plus
intervention_record.json before the child manifest is generated.

No prompt optimization, guardrail change, tool substitution, trace mutation, or
synthetic event creation is performed.
"""
from __future__ import annotations
import argparse,datetime as dt,hashlib,importlib,importlib.util,json,sys
from pathlib import Path
from typing import Any
VERSION='EX5_7C_TRACE_PERSISTENCE_REPLICATION_v5.73'
PIPELINE_SHA='88970AC7329F6BB25351DEFF1FB6F3E81F2148EFEA20CEEE43AEC45B1C398DF9'
PROMPT_SHA='3F8BA146E8B3DEDD45EBB4D276A6D55F0BEC8C7C0EFAC2B272B3B21239635176'
MODEL_SHA='C27536640E410032865DC68781D80A08B98F8DB5E93575919AF8CCC0568AEB4F'
def hb(b:bytes)->str:return hashlib.sha256(b).hexdigest().upper()
def hf(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def write_json_x(p:Path,v:Any):
 with p.open('x',encoding='utf-8') as f:json.dump(v,f,indent=2,sort_keys=True,default=str);f.write('\n')
def utc()->str:return dt.datetime.now(dt.timezone.utc).isoformat()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--pipeline',required=True,type=Path);ap.add_argument('--project-root',required=True,type=Path);ap.add_argument('--model-path',required=True,type=Path);ap.add_argument('--server-url',default='http://127.0.0.1:8080');ap.add_argument('--out-root',required=True,type=Path);ap.add_argument('--max-new-tokens',type=int,default=1024);ap.add_argument('--max-tool-hops',type=int,default=2);ap.add_argument('--server-epoch-binding',type=Path);ap.add_argument('--expected-server-epoch-sha256');a=ap.parse_args()
 pipeline=a.pipeline.resolve();model=a.model_path.resolve()
 if not pipeline.is_file() or hf(pipeline)!=PIPELINE_SHA:ap.error('Frozen pipeline SHA-256 mismatch')
 if not model.is_file() or hf(model)!=MODEL_SHA:ap.error('Frozen model SHA-256 mismatch')
 epoch_sha=None
 if a.server_epoch_binding:
  ep=a.server_epoch_binding.resolve()
  if not a.expected_server_epoch_sha256:ap.error('--expected-server-epoch-sha256 required with --server-epoch-binding')
  if not ep.is_file() or hf(ep)!=a.expected_server_epoch_sha256.upper():ap.error('Server epoch binding SHA-256 mismatch')
  epoch_sha=hf(ep)
 spec=importlib.util.spec_from_file_location('frozen_ex_pipeline',pipeline);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 predmod=importlib.import_module('aicomp_sdk.core.predicates');original_eval=predmod.eval_predicates;captured={'trace':None,'predicate_calls':0,'request_calls':0,'started_utc':utc()}
 def capture_eval(trace):
  if captured['trace'] is not None:raise RuntimeError('Official predicate evaluation invoked more than once')
  captured['trace']=trace;captured['predicate_calls']+=1
  return original_eval(trace)
 predmod.eval_predicates=capture_eval
 original_http=mod.http_json
 def intervened_http(url,payload,timeout=300):
  if url.rstrip('/').endswith('/v1/chat/completions'):
   if 'reasoning_effort' in payload:raise RuntimeError('Baseline request already contains reasoning_effort')
   payload=dict(payload);payload['reasoning_effort']='none';captured['request_calls']+=1
  return original_http(url,payload,timeout)
 mod.http_json=intervened_http
 original_dump=mod.dump
 def persistence_dump(path,obj):
  path=Path(path)
  if path.name=='summary.json':
   if captured['trace'] is None:raise RuntimeError('Exact exported trace was not captured before summary persistence')
   out=path.parent;trace_path=out/'exported_trace.json';intervention_path=out/'intervention_record.json'
   write_json_x(trace_path,captured['trace'])
   record={'schema':'EX5_7C_INTERVENTION_V5_73','version':VERSION,'changed_variable_count':1,'intervention_field':'reasoning_effort','intervention_value':'none','chat_completion_requests_modified':captured['request_calls'],'official_predicate_calls_captured':captured['predicate_calls'],'pipeline_sha256':PIPELINE_SHA,'prompt_sha256':PROMPT_SHA,'model_sha256':MODEL_SHA,'server_epoch_binding_sha256':epoch_sha,'max_new_tokens':a.max_new_tokens,'max_tool_hops':a.max_tool_hops,'started_utc':captured['started_utc'],'completed_utc':utc(),'attack_optimization_authorized':False}
   write_json_x(intervention_path,record)
   obj=dict(obj);obj.update({'experiment_version':VERSION,'exported_trace_sha256':hf(trace_path),'intervention_record_sha256':hf(intervention_path),'intervention_applied':captured['request_calls']>0,'intervention_field':'reasoning_effort','intervention_value':'none','server_epoch_binding_sha256':epoch_sha})
  return original_dump(path,obj)
 mod.dump=persistence_dump
 sys.argv=[str(pipeline),'--project-root',str(a.project_root.resolve()),'--model-path',str(model),'--server-url',a.server_url,'--out-root',str(a.out_root.resolve()),'--mode','ex5-frozen','--max-new-tokens',str(a.max_new_tokens),'--max-tool-hops',str(a.max_tool_hops)]
 rc=mod.main()
 if captured['request_calls']<1:raise RuntimeError('No chat-completions request received the intervention')
 return rc
if __name__=='__main__':raise SystemExit(main())
