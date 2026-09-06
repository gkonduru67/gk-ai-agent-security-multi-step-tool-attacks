#!/usr/bin/env python3
"""EX5.7 one-variable output-completion intervention.

Loads the frozen benign_pipeline_EX_v6.py by file path and SHA-256, then injects
exactly one OpenAI-compatible request field: reasoning_effort='none'. The frozen
EX5 prompt, model, server, pipeline behavior, tools, GuardrailBase, max_tool_hops,
and response budget remain controlled by the frozen pipeline invocation.
"""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,sys
from pathlib import Path
VERSION='EX5_7_LLAMA_SERVER_REASONING_OUTPUT_SINGLE_INTERVENTION_v5.70'
PIPELINE_SHA='88970AC7329F6BB25351DEFF1FB6F3E81F2148EFEA20CEEE43AEC45B1C398DF9'
def hf(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--pipeline',required=True,type=Path);ap.add_argument('--project-root',required=True,type=Path);ap.add_argument('--model-path',required=True,type=Path);ap.add_argument('--server-url',default='http://127.0.0.1:8080');ap.add_argument('--out-root',required=True,type=Path);ap.add_argument('--max-new-tokens',type=int,default=1024);ap.add_argument('--max-tool-hops',type=int,default=2);a=ap.parse_args();p=a.pipeline.resolve()
 if hf(p)!=PIPELINE_SHA:ap.error('Frozen pipeline SHA-256 mismatch')
 spec=importlib.util.spec_from_file_location('frozen_ex_pipeline',p);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 original=mod.http_json;calls={'count':0}
 def intervened_http_json(url,payload,timeout=300):
  if url.rstrip('/').endswith('/v1/chat/completions'):
   if 'reasoning_effort' in payload:raise RuntimeError('reasoning_effort already present; baseline not clean')
   payload=dict(payload);payload['reasoning_effort']='none';calls['count']+=1
  return original(url,payload,timeout)
 mod.http_json=intervened_http_json
 sys.argv=[str(p),'--project-root',str(a.project_root.resolve()),'--model-path',str(a.model_path.resolve()),'--server-url',a.server_url,'--out-root',str(a.out_root.resolve()),'--mode','ex5-frozen','--max-new-tokens',str(a.max_new_tokens),'--max-tool-hops',str(a.max_tool_hops)]
 rc=mod.main()
 print(json.dumps({'version':VERSION,'frozen_pipeline_sha256':PIPELINE_SHA,'changed_variable_count':1,'intervention_field':'reasoning_effort','intervention_value':'none','chat_completion_requests_modified':calls['count'],'attack_optimization_authorized':False},indent=2))
 return rc
if __name__=='__main__':raise SystemExit(main())
