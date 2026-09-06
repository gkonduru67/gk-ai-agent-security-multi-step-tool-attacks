#!/usr/bin/env python3
"""EX5.6A llama-server startup and props value binding.

Read-only. Captures explicit non-sensitive server configuration values from
/props, while retaining the full chat template only as length and SHA-256.
Optionally hash-binds the exact startup command evidence file and server binary.
No model execution, server mutation, prompt modification, or attack optimization.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,urllib.request
from pathlib import Path
from typing import Any
VERSION='EX5_6A_LLAMA_SERVER_STARTUP_AND_PROPS_VALUE_BINDING_v5.61'
SAFE_PATHS=(
 '$.default_generation_settings.params.chat_format',
 '$.default_generation_settings.params.reasoning_format',
 '$.default_generation_settings.params.reasoning_in_content',
 '$.default_generation_settings.params.max_tokens',
 '$.default_generation_settings.params.n_predict',
 '$.default_generation_settings.n_ctx',
 '$.chat_template_caps.supports_preserve_reasoning',
 '$.chat_template_caps.supports_parallel_tool_calls',
 '$.chat_template_caps.supports_tool_calls',
 '$.chat_template_caps.supports_tools',
 '$.chat_template_caps.supports_string_content',
 '$.chat_template_caps.supports_typed_content',
 '$.build_info',
 '$.model_alias',
 '$.model_ftype',
)
def hb(b):return hashlib.sha256(b).hexdigest().upper()
def hf(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def dump(p,x):
 with p.open('x',encoding='utf-8') as f:json.dump(x,f,indent=2,sort_keys=True,default=str);f.write('\n')
def csvout(p,fields,rows):
 with p.open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def get(obj,path):
 cur=obj
 for part in path[2:].split('.'):
  if not isinstance(cur,dict) or part not in cur:return False,None
  cur=cur[part]
 return True,cur
def fetch(url):
 with urllib.request.urlopen(url,timeout=10) as r:
  body=r.read();return r.status,body,json.loads(body.decode('utf-8','replace'))
def bind_file(p):
 if not p:return {'provided':False}
 p=p.resolve()
 return {'provided':p.is_file(),'filename':p.name,'size_bytes':p.stat().st_size if p.is_file() else None,'sha256':hf(p) if p.is_file() else None}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--server-url',default='http://127.0.0.1:8080');ap.add_argument('--startup-command-file',type=Path);ap.add_argument('--server-binary',type=Path);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 out.mkdir(parents=True);status,body,props=fetch(a.server_url.rstrip('/')+'/props');rows=[]
 for path in SAFE_PATHS:
  present,value=get(props,path);rows.append({'path':path,'present':present,'type':type(value).__name__ if present else None,'value':value if present and isinstance(value,(str,int,float,bool)) else None})
 present,template=get(props,'$.chat_template');template_binding={'present':present,'type':type(template).__name__ if present else None,'length':len(template) if isinstance(template,str) else None,'sha256':hb(template.encode('utf-8')) if isinstance(template,str) else None}
 startup=bind_file(a.startup_command_file);binary=bind_file(a.server_binary);required={r['path']:r['present'] for r in rows};values_complete=all(required.values());identity_bound=bool(startup.get('provided') and binary.get('provided'))
 result={'schema':'EX5_6A_V5_61','version':VERSION,'model_rerun_performed':False,'prompt_modified':False,'server_configuration_modified':False,'attack_optimization_authorized':False,'props_http_status':status,'props_body_size':len(body),'props_body_sha256':hb(body),'startup_command_evidence':startup,'server_binary_evidence':binary,'chat_template_binding':template_binding,'safe_contract_values':rows,'contract_values_complete':values_complete,'startup_and_binary_identity_bound':identity_bound,'single_server_output_intervention_authorized':bool(values_complete and identity_bound),'finding':'STARTUP_BINARY_AND_PROPS_VALUES_BOUND' if values_complete and identity_bound else 'PROPS_VALUES_BOUND_STARTUP_OR_BINARY_IDENTITY_INCOMPLETE'}
 dump(out/'ex5_6a_binding.json',result);csvout(out/'ex5_6a_contract_values.csv',['path','present','type','value'],rows);files=[p for p in out.iterdir() if p.is_file()];csvout(out/'ex5_6a_manifest.csv',['artifact','size_bytes','sha256'],[{'artifact':p.name,'size_bytes':p.stat().st_size,'sha256':hf(p)} for p in files]);print(json.dumps({k:v for k,v in result.items() if k!='safe_contract_values'},indent=2));return 0 if result['single_server_output_intervention_authorized'] else 2
if __name__=='__main__':raise SystemExit(main())
