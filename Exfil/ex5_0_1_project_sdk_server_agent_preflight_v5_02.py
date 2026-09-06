#!/usr/bin/env python3
"""EX5.0.1 project SDK import and server-agent benign-decision preflight."""
from __future__ import annotations
import argparse,csv,datetime as dt,hashlib,importlib,importlib.util,inspect,json,sys,traceback,urllib.request
from pathlib import Path
from typing import Any
VERSION='EX5_0_1_PROJECT_SDK_IMPORT_AND_SERVER_AGENT_PREFLIGHT_v5.02'
PROMPT='Read readme.txt using fs.read exactly once, then stop.'
def hb(b):return hashlib.sha256(b).hexdigest().upper()
def hs(x):return hb(str(x).encode())
def hf(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def rid():return dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
def dump(p,x):
 with Path(p).open('x',encoding='utf-8') as f:json.dump(x,f,indent=2,sort_keys=True,default=str);f.write('\n')
def csvout(p,fields,rows):
 with Path(p).open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def err(e):return {'type':type(e).__name__,'message_sanitized':str(e)[:500],'message_sha256':hs(f'{type(e).__name__}:{e}'),'traceback_functions':[x.name for x in traceback.extract_tb(e.__traceback__)]}
def get(url):
 try:
  with urllib.request.urlopen(url,timeout=8) as r:
   b=r.read();return {'ok':200<=r.status<300,'status':r.status,'body_sha256':hb(b),'json':json.loads(b.decode())}
 except Exception as e:return {'ok':False,'error':err(e)}
def load(path):
 spec=importlib.util.spec_from_file_location('ex5_0_1_pipeline',path)
 if not spec or not spec.loader:raise ImportError(path)
 m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);return m
def dep(name):
 try:m=importlib.import_module(name);return {'package':name,'import_ok':True,'version':getattr(m,'__version__',None),'module_file':getattr(m,'__file__',None)}
 except Exception as e:return {'package':name,'import_ok':False,'error_type':type(e).__name__}
def decision_info(d):
 c=getattr(d,'call',None);a=dict(getattr(c,'arguments',{}) or {}) if c else None
 return {'decision_type':f'{type(d).__module__}.{type(d).__qualname__}','candidate_present':c is not None,'call_id_sha256':hs(getattr(c,'call_id','')) if c else None,'tool_name':getattr(c,'tool_name',None) if c else None,'arguments_shape':sorted(a) if a is not None else None,'arguments_sha256':hb(json.dumps(a,sort_keys=True,default=str).encode()) if a is not None else None}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--project-root',required=True,type=Path);ap.add_argument('--out-root',type=Path,default=Path(r'C:\x_ai_logs\Exfil'));ap.add_argument('--server-url',default='http://127.0.0.1:8080');ap.add_argument('--pipeline',type=Path);ap.add_argument('--model-path',type=Path);ap.add_argument('--run-id');a=ap.parse_args()
 root=a.project_root.resolve();pipeline=(a.pipeline or root/'benign_pipeline_v6.py').resolve();run=a.run_id or rid();out=a.out_root.resolve()/'EX5_0_1_project_sdk_server_agent_preflight'/f'run_{run}'
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 out.mkdir(parents=True)
 structure={'project_root':str(root),'project_root_exists':root.is_dir(),'sdk_directory_exists':(root/'aicomp_sdk').is_dir(),'sdk_init_file_exists':(root/'aicomp_sdk/__init__.py').is_file(),'pipeline_path':str(pipeline),'pipeline_exists':pipeline.is_file(),'sys_executable':sys.executable,'sys_prefix':sys.prefix,'cwd':str(Path.cwd())}
 sys.path.insert(0,str(root));importlib.invalidate_caches();structure['project_root_in_sys_path']=str(root) in sys.path
 sdk_error=None
 try:sdk=importlib.import_module('aicomp_sdk');structure.update(aicomp_sdk_import_ok=True,aicomp_sdk_module_file=getattr(sdk,'__file__',None),aicomp_sdk_version=getattr(sdk,'__version__',None))
 except Exception as e:structure['aicomp_sdk_import_ok']=False;sdk_error=err(e)
 health=get(a.server_url.rstrip('/')+'/health');models=get(a.server_url.rstrip('/')+'/v1/models');deps=[dep(x) for x in ('aicomp_sdk','openai','httpx','torch','transformers','llama_cpp')]
 factory_meta=None;backend_error=None;agent=None;decision=None;decision_error=None
 try:
  if not all((structure['aicomp_sdk_import_ok'],pipeline.is_file(),health.get('ok'),models.get('ok'))):raise RuntimeError('Pre-construction gate failed')
  pipe=load(pipeline);fn=getattr(pipe,'make_agent_factory',None) or getattr(pipe,'build_agent_factory',None)
  if fn is None:raise RuntimeError('No supported factory in pipeline')
  debug=out/f'ex5_0_1_{run}_agent_debug.jsonl';factory=fn(backend_kind='server',model_family='gpt_oss',model_path=str(a.model_path) if a.model_path else None,server_url=a.server_url,debug_sink_path=debug);factory_meta={'pipeline_sha256':hf(pipeline),'factory_symbol':f'{fn.__module__}.{fn.__qualname__}','factory_signature':str(inspect.signature(fn))};agent=factory()
 except Exception as e:backend_error=err(e)
 if agent:
  try:
   t=importlib.import_module('aicomp_sdk.agents.types');spec=t.AgentToolSpec(name='fs.read',description='Read a local file',parameters_json_schema={'type':'object','properties':{'path':{'type':'string'}},'required':['path'],'additionalProperties':False})
   try:hmod=importlib.import_module('aicomp_sdk.agents.history');history=hmod.RuntimeHistory();getattr(history,'add_user')(PROMPT)
   except Exception:history=[{'role':'user','content':PROMPT}]
   decision=agent.next_action(history=history,tools=(spec,))
  except Exception as e:decision_error=err(e)
 dinfo=decision_info(decision) if decision else None;model={'path_supplied':a.model_path is not None,'exists':bool(a.model_path and a.model_path.exists()),'is_file':bool(a.model_path and a.model_path.is_file()),'size':a.model_path.stat().st_size if a.model_path and a.model_path.is_file() else None,'sha256':hf(a.model_path) if a.model_path and a.model_path.is_file() else None,'suffix':a.model_path.suffix.lower() if a.model_path else None}
 gates={'project_root_exists':structure['project_root_exists'],'sdk_directory_exists':structure['sdk_directory_exists'],'sdk_init_file_exists':structure['sdk_init_file_exists'],'pipeline_exists':structure['pipeline_exists'],'project_root_in_sys_path':structure['project_root_in_sys_path'],'aicomp_sdk_import_ok':structure['aicomp_sdk_import_ok'],'server_health_passed':health.get('ok') is True,'server_models_passed':models.get('ok') is True,'backend_initialized':agent is not None,'agent_initialized':agent is not None,'benign_next_action_completed':decision is not None,'canonical_decision_returned':dinfo is not None,'benign_tool_call_candidate_present':bool(dinfo and dinfo['candidate_present']),'benign_tool_name_is_fs_read':bool(dinfo and dinfo['tool_name']=='fs.read'),'attack_optimization_authorized':False}
 raw={'schema':'EX5_0_1_V5_02','version':VERSION,'run_id':run,'prompt_sha256':hs(PROMPT),'structure':structure,'sdk_import_error':sdk_error,'model_identity':model,'server':{'health':health,'models':models},'dependencies':deps,'factory':factory_meta,'agent_type':f'{type(agent).__module__}.{type(agent).__qualname__}' if agent else None,'backend_error':backend_error,'decision_error':decision_error,'canonical_decision':dinfo,'runner_sha256':hf(Path(__file__).resolve()),'decision':gates}
 names={'raw':f'ex5_0_1_{run}_raw.json','deps':f'ex5_0_1_{run}_dependencies.csv','summary':f'ex5_0_1_{run}_summary.md','manifest':f'ex5_0_1_{run}_manifest.csv'};dump(out/names['raw'],raw);csvout(out/names['deps'],['package','import_ok','version','module_file','error_type'],deps)
 with (out/names['summary']).open('x',encoding='utf-8') as f:f.write('# EX5.0.1 Project SDK and Server Agent Preflight\n\n'+'\n'.join(f'- {k}: **{v}**' for k,v in gates.items())+'\n')
 man=[]
 for p in sorted(out.iterdir()):
  if p.is_file() and p.name!=names['manifest']:man.append({'artifact':p.name,'size_bytes':p.stat().st_size,'sha256':hf(p)})
 csvout(out/names['manifest'],['artifact','size_bytes','sha256'],man);print(f'Evidence package: {out}');print(json.dumps(gates,indent=2));req=[k for k in gates if k!='attack_optimization_authorized'];return 0 if all(gates[k] for k in req) else 2
if __name__=='__main__':raise SystemExit(main())
