#!/usr/bin/env python3
"""EX6F.1C read-only llama-server process/startup binding.

Runs on Windows. It locates the process listening on a specified local TCP port,
records the exact executable path/hash and command-line hash, checks whether the
frozen GGUF path is present in that command line, and queries /health and
/v1/models. It does not call chat/completions, load a model, construct Sandbox,
or execute tools.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,subprocess,urllib.request,urllib.error
from pathlib import Path
from typing import Any
VERSION='EX6F_1C_SERVER_STARTUP_PROCESS_BINDING_v6.64'
EXPECTED_PARENT='B76963D07251D6EC666E1AC7952014FDF2E8D408355657B5F6388CA505558855'
EXPECTED_MODEL='C27536640E410032865DC68781D80A08B98F8DB5E93575919AF8CCC0568AEB4F'
def hf(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def hs(s:str)->str:return hashlib.sha256(s.encode('utf-8')).hexdigest().upper()
def dumpx(p:Path,v:Any):
 with p.open('x',encoding='utf-8') as f:json.dump(v,f,indent=2,sort_keys=True,default=str);f.write('\n')
def csvout(p:Path,fields,rows):
 with p.open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='raise');w.writeheader();w.writerows(rows)
def ps_json(script:str)->Any:
 r=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',script],capture_output=True,text=True,encoding='utf-8',errors='replace')
 if r.returncode:raise RuntimeError('PowerShell failed: '+r.stderr.strip())
 text=r.stdout.strip();return json.loads(text) if text else None
def http_get(url:str,timeout:float)->dict[str,Any]:
 try:
  with urllib.request.urlopen(urllib.request.Request(url,headers={'Accept':'application/json'}),timeout=timeout) as r:
   b=r.read();
   try:o=json.loads(b.decode('utf-8','replace'))
   except Exception:o=None
   return {'ok':True,'status':r.status,'body_size':len(b),'body_sha256':hashlib.sha256(b).hexdigest().upper(),'json':o}
 except Exception as e:return {'ok':False,'status':getattr(e,'code',None),'error_type':type(e).__name__,'error_sha256':hs(f'{type(e).__name__}:{e}')}
def ids(v:Any)->list[str]:
 out=[]
 if isinstance(v,dict):
  for k,x in v.items():
   if k in ('id','model','model_id') and isinstance(x,str):out.append(x)
   else:out+=ids(x)
 elif isinstance(v,list):
  for x in v:out+=ids(x)
 return sorted(set(out))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--parent-manifest',required=True,type=Path);ap.add_argument('--parent-binding',required=True,type=Path);ap.add_argument('--model-artifact',required=True,type=Path);ap.add_argument('--host',default='127.0.0.1');ap.add_argument('--port',type=int,default=8080);ap.add_argument('--server-url',default='http://127.0.0.1:8080');ap.add_argument('--timeout-s',type=float,default=10.0);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 if not a.parent_manifest.is_file() or hf(a.parent_manifest)!=EXPECTED_PARENT:ap.error('Parent manifest mismatch')
 if not a.parent_binding.is_file() or json.loads(a.parent_binding.read_text(encoding='utf-8')).get('manifest_sha256')!=hf(a.parent_manifest):ap.error('Parent binding mismatch')
 model=a.model_artifact.resolve()
 if not model.is_file() or hf(model)!=EXPECTED_MODEL:ap.error('Frozen model identity mismatch')
 ps=f"$c=Get-NetTCPConnection -LocalPort {a.port} -State Listen -ErrorAction Stop | Select-Object -First 1; if(-not $c){{throw 'No listener'}}; $p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$c.OwningProcess); [pscustomobject]@{{LocalAddress=$c.LocalAddress;LocalPort=$c.LocalPort;PID=$c.OwningProcess;ExecutablePath=$p.ExecutablePath;CommandLine=$p.CommandLine;Name=$p.Name}} | ConvertTo-Json -Compress"
 proc=ps_json(ps)
 exe=Path(proc['ExecutablePath']) if proc.get('ExecutablePath') else None
 exe_ok=bool(exe and exe.is_file());cmd=proc.get('CommandLine') or ''
 model_arg_present=str(model).lower() in cmd.lower();health=http_get(a.server_url.rstrip('/')+'/health',a.timeout_s);models=http_get(a.server_url.rstrip('/')+'/v1/models',a.timeout_s);reported=ids(models.get('json'))
 process_bound=exe_ok and bool(cmd);transport=health.get('ok') and models.get('ok');model_path_bound=model_arg_present
 if not process_bound:cl='SERVER_PROCESS_IDENTITY_NOT_ESTABLISHED'
 elif not transport:cl='SERVER_PROCESS_BOUND_ENDPOINT_NOT_REACHABLE'
 elif not model_path_bound:cl='SERVER_PROCESS_BOUND_FROZEN_MODEL_PATH_NOT_IN_COMMAND_LINE'
 else:cl='SERVER_PROCESS_STARTUP_AND_FROZEN_MODEL_PATH_BOUND'
 q={'schema':'EX6F_1C_V6_64','version':VERSION,'classification':cl,'execution_type':'READ_ONLY_SERVER_PROCESS_AND_STARTUP_BINDING','process':{'pid':proc.get('PID'),'name':proc.get('Name'),'local_address':proc.get('LocalAddress'),'local_port':proc.get('LocalPort'),'executable_filename':exe.name if exe else None,'executable_sha256':hf(exe) if exe_ok else None,'command_line_sha256':hs(cmd),'command_line_length':len(cmd),'frozen_model_path_present':model_arg_present},'model':{'filename':model.name,'size_bytes':model.stat().st_size,'sha256':hf(model)},'server':{'base_url_sha256':hs(a.server_url.rstrip('/')),'health':{k:v for k,v in health.items() if k!='json'},'models':{k:v for k,v in models.items() if k!='json'},'reported_model_id_count':len(reported),'reported_model_ids_sha256':[hs(x) for x in reported]},'claim_boundaries':{'process_executable_identity':'ESTABLISHED' if exe_ok else 'NOT_ESTABLISHED','startup_command_identity':'HASH_BOUND','frozen_model_path_in_startup_command':model_arg_present,'server_loaded_model_bytes_equal_frozen_GGUF':'SUPPORTED_BY_STARTUP_ARGUMENT_NOT_RUNTIME_BYTE_ATTESTATION' if model_arg_present else 'NOT_ESTABLISHED','chat_generation':'NOT_TESTED','Sandbox':'NOT_CONSTRUCTED','EX6F_matrix':'NOT_EXECUTED'},'text_only_generation_runner_development_authorized':cl=='SERVER_PROCESS_STARTUP_AND_FROZEN_MODEL_PATH_BOUND','chat_generation_authorized':False,'chat_completion_called':False,'SDK_imported':False,'Sandbox_constructed':False,'tool_execution':False,'harness_trick':'NOT_DEMONSTRATED','security_finding':'NOT_ESTABLISHED','attack_optimization_authorized':False,'hardened_policy_implementation_authorized':False}
 out.mkdir(parents=True);dumpx(out/'ex6f1c_process_binding.json',q);dumpx(out/'ex6f1c_redacted_startup_evidence.json',{'executable_filename':exe.name if exe else None,'executable_sha256':q['process']['executable_sha256'],'command_line_sha256':q['process']['command_line_sha256'],'command_line_length':len(cmd),'frozen_model_path_present':model_arg_present,'reported_model_ids_sha256':q['server']['reported_model_ids_sha256']})
 src=[a.parent_manifest,a.parent_binding,model,Path(__file__).resolve()];mr=[{'artifact':p.name,'role':'SOURCE_OR_PARENT','size_bytes':p.stat().st_size,'sha256':hf(p)} for p in src]
 for p in out.iterdir():
  if p.is_file():mr.append({'artifact':p.name,'role':'DERIVED','size_bytes':p.stat().st_size,'sha256':hf(p)})
 mp=out/'ex6f1c_manifest.csv';csvout(mp,['artifact','role','size_bytes','sha256'],mr);dumpx(out/'ex6f1c_manifest_external_binding.json',{'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':hf(mp),'binding_scope':'EXTERNAL_SELF_BINDING_RECORD'});print(json.dumps({'version':VERSION,'classification':cl,'text_only_generation_runner_development_authorized':q['text_only_generation_runner_development_authorized'],'chat_generation_authorized':False,'manifest_sha256':hf(mp)},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
