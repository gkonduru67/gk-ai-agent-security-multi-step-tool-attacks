#!/usr/bin/env python3
"""EX5.6B Windows llama-server live epoch identity binding.

Read-only. On Windows, queries Win32_Process through PowerShell/CIM to capture the
currently running llama-server executable path and command line. The canonical
output stores the command text in a dedicated evidence file and stores hashes in
JSON/CSV. It also binds the executable, model, /health, /v1/models, and /props.
No model generation or server mutation is performed.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,platform,subprocess,urllib.request
from pathlib import Path
VERSION='EX5_6B_WINDOWS_LLAMA_SERVER_EPOCH_BINDING_v5.62'
def hb(b):return hashlib.sha256(b).hexdigest().upper()
def hf(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def dumpx(p,x):
 with p.open('x',encoding='utf-8') as f:json.dump(x,f,indent=2,sort_keys=True,default=str);f.write('\n')
def writex(p,s):
 with p.open('x',encoding='utf-8',newline='\n') as f:f.write(s.rstrip()+"\n")
def csvout(p,fields,rows):
 with p.open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def get_json(url):
 with urllib.request.urlopen(url,timeout=10) as r:
  b=r.read();return {'status':r.status,'size_bytes':len(b),'sha256':hb(b)}
def powershell_processes():
 script=r'''$p = Get-CimInstance Win32_Process | Where-Object { $_.Name -ieq 'llama-server.exe' }; $p | Select-Object ProcessId,Name,ExecutablePath,CommandLine,CreationDate | ConvertTo-Json -Depth 4 -Compress'''
 cp=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],capture_output=True,text=True,timeout=30)
 if cp.returncode!=0:raise RuntimeError('PowerShell process query failed')
 if not cp.stdout.strip():return []
 obj=json.loads(cp.stdout);return obj if isinstance(obj,list) else [obj]
def norm(s):return ' '.join((s or '').strip().split()).lower()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--expected-command',required=True);ap.add_argument('--model-path',required=True,type=Path);ap.add_argument('--server-url',default='http://127.0.0.1:8080');ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 out.mkdir(parents=True)
 if platform.system()!='Windows':ap.error('This runner must execute on Windows')
 procs=powershell_processes()
 if len(procs)!=1:ap.error(f'Expected exactly one llama-server.exe process, found {len(procs)}')
 p=procs[0];exe=Path(p.get('ExecutablePath') or '').resolve();model=a.model_path.resolve()
 if not exe.is_file():ap.error('Running executable path is unavailable or not a file')
 if not model.is_file():ap.error('Model path is unavailable or not a file')
 observed=p.get('CommandLine') or ''
 writex(out/'observed_startup_command.txt',observed);writex(out/'researcher_reported_startup_command.txt',a.expected_command)
 endpoints={n:get_json(a.server_url.rstrip('/')+s) for n,s in [('health','/health'),('models','/v1/models'),('props','/props')]}
 exact=norm(observed)==norm(a.expected_command);contains_model=norm(str(model)) in norm(observed);contains_ctx=('-c 8192' in norm(observed) or '--ctx-size 8192' in norm(observed));contains_host=('127.0.0.1' in norm(observed));contains_ngl=('-ngl 999' in norm(observed) or '--gpu-layers 999' in norm(observed) or '--n-gpu-layers 999' in norm(observed))
 row={'process_id':p.get('ProcessId'),'process_name':p.get('Name'),'creation_date':str(p.get('CreationDate')),'observed_command_length':len(observed),'observed_command_sha256':hf(out/'observed_startup_command.txt'),'reported_command_length':len(a.expected_command),'reported_command_sha256':hf(out/'researcher_reported_startup_command.txt'),'normalized_exact_match':exact,'model_path_present_in_observed_command':contains_model,'context_8192_present':contains_ctx,'host_127_0_0_1_present':contains_host,'ngl_999_present':contains_ngl,'running_executable_filename':exe.name,'running_executable_size_bytes':exe.stat().st_size,'running_executable_sha256':hf(exe),'model_filename':model.name,'model_size_bytes':model.stat().st_size,'model_sha256':hf(model)}
 complete=all([contains_model,contains_ctx,contains_host,contains_ngl])
 result={'schema':'EX5_6B_V5_62','version':VERSION,'model_rerun_performed':False,'server_configuration_modified':False,'attack_optimization_authorized':False,'live_process_count':1,'live_epoch_identity_complete':complete,'reported_command_exactly_matches_live_command_after_whitespace_case_normalization':exact,'process':row,'endpoint_evidence':endpoints,'single_server_output_intervention_authorized':complete,'finding':'LIVE_LLAMA_SERVER_EPOCH_IDENTITY_BOUND' if complete else 'LIVE_COMMAND_DIFFERS_OR_REQUIRED_ARGUMENTS_MISSING'}
 dumpx(out/'ex5_6b_epoch_binding.json',result);csvout(out/'ex5_6b_process_binding.csv',list(row),[row]);files=[x for x in out.iterdir() if x.is_file()];csvout(out/'ex5_6b_manifest.csv',['artifact','size_bytes','sha256'],[{'artifact':x.name,'size_bytes':x.stat().st_size,'sha256':hf(x)} for x in files]);print(json.dumps({k:v for k,v in result.items() if k!='process'},indent=2));return 0 if complete else 2
if __name__=='__main__':raise SystemExit(main())
