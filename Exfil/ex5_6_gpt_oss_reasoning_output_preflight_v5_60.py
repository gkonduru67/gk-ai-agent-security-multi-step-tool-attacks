#!/usr/bin/env python3
"""EX5.6 GPT-OSS reasoning-channel and output-completion preflight v5.60.

Read-only preflight. It hash-binds the llama-server process/startup evidence,
queries safe local metadata endpoints, inspects the frozen three-row transport
records, and produces a bounded authorization decision for at most one later
server-output-channel intervention. It does not rerun the model, change server
configuration, expose prompts/reasoning, or authorize attack optimization.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,os,subprocess,urllib.request
from pathlib import Path
from typing import Any
VERSION='EX5_6_GPT_OSS_REASONING_CHANNEL_AND_OUTPUT_COMPLETION_PREFLIGHT_v5.60'
BUDGETS=(256,512,1024)
def hb(b):return hashlib.sha256(b).hexdigest().upper()
def hs(x):return hb(str(x).encode('utf-8'))
def hf(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def dump(p,x):
 with p.open('x',encoding='utf-8') as f:json.dump(x,f,indent=2,sort_keys=True,default=str);f.write('\n')
def csvout(p,fields,rows):
 with p.open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def get_json(url):
 try:
  with urllib.request.urlopen(url,timeout=8) as r:
   body=r.read();obj=json.loads(body.decode('utf-8','replace'))
   return {'ok':True,'status':r.status,'body_size':len(body),'body_sha256':hb(body),'shape':shape(obj)}
 except Exception as e:return {'ok':False,'error_type':type(e).__name__,'error_sha256':hs(f'{type(e).__name__}:{e}')}
def shape(v,path='$',out=None):
 if out is None:out=[]
 if isinstance(v,dict):
  out.append({'path':path,'type':'object','count':len(v)})
  for k,x in v.items():shape(x,f'{path}.{k}',out)
 elif isinstance(v,list):
  out.append({'path':path,'type':'array','count':len(v)})
  for i,x in enumerate(v):shape(x,f'{path}[{i}]',out)
 elif isinstance(v,str):out.append({'path':path,'type':'string','length':len(v),'sha256':hs(v),'empty':not bool(v)})
 elif v is None:out.append({'path':path,'type':'null'})
 else:out.append({'path':path,'type':type(v).__name__,'value_sha256':hs(v)})
 return out
def read_response(path):
 for line in path.read_text(encoding='utf-8',errors='replace').splitlines():
  try:o=json.loads(line)
  except Exception:continue
  if o.get('phase')=='http_response':return o
 return None
def process_inventory():
 rows=[]
 try:
  text=subprocess.check_output(['ps','-eo','pid=,comm=,args='],text=True,errors='replace')
  for line in text.splitlines():
   low=line.lower()
   if 'llama-server' in low or 'llama_server' in low:
    parts=line.strip().split(None,2);pid=int(parts[0]);comm=parts[1] if len(parts)>1 else '';args=parts[2] if len(parts)>2 else ''
    exe=None
    try:exe=os.readlink(f'/proc/{pid}/exe')
    except Exception:pass
    rows.append({'pid':pid,'command':comm,'command_line_sha256':hs(args),'command_line_length':len(args),'executable_path_sha256':hs(exe) if exe else None,'executable_sha256':hf(Path(exe)) if exe and Path(exe).is_file() else None})
 except Exception:pass
 return rows
def main():
 ap=argparse.ArgumentParser()
 for b in BUDGETS:
  ap.add_argument(f'--transport-{b}',required=True,type=Path);ap.add_argument(f'--sha256-{b}',required=True)
 ap.add_argument('--server-url',default='http://127.0.0.1:8080');ap.add_argument('--startup-command-file',type=Path);ap.add_argument('--server-binary',type=Path);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 out.mkdir(parents=True);rows=[]
 for b in BUDGETS:
  p=getattr(a,f'transport_{b}').resolve();expected=getattr(a,f'sha256_{b}').upper();actual=hf(p)
  if actual!=expected:ap.error(f'Frozen transport SHA-256 mismatch for {b}')
  r=read_response(p)
  if r is None:ap.error(f'No http_response record for {b}')
  semantic={x.get('path'):x for x in r.get('response_shape',[]) if isinstance(x,dict) and isinstance(x.get('path'),str)}
  reason=semantic.get('$.choices[0].message.reasoning_content',{});content=semantic.get('$.choices[0].message.content',{});tools=semantic.get('$.choices[0].message.tool_calls')
  rows.append({'budget':b,'transport_sha256':actual,'http_status':r.get('http_status'),'finish_reason':r.get('finish_reason'),'reasoning_path_present':bool(reason),'reasoning_length':reason.get('length'),'reasoning_sha256':reason.get('sha256'),'visible_content_path_present':bool(content),'visible_content_length':content.get('length'),'tool_calls_path_present':tools is not None,'tool_calls_count':r.get('tool_calls_count'),'body_sha256':r.get('body_sha256')})
 startup={'provided':False}
 if a.startup_command_file:
  p=a.startup_command_file.resolve();startup={'provided':p.is_file(),'filename':p.name,'size_bytes':p.stat().st_size if p.is_file() else None,'sha256':hf(p) if p.is_file() else None}
 binary={'provided':False}
 if a.server_binary:
  p=a.server_binary.resolve();binary={'provided':p.is_file(),'filename':p.name,'size_bytes':p.stat().st_size if p.is_file() else None,'sha256':hf(p) if p.is_file() else None}
 endpoints={name:get_json(a.server_url.rstrip('/')+suffix) for name,suffix in [('health','/health'),('models','/v1/models'),('props','/props')]}
 processes=process_inventory();reasoning_all=all(r['reasoning_path_present'] and (r['reasoning_length'] or 0)>0 for r in rows);visible_any=any((r['visible_content_length'] or 0)>0 for r in rows);tools_any=any((r['tool_calls_count'] or 0)>0 for r in rows);contract_evidence=any(v.get('ok') for v in endpoints.values());startup_bound=startup['provided'] or bool(processes)
 intervention_authorized=reasoning_all and not visible_any and not tools_any and contract_evidence and startup_bound
 finding='REASONING_ONLY_LENGTH_TERMINATION_WITH_STARTUP_AND_CONTRACT_EVIDENCE_BOUND' if intervention_authorized else 'PREFLIGHT_EVIDENCE_INCOMPLETE_FOR_SERVER_OUTPUT_INTERVENTION'
 result={'schema':'EX5_6_V5_60','version':VERSION,'model_rerun_performed':False,'prompt_modified':False,'server_configuration_modified':False,'attack_optimization_authorized':False,'single_server_output_intervention_authorized':intervention_authorized,'finding':finding,'startup_command_evidence':startup,'server_binary_evidence':binary,'process_inventory':processes,'endpoint_evidence':endpoints,'rows':rows,'advancement_gate':{'visible_message_content_or_structured_tool_calls_required':True,'currently_passed':visible_any or tools_any}}
 dump(out/'ex5_6_preflight.json',result);csvout(out/'ex5_6_transport_matrix.csv',list(rows[0]),rows);csvout(out/'ex5_6_process_inventory.csv',['pid','command','command_line_sha256','command_line_length','executable_path_sha256','executable_sha256'],processes);files=[p for p in out.iterdir() if p.is_file()];csvout(out/'ex5_6_manifest.csv',['artifact','size_bytes','sha256'],[{'artifact':p.name,'size_bytes':p.stat().st_size,'sha256':hf(p)} for p in files]);print(json.dumps({k:v for k,v in result.items() if k not in ('rows','process_inventory','endpoint_evidence')},indent=2));return 0 if intervention_authorized else 2
if __name__=='__main__':raise SystemExit(main())
