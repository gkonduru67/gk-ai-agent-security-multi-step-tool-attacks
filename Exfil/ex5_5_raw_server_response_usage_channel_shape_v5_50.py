#!/usr/bin/env python3
"""EX5.5 read-only raw server response usage and channel-shape diagnosis.

Consumes three frozen server_transport.jsonl files (256/512/1024). No model
execution. No raw prompts, model prose, reasoning, protected values, or tool
arguments are emitted. Output contains paths, types, counts, lengths, hashes,
explicit numeric usage fields, and safe control metadata only.
"""
from __future__ import annotations
import argparse,csv,hashlib,json
from pathlib import Path
from typing import Any
VERSION='EX5_5_RAW_SERVER_RESPONSE_USAGE_AND_CHANNEL_SHAPE_DIAGNOSIS_v5.50'
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
def load_response(path):
 for line in path.read_text(encoding='utf-8',errors='replace').splitlines():
  try:o=json.loads(line)
  except Exception:continue
  if o.get('phase')=='http_response':return o
 return None
def walk(v:Any,path='$',out=None):
 if out is None:out=[]
 if isinstance(v,dict):
  out.append({'path':path,'type':'object','count':len(v)})
  for k,x in v.items():walk(x,f'{path}.{k}',out)
 elif isinstance(v,list):
  out.append({'path':path,'type':'array','count':len(v)})
  for i,x in enumerate(v):walk(x,f'{path}[{i}]',out)
 elif isinstance(v,str):out.append({'path':path,'type':'string','length':len(v),'sha256':hs(v),'empty':not bool(v)})
 elif v is None:out.append({'path':path,'type':'null'})
 elif isinstance(v,(int,float,bool)):out.append({'path':path,'type':type(v).__name__,'numeric_value':v if not isinstance(v,bool) else None,'value_sha256':hs(v)})
 else:out.append({'path':path,'type':type(v).__name__,'value_sha256':hs(v)})
 return out
def numeric(rows,names):
 vals={}
 for r in rows:
  low=r['path'].lower()
  if r.get('numeric_value') is not None:
   for n in names:
    if low.endswith('.'+n) or low.endswith('['+n+']'):vals[n]=r['numeric_value']
 return vals
def main():
 ap=argparse.ArgumentParser()
 for b in BUDGETS:
  ap.add_argument(f'--transport-{b}',required=True,type=Path);ap.add_argument(f'--sha256-{b}',required=True)
 ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 out.mkdir(parents=True);all_paths=[];rows=[]
 for b in BUDGETS:
  p=getattr(a,f'transport_{b}').resolve();expected=getattr(a,f'sha256_{b}').upper();actual=hf(p)
  if actual!=expected:ap.error(f'Frozen transport SHA-256 mismatch for {b}')
  obj=load_response(p)
  if obj is None:ap.error(f'No http_response record for {b}')
  paths=walk(obj);all_paths.extend([{'budget':b,**r} for r in paths]);usage=[r for r in paths if '.usage' in r['path'].lower()];reasoning=[r for r in paths if any(t in r['path'].lower() for t in ('reason','analysis','thinking'))];content=[r for r in paths if any(t in r['path'].lower() for t in ('content','text','output'))];tools=[r for r in paths if 'tool' in r['path'].lower() or 'function' in r['path'].lower()];timings=[r for r in paths if 'timing' in r['path'].lower() or 'duration' in r['path'].lower()]
  nums=numeric(usage,['prompt_tokens','completion_tokens','total_tokens','reasoning_tokens','cached_tokens'])
  rows.append({'budget':b,'transport_sha256':actual,'http_status':obj.get('http_status'),'body_size':obj.get('body_size'),'body_sha256':obj.get('body_sha256'),'choices_count':obj.get('choices_count'),'finish_reason':obj.get('finish_reason'),'message_content_length':obj.get('message_content_length'),'tool_calls_count':obj.get('tool_calls_count'),'usage_path_count':len(usage),'usage_shape_sha256':hs([(r['path'],r['type'],r.get('count')) for r in usage]),'prompt_tokens':nums.get('prompt_tokens'),'completion_tokens':nums.get('completion_tokens'),'total_tokens':nums.get('total_tokens'),'reasoning_tokens':nums.get('reasoning_tokens'),'cached_tokens':nums.get('cached_tokens'),'reasoning_path_count':len(reasoning),'reasoning_nonempty_string_count':sum(1 for r in reasoning if r.get('type')=='string' and (r.get('length') or 0)>0),'reasoning_shape_sha256':hs([(r['path'],r['type'],r.get('count'),r.get('length')) for r in reasoning]),'content_path_count':len(content),'content_nonempty_string_count':sum(1 for r in content if r.get('type')=='string' and (r.get('length') or 0)>0),'tool_path_count':len(tools),'timing_path_count':len(timings),'full_shape_sha256':hs([(r['path'],r['type'],r.get('count'),r.get('length')) for r in paths])})
 completion_equals=[r['completion_tokens']==r['budget'] for r in rows if r['completion_tokens'] is not None]
 if any(r['reasoning_nonempty_string_count']>0 or (r['reasoning_tokens'] or 0)>0 for r in rows):finding='EXPLICIT_REASONING_OR_ANALYSIS_CHANNEL_PRESENT'
 elif completion_equals and all(completion_equals):finding='COMPLETION_TOKEN_USAGE_EQUALS_EACH_TESTED_BUDGET_WITH_NO_VISIBLE_OUTPUT'
 elif len({r['full_shape_sha256'] for r in rows})>1:finding='RAW_RESPONSE_SHAPE_OR_FIELD_LENGTHS_VARY_BY_BUDGET'
 else:finding='BODY_GROWTH_NOT_EXPLAINED_BY_EXPOSED_USAGE_OR_CHANNEL_FIELDS'
 result={'schema':'EX5_5_V5_50','version':VERSION,'model_rerun_performed':False,'prompt_modified':False,'budgets':list(BUDGETS),'row_count':len(rows),'finding':finding,'attack_optimization_authorized':False,'rows':rows};dump(out/'ex5_5_result.json',result);csvout(out/'ex5_5_matrix.csv',list(rows[0]),rows);csvout(out/'ex5_5_paths.csv',['budget','path','type','count','length','sha256','empty','numeric_value','value_sha256'],all_paths);files=[p for p in out.iterdir() if p.is_file()];csvout(out/'ex5_5_manifest.csv',['artifact','size_bytes','sha256'],[{'artifact':p.name,'size_bytes':p.stat().st_size,'sha256':hf(p)} for p in files]);print(json.dumps({k:v for k,v in result.items() if k!='rows'},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
