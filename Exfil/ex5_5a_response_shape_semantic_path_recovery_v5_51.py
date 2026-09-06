#!/usr/bin/env python3
"""EX5.5A read-only semantic recovery of inner response_shape/usage_shape entries.

Consumes the three frozen server_transport.jsonl files from EX5.4. It interprets
only the already-sanitized inner shape entries produced by benign_pipeline_EX_v6.
No model execution, prompt modification, raw prose serialization, protected-value
serialization, or attack optimization.
"""
from __future__ import annotations
import argparse,csv,hashlib,json
from pathlib import Path
from typing import Any
VERSION='EX5_5A_RESPONSE_SHAPE_SEMANTIC_PATH_RECOVERY_v5.51'
BUDGETS=(256,512,1024)
REASONING_SUFFIXES=('.reasoning','.reasoning_content','.analysis','.thinking')
CONTENT_SUFFIXES=('.message.content','.content','.text','.output_text')
TOOL_SUFFIXES=('.tool_calls','.function_call')
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
def read_http_response(path):
 for line in path.read_text(encoding='utf-8',errors='replace').splitlines():
  try:o=json.loads(line)
  except Exception:continue
  if o.get('phase')=='http_response':return o
 return None
def exact_class(path):
 low=path.lower()
 if any(low.endswith(s) for s in REASONING_SUFFIXES):return 'REASONING'
 if any(low.endswith(s) for s in CONTENT_SUFFIXES):return 'VISIBLE_CONTENT'
 if any(low.endswith(s) for s in TOOL_SUFFIXES):return 'TOOL_CALL'
 return 'OTHER'
def normalize_entry(budget,kind,index,e):
 p=e.get('path') if isinstance(e.get('path'),str) else None
 return {'budget':budget,'shape_kind':kind,'entry_index':index,'original_response_path':p,'semantic_class':exact_class(p or ''),'original_type':e.get('type'),'original_count':e.get('count'),'original_string_length':e.get('length'),'original_string_sha256':e.get('sha256'),'original_empty':e.get('empty'),'original_scalar_value_sha256':e.get('value_sha256')}
def main():
 ap=argparse.ArgumentParser()
 for b in BUDGETS:
  ap.add_argument(f'--transport-{b}',required=True,type=Path);ap.add_argument(f'--sha256-{b}',required=True)
 ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 out.mkdir(parents=True);entries=[];rows=[]
 for b in BUDGETS:
  p=getattr(a,f'transport_{b}').resolve();expected=getattr(a,f'sha256_{b}').upper();actual=hf(p)
  if actual!=expected:ap.error(f'Frozen transport SHA-256 mismatch for {b}')
  rec=read_http_response(p)
  if rec is None:ap.error(f'No http_response record for {b}')
  for kind in ('response_shape','usage_shape'):
   seq=rec.get(kind)
   if isinstance(seq,list):
    for i,e in enumerate(seq):
     if isinstance(e,dict):entries.append(normalize_entry(b,kind,i,e))
  response_entries=[x for x in entries if x['budget']==b and x['shape_kind']=='response_shape']
  scaling_candidates=[x for x in response_entries if x['original_type']=='string' and isinstance(x['original_string_length'],int) and x['original_string_length']>0]
  rows.append({'budget':b,'transport_sha256':actual,'http_status':rec.get('http_status'),'body_size':rec.get('body_size'),'body_sha256':rec.get('body_sha256'),'finish_reason':rec.get('finish_reason'),'message_content_length':rec.get('message_content_length'),'tool_calls_count':rec.get('tool_calls_count'),'response_shape_entry_count':len(response_entries),'usage_shape_entry_count':sum(1 for x in entries if x['budget']==b and x['shape_kind']=='usage_shape'),'reasoning_entry_count':sum(1 for x in response_entries if x['semantic_class']=='REASONING'),'visible_content_entry_count':sum(1 for x in response_entries if x['semantic_class']=='VISIBLE_CONTENT'),'tool_call_entry_count':sum(1 for x in response_entries if x['semantic_class']=='TOOL_CALL'),'nonempty_reasoning_entry_count':sum(1 for x in response_entries if x['semantic_class']=='REASONING' and (x['original_string_length'] or 0)>0),'nonempty_visible_content_entry_count':sum(1 for x in response_entries if x['semantic_class']=='VISIBLE_CONTENT' and (x['original_string_length'] or 0)>0),'largest_string_path':max(scaling_candidates,key=lambda x:x['original_string_length'])['original_response_path'] if scaling_candidates else None,'largest_string_length':max((x['original_string_length'] for x in scaling_candidates),default=None)})
 # cross-budget path comparison
 by_path={}
 for e in entries:
  if e['shape_kind']=='response_shape' and e['original_type']=='string' and e['original_response_path']:
   by_path.setdefault(e['original_response_path'],{})[e['budget']]=e['original_string_length']
 scaling=[]
 for p,vals in sorted(by_path.items()):
  if all(b in vals for b in BUDGETS) and vals[256] < vals[512] < vals[1024]:scaling.append({'original_response_path':p,'semantic_class':exact_class(p),'length_256':vals[256],'length_512':vals[512],'length_1024':vals[1024]})
 explicit_reasoning=any(x['semantic_class']=='REASONING' and any((x[f'length_{b}'] or 0)>0 for b in BUDGETS) for x in scaling)
 if explicit_reasoning:finding='BUDGET_SCALING_FIELD_IS_EXPLICIT_REASONING_OR_ANALYSIS_PATH'
 elif scaling:finding='BUDGET_SCALING_FIELD_IDENTITY_RECOVERED_NON_REASONING_OR_AMBIGUOUS'
 else:finding='NO_MONOTONIC_BUDGET_SCALING_STRING_PATH_RECOVERED'
 result={'schema':'EX5_5A_V5_51','version':VERSION,'model_rerun_performed':False,'prompt_modified':False,'budgets':list(BUDGETS),'finding':finding,'explicit_reasoning_channel_established':explicit_reasoning,'scaling_fields':scaling,'attack_optimization_authorized':False,'rows':rows};dump(out/'ex5_5a_result.json',result);csvout(out/'ex5_5a_entries.csv',['budget','shape_kind','entry_index','original_response_path','semantic_class','original_type','original_count','original_string_length','original_string_sha256','original_empty','original_scalar_value_sha256'],entries);csvout(out/'ex5_5a_matrix.csv',list(rows[0]),rows);csvout(out/'ex5_5a_scaling_fields.csv',['original_response_path','semantic_class','length_256','length_512','length_1024'],scaling);files=[p for p in out.iterdir() if p.is_file()];csvout(out/'ex5_5a_manifest.csv',['artifact','size_bytes','sha256'],[{'artifact':p.name,'size_bytes':p.stat().st_size,'sha256':hf(p)} for p in files]);print(json.dumps({k:v for k,v in result.items() if k!='rows'},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
