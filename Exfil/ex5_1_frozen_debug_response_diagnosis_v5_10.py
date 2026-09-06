#!/usr/bin/env python3
"""EX5.1 read-only frozen debug response shape and empty-output diagnosis."""
from __future__ import annotations
import argparse,csv,hashlib,json
from pathlib import Path
from typing import Any
VERSION='EX5_1_FROZEN_DEBUG_RESPONSE_SHAPE_AND_EMPTY_OUTPUT_DIAGNOSIS_v5.10'
def hb(b):return hashlib.sha256(b).hexdigest().upper()
def hs(x):return hb(str(x).encode('utf-8'))
def hf(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def dump(p,x):
 with p.open('x',encoding='utf-8') as f:json.dump(x,f,indent=2,sort_keys=True,default=str);f.write('\n')
def csvout(p,fields,rows):
 with p.open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def walk(v:Any,path='$',out=None):
 if out is None:out=[]
 if isinstance(v,dict):
  out.append({'path':path,'type':'object','count':len(v)})
  for k,x in v.items():walk(x,f'{path}.{k}',out)
 elif isinstance(v,list):
  out.append({'path':path,'type':'array','count':len(v)})
  for i,x in enumerate(v):walk(x,f'{path}[{i}]',out)
 elif isinstance(v,str):out.append({'path':path,'type':'string','length':len(v),'sha256':hs(v),'empty':len(v)==0})
 elif v is None:out.append({'path':path,'type':'null'})
 else:out.append({'path':path,'type':type(v).__name__,'value_hash':hs(v)})
 return out
def pick(rows,tokens):
 return [r for r in rows if any(t in r['path'].lower() for t in tokens)]
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--debug-jsonl',required=True,type=Path);ap.add_argument('--out-root',required=True,type=Path);ap.add_argument('--expected-debug-sha256');a=ap.parse_args();src=a.debug_jsonl.resolve()
 if not src.is_file():ap.error(f'Not found: {src}')
 actual=hf(src)
 if a.expected_debug_sha256 and actual.upper()!=a.expected_debug_sha256.upper():ap.error('Frozen debug SHA-256 mismatch')
 out=a.out_root.resolve();out.mkdir(parents=True,exist_ok=True);stem='ex5_1_'+src.stem
 records=[];paths=[]
 for i,line in enumerate(src.read_text(encoding='utf-8',errors='replace').splitlines()):
  try:o=json.loads(line)
  except Exception as e:records.append({'record_index':i,'record_sha256':hs(line),'json_valid':False,'error_type':type(e).__name__});continue
  rows=walk(o);paths.extend([{'record_index':i,**r} for r in rows]);content=pick(rows,['content','text','output']);reason=pick(rows,['reasoning','analysis']);tools=pick(rows,['tool_call','tool_calls','function']);finish=pick(rows,['finish_reason','finishreason']);errors=pick(rows,['error'])
  nonempty_content=[r for r in content if r.get('type')=='string' and r.get('length',0)>0];empty_content=[r for r in content if r.get('type')=='string' and r.get('length')==0]
  records.append({'record_index':i,'record_sha256':hs(line),'json_valid':True,'phase':o.get('phase'),'backend':o.get('backend'),'model':o.get('model'),'latency_ms_hash':hs(o.get('latency_ms')) if o.get('latency_ms') is not None else None,'request_payload_shape_hash':hs([(r['path'],r['type'],r.get('count')) for r in rows if r['path'].startswith('$.request_payload')]),'response_payload_shape_hash':hs([(r['path'],r['type'],r.get('count')) for r in rows if r['path'].startswith('$.response_payload')]),'provider_payload_shape_hash':hs([(r['path'],r['type'],r.get('count')) for r in rows if r['path'].startswith('$.provider_payload')]),'content_path_count':len(content),'nonempty_content_count':len(nonempty_content),'empty_content_count':len(empty_content),'reasoning_path_count':len(reason),'tool_call_path_count':len(tools),'finish_reason_path_count':len(finish),'error_path_count':len(errors),'provider_nonempty_content_present':any(r['path'].startswith('$.provider_payload') for r in nonempty_content),'response_nonempty_content_present':any(r['path'].startswith('$.response_payload') for r in nonempty_content),'provider_tool_candidate_path_present':any(r['path'].startswith('$.provider_payload') for r in tools),'response_tool_candidate_path_present':any(r['path'].startswith('$.response_payload') for r in tools)})
 provider_nonempty=any(r.get('provider_nonempty_content_present') for r in records);response_nonempty=any(r.get('response_nonempty_content_present') for r in records);provider_tool=any(r.get('provider_tool_candidate_path_present') for r in records);response_tool=any(r.get('response_tool_candidate_path_present') for r in records)
 if not provider_nonempty and not provider_tool:determination='PROVIDER_RESPONSE_HAS_NO_OBSERVED_NONEMPTY_CONTENT_OR_TOOL_CANDIDATE'
 elif (provider_nonempty or provider_tool) and not (response_nonempty or response_tool):determination='OUTPUT_PRESENT_PROVIDER_SIDE_BUT_ABSENT_NORMALIZED_RESPONSE'
 else:determination='OUTPUT_SHAPE_REQUIRES_SOURCE_CONTRACT_REVIEW'
 summary={'schema':'EX5_1_V5_10','version':VERSION,'source_debug_file':src.name,'source_debug_sha256':actual,'source_size_bytes':src.stat().st_size,'record_count':len(records),'provider_nonempty_content_present':provider_nonempty,'response_nonempty_content_present':response_nonempty,'provider_tool_candidate_path_present':provider_tool,'response_tool_candidate_path_present':response_tool,'determination_status':determination,'model_rerun_performed':False,'raw_content_serialized':False,'records':records}
 raw=out/f'{stem}_diagnosis.json';csvp=out/f'{stem}_paths.csv';manifest=out/f'{stem}_manifest.csv';dump(raw,summary);csvout(csvp,['record_index','path','type','count','length','sha256','empty','value_hash'],paths);csvout(manifest,['artifact','size_bytes','sha256'],[{'artifact':raw.name,'size_bytes':raw.stat().st_size,'sha256':hf(raw)},{'artifact':csvp.name,'size_bytes':csvp.stat().st_size,'sha256':hf(csvp)}]);print(json.dumps({k:summary[k] for k in summary if k!='records'},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
