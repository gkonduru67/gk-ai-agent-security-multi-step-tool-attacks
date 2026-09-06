#!/usr/bin/env python3
"""EX5.2 read-only server response contract and finish-reason preflight."""
from __future__ import annotations
import argparse,ast,csv,hashlib,json
from pathlib import Path
VERSION='EX5_2_SERVER_RESPONSE_CONTRACT_AND_FINISH_REASON_PREFLIGHT_v5.20'
def hb(b):return hashlib.sha256(b).hexdigest().upper()
def hs(x):return hb(str(x).encode())
def hf(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def dump(p,x):
 with p.open('x',encoding='utf-8') as f:json.dump(x,f,indent=2,sort_keys=True,default=str);f.write('\n')
def csvout(p,fields,rows):
 with p.open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def inspect_sources(root):
 terms=('choices','message','content','tool_calls','HFGenerationResponse','finish_reason','raw_text','parsed_response','response_payload','provider_payload','create_chat_completion','chat/completions')
 rows=[]
 for p in root.rglob('*.py'):
  try:text=p.read_text(encoding='utf-8');tree=ast.parse(text)
  except Exception:continue
  for n in ast.walk(tree):
   if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
    seg=ast.get_source_segment(text,n) or '';hits=[t for t in terms if t in seg]
    if hits:rows.append({'source_file':str(p.relative_to(root)),'source_sha256':hf(p),'symbol':getattr(n,'name',''),'start_line':n.lineno,'end_line':getattr(n,'end_lineno',n.lineno),'source_segment_sha256':hb(seg.encode()),'matched_terms':','.join(hits)})
 return rows
def read_debug(path):
 recs=[]
 for i,line in enumerate(path.read_text(encoding='utf-8',errors='replace').splitlines()):
  try:o=json.loads(line)
  except Exception:continue
  rp=o.get('response_payload');pp=o.get('provider_payload')
  recs.append({'record_index':i,'phase':o.get('phase'),'finish_reason':rp.get('finish_reason') if isinstance(rp,dict) else None,'finish_reason_sha256':hs(rp.get('finish_reason')) if isinstance(rp,dict) and rp.get('finish_reason') is not None else None,'raw_text_length':len(rp.get('raw_text','')) if isinstance(rp,dict) and isinstance(rp.get('raw_text'),str) else None,'text_length':len(rp.get('text','')) if isinstance(rp,dict) and isinstance(rp.get('text'),str) else None,'parsed_response_present':bool(isinstance(rp,dict) and rp.get('parsed_response') is not None),'provider_keys':sorted(pp) if isinstance(pp,dict) else None,'raw_server_response_captured':bool(isinstance(pp,dict) and any(k in pp for k in ('choices','response','body','raw_response','completion'))),'error_sha256':hs(o.get('error')) if o.get('error') is not None else None})
 return recs
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--project-root',required=True,type=Path);ap.add_argument('--debug-jsonl',required=True,type=Path);ap.add_argument('--expected-debug-sha256',required=True);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();root=a.project_root.resolve();debug=a.debug_jsonl.resolve();out=a.out_root.resolve()
 if hf(debug)!=a.expected_debug_sha256.upper():ap.error('Frozen debug SHA-256 mismatch')
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 out.mkdir(parents=True);sources=inspect_sources(root);records=read_debug(debug);raw_captured=any(r['raw_server_response_captured'] for r in records);response_empty=any(r['phase']=='response_received' and r['raw_text_length']==0 and r['text_length']==0 and not r['parsed_response_present'] for r in records)
 determination='RAW_SERVER_RESPONSE_NOT_CAPTURED_BACKEND_OBJECT_EMPTY' if response_empty and not raw_captured else 'RAW_SERVER_RESPONSE_AVAILABLE_FOR_COMPARISON' if raw_captured else 'CONTRACT_REVIEW_REQUIRED'
 summary={'schema':'EX5_2_V5_20','version':VERSION,'source_debug_sha256':hf(debug),'source_debug_size':debug.stat().st_size,'model_rerun_performed':False,'prompt_modified':False,'source_contract_match_count':len(sources),'raw_server_response_captured':raw_captured,'backend_response_object_empty':response_empty,'determination_status':determination,'records':records}
 dump(out/'ex5_2_diagnosis.json',summary);csvout(out/'ex5_2_source_contract.csv',['source_file','source_sha256','symbol','start_line','end_line','source_segment_sha256','matched_terms'],sources);csvout(out/'ex5_2_debug_records.csv',['record_index','phase','finish_reason','finish_reason_sha256','raw_text_length','text_length','parsed_response_present','provider_keys','raw_server_response_captured','error_sha256'],[{**r,'provider_keys':json.dumps(r['provider_keys'])} for r in records]);files=[p for p in out.iterdir() if p.is_file()];csvout(out/'ex5_2_manifest.csv',['artifact','size_bytes','sha256'],[{'artifact':p.name,'size_bytes':p.stat().st_size,'sha256':hf(p)} for p in files]);print(json.dumps({k:v for k,v in summary.items() if k!='records'},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
