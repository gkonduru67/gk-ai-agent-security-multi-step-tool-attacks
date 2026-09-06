#!/usr/bin/env python3
"""EX5.3 read-only server transport to agent decision reconciliation.

Consumes frozen server_transport.jsonl and agent_debug.jsonl. It performs no
model execution and serializes only structure, counts, lengths, hashes, finish
reasons, decision types, and non-sensitive tool names. It never emits prompt
text, model prose, reasoning, protected values, or tool arguments.
"""
from __future__ import annotations
import argparse,csv,hashlib,json
from pathlib import Path
from typing import Any
VERSION='EX5_3_SERVER_TRANSPORT_TO_AGENT_DECISION_RECONCILIATION_v5.30'
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
def load_jsonl(path):
 out=[]
 for i,line in enumerate(path.read_text(encoding='utf-8',errors='replace').splitlines()):
  try:o=json.loads(line);out.append((i,o,hs(line)))
  except Exception as e:out.append((i,{'_json_error':type(e).__name__},hs(line)))
 return out
def leaf(v,path='$',out=None):
 if out is None:out=[]
 if isinstance(v,dict):
  out.append((path,'object',len(v),None,None))
  for k,x in v.items():leaf(x,f'{path}.{k}',out)
 elif isinstance(v,list):
  out.append((path,'array',len(v),None,None))
  for i,x in enumerate(v):leaf(x,f'{path}[{i}]',out)
 elif isinstance(v,str):out.append((path,'string',None,len(v),hs(v)))
 elif v is None:out.append((path,'null',None,None,None))
 else:out.append((path,type(v).__name__,None,None,hs(v)))
 return out
def transport_rows(records):
 rows=[]
 for i,o,rh in records:
  phase=o.get('phase');rows.append({'record_index':i,'record_sha256':rh,'phase':phase,'http_status':o.get('http_status'),'body_size':o.get('body_size'),'body_sha256':o.get('body_sha256'),'choices_count':o.get('choices_count'),'message_content_length':o.get('message_content_length'),'message_content_sha256':o.get('message_content_sha256'),'tool_calls_count':o.get('tool_calls_count'),'tool_calls_shape_sha256':o.get('tool_calls_shape_sha256'),'finish_reason':o.get('finish_reason'),'usage_shape_sha256':hs(o.get('usage_shape')) if o.get('usage_shape') is not None else None,'request_sha256':o.get('request_sha256')})
 return rows
def agent_rows(records):
 rows=[]
 for i,o,rh in records:
  rp=o.get('response_payload') if isinstance(o.get('response_payload'),dict) else {};dp=o.get('decision_payload') if isinstance(o.get('decision_payload'),dict) else {};phase=o.get('phase');raw=rp.get('raw_text');text=rp.get('text');parsed=rp.get('parsed_response')
  tool_name=None
  for key in ('tool_name','name'):
   if key in dp and isinstance(dp[key],str):tool_name=dp[key]
  rows.append({'record_index':i,'record_sha256':rh,'phase':phase,'turn_index':o.get('turn_index'),'finish_reason':rp.get('finish_reason'),'raw_text_length':len(raw) if isinstance(raw,str) else None,'raw_text_sha256':hs(raw) if isinstance(raw,str) else None,'text_length':len(text) if isinstance(text,str) else None,'text_sha256':hs(text) if isinstance(text,str) else None,'parsed_response_present':parsed is not None,'parsed_response_shape_sha256':hs(leaf(parsed)) if parsed is not None else None,'decision_emitted':phase=='decision_emitted','decision_type':dp.get('type') or dp.get('decision_type'),'canonical_tool_name':tool_name,'error_sha256':hs(o.get('error')) if o.get('error') is not None else None})
 return rows
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--server-transport',required=True,type=Path);ap.add_argument('--agent-debug',required=True,type=Path);ap.add_argument('--expected-transport-sha256',required=True);ap.add_argument('--expected-debug-sha256',required=True);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();tp=a.server_transport.resolve();dp=a.agent_debug.resolve();out=a.out_root.resolve()
 if hf(tp)!=a.expected_transport_sha256.upper():ap.error('Frozen transport SHA-256 mismatch')
 if hf(dp)!=a.expected_debug_sha256.upper():ap.error('Frozen debug SHA-256 mismatch')
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 out.mkdir(parents=True);tr=transport_rows(load_jsonl(tp));ar=agent_rows(load_jsonl(dp));responses=[r for r in tr if r['phase']=='http_response'];received=[r for r in ar if r['phase']=='response_received'];decisions=[r for r in ar if r['decision_emitted']];errors=[r for r in ar if r['phase']=='parse_error']
 server_tool=any((r.get('tool_calls_count') or 0)>0 for r in responses);server_text=any((r.get('message_content_length') or 0)>0 for r in responses);agent_parsed=any(r.get('parsed_response_present') for r in received);agent_text=any((r.get('text_length') or 0)>0 or (r.get('raw_text_length') or 0)>0 for r in received)
 if decisions:classification='CANONICAL_DECISION_EMITTED'
 elif errors:classification='AGENT_PARSE_ERROR_AFTER_SERVER_RESPONSE'
 elif server_tool and not agent_parsed:classification='SERVER_TOOL_CALL_NOT_PRESERVED_IN_BACKEND_RESPONSE'
 elif server_text and not agent_text:classification='SERVER_CONTENT_NOT_PRESERVED_IN_BACKEND_RESPONSE'
 elif not server_tool and not server_text:classification='SERVER_RETURNED_NO_VISIBLE_CONTENT_OR_TOOL_CALLS'
 else:classification='RECONCILIATION_INCOMPLETE'
 summary={'schema':'EX5_3_V5_30','version':VERSION,'model_rerun_performed':False,'prompt_modified':False,'source_transport_sha256':hf(tp),'source_debug_sha256':hf(dp),'transport_record_count':len(tr),'agent_record_count':len(ar),'server_response_count':len(responses),'agent_response_received_count':len(received),'agent_decision_count':len(decisions),'agent_parse_error_count':len(errors),'server_nonempty_content_present':server_text,'server_tool_calls_present':server_tool,'agent_nonempty_text_present':agent_text,'agent_parsed_response_present':agent_parsed,'classification':classification,'behavioral_source_selection':'WITHHELD' if not decisions else 'REQUIRES_DECISION_PAYLOAD_REVIEW','attack_optimization_authorized':False}
 dump(out/'ex5_3_reconciliation.json',summary);csvout(out/'ex5_3_transport_records.csv',list(tr[0]) if tr else ['record_index'],tr);csvout(out/'ex5_3_agent_records.csv',list(ar[0]) if ar else ['record_index'],ar);files=[p for p in out.iterdir() if p.is_file()];csvout(out/'ex5_3_manifest.csv',['artifact','size_bytes','sha256'],[{'artifact':p.name,'size_bytes':p.stat().st_size,'sha256':hf(p)} for p in files]);print(json.dumps(summary,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
