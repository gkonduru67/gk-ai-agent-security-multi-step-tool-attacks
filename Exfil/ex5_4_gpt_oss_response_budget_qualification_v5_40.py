#!/usr/bin/env python3
"""EX5.4 matched GPT-OSS response-budget qualification.

Runs the frozen EX5 prompt at 256, 512, and 1024 max_new_tokens through the
frozen benign_pipeline_EX_v6.py. All other CLI-controlled identities remain
fixed. Each child run retains its own debug, transport, summary, and manifest.
The matrix output stores only structural fields, counts, hashes, decisions, and
classifications. No prompt optimization is performed.
"""
from __future__ import annotations
import argparse,csv,datetime as dt,hashlib,json,subprocess,sys
from pathlib import Path
from typing import Any
VERSION='EX5_4_GPT_OSS_RESPONSE_BUDGET_QUALIFICATION_v5.40'
EXPECTED_PIPELINE_SHA='88970AC7329F6BB25351DEFF1FB6F3E81F2148EFEA20CEEE43AEC45B1C398DF9'
EXPECTED_PROMPT_SHA='3F8BA146E8B3DEDD45EBB4D276A6D55F0BEC8C7C0EFAC2B272B3B21239635176'
BUDGETS=(256,512,1024)
def hb(b):return hashlib.sha256(b).hexdigest().upper()
def hs(x):return hb(str(x).encode('utf-8'))
def hf(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def rid():return dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
def dump(p,x):
 with p.open('x',encoding='utf-8') as f:json.dump(x,f,indent=2,sort_keys=True,default=str);f.write('\n')
def csvout(p,fields,rows):
 with p.open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def jsonl(path):
 out=[]
 if not path.is_file():return out
 for line in path.read_text(encoding='utf-8',errors='replace').splitlines():
  try:out.append(json.loads(line))
  except Exception:pass
 return out
def classify(summary,transport,debug):
 responses=[x for x in transport if x.get('phase')=='http_response'];received=[x for x in debug if x.get('phase')=='response_received'];decisions=[x for x in debug if x.get('phase')=='decision_emitted'];errors=[x for x in debug if x.get('phase')=='parse_error']
 server_text=any((x.get('message_content_length') or 0)>0 for x in responses);server_tools=any((x.get('tool_calls_count') or 0)>0 for x in responses)
 rp=[x.get('response_payload') for x in received if isinstance(x.get('response_payload'),dict)];agent_text=any(len(x.get('text',''))>0 or len(x.get('raw_text',''))>0 for x in rp);agent_parsed=any(x.get('parsed_response') is not None for x in rp)
 decision_type=None;tool_name=None
 if decisions:
  d=decisions[-1].get('decision_payload') or {};decision_type=d.get('type') or d.get('decision_type');tool_name=d.get('tool_name') or d.get('name')
 if decisions:label='CANONICAL_DECISION_EMITTED'
 elif errors and not server_text and not server_tools:label='SERVER_RETURNED_EMPTY_LENGTH_TERMINATED_RESPONSE'
 elif errors:label='AGENT_PARSE_ERROR_AFTER_SERVER_RESPONSE'
 elif server_tools and not agent_parsed:label='SERVER_TOOL_CALL_NOT_PRESERVED'
 elif server_text and not agent_text:label='SERVER_CONTENT_NOT_PRESERVED'
 else:label='FORMATION_OUTCOME_UNRESOLVED'
 last=responses[-1] if responses else {}
 return {'classification':label,'server_http_status':last.get('http_status'),'server_body_sha256':last.get('body_sha256'),'server_body_size':last.get('body_size'),'choices_count':last.get('choices_count'),'finish_reason':last.get('finish_reason'),'message_content_length':last.get('message_content_length'),'message_content_sha256':last.get('message_content_sha256'),'tool_calls_count':last.get('tool_calls_count'),'tool_calls_shape_sha256':last.get('tool_calls_shape_sha256'),'usage_shape_sha256':hs(last.get('usage_shape')) if last.get('usage_shape') is not None else None,'agent_response_received':bool(received),'agent_nonempty_text_present':agent_text,'agent_parsed_response_present':agent_parsed,'agent_parse_error':bool(errors),'canonical_decision_emitted':bool(decisions),'canonical_decision_type':decision_type,'canonical_tool_name':tool_name,'tool_event_count':summary.get('tool_event_count'),'predicates':json.dumps(summary.get('predicates'),sort_keys=True),'breach':summary.get('breach'),'run_error':json.dumps(summary.get('run_error'),sort_keys=True)}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--pipeline',required=True,type=Path);ap.add_argument('--project-root',required=True,type=Path);ap.add_argument('--model-path',required=True,type=Path);ap.add_argument('--server-url',default='http://127.0.0.1:8080');ap.add_argument('--runtime-root',type=Path,default=Path(r'C:\x_ai_logs\Exfil'));ap.add_argument('--out-root',type=Path,default=Path(r'C:\x_ai_logs\Exfil'));ap.add_argument('--max-tool-hops',type=int,default=2);a=ap.parse_args();pipeline=a.pipeline.resolve()
 if hf(pipeline)!=EXPECTED_PIPELINE_SHA:ap.error('Frozen pipeline SHA-256 mismatch')
 matrix_id=rid();out=a.out_root.resolve()/'EX5_4_gpt_oss_response_budget_qualification'/f'matrix_{matrix_id}'
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 out.mkdir(parents=True);rows=[]
 base=a.runtime_root.resolve()/'benign_pipeline_EX_v6';before={p.name for p in base.glob('run_*')} if base.exists() else set()
 for budget in BUDGETS:
  cmd=[sys.executable,str(pipeline),'--project-root',str(a.project_root.resolve()),'--model-path',str(a.model_path.resolve()),'--server-url',a.server_url,'--out-root',str(a.runtime_root.resolve()),'--mode','ex5-frozen','--max-new-tokens',str(budget),'--max-tool-hops',str(a.max_tool_hops)]
  proc=subprocess.run(cmd,capture_output=True,text=True,timeout=1800)
  current=sorted([p for p in base.glob('run_*') if p.name not in before],key=lambda p:p.stat().st_mtime)
  run_dir=current[-1] if current else None
  if run_dir:before.add(run_dir.name)
  summary={};transport=[];debug=[]
  if run_dir and (run_dir/'summary.json').is_file():summary=json.loads((run_dir/'summary.json').read_text(encoding='utf-8'));transport=jsonl(run_dir/'server_transport.jsonl');debug=jsonl(run_dir/'agent_debug.jsonl')
  row={'matrix_id':matrix_id,'budget':budget,'child_exit_code':proc.returncode,'child_run_id':summary.get('run_id'),'child_run_dir':str(run_dir) if run_dir else None,'prompt_sha256':summary.get('prompt_sha256'),'model_sha256':summary.get('model_sha256'),'runner_sha256':summary.get('runner_sha256'),'max_tool_hops':summary.get('max_tool_hops'),'transport_sha256':summary.get('transport_sha256'),'debug_sha256':summary.get('debug_sha256'),**classify(summary,transport,debug)};rows.append(row)
 fields=list(rows[0]);csvout(out/'ex5_4_matrix.csv',fields,rows)
 advancement=any(r['canonical_decision_emitted'] for r in rows)
 result={'schema':'EX5_4_V5_40','version':VERSION,'matrix_id':matrix_id,'pipeline_sha256':hf(pipeline),'prompt_sha256_expected':EXPECTED_PROMPT_SHA,'budgets':list(BUDGETS),'max_tool_hops':a.max_tool_hops,'row_count':len(rows),'all_prompt_hashes_match':all(r['prompt_sha256']==EXPECTED_PROMPT_SHA for r in rows),'all_model_hashes_identical':len({r['model_sha256'] for r in rows})==1,'all_runner_hashes_match':all(r['runner_sha256']==EXPECTED_PIPELINE_SHA for r in rows),'canonical_decision_observed':advancement,'advancement_gate_passed':advancement,'attack_optimization_authorized':False,'rows':rows};dump(out/'ex5_4_result.json',result)
 files=[p for p in out.iterdir() if p.is_file()];csvout(out/'ex5_4_manifest.csv',['artifact','size_bytes','sha256'],[{'artifact':p.name,'size_bytes':p.stat().st_size,'sha256':hf(p)} for p in files]);print(json.dumps({k:v for k,v in result.items() if k!='rows'},indent=2));return 0 if len(rows)==3 and result['all_prompt_hashes_match'] and result['all_runner_hashes_match'] else 2
if __name__=='__main__':raise SystemExit(main())
