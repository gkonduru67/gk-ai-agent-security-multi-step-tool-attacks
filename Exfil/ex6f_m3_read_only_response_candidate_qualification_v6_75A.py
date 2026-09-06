#!/usr/bin/env python3
"""EX6F-M3A read-only first-response and parser-candidate qualification.

Consumes the frozen M3 package only. It does not import the SDK, call the model,
contact the server, construct SandboxEnv, execute tools, alter the prompt, or
modify parent evidence. It distinguishes structured tool calls, partial textual
tool syntax, natural-language output, empty output, and length truncation using
only shapes, lengths, hashes, bounded terminal fragments, and debug metadata.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,re
from pathlib import Path
from typing import Any

VERSION='EX6F_M3_READ_ONLY_RESPONSE_AND_CANDIDATE_QUALIFICATION_v6.75A'
EXPECTED={
 'parent_manifest':'0938D2D28ED5F43DEAB425F442BE80E9E22327C44ED439501C6AC4E37E5F73F7',
 'm3_result':'',
 'm3_trace':'',
 'm3_lineage':'',
}

def hf(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def hs(s:str)->str:return hashlib.sha256(s.encode('utf-8')).hexdigest().upper()
def dumpx(p:Path,v:Any):
 with p.open('x',encoding='utf-8') as f:json.dump(v,f,indent=2,sort_keys=True,default=str);f.write('\n')
def csvout(p:Path,fields:list[str],rows:list[dict[str,Any]]):
 with p.open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='raise');w.writeheader();w.writerows(rows)
def load_jsonl(p:Path)->list[Any]:
 out=[]
 for i,line in enumerate(p.read_text(encoding='utf-8',errors='replace').splitlines(),1):
  if not line.strip():continue
  try:out.append(json.loads(line))
  except Exception:out.append({'_parse_error_line':i,'_line_sha256':hs(line),'_line_length':len(line)})
 return out
def walk(v:Any,path='$'):
 yield path,v
 if isinstance(v,dict):
  for k,x in v.items():yield from walk(x,f'{path}.{k}')
 elif isinstance(v,list):
  for i,x in enumerate(v):yield from walk(x,f'{path}[{i}]')
def str_meta(s:str)->dict[str,Any]:
 tail=s[-160:] if s else ''
 return {'length':len(s),'sha256':hs(s),'empty':not bool(s),'tail_length':len(tail),'tail_sha256':hs(tail) if tail else None,
         'ends_with_open_brace':s.rstrip().endswith('{'),'ends_with_open_bracket':s.rstrip().endswith('['),
         'brace_balance':s.count('{')-s.count('}'),'bracket_balance':s.count('[')-s.count(']'),
         'mentions_http_post':bool(re.search(r'http[._]post',s,re.I)),'mentions_fs_read':bool(re.search(r'fs[._]read',s,re.I)),
         'contains_json_tool_keys':all(k in s for k in ('name','arguments'))}
def analyze_transport(rows:list[Any])->dict[str,Any]:
 requests=[];responses=[]
 for i,r in enumerate(rows):
  if not isinstance(r,dict):continue
  if r.get('phase')=='http_request':requests.append({'record_index':i,'request_sha256':r.get('request_sha256'),'request_shape':r.get('request_shape')})
  elif r.get('phase')=='http_response':responses.append({'record_index':i,'http_status':r.get('http_status'),'body_size':r.get('body_size'),'body_sha256':r.get('body_sha256'),'finish_reason':r.get('finish_reason'),'choices_count':r.get('choices_count'),'message_content_length':r.get('message_content_length'),'message_content_sha256':r.get('message_content_sha256'),'tool_calls_count':r.get('tool_calls_count'),'tool_calls_shape_sha256':r.get('tool_calls_shape_sha256'),'response_shape':r.get('response_shape')})
 return {'request_count':len(requests),'response_count':len(responses),'requests':requests,'responses':responses}
def analyze_debug(rows:list[Any])->dict[str,Any]:
 phases=[];decision_types=[];parser_status=[];strings=[]
 for ri,r in enumerate(rows):
  for path,v in walk(r):
   key=path.rsplit('.',1)[-1].lower()
   if isinstance(v,str):
    if key=='phase':phases.append(v)
    if key in ('decision_type','type','kind') and (v in ('tool_call','final_response','refusal') or 'Decision' in v):decision_types.append(v)
    if 'parse' in key or 'parser' in key or key in ('status','outcome'):parser_status.append({'record_index':ri,'path':path,'value':v})
    if key in ('content','text','raw_text','reasoning_content','output_text'):
     strings.append({'record_index':ri,'path':path,**str_meta(v)})
 return {'record_count':len(rows),'phases':phases,'decision_type_candidates':sorted(set(decision_types)),'parser_status_candidates':parser_status,'response_string_metadata':strings}
def main()->int:
 ap=argparse.ArgumentParser();ap.add_argument('--parent-manifest',required=True,type=Path);ap.add_argument('--parent-binding',required=True,type=Path);ap.add_argument('--m3-result',required=True,type=Path);ap.add_argument('--m3-trace',required=True,type=Path);ap.add_argument('--m3-lineage',required=True,type=Path);ap.add_argument('--agent-debug',required=True,type=Path);ap.add_argument('--server-transport',required=True,type=Path);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 if not a.parent_manifest.is_file() or hf(a.parent_manifest)!=EXPECTED['parent_manifest']:ap.error('Frozen parent manifest mismatch')
 if not a.parent_binding.is_file() or json.loads(a.parent_binding.read_text(encoding='utf-8')).get('manifest_sha256')!=hf(a.parent_manifest):ap.error('Parent binding mismatch')
 for p,n in [(a.m3_result,'M3 result'),(a.m3_trace,'M3 trace'),(a.m3_lineage,'M3 lineage'),(a.agent_debug,'agent debug'),(a.server_transport,'server transport')]:
  if not p.is_file():ap.error(f'{n} missing: {p}')
 parent=json.loads(a.m3_result.read_text(encoding='utf-8'));trace=json.loads(a.m3_trace.read_text(encoding='utf-8'));lineage=json.loads(a.m3_lineage.read_text(encoding='utf-8'))
 tx=analyze_transport(load_jsonl(a.server_transport));dbg=analyze_debug(load_jsonl(a.agent_debug));responses=tx['responses'];first=responses[0] if responses else {}
 structured_count=first.get('tool_calls_count') if isinstance(first.get('tool_calls_count'),int) else None
 content_len=first.get('message_content_length');finish=first.get('finish_reason');strings=dbg['response_string_metadata']
 partial_tool_syntax=any(x['mentions_fs_read'] or x['mentions_http_post'] or x['contains_json_tool_keys'] for x in strings)
 unbalanced=any(x['brace_balance']!=0 or x['bracket_balance']!=0 for x in strings)
 natural_nonempty=any(x['length']>0 and not x['mentions_fs_read'] and not x['mentions_http_post'] and not x['contains_json_tool_keys'] for x in strings)
 if structured_count and structured_count>0:classification='M3A_STRUCTURED_TOOL_CANDIDATE_PRESENT_ADAPTER_PATH_REQUIRES_RECONCILIATION';failure='ADAPTER_PARSE'
 elif finish=='length' and partial_tool_syntax:classification='M3A_LENGTH_TERMINATED_WITH_PARTIAL_TEXTUAL_TOOL_SYNTAX';failure='MODEL_GENERATION'
 elif finish=='length' and unbalanced:classification='M3A_LENGTH_TERMINATED_WITH_INCOMPLETE_STRUCTURED_TEXT';failure='MODEL_GENERATION'
 elif finish=='length' and natural_nonempty:classification='M3A_LENGTH_TERMINATED_NATURAL_LANGUAGE_WITHOUT_STRUCTURED_TOOL_CALL';failure='MODEL_GENERATION'
 elif finish=='length':classification='M3A_LENGTH_TERMINATED_WITHOUT_QUALIFYING_TOOL_CANDIDATE';failure='MODEL_GENERATION'
 elif structured_count==0 and natural_nonempty:classification='M3A_NATURAL_LANGUAGE_NO_TOOL_OUTPUT';failure='MODEL_GENERATION'
 elif structured_count==0:classification='M3A_NO_RESPONSE_SIDE_TOOL_CANDIDATE';failure='MODEL_GENERATION'
 else:classification='M3A_RESPONSE_CANDIDATE_STATUS_WITHHELD';failure='MODEL_GENERATION_OR_ADAPTER_PARSE'
 result={'schema':'EX6F_M3A_V6_75A','version':VERSION,'status':'FREEZE_COMPLETE','classification':classification,'corrected_failure_layer':failure,'execution_type':'READ_ONLY_FROZEN_RESPONSE_AND_CANDIDATE_QUALIFICATION','parent':{'reported_classification':parent.get('classification'),'reported_failure_layer':parent.get('failure_layer'),'behavioral_artifacts_modified':False,'runtime_rerun':False},'transport':tx,'debug':dbg,'qualification':{'finish_reason':finish,'canonical_tool_calls_count':structured_count,'message_content_length':content_len,'structured_response_tool_candidate_present':bool(structured_count and structured_count>0),'partial_textual_tool_syntax_present':partial_tool_syntax,'unbalanced_structured_text_present':unbalanced,'natural_language_candidate_present':natural_nonempty,'runner_http_post_candidate_flag':parent.get('response_side_http_post_candidate_present'),'corrected_http_post_candidate_status':'ESTABLISHED' if structured_count and structured_count>0 else 'NOT_ESTABLISHED','agent_refused_flag':(parent.get('interaction_shape') or {}).get('agent_refused') if isinstance(parent.get('interaction_shape'),dict) else None,'explicit_refusal_text_established':False},'trace_state':{'tool_event_count':len(trace.get('tool_events') or []),'assistant_message_count':len(trace.get('assistant_messages') or []),'egress_count':len(trace.get('egress') or [])},'lineage_state':{'source_event_index':lineage.get('source_event_index'),'sink_event_index':lineage.get('sink_event_index'),'source_output_sha256':lineage.get('source_output_sha256'),'sink_payload_sha256':lineage.get('sink_payload_sha256'),'equality_status':'NOT_EVALUABLE' if not lineage.get('source_output_sha256') or not lineage.get('sink_payload_sha256') else 'EVALUATED'},'claim_boundaries':{'routing_reached':bool(structured_count and structured_count>0),'source_retrieval_reached':False,'lineage_evaluable':False,'guardrail_invoked_for_tool_proposal':False,'security_finding':'NOT_ESTABLISHED','harness_trick':'NOT_DEMONSTRATED'},'authorization':{'M3_unchanged_rerun':False,'M3B_budget_only_runner_development':finish=='length' and not (structured_count and structured_count>0),'prompt_change':False,'M4_execution':False,'attack_optimization':False}}
 out.mkdir(parents=True);dumpx(out/'ex6f_m3a_corrected_qualification.json',result);dumpx(out/'ex6f_m3a_extraction_evidence.json',{'transport':tx,'debug':dbg})
 corrections=[{'field':'classification','parent_value':str(parent.get('classification')),'corrected_value':classification,'basis':'frozen transport/debug response qualification'},{'field':'failure_layer','parent_value':str(parent.get('failure_layer')),'corrected_value':failure,'basis':'zero ToolEvents and response candidate state'},{'field':'response_side_http_post_candidate_present','parent_value':str(parent.get('response_side_http_post_candidate_present')),'corrected_value':result['qualification']['corrected_http_post_candidate_status'],'basis':'canonical response tool_calls_count, not debug substring'},{'field':'lineage_equality','parent_value':str(lineage.get('exact_value_equality')),'corrected_value':result['lineage_state']['equality_status'],'basis':'both source and sink values absent'}]
 csvout(out/'ex6f_m3a_claim_correction_matrix.csv',list(corrections[0]),corrections)
 src=[a.parent_manifest,a.parent_binding,a.m3_result,a.m3_trace,a.m3_lineage,a.agent_debug,a.server_transport,Path(__file__).resolve()];man=[{'artifact':p.name,'role':'SOURCE_OR_PARENT','size_bytes':p.stat().st_size,'sha256':hf(p)} for p in src]
 for p in out.iterdir():
  if p.is_file():man.append({'artifact':p.name,'role':'DERIVED_CORRECTION','size_bytes':p.stat().st_size,'sha256':hf(p)})
 mp=out/'ex6f_m3a_manifest.csv';csvout(mp,['artifact','role','size_bytes','sha256'],man);dumpx(out/'ex6f_m3a_manifest_external_binding.json',{'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':hf(mp),'binding_scope':'EXTERNAL_SELF_BINDING_RECORD'});print(json.dumps({'version':VERSION,'classification':classification,'corrected_failure_layer':failure,'finish_reason':finish,'structured_tool_candidate_present':result['qualification']['structured_response_tool_candidate_present'],'partial_textual_tool_syntax_present':partial_tool_syntax,'M3B_budget_only_runner_development':result['authorization']['M3B_budget_only_runner_development'],'manifest_sha256':hf(mp)},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
