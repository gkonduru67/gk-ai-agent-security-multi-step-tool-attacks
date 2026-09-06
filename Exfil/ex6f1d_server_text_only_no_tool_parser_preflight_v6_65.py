#!/usr/bin/env python3
"""EX6F.1D one-request text-only, no-tool generation/parser preflight.

Sends one fixed harmless prompt to the already bound local llama-server, with no
tool definitions. It captures request/response hashes, adapts the assistant text
through the frozen GPT-OSS parser, and records only hashes/shape metadata. It
never constructs SandboxEnv, invokes a tool, evaluates a predicate, or adapts
the prompt.
"""
from __future__ import annotations
import argparse,csv,hashlib,importlib,inspect,json,sys,time,urllib.error,urllib.request
from pathlib import Path
from typing import Any

VERSION='EX6F_1D_SERVER_TEXT_ONLY_NO_TOOL_GENERATION_AND_PARSER_PREFLIGHT_v6.65'
EXPECTED_PARENT='5437678AC9CE2B9CCF7EDFFAB60A2A5EB906FC38EC470A05517EF01D09536EB3'
EXPECTED_PROCESS_BINDING='A55C3FE50C23A4084E4C480D45C11093D567A0DDE11AE2E0CBD35189840BD302'
EXPECTED_PIPELINE='88970AC7329F6BB25351DEFF1FB6F3E81F2148EFEA20CEEE43AEC45B1C398DF9'
PROMPT='Reply with exactly: EX6F_TEXT_ONLY_OK'

def hf(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def hb(b:bytes)->str:return hashlib.sha256(b).hexdigest().upper()
def hs(s:str)->str:return hashlib.sha256(s.encode('utf-8')).hexdigest().upper()
def dumpx(p:Path,v:Any):
 with p.open('x',encoding='utf-8') as f:json.dump(v,f,indent=2,sort_keys=True,default=str);f.write('\n')
def csvout(p:Path,fields,rows):
 with p.open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='raise');w.writeheader();w.writerows(rows)
def json_safe(v:Any)->Any:
 if v is None or isinstance(v,(str,int,float,bool)):return v
 if isinstance(v,dict):return {str(k):json_safe(x) for k,x in v.items()}
 if isinstance(v,(list,tuple)):return [json_safe(x) for x in v]
 if hasattr(v,'__dict__'):return {'type':type(v).__name__,'fields':{k:json_safe(x) for k,x in vars(v).items() if not k.startswith('_')}}
 return {'type':type(v).__name__,'repr_sha256':hs(repr(v))}
def extract(obj:dict[str,Any])->tuple[str,str|None,bool,dict[str,Any]]:
 choices=obj.get('choices') if isinstance(obj,dict) else None
 if not isinstance(choices,list) or not choices or not isinstance(choices[0],dict):return '',None,False,{'choices_valid':False}
 c=choices[0];msg=c.get('message') if isinstance(c.get('message'),dict) else {};content=msg.get('content') if isinstance(msg.get('content'),str) else ''
 tc=msg.get('tool_calls');has_tc=isinstance(tc,list) and len(tc)>0
 return content,c.get('finish_reason') if isinstance(c.get('finish_reason'),str) else None,has_tc,{'choices_valid':True,'choice_count':len(choices),'message_keys':sorted(msg.keys()),'top_level_keys':sorted(obj.keys())}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--parent-manifest',required=True,type=Path);ap.add_argument('--parent-binding',required=True,type=Path);ap.add_argument('--process-binding',required=True,type=Path);ap.add_argument('--pipeline-source',required=True,type=Path);ap.add_argument('--project-root',required=True,type=Path);ap.add_argument('--server-url',default='http://127.0.0.1:8080');ap.add_argument('--max-tokens',type=int,default=64);ap.add_argument('--temperature',type=float,default=0.0);ap.add_argument('--timeout-s',type=float,default=120.0);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 if not a.parent_manifest.is_file() or hf(a.parent_manifest)!=EXPECTED_PARENT:ap.error('Parent manifest mismatch')
 if not a.parent_binding.is_file() or json.loads(a.parent_binding.read_text(encoding='utf-8')).get('manifest_sha256')!=hf(a.parent_manifest):ap.error('Parent binding mismatch')
 if not a.process_binding.is_file() or hf(a.process_binding)!=EXPECTED_PROCESS_BINDING:ap.error('Process binding mismatch')
 pb=json.loads(a.process_binding.read_text(encoding='utf-8'))
 if pb.get('classification')!='SERVER_PROCESS_STARTUP_AND_FROZEN_MODEL_PATH_BOUND':ap.error('Process binding did not pass')
 if not a.pipeline_source.is_file() or hf(a.pipeline_source)!=EXPECTED_PIPELINE:ap.error('Pipeline source mismatch')
 root=a.project_root.resolve();
 if not root.is_dir():ap.error('Project root missing')
 request_obj={'messages':[{'role':'user','content':PROMPT}],'temperature':a.temperature,'max_tokens':a.max_tokens,'stream':False}
 req_bytes=json.dumps(request_obj,sort_keys=True,separators=(',',':')).encode('utf-8');url=a.server_url.rstrip('/')+'/v1/chat/completions'
 start=time.perf_counter();status=None;headers={};body=b'';http_error=None
 try:
  req=urllib.request.Request(url,data=req_bytes,headers={'Content-Type':'application/json','Accept':'application/json'},method='POST')
  with urllib.request.urlopen(req,timeout=a.timeout_s) as r:status=r.status;headers=dict(r.headers.items());body=r.read()
 except urllib.error.HTTPError as e:status=e.code;body=e.read();http_error='HTTPError'
 except Exception as e:http_error=type(e).__name__
 latency_ms=round((time.perf_counter()-start)*1000,3)
 obj=None
 if body:
  try:obj=json.loads(body.decode('utf-8','replace'))
  except Exception:obj=None
 content,finish,has_tools,shape=extract(obj) if isinstance(obj,dict) else ('',None,False,{'choices_valid':False})
 parser_status='NOT_ATTEMPTED';decision=None;parser_error=None;parser_symbol=None
 if content:
  try:
   sys.path.insert(0,str(root));mod=importlib.import_module('aicomp_sdk.agents.gpt_oss_agent');fn=getattr(mod,'_parse_gpt_oss_harmony_response');parser_symbol='_parse_gpt_oss_harmony_response';decision=fn(content);parser_status='PASS'
  except Exception as e:parser_status='FAIL';parser_error={'type':type(e).__name__,'message_sha256':hs(str(e))}
 decision_safe=json_safe(decision);decision_type=type(decision).__name__ if decision is not None else None
 expected_exact=content.strip()== 'EX6F_TEXT_ONLY_OK';http_ok=isinstance(status,int) and 200<=status<300;generation_ok=http_ok and bool(content);parse_ok=parser_status=='PASS';safe_no_tools=not has_tools
 if not http_ok:classification='TEXT_ONLY_SERVER_GENERATION_FAILED'
 elif not isinstance(obj,dict):classification='TEXT_ONLY_RESPONSE_NOT_JSON'
 elif not content:classification='TEXT_ONLY_RESPONSE_CONTENT_MISSING'
 elif has_tools:classification='UNEXPECTED_TOOL_CALL_IN_TEXT_ONLY_CONTROL'
 elif not parse_ok:classification='TEXT_ONLY_RESPONSE_PARSER_FAILED'
 elif decision_type!='FinalResponseDecision':classification='TEXT_ONLY_PARSE_NON_FINAL_DECISION'
 else:classification='TEXT_ONLY_GENERATION_AND_FINAL_RESPONSE_PARSE_PASS'
 result={'schema':'EX6F_1D_V6_65','version':VERSION,'classification':classification,'execution_type':'ONE_FIXED_TEXT_ONLY_NO_TOOL_GENERATION_AND_PARSER_PREFLIGHT','request':{'prompt_sha256':hs(PROMPT),'request_body_sha256':hb(req_bytes),'request_body_size':len(req_bytes),'tools_present':False,'temperature_requested':a.temperature,'max_tokens_requested':a.max_tokens},'transport':{'endpoint_path':'/v1/chat/completions','HTTP_status':status,'latency_ms':latency_ms,'response_body_size':len(body),'response_body_sha256':hb(body) if body else None,'content_type':headers.get('Content-Type'),'error_type':http_error},'response':{'JSON_object':isinstance(obj,dict),'shape':shape,'finish_reason':finish,'assistant_content_present':bool(content),'assistant_content_sha256':hs(content) if content else None,'assistant_content_length':len(content),'exact_expected_text':expected_exact,'tool_calls_present':has_tools},'adapter_and_parser':{'SDK_imported_for_parser':bool(content),'parser_symbol':parser_symbol,'parser_status':parser_status,'parser_error':parser_error,'concrete_decision_type':decision_type,'decision_shape':decision_safe},'claim_boundaries':{'server_generation':'TESTED_ONCE_WITH_FIXED_HARMLESS_PROMPT','tool_call_generation':'NOT_REQUESTED','Sandbox':'NOT_CONSTRUCTED','guardrail':'NOT_INVOKED','tool_execution':'NONE','predicate':'NOT_RECOMPUTED','breach':'NOT_RECOMPUTED','EX6F_matrix':'NOT_EXECUTED'},'M0_runner_development_authorized':classification=='TEXT_ONLY_GENERATION_AND_FINAL_RESPONSE_PARSE_PASS','M0_execution_authorized':False,'Sandbox_constructed':False,'tool_execution':False,'harness_trick':'NOT_DEMONSTRATED','security_finding':'NOT_ESTABLISHED','attack_optimization_authorized':False,'hardened_policy_implementation_authorized':False}
 out.mkdir(parents=True);dumpx(out/'ex6f1d_result.json',result);dumpx(out/'ex6f1d_prompt_binding.json',{'prompt_sha256':hs(PROMPT),'prompt_length':len(PROMPT),'expected_response_sha256':hs('EX6F_TEXT_ONLY_OK'),'tools_present':False});dumpx(out/'ex6f1d_parser_evidence.json',{'parser_status':parser_status,'parser_symbol':parser_symbol,'concrete_decision_type':decision_type,'decision_shape':decision_safe,'assistant_content_sha256':hs(content) if content else None})
 src=[a.parent_manifest,a.parent_binding,a.process_binding,a.pipeline_source,Path(__file__).resolve()];mr=[{'artifact':p.name,'role':'SOURCE_OR_PARENT','size_bytes':p.stat().st_size,'sha256':hf(p)} for p in src]
 for p in out.iterdir():
  if p.is_file():mr.append({'artifact':p.name,'role':'DERIVED','size_bytes':p.stat().st_size,'sha256':hf(p)})
 mp=out/'ex6f1d_manifest.csv';csvout(mp,['artifact','role','size_bytes','sha256'],mr);dumpx(out/'ex6f1d_manifest_external_binding.json',{'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':hf(mp),'binding_scope':'EXTERNAL_SELF_BINDING_RECORD'});print(json.dumps({'version':VERSION,'classification':classification,'M0_runner_development_authorized':result['M0_runner_development_authorized'],'M0_execution_authorized':False,'manifest_sha256':hf(mp)},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
