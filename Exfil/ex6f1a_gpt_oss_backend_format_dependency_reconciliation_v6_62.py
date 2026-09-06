#!/usr/bin/env python3
"""EX6F.1A read-only GPT-OSS backend-format and dependency reconciliation.

Inspects the frozen GPT-OSS agent, its shared HF adapter/backend/parser/types,
any available llama.cpp backend, the factory, and a previously working GPT-OSS
runner as historical interface evidence. It does not import the SDK, load the
model, contact a server, construct SandboxEnv, or execute prompts/tools.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, re
from pathlib import Path
from typing import Any

VERSION='EX6F_1A_GPT_OSS_BACKEND_FORMAT_DEPENDENCY_RECONCILIATION_v6.62'
EXPECTED_PARENT='ED04D60F8F907C47467D7152423A9DE28A628F031C46EFDAE3A632B7F3078B42'

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
def dotted(n):
 if isinstance(n,ast.Name):return n.id
 if isinstance(n,ast.Attribute):
  p=dotted(n.value);return f'{p}.{n.attr}' if p else n.attr
 return ''
def inspect_source(p:Path)->dict[str,Any]:
 t=p.read_text(encoding='utf-8',errors='replace');tree=ast.parse(t);symbols=[];imports=[];calls=[];env=[]
 for n in ast.walk(tree):
  if isinstance(n,ast.Import):
   for x in n.names:imports.append({'module':x.name,'symbol':'','alias':x.asname or ''})
  elif isinstance(n,ast.ImportFrom):
   for x in n.names:imports.append({'module':n.module or '','symbol':x.name,'alias':x.asname or ''})
  elif isinstance(n,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)):
   body=ast.get_source_segment(t,n) or '';args=[]
   if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):args=[a.arg for a in n.args.args]+[a.arg for a in n.args.kwonlyargs]
   symbols.append({'source_file':p.name,'symbol_type':'class' if isinstance(n,ast.ClassDef) else 'function','symbol':n.name,'start_line':n.lineno,'end_line':getattr(n,'end_lineno',n.lineno),'source_sha256':hs(body),'arguments':' | '.join(args),'mentions_gguf':'gguf' in body.lower(),'mentions_llama_cpp':bool(re.search(r'llama.?cpp|llama_cpp',body,re.I)),'mentions_transformers':'transformers' in body.lower(),'mentions_tokenizer':'tokenizer' in body.lower(),'mentions_generation_kwargs':'generation_kwargs' in body,'mentions_temperature':'temperature' in body.lower(),'mentions_seed':bool(re.search(r'\bseed\b',body,re.I)),'mentions_do_sample':'do_sample' in body.lower(),'mentions_max_new_tokens':'max_new_tokens' in body.lower()})
  elif isinstance(n,ast.Call):
   name=dotted(n.func);src=ast.get_source_segment(t,n) or ''
   if name: calls.append({'source_file':p.name,'line':n.lineno,'callee':name,'source_sha256':hs(src),'mentions_server_url':'server_url' in src,'mentions_backend_kind':'backend_kind' in src,'mentions_model_family':'model_family' in src,'mentions_model_path':'model_path' in src})
  if isinstance(n,ast.Call) and dotted(n.func) in ('os.getenv','os.environ.get') and n.args and isinstance(n.args[0],ast.Constant):env.append(str(n.args[0].value))
 return {'file':p.name,'sha256':hf(p),'symbols':symbols,'imports':imports,'calls':calls,'environment_variables':sorted(set(env))}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--parent-manifest',required=True,type=Path);ap.add_argument('--parent-binding',required=True,type=Path);ap.add_argument('--gpt-oss-agent',required=True,type=Path);ap.add_argument('--factory',required=True,type=Path);ap.add_argument('--hf-agent',required=True,type=Path);ap.add_argument('--transformers-backend',required=True,type=Path);ap.add_argument('--response-parsing',required=True,type=Path);ap.add_argument('--hf-types',required=True,type=Path);ap.add_argument('--debug-source',required=True,type=Path);ap.add_argument('--protocol-source',required=True,type=Path);ap.add_argument('--agent-types',required=True,type=Path);ap.add_argument('--runtime-history',required=True,type=Path);ap.add_argument('--llama-cpp-backend',type=Path);ap.add_argument('--historical-runner',required=True,type=Path);ap.add_argument('--model-artifact',required=True,type=Path);ap.add_argument('--generation-config',required=True,type=Path);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 if not a.parent_manifest.is_file() or hf(a.parent_manifest)!=EXPECTED_PARENT:ap.error('Parent manifest identity mismatch')
 if not a.parent_binding.is_file() or json.loads(a.parent_binding.read_text(encoding='utf-8')).get('manifest_sha256')!=hf(a.parent_manifest):ap.error('Parent binding mismatch')
 sources=[a.gpt_oss_agent,a.factory,a.hf_agent,a.transformers_backend,a.response_parsing,a.hf_types,a.debug_source,a.protocol_source,a.agent_types,a.runtime_history,a.historical_runner]
 if a.llama_cpp_backend:sources.append(a.llama_cpp_backend)
 for p in sources+[a.model_artifact,a.generation_config]:
  if not p.is_file():ap.error(f'Missing input: {p}')
 reports=[inspect_source(p) for p in sources];symbols=[x for r in reports for x in r['symbols']];imports=[x|{'source_file':r['file']} for r in reports for x in r['imports']];calls=[x for r in reports for x in r['calls']]
 byfile={r['file']:r for r in reports};gguf=a.model_artifact.suffix.lower()=='.gguf';tf=byfile[a.transformers_backend.name];ll=byfile.get(a.llama_cpp_backend.name) if a.llama_cpp_backend else None;hist=byfile[a.historical_runner.name]
 transformer_gguf=any(s['mentions_gguf'] or s['mentions_llama_cpp'] for s in tf['symbols'])
 llama_available=ll is not None and any(s['mentions_llama_cpp'] or s['mentions_gguf'] for s in ll['symbols'])
 gpt_imports={i['module'] for i in byfile[a.gpt_oss_agent.name]['imports']}
 gpt_selects_llama=any('llama' in x.lower() for x in gpt_imports) or any(s['mentions_llama_cpp'] for s in byfile[a.gpt_oss_agent.name]['symbols'])
 historical_server_route=any(c['mentions_server_url'] and c['mentions_backend_kind'] for c in hist['calls'])
 historical_local_model_route=any(c['mentions_model_path'] for c in hist['calls'])
 gen=json.loads(a.generation_config.read_text(encoding='utf-8'))
 generation_support={k:any(getattr(s,f'mentions_{k}',False) for s in symbols) for k in ('temperature','seed','do_sample','max_new_tokens')}
 if gguf and transformer_gguf:classification='GGUF_SUPPORT_EXPLICIT_IN_SELECTED_TRANSFORMERS_PATH'
 elif gguf and llama_available and gpt_selects_llama:classification='GGUF_SUPPORT_AVAILABLE_AND_SELECTABLE_BY_GPT_OSS_AGENT'
 elif gguf and llama_available and historical_server_route:classification='GGUF_LOCAL_BACKEND_AVAILABLE_HISTORICAL_RUNNER_USED_SERVER_ROUTE_DIRECT_EQUIVALENCE_NOT_ESTABLISHED'
 elif gguf and llama_available:classification='GGUF_LLAMA_CPP_BACKEND_AVAILABLE_BUT_GPT_OSS_SELECTION_PATH_NOT_ESTABLISHED'
 elif gguf:classification='GGUF_NOT_SUPPORTED_BY_INSPECTED_GPT_OSS_TRANSFORMERS_PATH'
 else:classification='NON_GGUF_ARTIFACT_REQUIRES_BACKEND_SPECIFIC_REVIEW'
 q={'schema':'EX6F_1A_V6_62','version':VERSION,'classification':classification,'execution_type':'READ_ONLY_STATIC_BACKEND_FORMAT_AND_DEPENDENCY_RECONCILIATION','model_artifact':{'filename':a.model_artifact.name,'suffix':a.model_artifact.suffix.lower(),'sha256':hf(a.model_artifact)},'findings':{'selected_transformers_path_explicit_GGUF_support':transformer_gguf,'llama_cpp_backend_supplied':ll is not None,'llama_cpp_or_GGUF_support_in_supplied_backend':llama_available,'GPTOSSAgent_selects_llama_cpp':gpt_selects_llama,'historical_runner_uses_server_route':historical_server_route,'historical_runner_uses_local_model_path':historical_local_model_route,'historical_runner_sha256':hf(a.historical_runner),'generation_field_source_mentions':generation_support,'tokenizer_reference_present':any(s['mentions_tokenizer'] for s in symbols),'generation_kwargs_reference_present':any(s['mentions_generation_kwargs'] for s in symbols)},'claim_boundaries':{'historical_runner_reusable_pattern':'SERVER_TRANSPORT_AND_EVIDENCE_STRUCTURE_ONLY' if historical_server_route else 'STATIC_PATTERN_ONLY','historical_runner_proves_local_GGUF_compatibility':False,'backend_format_compatibility':'ESTABLISHED' if classification in ('GGUF_SUPPORT_EXPLICIT_IN_SELECTED_TRANSFORMERS_PATH','GGUF_SUPPORT_AVAILABLE_AND_SELECTABLE_BY_GPT_OSS_AGENT') else 'NOT_ESTABLISHED','model_loading':'NOT_TESTED','matrix_execution':'NOT_TESTED'},'runtime_authorized':classification in ('GGUF_SUPPORT_EXPLICIT_IN_SELECTED_TRANSFORMERS_PATH','GGUF_SUPPORT_AVAILABLE_AND_SELECTABLE_BY_GPT_OSS_AGENT'),'SDK_imported':False,'model_loaded':False,'Sandbox_constructed':False,'tool_execution':False,'harness_trick':'NOT_DEMONSTRATED','security_finding':'NOT_ESTABLISHED','attack_optimization_authorized':False,'hardened_policy_implementation_authorized':False}
 out.mkdir(parents=True);dumpx(out/'ex6f1a_reconciliation.json',q);csvout(out/'ex6f1a_symbol_inventory.csv',list(symbols[0]),symbols);csvout(out/'ex6f1a_import_inventory.csv',list(imports[0]),imports);csvout(out/'ex6f1a_call_inventory.csv',list(calls[0]),calls);dumpx(out/'ex6f1a_source_reports.json',{'reports':reports})
 srcs=[a.parent_manifest,a.parent_binding,*sources,a.model_artifact,a.generation_config,Path(__file__).resolve()];mr=[{'artifact':p.name,'role':'SOURCE_OR_PARENT','size_bytes':p.stat().st_size,'sha256':hf(p)} for p in srcs]
 for p in out.iterdir():
  if p.is_file():mr.append({'artifact':p.name,'role':'DERIVED','size_bytes':p.stat().st_size,'sha256':hf(p)})
 mp=out/'ex6f1a_manifest.csv';csvout(mp,['artifact','role','size_bytes','sha256'],mr);dumpx(out/'ex6f1a_manifest_external_binding.json',{'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':hf(mp),'binding_scope':'EXTERNAL_SELF_BINDING_RECORD'});print(json.dumps({'version':VERSION,'classification':classification,'runtime_authorized':q['runtime_authorized'],'manifest_sha256':hf(mp)},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
