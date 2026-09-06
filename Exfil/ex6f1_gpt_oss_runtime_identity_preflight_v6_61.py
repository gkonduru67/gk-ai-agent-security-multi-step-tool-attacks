#!/usr/bin/env python3
"""EX6F.1 GPT-OSS runtime identity and interface preflight.

Read-only static inspection. It validates the frozen EX6F design package and
extracts model, agent-factory, adapter, backend, and generation-parameter
interfaces needed before any model-backed packaged-Optimal execution. It does
not import the SDK, load a model, construct SandboxEnv, or execute tools.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, re
from pathlib import Path
from typing import Any

VERSION='EX6F_1_GPT_OSS_RUNTIME_IDENTITY_PREFLIGHT_v6.61'
EXPECTED={
 'design_manifest':'A7AA4695590D955CAFEBF1A8BDAEFA3E564DAFFFC1542EB7CB64EAF020CECD72',
 'matrix':'CFBD200E2FA60D45D7CD29768FB102E24ECA6FCF516D370D5651C11B129314FE',
 'gpt_oss_agent':'E3861EF6A69C470B4B47DE7604621C428D0E2DDDB8CC692EF44C466E37C8298D',
 'factory':'C680BFAD91B1C7FE5AA486E111C6EC1B1650F7EF717E05C07962CB07A922416D',
}
def hf(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def hs(s:str)->str:return hashlib.sha256(s.encode()).hexdigest().upper()
def dumpx(p:Path,v:Any):
 with p.open('x',encoding='utf-8') as f:json.dump(v,f,indent=2,sort_keys=True,default=str);f.write('\n')
def csvout(p:Path,fields:list[str],rows:list[dict[str,Any]]):
 with p.open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='raise');w.writeheader();w.writerows(rows)
def dotted(n):
 if isinstance(n,ast.Name):return n.id
 if isinstance(n,ast.Attribute):
  p=dotted(n.value);return f'{p}.{n.attr}' if p else n.attr
 return ''
def inspect(path:Path)->dict[str,Any]:
 text=path.read_text(encoding='utf-8');tree=ast.parse(text);symbols=[];imports=[];env=[];literals=[]
 for n in ast.walk(tree):
  if isinstance(n,ast.Import):
   for x in n.names:imports.append({'module':x.name,'symbol':'','alias':x.asname or ''})
  elif isinstance(n,ast.ImportFrom):
   for x in n.names:imports.append({'module':n.module or '','symbol':x.name,'alias':x.asname or ''})
  elif isinstance(n,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)):
   body=ast.get_source_segment(text,n) or '';args=[]
   if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):
    args=[a.arg for a in n.args.args]+[a.arg for a in n.args.kwonlyargs]
   symbols.append({'source_file':path.name,'symbol_type':'class' if isinstance(n,ast.ClassDef) else 'function','symbol':n.name,'start_line':n.lineno,'end_line':getattr(n,'end_lineno',n.lineno),'source_sha256':hs(body),'arguments':' | '.join(args),'mentions_model':bool(re.search(r'model|checkpoint|backend',body,re.I)),'mentions_generation':bool(re.search(r'temperature|max_new_tokens|seed|top_p|reasoning_effort',body,re.I)),'mentions_parser':bool(re.search(r'parse|normaliz|tool_call|decision',body,re.I))})
  elif isinstance(n,ast.Call):
   name=dotted(n.func)
   if name in ('os.getenv','os.environ.get') and n.args and isinstance(n.args[0],ast.Constant):env.append(str(n.args[0].value))
  elif isinstance(n,ast.Constant) and isinstance(n.value,str):
   if re.search(r'gpt|model|checkpoint|temperature|max_new_tokens|reasoning|backend|parser',n.value,re.I):literals.append(n.value)
 return {'sha256':hf(path),'imports':imports,'symbols':symbols,'environment_variables':sorted(set(env)),'relevant_string_literals':sorted(set(literals))}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--design-manifest',required=True,type=Path);ap.add_argument('--design-binding',required=True,type=Path);ap.add_argument('--matrix',required=True,type=Path);ap.add_argument('--gpt-oss-agent-source',required=True,type=Path);ap.add_argument('--factory-source',required=True,type=Path);ap.add_argument('--additional-source',action='append',type=Path,default=[]);ap.add_argument('--model-artifact');ap.add_argument('--model-endpoint-id');ap.add_argument('--generation-config',type=Path);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 core={'design_manifest':a.design_manifest,'matrix':a.matrix,'gpt_oss_agent':a.gpt_oss_agent_source,'factory':a.factory_source}
 for n,p in core.items():
  if not p.is_file() or hf(p)!=EXPECTED[n]:ap.error(f'Frozen {n} identity mismatch')
 if not a.design_binding.is_file():ap.error('Design binding missing')
 bind=json.loads(a.design_binding.read_text(encoding='utf-8'))
 if bind.get('manifest_sha256')!=hf(a.design_manifest):ap.error('Design binding mismatch')
 for p in a.additional_source:
  if not p.is_file():ap.error(f'Additional source missing: {p}')
 if a.generation_config and not a.generation_config.is_file():ap.error('Generation config missing')
 inspected=[a.gpt_oss_agent_source,a.factory_source,*a.additional_source];reports=[inspect(p) for p in inspected]
 allsymbols=[s for r in reports for s in r['symbols']];allimports=[i for r in reports for i in r['imports']]
 model_identity=None;model_identity_type='NOT_BOUND'
 if a.model_artifact:
  p=Path(a.model_artifact)
  if p.is_file():model_identity=hf(p);model_identity_type='FILE_SHA256'
  elif p.is_dir():
   manifest='\n'.join(f'{x.relative_to(p).as_posix()}\t{x.stat().st_size}\t{hf(x)}' for x in sorted(p.rglob('*')) if x.is_file())
   model_identity=hs(manifest);model_identity_type='DIRECTORY_MANIFEST_SHA256'
  else:ap.error('model-artifact path not found')
 elif a.model_endpoint_id:
  model_identity=hs(a.model_endpoint_id);model_identity_type='ENDPOINT_ID_SHA256'
 gen=None
 if a.generation_config:gen=json.loads(a.generation_config.read_text(encoding='utf-8'))
 required={'model_identity_bound':model_identity is not None,'generation_config_bound':gen is not None,'agent_source_bound':True,'factory_source_bound':True,'matrix_bound':True,'adapter_or_parser_symbol_found':any(s['mentions_parser'] for s in allsymbols),'model_or_backend_symbol_found':any(s['mentions_model'] for s in allsymbols)}
 ready=all(required.values())
 classification='GPT_OSS_MODEL_RUNTIME_IDENTITY_PREFLIGHT_PASS' if ready else 'GPT_OSS_MODEL_RUNTIME_IDENTITY_PREFLIGHT_INCOMPLETE'
 q={'schema':'EX6F_1_V6_61','version':VERSION,'classification':classification,'execution_type':'READ_ONLY_STATIC_RUNTIME_IDENTITY_PREFLIGHT','gates':required,'model_identity_type':model_identity_type,'model_identity_sha256':model_identity,'generation_config_sha256':hf(a.generation_config) if a.generation_config else None,'generation_config':gen,'environment_variables_referenced':sorted({x for r in reports for x in r['environment_variables']}),'runtime_authorized':ready,'gradient_or_adaptive_prompting_authorized':False,'fixed_matrix_only':True,'SDK_imported':False,'model_loaded':False,'Sandbox_constructed':False,'tool_execution':False,'hardened_policy_implementation_authorized':False,'attack_optimization_authorized':False}
 out.mkdir(parents=True);dumpx(out/'ex6f1_preflight.json',q);csvout(out/'ex6f1_symbol_inventory.csv',list(allsymbols[0]),allsymbols);csvout(out/'ex6f1_import_inventory.csv',list(allimports[0]),allimports);dumpx(out/'ex6f1_source_reports.json',{'reports':reports})
 sources=[a.design_manifest,a.design_binding,a.matrix,*inspected,Path(__file__).resolve()]+([a.generation_config] if a.generation_config else [])
 mr=[{'artifact':p.name,'role':'SOURCE_OR_PARENT','size_bytes':p.stat().st_size,'sha256':hf(p)} for p in sources]
 for p in out.iterdir():
  if p.is_file():mr.append({'artifact':p.name,'role':'DERIVED','size_bytes':p.stat().st_size,'sha256':hf(p)})
 mp=out/'ex6f1_manifest.csv';csvout(mp,['artifact','role','size_bytes','sha256'],mr);dumpx(out/'ex6f1_manifest_external_binding.json',{'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':hf(mp),'binding_scope':'EXTERNAL_SELF_BINDING_RECORD'})
 print(json.dumps({'version':VERSION,'classification':classification,'runtime_authorized':ready,'manifest_sha256':hf(mp)},indent=2));return 0 if ready else 2
if __name__=='__main__':raise SystemExit(main())
