#!/usr/bin/env python3
"""EX6F-M4A authorization-transport preflight v6.83.

Read-only static inspection. Finds every reference, setter, constructor path,
and documented input surface for user_authorized/user_confirmed_safe across
Sandbox, API, Gym, CLI, hooks, and the SDK tree. No SDK module is imported or
executed. No model, Sandbox, tool, guardrail, predicate, or breach is run.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, re
from pathlib import Path
VERSION='EX6F_M4A_AUTHORIZATION_TRANSPORT_PREFLIGHT_v6.83'
PARENT_SHA='0A1A1C70B3866EE11912E5069618E52BD67800DDE2F8B7DCDA80053ADBDD9A2D'
TERMS=(
 'user_authorized','user_confirmed_safe','confirmed_safe','authorized',
 'authorization','confirmation','guardrail context','guardrail_context',
 'context','GuardrailContext','ctx'
)
PRIMARY=(
 'aicomp_sdk/core/env/sandbox.py','aicomp_sdk/core/env/api.py',
 'aicomp_sdk/core/env/gym.py','aicomp_sdk/cli/commands/test.py',
 'aicomp_sdk/guardrails/optimal.py'
)
def hb(b):return hashlib.sha256(b).hexdigest().upper()
def hf(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def jw(p,x):
 with Path(p).open('x',encoding='utf-8') as f:json.dump(x,f,indent=2,sort_keys=True);f.write('\n')
def cw(p,fields,rows):
 with Path(p).open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='raise');w.writeheader();w.writerows(rows)
def classify(line):
 s=line.lower()
 if re.search(r'["\']user_(?:authorized|confirmed_safe)["\']\s*[:=]',line):return 'POSSIBLE_SETTER_OR_LITERAL_CONSTRUCTION'
 if '.get(' in s and ('user_authorized' in s or 'user_confirmed_safe' in s):return 'CONSUMER_READ'
 if 'user_authorized' in s or 'user_confirmed_safe' in s:return 'DIRECT_REFERENCE'
 if any(x in s for x in ('argparse','add_argument','field(','basemodel','typeddict','dataclass')):return 'POSSIBLE_INPUT_SCHEMA'
 if any(x in s for x in ('context','ctx')):return 'CONTEXT_RELATED'
 return 'DOCUMENTATION_OR_OTHER'
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--project-root',required=True,type=Path);ap.add_argument('--parent-manifest',required=True,type=Path);ap.add_argument('--parent-binding',required=True,type=Path);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();root=a.project_root.resolve();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 if not a.parent_manifest.is_file() or hf(a.parent_manifest)!=PARENT_SHA:ap.error('v6.82A parent manifest mismatch')
 bind=json.loads(a.parent_binding.read_text(encoding='utf-8'))
 if bind.get('manifest_sha256')!=PARENT_SHA:ap.error('v6.82A external binding mismatch')
 sdk=root/'aicomp_sdk'
 if not sdk.is_dir():ap.error(f'Missing SDK tree: {sdk}')
 files=[]
 for ext in ('*.py','*.md','*.json','*.yaml','*.yml','*.toml'):
  files.extend(sdk.rglob(ext))
 files=sorted(set(p.resolve() for p in files if p.is_file()))
 rows=[]; exact_refs=[]
 for p in files:
  rel=p.relative_to(root).as_posix(); lines=p.read_text(encoding='utf-8',errors='replace').splitlines()
  for n,line in enumerate(lines,1):
   hits=[t for t in TERMS if t.lower() in line.lower()]
   if hits:
    row={'file':rel,'line':n,'terms':'|'.join(hits),'classification':classify(line),'line_sha256':hb(line.encode()),'text':line}
    rows.append(row)
    if 'user_authorized' in line or 'user_confirmed_safe' in line:exact_refs.append(row)
 out.mkdir(parents=True)
 cw(out/'ex6f_m4a_auth_transport_line_evidence.csv',['file','line','terms','classification','line_sha256','text'],rows)
 # AST assignments, calls, function signatures, and symbols for Python sources.
 ast_rows=[]; parse_errors=[]
 for p in [x for x in files if x.suffix=='.py']:
  rel=p.relative_to(root).as_posix(); src=p.read_text(encoding='utf-8',errors='replace')
  try:tree=ast.parse(src)
  except Exception as e:parse_errors.append({'file':rel,'error_type':type(e).__name__,'error_sha256':hb(str(e).encode())});continue
  for node in ast.walk(tree):
   seg=ast.get_source_segment(src,node) or ''
   if not any(t.lower() in seg.lower() for t in TERMS):continue
   kind=None; name=None
   if isinstance(node,(ast.Assign,ast.AnnAssign,ast.AugAssign)):kind='ASSIGNMENT';name=type(node).__name__
   elif isinstance(node,ast.Call):kind='CALL';name=ast.unparse(node.func) if hasattr(ast,'unparse') else 'call'
   elif isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):kind='FUNCTION';name=node.name
   elif isinstance(node,ast.ClassDef):kind='CLASS';name=node.name
   elif isinstance(node,ast.arg):kind='PARAMETER';name=node.arg
   elif isinstance(node,ast.Subscript):kind='SUBSCRIPT';name='subscript'
   if kind:ast_rows.append({'file':rel,'node_kind':kind,'name':name,'start_line':getattr(node,'lineno',None),'end_line':getattr(node,'end_lineno',getattr(node,'lineno',None)),'source_sha256':hb(seg.encode())})
 cw(out/'ex6f_m4a_auth_transport_ast_evidence.csv',['file','node_kind','name','start_line','end_line','source_sha256'],ast_rows)
 jw(out/'ex6f_m4a_auth_transport_parse_errors.json',parse_errors)
 primary=[]
 for rel in PRIMARY:
  p=root/rel
  primary.append({'path':rel,'exists':p.is_file(),'size_bytes':p.stat().st_size if p.is_file() else None,'sha256':hf(p) if p.is_file() else None})
 setters=[r for r in exact_refs if r['classification']=='POSSIBLE_SETTER_OR_LITERAL_CONSTRUCTION']
 consumers=[r for r in exact_refs if r['classification']=='CONSUMER_READ']
 other=[r for r in exact_refs if r not in setters and r not in consumers]
 result={'version':VERSION,'execution_type':'READ_ONLY_AUTHORIZATION_TRANSPORT_SOURCE_INSPECTION','sdk_file_count_inspected':len(files),'primary_sources':primary,'exact_flag_reference_count':len(exact_refs),'possible_setter_count':len(setters),'consumer_read_count':len(consumers),'other_exact_reference_count':len(other),'possible_setter_locations':[{'file':r['file'],'line':r['line'],'line_sha256':r['line_sha256']} for r in setters],'consumer_locations':[{'file':r['file'],'line':r['line'],'line_sha256':r['line_sha256']} for r in consumers],'classification':'M4A_AUTH_TRANSPORT_REVIEW_REQUIRED','answers':{'who_sets_the_flag':'WITHHELD_PENDING_REVIEW','where_it_is_set':'WITHHELD_PENDING_REVIEW','what_input_controls_it':'WITHHELD_PENDING_REVIEW','whether_documented':'WITHHELD_PENDING_REVIEW','whether_trusted':'WITHHELD_PENDING_REVIEW','whether_model_or_prompt_can_influence_it':'WITHHELD_PENDING_REVIEW','whether_persists_across_hops':'WITHHELD_PENDING_REVIEW','whether_action_and_target_bound':'WITHHELD_PENDING_REVIEW'},'runtime_authorized':False,'model_called':False,'sdk_imported':False,'tool_executed':False,'guardrail_executed':False}
 jw(out/'ex6f_m4a_auth_transport_preflight_result.json',result)
 manifest=[]
 for p in (a.parent_manifest,a.parent_binding,Path(__file__).resolve()):manifest.append({'artifact':p.name,'role':'SOURCE_OR_PARENT','size_bytes':p.stat().st_size,'sha256':hf(p)})
 for item in primary:
  if item['exists']:manifest.append({'artifact':item['path'],'role':'AUTHORITATIVE_SOURCE','size_bytes':item['size_bytes'],'sha256':item['sha256']})
 for p in out.iterdir():
  if p.is_file():manifest.append({'artifact':p.name,'role':'DERIVED_READ_ONLY','size_bytes':p.stat().st_size,'sha256':hf(p)})
 mp=out/'ex6f_m4a_auth_transport_manifest.csv';cw(mp,['artifact','role','size_bytes','sha256'],manifest);jw(out/'ex6f_m4a_auth_transport_manifest_external_binding.json',{'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':hf(mp),'parent_manifest_sha256':PARENT_SHA})
 print(json.dumps({'version':VERSION,'sdk_files_inspected':len(files),'exact_flag_references':len(exact_refs),'possible_setters':len(setters),'consumer_reads':len(consumers),'classification':result['classification'],'manifest_sha256':hf(mp)},indent=2))
if __name__=='__main__':main()
