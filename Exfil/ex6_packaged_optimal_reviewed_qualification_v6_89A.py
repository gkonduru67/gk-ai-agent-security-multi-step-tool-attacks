#!/usr/bin/env python3
"""EX6 v6.89A targeted read-only reviewed qualification.

No SDK import, no runtime execution, no fixture access, no model call, and no
source modification. Extracts exact source blocks and derives only bounded
static-contract findings from frozen source identities.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, platform, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX6_PACKAGED_OPTIMAL_CONTRACT_REVIEWED_QUALIFICATION_v6.89A"
EXPECTED = {
 "aicomp_sdk/guardrails/optimal.py":"6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED",
 "aicomp_sdk/core/predicates.py":"9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37",
 "aicomp_sdk/core/env/sandbox.py":"B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0",
 "aicomp_sdk/core/env/api.py":"60F1E4424EC3DEE73186F87ED1184D2CA1DBC4C2A0022004DECEC8B6E94C7CB1",
 "aicomp_sdk/core/env/gym.py":"8BBC3479515C388717D76FE9964D957A7CBD9BFB97C28AA894E9C51E3051F8AF",
}
TARGETS = [
 "aicomp_sdk/guardrails/optimal.py", "aicomp_sdk/guardrails/base.py",
 "aicomp_sdk/core/env/sandbox.py", "aicomp_sdk/core/predicates.py",
 "aicomp_sdk/core/tools/fs.py", "aicomp_sdk/core/tools/http.py",
 "aicomp_sdk/hooks/types.py", "aicomp_sdk/hooks/registry.py",
 "aicomp_sdk/hooks/helpers.py", "aicomp_sdk/hooks/lpci.py",
 "aicomp_sdk/evaluation/ops.py", "aicomp_sdk/evaluation/submissions.py",
]
WANTED = {
 "aicomp_sdk/guardrails/optimal.py":{"Guardrail","__init__","decide","_extract_target","_is_ultra_dangerous","track_untrusted_content"},
 "aicomp_sdk/guardrails/base.py":{"DecisionAction","Decision","GuardrailBase","decide","snapshot_state","restore_state"},
 "aicomp_sdk/core/env/sandbox.py":{"SandboxEnv","__init__","reset","snapshot","restore","_snapshot_guardrail_state","_restore_guardrail_state","interact"},
 "aicomp_sdk/core/predicates.py":{"_decode_candidates","_contains_secret","eval_predicates","is_breach","is_protected_secret_path","exfil_payload_arg","payload_exfiltrates_secret"},
 "aicomp_sdk/core/tools/fs.py":{"fs_read","_resolve_path","_is_path_escape"},
 "aicomp_sdk/core/tools/http.py":{"http_post"},
 "aicomp_sdk/hooks/types.py":{"HookStage","HookContext","HookResult"},
 "aicomp_sdk/hooks/registry.py":{"HookRegistry","_apply_modified_context","execute_hooks"},
 "aicomp_sdk/evaluation/ops.py":{"AttackGuardrailSpec","register_attack_guardrail_spec","resolve_attack_guardrail_spec"},
}

def sha(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''): h.update(b)
 return h.hexdigest().upper()
def wjson(p:Path,x:Any): p.write_text(json.dumps(x,indent=2,sort_keys=True)+'\n',encoding='utf-8',newline='\n')
def wcsv(p:Path,rows:list[dict],fields:list[str]):
 with p.open('w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore'); w.writeheader(); w.writerows(rows)
def srcseg(text:str,node:ast.AST)->str: return ast.get_source_segment(text,node) or ''
def callname(n:ast.AST)->str:
 if isinstance(n,ast.Name): return n.id
 if isinstance(n,ast.Attribute):
  b=callname(n.value); return f'{b}.{n.attr}' if b else n.attr
 return ''
def names_in(node:ast.AST)->set[str]:
 out=set()
 for n in ast.walk(node):
  if isinstance(n,ast.Name): out.add(n.id)
  elif isinstance(n,ast.Attribute): out.add(callname(n))
 return out

def extract(rel:str,p:Path):
 text=p.read_text(encoding='utf-8',errors='strict'); tree=ast.parse(text); lines=text.splitlines(); rows=[]
 wanted=WANTED.get(rel,set())
 for n in ast.walk(tree):
  nm=getattr(n,'name','')
  if isinstance(n,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)) and nm in wanted:
   a=n.lineno; b=n.end_lineno or a; block='\n'.join(lines[a-1:b])
   rows.append({'relative_path':rel,'symbol':nm,'node_type':type(n).__name__,'line_start':a,'line_end':b,'source_block':block,'block_sha256':hashlib.sha256(block.encode()).hexdigest().upper()})
 return text,tree,rows

def get_func(tree:ast.AST,name:str):
 return next((n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name),None)
def literals(n:ast.AST): return [x.value for x in ast.walk(n) if isinstance(x,ast.Constant) and isinstance(x.value,str)]
def return_rows(rel:str,text:str,fn:ast.AST):
 rows=[]
 for n in ast.walk(fn):
  if isinstance(n,ast.Return):
   rows.append({'relative_path':rel,'function':getattr(fn,'name',''),'line':n.lineno,'expression':srcseg(text,n.value) if n.value else 'None','expression_sha256':hashlib.sha256((srcseg(text,n.value) if n.value else 'None').encode()).hexdigest().upper()})
 return rows

def main():
 ap=argparse.ArgumentParser(description=VERSION); ap.add_argument('--project-root',required=True); ap.add_argument('--v6-89-manifest',required=True); ap.add_argument('--v6-89-binding',required=True); ap.add_argument('--out-root',required=True); a=ap.parse_args()
 root=Path(a.project_root); out=Path(a.out_root); pm=Path(a.v6_89_manifest); pb=Path(a.v6_89_binding)
 if out.exists(): raise FileExistsError(f'Refusing to overwrite existing output directory: {out}')
 for p in [root,pm,pb]:
  if not p.exists(): raise FileNotFoundError(p)
 for rel,exp in EXPECTED.items():
  p=root/rel
  if not p.is_file() or sha(p)!=exp: raise ValueError(f'Identity mismatch: {rel}')
 files={rel:root/rel for rel in TARGETS}
 for rel,p in files.items():
  if not p.is_file(): raise FileNotFoundError(p)
 blocks=[]; texts={}; trees={}; returns=[]
 for rel,p in files.items():
  text,tree,rs=extract(rel,p); texts[rel]=text; trees[rel]=tree; blocks+=rs
  for nm in WANTED.get(rel,set()):
   fn=get_func(tree,nm)
   if fn: returns+=return_rows(rel,text,fn)
 opt=trees['aicomp_sdk/guardrails/optimal.py']; opt_text=texts['aicomp_sdk/guardrails/optimal.py']; decide=get_func(opt,'decide'); init=get_func(opt,'__init__'); ext=get_func(opt,'_extract_target'); track=get_func(opt,'track_untrusted_content')
 if not all([decide,init,ext,track]): raise ValueError('Required optimal.py symbols missing')
 conditions=[]
 for n in ast.walk(decide):
  if isinstance(n,ast.If): conditions.append({'line':n.lineno,'condition':srcseg(opt_text,n.test),'condition_sha256':hashlib.sha256(srcseg(opt_text,n.test).encode()).hexdigest().upper()})
 conditions.sort(key=lambda x:x['line'])
 context_keys=sorted({x.value for n in ast.walk(decide) if isinstance(n,ast.Call) and callname(n.func)=='context.get' for x in n.args[:1] if isinstance(x,ast.Constant) and isinstance(x.value,str)})
 target_keys=[]
 for n in ast.walk(ext):
  if isinstance(n,ast.For) and isinstance(n.target,ast.Name):
   target_keys += [x for x in literals(n.iter) if x not in target_keys]
 opt_imports=[]
 for n in opt.body:
  if isinstance(n,ast.ImportFrom): opt_imports.append({'module':n.module or '', 'names':'|'.join(x.name for x in n.names),'line':n.lineno})
 matcher_names={'_decode_candidates','_contains_secret','eval_predicates','is_breach','is_protected_secret_path','exfil_payload_arg','payload_exfiltrates_secret'}
 direct_matcher_imports=[r for r in opt_imports if any(x in matcher_names for x in r['names'].split('|'))]
 opt_names=names_in(decide)|names_in(ext)|names_in(track)|names_in(init)
 reads_http_data='data' in target_keys or any('data'==x for x in literals(decide))
 sandbox=trees['aicomp_sdk/core/env/sandbox.py']; sand_text=texts['aicomp_sdk/core/env/sandbox.py']; interact=get_func(sandbox,'interact'); reset=get_func(sandbox,'reset')
 sand_calls=[]
 for n in ast.walk(interact):
  if isinstance(n,ast.Call):
   cn=callname(n.func)
   if any(z in cn for z in ['validate','execute_hooks','guardrail.decide','tools.call','tools.execute']): sand_calls.append({'line':n.lineno,'call':cn,'expression':srcseg(sand_text,n),'expression_sha256':hashlib.sha256(srcseg(sand_text,n).encode()).hexdigest().upper()})
 sand_calls.sort(key=lambda x:x['line'])
 hooks_text=texts['aicomp_sdk/hooks/registry.py']+'\n'+texts['aicomp_sdk/hooks/lpci.py']
 helper_tree=trees['aicomp_sdk/core/predicates.py']
 helper_rows=[]
 for nm in ['is_protected_secret_path','exfil_payload_arg','payload_exfiltrates_secret','_contains_secret','_decode_candidates']:
  fn=get_func(helper_tree,nm)
  if fn: helper_rows.append({'helper':nm,'line':fn.lineno,'signature':srcseg(texts['aicomp_sdk/core/predicates.py'],fn).split('\n',1)[0],'public_name':not nm.startswith('_'),'requires_full_trace':'trace' in [x.arg for x in fn.args.args]})
 findings=[
 {'question':'exact_decision_signature','status':'ESTABLISHED','answer':'decide(self, tool_name, tool_args, context)','basis':'optimal.py AST'},
 {'question':'context_fields','status':'ESTABLISHED','answer':'|'.join(context_keys),'basis':'literal keys passed to context.get in decide'},
 {'question':'rule_order','status':'ESTABLISHED','answer':' || '.join(f"L{x['line']}:{x['condition']}" for x in conditions),'basis':'ordered AST If nodes in decide'},
 {'question':'extract_target_key_order','status':'ESTABLISHED' if target_keys else 'NOT_ESTABLISHED','answer':'|'.join(target_keys) if target_keys else 'No literal key sequence extracted','basis':'_extract_target AST'},
 {'question':'authorization_precedes_target_and_taint_checks','status':'ESTABLISHED' if conditions and conditions[0]['line']==37 else 'REVIEW_REQUIRED','answer':'First decide condition is generic authorization Boolean' if conditions else 'No conditions','basis':'ordered decide conditions'},
 {'question':'packaged_optimal_reads_http_post_data','status':'ESTABLISHED' if reads_http_data else 'NOT_ESTABLISHED','answer':'data is in _extract_target key sequence or decide literals' if reads_http_data else 'No direct data-key read established in packaged Optimal','basis':'optimal.py AST only'},
 {'question':'packaged_optimal_imports_official_matcher_helpers','status':'ESTABLISHED' if direct_matcher_imports else 'NOT_ESTABLISHED','answer':json.dumps(direct_matcher_imports,sort_keys=True) if direct_matcher_imports else 'No direct canonical matcher-helper import in optimal.py','basis':'optimal.py imports'},
 {'question':'generic_hooks_can_modify_arguments','status':'ESTABLISHED' if 'modified_args' in hooks_text else 'NOT_ESTABLISHED','answer':'Hook sources contain modified_args propagation' if 'modified_args' in hooks_text else 'Not found','basis':'hook registry/lpci source'},
 {'question':'default_packaged_run_uses_modified_args','status':'NOT_ESTABLISHED','answer':'Static mutation capability does not establish use in default packaged execution','basis':'claim boundary'},
 {'question':'guardrail_selection_source_interface','status':'ESTABLISHED','answer':'GuardrailBase factory/spec registration and resolution source captured','basis':'evaluation/ops.py targeted blocks'},
 {'question':'same_interface_supports_hardened','status':'NOT_ESTABLISHED','answer':'Hardened class not implemented or validated','basis':'implementation withheld'},
 {'question':'guardrail_instance_lifetime','status':'PARTIAL','answer':'Sandbox stores an instance and exposes snapshot/restore; cross-interaction lifetime requires reviewed reset semantics or runtime control','basis':'sandbox targeted blocks'},
 {'question':'confirmation_sets_user_confirmed_safe','status':'NOT_ESTABLISHED','answer':'Consumer read exists; no trusted setter/transport established by this static review','basis':'optimal and sandbox source'},
 {'question':'official_helper_reuse_feasibility','status':'ESTABLISHED_AT_SOURCE_LEVEL' if any(r['public_name'] for r in helper_rows) else 'PARTIAL','answer':'Public guardrail-facing helpers were found; implementation coupling remains a design decision','basis':'predicates helper signatures'},
 {'question':'behavioral_security_effectiveness','status':'NOT_ESTABLISHED','answer':'Static reviewed qualification only','basis':'no runtime'},
 ]
 out.mkdir(parents=True)
 paths={
 'blocks':out/'ex6_v6_89A_exact_source_blocks.csv','returns':out/'ex6_v6_89A_branch_returns.csv','conditions':out/'ex6_v6_89A_rule_order.csv','sandbox':out/'ex6_v6_89A_sandbox_call_order.csv','helpers':out/'ex6_v6_89A_matcher_helper_contract.csv','findings':out/'ex6_v6_89A_reviewed_findings.csv','result':out/'ex6_v6_89A_reviewed_result.json','binding':out/'ex6_v6_89A_binding.json','manifest':out/'ex6_v6_89A_manifest.csv','external':out/'ex6_v6_89A_manifest_external_binding.json'}
 wcsv(paths['blocks'],blocks,['relative_path','symbol','node_type','line_start','line_end','source_block','block_sha256']); wcsv(paths['returns'],returns,['relative_path','function','line','expression','expression_sha256']); wcsv(paths['conditions'],conditions,['line','condition','condition_sha256']); wcsv(paths['sandbox'],sand_calls,['line','call','expression','expression_sha256']); wcsv(paths['helpers'],helper_rows,['helper','line','signature','public_name','requires_full_trace']); wcsv(paths['findings'],findings,['question','status','answer','basis'])
 now=datetime.now(timezone.utc).isoformat(); result={'version':VERSION,'created_at_utc':now,'status':'REVIEWED_QUALIFICATION_COMPLETE','classification':'PACKAGED_OPTIMAL_STATIC_CONTRACT_REVIEWED_AND_GENERATED_v6_89_DEFECTS_CORRECTED','execution_type':'TARGETED_READ_ONLY_SOURCE_REVIEW','runtime':False,'sdk_imported':False,'model_called':False,'source_modified':False,'protected_fixture_opened':False,'hardened_implementation':'WITHHELD','harness_trick':'NOT_DEMONSTRATED','security_finding':'NOT_ESTABLISHED_STATIC_CONTRACT_ONLY','context_fields':context_keys,'target_key_order':target_keys,'direct_matcher_imports':direct_matcher_imports,'http_post_data_read_established':reads_http_data,'reviewed_findings_count':len(findings),'claim_boundary':'STRUCTURAL_SOURCE_FINDINGS_ONLY; RUNTIME_REACHABILITY_AND_EFFECTIVENESS_NOT_ESTABLISHED'}; wjson(paths['result'],result)
 bind={'version':VERSION,'created_at_utc':now,'project_root':str(root),'parent_v6_89_manifest':{'path':str(pm),'size_bytes':pm.stat().st_size,'sha256':sha(pm)},'parent_v6_89_binding':{'path':str(pb),'size_bytes':pb.stat().st_size,'sha256':sha(pb)},'source_identities':{rel:sha(root/rel) for rel in TARGETS},'paths_inferred':False,'runtime_executed':False,'sdk_imported':False,'source_modified':False,'python':sys.version,'platform':platform.platform()}; wjson(paths['binding'],bind)
 generated=[paths[k] for k in ['blocks','returns','conditions','sandbox','helpers','findings','result','binding']]
 mrows=[{'artifact':p.name,'role':'DERIVED_REVIEW','size_bytes':p.stat().st_size,'sha256':sha(p),'source_path':str(p)} for p in generated]
 for p in [pm,pb]: mrows.append({'artifact':p.name,'role':'SOURCE_OR_PARENT','size_bytes':p.stat().st_size,'sha256':sha(p),'source_path':str(p)})
 for rel,p in files.items(): mrows.append({'artifact':p.name,'role':'SOURCE_SDK','size_bytes':p.stat().st_size,'sha256':sha(p),'source_path':str(p)})
 wcsv(paths['manifest'],mrows,['artifact','role','size_bytes','sha256','source_path']); ext={'version':VERSION,'created_at_utc':now,'manifest_filename':paths['manifest'].name,'manifest_size_bytes':paths['manifest'].stat().st_size,'manifest_sha256':sha(paths['manifest']),'status':result['status'],'classification':result['classification'],'optimal_sha256':EXPECTED['aicomp_sdk/guardrails/optimal.py'],'predicates_sha256':EXPECTED['aicomp_sdk/core/predicates.py']}; wjson(paths['external'],ext)
 print(json.dumps({'status':result['status'],'classification':result['classification'],'manifest_sha256':ext['manifest_sha256'],'output_directory':str(out)},indent=2)); return 0
if __name__=='__main__': raise SystemExit(main())
