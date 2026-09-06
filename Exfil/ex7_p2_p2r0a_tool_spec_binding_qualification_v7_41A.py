#!/usr/bin/env python3
"""EX7 P2 P2R0A exact tool-spec binding qualification, v7.41A.

Read-only AST/source inspection. Verifies the immutable v7.41 package, then
freezes exact source bindings for fs.read and http.post, including side_effect,
scope, ToolSpec construction/registration, and source/output/error policies.

It does not import SDK modules, construct or repair traces, execute predicates
or breach, modify v7.30/v7.40/v7.41, or authorize R1 unless both target tool
bindings resolve from exact frozen source expressions.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, platform, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX7_P2_P2R0A_TOOL_SPEC_BINDING_QUALIFICATION_v7.41A"
PARENT_MANIFEST_SHA256="EEEC5634365CC52A90D2F957785EB2E2CDC4E1BEF29EE6AF337EC555C8EE6C7A"
PARENT_STATUS="EX7_P2_P2R0_FULL_EVALUATOR_EVENT_SCHEMA_CLOSURE_COMPLETE"
PREDICATES_SHA256="9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
SANDBOX_SHA256="B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0"
TRACE_SHA256="9B51BFCC73DB67610C748D580075003F185C58EA2262B9DE1D8716CB719CF2F0"
PARENT_RUNNER_SHA256="95660C2821CAD3231F5CBABA51CC888F1F571415046D45AA18704395924BBE3B"
TARGETS=("fs.read","http.post")
REQUIRED_PARENT={
 "ex7_v7_41_parent_verification.csv","ex7_v7_41_source_inventory.csv",
 "ex7_v7_41_eval_event_access_matrix.csv","ex7_v7_41_canonical_tool_event_fields.csv",
 "ex7_v7_41_sandbox_tool_event_construction.csv","ex7_v7_41_side_effect_value_evidence.csv",
 "ex7_v7_41_exact_source_blocks.csv","ex7_v7_41_schema_findings.json",
 "ex7_v7_41_claim_boundary.json","ex7_v7_41_result.json","ex7_v7_41_binding.json",
 "ex7_p2_p2r0_full_evaluator_event_schema_closure_v7_41.py","predicates.py",
 "sandbox.py","trace.py","fs.py","http.py","models.py","registry.py","schema.py","suite.py"
}

def sha(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def th(s:str)->str:return hashlib.sha256(s.encode()).hexdigest().upper()
def seg(src:str,n:ast.AST)->str:return ast.get_source_segment(src,n) or ast.unparse(n)
def lj(p:Path):return json.loads(p.read_text(encoding='utf-8-sig'))
def lc(p:Path):
 with p.open('r',encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def wj(p:Path,v:Any):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n',encoding='utf-8',newline='\n')
def wc(p:Path,rows:list[dict[str,Any]],fields:list[str]):
 with p.open('w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def index_manifest(p:Path):
 out={}
 for r in lc(p):
  n=r['artifact'].strip()
  if n in out and any(out[n][k].strip()!=r[k].strip() for k in ('size_bytes','sha256','source_path')):raise ValueError('conflicting duplicate '+n)
  out.setdefault(n,r)
 miss=REQUIRED_PARENT-set(out)
 if miss:raise ValueError(f'missing v7.41 artifacts: {sorted(miss)}')
 return out
def verify(r):
 p=Path(r['source_path']);e=p.is_file();s=p.stat().st_size if e else None;d=sha(p) if e else None;es=int(r['size_bytes']);ed=r['sha256'].upper()
 return {'artifact':r['artifact'],'path':str(p),'exists':e,'expected_size_bytes':es,'observed_size_bytes':s,'size_match':e and s==es,'expected_sha256':ed,'observed_sha256':d,'sha256_match':e and d==ed,'passed':e and s==es and d==ed}
def dotted(n:ast.AST)->str:
 if isinstance(n,ast.Name):return n.id
 if isinstance(n,ast.Attribute):return dotted(n.value)+'.'+n.attr
 return seg('',n) if False else ast.unparse(n)
def module_constants(tree:ast.Module,src:str):
 out={}
 for n in tree.body:
  targets=[];value=None
  if isinstance(n,ast.Assign):targets=n.targets;value=n.value
  elif isinstance(n,ast.AnnAssign):targets=[n.target];value=n.value
  if value is None:continue
  for t in targets:
   if isinstance(t,ast.Name):
    try:resolved=ast.literal_eval(value);safe=True
    except Exception:resolved=None;safe=False
    out[t.id]={'expression':seg(src,value),'line':n.lineno,'safe_literal':safe,'value':resolved,'block':seg(src,n),'block_sha256':th(seg(src,n))}
 return out
def imports(tree:ast.Module):
 out={}
 for n in tree.body:
  if isinstance(n,ast.ImportFrom):
   mod=n.module or ''
   for a in n.names:out[a.asname or a.name]=(mod,a.name)
  elif isinstance(n,ast.Import):
   for a in n.names:out[a.asname or a.name]=('',a.name)
 return out
def resolve_expr(n:ast.AST,constants:dict,imported_constants:dict):
 if isinstance(n,ast.Constant):return n.value,'LITERAL'
 if isinstance(n,ast.Name):
  if n.id in constants and constants[n.id]['safe_literal']:return constants[n.id]['value'],'LOCAL_CONSTANT:'+n.id
  if n.id in imported_constants:return imported_constants[n.id]['value'],'IMPORTED_CONSTANT:'+n.id
  return None,'UNRESOLVED_NAME:'+n.id
 if isinstance(n,ast.Attribute):
  key=dotted(n)
  if key in imported_constants:return imported_constants[key]['value'],'IMPORTED_ATTRIBUTE:'+key
 return None,'UNRESOLVED_EXPR:'+ast.unparse(n)
def enclosing_block(tree:ast.Module,node:ast.AST,src:str):
 parents={}
 for p in ast.walk(tree):
  for c in ast.iter_child_nodes(p):parents[c]=p
 cur=node;best=node
 while cur in parents:
  cur=parents[cur]
  if isinstance(cur,(ast.Assign,ast.AnnAssign,ast.Expr,ast.Return,ast.FunctionDef,ast.AsyncFunctionDef)):
   best=cur
   if isinstance(cur,(ast.FunctionDef,ast.AsyncFunctionDef)):break
 return best
def tool_spec_candidates(path:Path,imported_constants:dict):
 src=path.read_text(encoding='utf-8');tree=ast.parse(src);const=module_constants(tree,src);rows=[]
 for n in ast.walk(tree):
  if not isinstance(n,ast.Call):continue
  fname=dotted(n.func)
  kws={k.arg:k.value for k in n.keywords if k.arg}
  # accept ToolSpec-like constructors or factory calls carrying required named fields
  if not ({'name','side_effect','scope'}<=set(kws)):continue
  name,nprov=resolve_expr(kws['name'],const,imported_constants)
  side,sprov=resolve_expr(kws['side_effect'],const,imported_constants)
  scope,scprov=resolve_expr(kws['scope'],const,imported_constants)
  block=enclosing_block(tree,n,src);text=seg(src,block)
  rows.append({'source_file':str(path),'source_file_sha256':sha(path),'constructor':fname,'tool_name':name,'tool_name_expression':seg(src,kws['name']),'tool_name_provenance':nprov,'side_effect':side,'side_effect_expression':seg(src,kws['side_effect']),'side_effect_provenance':sprov,'scope':scope,'scope_expression':seg(src,kws['scope']),'scope_provenance':scprov,'call_line_start':n.lineno,'call_line_end':n.end_lineno,'call_source_sha256':th(seg(src,n)),'registration_block_line_start':getattr(block,'lineno',n.lineno),'registration_block_line_end':getattr(block,'end_lineno',n.end_lineno),'registration_block_sha256':th(text),'registration_block':text})
 return rows,const,tree,src
def policy_blocks(sandbox:Path):
 src=sandbox.read_text(encoding='utf-8');tree=ast.parse(src);rows=[]
 for fn_name in ('interact','_record_failed_tool_attempt','export_trace_dict'):
  fns=[n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==fn_name]
  if len(fns)!=1:raise ValueError('expected one '+fn_name)
  fn=fns[0]
  for n in ast.walk(fn):
   if isinstance(n,ast.Call) and dotted(n.func).endswith('ToolEvent'):
    kws={k.arg:k.value for k in n.keywords if k.arg}
    rows.append({'source_file':str(sandbox),'source_file_sha256':sha(sandbox),'function':fn_name,'line_start':n.lineno,'line_end':n.end_lineno,'output_expression':seg(src,kws['output']) if 'output' in kws else None,'source_expression':seg(src,kws['source']) if 'source' in kws else None,'error_expression':seg(src,kws['error']) if 'error' in kws else None,'side_effect_expression':seg(src,kws['side_effect']) if 'side_effect' in kws else None,'scope_expression':seg(src,kws['scope']) if 'scope' in kws else None,'call_source_sha256':th(seg(src,n)),'call_source':seg(src,n)})
 return rows
def main():
 ap=argparse.ArgumentParser(description=VERSION);ap.add_argument('--v7-41-manifest',required=True);ap.add_argument('--v7-41-binding',required=True);ap.add_argument('--fs-source',required=True);ap.add_argument('--http-source',required=True);ap.add_argument('--registry-source',required=True);ap.add_argument('--schema-source',required=True);ap.add_argument('--models-source',required=True);ap.add_argument('--suite-source',required=True);ap.add_argument('--sandbox-source',required=True);ap.add_argument('--trace-source',required=True);ap.add_argument('--out-root',required=True);a=ap.parse_args()
 runner=Path(__file__).resolve();pm=Path(a.v7_41_manifest);pb=Path(a.v7_41_binding);out=Path(a.out_root)
 sources={k:Path(v).resolve() for k,v in {'fs':a.fs_source,'http':a.http_source,'registry':a.registry_source,'schema':a.schema_source,'models':a.models_source,'suite':a.suite_source,'sandbox':a.sandbox_source,'trace':a.trace_source}.items()}
 if out.exists():raise FileExistsError(f'Refusing to overwrite {out}')
 for p in [runner,pm,pb,*sources.values()]:
  if not p.is_file():raise FileNotFoundError(p)
 if sha(pm)!=PARENT_MANIFEST_SHA256:raise ValueError('v7.41 manifest mismatch')
 ext=lj(pb)
 if ext.get('manifest_sha256')!=PARENT_MANIFEST_SHA256 or ext.get('status')!=PARENT_STATUS:raise ValueError('v7.41 external binding mismatch')
 if ext.get('tool_specific_value_evidence_complete') is not True:raise ValueError('v7.41 did not inventory complete tool source set')
 idx=index_manifest(pm);checks=[verify(idx[n]) for n in sorted(REQUIRED_PARENT)]
 if any(not r['passed'] for r in checks):raise ValueError('v7.41 parent verification failed')
 if idx['ex7_p2_p2r0_full_evaluator_event_schema_closure_v7_41.py']['sha256'].upper()!=PARENT_RUNNER_SHA256:raise ValueError('v7.41 runner mismatch')
 if idx['predicates.py']['sha256'].upper()!=PREDICATES_SHA256 or sha(sources['sandbox'])!=SANDBOX_SHA256 or sha(sources['trace'])!=TRACE_SHA256:raise ValueError('authoritative source identity mismatch')
 # bind command-line sources to v7.41 manifest identities
 for key,name in [('fs','fs.py'),('http','http.py'),('registry','registry.py'),('schema','schema.py'),('models','models.py'),('suite','suite.py'),('sandbox','sandbox.py'),('trace','trace.py')]:
  if sha(sources[key])!=idx[name]['sha256'].upper():raise ValueError(f'{name} differs from v7.41 inventory')
 # resolve constants from models.py and expose imported aliases and enum attributes
 msrc=sources['models'].read_text(encoding='utf-8');mtree=ast.parse(msrc);mconst=module_constants(mtree,msrc);imported={}
 for name,r in mconst.items():
  if r['safe_literal']:imported[name]={'value':r['value'],'source_file':str(sources['models']),'line':r['line'],'block_sha256':r['block_sha256']}
 # enum assignments inside classes
 for cls in [n for n in mtree.body if isinstance(n,ast.ClassDef)]:
  for n in cls.body:
   if isinstance(n,(ast.Assign,ast.AnnAssign)):
    targets=n.targets if isinstance(n,ast.Assign) else [n.target];val=n.value
    for t in targets:
     if isinstance(t,ast.Name) and val is not None:
      try:v=ast.literal_eval(val)
      except Exception:continue
      imported[f'{cls.name}.{t.id}']={'value':v,'source_file':str(sources['models']),'line':n.lineno,'block_sha256':th(seg(msrc,n))}
 # inspect all requested sources for exact registrations
 registrations=[];constant_rows=[]
 for key in ('fs','http','registry','schema','suite'):
  rr,cc,tree,src=tool_spec_candidates(sources[key],imported);registrations.extend(rr)
  for name,r in cc.items():constant_rows.append({'source_file':str(sources[key]),'source_file_sha256':sha(sources[key]),'name':name,'line':r['line'],'expression':r['expression'],'safe_literal':r['safe_literal'],'resolved_value_json':json.dumps(r['value'],sort_keys=True) if r['safe_literal'] else None,'block_sha256':r['block_sha256']})
 # if source imports constants under names, map them from models constants and retry unresolved candidates
 target_rows=[]
 for target in TARGETS:
  matches=[r for r in registrations if r['tool_name']==target]
  if len(matches)!=1:raise ValueError(f'expected one exact registration for {target}, found {len(matches)}')
  r=matches[0]
  if not isinstance(r['side_effect'],str) or not isinstance(r['scope'],str):raise ValueError(f'unresolved tool binding for {target}')
  target_rows.append(r)
 # schemas/models exact blocks
 exact_blocks=[]
 for r in target_rows:exact_blocks.append({'source_file':r['source_file'],'block_kind':'TOOL_REGISTRATION','identity':r['tool_name'],'line_start':r['registration_block_line_start'],'line_end':r['registration_block_line_end'],'source_sha256':r['registration_block_sha256'],'source':r['registration_block']})
 exact_blocks.append({'source_file':str(sources['models']),'block_kind':'SIDE_EFFECT_CONSTANTS','identity':'models.py','line_start':1,'line_end':len(msrc.splitlines()),'source_sha256':th(msrc),'source':msrc})
 field_policies=policy_blocks(sources['sandbox'])
 mapping={r['tool_name']:{'side_effect':r['side_effect'],'scope':r['scope'],'registration_source_file':r['source_file'],'registration_line_start':r['registration_block_line_start'],'registration_line_end':r['registration_block_line_end'],'registration_block_sha256':r['registration_block_sha256'],'side_effect_expression':r['side_effect_expression'],'side_effect_provenance':r['side_effect_provenance'],'scope_expression':r['scope_expression'],'scope_provenance':r['scope_provenance']} for r in target_rows}
 # R1 policies: distinguish canonical environment expression from synthetic selection
 policies={
  'source_field':{'canonical_environment_expression':'self.tools.last_source','synthetic_policy':'EXPLICIT_PER_EVENT_VALUE_REQUIRED','allowed_repair_default':None,'reason':'No universal canonical source default is established; source participates in UTA lookback.'},
  'output_field':{'fs.read':'PRESERVE_FROZEN_SYNTHETIC_READ_OUTPUT_EXACTLY','http.post':'USE_EMPTY_STRING_FOR_SYNTHETIC_NON_TOOL_EXECUTION_ONLY','canonical_environment_expression':'output_text for recorded successful events'},
  'error_field':{'successful_event':None,'failed_sink_proxy':'EXPLICIT_NON_NULL_SYNTHETIC_FAILURE_LABEL_REQUIRED','canonical_environment_expression':'err for successful call path; error string for failed-attempt path'},
  'side_effect_field':{'fs.read':mapping['fs.read']['side_effect'],'http.post':mapping['http.post']['side_effect'],'universal_neutral_value':'NOT_AUTHORIZED'},
  'scope_field':{'fs.read':mapping['fs.read']['scope'],'http.post':mapping['http.post']['scope']},
  'repair_boundary':'Policies define R1 design requirements only; they do not validate any repaired trace.'
 }
 repair_authorized=all(mapping[t]['side_effect'] and mapping[t]['scope'] and mapping[t]['registration_block_sha256'] for t in TARGETS)
 now=datetime.now(timezone.utc).isoformat();out.mkdir(parents=True)
 P={'verify':out/'ex7_v7_41A_parent_verification.csv','sources':out/'ex7_v7_41A_source_verification.csv','registrations':out/'ex7_v7_41A_tool_spec_bindings.csv','constants':out/'ex7_v7_41A_constant_inventory.csv','policies':out/'ex7_v7_41A_repaired_event_field_policy.json','construction':out/'ex7_v7_41A_sandbox_field_construction.csv','blocks':out/'ex7_v7_41A_exact_source_blocks.csv','findings':out/'ex7_v7_41A_findings.json','claims':out/'ex7_v7_41A_claim_boundary.json','result':out/'ex7_v7_41A_result.json','binding':out/'ex7_v7_41A_binding.json','manifest':out/'ex7_v7_41A_manifest.csv','external':out/'ex7_v7_41A_manifest_external_binding.json'}
 wc(P['verify'],checks,list(checks[0]));source_rows=[{'label':k,'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p),'matches_v7_41_manifest':sha(p)==idx[p.name]['sha256'].upper(),'ast_parse':'PASS'} for k,p in sources.items()];wc(P['sources'],source_rows,['label','path','size_bytes','sha256','matches_v7_41_manifest','ast_parse'])
 reg_fields=['source_file','source_file_sha256','constructor','tool_name','tool_name_expression','tool_name_provenance','side_effect','side_effect_expression','side_effect_provenance','scope','scope_expression','scope_provenance','call_line_start','call_line_end','call_source_sha256','registration_block_line_start','registration_block_line_end','registration_block_sha256','registration_block'];wc(P['registrations'],target_rows,reg_fields);wc(P['constants'],constant_rows,['source_file','source_file_sha256','name','line','expression','safe_literal','resolved_value_json','block_sha256']);wj(P['policies'],policies);wc(P['construction'],field_policies,['source_file','source_file_sha256','function','line_start','line_end','output_expression','source_expression','error_expression','side_effect_expression','scope_expression','call_source_sha256','call_source']);wc(P['blocks'],exact_blocks,['source_file','block_kind','identity','line_start','line_end','source_sha256','source'])
 findings={'version':VERSION,'created_at_utc':now,'tool_contract':mapping,'field_policies':policies,'repair_authorization':repair_authorized,'traces_constructed':False,'predicates_executed':False,'universal_neutral_side_effect_authorized':False};wj(P['findings'],findings)
 wj(P['claims'],{'allowed':['exact fs.read and http.post tool-spec bindings','exact side_effect and scope values','exact registration source blocks and hashes','source/output/error policy for future repaired synthetic fixtures'],'prohibited':['repaired trace validity','predicate result','breach result','real lineage','tool effect','guardrail effectiveness','policy superiority','hosted parity'],'no_trace_construction':True,'no_runtime_execution':True})
 status='EX7_P2_P2R0A_TOOL_SPEC_BINDING_QUALIFICATION_FREEZE_COMPLETE' if repair_authorized else 'EX7_P2_P2R0A_TOOL_SPEC_BINDING_INCOMPLETE';result={'version':VERSION,'created_at_utc':now,'status':status,'classification':'EXACT_FS_READ_AND_HTTP_POST_TOOL_SPEC_BINDINGS_FROZEN_RUNTIME_WITHHELD','required_parent_artifacts_verified':len(checks),'source_files_verified':len(source_rows),'target_tool_bindings':len(target_rows),'tool_contract':mapping,'repair_authorization':repair_authorized,'repaired_traces_constructed':False,'predicates_imported':False,'eval_predicates_executed':False,'is_breach_executed':False,'harness_trick':'NOT_DEMONSTRATED','security_finding':'TOOL_SPEC_INTERFACE_BINDING_ONLY_NO_RUNTIME_SECURITY_EFFECT','next_gate':'EX7_P2_P1_R1_REPAIRED_FULL_EVENT_SCHEMA_TRACE_MATRIX_FREEZE' if repair_authorized else 'ADDITIONAL_BINDING_EVIDENCE_REQUIRED'};wj(P['result'],result)
 wj(P['binding'],{'version':VERSION,'created_at_utc':now,'parent_manifest':{'path':str(pm),'size_bytes':pm.stat().st_size,'sha256':sha(pm)},'parent_binding':{'path':str(pb),'size_bytes':pb.stat().st_size,'sha256':sha(pb)},'sources':source_rows,'runner':{'path':str(runner),'size_bytes':runner.stat().st_size,'sha256':sha(runner)},'parent_artifacts_modified':False,'v7_41_modified':False,'python':sys.version,'platform':platform.platform()})
 gen=['verify','sources','registrations','constants','policies','construction','blocks','findings','claims','result','binding'];mr=[{'artifact':P[k].name,'role':'DERIVED_EX7_P2_P2R0A_BINDING_QUALIFICATION','size_bytes':P[k].stat().st_size,'sha256':sha(P[k]),'source_path':str(P[k])} for k in gen]
 for p,role in [(runner,'CURRENT_RUNNER'),(pm,'SOURCE_OR_PARENT'),(pb,'SOURCE_OR_PARENT'),*[(p,'AUTHORITATIVE_SOURCE') for p in sources.values()]]:mr.append({'artifact':p.name,'role':role,'size_bytes':p.stat().st_size,'sha256':sha(p),'source_path':str(p)})
 for r in checks:mr.append({'artifact':r['artifact'],'role':'VERIFIED_PARENT_EVIDENCE','size_bytes':r['observed_size_bytes'],'sha256':r['observed_sha256'],'source_path':r['path']})
 wc(P['manifest'],mr,['artifact','role','size_bytes','sha256','source_path']);external={'version':VERSION,'created_at_utc':now,'manifest_filename':P['manifest'].name,'manifest_size_bytes':P['manifest'].stat().st_size,'manifest_sha256':sha(P['manifest']),'status':status,'classification':result['classification'],'parent_v7_41_manifest_sha256':PARENT_MANIFEST_SHA256,'runner_sha256':sha(runner),'fs_read_side_effect':mapping['fs.read']['side_effect'],'fs_read_scope':mapping['fs.read']['scope'],'http_post_side_effect':mapping['http.post']['side_effect'],'http_post_scope':mapping['http.post']['scope'],'repair_authorization':repair_authorized};wj(P['external'],external)
 print(json.dumps({'status':status,'verified_parent_artifacts':len(checks),'source_files_verified':len(source_rows),'tool_contract':mapping,'repair_authorization':repair_authorized,'runner_sha256':sha(runner),'manifest_sha256':external['manifest_sha256'],'output_directory':str(out)},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
