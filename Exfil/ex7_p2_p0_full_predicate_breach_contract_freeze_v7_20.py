#!/usr/bin/env python3
"""EX7 P2 P0 full EXFILTRATION predicate and breach contract freeze.

Read-only AST and exact-source inspection. This runner verifies the frozen P1A
package and predicates.py identity, then captures eval_predicates, is_breach,
payload_exfiltrates_secret, exfil_payload_arg, is_protected_secret_path, and
all source-reachable local helpers and module globals. It does not import or
execute predicates.py, construct traces, evaluate predicates/breach, run a
model/guardrail/Sandbox/Gym/tool, or claim real lineage/effects.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, platform, re, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX7_P2_P0_FULL_PREDICATE_AND_BREACH_CONTRACT_FREEZE_v7.20"
EXPECTED_PARENT_MANIFEST_SHA256="268212FA45906E915E22F1405AC22E316D619F7A346F2DB51A486A032FEDFCAB"
EXPECTED_PARENT_STATUS="EX7_P1A_INDEPENDENT_MATCHER_RESULT_QUALIFICATION_FREEZE_COMPLETE"
EXPECTED_PREDICATES_SHA256="9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
ROOTS=["eval_predicates","is_breach","payload_exfiltrates_secret","exfil_payload_arg","is_protected_secret_path"]
REQUIRED_PARENT={
 "ex7_v7_10A_parent_verification.csv","ex7_v7_10A_raw_canonical_reconciliation.csv",
 "ex7_v7_10A_population_and_call_qualification.csv","ex7_v7_10A_transformation_findings.csv",
 "ex7_v7_10A_finding_claim_matrix.csv","ex7_v7_10A_result.json","ex7_v7_10A_binding.json",
 "ex7_p1a_independent_matcher_result_qualification_v7_10A.py","predicates.py"}
CONTRACT_QUESTIONS=[
 ("CQ01","accepted_trace_event_shape","Exact accepted trace/event object shape"),
 ("CQ02","success_field_semantics","Exact success-field semantics"),
 ("CQ03","fs_read_source_qualification","Exact fs.read source qualification"),
 ("CQ04","protected_path_qualification","Exact protected-path qualification"),
 ("CQ05","source_value_extraction","Exact source-value extraction"),
 ("CQ06","same_trace_ordering","Exact same-trace ordering requirement"),
 ("CQ07","http_post_recognition","Exact http.post sink recognition"),
 ("CQ08","data_argument_extraction","Exact data-argument extraction"),
 ("CQ09","successful_sink_requirement","Exact successful-sink-event requirement"),
 ("CQ10","predicate_representation","Exact EXFILTRATION predicate representation"),
 ("CQ11","predicate_to_breach","Exact predicate-to-breach relationship"),
 ("CQ12","denied_failed_sink_behavior","Whether denied or failed sink events can trigger predicate or breach")]
TRACE_CONTROLS=["EXFIL_SYNTHETIC_PREDICATE_POSITIVE","EXFIL_SOURCE_ONLY","EXFIL_SINK_ONLY","EXFIL_READ_THEN_POST","EXFIL_UNRELATED_POST","EXFIL_ENCODED_DERIVATION","EXFIL_GUARDRAIL_BLOCK","EXFIL_FAILED_SOURCE_ATTRIBUTION","EXFIL_WRONG_SOURCE_VALUE","EXFIL_POST_WITHOUT_SUCCESSFUL_EFFECT"]

def sha(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''): h.update(b)
 return h.hexdigest().upper()
def tsha(s:str)->str:return hashlib.sha256(s.encode()).hexdigest().upper()
def loadj(p:Path):return json.loads(p.read_text(encoding='utf-8-sig'))
def loadc(p:Path):
 with p.open('r',encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def writej(p:Path,v):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n',encoding='utf-8',newline='\n')
def writec(p:Path,rows,fields):
 with p.open('w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def segment(src,node):return ast.get_source_segment(src,node) or ast.unparse(node)
def index_manifest(p):
 rows=loadc(p); out={}
 for r in rows:
  n=r['artifact'].strip()
  if n in out and any(out[n][k].strip()!=r[k].strip() for k in ('size_bytes','sha256','source_path')):raise ValueError(f'Conflicting duplicate {n}')
  out.setdefault(n,r)
 miss=sorted(REQUIRED_PARENT-set(out))
 if miss:raise ValueError(f'Missing P1A artifacts: {miss}')
 return out
def verify(r):
 p=Path(r['source_path']);e=p.is_file();s=p.stat().st_size if e else None;d=sha(p) if e else None;es=int(r['size_bytes']);ed=r['sha256'].upper()
 return {'artifact':r['artifact'],'path':str(p),'exists':e,'expected_size_bytes':es,'observed_size_bytes':s,'size_match':e and s==es,'expected_sha256':ed,'observed_sha256':d,'sha256_match':e and d==ed,'passed':e and s==es and d==ed}
def dotted(n):
 if isinstance(n,ast.Name):return n.id
 if isinstance(n,ast.Attribute):return dotted(n.value)+'.'+n.attr
 return ast.unparse(n)
def calls(n):return sorted({dotted(x.func) for x in ast.walk(n) if isinstance(x,ast.Call)})
def imports(tree):
 out=set()
 for n in tree.body:
  if isinstance(n,ast.Import):out|={a.asname or a.name.split('.')[0] for a in n.names}
  elif isinstance(n,ast.ImportFrom):out|={a.asname or a.name for a in n.names}
 return out
def assignments(tree,src):
 out={}
 for n in tree.body:
  val=None;targets=[]
  if isinstance(n,ast.Assign):val=n.value;targets=n.targets
  elif isinstance(n,ast.AnnAssign):val=n.value;targets=[n.target]
  if val is None:continue
  for t in targets:
   if isinstance(t,ast.Name):
    expr=segment(src,val);safe=True;rv=None
    try:rv=ast.literal_eval(val)
    except Exception:safe=False
    out[t.id]={'name':t.id,'line':n.lineno,'source_expression':expr,'source_expression_sha256':tsha(expr),'safe_literal':safe,'resolved_type':type(rv).__name__ if safe else None,'resolved_value_json':json.dumps(rv,sort_keys=True,ensure_ascii=True) if safe else None}
 return out
def local_closure(funcs,roots):
 sel=set(roots);changed=True
 while changed:
  changed=False
  for name in list(sel):
   for c in calls(funcs[name]):
    leaf=c.rsplit('.',1)[-1]
    if leaf in funcs and leaf not in sel:sel.add(leaf);changed=True
 return sorted(sel,key=lambda x:funcs[x].lineno)
def bound(fn):
 b={a.arg for a in fn.args.posonlyargs+fn.args.args+fn.args.kwonlyargs}
 if fn.args.vararg:b.add(fn.args.vararg.arg)
 if fn.args.kwarg:b.add(fn.args.kwarg.arg)
 for n in ast.walk(fn):
  if isinstance(n,ast.Name) and isinstance(n.ctx,(ast.Store,ast.Del)):b.add(n.id)
  elif isinstance(n,ast.ExceptHandler) and isinstance(n.name,str):b.add(n.name)
 return b
def string_keys(fn):
 rows=[]
 for n in ast.walk(fn):
  if isinstance(n,ast.Subscript):
   sl=n.slice
   if isinstance(sl,ast.Constant) and isinstance(sl.value,str):rows.append((sl.value,n.lineno,'SUBSCRIPT'))
  if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='get' and n.args and isinstance(n.args[0],ast.Constant) and isinstance(n.args[0].value,str):rows.append((n.args[0].value,n.lineno,'GET'))
 return rows

def main():
 ap=argparse.ArgumentParser(description=VERSION);ap.add_argument('--v7-10a-manifest',required=True);ap.add_argument('--v7-10a-binding',required=True);ap.add_argument('--predicates-source',required=True);ap.add_argument('--out-root',required=True);a=ap.parse_args()
 runner=Path(__file__).resolve();pm=Path(a.v7_10a_manifest);pb=Path(a.v7_10a_binding);pred=Path(a.predicates_source).resolve();out=Path(a.out_root)
 if out.exists():raise FileExistsError(f'Refusing to overwrite {out}')
 for p in (runner,pm,pb,pred):
  if not p.is_file():raise FileNotFoundError(p)
 if sha(pm)!=EXPECTED_PARENT_MANIFEST_SHA256:raise ValueError('P1A manifest mismatch')
 ext=loadj(pb)
 if ext.get('manifest_sha256')!=EXPECTED_PARENT_MANIFEST_SHA256 or ext.get('status')!=EXPECTED_PARENT_STATUS:raise ValueError('P1A binding mismatch')
 if sha(pred)!=EXPECTED_PREDICATES_SHA256:raise ValueError('predicates.py mismatch')
 idx=index_manifest(pm);checks=[verify(idx[n]) for n in sorted(REQUIRED_PARENT)]
 if any(not r['passed'] for r in checks):raise ValueError('Parent verification failed')
 src=pred.read_text(encoding='utf-8');tree=ast.parse(src);funcs={n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
 missing=[n for n in ROOTS if n not in funcs]
 if missing:raise ValueError(f'Required functions missing: {missing}')
 clos=local_closure(funcs,ROOTS);imps=imports(tree);assigns=assignments(tree,src);module_names=set(funcs)|set(assigns)|imps
 function_rows=[];call_rows=[];field_rows=[];global_names=set();blocks=[]
 for name in clos:
  fn=funcs[name];b=bound(fn);loads={n.id for n in ast.walk(fn) if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Load)}
  globals_used=sorted(x for x in loads if x in module_names and x not in funcs and x not in imps and x not in b)
  global_names.update(globals_used);text=segment(src,fn)
  function_rows.append({'function':name,'root':name in ROOTS,'visibility':'PRIVATE' if name.startswith('_') else 'PUBLIC','line_start':fn.lineno,'line_end':fn.end_lineno,'args_json':json.dumps([a.arg for a in fn.args.posonlyargs+fn.args.args]),'kwonly_args_json':json.dumps([a.arg for a in fn.args.kwonlyargs]),'source_sha256':tsha(text),'globals_json':json.dumps(globals_used),'calls_json':json.dumps(calls(fn))})
  blocks.append({'function':name,'line_start':fn.lineno,'line_end':fn.end_lineno,'source_sha256':tsha(text),'source':text})
  for c in calls(fn):call_rows.append({'caller':name,'callee':c,'callee_leaf':c.rsplit('.',1)[-1],'local_function':c.rsplit('.',1)[-1] in funcs})
  for key,line,access in string_keys(fn):field_rows.append({'function':name,'field_or_key':key,'line':line,'access_kind':access})
 global_rows=[]
 for name in sorted(global_names):
  r=assigns.get(name)
  global_rows.append(r or {'name':name,'line':None,'source_expression':None,'source_expression_sha256':None,'safe_literal':False,'resolved_type':None,'resolved_value_json':None})
 # Source-evidence hints only; exact answers remain review statuses.
 closure_text='\n'.join(b['source'] for b in blocks);lower=closure_text.lower()
 evidence_map={
  'accepted_trace_event_shape':['trace','event','history'], 'success_field_semantics':['success','succeeded','ok'],
  'fs_read_source_qualification':['fs.read'], 'protected_path_qualification':['protected','secret_path'],
  'source_value_extraction':['output','result','value'], 'same_trace_ordering':['for ','enumerate','index','before','after'],
  'http_post_recognition':['http.post'], 'data_argument_extraction':['data'],
  'successful_sink_requirement':['success','succeeded','ok'], 'predicate_representation':['exfiltration'],
  'predicate_to_breach':['is_breach','breach'], 'denied_failed_sink_behavior':['denied','failed','success']}
 question_rows=[]
 for qid,key,q in CONTRACT_QUESTIONS:
  terms=evidence_map[key];hits=[t for t in terms if t in lower]
  question_rows.append({'question_id':qid,'contract_key':key,'question':q,'source_hint_terms_json':json.dumps(hits),'status':'SOURCE_CAPTURED_REQUIRES_HUMAN_SEMANTIC_REVIEW' if hits else 'WITHHELD_NO_DIRECT_SOURCE_HINT','runtime_validated':False,'claim_boundary':'SOURCE_CONTRACT_ONLY'})
 control_rows=[{'control_id':c,'status':'PLANNED_NOT_CONSTRUCTED','trace_executed':False,'predicate_executed':False,'breach_executed':False,'real_lineage_claim':False} for c in TRACE_CONTROLS]
 now=datetime.now(timezone.utc).isoformat();out.mkdir(parents=True)
 paths={k:out/f'ex7_v7_20_{v}' for k,v in {'verify':'parent_verification.csv','functions':'function_contract.csv','blocks':'exact_source_blocks.csv','calls':'call_graph.csv','globals':'global_dependencies.csv','fields':'event_field_inventory.csv','questions':'contract_question_matrix.csv','controls':'future_trace_control_plan.csv','result':'result.json','binding':'binding.json','manifest':'manifest.csv','external':'manifest_external_binding.json'}.items()}
 writec(paths['verify'],checks,['artifact','path','exists','expected_size_bytes','observed_size_bytes','size_match','expected_sha256','observed_sha256','sha256_match','passed'])
 writec(paths['functions'],function_rows,['function','root','visibility','line_start','line_end','args_json','kwonly_args_json','source_sha256','globals_json','calls_json'])
 writec(paths['blocks'],blocks,['function','line_start','line_end','source_sha256','source'])
 writec(paths['calls'],call_rows,['caller','callee','callee_leaf','local_function'])
 writec(paths['globals'],global_rows,['name','line','source_expression','source_expression_sha256','safe_literal','resolved_type','resolved_value_json'])
 writec(paths['fields'],field_rows,['function','field_or_key','line','access_kind'])
 writec(paths['questions'],question_rows,['question_id','contract_key','question','source_hint_terms_json','status','runtime_validated','claim_boundary'])
 writec(paths['controls'],control_rows,['control_id','status','trace_executed','predicate_executed','breach_executed','real_lineage_claim'])
 result={'version':VERSION,'created_at_utc':now,'status':'EX7_P2_P0_FULL_PREDICATE_AND_BREACH_CONTRACT_FREEZE_COMPLETE','classification':'OFFICIAL_FULL_PREDICATE_AND_BREACH_SOURCE_CONTRACT_FROZEN_TRACE_EXECUTION_WITHHELD','execution_type':'READ_ONLY_AST_AND_EXACT_SOURCE_INSPECTION','required_parent_artifacts_verified':len(checks),'predicates_sha256':sha(pred),'required_root_functions':ROOTS,'local_function_closure':clos,'closure_function_count':len(clos),'module_global_dependency_count':len(global_rows),'event_field_reference_count':len(field_rows),'contract_question_count':len(question_rows),'future_trace_control_count':len(control_rows),'predicates_imported':False,'traces_constructed':False,'traces_executed':False,'eval_predicates_executed':False,'is_breach_executed':False,'matcher_executed':False,'model_used':False,'guardrail_used':False,'sandbox_used':False,'gym_used':False,'tools_executed':False,'effects_observed':False,'harness_trick':'NOT_DEMONSTRATED','security_finding':'NOT_ESTABLISHED_SOURCE_CONTRACT_FREEZE_ONLY','real_lineage_claim':False,'next_gate':'INDEPENDENT_P2_P0_SEMANTIC_REVIEW_BEFORE_TRACE_MATRIX_CONSTRUCTION'}
 writej(paths['result'],result)
 writej(paths['binding'],{'version':VERSION,'created_at_utc':now,'parent_manifest':{'path':str(pm),'size_bytes':pm.stat().st_size,'sha256':sha(pm)},'parent_binding':{'path':str(pb),'size_bytes':pb.stat().st_size,'sha256':sha(pb)},'predicates':{'path':str(pred),'size_bytes':pred.stat().st_size,'sha256':sha(pred)},'runner':{'path':str(runner),'size_bytes':runner.stat().st_size,'sha256':sha(runner)},'verified_parent_artifacts':checks,'source_modified':False,'parent_artifacts_modified':False,'python':sys.version,'platform':platform.platform()})
 generated=['verify','functions','blocks','calls','globals','fields','questions','controls','result','binding'];mrows=[{'artifact':paths[k].name,'role':'DERIVED_EX7_P2_P0_CONTRACT_FREEZE','size_bytes':paths[k].stat().st_size,'sha256':sha(paths[k]),'source_path':str(paths[k])} for k in generated]
 for p,role in ((runner,'CURRENT_RUNNER'),(pm,'SOURCE_OR_PARENT'),(pb,'SOURCE_OR_PARENT'),(pred,'AUTHORITATIVE_PREDICATE_SOURCE')):mrows.append({'artifact':p.name,'role':role,'size_bytes':p.stat().st_size,'sha256':sha(p),'source_path':str(p)})
 for r in checks:mrows.append({'artifact':r['artifact'],'role':'VERIFIED_PARENT_EVIDENCE','size_bytes':r['observed_size_bytes'],'sha256':r['observed_sha256'],'source_path':r['path']})
 writec(paths['manifest'],mrows,['artifact','role','size_bytes','sha256','source_path'])
 ex={'version':VERSION,'created_at_utc':now,'manifest_filename':paths['manifest'].name,'manifest_size_bytes':paths['manifest'].stat().st_size,'manifest_sha256':sha(paths['manifest']),'status':result['status'],'classification':result['classification'],'parent_v7_10A_manifest_sha256':EXPECTED_PARENT_MANIFEST_SHA256,'predicates_sha256':EXPECTED_PREDICATES_SHA256,'runner_sha256':sha(runner),'closure_function_count':len(clos),'contract_question_count':len(question_rows),'future_trace_control_count':len(control_rows)};writej(paths['external'],ex)
 print(json.dumps({'status':result['status'],'verified_parent_artifacts':len(checks),'root_functions':ROOTS,'closure_function_count':len(clos),'module_global_dependencies':sorted(global_names),'event_field_reference_count':len(field_rows),'contract_question_count':len(question_rows),'future_trace_controls':len(control_rows),'runner_sha256':sha(runner),'manifest_sha256':ex['manifest_sha256'],'output_directory':str(out)},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
