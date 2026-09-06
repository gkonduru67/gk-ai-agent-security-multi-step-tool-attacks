#!/usr/bin/env python3
"""EX7 P2 P2 R1 direct official predicate and breach execution, v7.43.

Consumes the immutable v7.42 R1 matrix plus the independently qualified
v7.42A.3.3 expectation package and metadata rebind. Imports only the frozen
predicates.py, calls eval_predicates exactly once per semantic row, calls
is_breach exactly once for each completed behavior row, and never calls
is_breach after an expected evaluator exception.

No model, guardrail, Sandbox, Gym, tool, filesystem effect, network effect, or
real-lineage execution is performed.
"""
from __future__ import annotations
import argparse,csv,hashlib,importlib.util,json,platform,sys,time,traceback
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
from typing import Any,Callable

VERSION="EX7_P2_P2_R1_DIRECT_OFFICIAL_PREDICATE_AND_BREACH_EXECUTION_v7.43"
R1_MATRIX_SHA="0E12B4D77CA631DEB78FE9C1436BFCA9A78B4B08686D97A5D897315D87BA29BA"
ROW_REVIEW_SHA="E1C67623616FEFAA4CDDFEECAE2E0432702A8D1E807CE96600B144ECC95DA6E2"
RESOLVED_CROSS_SHA="7391BB045F3D82275953964813A9094544B1B0CB14D46556410A7B218FB43FA0"
CONTRACT_FILE_SHA="4A8A454ED147BF5E1A99475683C1E31360717ABC276B763EAEE5FBC7678A25F6"
CONTRACT_CLOSURE_SHA="E0F20E85396A9255B0014662E2BDF18CE045D2D28A34A0D0FAC7E2FB9D2E153E"
META_MANIFEST_SHA="7ADB87F7F74A1AC9EB8411322C6500737DCC01DBA8CE9EBB319830B4B8D246F1"
META_MANIFEST_SIZE=4209
PREDICATES_SHA="9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
CORRECTED_RESULT_SHA="F58FA23849F54F9FD7BDCCA9E50A9D6A9FF74ED7D7CE8153186B9A9E0318C36D"
CORRECTED_BINDING_SHA="F11B95B075DE8C914E4E1895BFB1EF1A446D05AE9634C149F3EC3DF2E9B25F8C"
CANONICAL_META_VERSION="EX7_P2_P1A_R1_HELPER_COMPLETE_INDEPENDENT_RECOMPUTATION_v7.42A.3.3"
EXPECTED_STATUS_COUNTS={"PASS_EXACT_RECOMPUTATION":23,"PASS_WITH_SEMANTIC_QUALIFICATION":3,"EXPECTED_EXCEPTION_VALID":2,"EXPECTATION_WITHHELD_RESOLVED":1}
EXPECTED_TOTAL=29;EXPECTED_BEHAVIOR=27;EXPECTED_EXCEPTIONS=2;EXPECTED_DIRECT=2;EXPECTED_UNIQUE=24

def sha(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest().upper()
def th(s:str)->str:return hashlib.sha256(s.encode('utf-8')).hexdigest().upper()
def cj(v:Any)->str:return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True)
def load_json(p:Path)->Any:return json.loads(p.read_text(encoding='utf-8-sig'))
def load_csv(p:Path)->list[dict[str,str]]:
 with p.open('r',encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def write_json(p:Path,v:Any):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n',encoding='utf-8',newline='\n')
def write_csv(p:Path,rows:list[dict[str,Any]],fields:list[str]):
 with p.open('w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def parse_bool(v:Any)->bool:
 if isinstance(v,bool):return v
 s=str(v).strip().lower()
 if s=='true':return True
 if s=='false':return False
 raise ValueError(f'invalid Boolean {v!r}')
def require_identity(p:Path,expected_sha:str,expected_size:int|None=None):
 if not p.is_file():raise FileNotFoundError(p)
 if expected_size is not None and p.stat().st_size!=expected_size:raise ValueError(f'{p.name}: size mismatch')
 observed=sha(p)
 if observed!=expected_sha:raise ValueError(f'{p.name}: SHA-256 mismatch: {observed}')
def inventory(p:Path,role:str)->dict[str,Any]:return {'artifact':p.name,'role':role,'size_bytes':p.stat().st_size,'sha256':sha(p),'source_path':str(p.resolve())}
def exception_field(exc:BaseException)->str|None:
 if isinstance(exc,KeyError) and exc.args:return str(exc.args[0])
 return None
def import_frozen_predicates(p:Path):
 spec=importlib.util.spec_from_file_location('_ex7_frozen_predicates_v743',p)
 if spec is None or spec.loader is None:raise ImportError('could not create predicates module specification')
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 for name in ('eval_predicates','is_breach'):
  if not callable(getattr(module,name,None)):raise AttributeError(f'frozen predicates source missing callable {name}')
 return module

def main()->int:
 ap=argparse.ArgumentParser(description=VERSION)
 ap.add_argument('--r1-matrix',required=True);ap.add_argument('--row-review',required=True)
 ap.add_argument('--resolved-cross-predicate',required=True);ap.add_argument('--contract-closure',required=True)
 ap.add_argument('--meta-manifest',required=True);ap.add_argument('--meta-external-binding',required=True)
 ap.add_argument('--meta-corrected-result',required=True);ap.add_argument('--meta-corrected-binding',required=True)
 ap.add_argument('--predicates-source',required=True);ap.add_argument('--out-root',required=True)
 a=ap.parse_args();runner=Path(__file__).resolve();out=Path(a.out_root).resolve()
 paths={k:Path(v).resolve() for k,v in {'matrix':a.r1_matrix,'review':a.row_review,'resolved':a.resolved_cross_predicate,'closure':a.contract_closure,'meta_manifest':a.meta_manifest,'meta_external':a.meta_external_binding,'meta_result':a.meta_corrected_result,'meta_binding':a.meta_corrected_binding,'predicates':a.predicates_source}.items()}
 if out.exists():raise FileExistsError(f'Refusing to overwrite existing output directory: {out}')
 require_identity(paths['matrix'],R1_MATRIX_SHA);require_identity(paths['review'],ROW_REVIEW_SHA)
 require_identity(paths['resolved'],RESOLVED_CROSS_SHA);require_identity(paths['closure'],CONTRACT_FILE_SHA)
 require_identity(paths['meta_manifest'],META_MANIFEST_SHA,META_MANIFEST_SIZE)
 require_identity(paths['meta_result'],CORRECTED_RESULT_SHA);require_identity(paths['meta_binding'],CORRECTED_BINDING_SHA)
 require_identity(paths['predicates'],PREDICATES_SHA)
 meta_external=load_json(paths['meta_external'])
 if meta_external.get('manifest_sha256')!=META_MANIFEST_SHA or meta_external.get('manifest_size_bytes')!=META_MANIFEST_SIZE:raise ValueError('metadata external binding does not bind supplied manifest')
 if meta_external.get('version')!=CANONICAL_META_VERSION or meta_external.get('status')!='EX7_P2_P1A_R1_HELPER_COMPLETE_RECOMPUTATION_METADATA_REBIND_COMPLETE':raise ValueError('metadata external binding canonical status/version mismatch')
 meta_result=load_json(paths['meta_result']);meta_binding=load_json(paths['meta_binding']);closure=load_json(paths['closure'])
 if meta_result.get('version')!=CANONICAL_META_VERSION or meta_binding.get('version')!=CANONICAL_META_VERSION:raise ValueError('corrected metadata version mismatch')
 if meta_result.get('rows_failed')!=0 or meta_result.get('total_rows_reviewed')!=EXPECTED_TOTAL or meta_result.get('scientific_rows_recomputed') is not False:raise ValueError('corrected result invariants mismatch')
 if meta_binding.get('predicates_sha256')!=PREDICATES_SHA or meta_binding.get('r1_matrix_sha256')!=R1_MATRIX_SHA or meta_binding.get('contract_closure_sha256')!=CONTRACT_CLOSURE_SHA or meta_binding.get('sdk_imported') is not False:raise ValueError('corrected binding invariants mismatch')
 if closure.get('closure_sha256')!=CONTRACT_CLOSURE_SHA:raise ValueError('contract closure identity mismatch')
 matrix=load_csv(paths['matrix']);review=load_csv(paths['review']);resolved=load_csv(paths['resolved'])
 if len(matrix)!=EXPECTED_TOTAL or len({r['control_id'] for r in matrix})!=EXPECTED_TOTAL:raise ValueError('R1 matrix population mismatch')
 if len(review)!=EXPECTED_TOTAL or len({r['control_id'] for r in review})!=EXPECTED_TOTAL:raise ValueError('row-review population mismatch')
 if Counter(r['row_review_status'] for r in review)!=Counter(EXPECTED_STATUS_COUNTS):raise ValueError('row-review status count mismatch')
 if len(resolved)!=1:raise ValueError('expected exactly one resolved cross-predicate row')
 matrix_by={r['control_id']:r for r in matrix};review_by={r['control_id']:r for r in review}
 if set(matrix_by)!=set(review_by):raise ValueError('matrix/review control identity mismatch')
 resolved_row=resolved[0];resolved_id=resolved_row['control_id']
 if resolved_id not in matrix_by:raise ValueError('resolved control not present in matrix')
 resolved_preds=json.loads(resolved_row['resolved_predicates_json'])
 if [p.get('predicate') for p in resolved_preds]!=['UNTRUSTED_TO_ACTION','EXFILTRATION'] or int(resolved_row['resolved_EXFILTRATION_count'])!=1 or not parse_bool(resolved_row['resolved_breach']):raise ValueError('resolved cross-predicate expectation mismatch')
 # Build immutable expected authority.
 expected={}
 for cid,r in review_by.items():
  status=r['row_review_status'];ec=r['expectation_class']
  expected[cid]={'expectation_class':ec,'row_review_status':status,'predicates':json.loads(r['recomputed_predicates_json']) if r.get('recomputed_predicates_json','').strip() else None,'breach':parse_bool(r['recomputed_breach']) if r.get('recomputed_breach','').strip() else None,'exception_type':r.get('recomputed_exception_type') or None,'exception_field':r.get('recomputed_exception_field') or None}
 expected[resolved_id]['predicates']=resolved_preds;expected[resolved_id]['breach']=parse_bool(resolved_row['resolved_breach'])
 behavior_ids=[cid for cid,e in expected.items() if e['expectation_class']!='EXPECTED_INTERFACE_EXCEPTION']
 exception_ids=[cid for cid,e in expected.items() if e['expectation_class']=='EXPECTED_INTERFACE_EXCEPTION']
 direct_ids=[cid for cid,e in expected.items() if e['expectation_class']=='DIRECT_BREACH_UNIT']
 if (len(behavior_ids),len(exception_ids),len(direct_ids))!=(EXPECTED_BEHAVIOR,EXPECTED_EXCEPTIONS,EXPECTED_DIRECT):raise ValueError('execution subset population mismatch')
 unique_hashes={r['repaired_trace_sha256'] for r in matrix}
 if len(unique_hashes)!=EXPECTED_UNIQUE:raise ValueError('independent trace input count mismatch')
 module=import_frozen_predicates(paths['predicates']);eval_fn:Callable=module.eval_predicates;breach_fn:Callable=module.is_breach
 out.mkdir(parents=True);raw_path=out/'ex7_v7_43_raw_results.jsonl';results=[]
 with raw_path.open('w',encoding='utf-8',newline='\n') as raw:
  for cid in [r['control_id'] for r in matrix]:
   m=matrix_by[cid];e=expected[cid];trace=json.loads(m['repaired_trace_json']);supplied=json.loads(m['supplied_predicates_json']);eval_calls=0;breach_calls=0;observed_preds=None;observed_breach=None;pred_exc=None;breach_exc=None;pred_tb=None;breach_tb=None
   start=time.perf_counter_ns()
   try:
    eval_calls+=1;observed_preds=eval_fn(trace)
   except Exception as exc:
    pred_exc={'type':type(exc).__name__,'message':str(exc),'field':exception_field(exc)};pred_tb=traceback.format_exc()
   if pred_exc is None:
    breach_input=supplied if e['expectation_class']=='DIRECT_BREACH_UNIT' else observed_preds
    try:
     breach_calls+=1;observed_breach=breach_fn(trace,breach_input)
    except Exception as exc:
     breach_exc={'type':type(exc).__name__,'message':str(exc),'field':exception_field(exc)};breach_tb=traceback.format_exc()
   duration=time.perf_counter_ns()-start
   expected_exception=e['expectation_class']=='EXPECTED_INTERFACE_EXCEPTION'
   predicate_match=(observed_preds==e['predicates']) if not expected_exception and pred_exc is None else None
   breach_match=(observed_breach==e['breach']) if not expected_exception and pred_exc is None and breach_exc is None else None
   exception_match=(pred_exc is not None and pred_exc['type']==e['exception_type'] and pred_exc['field']==e['exception_field']) if expected_exception else None
   call_contract_match=eval_calls==1 and ((expected_exception and breach_calls==0) or (not expected_exception and pred_exc is None and breach_calls==1))
   full_match=(exception_match and call_contract_match) if expected_exception else (pred_exc is None and breach_exc is None and predicate_match and breach_match and call_contract_match)
   row={'experiment_version':VERSION,'control_id':cid,'expectation_class':e['expectation_class'],'row_review_status_authority':e['row_review_status'],'trace_sha256':m['repaired_trace_sha256'],'supplied_predicates_sha256':m['supplied_predicates_sha256'],'predicates_source_sha256':PREDICATES_SHA,'meta_manifest_sha256':META_MANIFEST_SHA,'contract_closure_sha256':CONTRACT_CLOSURE_SHA,'eval_predicates_call_count':eval_calls,'eval_predicates_status':'EXCEPTION' if pred_exc else 'RETURNED','observed_predicates_json':cj(observed_preds) if observed_preds is not None else '','observed_predicates_sha256':th(cj(observed_preds)) if observed_preds is not None else '','observed_EXFILTRATION_count':sum(p.get('predicate')=='EXFILTRATION' for p in observed_preds or []) if observed_preds is not None else '','predicate_exception_json':cj(pred_exc) if pred_exc else '','is_breach_call_count':breach_calls,'breach_predicate_input_source':'SUPPLIED_PREDICATES' if e['expectation_class']=='DIRECT_BREACH_UNIT' and pred_exc is None else 'OBSERVED_PREDICATES' if pred_exc is None else 'NOT_CALLED_AFTER_EVAL_EXCEPTION','observed_breach':observed_breach if observed_breach is not None else '','breach_exception_json':cj(breach_exc) if breach_exc else '','expected_predicates_json':cj(e['predicates']) if e['predicates'] is not None else '','expected_breach':e['breach'] if e['breach'] is not None else '','expected_exception_type':e['exception_type'],'expected_exception_field':e['exception_field'],'predicate_objects_match':predicate_match if predicate_match is not None else '','breach_match':breach_match if breach_match is not None else '','exception_match':exception_match if exception_match is not None else '','call_contract_match':call_contract_match,'full_expectation_match':full_match,'execution_duration_ns':duration,'synthetic_trace':True,'real_lineage_claim':False,'effect_observed':False,'guardrail_executed':False,'model_used':False,'sandbox_used':False,'gym_used':False,'tools_executed':False,'predicate_traceback':pred_tb or '','breach_traceback':breach_tb or ''}
   results.append(row);raw.write(cj(row)+'\n');raw.flush()
 behavior=[r for r in results if r['expectation_class']!='EXPECTED_INTERFACE_EXCEPTION'];exceptions=[r for r in results if r['expectation_class']=='EXPECTED_INTERFACE_EXCEPTION'];direct=[r for r in results if r['expectation_class']=='DIRECT_BREACH_UNIT']
 behavior_matches=sum(bool(r['full_expectation_match']) for r in behavior);exception_matches=sum(bool(r['full_expectation_match']) for r in exceptions);direct_matches=sum(bool(r['full_expectation_match']) for r in direct);all_matches=sum(bool(r['full_expectation_match']) for r in results)
 canonical_path=out/'ex7_v7_43_canonical_results.csv';fields=[k for k in results[0] if k not in {'predicate_traceback','breach_traceback'}];write_csv(canonical_path,results,fields)
 exception_log=out/'ex7_v7_43_exception_log.jsonl'
 with exception_log.open('w',encoding='utf-8',newline='\n') as f:
  for r in results:
   if r['predicate_exception_json'] or r['breach_exception_json']:f.write(cj({k:r[k] for k in ('control_id','expectation_class','predicate_exception_json','breach_exception_json','predicate_traceback','breach_traceback','exception_match')})+'\n')
 summary={'version':VERSION,'created_at_utc':datetime.now(timezone.utc).isoformat(),'status':'EX7_P2_P2_R1_DIRECT_OFFICIAL_EXECUTION_COMPLETE','classification':'DIRECT_OFFICIAL_PREDICATE_AND_BREACH_EXECUTION_SYNTHETIC_TRACES_ONLY','semantic_control_rows':EXPECTED_TOTAL,'official_behavior_denominator':EXPECTED_BEHAVIOR,'official_behavior_matches':behavior_matches,'expected_exception_denominator':EXPECTED_EXCEPTIONS,'expected_exception_matches':exception_matches,'direct_breach_unit_denominator':EXPECTED_DIRECT,'direct_breach_unit_matches':direct_matches,'all_semantic_rows_matching':all_matches,'unique_trace_inputs':EXPECTED_UNIQUE,'eval_predicates_calls':sum(r['eval_predicates_call_count'] for r in results),'eval_predicates_returns':sum(r['eval_predicates_status']=='RETURNED' for r in results),'eval_predicates_exceptions':sum(r['eval_predicates_status']=='EXCEPTION' for r in results),'is_breach_calls':sum(r['is_breach_call_count'] for r in results),'is_breach_boolean_returns':sum(isinstance(r['observed_breach'],bool) for r in results),'predicate_mismatches':[r['control_id'] for r in behavior if r['predicate_objects_match'] is not True],'breach_mismatches':[r['control_id'] for r in behavior if r['breach_match'] is not True],'exception_mismatches':[r['control_id'] for r in exceptions if r['exception_match'] is not True],'call_contract_mismatches':[r['control_id'] for r in results if r['call_contract_match'] is not True],'full_expectation_mismatches':[r['control_id'] for r in results if r['full_expectation_match'] is not True],'predicates_imported':True,'model_used':False,'guardrail_used':False,'sandbox_used':False,'gym_used':False,'tools_executed':False,'effects_observed':False,'real_lineage_claim':False,'harness_trick':'NOT_DEMONSTRATED','claim_boundary':'OFFICIAL_FUNCTION_RUNTIME_ON_FROZEN_SYNTHETIC_TRACES_ONLY'}
 summary_path=out/'ex7_v7_43_summary.json';write_json(summary_path,summary)
 binding={'version':VERSION,'created_at_utc':summary['created_at_utc'],'sources':[inventory(p,'VERIFIED_INPUT') for p in paths.values()],'runner':inventory(runner,'CURRENT_RUNNER'),'raw_results':inventory(raw_path,'RAW_EXECUTION_RESULT'),'canonical_results':inventory(canonical_path,'CANONICAL_EXECUTION_RESULT'),'exception_log':inventory(exception_log,'EXECUTION_EXCEPTION_EVIDENCE'),'parent_artifacts_modified':False,'python':sys.version,'platform':platform.platform()};binding_path=out/'ex7_v7_43_binding.json';write_json(binding_path,binding)
 claim={'allowed':['official eval_predicates results on frozen synthetic traces','official is_breach results on frozen synthetic traces','exact expected interface exceptions','call-count compliance'],'prohibited':['real lineage','tool execution','effect observation','guardrail effectiveness','policy superiority','hosted parity'],'model_used':False,'guardrail_used':False,'sandbox_used':False,'gym_used':False,'tools_executed':False,'effects_observed':False};claim_path=out/'ex7_v7_43_claim_boundary.json';write_json(claim_path,claim)
 generated=[raw_path,canonical_path,exception_log,summary_path,binding_path,claim_path];manifest_rows=[inventory(p,'DERIVED_EX7_P2_P2_R1_OFFICIAL_EXECUTION') for p in generated]+[inventory(p,'VERIFIED_INPUT') for p in paths.values()]+[inventory(runner,'CURRENT_RUNNER')]
 manifest_path=out/'ex7_v7_43_manifest.csv';write_csv(manifest_path,manifest_rows,['artifact','role','size_bytes','sha256','source_path'])
 external={'version':VERSION,'created_at_utc':summary['created_at_utc'],'status':summary['status'],'classification':summary['classification'],'manifest_filename':manifest_path.name,'manifest_size_bytes':manifest_path.stat().st_size,'manifest_sha256':sha(manifest_path),'runner_sha256':sha(runner),'raw_results_sha256':sha(raw_path),'canonical_results_sha256':sha(canonical_path),'summary_sha256':sha(summary_path),'semantic_control_rows':EXPECTED_TOTAL,'official_behavior_denominator':EXPECTED_BEHAVIOR,'official_behavior_matches':behavior_matches,'expected_exception_denominator':EXPECTED_EXCEPTIONS,'expected_exception_matches':exception_matches,'direct_breach_unit_denominator':EXPECTED_DIRECT,'direct_breach_unit_matches':direct_matches,'unique_trace_inputs':EXPECTED_UNIQUE,'all_semantic_rows_matching':all_matches};external_path=out/'ex7_v7_43_manifest_external_binding.json';write_json(external_path,external)
 print(json.dumps({'status':summary['status'],'semantic_control_rows':EXPECTED_TOTAL,'official_behavior_matches':f'{behavior_matches}/{EXPECTED_BEHAVIOR}','expected_exception_matches':f'{exception_matches}/{EXPECTED_EXCEPTIONS}','direct_breach_unit_matches':f'{direct_matches}/{EXPECTED_DIRECT}','all_semantic_rows_matching':f'{all_matches}/{EXPECTED_TOTAL}','unique_trace_inputs':EXPECTED_UNIQUE,'eval_predicates_calls':summary['eval_predicates_calls'],'is_breach_calls':summary['is_breach_calls'],'full_expectation_mismatches':summary['full_expectation_mismatches'],'runner_sha256':sha(runner),'manifest_sha256':sha(manifest_path),'output_directory':str(out)},indent=2))
 return 0 if all_matches==EXPECTED_TOTAL else 2
if __name__=='__main__':raise SystemExit(main())
