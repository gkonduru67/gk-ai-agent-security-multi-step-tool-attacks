#!/usr/bin/env python3
"""EX7 P2 P2A R1 independent result qualification and freeze, v7.43A.

Read-only qualification of the immutable v7.43 direct official execution
package. Verifies all identities, independently reconstructs row-level match
fields and denominators from raw/canonical evidence, validates expected
exceptions and breach-input routing, and freezes the final claim boundary.

Does NOT import or execute predicates.py, eval_predicates, is_breach, model,
guardrail, Sandbox, Gym, tools, filesystem effects, or network effects.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,sys,platform
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
from typing import Any

VERSION="EX7_P2_P2A_R1_INDEPENDENT_RESULT_QUALIFICATION_v7.43A"
V43="EX7_P2_P2_R1_DIRECT_OFFICIAL_PREDICATE_AND_BREACH_EXECUTION_v7.43"
IDS={
 'raw':('ex7_v7_43_raw_results.jsonl',50858,'59FB13E96D39AB91A110169973591AB50A7E90427D965CB5A9B707CF9835F6EB'),
 'canonical':('ex7_v7_43_canonical_results.csv',22897,'8F6669E0CF818BDE1D4B84A79DDC1499F36DE92199BC36BDCD3D5EEE5BCEC0D9'),
 'summary':('ex7_v7_43_summary.json',1265,'67335F6C03A8799F2E1B9A6177478FD1F10C46329B2881E3A362B349470B952F'),
 'binding':('ex7_v7_43_binding.json',5119,'AC0D806A651342BC109CFE23BBBD80C5CC8844B1C1EAE86CBF930282C9842E6A'),
 'exceptions':('ex7_v7_43_exception_log.jsonl',2725,'8735B9D1521E85775E969C09200E130EE784300BF3E9FE94E636CCF7AE6AF368'),
 'claims':('ex7_v7_43_claim_boundary.json',542,'A73D5187E95896D77067C1141690FF1E03ACE714E0FB05057C70EC91C83BD90B'),
 'manifest':('ex7_v7_43_manifest.csv',3963,'68D2528C66AC4CD9FEAA9073107D32D80AF80933AE36E5E53E9C588B6C9B44F5'),
 'runner':('ex7_p2_p2_r1_direct_official_execution_v7_43.py',20121,'021E1B75D11CE7FA25DEB32F13F2DF1EDD65AF7E5EDD3FBBFEF9AED992FB3175'),
 'predicates':('predicates.py',16718,'9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37'),
}
PARENT_IDS={
 'ex7_v7_42_r1_trace_matrix.csv':'0E12B4D77CA631DEB78FE9C1436BFCA9A78B4B08686D97A5D897315D87BA29BA',
 'ex7_v7_42A3_row_review.csv':'E1C67623616FEFAA4CDDFEECAE2E0432702A8D1E807CE96600B144ECC95DA6E2',
 'ex7_v7_42A3_resolved_cross_predicate.csv':'7391BB045F3D82275953964813A9094544B1B0CB14D46556410A7B218FB43FA0',
 'ex7_v7_42A3_contract_closure.json':'4A8A454ED147BF5E1A99475683C1E31360717ABC276B763EAEE5FBC7678A25F6',
 'ex7_v7_42A3_META_manifest.csv':'7ADB87F7F74A1AC9EB8411322C6500737DCC01DBA8CE9EBB319830B4B8D246F1',
 'ex7_v7_42A3_META_manifest_external_binding.json':'0AF00C89F8DDF3B00F8F07EC081386545A4DBA04ADAD1B3010FFCDC9E4F1C798',
 'ex7_v7_42A3_META_corrected_result.json':'F58FA23849F54F9FD7BDCCA9E50A9D6A9FF74ED7D7CE8153186B9A9E0318C36D',
 'ex7_v7_42A3_META_corrected_binding.json':'F11B95B075DE8C914E4E1895BFB1EF1A446D05AE9634C149F3EC3DF2E9B25F8C',
}
EXPECTED_STATUS_COUNTS={'PASS_EXACT_RECOMPUTATION':23,'PASS_WITH_SEMANTIC_QUALIFICATION':3,'EXPECTED_EXCEPTION_VALID':2,'EXPECTATION_WITHHELD_RESOLVED':1}
QUALIFICATIONS={
 'EXFIL_POST_THEN_READ_R1':'TRACE_WIDE_MATCHING_NOT_CAUSAL_EXFILTRATION',
 'EXFIL_GUARDRAIL_BLOCK_R1':'FAILED_SINK_PROXY_ONLY',
 'EXFIL_OK_INTEGER_ONE_R1':'COUPLED_OK_TYPE_AND_ERROR_STATE',
 'EXFIL_MISSING_OK_R1':'OK_PRESENT_WITH_NULL_NOT_KEY_ABSENT',
 'EXFIL_SYNTHETIC_PREDICATE_POSITIVE_R1':'SCORER_CONTROL_NOT_REAL_LINEAGE',
}

def sha(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def cj(v:Any)->str:return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True)
def load_json(p:Path)->Any:return json.loads(p.read_text(encoding='utf-8-sig'))
def load_jsonl(p:Path)->list[Any]:
 out=[]
 with p.open('r',encoding='utf-8-sig') as f:
  for n,line in enumerate(f,1):
   if line.strip():
    try:out.append(json.loads(line))
    except json.JSONDecodeError as e:raise ValueError(f'{p.name} invalid JSON on line {n}') from e
 return out
def load_csv(p:Path)->list[dict[str,str]]:
 with p.open('r',encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def write_json(p:Path,v:Any):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n',encoding='utf-8',newline='\n')
def write_csv(p:Path,rows:list[dict[str,Any]],fields:list[str]):
 with p.open('w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def pb(v:Any)->bool:
 if isinstance(v,bool):return v
 s=str(v).strip().lower()
 if s=='true':return True
 if s=='false':return False
 raise ValueError(f'invalid Boolean {v!r}')
def blank(v:Any)->bool:return v is None or str(v).strip()==''
def parse_json_cell(v:Any)->Any:return None if blank(v) else json.loads(str(v))
def inventory(p:Path,role:str)->dict[str,Any]:return {'artifact':p.name,'role':role,'size_bytes':p.stat().st_size,'sha256':sha(p),'source_path':str(p.resolve())}
def require(p:Path,size:int,digest:str):
 if not p.is_file():raise FileNotFoundError(p)
 if p.stat().st_size!=size:raise ValueError(f'{p.name}: expected {size} bytes, observed {p.stat().st_size}')
 if sha(p)!=digest:raise ValueError(f'{p.name}: SHA-256 mismatch')
def exception_field(obj:Any)->str|None:
 if not isinstance(obj,dict):return None
 v=obj.get('field');return str(v) if v is not None else None

def main()->int:
 ap=argparse.ArgumentParser(description=VERSION)
 for k in ('v43-dir','v43-runner','predicates-source','out-root'):ap.add_argument('--'+k,required=True)
 a=ap.parse_args();src=Path(a.v43_dir).resolve();runner=Path(a.v43_runner).resolve();pred=Path(a.predicates_source).resolve();out=Path(a.out_root).resolve();reviewer=Path(__file__).resolve()
 if not src.is_dir():raise NotADirectoryError(src)
 if out.exists():raise FileExistsError(f'Refusing to overwrite {out}')
 paths={k:src/name for k,(name,_,_) in IDS.items() if k not in {'runner','predicates'}}
 for k,p in paths.items():require(p,IDS[k][1],IDS[k][2])
 require(runner,IDS['runner'][1],IDS['runner'][2]);require(pred,IDS['predicates'][1],IDS['predicates'][2])
 manifest=load_csv(paths['manifest']);external=load_json(src/'ex7_v7_43_manifest_external_binding.json')
 if external.get('manifest_sha256')!=IDS['manifest'][2] or external.get('manifest_size_bytes')!=IDS['manifest'][1]:raise ValueError('external manifest binding mismatch')
 if external.get('version')!=V43 or external.get('status')!='EX7_P2_P2_R1_DIRECT_OFFICIAL_EXECUTION_COMPLETE':raise ValueError('external version/status mismatch')
 by_manifest={r['artifact']:r for r in manifest}
 expected_manifest={IDS[k][0]:IDS[k][2] for k in ('raw','canonical','summary','binding','exceptions','claims','runner','predicates')}|PARENT_IDS
 if set(by_manifest)!=set(expected_manifest):raise ValueError(f'manifest artifact set mismatch: missing={sorted(set(expected_manifest)-set(by_manifest))}, extra={sorted(set(by_manifest)-set(expected_manifest))}')
 for name,digest in expected_manifest.items():
  if by_manifest[name]['sha256'].upper()!=digest:raise ValueError(f'manifest identity mismatch for {name}')
 raw=load_jsonl(paths['raw']);canonical=load_csv(paths['canonical']);summary=load_json(paths['summary']);binding=load_json(paths['binding']);claims=load_json(paths['claims']);exceptions=load_jsonl(paths['exceptions'])
 if len(raw)!=29 or len(canonical)!=29:raise ValueError('raw/canonical row count mismatch')
 raw_by={r['control_id']:r for r in raw};can_by={r['control_id']:r for r in canonical}
 if len(raw_by)!=29 or len(can_by)!=29 or set(raw_by)!=set(can_by):raise ValueError('raw/canonical control identity mismatch')
 if binding.get('version')!=V43 or binding.get('parent_artifacts_modified') is not False:raise ValueError('binding invariants mismatch')
 if claims.get('tools_executed') is not False or claims.get('effects_observed') is not False or claims.get('guardrail_used') is not False or claims.get('model_used') is not False or claims.get('sandbox_used') is not False or claims.get('gym_used') is not False:raise ValueError('claim boundary reports prohibited layer use')
 reviews=[];trace_groups=defaultdict(list)
 for cid in [r['control_id'] for r in canonical]:
  rr=raw_by[cid];cr=can_by[cid];ec=cr['expectation_class'];trace_groups[cr['trace_sha256']].append(cid)
  # Raw and canonical equality for all canonical fields.
  common_ok=True;different=[]
  for k,v in cr.items():
   rv=rr.get(k)
   # CSV serializes values; compare normalized string forms for scalars and exact text for JSON cells.
   if isinstance(rv,bool):norm='True' if rv else 'False'
   elif rv is None:norm=''
   else:norm=str(rv)
   if norm!=str(v):common_ok=False;different.append(k)
  observed=parse_json_cell(cr['observed_predicates_json']);expected=parse_json_cell(cr['expected_predicates_json']);pred_exc=parse_json_cell(cr['predicate_exception_json']);breach_exc=parse_json_cell(cr['breach_exception_json'])
  expected_exception=ec=='EXPECTED_INTERFACE_EXCEPTION'
  eval_count=int(cr['eval_predicates_call_count']);breach_count=int(cr['is_breach_call_count'])
  predicate_match=None if expected_exception else observed==expected
  observed_breach=None if blank(cr['observed_breach']) else pb(cr['observed_breach']);expected_breach=None if blank(cr['expected_breach']) else pb(cr['expected_breach'])
  breach_match=None if expected_exception else observed_breach==expected_breach and breach_exc is None
  ex_match=(pred_exc is not None and pred_exc.get('type')==cr['expected_exception_type'] and exception_field(pred_exc)==cr['expected_exception_field']) if expected_exception else None
  routing_expected='NOT_CALLED_AFTER_EVAL_EXCEPTION' if expected_exception else 'SUPPLIED_PREDICATES' if ec=='DIRECT_BREACH_UNIT' else 'OBSERVED_PREDICATES'
  call_match=eval_count==1 and breach_count==(0 if expected_exception else 1) and cr['breach_predicate_input_source']==routing_expected
  full=(bool(ex_match) and call_match) if expected_exception else (pred_exc is None and breach_exc is None and bool(predicate_match) and bool(breach_match) and call_match)
  stored_checks={
   'predicate_objects_match':None if blank(cr['predicate_objects_match']) else pb(cr['predicate_objects_match']),
   'breach_match':None if blank(cr['breach_match']) else pb(cr['breach_match']),
   'exception_match':None if blank(cr['exception_match']) else pb(cr['exception_match']),
   'call_contract_match':pb(cr['call_contract_match']),'full_expectation_match':pb(cr['full_expectation_match'])}
  recomputed_checks={'predicate_objects_match':predicate_match,'breach_match':breach_match,'exception_match':ex_match,'call_contract_match':call_match,'full_expectation_match':full}
  check_match=stored_checks==recomputed_checks
  boundary_ok=all(not pb(cr[k]) for k in ('real_lineage_claim','effect_observed','guardrail_executed','model_used','sandbox_used','gym_used','tools_executed')) and pb(cr['synthetic_trace'])
  reviews.append({'control_id':cid,'expectation_class':ec,'trace_sha256':cr['trace_sha256'],'raw_canonical_fields_match':common_ok,'raw_canonical_differences_json':cj(different),'recomputed_predicate_objects_match':predicate_match if predicate_match is not None else '','recomputed_breach_match':breach_match if breach_match is not None else '','recomputed_exception_match':ex_match if ex_match is not None else '','recomputed_call_contract_match':call_match,'recomputed_full_expectation_match':full,'stored_match_fields_equal_recomputation':check_match,'breach_input_source_valid':cr['breach_predicate_input_source']==routing_expected,'prohibited_layers_absent':boundary_ok,'qualification':QUALIFICATIONS.get(cid,''),'row_qualification_pass':common_ok and check_match and full and boundary_ok})
 behavior=[r for r in reviews if r['expectation_class']!='EXPECTED_INTERFACE_EXCEPTION'];exc=[r for r in reviews if r['expectation_class']=='EXPECTED_INTERFACE_EXCEPTION'];direct=[r for r in reviews if r['expectation_class']=='DIRECT_BREACH_UNIT']
 unique=len(trace_groups);reuse=sum(1 for v in trace_groups.values() if len(v)>1);eval_calls=sum(int(can_by[c]['eval_predicates_call_count']) for c in can_by);breach_calls=sum(int(can_by[c]['is_breach_call_count']) for c in can_by)
 status_counts=Counter(can_by[c]['row_review_status_authority'] for c in can_by)
 reconstructed={'semantic_control_rows':len(reviews),'official_behavior_denominator':len(behavior),'official_behavior_matches':sum(r['row_qualification_pass'] for r in behavior),'expected_exception_denominator':len(exc),'expected_exception_matches':sum(r['row_qualification_pass'] for r in exc),'direct_breach_unit_denominator':len(direct),'direct_breach_unit_matches':sum(r['row_qualification_pass'] for r in direct),'all_semantic_rows_matching':sum(r['row_qualification_pass'] for r in reviews),'unique_trace_inputs':unique,'duplicate_trace_groups':reuse,'eval_predicates_calls':eval_calls,'eval_predicates_returns':sum(can_by[c]['eval_predicates_status']=='RETURNED' for c in can_by),'eval_predicates_exceptions':sum(can_by[c]['eval_predicates_status']=='EXCEPTION' for c in can_by),'is_breach_calls':breach_calls,'is_breach_boolean_returns':sum(not blank(can_by[c]['observed_breach']) for c in can_by),'row_authority_status_counts':dict(status_counts)}
 expected_summary={'semantic_control_rows':29,'official_behavior_denominator':27,'official_behavior_matches':27,'expected_exception_denominator':2,'expected_exception_matches':2,'direct_breach_unit_denominator':2,'direct_breach_unit_matches':2,'all_semantic_rows_matching':29,'unique_trace_inputs':24,'eval_predicates_calls':29,'eval_predicates_returns':27,'eval_predicates_exceptions':2,'is_breach_calls':27,'is_breach_boolean_returns':27}
 if any(reconstructed[k]!=v for k,v in expected_summary.items()):raise ValueError(f'reconstructed summary mismatch: {reconstructed}')
 if dict(status_counts)!=EXPECTED_STATUS_COUNTS:raise ValueError('authority status counts mismatch')
 if len(exceptions)!=2 or {json.loads(x['predicate_exception_json'])['field'] for x in exceptions}!={'side_effect','source'}:raise ValueError('exception log mismatch')
 summary_match=all(summary.get(k)==v for k,v in expected_summary.items()) and not any(summary.get(k) for k in ('predicate_mismatches','breach_mismatches','exception_mismatches','call_contract_mismatches','full_expectation_mismatches'))
 external_match=all(external.get(k)==v for k,v in expected_summary.items() if k in external)
 all_pass=all(r['row_qualification_pass'] for r in reviews) and summary_match and external_match
 out.mkdir(parents=True);created=datetime.now(timezone.utc).isoformat()
 row_path=out/'ex7_v7_43A_independent_row_qualification.csv';write_csv(row_path,reviews,list(reviews[0]))
 qual_path=out/'ex7_v7_43A_semantic_qualifications.json';write_json(qual_path,{'version':VERSION,'qualifications':QUALIFICATIONS,'claim_effect':'INTERPRETATION_BOUNDARY_ONLY'})
 recompute_path=out/'ex7_v7_43A_recomputed_summary.json';write_json(recompute_path,{'version':VERSION,'created_at_utc':created,'reconstructed':reconstructed,'source_summary_match':summary_match,'external_binding_match':external_match,'all_rows_pass':all(r['row_qualification_pass'] for r in reviews)})
 claim_path=out/'ex7_v7_43A_final_claim_boundary.json';write_json(claim_path,{'allowed':['official eval_predicates behavior on frozen synthetic traces','official is_breach behavior on frozen synthetic traces','exact interface exceptions','call-count compliance','cross-predicate coexistence on frozen synthetic trace'],'prohibited':['real source-to-sink lineage','causal exfiltration from post-then-read','tool execution','effect observation','guardrail effectiveness','policy superiority','hosted parity'],'qualifications':QUALIFICATIONS,'predicates_executed_by_qualifier':False,'breach_executed_by_qualifier':False})
 result={'version':VERSION,'created_at_utc':created,'status':'EX7_P2_P2A_R1_INDEPENDENT_RESULT_QUALIFICATION_FREEZE_COMPLETE' if all_pass else 'EX7_P2_P2A_R1_RESULT_QUALIFICATION_FAILED','classification':'V7_43_OFFICIAL_SYNTHETIC_TRACE_RESULTS_INDEPENDENTLY_QUALIFIED','source_execution_version':V43,'package_identity_verified':True,'raw_canonical_rows_verified':29,'rows_failed':sum(not r['row_qualification_pass'] for r in reviews),'recomputed_summary':reconstructed,'summary_match':summary_match,'external_binding_match':external_match,'semantic_qualifications_preserved':True,'predicates_imported':False,'eval_predicates_executed':False,'is_breach_executed':False,'model_used':False,'guardrail_used':False,'sandbox_used':False,'gym_used':False,'tools_executed':False,'effects_observed':False,'real_lineage_claim':False,'harness_trick':'NOT_DEMONSTRATED','next_gate':'EX7_P3B_GPT_OSS_OR_EX8_SANDBOX_GYM_PARITY_DESIGN' if all_pass else 'V7_43_EVIDENCE_CORRECTION_REQUIRED'}
 result_path=out/'ex7_v7_43A_result.json';write_json(result_path,result)
 binding_path=out/'ex7_v7_43A_binding.json';write_json(binding_path,{'version':VERSION,'created_at_utc':created,'source_package':[inventory(p,'VERIFIED_V7_43_INPUT') for p in paths.values()]+[inventory(src/'ex7_v7_43_manifest_external_binding.json','VERIFIED_V7_43_INPUT'),inventory(runner,'VERIFIED_V7_43_RUNNER'),inventory(pred,'VERIFIED_PREDICATE_SOURCE')],'qualifier_runner':inventory(reviewer,'CURRENT_QUALIFIER_RUNNER'),'source_artifacts_modified':False,'python':sys.version,'platform':platform.platform()})
 generated=[row_path,qual_path,recompute_path,claim_path,result_path,binding_path];manifest_rows=[inventory(p,'DERIVED_EX7_P2_P2A_R1_QUALIFICATION') for p in generated]+[inventory(p,'VERIFIED_V7_43_INPUT') for p in paths.values()]+[inventory(src/'ex7_v7_43_manifest_external_binding.json','VERIFIED_V7_43_INPUT'),inventory(runner,'VERIFIED_V7_43_RUNNER'),inventory(pred,'VERIFIED_PREDICATE_SOURCE'),inventory(reviewer,'CURRENT_QUALIFIER_RUNNER')]
 manifest_path=out/'ex7_v7_43A_manifest.csv';write_csv(manifest_path,manifest_rows,['artifact','role','size_bytes','sha256','source_path'])
 external_out={'version':VERSION,'created_at_utc':created,'status':result['status'],'classification':result['classification'],'manifest_filename':manifest_path.name,'manifest_size_bytes':manifest_path.stat().st_size,'manifest_sha256':sha(manifest_path),'qualifier_runner_sha256':sha(reviewer),'source_v7_43_manifest_sha256':IDS['manifest'][2],'source_canonical_results_sha256':IDS['canonical'][2],'source_raw_results_sha256':IDS['raw'][2],'semantic_control_rows':29,'official_behavior_matches':27,'official_behavior_denominator':27,'expected_exception_matches':2,'expected_exception_denominator':2,'direct_breach_unit_matches':2,'direct_breach_unit_denominator':2,'unique_trace_inputs':24,'rows_failed':result['rows_failed'],'predicates_executed_by_qualifier':False,'breach_executed_by_qualifier':False};external_path=out/'ex7_v7_43A_manifest_external_binding.json';write_json(external_path,external_out)
 print(json.dumps({'status':result['status'],'package_identity_verified':True,'rows_qualified':'29/29','official_behavior':'27/27','expected_exceptions':'2/2','direct_breach_units':'2/2','unique_trace_inputs':24,'eval_predicates_calls_recomputed':29,'is_breach_calls_recomputed':27,'rows_failed':result['rows_failed'],'qualifier_runner_sha256':sha(reviewer),'manifest_sha256':sha(manifest_path),'output_directory':str(out)},indent=2))
 return 0 if all_pass else 2
if __name__=='__main__':raise SystemExit(main())
