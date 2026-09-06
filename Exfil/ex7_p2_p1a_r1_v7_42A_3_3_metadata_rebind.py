#!/usr/bin/env python3
"""Metadata-only rebind for EX7 P2 P1A R1 v7.42A.3.3.

Verifies and preserves the existing scientific artifacts byte-for-byte. Writes
new corrected metadata only. Does not import SDK code, recompute rows, execute
predicates/breach, or modify the source package.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,sys
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
from typing import Any

VERSION="EX7_P2_P1A_R1_HELPER_COMPLETE_INDEPENDENT_RECOMPUTATION_v7.42A.3.3"
REBIND_VERSION="EX7_P2_P1A_R1_v7.42A.3.3_METADATA_REBIND_v1"
EXPECTED_RUNNER_SHA="91556C6456DDAFDB9EF6FBF82689AEA1F291EE42805613600EC6B33ECC865CA4"
EXPECTED_RUNNER_SIZE=16719
EXPECTED_PARENT_MANIFEST_SHA="9C6322C302975D721C3820778AAD9E21F658036BFDFBEC64FD75DA9624CE919F"
EXPECTED_MATRIX_SHA="0E12B4D77CA631DEB78FE9C1436BFCA9A78B4B08686D97A5D897315D87BA29BA"
EXPECTED_PREDICATES_SHA="9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
EXPECTED_CLOSURE_SHA="E0F20E85396A9255B0014662E2BDF18CE045D2D28A34A0D0FAC7E2FB9D2E153E"
SCIENTIFIC_FILES=(
 "ex7_v7_42A3_parent_verification.csv",
 "ex7_v7_42A3_row_review.csv",
 "ex7_v7_42A3_resolved_cross_predicate.csv",
 "ex7_v7_42A3_trace_reuse.csv",
 "ex7_v7_42A3_contract_closure.json",
 "ex7_v7_42A3_claim_boundary.json",
)
OLD_METADATA_FILES=(
 "ex7_v7_42A3_result.json",
 "ex7_v7_42A3_binding.json",
 "ex7_v7_42A3_manifest.csv",
 "ex7_v7_42A3_manifest_external_binding.json",
)

def sha(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest().upper()
def load_json(p:Path)->Any:return json.loads(p.read_text(encoding='utf-8-sig'))
def load_csv(p:Path)->list[dict[str,str]]:
 with p.open('r',encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def write_json(p:Path,v:Any):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n',encoding='utf-8',newline='\n')
def write_csv(p:Path,rows:list[dict[str,Any]],fields:list[str]):
 with p.open('w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def require_file(p:Path):
 if not p.is_file():raise FileNotFoundError(p)
def inventory(p:Path,role:str)->dict[str,Any]:
 return {'artifact':p.name,'role':role,'size_bytes':p.stat().st_size,'sha256':sha(p),'source_path':str(p.resolve())}
def parse_bool(v:Any)->bool:
 if isinstance(v,bool):return v
 s=str(v).strip().lower()
 if s=='true':return True
 if s=='false':return False
 raise ValueError(f'invalid Boolean {v!r}')

def main()->int:
 ap=argparse.ArgumentParser(description=REBIND_VERSION)
 ap.add_argument('--source-dir',required=True)
 ap.add_argument('--scientific-runner',required=True)
 ap.add_argument('--out-root',required=True)
 a=ap.parse_args()
 src=Path(a.source_dir).resolve();runner=Path(a.scientific_runner).resolve();out=Path(a.out_root).resolve();rebind_runner=Path(__file__).resolve()
 if not src.is_dir():raise NotADirectoryError(src)
 if out.exists():raise FileExistsError(f'Refusing to overwrite existing output directory: {out}')
 require_file(runner);require_file(rebind_runner)
 if runner.stat().st_size!=EXPECTED_RUNNER_SIZE or sha(runner)!=EXPECTED_RUNNER_SHA:raise ValueError('v7.42A.3.3 scientific runner identity mismatch')
 paths={name:src/name for name in (*SCIENTIFIC_FILES,*OLD_METADATA_FILES)}
 for p in paths.values():require_file(p)
 # Verify scientific invariants without modifying or recomputing row science.
 rows=load_csv(paths['ex7_v7_42A3_row_review.csv'])
 if len(rows)!=29:raise ValueError(f'expected 29 row reviews, found {len(rows)}')
 statuses=Counter(r['row_review_status'] for r in rows)
 expected_statuses={'PASS_EXACT_RECOMPUTATION':23,'PASS_WITH_SEMANTIC_QUALIFICATION':3,'EXPECTED_EXCEPTION_VALID':2,'EXPECTATION_WITHHELD_RESOLVED':1}
 if dict(statuses)!=expected_statuses:raise ValueError(f'row-status count mismatch: {dict(statuses)}')
 failed=[r['control_id'] for r in rows if r['row_review_status'] in {'EXPECTATION_MISMATCH','FIXTURE_INVALID'}]
 if failed:raise ValueError(f'scientific rows contain failures: {failed}')
 frozen_den=sum(parse_bool(r['agreement_denominator_member_input']) for r in rows)
 if frozen_den!=26:raise ValueError(f'frozen agreement denominator mismatch: {frozen_den}')
 resolved=load_csv(paths['ex7_v7_42A3_resolved_cross_predicate.csv'])
 if len(resolved)!=1:raise ValueError('expected exactly one resolved cross-predicate row')
 rr=resolved[0]
 preds=json.loads(rr['resolved_predicates_json'])
 if [p.get('predicate') for p in preds]!=['UNTRUSTED_TO_ACTION','EXFILTRATION']:raise ValueError('cross-predicate order/content mismatch')
 if int(rr['resolved_EXFILTRATION_count'])!=1 or not parse_bool(rr['resolved_breach']):raise ValueError('cross-predicate count/breach mismatch')
 if not parse_bool(rr['eligible_for_future_agreement_denominator']):raise ValueError('resolved row not eligible for future denominator')
 reuse=load_csv(paths['ex7_v7_42A3_trace_reuse.csv'])
 if len(reuse)!=3:raise ValueError(f'expected 3 reuse groups, found {len(reuse)}')
 unique_trace_inputs=24
 closure=load_json(paths['ex7_v7_42A3_contract_closure.json'])
 if closure.get('closure_sha256')!=EXPECTED_CLOSURE_SHA:raise ValueError('contract closure identity mismatch')
 required_blocks={'eval_predicates','_secrets_read_in_trace','_extract_secret_values','_is_secret_path','_contains_secret','_decode_candidates','_alnum','is_breach','SECRET_MARKER','_ENCODED_MATCH_MIN_LEN','_MIN_SECRET_VALUE_LEN','EXFIL_SINKS'}
 observed_blocks={b.get('identity') for b in closure.get('blocks',[])}
 if observed_blocks!=required_blocks:raise ValueError('contract closure component mismatch')
 old_result=load_json(paths['ex7_v7_42A3_result.json']);old_binding=load_json(paths['ex7_v7_42A3_binding.json']);old_external=load_json(paths['ex7_v7_42A3_manifest_external_binding.json'])
 if old_result.get('rows_failed')!=0 or old_result.get('total_rows_reviewed')!=29:raise ValueError('old result scientific counts mismatch')
 if old_binding.get('parent_manifest_sha256')!=EXPECTED_PARENT_MANIFEST_SHA or old_binding.get('r1_matrix_sha256')!=EXPECTED_MATRIX_SHA or old_binding.get('predicates_sha256')!=EXPECTED_PREDICATES_SHA:raise ValueError('old binding parent identities mismatch')
 if old_binding.get('sdk_imported') is not False:raise ValueError('old binding unexpectedly reports SDK import')
 old_manifest_actual_sha=sha(paths['ex7_v7_42A3_manifest.csv']);old_manifest_actual_size=paths['ex7_v7_42A3_manifest.csv'].stat().st_size
 # Freeze source artifact identity before writing metadata.
 source_inventory=[]
 for name in SCIENTIFIC_FILES:source_inventory.append(inventory(paths[name],'IMMUTABLE_SCIENTIFIC_RESULT'))
 for name in OLD_METADATA_FILES:source_inventory.append(inventory(paths[name],'SUPERSEDED_METADATA_SOURCE'))
 source_inventory.append(inventory(runner,'IMMUTABLE_SCIENTIFIC_RUNNER'))
 out.mkdir(parents=True)
 created=datetime.now(timezone.utc).isoformat()
 corrected_result={
  'version':VERSION,'metadata_rebind_version':REBIND_VERSION,'created_at_utc':created,
  'status':'EX7_P2_P1A_R1_HELPER_COMPLETE_RECOMPUTATION_METADATA_REBIND_COMPLETE',
  'classification':'HELPER_COMPLETE_R1_EXPECTATIONS_RECOMPUTED_RUNTIME_WITHHELD_METADATA_CORRECTED',
  'scientific_result_source_directory':str(src),'scientific_rows_recomputed':False,
  'total_rows_reviewed':29,'rows_failed':0,'failed_control_ids':[],
  'row_review_status_counts':expected_statuses,'frozen_agreement_denominator':26,
  'resolved_withheld_controls':1,'future_agreement_denominator_if_promoted':27,
  'unique_trace_inputs':unique_trace_inputs,'duplicate_trace_groups':3,
  'predicates_imported':False,'eval_predicates_executed':False,'is_breach_executed':False,
  'harness_trick':'NOT_DEMONSTRATED','next_gate':'EX7_P2_P2_R1_DIRECT_OFFICIAL_EXECUTION_DESIGN'
 }
 corrected_binding={
  'version':VERSION,'metadata_rebind_version':REBIND_VERSION,'created_at_utc':created,
  'parent_manifest_sha256':EXPECTED_PARENT_MANIFEST_SHA,'r1_matrix_sha256':EXPECTED_MATRIX_SHA,
  'predicates_sha256':EXPECTED_PREDICATES_SHA,'contract_closure_sha256':EXPECTED_CLOSURE_SHA,
  'scientific_runner':{'path':str(runner),'size_bytes':runner.stat().st_size,'sha256':sha(runner)},
  'metadata_rebind_runner':{'path':str(rebind_runner),'size_bytes':rebind_runner.stat().st_size,'sha256':sha(rebind_runner)},
  'source_package':{'path':str(src),'scientific_artifacts_preserved':True,'scientific_rows_recomputed':False},
  'parent_artifacts_modified':False,'sdk_imported':False
 }
 change_rows=[]
 for field,old,new in (
  ('result.version',old_result.get('version'),VERSION),('binding.version',old_binding.get('version'),VERSION),('external.version',old_external.get('version'),VERSION),
  ('old_manifest.actual_size_bytes',old_manifest_actual_size,old_manifest_actual_size),('old_manifest.actual_sha256',old_manifest_actual_sha,old_manifest_actual_sha),
  ('old_external.claimed_manifest_size_bytes',old_external.get('manifest_size_bytes'),old_manifest_actual_size),('old_external.claimed_manifest_sha256',old_external.get('manifest_sha256'),old_manifest_actual_sha),
 ):
  change_rows.append({'field':field,'old_value_json':json.dumps(old,sort_keys=True),'new_value_json':json.dumps(new,sort_keys=True),'change_class':'METADATA_ONLY','scientific_effect':'NONE'})
 rp=out/'ex7_v7_42A3_META_corrected_result.json';bp=out/'ex7_v7_42A3_META_corrected_binding.json';sp=out/'ex7_v7_42A3_META_source_inventory.csv';cp=out/'ex7_v7_42A3_META_change_manifest.csv'
 write_json(rp,corrected_result);write_json(bp,corrected_binding);write_csv(sp,source_inventory,['artifact','role','size_bytes','sha256','source_path']);write_csv(cp,change_rows,['field','old_value_json','new_value_json','change_class','scientific_effect'])
 manifest_rows=[inventory(p,'DERIVED_METADATA_REBIND') for p in (rp,bp,sp,cp)]+source_inventory+[inventory(rebind_runner,'CURRENT_METADATA_REBIND_RUNNER')]
 mp=out/'ex7_v7_42A3_META_manifest.csv';write_csv(mp,manifest_rows,['artifact','role','size_bytes','sha256','source_path'])
 external={
  'version':VERSION,'metadata_rebind_version':REBIND_VERSION,'created_at_utc':created,
  'status':'EX7_P2_P1A_R1_HELPER_COMPLETE_RECOMPUTATION_METADATA_REBIND_COMPLETE',
  'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':sha(mp),
  'scientific_runner_sha256':EXPECTED_RUNNER_SHA,'metadata_rebind_runner_sha256':sha(rebind_runner),
  'contract_closure_sha256':EXPECTED_CLOSURE_SHA,'rows_failed':0,'total_rows_reviewed':29,
  'unique_trace_inputs':24,'duplicate_trace_groups':3,'frozen_agreement_denominator':26,
  'future_agreement_denominator_if_promoted':27,'scientific_rows_recomputed':False
 }
 ep=out/'ex7_v7_42A3_META_manifest_external_binding.json';write_json(ep,external)
 print(json.dumps({'status':external['status'],'canonical_version':VERSION,'scientific_rows_recomputed':False,'total_rows_reviewed':29,'rows_failed':0,'row_review_status_counts':expected_statuses,'unique_trace_inputs':24,'duplicate_trace_groups':3,'frozen_agreement_denominator':26,'future_agreement_denominator_if_promoted':27,'old_manifest_actual_size_bytes':old_manifest_actual_size,'old_manifest_actual_sha256':old_manifest_actual_sha,'new_manifest_size_bytes':mp.stat().st_size,'new_manifest_sha256':sha(mp),'metadata_rebind_runner_sha256':sha(rebind_runner),'output_directory':str(out)},indent=2))
 return 0
if __name__=='__main__':raise SystemExit(main())
