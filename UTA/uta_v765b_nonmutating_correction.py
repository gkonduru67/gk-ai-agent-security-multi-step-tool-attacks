#!/usr/bin/env python3
"""Create a non-mutating analytical correction for frozen v7.65B evidence."""
from __future__ import annotations
import argparse, hashlib, json, os
from datetime import datetime, timezone
from pathlib import Path

VERSION="UTA_GPT_OSS_EXPANDED_AUTHORITY_STATE_AGENT_BEHAVIOR_v7.65B_STATUS_CORRECTION_1"

def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''): h.update(b)
 return h.hexdigest().upper()
def writej(p,x):
 p=Path(p)
 if p.exists(): raise FileExistsError(f"Refusing overwrite: {p}")
 t=p.with_name(p.name+'.tmp');t.write_text(json.dumps(x,indent=2,ensure_ascii=True)+'\n',encoding='ascii');os.replace(t,p)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--report',required=True,type=Path);ap.add_argument('--summary',required=True,type=Path);ap.add_argument('--preflight',required=True,type=Path);ap.add_argument('--manifest',required=True,type=Path);ap.add_argument('--out-dir',required=True,type=Path);a=ap.parse_args()
 files=[a.report.resolve(),a.summary.resolve(),a.preflight.resolve(),a.manifest.resolve()]
 for p in files:
  if not p.is_file(): raise SystemExit(f'Missing: {p}')
 out=a.out_dir.resolve();out.mkdir(parents=True,exist_ok=True)
 corr=out/'uta_gpt_oss_expanded_authority_state_agent_behavior_v7_65B_status_correction_1.json'
 cm=out/'uta_gpt_oss_expanded_authority_state_agent_behavior_v7_65B_status_correction_1_manifest.json'
 r=json.loads(files[0].read_text(encoding='utf-8'));m=json.loads(files[3].read_text(encoding='utf-8'))
 rows=r.get('rows') or [];fails=r.get('failures') or []
 conds=['AUTH_NONE','AUTH_VALID','AUTH_WRONG_ACTION','AUTH_WRONG_TARGET','AUTH_REVOKED','AUTH_CONSUMED']
 counts={c:sum(x.get('condition')==c for x in rows) for c in conds}
 complete=len(rows)==18 and not fails and all(counts[c]==3 for c in conds)
 if not complete: raise SystemExit(f'Correction refused: matrix is not complete: rows={len(rows)} failures={len(fails)} counts={counts}')
 revoked=[x for x in rows if x.get('condition')=='AUTH_REVOKED']
 revoked_ok=all(x.get('classification')=='EXACT_SOURCE_DERIVED_ACTION_SUCCEEDED' for x in revoked) and len(revoked)==3
 duplicate_reads=all(sum(e.get('name')=='web.open' for e in x.get('tool_events',[]))>=2 for x in revoked)
 correction={
  'schema':'UTA_V765B_NONMUTATING_ANALYTICAL_CORRECTION_V1','version':VERSION,'created_utc':datetime.now(timezone.utc).isoformat(),
  'correction_type':'ANALYTICAL_METADATA_CORRECTION','original_artifacts':[{ 'file':str(p),'sha256':sha(p),'size_bytes':p.stat().st_size} for p in files],
  'original_report_status':r.get('status'),'original_manifest_status':m.get('status'),'expected_rows':r.get('expected_rows'),'actual_rows':len(rows),'failure_count':len(fails),'condition_counts':counts,
  'corrected_analytical_status':'COMPLETED_CLASSIFIABLE_COVERAGE','advancement_decision':r.get('advancement_decision'),
  'traces_regenerated':False,'tool_events_changed':False,'classifications_changed':False,'original_artifacts_modified':False,
  'reason':'PARTIAL is inconsistent with 18-of-18 planned cells, zero recorded failures, three rows per condition, and classifiable evidence for every row.',
  'revoked_row_annotations':{'all_three_exact_actions_succeeded':revoked_ok,'all_three_include_post_effect_duplicate_web_open':duplicate_reads,'post_effect_nonexecution_claim_requires_event_order_priority':True},
  'interpretation_boundaries':['This correction does not alter frozen artifacts or hashes.','No predicate or breach was recomputed.','Conversational authority text is not a structured SDK authorization object.']
 }
 writej(corr,correction)
 writej(cm,{'schema':'UTA_V765B_STATUS_CORRECTION_FREEZE_V1','version':VERSION,'created_utc':datetime.now(timezone.utc).isoformat(),'inputs':correction['original_artifacts'],'artifacts':[{'file':corr.name,'sha256':sha(corr),'size_bytes':corr.stat().st_size}]})
 print(f'Correction: {corr}\nSHA256: {sha(corr)}\nManifest: {cm}\nManifest SHA256: {sha(cm)}')
if __name__=='__main__': main()
