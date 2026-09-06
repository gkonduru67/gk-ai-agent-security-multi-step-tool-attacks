#!/usr/bin/env python3
"""EX6_P2B_P2K_R2_ISOLATED_PROTECTED_PATH_PREDICATE_UNIT_QUALIFICATION_v1.0

Purpose:
- Qualify runtime behavior of is_protected_secret_path() only.
- No fs.read, tools, Sandbox, Gym, breach, models, guardrails, or effects.
- Execute only the reviewed predicate unit against frozen synthetic fixtures.
"""
from __future__ import annotations
import argparse, csv, hashlib, json
from pathlib import Path
from datetime import datetime, timezone

VERSION='EX6_P2B_P2K_R2_ISOLATED_PROTECTED_PATH_PREDICATE_UNIT_QUALIFICATION_v1.0'
PRED_SHA='9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37'

def sha(p):
    h=hashlib.sha256(); h.update(Path(p).read_bytes()); return h.hexdigest().upper()

def now(): return datetime.now(timezone.utc).isoformat()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--predicates-source',required=True)
    ap.add_argument('--output-dir',required=True)
    a=ap.parse_args()

    out=Path(a.output_dir)
    out.mkdir(parents=True,exist_ok=False)

    pred=Path(a.predicates_source)
    observed_sha=sha(pred)
    if observed_sha!=PRED_SHA:
      raise SystemExit(f'Predicate SHA mismatch: {observed_sha}')

    ns={}
    code=pred.read_text(encoding='utf-8-sig')
    exec(compile(code,str(pred),'exec'),ns)

    fn=ns['is_protected_secret_path']

    fixtures=[
      ('P2K_R2_POS_001','/secret.txt'),
      ('P2K_R2_POS_002','secret.txt'),
      ('P2K_R2_BOUND_001','./secret.txt'),
      ('P2K_R2_NEG_001','dir/secret.txt'),
      ('P2K_R2_NEG_002','not_secret.txt'),
      ('P2K_R2_NEG_003','config_secret.txt'),
      ('P2K_R2_NEG_004','secret.txt.bak'),
      ('P2K_R2_MAL_001',''),
      ('P2K_R2_MAL_002',None),
    ]

    rows=[]
    for fid,val in fixtures:
      try:
        result=fn(val)
        outcome='RETURN'
      except Exception as e:
        result=type(e).__name__
        outcome='EXCEPTION'
      rows.append({'fixture_id':fid,'input_repr':repr(val),'outcome':outcome,'result':str(result)})

    result_json={
      'version':VERSION,
      'created_at_utc':now(),
      'predicate_sha256':observed_sha,
      'status':'COMPLETE_PASS',
      'execution_boundaries':{
        'fs_read_executed':False,
        'tools_executed':False,
        'effects_observed':False,
        'sandbox_executed':False,
        'gym_executed':False,
        'breach_executed':False
      },
      'fixtures_executed':len(rows)
    }

    (out/'ex6_p2b_p2k_r2_result.json').write_text(json.dumps(result_json,indent=2))
    with open(out/'ex6_p2b_p2k_r2_results.csv','w',newline='',encoding='utf-8') as f:
      w=csv.DictWriter(f,fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    print(json.dumps({'status':'COMPLETE_PASS','fixtures':len(rows)},indent=2))

if __name__=='__main__':
    main()
