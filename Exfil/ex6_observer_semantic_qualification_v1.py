#!/usr/bin/env python3
"""Deterministic semantic qualification for ex6_guardrail_observer_v1.py."""
from __future__ import annotations
import argparse,csv,hashlib,importlib.util,json
from pathlib import Path
def hf(p):
 h=hashlib.sha256();h.update(Path(p).read_bytes());return h.hexdigest().upper()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--observer',required=True,type=Path);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();out=a.out_root
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 out.mkdir(parents=True);spec=importlib.util.spec_from_file_location('obs',a.observer);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 class D:
  def __init__(self,k,r):self.decision=k;self.reason=r
 class G:
  def __init__(self,k):self.k=k;self.last=None
  def decide(self,n,args,ctx):
   self.last=D(self.k,'fixed reason');return self.last
 class E:
  def decide(self,n,args,ctx):raise ValueError('fixed')
 rows=[]
 for kind in ('ALLOW','DENY','CONFIRM','SANITIZE'):
  g=G(kind);args={'url':'x','data':'y'};ctx={'recent_sources':['file']};w=m.ObservedGuardrail(g,policy_track='test',guardrail_source_sha256='A'*64,proposal_identity={'proposal_sha256':'B'*64})
  ret=w.decide('http.post',args,ctx);r=w.records[-1];rows.append({'case':kind,'decision_identity_preserved':ret is g.last,'argument_passthrough':r['argument_passthrough'],'context_passthrough':r['context_passthrough'],'observed_decision':r['guardrail_decision'],'exception_captured':False})
 w=m.ObservedGuardrail(E(),policy_track='test',guardrail_source_sha256='A'*64,proposal_identity={})
 try:w.decide('http.post',{},{});capt=False
 except ValueError:capt=w.records[-1]['guardrail_exception']=='ValueError'
 rows.append({'case':'EXCEPTION','decision_identity_preserved':None,'argument_passthrough':None,'context_passthrough':None,'observed_decision':'EXCEPTION','exception_captured':capt})
 passed=all((r['exception_captured'] if r['case']=='EXCEPTION' else r['decision_identity_preserved'] and r['argument_passthrough'] and r['context_passthrough'] and r['observed_decision']==r['case']) for r in rows)
 with (out/'ex6_observer_semantic_matrix.csv').open('w',newline='',encoding='utf-8-sig') as f:w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
 result={'schema':'EX6_OBSERVER_SEMANTIC_QUALIFICATION_V1','observer_sha256':hf(a.observer),'cases':len(rows),'passed':passed,'scope':'DETERMINISTIC_WRAPPER_PASSTHROUGH_ONLY','sandbox_integration_validated':False}
 (out/'ex6_observer_semantic_qualification.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result,indent=2));return 0 if passed else 2
if __name__=='__main__':raise SystemExit(main())
