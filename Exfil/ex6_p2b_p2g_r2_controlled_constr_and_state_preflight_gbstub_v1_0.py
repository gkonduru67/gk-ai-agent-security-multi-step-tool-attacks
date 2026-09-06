#!/usr/bin/env python3
"""EX6_P2B_P2G_R2_CONTROLLED_CONSTRUCTOR_AND_STATE_PREFLIGHT_WITH_GUARDRAILBASE_STUB.
Single adapter construction using a valid GuardrailBase subclass stub.
No decide(), before_decide(), after_tool(), tools, Sandbox, Gym, predicates, or breach execution.
"""
from __future__ import annotations
import argparse,json,hashlib,importlib,sys
from pathlib import Path
from datetime import datetime,timezone

EXPECTED_STATUS='P2G_R1_GUARDRAILBASE_CONTRACT_DISCOVERY_COMPLETE_PASS'
MOD='aicomp_sdk.guardrails.trusted_context_adapter_v1_1'
CLS='TrustedGuardrailContextAdapterV1_1'
BASE='aicomp_sdk.guardrails.base'

def now(): return datetime.now(timezone.utc).isoformat()

def sha(p):
 h=hashlib.sha256(); h.update(Path(p).read_bytes()); return h.hexdigest().upper()

p=argparse.ArgumentParser()
p.add_argument('--p2g-r1-result',required=True)
p.add_argument('--project-root',required=True)
p.add_argument('--output-dir',required=True)
a=p.parse_args()

out=Path(a.output_dir)
if out.exists(): raise SystemExit('Refusing overwrite existing evidence directory')
out.mkdir(parents=True)

parent=json.loads(Path(a.p2g_r1_result).read_text())
if parent['status']!=EXPECTED_STATUS:
 raise SystemExit('Parent gate not PASS')

sys.path.insert(0,a.project_root)
base_mod=importlib.import_module(BASE)
adapter_mod=importlib.import_module(MOD)
GuardrailBase=getattr(base_mod,'GuardrailBase')
Adapter=getattr(adapter_mod,CLS)

class P2GR2GuardrailBaseStub(GuardrailBase):
 def decide(self,*args,**kwargs):
  raise RuntimeError('DECISION_EXECUTION_PROHIBITED_IN_P2G_R2')

result={
 'version':'EX6_P2B_P2G_R2_CONTROLLED_CONSTRUCTOR_AND_STATE_PREFLIGHT_WITH_GUARDRAILBASE_STUB_v1.0',
 'created_at_utc':now(),
 'adapter_instantiated':False,
 'snapshot_state_called':False,
 'restore_state_called':False,
 'reset_state_called':False,
 'error':None,
 'execution_boundaries':{
   'decide_executed':False,'before_decide_executed':False,'after_tool_executed':False,
   'tools_executed':False,'sandbox_executed':False,'gym_executed':False,
   'predicates_executed':False,'breach_executed':False}
}
try:
 stub=P2GR2GuardrailBaseStub()
 adapter=Adapter(stub,{('issuer','domain'):b'cap'})
 result['adapter_instantiated']=True
 if hasattr(adapter,'snapshot_state'):
  snap=adapter.snapshot_state(); result['snapshot_state_called']=True
  if hasattr(adapter,'restore_state'):
   adapter.restore_state(snap); result['restore_state_called']=True
 if hasattr(adapter,'reset_state'):
  adapter.reset_state(); result['reset_state_called']=True
except Exception as e:
 result['error']=str(e)

result['scientific_verdict']={
 'constructor_compatibility':'ESTABLISHED' if result['adapter_instantiated'] else 'NOT_ESTABLISHED',
 'state_interface_compatibility':'ESTABLISHED' if result['snapshot_state_called'] and result['restore_state_called'] else 'NOT_ESTABLISHED',
 'runtime_compatibility':'NOT_ESTABLISHED',
 'authorization_transport_correctness':'NOT_ESTABLISHED',
 'harness_trick':'NOT_DEMONSTRATED',
 'robust_security_findings':'NOT_ESTABLISHED'}

(Path(out/'ex6_p2b_p2g_r2_result.json')).write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result,indent=2))
