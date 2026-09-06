#!/usr/bin/env python3
"""EX6_P2B_P2G_CONTROLLED_CONSTRUCTOR_AND_STATE_INTERFACE_PREFLIGHT.
Purpose: controlled constructor/state-interface preflight only.
Allows import and single constructor instantiation with deterministic stubs.
Prohibits decide(), before_decide(), after_tool(), tools, predicates, Sandbox, Gym.
"""
import argparse, json, hashlib, importlib, sys
from pathlib import Path
from datetime import datetime, timezone

EXPECTED_STATUS='P2F_R1_PACKAGE_DISCOVERY_AND_IMPORT_INTERFACE_PREFLIGHT_COMPLETE_PASS'
EXPECTED_CLASS='TrustedGuardrailContextAdapterV1_1'
MODULE='aicomp_sdk.guardrails.trusted_context_adapter_v1_1'

def sha(p):
 h=hashlib.sha256(); h.update(Path(p).read_bytes()); return h.hexdigest().upper()

class StubGuardrail:
 def decide(self,*a,**k):
  raise RuntimeError('DECIDE_PROHIBITED_IN_P2G')

class ConstructorOnlyCapability(dict):
 pass

p=argparse.ArgumentParser()
p.add_argument('--p2f-r1-result',required=True)
p.add_argument('--project-root',required=True)
p.add_argument('--output-dir',required=True)
a=p.parse_args()

out=Path(a.output_dir)
if out.exists(): raise SystemExit('Refusing overwrite')
out.mkdir(parents=True)

r=json.loads(Path(a.p2f_r1_result).read_text())
assert r['status']==EXPECTED_STATUS
sys.path.insert(0,a.project_root)
mod=importlib.import_module(MODULE)
cls=getattr(mod,EXPECTED_CLASS)

ctor_ok=False
snapshot_ok=False
reset_ok=False
err=None
try:
 inst=cls(StubGuardrail(), {('issuer','domain'): b'cap'})
 ctor_ok=True
 if hasattr(inst,'snapshot_state'):
  snap=inst.snapshot_state()
  snapshot_ok=True
 if hasattr(inst,'reset_state'):
  inst.reset_state()
  reset_ok=True
except Exception as e:
 err=str(e)

result={
 'version':'EX6_P2B_P2G_CONTROLLED_CONSTRUCTOR_AND_STATE_INTERFACE_PREFLIGHT_v1.0',
 'created_at_utc':datetime.now(timezone.utc).isoformat(),
 'constructor_success':ctor_ok,
 'snapshot_state_callable':snapshot_ok,
 'reset_state_callable':reset_ok,
 'error':err,
 'execution_boundaries':{
   'adapter_instantiated':ctor_ok,
   'decide_executed':False,
   'before_decide_executed':False,
   'after_tool_executed':False,
   'tools_executed':False,
   'sandbox_executed':False,
   'gym_executed':False,
   'predicates_executed':False},
 'scientific_verdict':{
   'constructor_compatibility':'ESTABLISHED' if ctor_ok else 'NOT_ESTABLISHED',
   'state_interface_visibility':'ESTABLISHED' if snapshot_ok and reset_ok else 'NOT_ESTABLISHED',
   'runtime_compatibility':'NOT_ESTABLISHED',
   'authorization_transport_correctness':'NOT_ESTABLISHED'}
}
fp=out/'ex6_p2b_p2g_result.json'
fp.write_text(json.dumps(result,indent=2))
print(json.dumps(result,indent=2))
