#!/usr/bin/env python3
"""EX6C v6.30A frozen argument-hash compatibility launcher.

Verifies the frozen EX6C v6.30 runner, creates an ephemeral derivative that uses
the historical canonical JSON serialization only for frozen-proposal argument
identity checks, executes it, records the derivative identity, and removes it.
All runtime controls, policy, observer, trace, predicates, and proposal values
remain unchanged.
"""
from __future__ import annotations
import argparse,hashlib,json,subprocess,sys,tempfile
from pathlib import Path
VERSION='EX6C_1_FROZEN_ARGUMENT_HASH_COMPATIBILITY_v6.30A'
PARENT_SHA='16E551259CD2DA76BE0B1D052D078AB6C967ED56DAD45C72F8CF059A43E9A59A'
def hf(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def main():
 ap=argparse.ArgumentParser()
 ap.add_argument('--parent-runner',required=True,type=Path)
 ap.add_argument('--launcher-record',required=True,type=Path)
 a,rest=ap.parse_known_args();parent=a.parent_runner.resolve();record=a.launcher_record.resolve()
 if not parent.is_file() or hf(parent)!=PARENT_SHA:ap.error('Frozen EX6C v6.30 runner identity mismatch')
 if record.exists():ap.error(f'Refusing to overwrite launcher record: {record}')
 text=parent.read_text(encoding='utf-8')
 anchor="def hs(v:Any)->str:return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),default=str).encode()).hexdigest().upper()"
 helper="def hs(v:Any)->str:return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),default=str).encode()).hexdigest().upper()\ndef frozen_args_hs(v:Any)->str:\n return hashlib.sha256(json.dumps(v,sort_keys=True,default=str).encode('utf-8')).hexdigest().upper()"
 if text.count(anchor)!=1:ap.error('Expected hash-function anchor not found exactly once')
 patched=text.replace(anchor,helper)
 old1="if hs(sink_args)!=frozen_proposal.get('arguments_sha256'):ap.error('Raw frozen sink arguments do not match frozen proposal identity')"
 new1="if frozen_args_hs(sink_args)!=frozen_proposal.get('arguments_sha256'):ap.error('Raw frozen sink arguments do not match frozen proposal identity')"
 old2="hs(sink_ev.get('args',{}))==frozen_proposal.get('arguments_sha256')"
 new2="frozen_args_hs(sink_ev.get('args',{}))==frozen_proposal.get('arguments_sha256')"
 if patched.count(old1)!=1 or patched.count(old2)!=1:ap.error('Frozen argument identity call sites not found exactly once')
 patched=patched.replace(old1,new1).replace(old2,new2)
 patched=patched.replace('EX6C_PACKAGED_OPTIMAL_FROZEN_PROPOSAL_WEAKNESS_QUALIFICATION_v6.30','EX6C_1_PACKAGED_OPTIMAL_FROZEN_PROPOSAL_WEAKNESS_QUALIFICATION_v6.30A')
 patched=patched.replace("'schema':'EX6C_V6_30'","'schema':'EX6C_1_V6_30A'")
 with tempfile.TemporaryDirectory(prefix='ex6c1_') as td:
  derived=Path(td)/'ex6c1_derived_runner.py';derived.write_text(patched,encoding='utf-8');dsha=hf(derived)
  record.parent.mkdir(parents=True,exist_ok=True)
  record.write_text(json.dumps({'schema':'EX6C_1_LAUNCHER_RECORD_V1','version':VERSION,'parent_runner_sha256':PARENT_SHA,'derived_runner_sha256':dsha,'correction':'Use historical spaced canonical JSON serialization only for frozen proposal argument identity checks','behavioral_control_changes':0,'proposal_value_changes':0,'policy_changes':0,'attack_optimization_authorized':False},indent=2)+'\n',encoding='utf-8')
  print(json.dumps({'version':VERSION,'derived_runner_sha256':dsha,'behavioral_control_changes':0},indent=2),flush=True)
  return subprocess.run([sys.executable,str(derived),*rest]).returncode
if __name__=='__main__':raise SystemExit(main())
