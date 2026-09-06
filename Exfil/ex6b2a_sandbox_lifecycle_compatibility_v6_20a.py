#!/usr/bin/env python3
"""EX6B.2A lifecycle compatibility launcher.

Verifies the frozen EX6B.2 v6.20 runner and the lifecycle-compatible observer
v1.1, creates an ephemeral exact-source derivative changing only the observer
SHA-256 gate and version label, executes it, records the derivative identity,
and removes the ephemeral file. No model, policy, proposal, or control changes.
"""
from __future__ import annotations
import argparse,hashlib,json,subprocess,sys,tempfile
from pathlib import Path
VERSION='EX6B_2A_SANDBOX_LIFECYCLE_COMPATIBILITY_v6.20A'
PARENT_SHA='7290E835C14BD25D2D7CDDFE4A6CD6B7E443A132C8388650858B448E1B97C78A'
OLD_OBSERVER_SHA='5D4B84933FFB477774C979CDD9724FA77D0131944801E89C1C3E43391F1BA9D1'
NEW_OBSERVER_SHA='F5ADF6D46504A998036D8AF7F2B8296CC301740D429CE45D9D25724D23E0D14E'
def hf(p:Path)->str:
 h=hashlib.sha256();
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--parent-runner',required=True,type=Path);ap.add_argument('--observer-v1-1',required=True,type=Path);ap.add_argument('--launcher-record',required=True,type=Path);a,rest=ap.parse_known_args();parent=a.parent_runner.resolve();observer=a.observer_v1_1.resolve();record=a.launcher_record.resolve()
 if not parent.is_file() or hf(parent)!=PARENT_SHA:ap.error('Frozen EX6B.2 v6.20 runner identity mismatch')
 if not observer.is_file() or hf(observer)!=NEW_OBSERVER_SHA:ap.error('Observer v1.1 identity mismatch')
 if record.exists():ap.error(f'Refusing to overwrite launcher record: {record}')
 if '--observer' in rest:ap.error('Do not supply --observer; EX6B.2A supplies observer v1.1')
 text=parent.read_text(encoding='utf-8')
 if OLD_OBSERVER_SHA not in text:ap.error('Parent observer identity token not found exactly once')
 if text.count(OLD_OBSERVER_SHA)!=1:ap.error('Parent observer identity token count is not one')
 patched=text.replace(OLD_OBSERVER_SHA,NEW_OBSERVER_SHA).replace('EX6B_2_AGENT_BACKED_HARMLESS_SANDBOX_OBSERVER_INTEGRATION_v6.20','EX6B_2A_AGENT_BACKED_HARMLESS_SANDBOX_OBSERVER_INTEGRATION_v6.20A').replace("'schema':'EX6B_2_V6_20'","'schema':'EX6B_2A_V6_20A'")
 with tempfile.TemporaryDirectory(prefix='ex6b2a_') as td:
  derived=Path(td)/'ex6b2a_derived_runner.py';derived.write_text(patched,encoding='utf-8');derived_sha=hf(derived)
  record.parent.mkdir(parents=True,exist_ok=True)
  record.write_text(json.dumps({'schema':'EX6B_2A_LAUNCHER_RECORD_V1','version':VERSION,'parent_runner_sha256':PARENT_SHA,'observer_v1_1_sha256':NEW_OBSERVER_SHA,'derived_runner_sha256':derived_sha,'changed_source_tokens':['observer SHA-256 gate','experiment version label','schema label'],'behavioral_control_changes':0,'attack_optimization_authorized':False},indent=2)+'\n',encoding='utf-8')
  cmd=[sys.executable,str(derived),*rest,'--observer',str(observer)]
  print(json.dumps({'version':VERSION,'derived_runner_sha256':derived_sha,'observer_sha256':NEW_OBSERVER_SHA},indent=2),flush=True)
  return subprocess.run(cmd).returncode
if __name__=='__main__':raise SystemExit(main())
