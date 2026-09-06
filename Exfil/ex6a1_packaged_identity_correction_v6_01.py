#!/usr/bin/env python3
"""EX6A.1 packaged identity correction wrapper.

Invokes the frozen EX6A v6.00 runner with the corrected concrete packaged class
name Guardrail. No policy, proposal, observer, or trace is modified.
"""
from __future__ import annotations
import argparse,hashlib,subprocess,sys
from pathlib import Path
VERSION='EX6A_1_PACKAGED_GUARDRAIL_IDENTITY_CORRECTION_v6.01'
V600_SHA='4BEEF3CD1043B6091D7E098A58D77DF1975572DE2756E8BF5A24E6FE6D6A7803'
def hf(p):
 h=hashlib.sha256();h.update(Path(p).read_bytes());return h.hexdigest().upper()
def main():
 ap=argparse.ArgumentParser(add_help=True);ap.add_argument('--ex6a-v600-runner',required=True,type=Path);a,rest=ap.parse_known_args();runner=a.ex6a_v600_runner.resolve()
 if not runner.is_file() or hf(runner)!=V600_SHA:ap.error('Frozen EX6A v6.00 runner identity mismatch')
 if '--packaged-class' in rest:ap.error('Do not supply --packaged-class; EX6A.1 fixes it to Guardrail')
 cmd=[sys.executable,str(runner),*rest,'--packaged-class','Guardrail']
 print(f'{VERSION}: invoking frozen EX6A v6.00 with concrete class Guardrail',flush=True)
 return subprocess.run(cmd).returncode
if __name__=='__main__':raise SystemExit(main())
