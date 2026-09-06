#!/usr/bin/env python3
"""EX6 P2B P2F Import and Interface Preflight.
Read-only import/interface validation only.
No model, tool, Sandbox, Gym, predicate, breach, or runtime evaluation.
"""
import argparse, ast, csv, hashlib, importlib.util, json, sys
from pathlib import Path
from datetime import datetime, timezone

VERSION='EX6_P2B_P2F_IMPORT_AND_INTERFACE_PREFLIGHT_v1.0'
EXPECTED_SHA='BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99'
EXPECTED_CLASS='TrustedGuardrailContextAdapterV1_1'

def sha(p):
 h=hashlib.sha256();h.update(Path(p).read_bytes());return h.hexdigest().upper()

def main():
 ap=argparse.ArgumentParser()
 ap.add_argument('--p2e-result',required=True)
 ap.add_argument('--p2e-external-binding',required=True)
 ap.add_argument('--repaired-source',required=True)
 ap.add_argument('--output-dir',required=True)
 a=ap.parse_args()
 out=Path(a.output_dir)
 if out.exists(): raise SystemExit('Refusing overwrite')
 out.mkdir(parents=True)
 res=json.loads(Path(a.p2e_result).read_text())
 assert res['status']=='P2B_P2E_CORRECTED_QUALIFIER_REQUALIFICATION_COMPLETE_PASS'
 src=Path(a.repaired_source)
 assert sha(src)==EXPECTED_SHA
 text=src.read_text(encoding='utf-8')
 tree=ast.parse(text)
 cls=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==EXPECTED_CLASS]
 iface_pass=bool(cls)
 import_pass=False
 import_error=None
 try:
  spec=importlib.util.spec_from_file_location('p2f_adapter',src)
  mod=importlib.util.module_from_spec(spec)
  spec.loader.exec_module(mod)
  import_pass=hasattr(mod,EXPECTED_CLASS)
 except Exception as e:
  import_error=str(e)
 result={
  'version':VERSION,
  'created_at_utc':datetime.now(timezone.utc).isoformat(),
  'status':'P2F_IMPORT_PREFLIGHT_PASS' if (iface_pass and import_pass) else 'P2F_IMPORT_PREFLIGHT_BLOCKED',
  'repaired_source_sha256':EXPECTED_SHA,
  'interface_presence':iface_pass,
  'module_importable':import_pass,
  'import_error':import_error,
  'execution_boundaries':{'runtime_behavior_tested':False,'adapter_instantiated':False,'tools_executed':False,'sandbox_executed':False,'gym_executed':False},
  'scientific_verdict':{'runtime_compatibility':'NOT_ESTABLISHED','authorization_transport_correctness':'NOT_ESTABLISHED'}
 }
 rp=out/'ex6_p2b_p2f_result.json'
 rp.write_text(json.dumps(result,indent=2))
 print(json.dumps(result,indent=2))
if __name__=='__main__': main()
