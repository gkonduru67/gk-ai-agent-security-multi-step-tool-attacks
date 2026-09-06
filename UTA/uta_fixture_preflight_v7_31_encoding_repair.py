#!/usr/bin/env python3
"""UTA fixture preflight v7.31, encoding-normalized repair.

Repairs the confirmed Windows cp1252 construction failure by creating the
isolated fixture copy and serializing every JSON fixture with ensure_ascii=True
before ToolSuite reads it with Path.read_text() and the platform default codec.
No packaged fixture is modified.
"""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, sys, traceback
from pathlib import Path

def sha256(p: Path)->str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest().upper()

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--project-root',required=True,type=Path)
    ap.add_argument('--out-dir',required=True,type=Path)
    ap.add_argument('--preflight-script',required=True,type=Path,
                    help='Path to uta_fixture_preflight_v7_30_fixed.py')
    a=ap.parse_args()
    root=a.project_root.resolve(); out=a.out_dir.resolve(); src=(root/'aicomp_sdk/fixtures').resolve()
    if out.exists(): raise SystemExit(f'Refusing existing output directory: {out}')
    if not src.is_dir(): raise SystemExit(f'Fixture root not found: {src}')
    if not a.preflight_script.is_file(): raise SystemExit(f'Preflight script not found: {a.preflight_script}')
    # Build an ASCII-safe mirror of all JSON fixtures. ensure_ascii=True makes
    # bytes decodable by cp1252 while preserving decoded JSON string values.
    normalized=out/'normalized_packaged_fixtures'
    out.mkdir(parents=True,exist_ok=False); shutil.copytree(src,normalized)
    records=[]
    try:
        for jp in sorted(normalized.rglob('*.json')):
            before=sha256(jp)
            raw=jp.read_bytes()
            try: obj=json.loads(raw.decode('utf-8'))
            except UnicodeDecodeError: obj=json.loads(raw.decode('utf-8-sig'))
            tmp=jp.with_name(jp.name+'.tmp')
            tmp.write_text(json.dumps(obj,ensure_ascii=True,separators=(',',':'))+'\n',encoding='ascii',newline='\n')
            os.replace(tmp,jp)
            # prove ASCII-only bytes
            jp.read_bytes().decode('ascii')
            records.append({'file':jp.relative_to(out).as_posix(),'source_sha256':before,
                            'normalized_sha256':sha256(jp),'ascii_safe':True})
        # Create a temporary project overlay containing only normalized fixtures
        # and directory links/copies needed by the real source-tree script.
        overlay=out/'project_overlay'; overlay.mkdir()
        sdk_overlay=overlay/'aicomp_sdk'; sdk_overlay.mkdir()
        shutil.copytree(root/'aicomp_sdk/core',sdk_overlay/'core')
        shutil.copytree(normalized,sdk_overlay/'fixtures')
        for extra in ('guardrails','hooks.py','agents','attacks'):
            source=root/'aicomp_sdk'/extra
            if source.exists():
                if source.is_dir(): shutil.copytree(source,sdk_overlay/extra)
                else: shutil.copy2(source,sdk_overlay/extra)
        init=root/'aicomp_sdk/__init__.py'
        if init.exists(): shutil.copy2(init,sdk_overlay/'__init__.py')
        nested_out=out/'preflight_result'
        import subprocess
        cmd=[sys.executable,str(a.preflight_script.resolve()),'--project-root',str(overlay),'--out-dir',str(nested_out)]
        cp=subprocess.run(cmd,text=True,capture_output=True)
        result={'schema':'UTA_FIXTURE_ENCODING_REPAIR_V1','status':'PASS' if cp.returncode==0 else 'CHILD_FAILED',
                'reason':'ASCII-safe JSON mirror used to avoid Windows default-codec failure',
                'packaged_fixtures_modified':False,'normalization_records':records,
                'child_command':cmd,'child_returncode':cp.returncode,'child_stdout':cp.stdout,'child_stderr':cp.stderr}
        rp=out/'uta_fixture_preflight_v7_31_encoding_repair.json'
        rp.write_text(json.dumps(result,indent=2,ensure_ascii=True)+'\n',encoding='ascii')
        print(cp.stdout,end=''); print(cp.stderr,end='',file=sys.stderr)
        print(f'Encoding repair record: {rp}')
        return cp.returncode
    except Exception as e:
        d={'status':'SCRIPT_OR_ENVIRONMENT_FAILURE','exception_type':type(e).__name__,'exception':str(e),'traceback':traceback.format_exc()}
        (out/'uta_fixture_preflight_v7_31_failure.json').write_text(json.dumps(d,indent=2,ensure_ascii=True)+'\n',encoding='ascii')
        raise
if __name__=='__main__': raise SystemExit(main())
