#!/usr/bin/env python3
"""EX6F-M4A read-only protected-source contract preflight v6.81.

No model, Sandbox, tool, guardrail, or predicate execution occurs. This script:
1. binds the frozen M3F parent manifest and external binding;
2. locates and hashes the exact protected fixture candidate secret.txt;
3. hashes predicates.py, sandbox.py, and packaged optimal.py;
4. records line-bound source excerpts for protected-source, fs.read, secret,
   http.post, data, guardrail, deny, predicate, and breach terms;
5. emits a preflight decision without exposing the protected value in summaries.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,re
from pathlib import Path

VERSION='EX6F_M4A_PROTECTED_SOURCE_CONTRACT_PREFLIGHT_v6.81'
PARENT_MANIFEST_SHA='65BCA01C452629BC5463DDD3DF538C72D3AED72A8D2C5D8BBB17CB8DFA0BAD92'
EXPECTED_M3F_RUNNER_SHA='5B8ADFBF5C5A389984E732FF20FEA178A4B01E52187208F38E6DD2B9BD2ED763'
TERMS=('EXFILTRATION','fs.read','secret.txt','secret','http.post','data','breach','predicate','guardrail','DENY','ALLOW')

def hb(b): return hashlib.sha256(b).hexdigest().upper()
def hf(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''): h.update(b)
    return h.hexdigest().upper()
def jwrite(p,x):
    with Path(p).open('x',encoding='utf-8') as f: json.dump(x,f,indent=2,sort_keys=True); f.write('\n')
def cwrite(p,fields,rows):
    with Path(p).open('x',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='raise'); w.writeheader(); w.writerows(rows)
def excerpt(path):
    text=path.read_text(encoding='utf-8',errors='replace').splitlines(); rows=[]
    for n,line in enumerate(text,1):
        hits=[t for t in TERMS if t.lower() in line.lower()]
        if hits:
            rows.append({'file':path.as_posix(),'line':n,'terms':'|'.join(hits),'line_sha256':hb(line.encode('utf-8')),'text':line})
    return rows

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--project-root',required=True,type=Path)
    ap.add_argument('--parent-manifest',required=True,type=Path)
    ap.add_argument('--parent-binding',required=True,type=Path)
    ap.add_argument('--out-root',required=True,type=Path)
    a=ap.parse_args(); root=a.project_root.resolve(); out=a.out_root.resolve()
    if out.exists(): ap.error(f'Refusing to overwrite: {out}')
    if not a.parent_manifest.is_file() or hf(a.parent_manifest)!=PARENT_MANIFEST_SHA: ap.error('Frozen M3F parent manifest identity mismatch')
    binding=json.loads(a.parent_binding.read_text(encoding='utf-8'))
    if binding.get('manifest_sha256')!=PARENT_MANIFEST_SHA: ap.error('M3F external binding does not bind expected parent manifest')
    paths={
      'predicates':root/'aicomp_sdk/core/predicates.py',
      'sandbox':root/'aicomp_sdk/core/env/sandbox.py',
      'optimal':root/'aicomp_sdk/guardrails/optimal.py',
      'readme':root/'aicomp_sdk/fixtures/file_seed/readme.txt',
      'protected_candidate':root/'aicomp_sdk/fixtures/file_seed/secret.txt',
    }
    for k,p in paths.items():
        if not p.is_file(): ap.error(f'Missing required {k} file: {p}')
    out.mkdir(parents=True)
    protected=paths['protected_candidate']; protected_bytes=protected.read_bytes()
    inventory=[]
    for role,p in paths.items(): inventory.append({'role':role,'path':p.as_posix(),'size_bytes':p.stat().st_size,'sha256':hf(p),'contains_value_in_summary':False if role=='protected_candidate' else None})
    cwrite(out/'ex6f_m4a_source_inventory.csv',['role','path','size_bytes','sha256','contains_value_in_summary'],inventory)
    rows=[]
    for role in ('predicates','sandbox','optimal'):
        rows.extend(excerpt(paths[role]))
    cwrite(out/'ex6f_m4a_line_bound_contract_evidence.csv',['file','line','terms','line_sha256','text'],rows)
    term_summary={t:{'match_count':sum(t in r['terms'].split('|') for r in rows),'files':sorted({r['file'] for r in rows if t in r['terms'].split('|')})} for t in TERMS}
    protected_meta={'path':protected.relative_to(root).as_posix(),'filename':protected.name,'size_bytes':len(protected_bytes),'sha256':hb(protected_bytes),'value_exported':False,'value_preview_exported':False,'qualifying_status':'REQUIRES_LINE_BOUND_PREDICATE_AND_GUARDRAIL_REVIEW'}
    result={'version':VERSION,'execution_type':'READ_ONLY_SOURCE_AND_FIXTURE_PREFLIGHT','parent_manifest_sha256':PARENT_MANIFEST_SHA,'protected_fixture':protected_meta,'authoritative_sources':{k:{'path':p.relative_to(root).as_posix(),'sha256':hf(p)} for k,p in paths.items() if k in ('predicates','sandbox','optimal')},'term_summary':term_summary,'model_called':False,'sandbox_constructed':False,'tool_executed':False,'guardrail_executed':False,'predicates_executed':False,'protected_value_exported':False,'classification':'M4A_PREFLIGHT_REVIEW_REQUIRED','authorization':{'M4A_runtime_execution':False,'next_step':'Review line-bound evidence and freeze exact protected-source and policy contract before runner creation'}}
    jwrite(out/'ex6f_m4a_preflight_result.json',result)
    manifest=[]
    for p in [a.parent_manifest,a.parent_binding,*paths.values(),Path(__file__).resolve()]: manifest.append({'artifact':p.name,'role':'SOURCE_OR_PARENT','size_bytes':p.stat().st_size,'sha256':hf(p)})
    for p in out.iterdir():
        if p.is_file(): manifest.append({'artifact':p.name,'role':'DERIVED_READ_ONLY','size_bytes':p.stat().st_size,'sha256':hf(p)})
    mp=out/'ex6f_m4a_preflight_manifest.csv'; cwrite(mp,['artifact','role','size_bytes','sha256'],manifest)
    jwrite(out/'ex6f_m4a_preflight_manifest_external_binding.json',{'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':hf(mp),'binding_scope':'EXTERNAL_SELF_BINDING_RECORD','parent_manifest_sha256':PARENT_MANIFEST_SHA})
    print(json.dumps({'version':VERSION,'classification':result['classification'],'protected_path':protected_meta['path'],'protected_sha256':protected_meta['sha256'],'protected_value_exported':False,'manifest_sha256':hf(mp)},indent=2)); return 0
if __name__=='__main__': raise SystemExit(main())
