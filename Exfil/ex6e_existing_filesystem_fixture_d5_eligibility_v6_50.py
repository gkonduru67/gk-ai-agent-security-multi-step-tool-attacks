#!/usr/bin/env python3
"""EX6E read-only existing filesystem fixture classification and D5 eligibility.

Inspects only existing SDK fixture/source files. It never imports the SDK,
constructs Sandbox, calls tools, reads files through the agent interface,
creates aliases, renames files, or modifies fixtures. Content is summarized by
hashes and lexical indicators; raw content is not exported.
"""
from __future__ import annotations
import argparse,ast,csv,hashlib,json,re
from pathlib import Path
from typing import Any
VERSION='EX6E_EXISTING_FILESYSTEM_FIXTURE_CLASSIFICATION_AND_D5_ELIGIBILITY_v6.50'
EXPECTED={'sandbox':'B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0','api':'60F1E4424EC3DEE73186F87ED1184D2CA1DBC4C2A0022004DECEC8B6E94C7CB1','optimal':'6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED','predicates':'9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37','parent_manifest':'A2ABA68E26DF4C9A2E35BBEF221A8A118AEF3E293D64E8CF9D9DE42F6EA2322B'}
PATH_TERMS=('secret','credential','password','passwd','token','api_key','apikey','private','sensitive','key','auth')
CONTENT_TERMS=('secret','credential','password','passwd','token','api key','api_key','private key','sensitive','do not share','confidential')
AUTHORITATIVE_TERMS=('secret','protected','sensitive','credential')
def hf(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def hs(s:str)->str:return hashlib.sha256(s.encode('utf-8')).hexdigest().upper()
def dumpx(p:Path,v:Any):
 with p.open('x',encoding='utf-8') as f:json.dump(v,f,indent=2,sort_keys=True,default=str);f.write('\n')
def csvout(p:Path,fields:list[str],rows:list[dict[str,Any]]):
 with p.open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='raise');w.writeheader();w.writerows(rows)
def text(p:Path)->str:
 try:return p.read_text(encoding='utf-8')
 except UnicodeDecodeError:return p.read_text(encoding='utf-8',errors='replace')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--project-root',required=True,type=Path);ap.add_argument('--fixtures-dir',required=True,type=Path);ap.add_argument('--sandbox-source',required=True,type=Path);ap.add_argument('--api-source',required=True,type=Path);ap.add_argument('--optimal-source',required=True,type=Path);ap.add_argument('--predicate-source',required=True,type=Path);ap.add_argument('--parent-manifest',required=True,type=Path);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 mapping={'sandbox':a.sandbox_source,'api':a.api_source,'optimal':a.optimal_source,'predicates':a.predicate_source,'parent_manifest':a.parent_manifest}
 for n,p in mapping.items():
  if not p.is_file() or hf(p)!=EXPECTED[n]:ap.error(f'Frozen {n} identity mismatch')
 if not a.fixtures_dir.is_dir():ap.error('fixtures directory missing')
 root=a.project_root.resolve();fixtures=a.fixtures_dir.resolve()
 if root not in fixtures.parents and fixtures!=root:ap.error('fixtures-dir is outside project-root')
 # Extract source references to filenames and protection semantics without executing code.
 source_refs=[]
 for role,p in [('sandbox',a.sandbox_source),('api',a.api_source),('optimal',a.optimal_source),('predicates',a.predicate_source)]:
  s=text(p)
  for i,line in enumerate(s.splitlines(),1):
   low=line.lower()
   if any(t in low for t in AUTHORITATIVE_TERMS) or re.search(r"[A-Za-z0-9_.-]+\.txt",line):
    source_refs.append({'source_role':role,'source_file':p.name,'line':i,'line_sha256':hs(line),'filename_tokens':' | '.join(sorted(set(re.findall(r"[A-Za-z0-9_.-]+\.txt",line,re.I)))),'semantic_terms':' | '.join(t for t in AUTHORITATIVE_TERMS if t in low)})
 # Inventory existing fixture disk files only. JSON corpora remain artifacts, not fs.read paths unless source explicitly maps them.
 rows=[]
 for p in sorted(fixtures.rglob('*')):
  if not p.is_file():continue
  rel=p.relative_to(fixtures).as_posix();lowpath=rel.lower();raw=p.read_bytes();is_text=p.suffix.lower() in {'.txt','.json','.csv','.md','.yaml','.yml','.log'}
  body=text(p) if is_text else '';lowbody=body.lower();path_hits=[t for t in PATH_TERMS if t in lowpath];content_hits=[t for t in CONTENT_TERMS if t in lowbody]
  explicit_refs=[r for r in source_refs if rel.lower() in r['filename_tokens'].lower() or p.name.lower() in r['filename_tokens'].lower()]
  authoritative=bool(explicit_refs and any(r['semantic_terms'] for r in explicit_refs))
  benign_name=not path_hits
  rows.append({'relative_path':rel,'filename':p.name,'suffix':p.suffix.lower(),'size_bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest().upper(),'text_decoded':is_text,'path_lexically_sensitive':bool(path_hits),'path_indicators':' | '.join(path_hits),'content_indicator_present':bool(content_hits),'content_indicators':' | '.join(content_hits),'source_reference_count':len(explicit_refs),'authoritative_protected_classification':authoritative,'benign_named_protected_candidate':benign_name and authoritative,'lexical_only_candidate':benign_name and bool(content_hits) and not authoritative,'raw_content_exported':False})
 candidates=[r for r in rows if r['benign_named_protected_candidate']]
 lexical=[r for r in rows if r['lexical_only_candidate']]
 if candidates:classification='D5_AUTHORITATIVE_EXISTING_BENIGN_NAMED_PROTECTED_FIXTURE_FOUND'
 elif lexical:classification='D5_NOT_AUTHORIZED_LEXICAL_CONTENT_INDICATORS_ONLY'
 else:classification='D5_UNAVAILABLE_NO_AUTHORITATIVE_EXISTING_FIXTURE_FOUND'
 report={'schema':'EX6E_V6_50','version':VERSION,'classification':classification,'execution_type':'READ_ONLY_STATIC_FIXTURE_AND_SOURCE_INSPECTION','fixture_root_relative':fixtures.relative_to(root).as_posix(),'fixture_file_count':len(rows),'authoritative_D5_candidate_count':len(candidates),'lexical_only_candidate_count':len(lexical),'D5_runtime_authorized':len(candidates)==1,'D5_candidate_paths_sha256':[hs(r['relative_path']) for r in candidates],'authoritative_definition':'Existing benign-named fixture file plus explicit protected/sensitive classification in inspected SDK source reference','lexical_content_is_authoritative':False,'raw_content_exported':False,'files_created':False,'files_modified':False,'files_renamed':False,'SDK_imported':False,'Sandbox_constructed':False,'tool_execution':False,'model_called':False,'harness_trick':'NOT_DEMONSTRATED','new_security_finding':'NOT_TESTED','hardened_policy_implementation_authorized':False,'packaged_vs_hardened_execution_authorized':False,'attack_optimization_authorized':False}
 out.mkdir(parents=True);csvout(out/'ex6e_fixture_inventory.csv',list(rows[0]) if rows else ['relative_path'],rows or [{'relative_path':''}]);csvout(out/'ex6e_source_references.csv',list(source_refs[0]) if source_refs else ['source_role','source_file','line','line_sha256','filename_tokens','semantic_terms'],source_refs or [{'source_role':'','source_file':'','line':'','line_sha256':'','filename_tokens':'','semantic_terms':''}]);dumpx(out/'ex6e_qualification.json',report)
 sources=list(mapping.values())+[Path(__file__).resolve()];mr=[{'artifact':p.name,'role':'SOURCE_OR_PARENT','size_bytes':p.stat().st_size,'sha256':hf(p)} for p in sources]
 # Bind each inspected fixture directly, then bind derived outputs.
 for p in sorted(fixtures.rglob('*')):
  if p.is_file():mr.append({'artifact':p.relative_to(fixtures).as_posix(),'role':'INSPECTED_FIXTURE','size_bytes':p.stat().st_size,'sha256':hf(p)})
 for p in out.iterdir():
  if p.is_file():mr.append({'artifact':p.name,'role':'DERIVED','size_bytes':p.stat().st_size,'sha256':hf(p)})
 mp=out/'ex6e_manifest.csv';csvout(mp,['artifact','role','size_bytes','sha256'],mr);dumpx(out/'ex6e_manifest_external_binding.json',{'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':hf(mp),'binding_scope':'EXTERNAL_SELF_BINDING_RECORD'});print(json.dumps(report,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
