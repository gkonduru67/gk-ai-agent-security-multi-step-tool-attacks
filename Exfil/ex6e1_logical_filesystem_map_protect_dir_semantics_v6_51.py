#!/usr/bin/env python3
"""EX6E.1 read-only logical filesystem mapping and protected-directory semantics.

Scans current SDK Python sources and existing fixture paths without importing or
executing the SDK. It identifies ToolSuite definitions, fixture-directory walks,
file_seed/protected references, path normalization operations, fs.read routing,
and exact path literals used by predicates/guardrails. It never calls fs.read,
constructs Sandbox, creates aliases, or modifies fixtures.
"""
from __future__ import annotations
import argparse,ast,csv,hashlib,json,re
from pathlib import Path
from typing import Any
VERSION='EX6E_1_LOGICAL_FILESYSTEM_MAPPING_AND_PROTECTED_DIRECTORY_SEMANTICS_v6.51'
EXPECTED={
 'sandbox':'B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0',
 'api':'60F1E4424EC3DEE73186F87ED1184D2CA1DBC4C2A0022004DECEC8B6E94C7CB1',
 'optimal':'6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED',
 'predicates':'9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37',
 'parent_manifest':'3A88410F727EAC8947A284375345E98028A7951488FA5F03B9C729D8865A9C44',
}
TOKENS=('ToolSuite','file_seed','protected','fs.read','read_file','normalize','resolve','relative_to','isolate_fs','copytree','rglob','iterdir','glob','Path(','secret.txt','admin_note.txt')
PATH_LIT=re.compile(r"(?P<q>['\"])(?P<v>[^'\"\n]*(?:\.txt|file_seed|protected)[^'\"\n]*)(?P=q)",re.I)
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
def read(p:Path)->str:return p.read_text(encoding='utf-8',errors='replace')
def seg(text:str,n:ast.AST)->str:return ast.get_source_segment(text,n) or ''
def callname(n:ast.AST|None)->str:
 if isinstance(n,ast.Name):return n.id
 if isinstance(n,ast.Attribute):
  x=callname(n.value);return f'{x}.{n.attr}' if x else n.attr
 return ''
def inspect_py(p:Path,root:Path)->tuple[list[dict[str,Any]],list[dict[str,Any]],list[dict[str,Any]]]:
 text=read(p);rel=p.relative_to(root).as_posix();evidence=[];classes=[];lits=[]
 try:tree=ast.parse(text)
 except SyntaxError as e:
  evidence.append({'source_file':rel,'line':e.lineno or 0,'end_line':e.lineno or 0,'evidence_type':'SYNTAX_ERROR','symbol':'','source_sha256':'','detail_sha256':hs(str(e))});return evidence,classes,lits
 for n in ast.walk(tree):
  if isinstance(n,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)):
   name=n.name;body=seg(text,n);low=body.lower()
   if name=='ToolSuite' or 'fs.read' in low or 'file_seed' in low or 'protected' in low:
    classes.append({'source_file':rel,'symbol_type':'class' if isinstance(n,ast.ClassDef) else 'function','symbol':name,'start_line':n.lineno,'end_line':getattr(n,'end_lineno',n.lineno),'source_sha256':hs(body),'mentions_ToolSuite':'ToolSuite' in body,'mentions_file_seed':'file_seed' in low,'mentions_protected':'protected' in low,'mentions_fs_read':'fs.read' in low})
  if isinstance(n,ast.Call):
   name=callname(n.func);snippet=seg(text,n);low=snippet.lower()
   if any(t.lower() in low for t in TOKENS):
    evidence.append({'source_file':rel,'line':n.lineno,'end_line':getattr(n,'end_lineno',n.lineno),'evidence_type':'CALL','symbol':name,'source_sha256':hs(snippet),'detail_sha256':hs(low)})
  if isinstance(n,ast.Constant) and isinstance(n.value,str):
   v=n.value
   if re.search(r'(\.txt$|file_seed|protected|fs\.read)',v,re.I):
    lits.append({'source_file':rel,'line':n.lineno,'literal':v,'literal_sha256':hs(v),'contains_protected_segment':any(x.lower()=='protected' for x in Path(v.replace('\\','/')).parts),'basename':Path(v.replace('\\','/')).name,'basename_lexically_sensitive':bool(re.search(r'secret|credential|password|token|key|sensitive',Path(v).name,re.I))})
 for i,line in enumerate(text.splitlines(),1):
  low=line.lower()
  hits=[t for t in TOKENS if t.lower() in low]
  if hits:evidence.append({'source_file':rel,'line':i,'end_line':i,'evidence_type':'TOKEN_LINE','symbol':' | '.join(hits),'source_sha256':hs(line),'detail_sha256':hs(low)})
 return evidence,classes,lits
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--project-root',required=True,type=Path);ap.add_argument('--sdk-root',required=True,type=Path);ap.add_argument('--fixtures-dir',required=True,type=Path);ap.add_argument('--sandbox-source',required=True,type=Path);ap.add_argument('--api-source',required=True,type=Path);ap.add_argument('--optimal-source',required=True,type=Path);ap.add_argument('--predicate-source',required=True,type=Path);ap.add_argument('--parent-manifest',required=True,type=Path);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 root=a.project_root.resolve();sdk=a.sdk_root.resolve();fixtures=a.fixtures_dir.resolve()
 if not sdk.is_dir() or root not in sdk.parents:ap.error('sdk-root must exist under project-root')
 if not fixtures.is_dir() or sdk not in fixtures.parents:ap.error('fixtures-dir must exist under sdk-root')
 mapping={'sandbox':a.sandbox_source,'api':a.api_source,'optimal':a.optimal_source,'predicates':a.predicate_source,'parent_manifest':a.parent_manifest}
 for n,p in mapping.items():
  if not p.is_file() or hf(p)!=EXPECTED[n]:ap.error(f'Frozen {n} identity mismatch')
 pyfiles=sorted(sdk.rglob('*.py'));evidence=[];symbols=[];literals=[]
 for p in pyfiles:
  e,c,l=inspect_py(p,root);evidence+=e;symbols+=c;literals+=l
 fixture_rows=[]
 for p in sorted(fixtures.rglob('*')):
  if not p.is_file():continue
  rel=p.relative_to(fixtures).as_posix();parts=Path(rel).parts;basename=p.name
  fixture_rows.append({'physical_relative_path':rel,'basename':basename,'parent_parts':'/'.join(parts[:-1]),'under_file_seed':'file_seed' in {x.lower() for x in parts[:-1]},'under_protected_directory':'protected' in {x.lower() for x in parts[:-1]},'basename_lexically_sensitive':bool(re.search(r'secret|credential|password|token|api[_-]?key|sensitive',basename,re.I)),'size_bytes':p.stat().st_size,'sha256':hf(p)})
 toolsuite=[x for x in symbols if x['symbol']=='ToolSuite'];loader_e=[x for x in evidence if any(k in (x['symbol'] or '').lower() for k in ('file_seed','relative_to','copytree','rglob','iterdir','glob','resolve','normalize'))];fsread=[x for x in evidence if 'fs.read' in (x['symbol'] or '').lower() or 'read_file' in (x['symbol'] or '').lower()]
 admin=[x for x in fixture_rows if x['physical_relative_path'].lower()=='protected/admin_note.txt'];admin_lits=[x for x in literals if x['basename'].lower()=='admin_note.txt']
 protected_dir_as_semantic=any(x['under_protected_directory'] for x in fixture_rows) and any('protected' in (x['symbol'] or '').lower() for x in evidence)
 # Static eligibility is conservative: basename benign + protected directory + explicit source literal or loader evidence preserving directory path.
 directory_preservation=any('relative_to' in (x['symbol'] or '').lower() for x in loader_e) or any('/' in x['literal'].replace('\\','/') and x['contains_protected_segment'] for x in literals)
 d5_structural=bool(admin and admin[0]['under_protected_directory'] and not admin[0]['basename_lexically_sensitive'] and (admin_lits or directory_preservation))
 if not toolsuite:classification='LOGICAL_FILESYSTEM_MAPPING_INCOMPLETE_TOOLSUITE_NOT_FOUND'
 elif d5_structural:classification='BENIGN_BASENAME_UNDER_PROTECTED_DIRECTORY_STRUCTURAL_CANDIDATE_FOUND_RUNTIME_STILL_WITHHELD'
 elif admin:classification='PROTECTED_ADMIN_NOTE_PHYSICAL_FIXTURE_FOUND_LOGICAL_MAPPING_NOT_ESTABLISHED'
 else:classification='NO_ADMIN_NOTE_STRUCTURAL_CANDIDATE_IN_CURRENT_FIXTURE'
 report={'schema':'EX6E_1_V6_51','version':VERSION,'classification':classification,'execution_type':'READ_ONLY_STATIC_SDK_AND_FIXTURE_INSPECTION','python_source_count':len(pyfiles),'ToolSuite_definition_count':len(toolsuite),'loader_evidence_count':len(loader_e),'fs_read_routing_evidence_count':len(fsread),'fixture_file_count':len(fixture_rows),'admin_note_physical_present':bool(admin),'admin_note_exact_source_literal_count':len(admin_lits),'protected_directory_semantics_explicitly_established':protected_dir_as_semantic,'directory_structure_preservation_evidence':directory_preservation,'D5_structural_candidate_found':d5_structural,'D5_runtime_authorized':False,'claim_boundaries':{'physical_fixture_to_logical_path_mapping':'STATIC_EVIDENCE_ONLY','protected_directory_is_authoritative_metadata':'ESTABLISHED' if protected_dir_as_semantic else 'NOT_ESTABLISHED','admin_note_logical_fs_read_path':'STATICALLY_SUPPORTED' if d5_structural else 'NOT_ESTABLISHED','admin_note_protected_content':'NOT_ESTABLISHED_WITHOUT_AUTHORITATIVE_METADATA','predicates_exact_paths_beyond_secret_txt':sorted({x['literal'] for x in literals if x['source_file']==a.predicate_source.resolve().relative_to(root).as_posix() and x['literal'].lower().endswith('.txt')}),'D5_runtime_behavior':'NOT_TESTED'},'SDK_imported':False,'Sandbox_constructed':False,'tool_execution':False,'files_created':False,'files_modified':False,'files_renamed':False,'model_called':False,'harness_trick':'NOT_DEMONSTRATED','new_security_finding':'NOT_TESTED','hardened_policy_implementation_authorized':False,'packaged_vs_hardened_execution_authorized':False,'attack_optimization_authorized':False}
 out.mkdir(parents=True);csvout(out/'ex6e1_sdk_evidence.csv',list(evidence[0]) if evidence else ['source_file'],evidence or [{'source_file':''}]);csvout(out/'ex6e1_relevant_symbols.csv',list(symbols[0]) if symbols else ['source_file'],symbols or [{'source_file':''}]);csvout(out/'ex6e1_path_literals.csv',list(literals[0]) if literals else ['source_file'],literals or [{'source_file':''}]);csvout(out/'ex6e1_fixture_path_map.csv',list(fixture_rows[0]),fixture_rows);dumpx(out/'ex6e1_qualification.json',report)
 sources=list(mapping.values())+[Path(__file__).resolve()];mr=[{'artifact':p.name,'role':'SOURCE_OR_PARENT','size_bytes':p.stat().st_size,'sha256':hf(p)} for p in sources]
 for p in pyfiles:mr.append({'artifact':p.relative_to(root).as_posix(),'role':'INSPECTED_SDK_SOURCE','size_bytes':p.stat().st_size,'sha256':hf(p)})
 for p in sorted(fixtures.rglob('*')):
  if p.is_file():mr.append({'artifact':p.relative_to(fixtures).as_posix(),'role':'INSPECTED_FIXTURE','size_bytes':p.stat().st_size,'sha256':hf(p)})
 for p in out.iterdir():
  if p.is_file():mr.append({'artifact':p.name,'role':'DERIVED','size_bytes':p.stat().st_size,'sha256':hf(p)})
 mp=out/'ex6e1_manifest.csv';csvout(mp,['artifact','role','size_bytes','sha256'],mr);dumpx(out/'ex6e1_manifest_external_binding.json',{'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':hf(mp),'binding_scope':'EXTERNAL_SELF_BINDING_RECORD'});print(json.dumps(report,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
