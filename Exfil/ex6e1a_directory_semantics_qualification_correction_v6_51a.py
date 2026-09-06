#!/usr/bin/env python3
"""EX6E.1A read-only directory-semantics qualification correction.

Preserves and hash-validates the frozen EX6E.1 evidence package, corrects only
its analytical qualification, binds the corrected artifacts in a new manifest,
and creates an external manifest binding. It imports no SDK code, constructs no
Sandbox, executes no tools, and modifies no parent artifact.
"""
from __future__ import annotations
import argparse,csv,hashlib,json
from pathlib import Path
from typing import Any

VERSION='EX6E_1A_DIRECTORY_SEMANTICS_QUALIFICATION_CORRECTION_v6.51A'
EXPECTED={
 'qualification':'',
 'fixture_path_map':'',
 'path_literals':'',
 'relevant_symbols':'',
 'sdk_evidence':'',
 'manifest':'293B918AE4B979AFCADD6EF27635CC01F92C72EF6ACEEA0DFC91BE3E539070F4',
}

def hf(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()

def dumpx(p:Path,v:Any):
 with p.open('x',encoding='utf-8') as f:
  json.dump(v,f,indent=2,sort_keys=True,default=str);f.write('\n')

def csvout(p:Path,fields:list[str],rows:list[dict[str,Any]]):
 with p.open('x',encoding='utf-8-sig',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='raise');w.writeheader();w.writerows(rows)

def rows(p:Path)->list[dict[str,str]]:
 with p.open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))

def main():
 ap=argparse.ArgumentParser()
 ap.add_argument('--qualification',required=True,type=Path)
 ap.add_argument('--fixture-path-map',required=True,type=Path)
 ap.add_argument('--path-literals',required=True,type=Path)
 ap.add_argument('--relevant-symbols',required=True,type=Path)
 ap.add_argument('--sdk-evidence',required=True,type=Path)
 ap.add_argument('--parent-manifest',required=True,type=Path)
 ap.add_argument('--parent-binding',required=True,type=Path)
 ap.add_argument('--out-root',required=True,type=Path)
 a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 inputs={'qualification':a.qualification,'fixture_path_map':a.fixture_path_map,'path_literals':a.path_literals,'relevant_symbols':a.relevant_symbols,'sdk_evidence':a.sdk_evidence,'manifest':a.parent_manifest}
 for n,p in inputs.items():
  if not p.is_file():ap.error(f'Missing {n}: {p}')
 if hf(a.parent_manifest)!=EXPECTED['manifest']:ap.error('Parent manifest SHA-256 mismatch')
 if not a.parent_binding.is_file():ap.error('Parent external binding missing')
 binding=json.loads(a.parent_binding.read_text(encoding='utf-8'))
 if binding.get('manifest_sha256')!=hf(a.parent_manifest):ap.error('Parent binding does not match parent manifest')
 parent=json.loads(a.qualification.read_text(encoding='utf-8'))
 fixture=rows(a.fixture_path_map);literals=rows(a.path_literals);symbols=rows(a.relevant_symbols)
 admin=next((r for r in fixture if r.get('physical_relative_path','').lower()=='protected/admin_note.txt'),None)
 if not admin:ap.error('Expected protected/admin_note.txt row not found')
 tool_suite=next((r for r in symbols if r.get('symbol')=='ToolSuite'),None)
 creator=next((r for r in symbols if r.get('symbol')=='_create_fs_root'),None)
 if not tool_suite or not creator:ap.error('Expected ToolSuite and _create_fs_root symbol evidence not found')
 admin_literals=[r for r in literals if r.get('basename','').lower()=='admin_note.txt']
 exact_predicate_txt=sorted({r.get('literal','') for r in literals if r.get('source_file')=='aicomp_sdk/core/predicates.py' and r.get('literal','').lower().endswith('.txt')})
 other_predicate_txt=[x for x in exact_predicate_txt if x.lower()!='secret.txt']
 corrected={
  'schema':'EX6E_1A_V6_51A','version':VERSION,
  'correction_type':'READ_ONLY_ANALYTICAL_QUALIFICATION_CORRECTION',
  'parent_version':parent.get('version'),'parent_classification':parent.get('classification'),
  'classification':'BENIGN_BASENAME_UNDER_PROTECTED_DIRECTORY_PHYSICAL_CANDIDATE_FOUND_LOGICAL_MAPPING_STATICALLY_SUPPORTED_PROTECTION_SEMANTICS_UNRESOLVED',
  'parent_artifacts_modified':False,'runtime_rerun_performed':False,
  'findings':{
   'ToolSuite_definition_found':True,
   'physical_fixture_to_logical_path_mapping':'STATIC_EVIDENCE_ONLY',
   'directory_structure_preservation':'STATIC_EVIDENCE_PRESENT',
   'protected_directory_is_authoritative_metadata':'NOT_ESTABLISHED_FROM_ATTACHED_EVIDENCE',
   'admin_note':{
    'physical_relative_path':'protected/admin_note.txt','physical_present':True,
    'file_sha256':admin.get('sha256'),'basename':admin.get('basename'),
    'basename_lexically_sensitive':str(admin.get('basename_lexically_sensitive')).lower()=='true',
    'under_protected_directory':str(admin.get('under_protected_directory')).lower()=='true',
    'exact_source_literal_count':len(admin_literals),
    'logical_fs_read_path':'STATICALLY_SUPPORTED',
    'protected_content':'NOT_ESTABLISHED_WITHOUT_AUTHORITATIVE_METADATA',
    'candidate_type':'PROVISIONAL_STRUCTURAL_DIRECTORY_CANDIDATE',
    'authoritative_D5_candidate':False,
   },
   'predicates':{
    'exact_txt_path_literals':exact_predicate_txt,
    'exact_paths_other_than_secret_txt':other_predicate_txt,
    'admin_note_exact_binding':False,
   },
  },
  'correction':{
   'field':'protected_directory_is_authoritative_metadata','reported':'ESTABLISHED','corrected':'NOT_ESTABLISHED',
   'reason':'ToolSuite and _create_fs_root evidence mentions file_seed but does not itself establish protected-directory authority; broad protected-token evidence elsewhere is insufficient.',
   'layer':'ANALYSIS_AGGREGATION','runtime_result_changed':False,
  },
  'D5':{'structural_candidate_found':True,'authoritative_protected_candidate':False,'runtime_authorized':False,'behavior':'NOT_TESTED'},
  'runtime':{'SDK_imported':False,'Sandbox_constructed':False,'tool_execution':False,'model_called':False},
  'mutations':{'files_created':False,'files_modified':False,'files_renamed':False},
  'harness_trick':'NOT_DEMONSTRATED','security_finding':'NOT_ESTABLISHED',
  'methodological_finding':'PHYSICAL_PROTECTED_DIRECTORY_CANDIDATE_IDENTIFIED_WITH_STATIC_LOGICAL_MAPPING_BUT_NO_AUTHORITATIVE_CONTENT_CLASSIFICATION',
  'authorization':{'focused_function_body_inspection':True,'admin_note_source_only_runtime':False,'D5_sink_runtime':False,'hardened_policy_implementation':False,'packaged_vs_hardened_execution':False,'attack_optimization':False},
 }
 out.mkdir(parents=True)
 qp=out/'ex6e1a_corrected_qualification.json';dumpx(qp,corrected)
 matrix=[
  {'claim':'physical_fixture_to_logical_path_mapping','parent_value':parent.get('claim_boundaries',{}).get('physical_fixture_to_logical_path_mapping'),'corrected_value':'STATIC_EVIDENCE_ONLY','status':'PRESERVED'},
  {'claim':'protected_directory_is_authoritative_metadata','parent_value':parent.get('claim_boundaries',{}).get('protected_directory_is_authoritative_metadata'),'corrected_value':'NOT_ESTABLISHED','status':'CORRECTED'},
  {'claim':'admin_note_logical_fs_read_path','parent_value':parent.get('claim_boundaries',{}).get('admin_note_logical_fs_read_path'),'corrected_value':'STATICALLY_SUPPORTED','status':'PRESERVED'},
  {'claim':'admin_note_protected_content','parent_value':parent.get('claim_boundaries',{}).get('admin_note_protected_content'),'corrected_value':'NOT_ESTABLISHED_WITHOUT_AUTHORITATIVE_METADATA','status':'PRESERVED'},
  {'claim':'D5_runtime_authorized','parent_value':parent.get('D5_runtime_authorized'),'corrected_value':False,'status':'PRESERVED'},
 ]
 cp=out/'ex6e1a_claim_correction_matrix.csv';csvout(cp,list(matrix[0]),matrix)
 sources=[a.qualification,a.fixture_path_map,a.path_literals,a.relevant_symbols,a.sdk_evidence,a.parent_manifest,a.parent_binding,Path(__file__).resolve()]
 mr=[{'artifact':p.name,'role':'SOURCE_OR_PARENT','size_bytes':p.stat().st_size,'sha256':hf(p)} for p in sources]
 for p in (qp,cp):mr.append({'artifact':p.name,'role':'DERIVED_CORRECTED','size_bytes':p.stat().st_size,'sha256':hf(p)})
 mp=out/'ex6e1a_corrected_manifest.csv';csvout(mp,['artifact','role','size_bytes','sha256'],mr)
 dumpx(out/'ex6e1a_corrected_manifest_external_binding.json',{'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':hf(mp),'binding_scope':'EXTERNAL_SELF_BINDING_RECORD'})
 print(json.dumps({'version':VERSION,'classification':corrected['classification'],'corrected_qualification_sha256':hf(qp),'corrected_manifest_sha256':hf(mp)},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
