#!/usr/bin/env python3
"""EX6F-M4A authorization-transport reviewed qualification and freeze v6.83A.

Read-only post-processing of the frozen v6.83 preflight. No source rescan, SDK
import, runtime execution, model call, context mutation, guardrail call, tool
call, predicate evaluation, or modification of parent artifacts.
"""
from __future__ import annotations
import argparse,csv,hashlib,json
from pathlib import Path
VERSION='EX6F_M4A_AUTHORIZATION_TRANSPORT_REVIEW_AND_FREEZE_v6.83A'
PARENT_SHA='0A1A1C70B3866EE11912E5069618E52BD67800DDE2F8B7DCDA80053ADBDD9A2D'
EXPECTED_GENERATED='M4A_AUTH_TRANSPORT_REVIEW_REQUIRED'
EXPECTED_EXACT_REFS=1
EXPECTED_CONSUMERS=1
EXPECTED_SETTERS=0
EXPECTED_CONSUMER_FILE='aicomp_sdk/guardrails/optimal.py'
EXPECTED_CONSUMER_LINE=37

def hf(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def jw(p,x):
 with Path(p).open('x',encoding='utf-8') as f:json.dump(x,f,indent=2,sort_keys=True);f.write('\n')
def cw(p,fields,rows):
 with Path(p).open('x',encoding='utf-8-sig',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='raise');w.writeheader();w.writerows(rows)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--preflight-dir',required=True,type=Path);ap.add_argument('--parent-manifest',required=True,type=Path);ap.add_argument('--parent-binding',required=True,type=Path);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();pd=a.preflight_dir.resolve();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 if not a.parent_manifest.is_file() or hf(a.parent_manifest)!=PARENT_SHA:ap.error('v6.83 parent manifest mismatch')
 bind=json.loads(a.parent_binding.read_text(encoding='utf-8'))
 if bind.get('manifest_sha256')!=PARENT_SHA:ap.error('v6.83 external binding mismatch')
 resultp=pd/'ex6f_m4a_auth_transport_preflight_result.json';linep=pd/'ex6f_m4a_auth_transport_line_evidence.csv';astp=pd/'ex6f_m4a_auth_transport_ast_evidence.csv';errp=pd/'ex6f_m4a_auth_transport_parse_errors.json'
 for p in (resultp,linep,astp,errp):
  if not p.is_file():ap.error(f'Missing frozen parent artifact: {p}')
 r=json.loads(resultp.read_text(encoding='utf-8'))
 locs=r.get('consumer_locations') or []
 predicate=(r.get('classification')==EXPECTED_GENERATED and r.get('exact_flag_reference_count')==EXPECTED_EXACT_REFS and r.get('consumer_read_count')==EXPECTED_CONSUMERS and r.get('possible_setter_count')==EXPECTED_SETTERS and len(locs)==1 and locs[0].get('file')==EXPECTED_CONSUMER_FILE and locs[0].get('line')==EXPECTED_CONSUMER_LINE)
 if not predicate:ap.error('Frozen v6.83 evidence does not satisfy reviewed-qualification predicate')
 parse_errors=json.loads(errp.read_text(encoding='utf-8'))
 review={'version':VERSION,'execution_type':'READ_ONLY_REVIEWED_QUALIFICATION','source_rescan':False,'runtime':False,'model_called':False,'context_mutated':False,'original_artifacts_modified':False,'generated_classification':EXPECTED_GENERATED,'reviewed_classification':'AUTHORIZATION_FLAGS_CONSUMED_ONLY_NO_TRANSPORT_FOUND','review_predicate':{'exact_flag_references':1,'consumer_reads':1,'possible_setters':0,'sole_consumer_file':EXPECTED_CONSUMER_FILE,'sole_consumer_line':EXPECTED_CONSUMER_LINE,'parse_error_count':len(parse_errors)},'transport_review':{'who_sets_the_flag':'NOT_ESTABLISHED','where_it_is_set':'NOT_FOUND_IN_SCANNED_SDK','what_input_controls_it':'NOT_ESTABLISHED','documented_interface':'NOT_FOUND_IN_SCANNED_SDK','trusted_source':'NOT_EVALUABLE','prompt_or_model_influence':'NOT_ESTABLISHED','persistence_across_hops':'NOT_EVALUABLE','action_binding':'NOT_PRESENT_IN_CONSUMER_CONDITION','target_binding':'NOT_PRESENT_IN_CONSUMER_CONDITION'},'generic_hook_mutation':{'infrastructure_present':True,'bundled_authorization_setter':'NOT_FOUND','documented_authorization_hook':'NOT_FOUND'},'authorization_matched_runtime':'WITHHELD_NOT_JUSTIFIED_THROUGH_DOCUMENTED_INTERFACE','claim_boundaries':{'universal_absence_of_setter':'NOT_CLAIMED','external_or_custom_setter':'NOT_EVALUATED','runtime_reachability':'NOT_ESTABLISHED','exploitability':'NOT_ESTABLISHED'},'harness_trick':'NOT_DEMONSTRATED','security_finding':{'vulnerability':'NOT_ESTABLISHED','policy_structure':'AUTHORIZATION_CONSUMER_EXISTS_WITHOUT_DISCOVERED_BUNDLED_TRANSPORT','local_defensive_behavior':'PACKAGED_OPTIMAL_DENIED_PROTECTED_READ_WITHOUT_DEMONSTRATED_AUTHORIZATION_CONTEXT'},'next_authorized_control':'EXFIL_FAILED_SOURCE_ATTRIBUTION_DESIGN_ONLY'}
 out.mkdir(parents=True);jw(out/'ex6f_m4a_auth_transport_reviewed_qualification.json',review)
 matrix=[{'question':'who_sets_the_flag','answer':'NOT_ESTABLISHED','evidence_basis':'zero exact-name setters in scanned SDK'},{'question':'where_it_is_set','answer':'NOT_FOUND_IN_SCANNED_SDK','evidence_basis':'sole exact reference is packaged Optimal consumer'},{'question':'documented_interface','answer':'NOT_FOUND_IN_SCANNED_SDK','evidence_basis':'no exact API, Gym, CLI, Sandbox, hook, schema, or docs transport'},{'question':'prompt_or_model_influence','answer':'NOT_ESTABLISHED','evidence_basis':'no exact mapping found'},{'question':'persistence_across_hops','answer':'NOT_EVALUABLE','evidence_basis':'flag creation not established'},{'question':'action_binding','answer':'NOT_PRESENT_IN_CONSUMER_CONDITION','evidence_basis':'consumer is Boolean condition'},{'question':'target_binding','answer':'NOT_PRESENT_IN_CONSUMER_CONDITION','evidence_basis':'consumer allow precedes target evaluation'}]
 cw(out/'ex6f_m4a_auth_transport_review_matrix.csv',['question','answer','evidence_basis'],matrix)
 manifest=[]
 for p in (a.parent_manifest,a.parent_binding,resultp,linep,astp,errp,Path(__file__).resolve()):manifest.append({'artifact':p.name,'role':'SOURCE_OR_PARENT','size_bytes':p.stat().st_size,'sha256':hf(p)})
 for p in out.iterdir():
  if p.is_file():manifest.append({'artifact':p.name,'role':'DERIVED_READ_ONLY','size_bytes':p.stat().st_size,'sha256':hf(p)})
 mp=out/'ex6f_m4a_auth_transport_review_manifest.csv';cw(mp,['artifact','role','size_bytes','sha256'],manifest);jw(out/'ex6f_m4a_auth_transport_review_manifest_external_binding.json',{'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':hf(mp),'parent_manifest_sha256':PARENT_SHA})
 print(json.dumps({'version':VERSION,'reviewed_classification':review['reviewed_classification'],'authorization_matched_runtime':review['authorization_matched_runtime'],'next_authorized_control':review['next_authorized_control'],'manifest_sha256':hf(mp)},indent=2))
if __name__=='__main__':main()
