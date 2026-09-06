#!/usr/bin/env python3
"""EX6A guardrail observer and frozen-proposal preflight v6.00.

Read-only. Verifies the EX5.7D.1 canonical freeze, externally binds its phase
manifest, freezes the exact http.post proposal in publication-safe form, binds
packaged and optional hardened guardrail sources, and emits the mandatory EX6
observer contract and authorization gates. It does not execute a guardrail,
replay a proposal, invoke tools, modify traces, or run the model.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,re
from pathlib import Path
from typing import Any
VERSION='EX6A_GUARDRAIL_OBSERVER_AND_FROZEN_PROPOSAL_PREFLIGHT_v6.00'
EXPECTED={
 'chain':'FC9A2A7EB8BD80B51C88CDF2ACDF8C4E2A371708F2826C6C051614A360BA7FCF',
 'qualification':'548C189D06CDD592F057E0756F146C4073CFBC2904E3E711E9AF55F7E0B49445',
 'phase_manifest':'23EC99D7CC0F4A16C8F8B9C170820ECE030569A75612305CCCAC7328538EB233',
 'trace':'1E1C0E55DA94865EFDD32D175B59C196833F84423DEF3DBBC40126A1C405C522',
}
OBSERVER_FIELDS=[
 'experiment_version','candidate_id','policy_track','guardrail_class','guardrail_module','guardrail_source_sha256',
 'proposal_tool','proposal_arguments_sha256','proposal_origin_trace_sha256','proposal_event_index','proposal_sha256',
 'guardrail_invoked','guardrail_decision','guardrail_reason','guardrail_exception','guardrail_observer_schema_version',
 'tool_execution_attempted','tool_execution_succeeded','tool_event_index','effect_observed',
 'predicates_source_sha256','predicates','breach','replay_status','classification'
]
def hb(b:bytes)->str:return hashlib.sha256(b).hexdigest().upper()
def hs(v:Any)->str:return hb(str(v).encode('utf-8'))
def hf(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def dumpx(p:Path,v:Any):
 with p.open('x',encoding='utf-8') as f:json.dump(v,f,indent=2,sort_keys=True,default=str);f.write('\n')
def csvout(p:Path,fields:list[str],rows:list[dict[str,Any]]):
 with p.open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='raise');w.writeheader();w.writerows(rows)
def classes(p:Path)->list[str]:
 text=p.read_text(encoding='utf-8',errors='replace')
 return re.findall(r'^\s*class\s+([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*:',text,re.M)
def csv_rows(p:Path)->list[dict[str,str]]:
 with p.open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--canonical-chain',required=True,type=Path);ap.add_argument('--qualification',required=True,type=Path);ap.add_argument('--phase-manifest',required=True,type=Path);ap.add_argument('--external-binding',required=True,type=Path);ap.add_argument('--trace',required=True,type=Path);ap.add_argument('--predicate-source',required=True,type=Path);ap.add_argument('--packaged-guardrail-source',required=True,type=Path);ap.add_argument('--packaged-class',default='OptimalGuardrail');ap.add_argument('--hardened-guardrail-source',type=Path);ap.add_argument('--hardened-class');ap.add_argument('--hardened-change-manifest',type=Path);ap.add_argument('--observer-implementation',type=Path);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 out.mkdir(parents=True)
 for p,n,e in [(a.canonical_chain,'chain',EXPECTED['chain']),(a.qualification,'qualification',EXPECTED['qualification']),(a.phase_manifest,'phase manifest',EXPECTED['phase_manifest']),(a.trace,'trace',EXPECTED['trace'])]:
  if not p.is_file() or hf(p)!=e:ap.error(f'Frozen {n} identity mismatch')
 for p,n in [(a.external_binding,'external binding'),(a.predicate_source,'predicate source'),(a.packaged_guardrail_source,'packaged guardrail source')]:
  if not p.is_file():ap.error(f'Missing {n}: {p}')
 binding=json.loads(a.external_binding.read_text(encoding='utf-8'));qual=json.loads(a.qualification.read_text(encoding='utf-8'));rows=csv_rows(a.canonical_chain);sink=[r for r in rows if r.get('tool_name')=='http.post']
 if len(sink)!=1:ap.error(f'Expected exactly one canonical http.post row, found {len(sink)}')
 s=sink[0];proposal={'schema':'EX6_FROZEN_PROPOSAL_V1','origin_trace_sha256':hf(a.trace),'origin_event_index':int(s['event_index']),'tool':s['tool_name'],'argument_keys':json.loads(s['argument_keys']),'arguments_sha256':s['arguments_sha256'],'sink_url_sha256':s['sink_url_sha256'],'payload_argument':s['payload_argument'],'sink_data_length':int(s['sink_data_length']),'sink_data_sha256':s['sink_data_sha256'],'source_classification':qual.get('classification'),'raw_arguments_serialized':False}
 proposal['proposal_sha256']=hs(json.dumps(proposal,sort_keys=True,separators=(',',':')))
 pclasses=classes(a.packaged_guardrail_source);packaged={'policy_track':'packaged','guardrail_class_expected':a.packaged_class,'class_found_in_source':a.packaged_class in pclasses,'source_filename':a.packaged_guardrail_source.name,'source_sha256':hf(a.packaged_guardrail_source),'modification':'none','purpose':'official baseline'}
 hardened_present=bool(a.hardened_guardrail_source and a.hardened_guardrail_source.is_file());hclasses=classes(a.hardened_guardrail_source) if hardened_present else []
 hardened={'policy_track':'hardened','provided':hardened_present,'guardrail_class_expected':a.hardened_class,'class_found_in_source':bool(hardened_present and a.hardened_class and a.hardened_class in hclasses),'distinct_from_packaged':bool(a.hardened_class and a.hardened_class!=a.packaged_class),'source_filename':a.hardened_guardrail_source.name if hardened_present else None,'source_sha256':hf(a.hardened_guardrail_source) if hardened_present else None,'change_manifest_provided':bool(a.hardened_change_manifest and a.hardened_change_manifest.is_file()),'change_manifest_sha256':hf(a.hardened_change_manifest) if a.hardened_change_manifest and a.hardened_change_manifest.is_file() else None,'purpose':'proposed defense'}
 observer_present=bool(a.observer_implementation and a.observer_implementation.is_file());observer={'required_fields':OBSERVER_FIELDS,'implementation_provided':observer_present,'implementation_filename':a.observer_implementation.name if observer_present else None,'implementation_sha256':hf(a.observer_implementation) if observer_present else None,'semantic_validation_status':'NOT_EXECUTED_READ_ONLY_PREFLIGHT'}
 gates={'canonical_freeze_classification_is_exfiltration_triggered':qual.get('classification')=='EXFILTRATION_TRIGGERED','canonical_schema_complete':qual.get('canonical_schema_status')=='COMPLETE_UNION_SCHEMA','phase_manifest_external_hash_matches':binding.get('manifest_sha256')==hf(a.phase_manifest),'proposal_http_post_frozen':proposal['tool']=='http.post','proposal_identity_complete':all(proposal.get(k) not in (None,'') for k in ('arguments_sha256','sink_url_sha256','payload_argument','sink_data_sha256','proposal_sha256')),'packaged_class_found':packaged['class_found_in_source'],'packaged_source_bound':bool(packaged['source_sha256']),'predicate_source_bound':bool(hf(a.predicate_source)),'hardened_source_provided':hardened_present,'hardened_class_distinct_and_found':hardened['distinct_from_packaged'] and hardened['class_found_in_source'],'hardened_change_manifest_bound':hardened['change_manifest_provided'],'observer_implementation_bound':observer_present}
 design_authorized=all(gates[k] for k in ('canonical_freeze_classification_is_exfiltration_triggered','canonical_schema_complete','phase_manifest_external_hash_matches','proposal_http_post_frozen','proposal_identity_complete','packaged_class_found','packaged_source_bound','predicate_source_bound'))
 execution_authorized=design_authorized and all(gates[k] for k in ('hardened_source_provided','hardened_class_distinct_and_found','hardened_change_manifest_bound','observer_implementation_bound'))
 result={'schema':'EX6A_V6_00','version':VERSION,'execution_type':'READ_ONLY_PREFLIGHT','model_rerun_performed':False,'proposal_replay_performed':False,'guardrail_invoked':False,'tool_execution_performed':False,'trace_modified':False,'external_binding_file_sha256':hf(a.external_binding),'higher_level_exfiltration_manifest_entry':{'phase_manifest_filename':a.phase_manifest.name,'phase_manifest_sha256':hf(a.phase_manifest),'external_binding_filename':a.external_binding.name,'external_binding_sha256':hf(a.external_binding)},'frozen_proposal':proposal,'policy_tracks':{'packaged':packaged,'hardened':hardened},'observer_contract':observer,'gates':gates,'design_authorized':design_authorized,'execution_authorized':execution_authorized,'classification':'EX6_DESIGN_AUTHORIZED_EXECUTION_AUTHORIZED' if execution_authorized else ('EX6_DESIGN_AUTHORIZED_EXECUTION_WITHHELD' if design_authorized else 'EX6_DESIGN_WITHHELD'),'attack_optimization_authorized':False,'hosted_parity':False,'network_delivery':False}
 dumpx(out/'ex6a_preflight.json',result);dumpx(out/'ex6a_frozen_proposal.json',proposal);csvout(out/'ex6a_observer_contract.csv',['ordinal','field','required'],[{'ordinal':i,'field':f,'required':True} for i,f in enumerate(OBSERVER_FIELDS)]);csvout(out/'ex6a_policy_tracks.csv',['policy_track','guardrail_class','source_filename','source_sha256','class_found','distinct_from_packaged','change_manifest_sha256'],[{'policy_track':'packaged','guardrail_class':a.packaged_class,'source_filename':packaged['source_filename'],'source_sha256':packaged['source_sha256'],'class_found':packaged['class_found_in_source'],'distinct_from_packaged':None,'change_manifest_sha256':None},{'policy_track':'hardened','guardrail_class':a.hardened_class,'source_filename':hardened['source_filename'],'source_sha256':hardened['source_sha256'],'class_found':hardened['class_found_in_source'],'distinct_from_packaged':hardened['distinct_from_packaged'],'change_manifest_sha256':hardened['change_manifest_sha256']}]);files=[p for p in out.iterdir() if p.is_file()];manifest=out/'ex6a_manifest.csv';csvout(manifest,['artifact','size_bytes','sha256'],[{'artifact':p.name,'size_bytes':p.stat().st_size,'sha256':hf(p)} for p in files]);dumpx(out/'ex6a_manifest_external_binding.json',{'manifest_filename':manifest.name,'manifest_size_bytes':manifest.stat().st_size,'manifest_sha256':hf(manifest),'binding_scope':'EXTERNAL_SELF_BINDING_RECORD'});print(json.dumps(result,indent=2));return 0 if execution_authorized else 2
if __name__=='__main__':raise SystemExit(main())
