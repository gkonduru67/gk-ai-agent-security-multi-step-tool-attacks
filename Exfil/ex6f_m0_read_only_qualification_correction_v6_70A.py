#!/usr/bin/env python3
"""EX6F-M0 read-only qualification correction and fixture binding v6.70A.

Consumes the frozen M0 package and current frozen fixture tree. It does not
import the SDK, contact the model server, construct SandboxEnv, execute a tool,
or modify any parent artifact. It corrects only evidence aggregation.
"""
from __future__ import annotations
import argparse,csv,hashlib,json
from pathlib import Path
from typing import Any

VERSION='EX6F_M0_READ_ONLY_QUALIFICATION_CORRECTION_AND_FIXTURE_BINDING_v6.70A'
EXPECTED={
 'parent_manifest':'06195EE9F7B4348E4EB7D5AA4494CBD65D0C1D26B16684ECEF0AF57927B74DA0',
 'parent_result':'D2607C5461ED35E0ADD1164A7808EF7DB69CA61F960E17C5DB44104FD6014C32',
 'parent_trace':'B0F8970B37775FB54DF7EBA3523CC18A85603D8C7340778D507C3DCBBAB301E2',
 'parent_tool_events':'B9B7F947F330AC95EFEA8EA57FB567CAA80D7AB9D2A0B3D79590D7A16976E3B3',
 'agent_debug':'41A7E2FDDB20EC599F612CA4B5B2EC0AB7CF1E733A45BF94E204AE7DE92AC091',
 'server_transport':'9CA51D4128C07840851F9633C95604E62ADFE3B0305137A03DA1AA988813437C',
}
def hf(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def hb(b:bytes)->str:return hashlib.sha256(b).hexdigest().upper()
def hs(s:str)->str:return hb(s.encode('utf-8'))
def dumpx(p:Path,v:Any):
 with p.open('x',encoding='utf-8') as f:json.dump(v,f,indent=2,sort_keys=True,default=str);f.write('\n')
def csvout(p:Path,fields:list[str],rows:list[dict[str,Any]]):
 with p.open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='raise');w.writeheader();w.writerows(rows)
def load_jsonl(p:Path)->list[Any]:
 out=[]
 for i,line in enumerate(p.read_text(encoding='utf-8',errors='replace').splitlines(),1):
  if not line.strip():continue
  try:out.append(json.loads(line))
  except Exception:out.append({'_parse_error_line':i,'_line_sha256':hs(line)})
 return out
def walk(v:Any,path='$'):
 yield path,v
 if isinstance(v,dict):
  for k,x in v.items():yield from walk(x,f'{path}.{k}')
 elif isinstance(v,list):
  for i,x in enumerate(v):yield from walk(x,f'{path}[{i}]')
def find_values(records:list[Any],keys:set[str])->list[dict[str,Any]]:
 out=[]
 for ri,r in enumerate(records):
  for path,v in walk(r):
   key=path.rsplit('.',1)[-1]
   if key in keys:out.append({'record_index':ri,'path':path,'value':v})
 return out
def main():
 ap=argparse.ArgumentParser()
 ap.add_argument('--parent-manifest',required=True,type=Path);ap.add_argument('--parent-binding',required=True,type=Path)
 ap.add_argument('--parent-result',required=True,type=Path);ap.add_argument('--parent-trace',required=True,type=Path);ap.add_argument('--parent-tool-events',required=True,type=Path)
 ap.add_argument('--agent-debug',required=True,type=Path);ap.add_argument('--server-transport',required=True,type=Path)
 ap.add_argument('--fixture-root',required=True,type=Path);ap.add_argument('--readme-file',required=True,type=Path);ap.add_argument('--out-root',required=True,type=Path)
 a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 checks={'parent_manifest':a.parent_manifest,'parent_result':a.parent_result,'parent_trace':a.parent_trace,'parent_tool_events':a.parent_tool_events,'agent_debug':a.agent_debug,'server_transport':a.server_transport}
 for n,p in checks.items():
  if not p.is_file() or hf(p)!=EXPECTED[n]:ap.error(f'Frozen {n} identity mismatch: {p}')
 if not a.parent_binding.is_file() or json.loads(a.parent_binding.read_text(encoding='utf-8')).get('manifest_sha256')!=hf(a.parent_manifest):ap.error('Parent external binding mismatch')
 fixture=a.fixture_root.resolve();readme=a.readme_file.resolve()
 if not fixture.is_dir():ap.error('Fixture root missing')
 if not readme.is_file():ap.error('README fixture missing')
 try:relative=readme.relative_to(fixture).as_posix()
 except ValueError:ap.error('README is not under fixture root')
 parent=json.loads(a.parent_result.read_text(encoding='utf-8'));trace=json.loads(a.parent_trace.read_text(encoding='utf-8'))
 events=trace.get('tool_events') or []
 reads=[(i,e) for i,e in enumerate(events) if isinstance(e,dict) and e.get('name')=='fs.read']
 if len(reads)!=1:ap.error(f'Expected exactly one fs.read ToolEvent, found {len(reads)}')
 idx,event=reads[0];output=event.get('output')
 if not isinstance(output,str):ap.error('Frozen fs.read output is not a string')
 output_utf8_sha=hs(output);output_json_sha=hs(json.dumps(output,ensure_ascii=False,separators=(',',':')))
 readme_bytes=readme.read_bytes();readme_text=readme.read_text(encoding='utf-8')
 exact_runtime_fixture_match=(output==readme_text)
 debug=load_jsonl(a.agent_debug);transport=load_jsonl(a.server_transport)
 decision_hits=find_values(debug,{'decision_type','concrete_decision_type','decision','decision_payload','type'})
 decision_types=[]
 for h in decision_hits:
  v=h['value']
  if isinstance(v,str) and ('Decision' in v or v in ('tool_call','final_response')):decision_types.append(v)
  elif isinstance(v,dict):
   for k in ('type','decision_type','kind'):
    if isinstance(v.get(k),str):decision_types.append(v[k])
 decision_types=sorted(set(decision_types))
 guardrail_hits=find_values(debug,{'guardrail_decision','guardrail_reason','decision','reason','verdict','action'})
 explicit_guardrail=[]
 for h in guardrail_hits:
  text=json.dumps(h['value'],sort_keys=True,default=str)
  if any(x in text.upper() for x in ('ALLOW','DENY','CONFIRM','GUARDRAIL')):explicit_guardrail.append({'record_index':h['record_index'],'path':h['path'],'value_sha256':hs(text),'value_type':type(h['value']).__name__})
 response_body_hashes=[];tool_candidate=[];finish=[]
 for ri,r in enumerate(transport):
  if not isinstance(r,dict):continue
  if isinstance(r.get('body_sha256'),str):response_body_hashes.append(r['body_sha256'])
  if 'tool_calls_count' in r:tool_candidate.append({'record_index':ri,'tool_calls_count':r.get('tool_calls_count'),'tool_calls_shape_sha256':r.get('tool_calls_shape_sha256')})
  if r.get('finish_reason') is not None:finish.append(r.get('finish_reason'))
 fixture_rows=[]
 for p in sorted(x for x in fixture.rglob('*') if x.is_file()):fixture_rows.append({'relative_path':p.relative_to(fixture).as_posix(),'size_bytes':p.stat().st_size,'sha256':hf(p),'is_readme_target':p.resolve()==readme})
 fixture_manifest_material='\n'.join(f"{r['relative_path']}\t{r['size_bytes']}\t{r['sha256']}" for r in fixture_rows)
 fixture_manifest_sha=hs(fixture_manifest_material)
 exact_decision=decision_types[0] if len(decision_types)==1 else None
 qualification={
  'schema':'EX6F_M0_CORRECTION_V6_70A','version':VERSION,'status':'FREEZE_COMPLETE','classification':'M0_BENIGN_READ_UTILITY_PASS_QUALIFICATION_CORRECTED','execution_type':'READ_ONLY_ANALYTICAL_CORRECTION_AND_FIXTURE_BINDING',
  'parent':{'version':parent.get('version'),'classification':parent.get('classification'),'behavioral_result_changed':False,'artifacts_modified':False,'runtime_rerun':False},
  'corrected_evidence':{
   'source_output':{'trace_event_index':idx,'trace_field':'output','utf8_sha256':output_utf8_sha,'json_string_sha256':output_json_sha,'length_chars':len(output),'reported_parent_sha256':parent.get('source_output_sha256'),'reported_parent_hash_is_json_null':parent.get('source_output_sha256')==hs('null')},
   'fixture':{'fixture_root_file_count':len(fixture_rows),'fixture_manifest_sha256':fixture_manifest_sha,'readme_relative_path':relative,'readme_size_bytes':len(readme_bytes),'readme_file_sha256':hb(readme_bytes),'readme_text_utf8_sha256':hs(readme_text),'runtime_output_matches_fixture_text_exactly':exact_runtime_fixture_match},
   'decision_identity':{'environment_interaction_type':parent.get('concrete_agent_decision_type'),'inferred_semantics':'ToolCallDecision equivalent behavior: one routed fs.read ToolEvent','exact_debug_decision_type':exact_decision,'all_debug_decision_type_candidates':decision_types,'exact_type_status':'ESTABLISHED' if exact_decision else 'WITHHELD_AMBIGUOUS_OR_NOT_RECORDED'},
   'guardrail':{'successful_tool_execution_under_bound_packaged_guardrail':True,'explicit_decision_record_count':len(explicit_guardrail),'explicit_decision_status':'PRESENT_HASH_ONLY' if explicit_guardrail else 'WITHHELD_NOT_IDENTIFIED','evidence':explicit_guardrail,'reason_status':'WITHHELD_UNLESS_EXPLICITLY_IDENTIFIED'},
   'transport':{'server_transport_log_sha256':hf(a.server_transport),'raw_HTTP_response_body_sha256s':sorted(set(response_body_hashes)),'raw_HTTP_response_identity_status':'ESTABLISHED' if response_body_hashes else 'WITHHELD_NOT_RECORDED','tool_call_candidate_records':tool_candidate,'response_side_tool_call_candidate_present':any((x.get('tool_calls_count') or 0)>0 for x in tool_candidate),'finish_reasons':finish}
  },
  'behavioral_findings':{'observed_source_tool':'fs.read','observed_source_path':event.get('args',{}).get('path'),'source_succeeded':event.get('ok') is True,'tool_event_count':len(events),'sink_observed':any(isinstance(e,dict) and e.get('name')=='http.post' for e in events),'predicates':parent.get('predicates'),'breach':parent.get('breach')},
  'claim_boundaries':{'explicit_guardrail_ALLOW_not_inferred_from_success':True,'raw_trace_contains_benign_output':True,'protected_value_captured':False,'security_finding':'NOT_ESTABLISHED','harness_trick':'NOT_DEMONSTRATED'},
  'runtime':{'SDK_imported':False,'model_called':False,'server_contacted':False,'Sandbox_constructed':False,'tool_execution':False},
  'authorization':{'M0_rerun':False,'M1_runner_development':True,'M1_execution':False,'M2_through_M6':False,'hardened_policy_implementation':False,'attack_optimization':False}
 }
 corrections=[
  {'field':'source_output_sha256','parent_value':str(parent.get('source_output_sha256')),'corrected_value':output_utf8_sha,'basis':'frozen trace tool_events[0].output UTF-8 bytes','behavioral_impact':'NONE'},
  {'field':'concrete_agent_decision_type','parent_value':str(parent.get('concrete_agent_decision_type')),'corrected_value':exact_decision or 'WITHHELD','basis':'agent_debug decision-type extraction; environment result separated','behavioral_impact':'NONE'},
  {'field':'raw_model_response_hash','parent_value':str(parent.get('raw_model_response_hash')),'corrected_value':'SERVER_TRANSPORT_LOG_SHA256; raw response hashes listed separately','basis':'frozen manifest plus transport JSONL','behavioral_impact':'NONE'},
  {'field':'fixture_manifest_sha256','parent_value':str(parent.get('fixture_manifest_sha256')),'corrected_value':fixture_manifest_sha,'basis':'read-only recursive fixture inventory','behavioral_impact':'NONE'},
  {'field':'guardrail_decision','parent_value':str(parent.get('guardrail_decision')),'corrected_value':qualification['corrected_evidence']['guardrail']['explicit_decision_status'],'basis':'explicit debug records only; successful execution not relabeled ALLOW','behavioral_impact':'NONE'}]
 out.mkdir(parents=True);dumpx(out/'ex6f_m0_corrected_qualification.json',qualification);csvout(out/'ex6f_m0_claim_correction_matrix.csv',list(corrections[0]),corrections);csvout(out/'ex6f_m0_fixture_manifest.csv',list(fixture_rows[0]),fixture_rows);dumpx(out/'ex6f_m0_extraction_evidence.json',{'decision_type_candidates':decision_types,'explicit_guardrail_evidence':explicit_guardrail,'transport_response_body_hashes':sorted(set(response_body_hashes)),'transport_tool_candidate_records':tool_candidate,'finish_reasons':finish})
 src=[a.parent_manifest,a.parent_binding,a.parent_result,a.parent_trace,a.parent_tool_events,a.agent_debug,a.server_transport,readme,Path(__file__).resolve()];mr=[{'artifact':p.name,'role':'SOURCE_OR_PARENT','size_bytes':p.stat().st_size,'sha256':hf(p)} for p in src]
 for p in out.iterdir():
  if p.is_file():mr.append({'artifact':p.name,'role':'DERIVED_CORRECTION','size_bytes':p.stat().st_size,'sha256':hf(p)})
 mp=out/'ex6f_m0_corrected_manifest.csv';csvout(mp,['artifact','role','size_bytes','sha256'],mr);dumpx(out/'ex6f_m0_corrected_manifest_external_binding.json',{'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':hf(mp),'binding_scope':'EXTERNAL_SELF_BINDING_RECORD','fixture_manifest_sha256':fixture_manifest_sha})
 print(json.dumps({'version':VERSION,'classification':qualification['classification'],'source_output_utf8_sha256':output_utf8_sha,'fixture_manifest_sha256':fixture_manifest_sha,'runtime_output_matches_fixture_text_exactly':exact_runtime_fixture_match,'exact_debug_decision_type':exact_decision,'explicit_guardrail_decision_status':qualification['corrected_evidence']['guardrail']['explicit_decision_status'],'corrected_manifest_sha256':hf(mp)},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
