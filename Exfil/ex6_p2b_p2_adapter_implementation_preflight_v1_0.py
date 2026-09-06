#!/usr/bin/env python3
"""EX6 P2B P2 adapter implementation preflight.

Read-only with respect to all parent, SDK, and frozen-policy artifacts. This
runner freezes implementation-specific decisions and a non-overwriting source
plan for TrustedGuardrailContextAdapter. It does not create adapter source,
import the SDK, execute guardrails/Sandbox/Gym/tools/models/predicates/breach,
or claim runtime compatibility, requirement satisfaction, or security efficacy.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, re, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2_ADAPTER_IMPLEMENTATION_PREFLIGHT_v1.0"
PARENT_VERSION="EX6_P2B_P1A_INDEPENDENT_DESIGN_QUALIFICATION_v1.0"
STATUS="P2B_P2_ADAPTER_IMPLEMENTATION_PREFLIGHT_COMPLETE_PASS"
EXPECTED_PARENT_MANIFEST="0D29F8DF855E6D400C800EB9900E1D491A505AE75556A8614C5745489AD1DF7C"
EXPECTED_P1_DESIGN="897C48C1DA8C995A88AFA809E4F59723A7B53B17E9BC7724DF358A9B87089F60"
REQ_IDS=[f"AZ-{i:03d}" for i in range(1,8)]+[f"PV-{i:03d}" for i in range(2,5)]
FROZEN_FILES={"optimal":"optimal.py","proposal_aware":"proposal_aware_optimal.py"}
ALLOWED=[
 "P1A identity verification","frozen-source identity verification",
 "implementation-specific decision freeze","static SDK integration inventory",
 "non-overwriting source implementation plan","P2 source-creation eligibility recommendation",
]
PROHIBITED=[
 "adapter implementation exists","adapter imports successfully","runtime compatibility",
 "deferred requirement satisfaction","guardrail effectiveness","security improvement",
 "policy superiority","real exfiltration prevention","Sandbox parity","Gym parity",
 "hosted parity","attack success reduction",
]

def now(): return datetime.now(timezone.utc).isoformat()
def req(c:bool,m:str):
 if not c: raise ValueError(m)
def sha(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def ident(p:Path)->dict[str,Any]:
 return {"artifact":p.name,"path":str(p.resolve()),"size_bytes":p.stat().st_size,"sha256":sha(p)}
def loadj(p:Path):return json.loads(p.read_text(encoding='utf-8-sig'))
def loadcsv(p:Path)->list[dict[str,str]]:
 with p.open('r',encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def dumpx(p:Path,x:Any):
 with p.open('x',encoding='utf-8',newline='\n') as f:json.dump(x,f,indent=2,sort_keys=True);f.write('\n')
def csvx(p:Path,rows:list[dict[str,Any]],fields:list[str]):
 with p.open('x',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(rows)

def verify_parent(paths:dict[str,Path])->dict[str,Any]:
 ext=loadj(paths['p1a_external_binding']);result=loadj(paths['p1a_result'])
 req(ext.get('version')==PARENT_VERSION,'Unexpected P1A external-binding version')
 req(ext.get('status')=='P2B_P1A_INDEPENDENT_DESIGN_QUALIFICATION_COMPLETE_PASS','P1A status is not PASS')
 req(ext.get('manifest_filename')==paths['p1a_manifest'].name,'P1A manifest filename mismatch')
 req(ext.get('manifest_sha256')==sha(paths['p1a_manifest']),'P1A manifest SHA mismatch')
 req(sha(paths['p1a_manifest'])==EXPECTED_PARENT_MANIFEST,'P1A manifest differs from reviewed authority')
 req(int(ext.get('manifest_size_bytes',-1))==paths['p1a_manifest'].stat().st_size,'P1A manifest size mismatch')
 req(ext.get('adapter_created') is False and ext.get('requirements_satisfied') is False,'P1A crossed implementation boundary')
 req(result.get('version')==PARENT_VERSION and result.get('P1_parent_verified') is True,'P1A result identity/status mismatch')
 req(result.get('next_gate')=='EX6_P2B_P2_ADAPTER_IMPLEMENTATION_PREFLIGHT','P1A next gate differs')
 req(result.get('design_recomputation',{}).get('checks_passed')==17,'P1A design checks not 17/17')
 req(result.get('mapping_recomputation',{}).get('qualified')==10,'P1A requirement rows not 10/10')
 req(result.get('mapping_recomputation',{}).get('implemented')==0,'P1A says implementation exists')
 req(len(result.get('unresolved_design_decisions',[]))==6,'P1A unresolved decision count differs')
 req(sha(paths['p1_design_contract'])==EXPECTED_P1_DESIGN,'P1 design contract differs from reviewed authority')
 return result

def inspect_source(label:str,p:Path)->tuple[dict[str,Any],list[dict[str,Any]],str]:
 text=p.read_text(encoding='utf-8-sig');tree=ast.parse(text,filename=str(p));rows=[]
 for n in ast.walk(tree):
  if isinstance(n,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)):
   seg=ast.get_source_segment(text,n) or ast.unparse(n)
   rows.append({"source":label,"symbol":n.name,"kind":"class" if isinstance(n,ast.ClassDef) else "function","line_start":n.lineno,"line_end":getattr(n,'end_lineno',n.lineno),"block_sha256":hashlib.sha256(seg.encode()).hexdigest().upper()})
 return {**ident(p),"label":label,"ast_parse":"PASS","symbol_count":len(rows)},rows,text

def integration_inventory(texts:dict[str,str],symbols:list[dict[str,Any]])->dict[str,Any]:
 names={(r['source'],r['symbol']) for r in symbols}
 checks={
  "guardrail_decide_declared":('guardrail_base','decide') in names,
  "guardrail_snapshot_declared":('guardrail_base','snapshot_state') in names,
  "guardrail_restore_declared":('guardrail_base','restore_state') in names,
  "sandbox_interact_declared":('sandbox','interact') in names,
  "sandbox_guardrail_snapshot_helper":('sandbox','_snapshot_guardrail_state') in names,
  "sandbox_guardrail_restore_helper":('sandbox','_restore_guardrail_state') in names,
  "api_interact_declared":('api','interact') in names,
  "literal_before_decide_in_sdk":any('before_decide' in texts[k] for k in ('sandbox','guardrail_base','api')),
  "literal_after_tool_in_sdk":any('after_tool' in texts[k] for k in ('sandbox','guardrail_base','api')),
 }
 req(all(checks[k] for k in ('guardrail_decide_declared','guardrail_snapshot_declared','guardrail_restore_declared','sandbox_interact_declared','sandbox_guardrail_snapshot_helper','sandbox_guardrail_restore_helper','api_interact_declared')),'Required static lifecycle interface absent')
 return {"checks":checks,
  "conclusion":"WRAPPER_LIFECYCLE_STATICALLY_AVAILABLE_BUT_TRUSTED_CHANNEL_RUNTIME_INTEGRATION_NOT_ESTABLISHED",
  "implementation_boundary":"Adapter source will expose explicit trusted before_decide and after_tool methods plus GuardrailBase-compatible decide/snapshot_state/restore_state. No claim is made that current Sandbox invokes the new trusted methods.",
  "sandbox_modification_plan":"NONE_IN_P2_SOURCE_CREATION; integration adapter/harness changes require a later separately frozen gate if static SDK calls do not expose trusted channels."}

def decisions()->dict[str,Any]:
 return {
  "trusted_issuer_boundary":{
   "decision":"EXPLICIT_CONSTRUCTOR_CONFIGURED_ISSUER_REGISTRY",
   "issuer_identity":"immutable issuer_id plus issuer_trust_domain",
   "grant_creation_api":"register_trusted_grant(record, issuer_capability)",
   "capability_rule":"issuer capability is provided out-of-band by the trusted host and is never serialized into agent-visible context or snapshots",
   "prohibited_sources":["model output","prompt content","generic context dictionaries","arbitrary hook metadata","recent_sources-only labels"],
   "unknown_or_mismatched_issuer":"FAIL_CLOSED"},
  "canonical_serialization":{
   "decision":"CANONICAL_JSON_V1",
   "schema_tag":"aicomp.trusted-context.v1","character_encoding":"UTF-8","normalization":"Unicode NFC for strings","object_key_order":"lexicographic Unicode code-point order","array_order":"preserved","whitespace":"none","separators":[",",":"],"booleans_and_null":"lowercase JSON tokens","integers":"base-10, no leading plus or leading zeros except zero","floating_point":"PROHIBITED_FAIL_CLOSED","duplicate_object_keys":"PROHIBITED_FAIL_CLOSED","non_finite_numbers":"PROHIBITED_FAIL_CLOSED","unsupported_values":"PROHIBITED_FAIL_CLOSED","digest":"SHA-256 over exact UTF-8 bytes"},
  "event_identity_authority":{
   "decision":"TRUSTED_EXECUTION_BOUNDARY_ASSIGNS_TRACE_SCOPED_SEQUENCE",
   "identity_fields":["trace_identity","event_sequence","event_kind"],
   "uniqueness":"trace_identity plus strictly increasing non-negative integer event_sequence",
   "adapter_behavior":["reject duplicates","reject unknown identities","reject out-of-order acknowledgement","reject cross-trace reuse","do not derive event identity from agent prose"]},
  "grant_consumption":{
   "decision":"CONSUME_AT_AUTHORIZATION_RELEASE_BEFORE_TOOL_EXECUTION",
   "trigger":"correctly bound protected action is released as allowed by adapter",
   "restore_after_failure":False,"restore_after_timeout":False,"restore_after_downstream_error":False,
   "rationale":"fail-closed replay resistance; benign retry impact remains a future measured trade-off"},
  "protected_value_derivation":{
   "decision":"TRUSTED_RUNTIME_COMPARISON_WITH_REDACTED_EVIDENCE",
   "runtime_provenance":"trusted after_tool record binds fs.read success, canonical source path, trace identity, event identity, raw output bytes, and output digest",
   "derivation_check":"runtime component compares candidate sink payload/officially normalized candidate with the protected read value according to a separately frozen matcher contract",
   "evidence_artifacts":["source event identity","sink proposal digest","protected value SHA-256","raw sink payload SHA-256","derivation classification"],
   "publication":"no raw protected value","boundary":"hash equality alone does not establish provenance or derivation"},
  "integration":{
   "decision":"STANDALONE_GUARDRAIL_WRAPPER_WITH_EXPLICIT_TRUSTED_CHANNEL_API",
   "frozen_source_edits":False,"sandbox_edit_in_P2":False,
   "runtime_integration":"WITHHELD_TO_SEPARATE_INTEGRATION_AND_PARITY_GATE"},
 }

def implementation_plan()->dict[str,Any]:
 return {
  "source_file":"aicomp_sdk/guardrails/trusted_context_adapter.py","class":"TrustedGuardrailContextAdapter","must_not_exist_before_creation":True,
  "frozen_files_not_modified":["aicomp_sdk/guardrails/optimal.py","aicomp_sdk/guardrails/proposal_aware_optimal.py"],
  "planned_public_methods":["__init__","register_trusted_grant","before_decide","decide","after_tool","snapshot_state","restore_state","reset_state"],
  "planned_private_helpers":["_canonicalize_v1","_digest_v1","_validate_grant","_validate_event_identity","_qualify_protected_read","_consume_grant","_validate_snapshot"],
  "source_creation_gate":"P2_SOURCE_IMPLEMENTATION_AFTER_PREFLIGHT_FREEZE_AND_REVIEW",
  "runtime_execution_in_source_creation_gate":False,
 }

def requirement_plan()->list[dict[str,Any]]:
 mapping={
  'AZ-001':('trusted issuer registry and grant validation','register_trusted_grant; _validate_grant'),
  'AZ-002':('tool/target/proposal binding','before_decide; decide'),
  'AZ-003':('canonical JSON v1 digest','_canonicalize_v1; _digest_v1'),
  'AZ-004':('trace-scoped event identity','_validate_event_identity; after_tool'),
  'AZ-005':('one-use consumption and replay rejection','_consume_grant; before_decide'),
  'AZ-006':('trusted context enrichment and single delegation','before_decide; decide'),
  'AZ-007':('deterministic lifecycle state','snapshot_state; restore_state; reset_state'),
  'PV-002':('successful protected read record','after_tool; _qualify_protected_read'),
  'PV-003':('trusted tool outcome acknowledgement','after_tool'),
  'PV-004':('read-to-sink derivation evidence boundary','before_decide; protected-value derivation helper to be frozen separately'),
 }
 return [{"requirement_id":rid,"planned_behavior":mapping[rid][0],"planned_source_symbols":mapping[rid][1],"implemented":False,"runtime_validated":False,"satisfied":False,"claim_boundary":"implementation plan only"} for rid in REQ_IDS]

def main(a):
 out=Path(a.output_dir).resolve();req(not out.exists(),f'Refusing overwrite: {out}');out.mkdir(parents=True)
 try:
  keys=('p1a_manifest','p1a_external_binding','p1a_result','p1a_design_checks','p1a_requirement_qualification','p1_design_contract','sandbox','guardrail_base','api','optimal','proposal_aware')
  paths={k:Path(getattr(a,k)).resolve() for k in keys}
  for k,p in paths.items():req(p.is_file(),f'Missing {k}: {p}')
  p1a=verify_parent(paths)
  req(len(loadcsv(paths['p1a_design_checks']))==17,'P1A design-check row count differs')
  req(len(loadcsv(paths['p1a_requirement_qualification']))==10,'P1A requirement row count differs')
  source_info=[];blocks=[];texts={}
  for label in ('sandbox','guardrail_base','api','optimal','proposal_aware'):
   info,rows,text=inspect_source(label,paths[label]);source_info.append(info);blocks+=rows;texts[label]=text
  req(paths['optimal'].name==FROZEN_FILES['optimal'] and paths['proposal_aware'].name==FROZEN_FILES['proposal_aware'],'Frozen policy filenames differ')
  integ=integration_inventory(texts,blocks);decs=decisions();plan=implementation_plan();rplan=requirement_plan()
  result={"version":VERSION,"created_at_utc":now(),"status":STATUS,"classification":"READ_ONLY_IMPLEMENTATION_DECISION_AND_INTERFACE_PREFLIGHT",
   "P1A_parent_verified":True,"source_artifacts_modified":False,"adapter_source_created":False,"sdk_source_inventory":source_info,
   "implementation_decisions":decs,"integration_map":integ,"implementation_plan":plan,
   "requirement_plan_summary":{"total":10,"planned":10,"implemented":0,"runtime_validated":0,"satisfied":0},
   "all_six_implementation_decisions_frozen":True,"implementation_plan_distinct_and_non_overwriting":True,
   "implementation_eligibility":"ELIGIBLE_FOR_P2_ADAPTER_SOURCE_CREATION_AFTER_PREFLIGHT_REVIEW",
   "execution_boundaries":{"adapter_created":False,"sdk_imported":False,"guardrail_executed":False,"sandbox_executed":False,"gym_executed":False,"tools_executed":False,"predicates_executed":False,"breach_executed":False,"effects_observed":False},
   "claim_boundary":{"allowed":ALLOWED,"prohibited":PROHIBITED},"next_gate":"EX6_P2B_P2A_ADAPTER_SOURCE_IMPLEMENTATION"}
  rp=out/'ex6_p2b_p2_preflight_result.json';dp=out/'ex6_p2b_p2_frozen_implementation_decisions.json';ip=out/'ex6_p2b_p2_integration_map.json';pp=out/'ex6_p2b_p2_implementation_plan.json';mp=out/'ex6_p2b_p2_requirement_plan.csv';sp=out/'ex6_p2b_p2_source_blocks.csv';cp=out/'ex6_p2b_p2_claim_boundary.json';bp=out/'ex6_p2b_p2_binding.json'
  dumpx(rp,result);dumpx(dp,decs);dumpx(ip,integ);dumpx(pp,plan);csvx(mp,rplan,['requirement_id','planned_behavior','planned_source_symbols','implemented','runtime_validated','satisfied','claim_boundary']);csvx(sp,blocks,['source','symbol','kind','line_start','line_end','block_sha256']);dumpx(cp,result['claim_boundary']);dumpx(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{k:ident(v) for k,v in paths.items()},"source_artifacts_modified":False,"adapter_source_created":False})
  content=[rp,dp,ip,pp,mp,sp,cp,bp];rows=[]
  for p in content:rows.append({**ident(p),'role':'P2B_P2_PREFLIGHT_DERIVED'})
  for k,p in paths.items():rows.append({**ident(p),'role':'P2B_P2_PREFLIGHT_BOUND_'+k.upper()})
  man=out/'ex6_p2b_p2_preflight_manifest.csv';csvx(man,rows,['artifact','role','size_bytes','sha256','path'])
  ext=out/'ex6_p2b_p2_preflight_manifest_external_binding.json';dumpx(ext,{"version":VERSION,"created_at_utc":now(),"status":STATUS,"manifest_filename":man.name,"manifest_size_bytes":man.stat().st_size,"manifest_sha256":sha(man),"runner_sha256":sha(Path(__file__).resolve()),"adapter_source_created":False,"requirements_satisfied":False,"next_gate":result['next_gate']})
  print(json.dumps({"status":STATUS,"manifest_sha256":sha(man),"decisions_frozen":6,"adapter_source_created":False,"requirements_satisfied":False,"integration_conclusion":integ['conclusion'],"next_gate":result['next_gate']},indent=2))
 except Exception:
  (out/'P2B_P2_PREFLIGHT_FAILED.txt').write_text('P2B P2 preflight failed. No implementation-ready, adapter-created, compatibility, effectiveness, or superiority claim is allowed.\n',encoding='utf-8')
  raise

def args():
 p=argparse.ArgumentParser(description=VERSION)
 for x in ('p1a-manifest','p1a-external-binding','p1a-result','p1a-design-checks','p1a-requirement-qualification','p1-design-contract','sandbox','guardrail-base','api','optimal','proposal-aware','output-dir'):
  p.add_argument('--'+x,required=True,dest=x.replace('-','_'))
 return p.parse_args()
if __name__=='__main__':
 try:main(args())
 except Exception as e:print(f'FAILED: {e}',file=sys.stderr);raise SystemExit(1)
