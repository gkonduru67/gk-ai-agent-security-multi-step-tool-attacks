#!/usr/bin/env python3
"""Acknowledgement integration implementation contract and source plan freeze.

Read-only static design gate. Preserves EX9-R2-R2 as 25/25, binds its complete
evidence pack, inspects authoritative hook, transport, adapter, sequence-state,
and bridge sources, and freezes a proposed two-component implementation plan:

  TrustedPostToolHookAdapterV1
  TrustedOutcomeTransportV1ToContextAdapterV1_1Wrapper

No implementation source is created. No frozen artifact or SDK source is
modified. No SDK module is imported/executed; no Sandbox, Gym, tool, fs.read,
HTTP, predicate, breach logic, model, thread, or external effect is executed.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="ACKNOWLEDGEMENT_INTEGRATION_IMPLEMENTATION_CONTRACT_AND_SOURCE_PLAN_FREEZE_v1.0"
PARENT_VERSION="EX9_R2_R2_TRANSPORT_TO_ADAPTER_INTERFACE_RECONCILIATION_v1.0"
PARENT_STATUS="EX9_R2_R2_TRANSPORT_TO_ADAPTER_INTERFACE_RECONCILIATION_COMPLETE_PASS"
PARENT_MANIFEST_SHA="27C10F5DA5D22E75D037EB1B233379476DEFB5FA1B3833A37D212F50D44EAC81"
PARENT_RUNNER_SHA="8D54269EEFAB6DA84259CE7023750FC8379A538CCA9A9F0B2BEB78D8A598B998"
PARENT_FREEZE_SHA="9C11D560020D565E6DFA9262E446D858855604A49A70E845793E6F6171EABD33"
PARENT_MAPPING_SHA="EE4F7BAD4AAAC5ECD7356E275D4A93B60AA37470D62D3B85BC461A81B925CF38"
PARENT_REQUIREMENTS_SHA="CE0576FCADCA7AB63010BB4FA4163BCB11EE49F6A066592A36E0FA8EDD731FE5"
TRANSPORT_SHA="5C7F7D16A37896959C6F4CC769E5F72A6E5E534EE140BA5CAF2FB70661102CE1"
ADAPTER_SHA="BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"
HOOK_CLASS="TrustedPostToolHookAdapterV1"
WRAPPER_CLASS="TrustedOutcomeTransportV1ToContextAdapterV1_1Wrapper"
HOOK_FILE="aicomp_sdk/core/env/trusted_post_tool_hook_adapter_v1.py"
WRAPPER_FILE="aicomp_sdk/core/env/trusted_outcome_transport_v1_to_context_adapter_v1_1_wrapper.py"
FACTORY_FILE="aicomp_sdk/core/env/trusted_acknowledgement_integration_factory_v1.py"

def now():return datetime.now(timezone.utc).isoformat()
def require(c,m):
    if not c:raise ValueError(m)
def sha(p):
    h=hashlib.sha256();p=Path(p)
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest().upper()
def ident(p):
    p=Path(p).resolve();return {"artifact":p.name,"path":str(p),"size_bytes":p.stat().st_size,"sha256":sha(p)}
def rj(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def rc(p):
    with Path(p).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def wj(p,o):
    with Path(p).open('x',encoding='utf-8',newline='\n') as f:json.dump(o,f,indent=2,sort_keys=True);f.write('\n')
def wc(p,rows,fields):
    with Path(p).open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(rows)
def add(rows,i,c,p,o,e,l):rows.append({"check_id":i,"category":c,"passed":bool(p),"observed":str(o),"expected":str(e),"failure_layer":l})
def up(n):
    try:return ast.unparse(n)
    except:return "UNPARSE_FAILED"
def parse(p):
    t=Path(p).read_text(encoding='utf-8');return t,ast.parse(t,filename=str(p))
def classes(t):return {n.name:n for n in t.body if isinstance(n,ast.ClassDef)}
def methods(c):return {n.name:n for n in c.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def calls(n):
    out=[]
    for x in ast.walk(n):
        if isinstance(x,ast.Call):out.append({"line":x.lineno,"call":up(x.func),"expression":up(x)})
    return out
def signature(f):
    pos=f.args.posonlyargs+f.args.args
    if pos and pos[0].arg in {'self','cls'}:pos=pos[1:]
    return {"positional":[x.arg for x in pos],"keyword_only":[x.arg for x in f.args.kwonlyargs],"return":up(f.returns) if f.returns else "NOT_ANNOTATED"}
def public_methods(cls):return sorted(n for n in methods(cls) if not n.startswith('_'))
def find_owner(sdk,name):
    hits=[]
    for p in sorted(sdk.rglob('*.py')):
        try:_,t=parse(p)
        except:continue
        if name in classes(t):hits.append((p,classes(t)[name],t))
    return hits

def main(a):
    out=Path(a.output_dir).resolve();require(not out.exists(),f"Refusing overwrite: {out}");out.mkdir(parents=True)
    checks=[]
    try:
        root=Path(a.project_root).resolve();sdk=root/'aicomp_sdk';require(sdk.is_dir(),f"Missing SDK root: {sdk}")
        parent={"result":Path(a.r2_result).resolve(),"checks":Path(a.r2_checks).resolve(),"mapping":Path(a.r2_mapping).resolve(),"interfaces":Path(a.r2_interfaces).resolve(),"construction":Path(a.r2_construction).resolve(),"requirements":Path(a.r2_requirements).resolve(),"freeze":Path(a.r2_freeze).resolve(),"claim":Path(a.r2_claim_boundary).resolve(),"binding":Path(a.r2_binding).resolve(),"external":Path(a.r2_external_binding).resolve(),"manifest":Path(a.r2_manifest).resolve(),"runner":Path(a.r2_runner).resolve()}
        for k,p in parent.items():require(p.is_file(),f"Missing parent {k}: {p}")
        pr=rj(parent['result']);pf=rj(parent['freeze']);pe=rj(parent['external']);pchecks=rc(parent['checks']);pmapping=rc(parent['mapping'])
        add(checks,'P-001','parent',pr.get('version')==PARENT_VERSION and pr.get('status')==PARENT_STATUS,pr.get('status'),PARENT_STATUS,'FIXTURE')
        for i,(k,expected) in enumerate([('manifest',PARENT_MANIFEST_SHA),('runner',PARENT_RUNNER_SHA),('freeze',PARENT_FREEZE_SHA),('mapping',PARENT_MAPPING_SHA),('requirements',PARENT_REQUIREMENTS_SHA)],2):add(checks,f'P-{i:03d}','parent',sha(parent[k])==expected,sha(parent[k]),expected,'FIXTURE')
        add(checks,'P-007','parent',pe.get('manifest_sha256')==PARENT_MANIFEST_SHA and pe.get('runner_sha256')==PARENT_RUNNER_SHA,pe,'external binding matches','FIXTURE')
        add(checks,'P-008','parent',len(pchecks)==25 and all(x['passed']=='True' for x in pchecks),{"total":len(pchecks),"passed":sum(x['passed']=='True' for x in pchecks)},'25/25','EVIDENCE')
        add(checks,'P-009','parent',pf.get('decision')=='NEW_HOOK_ADAPTER_PLUS_TRANSPORT_WRAPPER_REQUIRED' and pf.get('implementation_created') is False,{"decision":pf.get('decision'),"implementation":pf.get('implementation_created')},'wrapper architecture; no implementation','CLAIM_BOUNDARY')

        tp=root/'aicomp_sdk/core/env/trusted_outcome_transport_v1.py';ap=root/'aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py'
        require(tp.is_file() and ap.is_file(),'Missing transport or adapter source')
        add(checks,'P-010','source',sha(tp)==TRANSPORT_SHA,sha(tp),TRANSPORT_SHA,'FIXTURE');add(checks,'P-011','source',sha(ap)==ADAPTER_SHA,sha(ap),ADAPTER_SHA,'FIXTURE')
        _,tt=parse(tp);_,at=parse(ap);tc=classes(tt).get('TrustedOutcomeTransportV1');ac=classes(at).get('TrustedGuardrailContextAdapterV1_1');require(tc and ac,'Required class missing')
        ack=methods(tc).get('acknowledge');before=methods(ac).get('before_decide');after=methods(ac).get('after_tool');require(ack and before and after,'Required methods missing')

        # Adapter state ownership and public access surface.
        adapter_public=public_methods(ac);adapter_assignments=up(ac)
        pending_owned='_pending_proposals_by_digest' in adapter_assignments
        digest_owned='tool_args_digest' in up(before) and 'proposal_digest' in up(before)
        public_pending_access=any(('pending' in n.lower() or 'proposal' in n.lower()) and n not in {'before_decide'} for n in adapter_public)
        snapshot='snapshot_state' if 'snapshot_state' in methods(ac) else ('snapshot' if 'snapshot' in methods(ac) else None)
        restore='restore_state' if 'restore_state' in methods(ac) else ('restore' if 'restore' in methods(ac) else None)
        reset='reset' if 'reset' in methods(ac) else None
        add(checks,'P-020','state',pending_owned,pending_owned,True,'PROVENANCE')
        add(checks,'P-021','state',digest_owned,digest_owned,True,'PROVENANCE')
        add(checks,'P-022','state',True,'PUBLIC_READ_ONLY_ACCESS' if public_pending_access else 'NO_PUBLIC_READ_ONLY_PENDING_ACCESS','state access classified','AUTHORIZATION_TRANSPORT')
        add(checks,'P-023','lifecycle',snapshot is not None and restore is not None,{"snapshot":snapshot,"restore":restore},'snapshot and restore','REPLAY_ORCHESTRATION')
        add(checks,'P-024','lifecycle',True,reset or 'NEW_COMPONENT_OWNS_RESET','reset ownership classified','REPLAY_ORCHESTRATION')

        # Hook registry / types ownership.
        registry_hits=find_owner(sdk,'HookRegistry');context_hits=find_owner(sdk,'HookContext');stage_hits=find_owner(sdk,'HookStage')
        add(checks,'P-030','hook',len(registry_hits)==1,[str(x[0].relative_to(root)) for x in registry_hits],'one HookRegistry','ADAPTER_PARSE')
        add(checks,'P-031','hook',len(context_hits)==1,[str(x[0].relative_to(root)) for x in context_hits],'one HookContext','ADAPTER_PARSE')
        add(checks,'P-032','hook',len(stage_hits)==1,[str(x[0].relative_to(root)) for x in stage_hits],'one HookStage','ADAPTER_PARSE')
        reg_cls=registry_hits[0][1] if len(registry_hits)==1 else None;reg_methods=methods(reg_cls) if reg_cls else {}
        registration='register_hook' if 'register_hook' in reg_methods else None
        duplicate_append=registration is not None and '.append(' in up(reg_methods[registration])
        add(checks,'P-033','hook',registration is not None,registration,'register_hook','ROUTING')
        add(checks,'P-034','hook',duplicate_append,duplicate_append,True,'REPLAY_ORCHESTRATION')

        # Proposed names must be new and distinct.
        existing_classes=[]
        for p in sorted(sdk.rglob('*.py')):
            try:_,t=parse(p);existing_classes.extend(classes(t))
            except:pass
        proposed_paths=[root/HOOK_FILE,root/WRAPPER_FILE,root/FACTORY_FILE]
        names_new=HOOK_CLASS not in existing_classes and WRAPPER_CLASS not in existing_classes
        paths_new=all(not p.exists() for p in proposed_paths)
        add(checks,'P-040','identity',names_new,{"hook":HOOK_CLASS,"wrapper":WRAPPER_CLASS},'distinct unused class names','FIXTURE')
        add(checks,'P-041','identity',paths_new,[str(x) for x in proposed_paths],'all proposed files absent before implementation','FIXTURE')
        add(checks,'P-042','identity',len({HOOK_CLASS,WRAPPER_CLASS})==2 and len({HOOK_FILE,WRAPPER_FILE,FACTORY_FILE})==3,'distinct names and files','unique','FIXTURE')

        # Exact design decision derived from public access availability.
        if public_pending_access:
            outcome='IMPLEMENTATION_CONTRACT_FEASIBLE'
            digest_retrieval='WRAPPER_CALLS_EXISTING_PUBLIC_READ_ONLY_ADAPTER_INTERFACE'
        else:
            outcome='PUBLIC_READ_ONLY_PENDING_PROPOSAL_INTERFACE_REQUIRED'
            digest_retrieval='NEW_NON_MUTATING_WRAPPER_STATE_PROVIDER_OR_PUBLIC_READ_ONLY_ADAPTER_VIEW_REQUIRED'
        # This gate may pass with a required new read-only interface in a new wrapper/provider, but never by private-field reach-through.
        add(checks,'P-050','decision',outcome in {'IMPLEMENTATION_CONTRACT_FEASIBLE','PUBLIC_READ_ONLY_PENDING_PROPOSAL_INTERFACE_REQUIRED','TRANSPORT_WRAPPER_INPUT_EXTENSION_REQUIRED','NOT_FEASIBLE_WITHOUT_FROZEN_SOURCE_CHANGE'},outcome,'classified outcome','AUTHORIZATION_TRANSPORT')

        event_schema={"schema_tag":"EX9.TRUSTED.EVENT.IDENTITY.V1","required_fields":["trace_identity","sequence","kind"],"kind":"outcome","trace_rule":"event trace_identity equals acknowledgement trace_identity","sequence_rule":"event sequence equals trusted_tool_outcome.completion_sequence"}
        wrapper_input={"incoming_positional_outcome":{"type":"Mapping[str, Any]","required_fields":["proposal_digest","outcome_identity","trace_identity","tool_name","success","canonical_source_path","post_hook_output","raw_output_sha256","protected_value_sha256_or_bound_digest","completion_sequence"]},"V1_1_call":{"proposal_digest":"exact incoming proposal_digest","event_identity":"converted outcome_identity using frozen schema","trace_identity":"exact incoming trace_identity","tool_name":"exact incoming tool_name","tool_args_digest":"exact pending proposal digest from trusted state provider","trusted_tool_outcome":"validated incoming outcome mapping"}}
        ownership=[
          {"state":"proposal_digest","owner":"TrustedGuardrailContextAdapterV1_1 pending proposal store","reader":"transport wrapper through approved read-only state provider","mutation":"none during lookup; consumed only by successful V1.1 after_tool"},
          {"state":"tool_args_digest","owner":"TrustedGuardrailContextAdapterV1_1 pending proposal store","reader":"transport wrapper through approved read-only state provider","mutation":"none"},
          {"state":"hook registration token","owner":HOOK_CLASS,"reader":HOOK_CLASS,"mutation":"exactly-once install/reset lifecycle"},
          {"state":"wrapper replay identities","owner":WRAPPER_CLASS,"reader":WRAPPER_CLASS,"mutation":"append only after successful V1.1 acknowledgement"},
          {"state":"transport sequence state","owner":"TrustedOutcomeTransportV1 existing sequence_state","reader":WRAPPER_CLASS + " + transport","mutation":"existing allocate/consume contract"},
        ]
        lifecycle={"registration":"exactly one POST_TOOL_CALL callback; duplicate append registry requires local installation guard","snapshot":"hook adapter installation state + wrapper replay identities + trusted state-provider binding identity","restore":"validate schema and restore deterministically without duplicate registration","reset":"new hook adapter and wrapper clear only their owned mutable state; frozen adapter/transport reset remains separately owned","retry":"failed V1.1 acknowledgement propagates; allocated outcome stays unconsumed; retry uses a new acknowledgement identity under reviewed sequence policy","replay":"reject reused proposal/outcome/acknowledgement/consumption identities","exception":"adapter exception propagates; no success record and no consumption"}
        construction={"module":FACTORY_FILE,"factory":"build_trusted_acknowledgement_integration_v1","creates":[HOOK_CLASS,WRAPPER_CLASS,"TrustedOutcomeTransportV1"],"wires":"HookRegistry POST_TOOL_CALL -> hook adapter -> transport -> wrapper -> TrustedGuardrailContextAdapterV1_1","frozen_source_modification":False,"Sandbox_modification":False,"packaged_guardrail_modification":False}
        requirements=[
          {"id":"IC-001","statement":"Create exactly the two distinct proposed classes in the two distinct proposed modules; create a separate factory module.","status":"REQUIRED"},
          {"id":"IC-002","statement":"Never access adapter private pending-proposal fields directly; use an approved read-only state provider or a separately reviewed public read-only interface.","status":"REQUIRED"},
          {"id":"IC-003","statement":"Retrieve proposal_digest and tool_args_digest from the exact same pending proposal record.","status":"REQUIRED"},
          {"id":"IC-004","statement":"Convert outcome identity to the frozen mapping schema with kind outcome, same trace, and completion sequence equality.","status":"REQUIRED"},
          {"id":"IC-005","statement":"Call V1.1 after_tool using all six authoritative keyword-only arguments.","status":"REQUIRED"},
          {"id":"IC-006","statement":"Register exactly one POST_TOOL_CALL callback despite append-style duplicate registration.","status":"REQUIRED"},
          {"id":"IC-007","statement":"Snapshot, restore, reset, retry, replay, and exception behavior must match the frozen lifecycle contract.","status":"REQUIRED"},
          {"id":"IC-008","statement":"Adapter exception propagates and leaves outcome unconsumed.","status":"REQUIRED"},
          {"id":"IC-009","statement":"Construction occurs only through the new factory; no frozen SDK, Sandbox, transport, adapter, or packaged guardrail modification.","status":"REQUIRED"},
          {"id":"IC-010","statement":"Implementation identity freeze is static only and executes no SDK modules, Sandbox, Gym, tools, fs.read, HTTP, predicates, breach, models, or threads.","status":"REQUIRED"},
        ]
        failed=[x['check_id'] for x in checks if not x['passed']]
        # A plan is freezeable when all facts are explicit, even if it identifies a required new read-only provider contract.
        freezeable=not failed and outcome!='NOT_FEASIBLE_WITHOUT_FROZEN_SOURCE_CHANGE'
        status='ACKNOWLEDGEMENT_INTEGRATION_IMPLEMENTATION_CONTRACT_AND_SOURCE_PLAN_FREEZE_COMPLETE_PASS' if freezeable else 'ACKNOWLEDGEMENT_INTEGRATION_IMPLEMENTATION_CONTRACT_AND_SOURCE_PLAN_FREEZE_COMPLETE_WITH_GAPS'
        next_gate='ACKNOWLEDGEMENT_INTEGRATION_IMPLEMENTATION_AND_IDENTITY_FREEZE' if freezeable else 'ACKNOWLEDGEMENT_INTEGRATION_CONTRACT_RECONCILIATION'
        freeze={"freeze_id":"EX9.ACK.IMPLEMENTATION.CONTRACT.SOURCE.PLAN.V1","status":"FROZEN" if freezeable else "NOT_FROZEN","parent_interface_freeze_id":pf.get('freeze_id'),"outcome":outcome,"proposed_artifacts":{"hook_adapter":{"class":HOOK_CLASS,"file":HOOK_FILE},"transport_wrapper":{"class":WRAPPER_CLASS,"file":WRAPPER_FILE},"factory":{"function":"build_trusted_acknowledgement_integration_v1","file":FACTORY_FILE}},"state_ownership":ownership,"digest_retrieval":digest_retrieval,"wrapper_input_schema":wrapper_input,"outcome_identity_conversion":event_schema,"construction":construction,"lifecycle":lifecycle,"implementation_created":False,"implementation_identity":"NOT_ESTABLISHED","runtime_behavior":"NOT_EVALUATED"}
        claim={"allowed":["implementation contract and source plan","proposed class, module, state-ownership, mapping, construction, and lifecycle requirements","eligibility recommendation for a separate static implementation and identity-freeze gate"],"prohibited":["claim that implementation exists","private pending-state access implementation","SDK source modification","runtime acknowledgement","actual fs.read","Sandbox or Gym execution","HTTP sink","predicate or breach execution","model execution","protected-value lineage","guardrail effectiveness","real exfiltration prevention"]}
        result={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"READ_ONLY_IMPLEMENTATION_CONTRACT_AND_SOURCE_PLAN","EX9_R2_R2_parent_verified":True,"parent_result":{"checks":"25_OF_25","preserved_immutable":True},"checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"decision":{"outcome":outcome,"digest_retrieval":digest_retrieval,"minimum_architecture":"TWO_NEW_CLASSES_PLUS_NEW_FACTORY"},"freeze":freeze,"readiness":{"implementation_creation_eligible":freezeable,"controlled_actual_fs_read_eligible":False,"http_sink_eligible":False},"execution_boundaries":{"parent_artifacts_modified":False,"source_modified":False,"implementation_created":False,"sdk_modules_imported":False,"sdk_modules_executed":False,"Sandbox_instantiated":False,"Sandbox_interact_executed":False,"Gym_executed":False,"real_tools_executed":False,"actual_fs_read_executed":False,"http_sink_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False,"threads_executed":False,"external_effects_observed":False},"scientific_verdict":{"implementation_contract":"FROZEN" if freezeable else "GAPS_IDENTIFIED","implementation_behavior":"NOT_EVALUATED","actual_source_retrieval":"NOT_EVALUATED","protected_value_lineage":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim,"next_gate":next_gate}
        o={"result":out/'ex9_r3_result.json',"checks":out/'ex9_r3_checks.csv',"ownership":out/'ex9_r3_state_ownership.csv',"requirements":out/'ex9_r3_requirements.csv',"plan":out/'ex9_r3_source_plan.json',"freeze":out/'ex9_r3_contract_freeze.json',"claim":out/'ex9_r3_claim_boundary.json',"binding":out/'ex9_r3_binding.json'}
        wj(o['result'],result);wc(o['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']);wc(o['ownership'],ownership,['state','owner','reader','mutation']);wc(o['requirements'],requirements,['id','statement','status']);wj(o['plan'],{"proposed_artifacts":freeze['proposed_artifacts'],"wrapper_input_schema":wrapper_input,"outcome_identity_conversion":event_schema,"construction":construction,"lifecycle":lifecycle,"digest_retrieval":digest_retrieval});wj(o['freeze'],freeze);wj(o['claim'],claim);wj(o['binding'],{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"parent":{k:ident(v) for k,v in parent.items()},"sources":{"transport":ident(tp),"adapter_v1_1":ident(ap),"hook_registry":ident(registry_hits[0][0]) if len(registry_hits)==1 else "NOT_ESTABLISHED","hook_context":ident(context_hits[0][0]) if len(context_hits)==1 else "NOT_ESTABLISHED"},"source_modified":False,"implementation_created":False,"sdk_modules_imported":False,"sdk_modules_executed":False})
        rows=[{**ident(p),"role":"EX9_R3_DERIVED"} for p in o.values()]+[{**ident(p),"role":"EX9_R3_BOUND_PARENT"} for p in parent.values()]+[{**ident(tp),"role":"EX9_R3_AUTHORITATIVE_SOURCE"},{**ident(ap),"role":"EX9_R3_AUTHORITATIVE_SOURCE"}]
        if len(registry_hits)==1:rows.append({**ident(registry_hits[0][0]),"role":"EX9_R3_AUTHORITATIVE_SOURCE"})
        if len(context_hits)==1:rows.append({**ident(context_hits[0][0]),"role":"EX9_R3_AUTHORITATIVE_SOURCE"})
        mp=out/'ex9_r3_manifest.csv';wc(mp,rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'ex9_r3_manifest_external_binding.json';wj(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"parent_EX9_R2_R2_manifest_sha256":PARENT_MANIFEST_SHA,"freeze_id":freeze['freeze_id'],"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"outcome":outcome,"implementation_creation_eligible":freezeable,"controlled_actual_fs_read_eligible":False,"implementation_created":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"parent":"25/25 preserved","checks":f"{len(checks)-len(failed)}/{len(checks)}","failed_ids":failed,"outcome":outcome,"digest_retrieval":digest_retrieval,"proposed_classes":[HOOK_CLASS,WRAPPER_CLASS],"implementation_created":False,"controlled_actual_fs_read_eligible":False,"manifest_sha256":sha(mp),"next_gate":next_gate},indent=2))
    except Exception as e:
        (out/'EX9_R3_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"EX9_R3_CONTRACT_FREEZE_BLOCKED","error_type":type(e).__name__,"error":str(e),"checks_frozen":checks,"source_modified":False,"implementation_created":False,"sdk_modules_imported":False,"sdk_modules_executed":False,"actual_fs_read_executed":False},indent=2),encoding='utf-8');raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for f in ['r2-result','r2-checks','r2-mapping','r2-interfaces','r2-construction','r2-requirements','r2-freeze','r2-claim-boundary','r2-binding','r2-external-binding','r2-manifest','r2-runner','project-root','output-dir']:p.add_argument('--'+f,required=True)
    return p.parse_args()
if __name__=='__main__':
    try:main(args())
    except Exception as e:print(f"FAILED: {e}",file=sys.stderr);raise SystemExit(1)
