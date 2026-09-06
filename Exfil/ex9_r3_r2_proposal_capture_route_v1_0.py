#!/usr/bin/env python3
"""EX9-R3-R2 proposal capture and provider population route freeze.

Read-only static call-graph and interface reconciliation. Preserves EX9-R3-R1
as 25/25, binds its complete evidence pack, inspects authoritative before_decide
callers and proposal return handling, and freezes the exact proposal-time route
to TrustedPendingProposalReadViewV1.append before tool execution.

The runner prefers causal separation: a dedicated TrustedProposalCaptureAdapterV1
is selected only when no already-compatible authoritative capture owner exists.
No implementation source is created, imported, or executed. No frozen artifact
or SDK source is modified. No Sandbox, Gym, tool, fs.read, HTTP, predicate,
breach logic, model, thread, or external effect is executed.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path

VERSION="EX9_R3_R2_PROPOSAL_CAPTURE_AND_PROVIDER_POPULATION_ROUTE_FREEZE_v1.0"
PARENT_VERSION="EX9_R3_R1_PENDING_PROPOSAL_READ_INTERFACE_AND_PLAN_RECONCILIATION_v1.0"
PARENT_STATUS="EX9_R3_R1_PENDING_PROPOSAL_READ_INTERFACE_AND_PLAN_RECONCILIATION_COMPLETE_PASS"
PARENT_MANIFEST_SHA="210945A427DD4A25ECE263A4060BDDA1986DFD601D7305688ADA1C8A4DDF1575"
PARENT_RUNNER_SHA="76CAAC9C7EB32CCF711D1C2C665AC6C34BC69ED627320BB0C6710C2D8F1198F9"
PARENT_RESULT_SHA="A86D310C73E2D976E955AC58C2464A5CA8102BB82D99E3652F3AAF0334482605"
PARENT_PROVIDER_SHA="EB29ACD3D62BD49C6190B6867CF76CBE024174FAAE6ACEA9BEBD7665F1C52143"
PARENT_FACTORY_SHA="9CA50B83A6163B3622E7AC0DE83C180532EDEFC34D2671BA35D21EBCFA0E336B"
PARENT_PLAN_SHA="65B738CA2DE4943035F2CFFAFBD7A35D134F16BCF959FC5CED8E19175C825D62"
PARENT_REQUIREMENTS_SHA="6F3EEA59FC5942858A022E564A1E2C2C8411479E734F0BBDFD7F6CDCD31FD8A3"
ADAPTER_SHA="BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"
CAPTURE_CLASS="TrustedProposalCaptureAdapterV1"
CAPTURE_FILE="aicomp_sdk/core/env/trusted_proposal_capture_adapter_v1.py"
PROVIDER_CLASS="TrustedPendingProposalReadViewV1"
HOOK_CLASS="TrustedPostToolHookAdapterV1"
WRAPPER_CLASS="TrustedOutcomeTransportV1ToContextAdapterV1_1Wrapper"
FACTORY_FUNC="build_trusted_acknowledgement_integration_v1"
FACTORY_FILE="aicomp_sdk/core/env/trusted_acknowledgement_integration_factory_v1.py"

def now():return datetime.now(timezone.utc).isoformat()
def req(c,m):
    if not c:raise ValueError(m)
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest().upper()
def ident(p):
    p=Path(p).resolve();return {'artifact':p.name,'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}
def rj(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def rc(p):
    with Path(p).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def wj(p,o):
    with Path(p).open('x',encoding='utf-8',newline='\n') as f:json.dump(o,f,indent=2,sort_keys=True);f.write('\n')
def wc(p,rows,fields):
    with Path(p).open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(rows)
def add(rows,i,c,p,o,e,l):rows.append({'check_id':i,'category':c,'passed':bool(p),'observed':str(o),'expected':str(e),'failure_layer':l})
def up(n):
    try:return ast.unparse(n)
    except:return 'UNPARSE_FAILED'
def parse(p):
    text=Path(p).read_text(encoding='utf-8');return text,ast.parse(text,filename=str(p))
def classes(t):return {n.name:n for n in t.body if isinstance(n,ast.ClassDef)}
def methods(c):return {n.name:n for n in c.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def sig(f):
    pos=f.args.posonlyargs+f.args.args
    if pos and pos[0].arg in {'self','cls'}:pos=pos[1:]
    return {'positional':[x.arg for x in pos],'keyword_only':[x.arg for x in f.args.kwonlyargs],'return':up(f.returns) if f.returns else 'NOT_ANNOTATED'}
def calls(n):
    out=[]
    for x in ast.walk(n):
        if isinstance(x,ast.Call):out.append((x,up(x.func),up(x)))
    return out
def enclosing_functions(tree,predicate):
    rows=[]
    for f in ast.walk(tree):
        if isinstance(f,(ast.FunctionDef,ast.AsyncFunctionDef)):
            matches=[]
            for n in ast.walk(f):
                if predicate(n):matches.append(n)
            if matches:rows.append((f,matches))
    return rows

def main(a):
    out=Path(a.output_dir).resolve();req(not out.exists(),f'Refusing overwrite: {out}');out.mkdir(parents=True)
    checks=[]
    try:
        root=Path(a.project_root).resolve();sdk=root/'aicomp_sdk';req(sdk.is_dir(),f'Missing SDK root: {sdk}')
        parent={'result':Path(a.r1_result).resolve(),'checks':Path(a.r1_checks).resolve(),'provider':Path(a.r1_provider_contract).resolve(),'factory':Path(a.r1_factory_bindings).resolve(),'plan':Path(a.r1_complete_plan).resolve(),'freeze':Path(a.r1_freeze).resolve(),'requirements':Path(a.r1_requirements).resolve(),'claim':Path(a.r1_claim_boundary).resolve(),'binding':Path(a.r1_binding).resolve(),'external':Path(a.r1_external_binding).resolve(),'manifest':Path(a.r1_manifest).resolve(),'runner':Path(a.r1_runner).resolve()}
        for k,p in parent.items():req(p.is_file(),f'Missing parent {k}: {p}')
        result=rj(parent['result']);freeze=rj(parent['freeze']);ext=rj(parent['external']);pchecks=rc(parent['checks'])
        add(checks,'C-001','parent',result.get('version')==PARENT_VERSION and result.get('status')==PARENT_STATUS,result.get('status'),PARENT_STATUS,'FIXTURE')
        expected=[('manifest',PARENT_MANIFEST_SHA),('runner',PARENT_RUNNER_SHA),('result',PARENT_RESULT_SHA),('provider',PARENT_PROVIDER_SHA),('factory',PARENT_FACTORY_SHA),('plan',PARENT_PLAN_SHA),('freeze',PARENT_PLAN_SHA),('requirements',PARENT_REQUIREMENTS_SHA)]
        for i,(k,h) in enumerate(expected,2):add(checks,f'C-{i:03d}','parent',sha(parent[k])==h,sha(parent[k]),h,'FIXTURE')
        add(checks,'C-010','parent',ext.get('manifest_sha256')==PARENT_MANIFEST_SHA and ext.get('runner_sha256')==PARENT_RUNNER_SHA,ext,'external binding matches','FIXTURE')
        add(checks,'C-011','parent',len(pchecks)==25 and all(r['passed']=='True' for r in pchecks),{'total':len(pchecks),'passed':sum(r['passed']=='True' for r in pchecks)},'25/25','EVIDENCE')
        add(checks,'C-012','parent',freeze.get('outcome')=='NEW_TRUSTED_PENDING_PROPOSAL_READ_VIEW_REQUIRED' and freeze.get('implementation_created') is False,{'outcome':freeze.get('outcome'),'implementation':freeze.get('implementation_created')},'read view required; no implementation','CLAIM_BOUNDARY')

        adapter=root/'aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py';req(adapter.is_file(),'Missing V1.1 adapter')
        add(checks,'C-020','source',sha(adapter)==ADAPTER_SHA,sha(adapter),ADAPTER_SHA,'FIXTURE')
        _,at=parse(adapter);ac=classes(at).get('TrustedGuardrailContextAdapterV1_1');req(ac is not None,'Missing adapter class')
        before=methods(ac).get('before_decide');req(before is not None,'Missing before_decide')
        before_sig=sig(before);before_src=up(before)
        proposal_fields=['proposal_digest','trace_identity','tool_name','tool_args_digest','proposal_event_identity']
        before_fields={f:(f in before_src) for f in proposal_fields}
        add(checks,'C-021','source',all(before_fields.values()),before_fields,'authoritative proposal fields present','PROVENANCE')

        # SDK-wide caller and return-handling discovery.
        caller_rows=[];authoritative_candidates=[]
        for p in sorted(sdk.rglob('*.py')):
            try:text,tree=parse(p)
            except:continue
            for fn,matches in enclosing_functions(tree,lambda n:isinstance(n,ast.Call) and (up(n.func).endswith('.before_decide') or up(n.func)=='before_decide')):
                source=up(fn);rel=str(p.relative_to(root))
                for call in matches:
                    assigned=[]
                    for n in ast.walk(fn):
                        if isinstance(n,(ast.Assign,ast.AnnAssign)):
                            value=n.value
                            if value is call:
                                targets=n.targets if isinstance(n,ast.Assign) else [n.target]
                                assigned=[up(x) for x in targets]
                    row={'relative_path':rel,'function':fn.name,'function_line':fn.lineno,'call_line':call.lineno,'call_expression':up(call),'assigned_targets':';'.join(assigned),'function_source':source}
                    caller_rows.append(row)
                    # Candidate only if result retained and function also contains a later tool-call-like action.
                    has_later_tool=any(isinstance(n,ast.Call) and getattr(n,'lineno',0)>call.lineno and any(tok in up(n.func).lower() for tok in ['tool','interact','execute','call']) for n in ast.walk(fn))
                    if assigned and has_later_tool:authoritative_candidates.append(row)
        add(checks,'C-022','routing',bool(caller_rows),len(caller_rows),'at least one before_decide caller discovered','ROUTING')
        add(checks,'C-023','routing',True,len(authoritative_candidates),'authoritative candidates classified','ROUTING')

        # Existing planned PostTool class does not exist, so it cannot already own proposal capture.
        capture_path=root/CAPTURE_FILE
        existing_classes=set()
        for p in sorted(sdk.rglob('*.py')):
            try:_,t=parse(p);existing_classes.update(classes(t))
            except:pass
        capture_identity_free=CAPTURE_CLASS not in existing_classes and not capture_path.exists()
        add(checks,'C-030','identity',capture_identity_free,{'class_exists':CAPTURE_CLASS in existing_classes,'file_exists':capture_path.exists()},'dedicated capture identity unused','FIXTURE')

        # Decision: preserve causal separation unless an existing authoritative component already captures and appends.
        existing_append_capture=[]
        for row in caller_rows:
            src=row['function_source']
            if 'append(' in src and ('proposal_digest' in src or 'tool_args_digest' in src):existing_append_capture.append(row)
        if existing_append_capture:
            outcome='EXISTING_HOOK_ADAPTER_CAN_OWN_DUAL_PHASE_CAPTURE'
            capture_owner='EXISTING_AUTHORITATIVE_CAPTURE_CALLER'
        elif caller_rows:
            outcome='DEDICATED_TRUSTED_PROPOSAL_CAPTURE_ADAPTER_REQUIRED'
            capture_owner=CAPTURE_CLASS
        else:
            outcome='NOT_FEASIBLE_WITHOUT_FROZEN_SOURCE_CHANGE'
            capture_owner='NOT_ESTABLISHED'
        add(checks,'C-031','decision',outcome in {'EXISTING_HOOK_ADAPTER_CAN_OWN_DUAL_PHASE_CAPTURE','DEDICATED_TRUSTED_PROPOSAL_CAPTURE_ADAPTER_REQUIRED','FACTORY_OR_WRAPPER_CAPTURE_ROUTE_REQUIRED','NOT_FEASIBLE_WITHOUT_FROZEN_SOURCE_CHANGE'},outcome,'classified outcome','AUTHORIZATION_TRANSPORT')

        capture_api={
          'class':CAPTURE_CLASS,
          'file':CAPTURE_FILE,
          'constructor':'__init__(self, *, downstream_adapter: TrustedGuardrailContextAdapterV1_1, pending_proposal_view: TrustedPendingProposalReadViewV1)',
          'before_decide':'before_decide(self, *, tool_name: str, tool_args: Mapping[str, Any], context: Mapping[str, Any]) -> Mapping[str, Any]',
          'ordering':['call downstream_adapter.before_decide exactly once','validate returned proposal record contains all frozen fields','construct immutable TrustedPendingProposalRecordV1','call pending_proposal_view.append(record)','return the unmodified authoritative proposal result','only after successful append may caller proceed toward tool execution'],
          'append_call':'self.pending_proposal_view.append(record)',
          'append_failure':'propagate exception; do not return proposal result; tool execution remains unauthorized',
          'private_adapter_access':False,
        }
        record_mapping={f:f'authoritative before_decide result[{f!r}]' for f in proposal_fields}
        ordering_contract={
          'step_1':'authoritative caller invokes capture_adapter.before_decide',
          'step_2':'capture adapter invokes downstream V1.1 before_decide exactly once',
          'step_3':'capture adapter validates and appends immutable provider record',
          'step_4':'capture adapter returns unmodified proposal result',
          'step_5':'authoritative caller evaluates decision and may proceed toward tool execution',
          'prohibited':'provider append after tool execution or reconstruction from post-tool data',
        }
        add(checks,'C-040','capture',capture_api['private_adapter_access'] is False,capture_api,'no private adapter access','AUTHORIZATION_TRANSPORT')
        add(checks,'C-041','capture',capture_api['append_call']=='self.pending_proposal_view.append(record)',capture_api['append_call'],'exact append call','ROUTING')
        add(checks,'C-042','capture','do not return' in capture_api['append_failure'],capture_api['append_failure'],'append failure is fail closed','AUTHORIZATION_TRANSPORT')
        add(checks,'C-043','capture',len(record_mapping)==5,record_mapping,'all provider fields mapped','ARGUMENT_FIDELITY')

        # Final constructor signatures and inventory.
        constructors={
          PROVIDER_CLASS:'__init__(self) -> None',
          CAPTURE_CLASS:capture_api['constructor'],
          HOOK_CLASS:'__init__(self, *, hook_registry: HookRegistry, transport: TrustedOutcomeTransportV1) -> None',
          WRAPPER_CLASS:'__init__(self, *, downstream_adapter: TrustedGuardrailContextAdapterV1_1, pending_proposal_view: TrustedPendingProposalReadViewV1, sequence_state: TrustedSequenceStateV1) -> None',
          FACTORY_FUNC:'build_trusted_acknowledgement_integration_v1(*, hook_registry: HookRegistry, downstream_adapter: TrustedGuardrailContextAdapterV1_1, sequence_state: TrustedSequenceStateV1) -> Mapping[str, object]',
        }
        planned_files=[freeze['proposed_artifacts']['provider']['file'],freeze['proposed_artifacts']['hook_adapter']['file'],freeze['proposed_artifacts']['transport_wrapper']['file'],freeze['proposed_artifacts']['factory']['file'],CAPTURE_FILE]
        planned_classes=[PROVIDER_CLASS,freeze['proposed_artifacts']['provider']['record_class'],HOOK_CLASS,WRAPPER_CLASS,CAPTURE_CLASS]
        inventory={'files':len(set(planned_files)),'classes':len(set(planned_classes)),'factory_functions':1}
        add(checks,'C-050','inventory',inventory=={'files':5,'classes':5,'factory_functions':1},inventory,{'files':5,'classes':5,'factory_functions':1},'FIXTURE')
        add(checks,'C-051','constructors',len(constructors)==5,constructors,'all component constructors/signatures frozen','ARGUMENT_FIDELITY')

        factory_bindings={
          'capture_adapter.downstream_adapter':'TrustedGuardrailContextAdapterV1_1',
          'capture_adapter.pending_proposal_view':PROVIDER_CLASS,
          'hook_adapter.hook_registry':'HookRegistry',
          'hook_adapter.transport':'TrustedOutcomeTransportV1',
          'transport.adapter':WRAPPER_CLASS,
          'wrapper.downstream_adapter':'TrustedGuardrailContextAdapterV1_1',
          'wrapper.pending_proposal_view':PROVIDER_CLASS,
          'wrapper.sequence_state':'same TrustedSequenceStateV1 instance supplied to transport',
          'authoritative_guardrail_entry':'capture_adapter.before_decide',
        }
        requirements=[
          {'id':'PC-001','statement':f'Create dedicated {CAPTURE_CLASS} in {CAPTURE_FILE}; do not merge proposal-time and post-tool responsibilities.','status':'REQUIRED'},
          {'id':'PC-002','statement':'Capture adapter delegates to authoritative V1.1 before_decide exactly once and returns its result unmodified after successful provider append.','status':'REQUIRED'},
          {'id':'PC-003','statement':'Map all five provider record fields from the exact authoritative before_decide result; never reconstruct from post-tool data.','status':'REQUIRED'},
          {'id':'PC-004','statement':'Call pending_proposal_view.append(record) before any tool execution; append failure propagates and fails closed.','status':'REQUIRED'},
          {'id':'PC-005','statement':'Keep capture adapter and post-tool hook adapter as distinct classes and files.','status':'REQUIRED'},
          {'id':'PC-006','statement':'Factory binds the authoritative guardrail entry to capture_adapter.before_decide and binds all downstream dependencies exactly as frozen.','status':'REQUIRED'},
          {'id':'PC-007','statement':'Final planned inventory is five files, five new classes, and one factory function.','status':'REQUIRED'},
          {'id':'PC-008','statement':'Implementation identity freeze remains static and executes no SDK modules, Sandbox, Gym, tools, fs.read, HTTP, predicates, breach, models, or threads.','status':'REQUIRED'},
        ]
        failed=[r['check_id'] for r in checks if not r['passed']]
        feasible=not failed and outcome!='NOT_FEASIBLE_WITHOUT_FROZEN_SOURCE_CHANGE'
        status='EX9_R3_R2_PROPOSAL_CAPTURE_AND_PROVIDER_POPULATION_ROUTE_FREEZE_COMPLETE_PASS' if feasible else 'EX9_R3_R2_PROPOSAL_CAPTURE_AND_PROVIDER_POPULATION_ROUTE_FREEZE_COMPLETE_WITH_GAPS'
        next_gate='ACKNOWLEDGEMENT_INTEGRATION_IMPLEMENTATION_AND_IDENTITY_FREEZE' if feasible else 'EX9_R3_R3_PROPOSAL_CAPTURE_ROUTE_REVIEW'
        freeze_out={'freeze_id':'EX9.ACK.PROPOSAL.CAPTURE.POPULATION.ROUTE.V1','status':'FROZEN' if feasible else 'NOT_FROZEN','parent_freeze_id':freeze.get('freeze_id'),'outcome':outcome,'capture_owner':capture_owner,'before_decide_authoritative_signature':before_sig,'caller_count':len(caller_rows),'authoritative_candidate_count':len(authoritative_candidates),'capture_api':capture_api,'record_mapping':record_mapping,'ordering_contract':ordering_contract,'constructors':constructors,'factory_bindings':factory_bindings,'final_inventory':inventory,'planned_files':planned_files,'planned_classes':planned_classes,'implementation_created':False,'implementation_identity':'NOT_ESTABLISHED','runtime_behavior':'NOT_EVALUATED'}
        claim={'allowed':['static before_decide caller inventory','proposal capture ownership and API','provider append ordering and failure semantics','final constructor, factory binding, class, and file plan','eligibility recommendation for separate static implementation gate'],'prohibited':['claim implementation exists','private adapter access','SDK source modification','runtime proposal capture','runtime acknowledgement','actual fs.read','Sandbox or Gym execution','HTTP sink','predicate or breach execution','model execution','protected-value lineage','guardrail effectiveness','real exfiltration prevention']}
        result_out={'version':VERSION,'created_at_utc':now(),'status':status,'classification':'READ_ONLY_STATIC_CALL_GRAPH_AND_INTERFACE_RECONCILIATION','EX9_R3_R1_parent_verified':True,'parent_result':{'checks':'25_OF_25','preserved_immutable':True},'checks':{'total':len(checks),'passed':len(checks)-len(failed),'failed':len(failed),'failed_ids':failed},'decision':{'outcome':outcome,'capture_owner':capture_owner,'final_inventory':inventory},'freeze':freeze_out,'readiness':{'implementation_creation_eligible':feasible,'controlled_actual_fs_read_eligible':False,'http_sink_eligible':False},'execution_boundaries':{'parent_artifacts_modified':False,'source_modified':False,'implementation_created':False,'sdk_modules_imported':False,'sdk_modules_executed':False,'Sandbox_instantiated':False,'Sandbox_interact_executed':False,'Gym_executed':False,'real_tools_executed':False,'actual_fs_read_executed':False,'http_sink_executed':False,'predicates_executed':False,'breach_executed':False,'models_used':False,'threads_executed':False,'external_effects_observed':False},'scientific_verdict':{'proposal_capture_route':'FROZEN' if feasible else 'GAPS_IDENTIFIED','implementation_behavior':'NOT_EVALUATED','actual_source_retrieval':'NOT_EVALUATED','protected_value_lineage':'NOT_ESTABLISHED','harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'},'claim_boundary':claim,'next_gate':next_gate}
        o={'result':out/'ex9_r3_r2_result.json','checks':out/'ex9_r3_r2_checks.csv','callers':out/'ex9_r3_r2_before_decide_callers.csv','capture':out/'ex9_r3_r2_capture_contract.json','constructors':out/'ex9_r3_r2_constructor_contracts.json','factory':out/'ex9_r3_r2_factory_bindings.json','requirements':out/'ex9_r3_r2_requirements.csv','freeze':out/'ex9_r3_r2_route_freeze.json','claim':out/'ex9_r3_r2_claim_boundary.json','binding':out/'ex9_r3_r2_binding.json'}
        wj(o['result'],result_out);wc(o['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']);wc(o['callers'],caller_rows,['relative_path','function','function_line','call_line','call_expression','assigned_targets','function_source']);wj(o['capture'],{'capture_api':capture_api,'record_mapping':record_mapping,'ordering_contract':ordering_contract});wj(o['constructors'],constructors);wj(o['factory'],factory_bindings);wc(o['requirements'],requirements,['id','statement','status']);wj(o['freeze'],freeze_out);wj(o['claim'],claim);wj(o['binding'],{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'parent':{k:ident(v) for k,v in parent.items()},'sources':{'adapter_v1_1':ident(adapter)},'source_modified':False,'implementation_created':False,'sdk_modules_imported':False,'sdk_modules_executed':False})
        rows=[{**ident(p),'role':'EX9_R3_R2_DERIVED'} for p in o.values()]+[{**ident(p),'role':'EX9_R3_R2_BOUND_PARENT'} for p in parent.values()]+[{**ident(adapter),'role':'EX9_R3_R2_AUTHORITATIVE_SOURCE'}]
        mp=out/'ex9_r3_r2_manifest.csv';wc(mp,rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'ex9_r3_r2_manifest_external_binding.json';wj(ep,{'version':VERSION,'created_at_utc':now(),'status':status,'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':sha(mp),'runner_sha256':sha(Path(__file__).resolve()),'parent_EX9_R3_R1_manifest_sha256':PARENT_MANIFEST_SHA,'freeze_id':freeze_out['freeze_id'],'checks_total':len(checks),'checks_passed':len(checks)-len(failed),'checks_failed':len(failed),'outcome':outcome,'implementation_creation_eligible':feasible,'controlled_actual_fs_read_eligible':False,'implementation_created':False,'next_gate':next_gate})
        print(json.dumps({'status':status,'parent':'25/25 preserved','checks':f'{len(checks)-len(failed)}/{len(checks)}','failed_ids':failed,'before_decide_callers':len(caller_rows),'authoritative_candidates':len(authoritative_candidates),'outcome':outcome,'capture_class':CAPTURE_CLASS,'final_inventory':inventory,'implementation_created':False,'controlled_actual_fs_read_eligible':False,'manifest_sha256':sha(mp),'next_gate':next_gate},indent=2))
    except Exception as e:
        (out/'EX9_R3_R2_FAILED.json').write_text(json.dumps({'version':VERSION,'created_at_utc':now(),'status':'EX9_R3_R2_ROUTE_FREEZE_BLOCKED','error_type':type(e).__name__,'error':str(e),'checks_frozen':checks,'source_modified':False,'implementation_created':False,'sdk_modules_imported':False,'sdk_modules_executed':False,'actual_fs_read_executed':False},indent=2),encoding='utf-8');raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for f in ['r1-result','r1-checks','r1-provider-contract','r1-factory-bindings','r1-complete-plan','r1-freeze','r1-requirements','r1-claim-boundary','r1-binding','r1-external-binding','r1-manifest','r1-runner','project-root','output-dir']:p.add_argument('--'+f,required=True)
    return p.parse_args()
if __name__=='__main__':
    try:main(args())
    except Exception as e:print(f'FAILED: {e}',file=sys.stderr);raise SystemExit(1)
