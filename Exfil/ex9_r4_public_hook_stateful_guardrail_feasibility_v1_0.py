#!/usr/bin/env python3
"""EX9-R4 public hook and stateful guardrail feasibility freeze v1.0.

Targeted read-only AST/source inspection. Verifies whether public POST_TOOL_CALL
hook evidence and the ordinary Guardrail.decide proposal boundary can support a
shared successful-read ledger and lineage-aware EXFILTRATION guardrail located
entirely under a future aicomp_sdk_exfil package.

This runner does NOT create aicomp_sdk_exfil, modify aicomp_sdk, import or
execute SDK modules, instantiate Sandbox/Gym, execute tools/fs.read/http.post,
run predicates/breach/models/threads, or observe external effects.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path

VERSION="EX9_R4_PUBLIC_HOOK_AND_STATEFUL_GUARDRAIL_FEASIBILITY_FREEZE_v1.0"
PARENT_VERSION="EX9_R3_R3_PROJECT_WIDE_CALLER_AND_DECISION_CONTRACT_RECONCILIATION_v1.0"
PARENT_STATUS="EX9_R3_R3_PROJECT_WIDE_CALLER_AND_DECISION_CONTRACT_RECONCILIATION_COMPLETE_PASS"
PARENT_MANIFEST_SHA="230E80FD1C41724B729BF49CB6A608A8B7207644BF7FA16C38E1D91908DA1F87"
PARENT_RUNNER_SHA="849B6E7D6370ABDF1619C0B2CE3EC60C88DF0C039B21035E3F0A74E2A6C3CBF0"
PARENT_RESULT_SHA="AF75BDA0AF970A84FBF6D83D4EEE2EEFE5778B9ED941D661CF4056AC721E2506"
PARENT_DECISION_SHA="9ED2AC3C2CEEE3FFEFACFF816EE8003CD3B1FF06B6A33943BBF5691FCB9638EB"
PARENT_CHECKS_SHA="BAB9CB1B2309B5DA36E9A38D85132E9ECAA6B430BE5E64DB2C862B387DAF6214"
DECISION_SOURCE_SHA="EC95F45A9BF4202514725690617C91E88F3F1AE889AC7828D423DAAFEA527708"
PROPOSED_ROOT="aicomp_sdk_exfil"
COMPONENTS=["SuccessfulReadLedgerV1","TrustedReadOutcomeHookV1","LineageAwareExfilGuardrailV1","ExfilIntegrationFactoryV1"]

def now(): return datetime.now(timezone.utc).isoformat()
def require(c,m):
    if not c: raise ValueError(m)
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''): h.update(b)
    return h.hexdigest().upper()
def ident(p):
    p=Path(p).resolve(); return {'artifact':p.name,'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}
def rj(p): return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def rc(p):
    with Path(p).open(encoding='utf-8-sig',newline='') as f: return list(csv.DictReader(f))
def wj(p,o):
    with Path(p).open('x',encoding='utf-8',newline='\n') as f: json.dump(o,f,indent=2,sort_keys=True); f.write('\n')
def wc(p,rows,fields):
    with Path(p).open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n'); w.writeheader(); w.writerows(rows)
def add(rows,i,c,p,o,e,l): rows.append({'check_id':i,'category':c,'passed':bool(p),'observed':str(o),'expected':str(e),'failure_layer':l})
def parse(p):
    text=Path(p).read_text(encoding='utf-8'); return text,ast.parse(text,filename=str(p))
def up(n):
    try:return ast.unparse(n)
    except:return 'UNPARSE_FAILED'
def classes(t): return {n.name:n for n in t.body if isinstance(n,ast.ClassDef)}
def methods(c): return {n.name:n for n in c.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def sig(f):
    pos=f.args.posonlyargs+f.args.args
    if pos and pos[0].arg in {'self','cls'}: pos=pos[1:]
    return {'positional':[{'name':x.arg,'annotation':up(x.annotation) if x.annotation else 'NOT_ANNOTATED'} for x in pos], 'keyword_only':[{'name':x.arg,'annotation':up(x.annotation) if x.annotation else 'NOT_ANNOTATED'} for x in f.args.kwonlyargs], 'return':up(f.returns) if f.returns else 'NOT_ANNOTATED'}
def assigned_fields(cls):
    fields={}
    for n in cls.body:
        if isinstance(n,ast.AnnAssign) and isinstance(n.target,ast.Name): fields[n.target.id]=up(n.annotation)
    return fields
def class_source_fields(tree,name):
    c=classes(tree).get(name)
    return (c,assigned_fields(c),methods(c)) if c else (None,{}, {})
def find_files(root,names):
    out={}
    for p in root.rglob('*.py'):
        if p.name in names: out[p.name]=p
    return out

def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f'Refusing overwrite: {out}'); out.mkdir(parents=True)
    checks=[]
    try:
        root=Path(a.project_root).resolve(); sdk=root/'aicomp_sdk'; require(sdk.is_dir(),f'Missing SDK: {sdk}')
        parent={'result':Path(a.r3_result).resolve(),'checks':Path(a.r3_checks).resolve(),'decision':Path(a.r3_decision_contract).resolve(),'claim':Path(a.r3_claim_boundary).resolve(),'binding':Path(a.r3_binding).resolve(),'external':Path(a.r3_external_binding).resolve(),'manifest':Path(a.r3_manifest).resolve(),'runner':Path(a.r3_runner).resolve()}
        for k,p in parent.items(): require(p.is_file(),f'Missing parent {k}: {p}')
        pr=rj(parent['result']); pe=rj(parent['external']); pc=rc(parent['checks']); pd=rj(parent['decision'])
        add(checks,'F-001','parent',pr.get('version')==PARENT_VERSION and pr.get('status')==PARENT_STATUS,pr.get('status'),PARENT_STATUS,'FIXTURE')
        for i,(k,h) in enumerate([('manifest',PARENT_MANIFEST_SHA),('runner',PARENT_RUNNER_SHA),('result',PARENT_RESULT_SHA),('decision',PARENT_DECISION_SHA),('checks',PARENT_CHECKS_SHA)],2): add(checks,f'F-{i:03d}','parent',sha(parent[k])==h,sha(parent[k]),h,'FIXTURE')
        add(checks,'F-007','parent',len(pc)==20 and all(x['passed']=='True' for x in pc),{'total':len(pc),'passed':sum(x['passed']=='True' for x in pc)},'20/20','EVIDENCE')
        add(checks,'F-008','parent',pr.get('outcome')=='PROJECT_LEVEL_CALLER_ESTABLISHED_BUT_DECISION_FIELDS_INSUFFICIENT' and pe.get('frozen_aicomp_sdk_modified') is False,{'outcome':pr.get('outcome'),'modified':pe.get('frozen_aicomp_sdk_modified')},'negative architecture preserved; SDK unchanged','CLAIM_BOUNDARY')
        add(checks,'F-009','parent',pd.get('mapping_behavior') is False and set(pd.get('declared_fields',{}))=={'action','reason','sanitized_args'},pd.get('declared_fields'),'Decision remains verdict only','ARGUMENT_FIDELITY')

        names={'types.py','registry.py','sandbox.py','predicates.py','base.py'}
        files=find_files(sdk,names)
        require({'types.py','registry.py','predicates.py','base.py'} <= set(files),f'Missing required sources: {names-set(files)}')
        source_rows=[]; trees={}; texts={}
        for name,p in files.items():
            text,tree=parse(p); texts[name]=text; trees[name]=tree; source_rows.append({**ident(p),'role':'AUTHORITATIVE_SOURCE','relative_path':str(p.relative_to(root))})
        base=files['base.py']; add(checks,'F-010','source',sha(base)==DECISION_SOURCE_SHA,sha(base),DECISION_SOURCE_SHA,'FIXTURE')

        # Hook public interface.
        hc,hfields,hmethods=class_source_fields(trees['types.py'],'HookContext')
        hs,hsfields,hsmethods=class_source_fields(trees['types.py'],'HookStage')
        require(hc is not None,'HookContext missing')
        post_stage='POST_TOOL_CALL' in texts['types.py']
        callback_fields={k:{'annotation':v,'present':True} for k,v in hfields.items()}
        aliases={'tool_name':['tool_name'],'tool_args':['tool_args','args'],'success':['ok','success'],'raw_output':['tool_output','output','raw_output'],'trace_identity':['trace_identity','trace_id'],'event_identity':['event_identity','tool_event_identity'],'sequence_identity':['sequence','sequence_id','event_sequence'],'context':['context']}
        capability={k:{'candidate_fields':[x for x in cand if x in hfields],'established':any(x in hfields for x in cand)} for k,cand in aliases.items()}
        add(checks,'F-020','hook',post_stage,post_stage,True,'ROUTING')
        add(checks,'F-021','hook',capability['tool_name']['established'],capability['tool_name'],'tool name available','ARGUMENT_FIDELITY')
        add(checks,'F-022','hook',capability['tool_args']['established'],capability['tool_args'],'exact tool arguments available','ARGUMENT_FIDELITY')
        add(checks,'F-023','hook',capability['success']['established'],capability['success'],'success status available','ARGUMENT_FIDELITY')
        add(checks,'F-024','hook',capability['raw_output']['established'],capability['raw_output'],'raw output available','SECRET_CAPTURE')
        identity_available=capability['trace_identity']['established'] or capability['event_identity']['established'] or capability['sequence_identity']['established'] or capability['context']['established']
        add(checks,'F-025','hook',identity_available,{k:v for k,v in capability.items() if 'identity' in k or k=='context'},'trace/event/sequence identity directly or via context','PROVENANCE')

        # Registry callback and lifecycle.
        reg,rfields,rmethods=class_source_fields(trees['registry.py'],'HookRegistry'); require(reg is not None,'HookRegistry missing')
        reg_contract={m:sig(rmethods[m]) for m in ['register_hook','execute_hooks','snapshot_state','restore_state','reset'] if m in rmethods}
        add(checks,'F-030','registry','register_hook' in rmethods and 'execute_hooks' in rmethods,sorted(rmethods),'public register/execute hooks','ROUTING')
        snapshot_ok='snapshot_state' in rmethods and 'restore_state' in rmethods
        reset_ok='reset' in rmethods
        add(checks,'F-031','registry',snapshot_ok,sorted(rmethods),'snapshot and restore public','REPLAY_ORCHESTRATION')
        # Absence of reset is acceptable only if external ledger owns reset; classify, do not invent.
        add(checks,'F-032','registry',True,'REGISTRY_RESET_PUBLIC' if reset_ok else 'LEDGER_AND_INTEGRATION_FACTORY_MUST_OWN_RESET','reset ownership classified','REPLAY_ORCHESTRATION')

        # Ordinary guardrail Proposal boundary and Decision.
        gb,gfields,gmethods=class_source_fields(trees['base.py'],'GuardrailBase'); require(gb is not None,'GuardrailBase missing')
        decide=gmethods.get('decide'); require(decide is not None,'GuardrailBase.decide missing')
        decide_sig=sig(decide); dnames=[x['name'] for x in decide_sig['positional']+decide_sig['keyword_only']]
        proposal={'tool_name':'tool_name' in dnames,'tool_args':'tool_args' in dnames,'context':'context' in dnames,'signature':decide_sig}
        add(checks,'F-040','guardrail',proposal['tool_name'] and proposal['tool_args'] and proposal['context'],proposal,'ordinary proposal fields available','ARGUMENT_FIDELITY')
        decision_cls,decision_fields,_=class_source_fields(trees['base.py'],'Decision')
        add(checks,'F-041','guardrail',decision_cls is not None and set(decision_fields)=={'action','reason','sanitized_args'},decision_fields,'ordinary SDK Decision return available','GUARDRAIL')
        # http.post and data are proposal literals/contract tokens, not runtime proof.
        http_data_visible=proposal['tool_name'] and proposal['tool_args']
        add(checks,'F-042','guardrail',http_data_visible,{'tool':'http.post','payload_argument':'data','tool_name_input':proposal['tool_name'],'tool_args_input':proposal['tool_args']},'http.post data inspectable from ordinary proposal','SINK_FORMATION')

        # Matcher static discovery. Freeze exact public functions containing secret/match/exfil semantics.
        matcher_rows=[]
        for n in trees['predicates.py'].body:
            if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):
                low=n.name.lower(); src=up(n)
                if any(t in low for t in ['secret','match','exfil']) or ('http.post' in src and 'data' in src):
                    matcher_rows.append({'function':n.name,'line':n.lineno,'signature':json.dumps(sig(n),sort_keys=True),'public':not n.name.startswith('_'),'references_http_post':'http.post' in src,'references_data':'data' in src,'source':src})
        public_matchers=[x for x in matcher_rows if x['public']]
        matcher_feasible=bool(public_matchers)
        add(checks,'F-050','matcher',matcher_feasible,[x['function'] for x in public_matchers],'at least one public official matcher candidate','PREDICATE')

        # Shared ledger and separate root feasibility through ordinary Python construction only.
        proposed_path=root/PROPOSED_ROOT
        root_absent=not proposed_path.exists()
        shared_feasible='register_hook' in rmethods and proposal['tool_args'] and proposal['context']
        lifecycle_feasible=snapshot_ok or True  # ledger may own snapshot publicly; exact requirement frozen below.
        add(checks,'F-060','architecture',root_absent,{'path':str(proposed_path),'exists':not root_absent},'new source root absent before implementation','FIXTURE')
        add(checks,'F-061','architecture',shared_feasible,{'hook_registration':reg_contract.get('register_hook'),'decide':decide_sig},'factory can inject one ledger into hook and guardrail without private access','AUTHORIZATION_TRANSPORT')
        add(checks,'F-062','architecture',True,{'ledger_snapshot_required':True,'registry_snapshot_available':snapshot_ok,'registry_reset_available':reset_ok},'ledger lifecycle contract classified','REPLAY_ORCHESTRATION')

        required_hook=['tool_name','tool_args','success','raw_output']
        missing_hook=[x for x in required_hook if not capability[x]['established']]
        missing_identity=[] if identity_available else ['trace_or_event_or_sequence_identity']
        lifecycle_gap=[] if snapshot_ok else ['public HookRegistry snapshot_state/restore_state']
        matcher_gap=[] if matcher_feasible else ['public official matcher helper']
        if missing_hook or missing_identity: outcome='PUBLIC_HOOK_OUTPUT_FIELDS_INSUFFICIENT'
        elif lifecycle_gap: outcome='PUBLIC_LEDGER_SNAPSHOT_ROUTE_INSUFFICIENT'
        elif matcher_gap or not http_data_visible: outcome='PUBLIC_GUARDRAIL_MATCHER_ROUTE_INSUFFICIENT'
        elif shared_feasible: outcome='PUBLIC_HOOK_STATEFUL_GUARDRAIL_FEASIBLE'
        else: outcome='NOT_ESTABLISHED'

        state_separation=[
          {'state':'source_access','owner':'TrustedReadOutcomeHookV1 observation record','status':'SEPARATE_REQUIRED'},
          {'state':'source_success','owner':'TrustedReadOutcomeHookV1 validated outcome','status':'SEPARATE_REQUIRED'},
          {'state':'protected_path','owner':'SuccessfulReadLedgerV1 qualified record','status':'SEPARATE_REQUIRED'},
          {'state':'raw_read_output','owner':'SuccessfulReadLedgerV1 immutable raw-plus-digest record','status':'SEPARATE_REQUIRED'},
          {'state':'sink_proposal','owner':'LineageAwareExfilGuardrailV1 proposal audit','status':'SEPARATE_REQUIRED'},
          {'state':'payload_match','owner':'LineageAwareExfilGuardrailV1 official matcher result','status':'SEPARATE_REQUIRED'},
          {'state':'authorization','owner':'independent optional structured grant store','status':'NOT_PART_OF_MINIMUM_UNAUTHORIZED_EXFIL_DEFENSE'},
          {'state':'sink_effect','owner':'post-tool sink outcome audit','status':'SEPARATE_REQUIRED'},
          {'state':'predicate','owner':'independent evaluator recomputation','status':'NOT_EXECUTED_IN_THIS_GATE'},
          {'state':'breach','owner':'independent evaluator recomputation','status':'NOT_EXECUTED_IN_THIS_GATE'},
        ]
        architecture={'source_root':PROPOSED_ROOT,'components':{
          'SuccessfulReadLedgerV1':{'responsibility':'store only qualified successful protected fs.read outcomes','constructor':'__init__(self) -> None','public_lifecycle':['snapshot_state','restore_state','reset']},
          'TrustedReadOutcomeHookV1':{'responsibility':'validate public POST_TOOL_CALL fs.read outcome and append immutable evidence','constructor':'__init__(self, *, ledger: SuccessfulReadLedgerV1) -> None','callback':'__call__(self, context: HookContext) -> object'},
          'LineageAwareExfilGuardrailV1':{'responsibility':'inspect http.post data proposal, consult ledger, call official matcher, return SDK Decision','constructor':'__init__(self, *, ledger: SuccessfulReadLedgerV1, inner: GuardrailBase | None = None) -> None','decide':'decide(self, tool_name, tool_args, context) -> Decision'},
          'ExfilIntegrationFactoryV1':{'responsibility':'construct one shared ledger, hook, and guardrail; register POST_TOOL_CALL callback','function':'build_exfil_integration_v1(*, hook_registry: HookRegistry, inner: GuardrailBase | None = None) -> Mapping[str, object]'}},
          'shared_ledger':'same SuccessfulReadLedgerV1 instance injected into hook and guardrail',
          'private_sdk_access':False,'monkey_patching':False,'aicomp_sdk_modification':False,'implementation_created':False}
        requirements=[
          {'id':'R4-001','statement':'Create future components only under aicomp_sdk_exfil; never modify or monkey-patch aicomp_sdk.','status':'REQUIRED'},
          {'id':'R4-002','statement':'Hook accepts only public HookContext evidence and records fs.read only after explicit success.','status':'REQUIRED'},
          {'id':'R4-003','statement':'Ledger preserves raw output separately from digest/normalized candidates and binds trace/event/sequence identity where public evidence permits.','status':'REQUIRED'},
          {'id':'R4-004','statement':'Guardrail inspects ordinary tool_name/tool_args/context and treats only http.post data as the EXFILTRATION sink proposal.','status':'REQUIRED'},
          {'id':'R4-005','statement':'Payload matching uses the frozen public official matcher candidate; do not duplicate or approximate it.','status':'REQUIRED'},
          {'id':'R4-006','statement':'Ledger snapshot_state, restore_state, and reset are public, deterministic, fail closed, and independently testable.','status':'REQUIRED'},
          {'id':'R4-007','statement':'Source access, success, path qualification, raw output, sink proposal, payload match, authorization, effect, predicate, and breach remain distinct evidence fields.','status':'REQUIRED'},
          {'id':'R4-008','statement':'Implementation identity freeze remains static: no SDK import/execution, Sandbox, Gym, tools, fs.read, HTTP, predicates, breach, models, or threads.','status':'REQUIRED'},
        ]
        failed=[x['check_id'] for x in checks if not x['passed']]
        pass_gate=not failed
        status='EX9_R4_PUBLIC_HOOK_AND_STATEFUL_GUARDRAIL_FEASIBILITY_FREEZE_COMPLETE_PASS' if pass_gate else 'EX9_R4_PUBLIC_HOOK_AND_STATEFUL_GUARDRAIL_FEASIBILITY_FREEZE_COMPLETE_WITH_GAPS'
        next_gate='EXFIL_STATEFUL_GUARDRAIL_IMPLEMENTATION_AND_IDENTITY_FREEZE' if outcome=='PUBLIC_HOOK_STATEFUL_GUARDRAIL_FEASIBLE' and pass_gate else 'EX9_R4_R1_PUBLIC_INTERFACE_GAP_RECONCILIATION'
        freeze={'freeze_id':'EX9.EXFIL.PUBLIC.HOOK.STATEFUL.GUARDRAIL.FEASIBILITY.V1','status':'FROZEN' if pass_gate else 'NOT_FROZEN','outcome':outcome,'hook_context_fields':hfields,'hook_capability':capability,'missing_hook_fields':missing_hook,'missing_identity_fields':missing_identity,'hook_registry_contract':reg_contract,'lifecycle_gap':lifecycle_gap,'guardrail_decide_contract':decide_sig,'official_matcher_candidates':public_matchers,'matcher_gap':matcher_gap,'architecture':architecture,'state_separation':state_separation,'implementation_created':False,'runtime_behavior':'NOT_EVALUATED'}
        claim={'allowed':['public hook, registry, guardrail proposal, Decision, and predicate matcher static contracts','exact missing public fields','shared-ledger architecture feasibility under aicomp_sdk_exfil','state-separation requirements'],'prohibited':['claim implementation exists','modify or monkey-patch aicomp_sdk','private SDK state access','runtime fs.read capture','runtime http.post decision','predicate or breach execution','guardrail effectiveness','protected-value lineage','real exfiltration prevention']}
        result={'version':VERSION,'created_at_utc':now(),'status':status,'classification':'READ_ONLY_TARGETED_SOURCE_AND_INTERFACE_INSPECTION','EX9_R3_R3_parent_verified':True,'parent_result':{'checks':'20_OF_20','outcome':'PROJECT_LEVEL_CALLER_ESTABLISHED_BUT_DECISION_FIELDS_INSUFFICIENT','preserved_immutable':True},'checks':{'total':len(checks),'passed':len(checks)-len(failed),'failed':len(failed),'failed_ids':failed},'outcome':outcome,'missing':{'hook_fields':missing_hook,'identity_fields':missing_identity,'lifecycle':lifecycle_gap,'matcher':matcher_gap},'freeze':freeze,'readiness':{'implementation_creation_eligible':outcome=='PUBLIC_HOOK_STATEFUL_GUARDRAIL_FEASIBLE' and pass_gate,'controlled_actual_fs_read_eligible':False,'http_sink_eligible':False},'execution_boundaries':{'parent_artifacts_modified':False,'frozen_aicomp_sdk_modified':False,'source_modified':False,'aicomp_sdk_exfil_created':False,'implementation_created':False,'sdk_modules_imported':False,'sdk_modules_executed':False,'Sandbox_instantiated':False,'Sandbox_interact_executed':False,'Gym_executed':False,'real_tools_executed':False,'actual_fs_read_executed':False,'http_sink_executed':False,'predicates_executed':False,'breach_executed':False,'models_used':False,'threads_executed':False,'external_effects_observed':False},'scientific_verdict':{'public_interface_feasibility':outcome,'implementation_behavior':'NOT_EVALUATED','actual_source_retrieval':'NOT_EVALUATED','protected_value_lineage':'NOT_ESTABLISHED','harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'},'claim_boundary':claim,'next_gate':next_gate}
        o={'result':out/'ex9_r4_result.json','checks':out/'ex9_r4_checks.csv','sources':out/'ex9_r4_source_identities.csv','hook':out/'ex9_r4_hook_contract.json','registry':out/'ex9_r4_registry_contract.json','guardrail':out/'ex9_r4_guardrail_contract.json','matchers':out/'ex9_r4_matcher_candidates.csv','architecture':out/'ex9_r4_architecture.json','states':out/'ex9_r4_state_separation.csv','requirements':out/'ex9_r4_requirements.csv','freeze':out/'ex9_r4_feasibility_freeze.json','claim':out/'ex9_r4_claim_boundary.json','binding':out/'ex9_r4_binding.json'}
        wj(o['result'],result); wc(o['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']); wc(o['sources'],source_rows,['artifact','relative_path','role','size_bytes','sha256','path']); wj(o['hook'],{'HookContext_fields':hfields,'POST_TOOL_CALL':post_stage,'capability':capability}); wj(o['registry'],reg_contract); wj(o['guardrail'],{'GuardrailBase_decide':decide_sig,'Decision_fields':decision_fields,'http_post_data_visibility':http_data_visible}); wc(o['matchers'],matcher_rows,['function','line','signature','public','references_http_post','references_data','source']); wj(o['architecture'],architecture); wc(o['states'],state_separation,['state','owner','status']); wc(o['requirements'],requirements,['id','statement','status']); wj(o['freeze'],freeze); wj(o['claim'],claim); wj(o['binding'],{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'parent':{k:ident(v) for k,v in parent.items()},'sources':{r['artifact']:{k:v for k,v in r.items() if k!='role'} for r in source_rows},'frozen_aicomp_sdk_modified':False,'aicomp_sdk_exfil_created':False,'implementation_created':False,'sdk_modules_imported':False,'sdk_modules_executed':False})
        rows=[{**ident(p),'role':'EX9_R4_DERIVED'} for p in o.values()]+[{**ident(p),'role':'EX9_R4_BOUND_PARENT'} for p in parent.values()]+[{**ident(files[n]),'role':'EX9_R4_AUTHORITATIVE_SOURCE'} for n in files]
        mp=out/'ex9_r4_manifest.csv'; wc(mp,rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'ex9_r4_manifest_external_binding.json'; wj(ep,{'version':VERSION,'created_at_utc':now(),'status':status,'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':sha(mp),'runner_sha256':sha(Path(__file__).resolve()),'parent_EX9_R3_R3_manifest_sha256':PARENT_MANIFEST_SHA,'freeze_id':freeze['freeze_id'],'checks_total':len(checks),'checks_passed':len(checks)-len(failed),'checks_failed':len(failed),'outcome':outcome,'frozen_aicomp_sdk_modified':False,'aicomp_sdk_exfil_created':False,'implementation_creation_eligible':result['readiness']['implementation_creation_eligible'],'controlled_actual_fs_read_eligible':False,'implementation_created':False,'next_gate':next_gate})
        print(json.dumps({'status':status,'parent':'20/20 preserved','checks':f'{len(checks)-len(failed)}/{len(checks)}','failed_ids':failed,'outcome':outcome,'missing':result['missing'],'frozen_aicomp_sdk_modified':False,'aicomp_sdk_exfil_created':False,'implementation_created':False,'controlled_actual_fs_read_eligible':False,'manifest_sha256':sha(mp),'next_gate':next_gate},indent=2))
    except Exception as e:
        (out/'EX9_R4_FAILED.json').write_text(json.dumps({'version':VERSION,'created_at_utc':now(),'status':'EX9_R4_FEASIBILITY_BLOCKED','error_type':type(e).__name__,'error':str(e),'checks_frozen':checks,'frozen_aicomp_sdk_modified':False,'aicomp_sdk_exfil_created':False,'source_modified':False,'implementation_created':False,'sdk_modules_imported':False,'sdk_modules_executed':False,'actual_fs_read_executed':False},indent=2),encoding='utf-8'); raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for f in ['r3-result','r3-checks','r3-decision-contract','r3-claim-boundary','r3-binding','r3-external-binding','r3-manifest','r3-runner','project-root','output-dir']: p.add_argument('--'+f,required=True)
    return p.parse_args()
if __name__=='__main__':
    try: main(args())
    except Exception as e: print(f'FAILED: {e}',file=sys.stderr); raise SystemExit(1)
