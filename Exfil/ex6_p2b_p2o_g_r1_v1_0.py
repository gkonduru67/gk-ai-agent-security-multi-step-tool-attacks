#!/usr/bin/env python3
"""P2O-G-R1 independent lifecycle qualification and evidence freeze.

Read-only verifier for frozen P2O-G artifacts. It does not import or execute the
implementation. It independently rehashes all parents and sources, recomputes
logical lifecycle ordering from raw ordered events, preserves exact raw events,
counts recursive canonicalization children, reconstructs snapshot transitions,
recomputes retry and trace identities from frozen check/result evidence,
revalidates concurrency-source findings against source AST, and freezes
P2O-G.EVENT.NORMALIZATION.V1.

No source modification, Sandbox, tool, fs.read, thread, HTTP, Gym, predicate,
breach logic, model, protected fixture value, real secret, or external effect.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, re, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="P2O_G_INDEPENDENT_LIFECYCLE_QUALIFICATION_AND_FREEZE_v1.0"
PARENT_VERSION="EX6_P2B_P2O_G_SYNTHETIC_POST_TOOL_LIFECYCLE_QUALIFICATION_v1.0"
PARENT_STATUS="P2O_G_SYNTHETIC_POST_TOOL_LIFECYCLE_QUALIFICATION_COMPLETE_PASS"
PARENT_MANIFEST_SHA="E86F392922734674288AC7F9FFE9351083259D3B9089F7CFA7C24A21FF35E39F"
PARENT_RUNNER_SHA="A89B033B6BFC5DB2BA50D2F6E8644A9C46A0720D907E7009631A75F417AA2E3E"
TRANSPORT_REL="aicomp_sdk/core/env/trusted_outcome_transport_v1.py"
TRANSPORT_SHA="5C7F7D16A37896959C6F4CC769E5F72A6E5E534EE140BA5CAF2FB70661102CE1"
BRIDGE_REL="aicomp_sdk/core/env/sandbox_trusted_bridge_v1.py"
BRIDGE_SHA="3EE9BBB1E65949795A5639D12C55D81D8D0645357260DFC5A91DB1E9710288B6"
LOGICAL_ORDER=["snapshot.before","proposal.allocate","outcome.allocate","canonicalize","raw_digest","bound_digest","adapter.after_tool","outcome.consume","snapshot.after"]
EXPECTED_SCENARIOS={"success":6,"failed_result":3,"adapter_error":1}
EXPECTED_KEYS={"success","completion_sequence","canonical_source_path","raw_output_sha256","protected_value_sha256_or_bound_digest"}


def now(): return datetime.now(timezone.utc).isoformat()
def require(c,m):
    if not c: raise ValueError(m)
def sha(path:Path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest().upper()
def ident(path:Path):
    path=path.resolve(); return {"artifact":path.name,"path":str(path),"size_bytes":path.stat().st_size,"sha256":sha(path)}
def write_json(path,obj):
    with path.open('x',encoding='utf-8',newline='\n') as f: json.dump(obj,f,indent=2,sort_keys=True); f.write('\n')
def write_csv(path,rows,fields):
    with path.open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n'); w.writeheader(); w.writerows(rows)
def add(rows,cid,category,passed,observed,expected,failure):
    rows.append({"check_id":cid,"category":category,"passed":bool(passed),"observed":str(observed),"expected":str(expected),"failure_layer":failure})
def parse_literal(text):
    import ast as pyast
    try: return pyast.literal_eval(text)
    except Exception: return text

def scenario_rows(events,name):
    rows=[r for r in events if r.get('scenario')==name]
    return sorted(rows,key=lambda r:int(r['order']))
def logical_projection(rows):
    projected=[]
    for r in rows:
        ev=r['event']
        if ev=='canonicalize':
            if not projected or projected[-1]!='canonicalize': projected.append('canonicalize')
        elif ev=='adapter.after_tool.raise': projected.append('adapter.after_tool.raise')
        else: projected.append(ev)
    return projected
def topological_match(projection,expected):
    pos=-1
    for target in expected:
        try: pos=projection.index(target,pos+1)
        except ValueError: return False
    return True

def ast_lock_review(path:Path):
    tree=ast.parse(path.read_text(encoding='utf-8'),filename=str(path))
    state=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='TrustedEventSequenceStateV1')
    methods={n.name:n for n in state.body if isinstance(n,ast.FunctionDef)}
    def locked(name):
        node=methods.get(name)
        return bool(node and any(isinstance(x,ast.With) and any('self._lock' in ast.unparse(i.context_expr) for i in x.items) for x in ast.walk(node)))
    transport=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='TrustedOutcomeTransportV1')
    ack=next(n for n in transport.body if isinstance(n,ast.FunctionDef) and n.name=='acknowledge')
    txt=ast.unparse(ack)
    return {"lock_field_declared":"_lock" in ast.unparse(state),"allocate_locked":locked('allocate'),"consume_locked":locked('consume_outcome'),"snapshot_locked":locked('snapshot'),"restore_locked":locked('restore'),"reset_locked":locked('reset'),"adapter_call_in_acknowledge":"self.adapter.after_tool" in txt,"transport_acknowledge_has_explicit_lock":"self.sequence_state._lock" in txt,"threaded_runtime_executed":False,"deadlock_behavior":"NOT_EVALUATED"}


def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    checks=[]; normalization_rows=[]; recomputed=[]
    try:
        project=Path(a.project_root).resolve(); require(project.is_dir(),f"Missing project root: {project}")
        inputs={"result":Path(a.p2o_g_result).resolve(),"checks":Path(a.p2o_g_checks).resolve(),"claim_boundary":Path(a.p2o_g_claim_boundary).resolve(),"concurrency":Path(a.p2o_g_concurrency_review).resolve(),"contract":Path(a.p2o_g_contract).resolve(),"ordered_events":Path(a.p2o_g_ordered_events).resolve(),"snapshots":Path(a.p2o_g_snapshots).resolve(),"binding":Path(a.p2o_g_binding).resolve(),"external_binding":Path(a.p2o_g_external_binding).resolve(),"manifest":Path(a.p2o_g_manifest).resolve(),"runner":Path(a.p2o_g_runner).resolve()}
        for k,p in inputs.items(): require(p.is_file(),f"Missing P2O-G {k}: {p}")
        result=json.loads(inputs['result'].read_text(encoding='utf-8-sig')); contract=json.loads(inputs['contract'].read_text(encoding='utf-8-sig')); claim=json.loads(inputs['claim_boundary'].read_text(encoding='utf-8-sig')); ext=json.loads(inputs['external_binding'].read_text(encoding='utf-8-sig'))
        parent_checks=list(csv.DictReader(inputs['checks'].open(encoding='utf-8-sig',newline=''))); events=list(csv.DictReader(inputs['ordered_events'].open(encoding='utf-8-sig',newline=''))); snapshots=list(csv.DictReader(inputs['snapshots'].open(encoding='utf-8-sig',newline=''))); parent_concurrency=next(csv.DictReader(inputs['concurrency'].open(encoding='utf-8-sig',newline='')))
        add(checks,'R1-01','identity',result.get('version')==PARENT_VERSION and result.get('status')==PARENT_STATUS,result.get('status'),PARENT_STATUS,'FIXTURE')
        add(checks,'R1-02','identity',sha(inputs['manifest'])==PARENT_MANIFEST_SHA and ext.get('manifest_sha256')==PARENT_MANIFEST_SHA,sha(inputs['manifest']),PARENT_MANIFEST_SHA,'FIXTURE')
        add(checks,'R1-03','identity',sha(inputs['runner'])==PARENT_RUNNER_SHA and ext.get('runner_sha256')==PARENT_RUNNER_SHA,sha(inputs['runner']),PARENT_RUNNER_SHA,'FIXTURE')
        transport=project/TRANSPORT_REL; bridge=project/BRIDGE_REL
        add(checks,'R1-04','identity',transport.is_file() and sha(transport)==TRANSPORT_SHA,sha(transport) if transport.is_file() else 'MISSING',TRANSPORT_SHA,'FIXTURE')
        add(checks,'R1-05','identity',bridge.is_file() and sha(bridge)==BRIDGE_SHA,sha(bridge) if bridge.is_file() else 'MISSING',BRIDGE_SHA,'FIXTURE')
        add(checks,'R1-06','parent_checks',len(parent_checks)==18 and all(r['passed']=='True' for r in parent_checks),{"rows":len(parent_checks),"passed":sum(r['passed']=='True' for r in parent_checks)},"18 rows; 18 true",'EVIDENCE')
        add(checks,'R1-07','contract',contract.get('contract_id')=='P2O-G.LIFECYCLE.CONTRACT.V1',contract.get('contract_id'),'P2O-G.LIFECYCLE.CONTRACT.V1','AUTHORIZATION_TRANSPORT')

        # Primary raw event recomputation and normalization.
        for index,name in enumerate(['success','failed_result','adapter_error'],20):
            rows=scenario_rows(events,name); raw=[r['event'] for r in rows]; projection=logical_projection(rows); cc=sum(e=='canonicalize' for e in raw)
            expected=LOGICAL_ORDER if name!='adapter_error' else ["snapshot.before","proposal.allocate","outcome.allocate","canonicalize","raw_digest","bound_digest","adapter.after_tool.raise","snapshot.after"]
            orders=[int(r['order']) for r in rows]
            add(checks,f'R1-{index}','raw_events',orders==list(range(1,len(rows)+1)),orders,list(range(1,len(rows)+1)),'AUTHORIZATION_TRANSPORT')
            add(checks,f'R1-{index+3}','normalization',cc==EXPECTED_SCENARIOS[name],cc,EXPECTED_SCENARIOS[name],'AUTHORIZATION_TRANSPORT')
            add(checks,f'R1-{index+6}','logical_order',projection==expected,projection,expected,'AUTHORIZATION_TRANSPORT')
            normalization_rows.append({"scenario":name,"raw_event_count":len(rows),"canonicalize_child_count":cc,"logical_projection":json.dumps(projection),"raw_sequence":json.dumps(raw),"logical_order_match":projection==expected})

        # Recompute success and failure identities/digests from primary event records and contract.
        success_rows=scenario_rows(events,'success'); failure_rows=scenario_rows(events,'failed_result'); error_rows=scenario_rows(events,'adapter_error')
        def one(rows,event_name,field):
            matches=[r for r in rows if r['event']==event_name]; require(len(matches)==1,f"Expected one {event_name}"); return matches[0].get(field,'')
        success_raw=one(success_rows,'raw_digest','digest'); success_bound=one(success_rows,'bound_digest','digest'); success_outcome=one(success_rows,'outcome.allocate','identity')
        add(checks,'R1-30','success_evidence',success_raw==contract['success']['expected_raw_output_sha256'],success_raw,contract['success']['expected_raw_output_sha256'],'PROVENANCE')
        add(checks,'R1-31','success_evidence',success_bound==contract['success']['expected_bound_digest'],success_bound,contract['success']['expected_bound_digest'],'PROVENANCE')
        add(checks,'R1-32','success_evidence',success_outcome==contract['success']['expected_outcome_identity'],success_outcome,contract['success']['expected_outcome_identity'],'REPLAY_ORCHESTRATION')
        add(checks,'R1-33','failure_evidence',one(failure_rows,'adapter.after_tool','success')=='False' and one(failure_rows,'outcome.consume','identity')=='g-trace-failure:outcome:2',{"success":one(failure_rows,'adapter.after_tool','success'),"consumed":one(failure_rows,'outcome.consume','identity')},{"success":"False","consumed":"g-trace-failure:outcome:2"},'AUTHORIZATION_TRANSPORT')
        add(checks,'R1-34','adapter_error',one(error_rows,'outcome.allocate','identity')=='g-trace-retry-error:outcome:2' and not any(r['event']=='outcome.consume' for r in error_rows),[r['event'] for r in error_rows],"allocated outcome 2 and no consume",'REPLAY_ORCHESTRATION')

        # Snapshot reconstruction from primary snapshot CSV and ordered event snapshots.
        snap={(r['scenario'],r['stage']):json.loads(r['snapshot_json']) for r in snapshots}
        success_before=snap[('success','before')]; success_after=snap[('success','after')]; failure_after=snap[('failed_result','after')]; error_after=snap[('adapter_error','after')]
        add(checks,'R1-35','snapshots',success_before=={"schema":"P2N.TRANSPORT.STATE.V1","counter_by_trace":{},"consumed_outcome_identities":[]},success_before,'empty state','REPLAY_ORCHESTRATION')
        add(checks,'R1-36','snapshots',success_after['counter_by_trace']=={'g-trace-success':2} and success_after['consumed_outcome_identities']==['g-trace-success:outcome:2'],success_after,'success sequence 2 consumed','REPLAY_ORCHESTRATION')
        add(checks,'R1-37','snapshots',failure_after['counter_by_trace']=={'g-trace-failure':2} and failure_after['consumed_outcome_identities']==['g-trace-failure:outcome:2'],failure_after,'failure result sequence 2 consumed','REPLAY_ORCHESTRATION')
        add(checks,'R1-38','snapshots',error_after['counter_by_trace']=={'g-trace-retry-error':2} and error_after['consumed_outcome_identities']==[],error_after,'adapter error sequence 2 unconsumed','REPLAY_ORCHESTRATION')

        # Artifact-consistency recomputation for G3/G4/G5 fields whose primary details are in checks/result.
        pc={r['check_id']:r for r in parent_checks}
        add(checks,'R1-39','artifact_consistency',parse_literal(pc['G3-01']['observed'])=={'calls':2,'sequences':[2,3]},pc['G3-01']['observed'],{'calls':2,'sequences':[2,3]},'REPLAY_ORCHESTRATION')
        add(checks,'R1-40','artifact_consistency',result['G3']=={"adapter_exception_contract":"ALLOCATED_NOT_CONSUMED","recovery_contract":"NEW_OUTCOME_EVENT_CONSUMED","successful_retry_contract":"NEW_OUTCOME_EVENT_AND_NEW_ADAPTER_CALL"},result['G3'],'frozen G3 contract','REPLAY_ORCHESTRATION')
        restored=parse_literal(pc['G4-01']['observed'])
        add(checks,'R1-41','artifact_consistency',restored==success_after and pc['G4-02']['observed']=='True',{"restored":restored,"duplicate":pc['G4-02']['observed']},{"restored":success_after,"duplicate":"True"},'REPLAY_ORCHESTRATION')
        sep=parse_literal(pc['G5-01']['observed']); expected_sep={"schema":"P2N.TRANSPORT.STATE.V1","counter_by_trace":{"g-trace-A":2,"g-trace-B":2},"consumed_outcome_identities":["g-trace-A:outcome:2","g-trace-B:outcome:2"]}
        add(checks,'R1-42','artifact_consistency',sep==expected_sep,sep,expected_sep,'REPLAY_ORCHESTRATION')

        # Independent AST concurrency review.
        review=ast_lock_review(transport)
        normalized_parent={k:(v=='True' if v in {'True','False'} else v) for k,v in parent_concurrency.items()}
        add(checks,'R1-43','concurrency',all(review[k] for k in ['lock_field_declared','allocate_locked','consume_locked','snapshot_locked','restore_locked','reset_locked']),review,'all state methods locked','AUTHORIZATION_TRANSPORT')
        add(checks,'R1-44','concurrency',review['adapter_call_in_acknowledge'] and not review['transport_acknowledge_has_explicit_lock'],review,'adapter call present; full acknowledge not explicitly locked','AUTHORIZATION_TRANSPORT')
        add(checks,'R1-45','concurrency',review['threaded_runtime_executed'] is False and review['deadlock_behavior']=='NOT_EVALUATED',review,'no threads; deadlock not evaluated','CLAIM_BOUNDARY')

        prohibited=set(claim.get('prohibited',[])); required_prohibited={'real tool-result lifecycle','Sandbox.interact behavior','threaded concurrency behavior','actual fs.read behavior','protected-value lineage','end-to-end authorization transport correctness','guardrail effectiveness','real exfiltration prevention'}
        add(checks,'R1-46','claim_boundary',required_prohibited<=prohibited,sorted(prohibited),sorted(required_prohibited),'CLAIM_BOUNDARY')
        boundaries=result.get('execution_boundaries',{})
        false_fields=['Sandbox_interact_executed','actual_fs_read_executed','breach_executed','external_effects_observed','gym_executed','http_sink_executed','models_used','predicates_executed','protected_fixture_values_used','real_secret_values_used','real_tools_executed','source_modified','threads_executed']
        add(checks,'R1-47','claim_boundary',all(boundaries.get(k) is False for k in false_fields),{k:boundaries.get(k) for k in false_fields},'all false','CLAIM_BOUNDARY')

        normalization={"normalization_id":"P2O-G.EVENT.NORMALIZATION.V1","canonicalize":{"representation":"LOGICAL_PARENT_WITH_RECURSIVE_CHILD_EVENTS","raw_child_events_preserved":True,"child_count":"SCENARIO_SPECIFIC"},"logical_stage_order":LOGICAL_ORDER,"exact_raw_event_sequence":{"status":"PRESERVED_NOT_REQUIRED_TO_EQUAL_LOGICAL_SEQUENCE"},"transaction_level_atomicity":"NOT_ESTABLISHED","threaded_behavior":"NOT_EVALUATED"}
        failed=[r['check_id'] for r in checks if not r['passed']]; qualified=not failed
        status='P2O_G_INDEPENDENT_LIFECYCLE_QUALIFICATION_AND_FREEZE_COMPLETE_PASS' if qualified else 'P2O_G_INDEPENDENT_LIFECYCLE_QUALIFICATION_COMPLETE_WITH_GAPS'
        next_gate='EX8_FROZEN_PROPOSAL_SANDBOX_GYM_PARITY' if qualified else 'P2O_G_R2_EVIDENCE_RECONCILIATION'
        claim_out={"allowed":["independently qualified synthetic lifecycle evidence","logical-parent and recursive-child event normalization","independently rehashed source and artifact identities","independently reconstructed ordering, digest, snapshot, retry, trace-separation, and static locking findings","eligibility recommendation for EX8 contract parity freeze"],"prohibited":["exact raw event sequence equals logical lifecycle sequence","transaction-level atomicity","threaded concurrency behavior","deadlock safety","real tool-result lifecycle","Sandbox.interact behavior","actual fs.read behavior","protected-value lineage","end-to-end authorization transport correctness","guardrail effectiveness","real exfiltration prevention"]}
        result_out={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"READ_ONLY_INDEPENDENT_LIFECYCLE_QUALIFICATION_AND_EVIDENCE_FREEZE","P2O_G_parent_verified":True,"checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"normalization":normalization,"evidence_scope":{"primary_raw_recomputations":["event continuity","recursive canonicalization counts","logical stage projections","success digests and outcome identity","failed-result consumption","adapter-error allocation without consumption","snapshot transitions","AST locking review"],"artifact_consistency_recomputations":["successful retry sequences","recovery contract","restored duplicate rejection","trace separation"]},"readiness":{"EX8_frozen_parity_gate_eligible":qualified,"lifecycle_evidence_frozen":qualified,"identity_freeze_eligible":qualified,"controlled_actual_fs_read_eligible":False},"execution_boundaries":{"source_modified":False,"implementation_imported":False,"implementation_executed":False,"Sandbox_interact_executed":False,"real_tools_executed":False,"actual_fs_read_executed":False,"threads_executed":False,"protected_fixture_values_used":False,"real_secret_values_used":False,"http_sink_executed":False,"gym_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False,"external_effects_observed":False},"scientific_verdict":{"synthetic_lifecycle_evidence":"INDEPENDENTLY_QUALIFIED_WITH_EVENT_NORMALIZATION" if qualified else "GAPS_IDENTIFIED","logical_stage_order":"ESTABLISHED" if qualified else "GAPS_IDENTIFIED","exact_raw_event_sequence":"PRESERVED_NOT_EQUATED_TO_LOGICAL_SEQUENCE","transaction_level_atomicity":"NOT_ESTABLISHED","threaded_concurrency":"NOT_EVALUATED","real_post_tool_lifecycle":"NOT_EVALUATED","actual_source_retrieval":"NOT_EVALUATED","protected_value_lineage":"NOT_ESTABLISHED","authorization_transport_correctness":"NOT_ESTABLISHED_END_TO_END","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim_out,"next_gate":next_gate}
        rp=out/'ex6_p2b_p2o_g_r1_result.json'; cp=out/'ex6_p2b_p2o_g_r1_checks.csv'; np=out/'ex6_p2b_p2o_g_r1_event_normalization.json'; nr=out/'ex6_p2b_p2o_g_r1_normalized_events.csv'; cr=out/'ex6_p2b_p2o_g_r1_concurrency_review.json'; cl=out/'ex6_p2b_p2o_g_r1_claim_boundary.json'; bp=out/'ex6_p2b_p2o_g_r1_binding.json'
        write_json(rp,result_out); write_csv(cp,checks,['check_id','category','passed','observed','expected','failure_layer']); write_json(np,normalization); write_csv(nr,normalization_rows,['scenario','raw_event_count','canonicalize_child_count','logical_projection','raw_sequence','logical_order_match']); write_json(cr,review); write_json(cl,claim_out); write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{k:ident(v) for k,v in inputs.items()},"sources":{"transport":ident(transport),"bridge":ident(bridge)},"project_root":str(project),"source_modified":False,"implementation_imported":False,"implementation_executed":False})
        derived=(rp,cp,np,nr,cr,cl,bp); bound=tuple(inputs.values()); sources=(transport,bridge)
        rows=[{**ident(p),"role":"P2O_G_R1_DERIVED"} for p in derived]+[{**ident(p),"role":"P2O_G_R1_BOUND"} for p in bound]+[{**ident(p),"role":"P2O_G_R1_REVIEWED_SOURCE"} for p in sources]
        mp=out/'ex6_p2b_p2o_g_r1_manifest.csv'; write_csv(mp,rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'ex6_p2b_p2o_g_r1_manifest_external_binding.json'; write_json(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"parent_p2o_g_manifest_sha256":PARENT_MANIFEST_SHA,"normalization_id":normalization['normalization_id'],"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"EX8_frozen_parity_gate_eligible":qualified,"implementation_executed":False,"controlled_actual_fs_read_eligible":False,"source_modified":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"normalization_id":normalization['normalization_id'],"implementation_executed":False,"actual_fs_read_executed":False,"manifest_sha256":sha(mp),"next_gate":next_gate},indent=2))
    except Exception as exc:
        (out/'P2O_G_R1_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2O_G_R1_QUALIFICATION_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"checks_frozen":checks,"source_modified":False,"implementation_imported":False,"implementation_executed":False,"actual_fs_read_executed":False,"effects_observed":False},indent=2),encoding='utf-8')
        raise


def parse_args():
    p=argparse.ArgumentParser(description=VERSION)
    for flag in ['p2o-g-result','p2o-g-checks','p2o-g-claim-boundary','p2o-g-concurrency-review','p2o-g-contract','p2o-g-ordered-events','p2o-g-snapshots','p2o-g-binding','p2o-g-external-binding','p2o-g-manifest','p2o-g-runner','project-root','output-dir']:
        p.add_argument('--'+flag,required=True)
    return p.parse_args()
if __name__=='__main__':
    try: main(parse_args())
    except Exception as exc: print(f"FAILED: {exc}",file=sys.stderr); raise SystemExit(1)
