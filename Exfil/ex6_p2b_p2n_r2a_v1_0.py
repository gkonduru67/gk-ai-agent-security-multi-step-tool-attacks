#!/usr/bin/env python3
"""EX6 P2B P2N R2A independent implementation-readiness qualification.

Read-only independent review of the frozen P2N-R2 implementation plan.
Validates: three create plus one bind-only entry, proposed-path collisions,
class/helper ownership, five-gap symbol coverage, wrapper claim discipline,
insertion ordering, immutable identity coverage, canonicalization specificity,
snapshot ownership, staged authorization boundaries, freeze/external-binding
completeness, and claim-boundary consistency.

No implementation or source file is created or modified. No SDK module is
imported. No tool, fs.read, Sandbox, Gym, predicate, breach, model, fixture
content, source-value preview/export, or external effect is executed.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2N_R2A_INDEPENDENT_IMPLEMENTATION_READINESS_QUALIFICATION_v1.0"
PARENT_VERSION="EX6_P2B_P2N_R2_IMPLEMENTATION_READINESS_AND_CHANGE_MANIFEST_SPECIFICATION_v1.0"
PARENT_STATUS="P2N_R2_IMPLEMENTATION_READINESS_AND_CHANGE_MANIFEST_SPECIFICATION_COMPLETE_PASS"
PARENT_MANIFEST_SHA="8864C8ADE722F3893E02C60A13F1CAF06AF8802FD8E0393DDA707AE17FC1BA69"
PARENT_RUNNER_SHA="F89B3C61EAF60E286FEE5BF3AA5B5A2BE0CD8B5A3C165CD12E0315D314EEBA90"
ADAPTER_SHA="BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"
CREATE_PATHS={
 "aicomp_sdk/core/env/trusted_outcome_transport_v1.py",
 "aicomp_sdk/core/env/sandbox_trusted_bridge_v1.py",
 "aicomp_sdk/core/tools/fs_trusted_result_v1.py",
}
BIND_PATH="aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py"
PROHIBITED_EXISTING={
 "aicomp_sdk/core/env/sandbox.py",
 "aicomp_sdk/core/tools/fs.py",
 "aicomp_sdk/guardrails/optimal.py",
 "aicomp_sdk/core/predicates.py",
 BIND_PATH,
}
FIVE_REQUIREMENTS={"P2N-01","P2N-02","P2N-03","P2N-04","P2N-05"}

def now(): return datetime.now(timezone.utc).isoformat()
def require(c,m):
    if not c: raise ValueError(m)
def sha(p:Path):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest().upper()
def ident(p:Path):
    p=p.resolve(); return {"artifact":p.name,"path":str(p),"size_bytes":p.stat().st_size,"sha256":sha(p)}
def write_json(p,x):
    with p.open('x',encoding='utf-8',newline='\n') as f: json.dump(x,f,indent=2,sort_keys=True); f.write('\n')
def write_csv(p,rows,fields):
    with p.open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n'); w.writeheader(); w.writerows(rows)
def add(rows,cid,category,condition,observed,expected,layer):
    rows.append({"check_id":cid,"category":category,"observed":str(observed),"expected":str(expected),"failure_layer":layer,"passed":bool(condition)})

def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    checks=[]
    try:
        project=Path(a.project_root).resolve(); require(project.is_dir(),f"Project root missing: {project}")
        inputs={
          "result":Path(a.p2n_r2_result).resolve(),"files":Path(a.p2n_r2_files).resolve(),"classes":Path(a.p2n_r2_classes).resolve(),"helpers":Path(a.p2n_r2_helpers).resolve(),"insertions":Path(a.p2n_r2_insertions).resolve(),"change_boundaries":Path(a.p2n_r2_change_boundaries).resolve(),"verification":Path(a.p2n_r2_verification).resolve(),"runtime_plan":Path(a.p2n_r2_runtime_plan).resolve(),"freeze_requirements":Path(a.p2n_r2_freeze_requirements).resolve(),"identity_strategy":Path(a.p2n_r2_identity_strategy).resolve(),"claim_boundary":Path(a.p2n_r2_claim_boundary).resolve(),"binding":Path(a.p2n_r2_binding).resolve(),"external_binding":Path(a.p2n_r2_external_binding).resolve(),"manifest":Path(a.p2n_r2_manifest).resolve(),"runner":Path(a.p2n_r2_runner).resolve()
        }
        for k,p in inputs.items(): require(p.is_file(),f"Missing R2 {k}: {p}")
        result=json.loads(inputs['result'].read_text(encoding='utf-8-sig')); ext=json.loads(inputs['external_binding'].read_text(encoding='utf-8-sig')); freeze=json.loads(inputs['freeze_requirements'].read_text(encoding='utf-8-sig')); ids=json.loads(inputs['identity_strategy'].read_text(encoding='utf-8-sig')); claim=json.loads(inputs['claim_boundary'].read_text(encoding='utf-8-sig')); binding=json.loads(inputs['binding'].read_text(encoding='utf-8-sig'))
        files=list(csv.DictReader(inputs['files'].open(encoding='utf-8-sig',newline=''))); classes=list(csv.DictReader(inputs['classes'].open(encoding='utf-8-sig',newline=''))); helpers=list(csv.DictReader(inputs['helpers'].open(encoding='utf-8-sig',newline=''))); insertions=list(csv.DictReader(inputs['insertions'].open(encoding='utf-8-sig',newline=''))); boundaries=list(csv.DictReader(inputs['change_boundaries'].open(encoding='utf-8-sig',newline=''))); verification=list(csv.DictReader(inputs['verification'].open(encoding='utf-8-sig',newline=''))); runtime=list(csv.DictReader(inputs['runtime_plan'].open(encoding='utf-8-sig',newline='')))
        require(result.get('version')==PARENT_VERSION and result.get('status')==PARENT_STATUS,'R2 parent differs')
        require(ext.get('status')==PARENT_STATUS and ext.get('manifest_sha256')==PARENT_MANIFEST_SHA,'R2 external binding differs')
        require(sha(inputs['manifest'])==PARENT_MANIFEST_SHA and sha(inputs['runner'])==PARENT_RUNNER_SHA,'R2 identities differ')
        require(ext.get('implementation_authorized') is False and ext.get('implementation_created') is False and ext.get('actual_fs_read_executed') is False,'R2 boundary differs')

        # Exact three-create plus one bind-only classification.
        creates={r['path'] for r in files if r['action']=='CREATE_PROPOSED'}; binds=[r for r in files if r['action']=='BIND_ONLY_NO_CHANGE']
        add(checks,'Q01','file_inventory',len(files)==4,len(files),4,'FIXTURE')
        add(checks,'Q02','file_inventory',creates==CREATE_PATHS,';'.join(sorted(creates)),';'.join(sorted(CREATE_PATHS)),'EVIDENCE_CLASSIFICATION')
        add(checks,'Q03','file_inventory',len(binds)==1 and binds[0]['path']==BIND_PATH,binds,'one bind-only adapter','EVIDENCE_CLASSIFICATION')
        add(checks,'Q04','file_inventory',binds and binds[0]['expected_parent']==ADAPTER_SHA,binds[0]['expected_parent'] if binds else '',ADAPTER_SHA,'FIXTURE')

        # Collision review and bound input identity.
        collisions=[p for p in sorted(CREATE_PATHS) if (project/Path(p)).exists()]
        add(checks,'Q10','collision_review',not collisions,';'.join(collisions),'no proposed file exists','FIXTURE')
        adapter=project/Path(BIND_PATH)
        add(checks,'Q11','bound_identity',adapter.is_file(),str(adapter),'existing adapter file','FIXTURE')
        add(checks,'Q12','bound_identity',adapter.is_file() and sha(adapter)==ADAPTER_SHA,sha(adapter) if adapter.is_file() else 'MISSING',ADAPTER_SHA,'FIXTURE')

        # Class and helper ownership completeness.
        class_files={r['proposed_file'] for r in classes}; helper_files={r['proposed_file'] for r in helpers}
        add(checks,'Q20','ownership',len(classes)==3,len(classes),3,'DESIGN_COMPLETENESS')
        add(checks,'Q21','ownership',class_files<=CREATE_PATHS,';'.join(sorted(class_files)),'all class files are proposed creates','DESIGN_COMPLETENESS')
        add(checks,'Q22','ownership',len(helpers)==5,len(helpers),5,'DESIGN_COMPLETENESS')
        add(checks,'Q23','ownership',helper_files<=CREATE_PATHS,';'.join(sorted(helper_files)),'all helper files are proposed creates','DESIGN_COMPLETENESS')
        add(checks,'Q24','ownership',all(r['status']=='PROPOSED_NOT_IMPLEMENTED' for r in classes+helpers),';'.join(sorted({r['status'] for r in classes+helpers})),'PROPOSED_NOT_IMPLEMENTED only','CLAIM_BOUNDARY')

        # Five requirements to proposed symbols through insertion manifest.
        mapped=set()
        for r in insertions: mapped.update(r['design_contract'].split('|'))
        add(checks,'Q30','traceability',mapped==FIVE_REQUIREMENTS,';'.join(sorted(mapped)),';'.join(sorted(FIVE_REQUIREMENTS)),'REQUIREMENT_TRACEABILITY')
        symbol_text=' '.join([r['class_name']+' '+r['responsibility'] for r in classes]+[r['helper_name']+' '+r['inputs']+' '+r['outputs'] for r in helpers])
        coverage={
          'P2N-01':('TrustedOutcomeTransportV1' in symbol_text and 'after_tool' in symbol_text),
          'P2N-02':('compute_raw_output_sha256_v1' in symbol_text and 'canonicalize_post_hook_output_v1' in symbol_text),
          'P2N-03':('compute_protected_value_bound_digest_v1' in symbol_text),
          'P2N-04':('TrustedEventSequenceStateV1' in symbol_text),
          'P2N-05':('canonical_source_path_v1' in symbol_text),
        }
        for i,(req_id,ok) in enumerate(coverage.items(),31): add(checks,f'Q{i}','traceability',ok,req_id+'='+str(ok),'proposed symbol coverage true','REQUIREMENT_TRACEABILITY')

        # Wrapper proposal without packaged compatibility claim.
        wrapper=next((r for r in classes if r['class_name']=='TrustedBridgeSandboxV1'),None)
        add(checks,'Q40','wrapper_boundary',wrapper is not None,str(wrapper),'TrustedBridgeSandboxV1 present','DESIGN_COMPLETENESS')
        add(checks,'Q41','wrapper_boundary',wrapper is not None and 'opt-in' in wrapper['responsibility'] and 'preserving frozen SandboxEnv ordering' in wrapper['responsibility'],wrapper['responsibility'] if wrapper else '','opt-in wrapper preserving ordering','CLAIM_BOUNDARY')
        prohibited_text=' '.join(claim.get('prohibited',[]))+' '+' '.join(r['prohibited'] for r in boundaries)
        add(checks,'Q42','wrapper_boundary','packaged runtime integration' in prohibited_text,prohibited_text,'packaged compatibility claim prohibited','CLAIM_BOUNDARY')

        # Insertion-order consistency.
        by_id={r['insertion_id']:r for r in insertions}
        add(checks,'Q50','insertion_order',set(by_id)=={'INS-001','INS-002','INS-003','INS-004'},';'.join(sorted(by_id)),'INS-001..INS-004','AUTHORIZATION_TRANSPORT')
        add(checks,'Q51','insertion_order','before adapter.before_decide' in by_id.get('INS-001',{}).get('relative_order',''),by_id.get('INS-001',{}).get('relative_order',''),'proposal identity before before_decide','AUTHORIZATION_TRANSPORT')
        add(checks,'Q52','insertion_order','after POST_TOOL_CALL' in by_id.get('INS-002',{}).get('relative_order','') and 'before serialization' in by_id.get('INS-002',{}).get('relative_order',''),by_id.get('INS-002',{}).get('relative_order',''),'metadata after post-hook before serialization','AUTHORIZATION_TRANSPORT')
        add(checks,'Q53','insertion_order','before adapter.after_tool' in by_id.get('INS-003',{}).get('relative_order',''),by_id.get('INS-003',{}).get('relative_order',''),'protected digest before after_tool','PROVENANCE')
        add(checks,'Q54','insertion_order',all(x in by_id.get('INS-004',{}).get('relative_order','') for x in ['before serialization','trace insertion','runtime history']),by_id.get('INS-004',{}).get('relative_order',''),'after_tool before serialization/trace/history','AUTHORIZATION_TRANSPORT')

        # Prohibited existing-file enumeration with current identities.
        prohibited_paths=set(PROHIBITED_EXISTING)
        boundary_text=' '.join(r['prohibited'] for r in boundaries)
        names_ok=all(Path(p).name in boundary_text for p in prohibited_paths)
        add(checks,'Q60','immutable_sources',names_ok,boundary_text,'all prohibited filenames enumerated','FIXTURE')
        current=[]; missing=[]
        for rel in sorted(prohibited_paths):
            p=project/Path(rel)
            if not p.is_file(): missing.append(rel)
            else: current.append({"path":rel,"size_bytes":p.stat().st_size,"sha256":sha(p)})
        add(checks,'Q61','immutable_sources',not missing,';'.join(missing),'all prohibited files exist','FIXTURE')
        add(checks,'Q62','immutable_sources',any(r['verification']=='pre/post SHA-256 equality for every prohibited file' for r in boundaries),str(boundaries),'pre/post SHA-256 requirement','FIXTURE')

        # Canonicalization sufficiency.
        canon=next((r for r in helpers if r['helper_name']=='canonicalize_post_hook_output_v1'),None)
        digest=next((r for r in helpers if r['helper_name']=='compute_raw_output_sha256_v1'),None)
        add(checks,'Q70','canonicalization',canon is not None and all(x in canon['inputs'] for x in ['post-hook-finalized output','explicit type tag']) and canon['outputs']=='canonical bytes',str(canon),'value + type tag -> canonical bytes','SECRET_CAPTURE')
        add(checks,'Q71','canonicalization',canon is not None and 'unsupported/noncanonical type' in canon['failure'],canon['failure'] if canon else '','unsupported/noncanonical fail closed','SECRET_CAPTURE')
        add(checks,'Q72','canonicalization',digest is not None and digest['inputs']=='canonical bytes' and '64 uppercase hex SHA-256' in digest['outputs'],str(digest),'canonical bytes -> uppercase SHA-256','SECRET_CAPTURE')
        # A design can be implementation-ready only if exact allowed type set/encoding is specified.
        precise_types=canon is not None and any(x in canon['inputs'].lower() for x in ['str','bytes','mapping','list','bool','int','none'])
        add(checks,'Q73','canonicalization',precise_types,canon['inputs'] if canon else '','exact allowed type set and byte encoding named','SECRET_CAPTURE')

        # Snapshot ownership.
        seq=next((r for r in classes if r['class_name']=='TrustedEventSequenceStateV1'),None); snap=next((r for r in helpers if r['helper_name']=='snapshot_trusted_transport_state_v1'),None); bridge=next((r for r in classes if r['class_name']=='TrustedBridgeSandboxV1'),None)
        add(checks,'Q80','snapshot_restore',seq is not None and all(x in seq['mutable_state'] for x in ['counter_by_trace','consumed_outcome_identities']),seq['mutable_state'] if seq else '','sequence class owns both mutable fields','REPLAY_ORCHESTRATION')
        add(checks,'Q81','snapshot_restore',snap is not None and 'sequence and consumed-identity state' in snap['inputs'],snap['inputs'] if snap else '','snapshot covers sequence and consumption','REPLAY_ORCHESTRATION')
        add(checks,'Q82','snapshot_restore',bridge is not None and 'transport and sequence snapshots' in bridge['mutable_state'],bridge['mutable_state'] if bridge else '','host wrapper owns transport/sequence snapshots','REPLAY_ORCHESTRATION')

        # Staged authorization boundaries.
        stages={r['stage']:r for r in runtime}
        add(checks,'Q90','runtime_staging',set(stages)=={'R2A','R2B','R2C','R2D','R2E'},';'.join(sorted(stages)),'R2A..R2E','SOURCE_RETRIEVAL')
        add(checks,'Q91','runtime_staging',all(r['authorization']=='future_gate_required' for r in runtime),';'.join(sorted({r['authorization'] for r in runtime})),'future_gate_required only','SOURCE_RETRIEVAL')
        add(checks,'Q92','runtime_staging',stages['R2D']['tools_allowed']=='none until separately approved',stages['R2D']['tools_allowed'],'no tool until separately approved','SOURCE_RETRIEVAL')
        add(checks,'Q93','runtime_staging',stages['R2E']['tools_allowed']=='fs.read only if explicitly authorized' and stages['R2E']['source_value_allowed']=='never exported',str(stages['R2E']),'explicit authorization and never exported','SOURCE_RETRIEVAL')

        # Freeze, binding, and claim boundary completeness.
        reqs=set(freeze.get('required_after_implementation',[]))
        add(checks,'Q100','freeze',freeze.get('implementation_identity_freeze_eligible') is False,str(freeze),'freeze ineligible before implementation','FIXTURE')
        add(checks,'Q101','freeze',len(reqs)>=7,len(reqs),'>=7 freeze requirements','FIXTURE')
        add(checks,'Q102','identity_binding',all(k in ids for k in ['source_binding','runner_binding','event_binding','proposal_binding','output_binding','protected_binding','raw_value_policy']),';'.join(sorted(ids)),'complete identity strategy keys','FIXTURE')
        add(checks,'Q103','identity_binding','external binding' in ids.get('runner_binding',''),ids.get('runner_binding',''),'runner externally bound','FIXTURE')
        required_prohibited={'implementation existence','source modification','runtime wiring','actual fs.read behavior','source retrieval success','secret capture','protected-value lineage','authorization transport correctness','guardrail effectiveness','real exfiltration prevention'}
        add(checks,'Q104','claim_boundary',required_prohibited<=set(claim.get('prohibited',[])),';'.join(sorted(claim.get('prohibited',[]))),';'.join(sorted(required_prohibited)),'CLAIM_BOUNDARY')
        add(checks,'Q105','authorization',result.get('readiness',{}).get('implementation_authorized') is False and result.get('readiness',{}).get('implementation_created') is False and result.get('readiness',{}).get('controlled_actual_fs_read_eligible') is False,str(result.get('readiness')),'all authorization false','CLAIM_BOUNDARY')

        failed=[r['check_id'] for r in checks if not r['passed']]
        status='P2N_R2A_INDEPENDENT_IMPLEMENTATION_READINESS_QUALIFICATION_COMPLETE_PASS' if not failed else 'P2N_R2A_INDEPENDENT_IMPLEMENTATION_READINESS_QUALIFICATION_COMPLETE_WITH_GAPS'
        next_gate='EX6_P2B_P2O_IMPLEMENTATION_AUTHORIZATION_AND_SOURCE_GENERATION' if not failed else 'EX6_P2B_P2N_R2B_IMPLEMENTATION_PLAN_RECONCILIATION'
        # Even a pass does not itself create or authorize source. It establishes eligibility for a separate authorization gate.
        eligible=not failed
        result_out={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"READ_ONLY_INDEPENDENT_IMPLEMENTATION_READINESS_QUALIFICATION","P2N_R2_parent_verified":True,"checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"current_prohibited_source_identities":current,"readiness":{"implementation_readiness_qualified":eligible,"separate_implementation_gate_required":True,"implementation_authorized":False,"implementation_created":False,"identity_freeze_eligible":False,"controlled_actual_fs_read_eligible":False},"execution_boundaries":{"source_modified":False,"implementation_created":False,"sdk_modules_imported":False,"actual_fs_read_executed":False,"tools_executed":False,"fixture_contents_read":False,"source_value_previewed":False,"source_value_exported":False,"effects_observed":False,"sandbox_executed":False,"gym_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False},"scientific_verdict":{"implementation_readiness":"QUALIFIED_AS_PLAN_ONLY" if eligible else "GAPS_IDENTIFIED","file_collision_review":"PASS" if not collisions else "COLLISIONS_FOUND","canonicalization_contract":"SUFFICIENT_FOR_IMPLEMENTATION" if next(r for r in checks if r['check_id']=='Q73')['passed'] else "INSUFFICIENT_EXACT_TYPE_ENCODING_NOT_SPECIFIED","implementation":"NOT_IMPLEMENTED","runtime_behavior":"NOT_EVALUATED","actual_source_retrieval":"NOT_EVALUATED","secret_capture":"NOT_ESTABLISHED","protected_value_lineage":"NOT_ESTABLISHED","authorization_transport_correctness":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":{"allowed":["independent readiness qualification of the frozen R2 plan","collision and ownership findings","current prohibited-file identities","readiness eligibility recommendation"],"prohibited":["implementation existence","source modification","runtime wiring","actual fs.read behavior","source retrieval success","secret capture","protected-value lineage","authorization transport correctness","guardrail effectiveness","real exfiltration prevention"]},"next_gate":next_gate}
        rp=out/'ex6_p2b_p2n_r2a_result.json'; cp=out/'ex6_p2b_p2n_r2a_checks.csv'; ip=out/'ex6_p2b_p2n_r2a_prohibited_identities.csv'; bp=out/'ex6_p2b_p2n_r2a_binding.json'; cl=out/'ex6_p2b_p2n_r2a_claim_boundary.json'
        write_json(rp,result_out); write_csv(cp,checks,['check_id','category','observed','expected','failure_layer','passed']); write_csv(ip,current,['path','size_bytes','sha256']); write_json(cl,result_out['claim_boundary']); write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{k:ident(v) for k,v in inputs.items()},"project_root":str(project),"source_modified":False,"implementation_created":False})
        derived=(rp,cp,ip,bp,cl); bound=tuple(inputs.values()); rows=[{**ident(p),"role":"P2N_R2A_DERIVED"} for p in derived]+[{**ident(p),"role":"P2N_R2A_BOUND"} for p in bound]
        man=out/'ex6_p2b_p2n_r2a_manifest.csv'; write_csv(man,rows,['artifact','role','size_bytes','sha256','path'])
        extp=out/'ex6_p2b_p2n_r2a_manifest_external_binding.json'; write_json(extp,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":man.name,"manifest_size_bytes":man.stat().st_size,"manifest_sha256":sha(man),"runner_sha256":sha(Path(__file__).resolve()),"parent_manifest_sha256":PARENT_MANIFEST_SHA,"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"implementation_readiness_qualified":eligible,"separate_implementation_gate_required":True,"implementation_authorized":False,"implementation_created":False,"identity_freeze_eligible":False,"controlled_actual_fs_read_eligible":False,"source_modified":False,"actual_fs_read_executed":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"implementation_readiness_qualified":eligible,"implementation_authorized":False,"controlled_actual_fs_read_eligible":False,"manifest_sha256":sha(man),"next_gate":next_gate},indent=2))
    except Exception as e:
        (out/'P2N_R2A_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2N_R2A_QUALIFICATION_BLOCKED","error_type":type(e).__name__,"error":str(e),"checks_frozen":checks,"source_modified":False,"implementation_created":False,"actual_fs_read_executed":False,"effects_observed":False},indent=2),encoding='utf-8')
        raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for flag in ['p2n-r2-result','p2n-r2-files','p2n-r2-classes','p2n-r2-helpers','p2n-r2-insertions','p2n-r2-change-boundaries','p2n-r2-verification','p2n-r2-runtime-plan','p2n-r2-freeze-requirements','p2n-r2-identity-strategy','p2n-r2-claim-boundary','p2n-r2-binding','p2n-r2-external-binding','p2n-r2-manifest','p2n-r2-runner','project-root','output-dir']:
        p.add_argument('--'+flag,required=True)
    return p.parse_args()
if __name__=='__main__':
    try: main(args())
    except Exception as e: print(f"FAILED: {e}",file=sys.stderr); raise SystemExit(1)
