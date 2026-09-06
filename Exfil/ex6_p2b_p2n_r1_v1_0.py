#!/usr/bin/env python3
"""EX6 P2B P2N R1 independent design qualification.

Read-only qualification of the five P2N producer design contracts. Validates
parent identities, schema/traceability completeness, ordering, fail-closed,
replay, snapshot/restore, mandatory separations, claim boundary, and
implementation feasibility. It does not modify source, create implementation,
import SDK modules, execute fs.read/tools/Sandbox/Gym/predicates/breach/models,
read fixture contents, export/preview protected values, or observe effects.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2N_R1_INDEPENDENT_DESIGN_QUALIFICATION_v1.0"
PARENT_VERSION="EX6_P2B_P2N_TRUSTED_OUTCOME_BRIDGE_AND_DIGEST_PRODUCER_DESIGN_v1.0"
PARENT_STATUS="P2N_TRUSTED_OUTCOME_BRIDGE_AND_DIGEST_PRODUCER_DESIGN_COMPLETE_PASS"
PARENT_MANIFEST_SHA="2021ACA0DDE6A5347E643039CC37CEABD765541DC96971A13CF803DFC435EF4C"
PARENT_RUNNER_SHA="CF1B0127161E28F91BF8065B2DEF66AC71558A15E7C391EC1B190302D2FA0605"
IDS=["P2N-01","P2N-02","P2N-03","P2N-04","P2N-05"]
GAPS=["after_tool runtime caller","raw_output_sha256 producer","protected_value_sha256_or_bound_digest producer","runtime event-sequence allocator","canonical_source_path producer"]
REQUIRED_AZ={f"AZ-{i:03d}" for i in range(1,8)}
REQUIRED_PV={"PV-002","PV-003","PV-004"}

def now(): return datetime.now(timezone.utc).isoformat()
def require(c,m):
    if not c: raise ValueError(m)
def sha(p:Path)->str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest().upper()
def ident(p:Path)->dict[str,Any]:
    p=p.resolve(); return {"artifact":p.name,"path":str(p),"size_bytes":p.stat().st_size,"sha256":sha(p)}
def write_json(p:Path,x:Any):
    with p.open('x',encoding='utf-8',newline='\n') as f: json.dump(x,f,indent=2,sort_keys=True); f.write('\n')
def write_csv(p:Path,rows:list[dict[str,Any]],fields:list[str]):
    with p.open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n'); w.writeheader(); w.writerows(rows)
def check(rows,cid,category,condition,evidence,expected):
    rows.append({"check_id":cid,"category":category,"expected":expected,"observed":evidence,"passed":bool(condition)})

def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    checks=[]
    try:
        paths={
          "result":Path(a.p2n_result).resolve(),"designs":Path(a.p2n_designs).resolve(),"traceability":Path(a.p2n_traceability).resolve(),"schema":Path(a.p2n_schema).resolve(),"feasibility":Path(a.p2n_feasibility).resolve(),"claim_boundary":Path(a.p2n_claim_boundary).resolve(),"binding":Path(a.p2n_binding).resolve(),"external_binding":Path(a.p2n_external_binding).resolve(),"manifest":Path(a.p2n_manifest).resolve(),"runner":Path(a.p2n_runner).resolve()
        }
        for k,p in paths.items(): require(p.is_file(),f"Missing P2N {k}: {p}")
        result=json.loads(paths['result'].read_text(encoding='utf-8-sig')); schema=json.loads(paths['schema'].read_text(encoding='utf-8-sig')); feas=json.loads(paths['feasibility'].read_text(encoding='utf-8-sig')); claim=json.loads(paths['claim_boundary'].read_text(encoding='utf-8-sig')); binding=json.loads(paths['binding'].read_text(encoding='utf-8-sig')); ext=json.loads(paths['external_binding'].read_text(encoding='utf-8-sig'))
        designs=list(csv.DictReader(paths['designs'].open(encoding='utf-8-sig',newline=''))); trace=list(csv.DictReader(paths['traceability'].open(encoding='utf-8-sig',newline='')))
        require(result.get('version')==PARENT_VERSION and result.get('status')==PARENT_STATUS,'P2N result differs')
        require(ext.get('status')==PARENT_STATUS and ext.get('manifest_sha256')==PARENT_MANIFEST_SHA,'P2N external binding differs')
        require(sha(paths['manifest'])==PARENT_MANIFEST_SHA and sha(paths['runner'])==PARENT_RUNNER_SHA,'P2N identities differ')
        require(ext.get('actual_fs_read_executed') is False and ext.get('implementation_created') is False and ext.get('source_modified') is False,'P2N boundary differs')

        by_id={r['design_id']:r for r in designs}
        check(checks,'Q01','identity',len(designs)==5,str(len(designs)),'5 designs')
        check(checks,'Q02','identity',list(by_id)==IDS,';'.join(by_id),';'.join(IDS))
        check(checks,'Q03','identity',[by_id[x]['gap'] for x in IDS]==GAPS,';'.join(by_id[x]['gap'] for x in IDS),';'.join(GAPS))

        mandatory_fields=['proposed_host','insertion_point','inputs','outputs','ordering','failure_behavior','replay_behavior','snapshot_restore','feasibility']
        for did in IDS:
            row=by_id[did]
            for field in mandatory_fields:
                check(checks,f'{did}-{field}','contract_completeness',bool(row.get(field,'').strip()),row.get(field,''),f'{field} nonempty')
            check(checks,f'{did}-notimpl','claim_boundary','NOT_IMPLEMENTED' in row['feasibility'],row['feasibility'],'feasibility contains NOT_IMPLEMENTED')

        d1=by_id['P2N-01']; ord1=d1['ordering']
        ordered_tokens=['PRE_TOOL_CALL','before_decide','tool call','POST_TOOL_CALL','trusted metadata production','after_tool','serialization','trace event','runtime history']
        positions=[ord1.find(x) for x in ordered_tokens]
        check(checks,'Q10','ordering',all(x>=0 for x in positions) and positions==sorted(positions),ord1,'declared bridge order is complete and monotonic')
        check(checks,'Q11','fail_closed',all(x in d1['failure_behavior'].lower() for x in ['absent','malformed','replayed','rejected']),d1['failure_behavior'],'absent/malformed/replayed/rejected handled')
        check(checks,'Q12','replay','one acknowledgement' in d1['replay_behavior'].lower(),d1['replay_behavior'],'single acknowledgement')
        check(checks,'Q13','snapshot','sequence state' in d1['snapshot_restore'].lower() and 'adapter state' in d1['snapshot_restore'].lower(),d1['snapshot_restore'],'bridge and adapter state snapshot together')

        d2=by_id['P2N-02']
        check(checks,'Q20','digest_representation','post-hook-finalized output' in d2['inputs'] and 'serialized output_text' in d2['ordering'],d2['inputs']+' | '+d2['ordering'],'post-hook value selected; serialized value excluded')
        check(checks,'Q21','digest_canonicalization','type tag' in d2['inputs'] and 'canonical byte encoding' in d2['inputs'],d2['inputs'],'type tag plus canonical bytes')
        check(checks,'Q22','digest_fail_closed','blocks digest production' in d2['failure_behavior'],d2['failure_behavior'],'unsupported type blocks digest')

        d3=by_id['P2N-03']
        required_bound=['domain tag','trace identity','proposal digest','outcome event identity','canonical source path','raw_output_sha256']
        check(checks,'Q30','provenance',all(x in d3['inputs'] for x in required_bound),d3['inputs'],'all bound identity inputs')
        check(checks,'Q31','value_free','never raw protected value' in d3['outputs'],d3['outputs'],'raw protected value not exported')
        check(checks,'Q32','prerequisites',all(x in d3['ordering'] for x in ['successful fs.read','protected-path classification','canonical source path','raw-output digest']),d3['ordering'],'all lineage prerequisites')

        d4=by_id['P2N-04']
        check(checks,'Q40','sequence','proposal identity before before_decide' in d4['insertion_point'] and 'outcome identity' in d4['insertion_point'] and 'before after_tool' in d4['insertion_point'],d4['insertion_point'],'proposal/outcome allocation points')
        check(checks,'Q41','sequence','strictly monotonic per trace' in d4['ordering'],d4['ordering'],'strict monotonicity per trace')
        check(checks,'Q42','replay','cannot be reused' in d4['replay_behavior'],d4['replay_behavior'],'consumed outcome cannot be reused')
        check(checks,'Q43','snapshot',all(x in d4['snapshot_restore'] for x in ['counter','consumed identities','snapshot','restore','reset']),d4['snapshot_restore'],'counter and consumed identities snapshot/restore/reset')

        d5=by_id['P2N-05']
        check(checks,'Q50','path','resolved sandbox path' in d5['insertion_point'],d5['insertion_point'],'resolved sandbox path is authority')
        check(checks,'Q51','path','workspace-relative POSIX path with a single leading slash' in d5['outputs'],d5['outputs'],'canonical output form')
        check(checks,'Q52','path_fail_closed',all(x in d5['failure_behavior'] for x in ['outside root','ambiguity','normalization mismatch']),d5['failure_behavior'],'escape/ambiguity/mismatch fail closed')

        required_fields={'success','completion_sequence','canonical_source_path','raw_output_sha256','protected_value_sha256_or_bound_digest'}
        observed_fields=set(schema.get('trusted_tool_outcome_required_fields',{}))
        check(checks,'Q60','schema',observed_fields==required_fields,';'.join(sorted(observed_fields)),';'.join(sorted(required_fields)))
        check(checks,'Q61','schema',schema.get('event_identity',{}).get('event_kind')=='proposal|outcome',str(schema.get('event_identity')),'event kinds proposal|outcome')
        check(checks,'Q62','schema',schema.get('value_export_policy')=='raw protected value and previews prohibited in evidence artifacts',schema.get('value_export_policy',''),'value-free evidence policy')

        az={r['requirement_id'] for r in trace if r['requirement_id'].startswith('AZ-')}; pv={r['requirement_id'] for r in trace if r['requirement_id'].startswith('PV-')}
        check(checks,'Q70','traceability',az==REQUIRED_AZ,';'.join(sorted(az)),';'.join(sorted(REQUIRED_AZ)))
        check(checks,'Q71','traceability',pv==REQUIRED_PV,';'.join(sorted(pv)),';'.join(sorted(REQUIRED_PV)))
        check(checks,'Q72','traceability',all(r['coverage']=='DESIGNED_NOT_IMPLEMENTED' for r in trace),';'.join(sorted({r['coverage'] for r in trace})),'DESIGNED_NOT_IMPLEMENTED only')
        check(checks,'Q73','traceability',all(r['design_id'] in IDS for r in trace),';'.join(sorted({r['design_id'] for r in trace})),'known design IDs only')

        prohibited=set(claim.get('prohibited',[]))
        required_prohibited={'implementation existence','runtime wiring','actual fs.read behavior','source retrieval success','secret capture','protected-value lineage','authorization transport correctness','guardrail effectiveness','real exfiltration prevention'}
        check(checks,'Q80','claim_boundary',required_prohibited<=prohibited,';'.join(sorted(prohibited)),'all required prohibited claims')
        check(checks,'Q81','feasibility',feas.get('overall')=='DESIGN_FEASIBLE_BUT_NOT_IMPLEMENTED' and feas.get('implementation_authorized') is False and feas.get('controlled_actual_fs_read_eligible') is False,str(feas),'feasible design, no implementation/read authorization')
        check(checks,'Q82','baseline',feas.get('immutable_baseline_policy')=='packaged OptimalGuardrail remains unmodified',feas.get('immutable_baseline_policy',''),'packaged baseline unmodified')

        failed=[r['check_id'] for r in checks if not r['passed']]
        pass_count=len(checks)-len(failed)
        status='P2N_R1_INDEPENDENT_DESIGN_QUALIFICATION_COMPLETE_PASS' if not failed else 'P2N_R1_INDEPENDENT_DESIGN_QUALIFICATION_COMPLETE_WITH_GAPS'
        next_gate='EX6_P2B_P2N_R2_IMPLEMENTATION_READINESS_AND_CHANGE_MANIFEST_SPECIFICATION' if not failed else 'EX6_P2B_P2N_R1A_DESIGN_RECONCILIATION'
        verdict={
          'insertion_point_correctness':'QUALIFIED_WITHIN_P2N_DESIGN_SCOPE' if not failed else 'GAPS_IDENTIFIED',
          'ordering_correctness':'QUALIFIED_WITHIN_P2N_DESIGN_SCOPE' if not failed else 'GAPS_IDENTIFIED',
          'replay_controls':'QUALIFIED_AS_DESIGN_ONLY' if not failed else 'GAPS_IDENTIFIED',
          'fail_closed_properties':'QUALIFIED_AS_DESIGN_ONLY' if not failed else 'GAPS_IDENTIFIED',
          'snapshot_restore_completeness':'QUALIFIED_AS_DESIGN_ONLY' if not failed else 'GAPS_IDENTIFIED',
          'claim_boundary_consistency':'QUALIFIED' if not failed else 'GAPS_IDENTIFIED',
          'requirement_traceability':'COMPLETE_DESIGNED_NOT_IMPLEMENTED' if not failed else 'GAPS_IDENTIFIED',
          'implementation_feasibility':'DESIGN_FEASIBLE_NOT_IMPLEMENTED' if not failed else 'NOT_ESTABLISHED',
          'runtime_behavior':'NOT_EVALUATED','actual_source_retrieval':'NOT_EVALUATED','secret_capture':'NOT_ESTABLISHED','protected_value_lineage':'NOT_ESTABLISHED','authorization_transport_correctness':'NOT_ESTABLISHED','harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'
        }
        claim_out={'allowed':['independent structural and semantic qualification of five design contracts','design-only insertion/ordering/replay/fail-closed/snapshot findings','traceability completeness','implementation-readiness planning recommendation'],'prohibited':['implementation existence','runtime wiring','actual fs.read behavior','source retrieval success','secret capture','protected-value lineage','authorization transport correctness','guardrail effectiveness','real exfiltration prevention']}
        result_out={'version':VERSION,'created_at_utc':now(),'status':status,'classification':'READ_ONLY_INDEPENDENT_DESIGN_QUALIFICATION','P2N_parent_verified':True,'checks':{'total':len(checks),'passed':pass_count,'failed':len(failed),'failed_ids':failed},'scientific_verdict':verdict,'execution_eligibility':{'implementation_authorized':False,'controlled_actual_fs_read_eligible':False,'reason':'independent design qualification does not itself authorize implementation or runtime execution'},'execution_boundaries':{'source_modified':False,'implementation_created':False,'sdk_modules_imported':False,'actual_fs_read_executed':False,'tools_executed':False,'fixture_contents_read':False,'source_value_previewed':False,'source_value_exported':False,'effects_observed':False,'sandbox_executed':False,'gym_executed':False,'predicates_executed':False,'breach_executed':False,'models_used':False},'claim_boundary':claim_out,'next_gate':next_gate}
        rp=out/'ex6_p2b_p2n_r1_result.json'; cp=out/'ex6_p2b_p2n_r1_checks.csv'; bp=out/'ex6_p2b_p2n_r1_binding.json'; cl=out/'ex6_p2b_p2n_r1_claim_boundary.json'
        write_json(rp,result_out); write_csv(cp,checks,['check_id','category','expected','observed','passed']); write_json(cl,claim_out); write_json(bp,{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'inputs':{k:ident(v) for k,v in paths.items()},'source_modified':False,'implementation_created':False})
        derived=(rp,cp,bp,cl); bound=tuple(paths.values())
        rows=[{**ident(p),'role':'P2N_R1_DERIVED'} for p in derived]+[{**ident(p),'role':'P2N_R1_BOUND'} for p in bound]
        man=out/'ex6_p2b_p2n_r1_manifest.csv'; write_csv(man,rows,['artifact','role','size_bytes','sha256','path'])
        extp=out/'ex6_p2b_p2n_r1_manifest_external_binding.json'; write_json(extp,{'version':VERSION,'created_at_utc':now(),'status':status,'manifest_filename':man.name,'manifest_size_bytes':man.stat().st_size,'manifest_sha256':sha(man),'runner_sha256':sha(Path(__file__).resolve()),'parent_manifest_sha256':PARENT_MANIFEST_SHA,'checks_total':len(checks),'checks_passed':pass_count,'checks_failed':len(failed),'implementation_authorized':False,'controlled_actual_fs_read_eligible':False,'source_modified':False,'implementation_created':False,'actual_fs_read_executed':False,'next_gate':next_gate})
        print(json.dumps({'status':status,'checks_total':len(checks),'checks_passed':pass_count,'checks_failed':len(failed),'failed_ids':failed,'implementation_authorized':False,'controlled_actual_fs_read_eligible':False,'manifest_sha256':sha(man),'next_gate':next_gate},indent=2))
    except Exception as exc:
        (out/'P2N_R1_FAILED.json').write_text(json.dumps({'version':VERSION,'created_at_utc':now(),'status':'P2N_R1_QUALIFICATION_BLOCKED','error_type':type(exc).__name__,'error':str(exc),'checks_frozen':checks,'source_modified':False,'implementation_created':False,'actual_fs_read_executed':False,'effects_observed':False},indent=2),encoding='utf-8')
        raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for flag in ['p2n-result','p2n-designs','p2n-traceability','p2n-schema','p2n-feasibility','p2n-claim-boundary','p2n-binding','p2n-external-binding','p2n-manifest','p2n-runner','output-dir']:
        p.add_argument('--'+flag,required=True)
    return p.parse_args()
if __name__=='__main__':
    try: main(args())
    except Exception as exc: print(f"FAILED: {exc}",file=sys.stderr); raise SystemExit(1)
