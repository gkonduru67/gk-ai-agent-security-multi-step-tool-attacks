#!/usr/bin/env python3
"""EX8-R2 independent parity qualification and evidence freeze.

Read-only verifier of EX8-R1's corrected static contract. It independently
rehashes EX8-R1, its EX8 v1.0 lineage, and nine authoritative SDK sources;
recomputes counts; parses source with AST; reconstructs API delegation, Sandbox
ToolEvent production and trace insertion, Sandbox/Gym/API trace export,
Gym evaluator consumers, packaged Guardrail identity, and corrected static
routes; and freezes the independently qualified static contract.

No SDK import/execution, source modification, Sandbox/Gym construction,
interaction, tool, fs.read, predicate, breach, model, HTTP, fixture value,
real secret, thread, or external effect. Runtime and hosted parity remain
NOT_EVALUATED / NOT_ESTABLISHED.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX8_INDEPENDENT_PARITY_QUALIFICATION_AND_FREEZE_v1.0"
PARENT_VERSION="EX8_R1_SOURCE_CONTRACT_RECONCILIATION_v1.0"
PARENT_STATUS="EX8_R1_SOURCE_CONTRACT_RECONCILIATION_COMPLETE_PASS"
PARENT_MANIFEST_SHA="99B6549C00B70F723214483F8C71E19C756E21AECE711FF77B449E2C4E84CA8F"
PARENT_RUNNER_SHA="56376CBE9E5BF53A16C89D20D305C3A04CF10DFF90558142FF3F8207E58DB816"
PARENT_CONTRACT_SHA="2E9EA79228A8FFF4C37276220F879C948F8767E5F26093A6CEB2DC3D9879A188"
PARENT_RECONCILIATION_SHA="319A1D3E6A7F322F19DA31353A59F14B3768608F214293ADE6D113F96ADA62C9"
PARENT_CLAIM_SHA="784DBFA5001201CA5025A596E2C829CB35DE9FD7017C062381DB6802874496CA"
ORIGINAL_EX8_MANIFEST_SHA="20F0F91E4FEC80C335A2A1F5FCEC94E12991557E2E01A788AC65DCFCAC05F622"
PARITY_ID="EX8.PROPOSAL.SANDBOX.GYM.STATIC.PARITY.V1.R1"
NORMALIZATION_ID="P2O-G.EVENT.NORMALIZATION.V1"
ORIGINAL_FAILED={"EX8-151","EX8-152","EX8-306"}
SOURCES={
 "sandbox":("aicomp_sdk/core/env/sandbox.py","B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0"),
 "gym":("aicomp_sdk/core/env/gym.py","8BBC3479515C388717D76FE9964D957A7CBD9BFB97C28AA894E9C51E3051F8AF"),
 "api":("aicomp_sdk/core/env/api.py","60F1E4424EC3DEE73186F87ED1184D2CA1DBC4C2A0022004DECEC8B6E94C7CB1"),
 "predicates":("aicomp_sdk/core/predicates.py","9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"),
 "optimal":("aicomp_sdk/guardrails/optimal.py","6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED"),
 "proposal_aware":("aicomp_sdk/guardrails/proposal_aware_optimal.py","918FFD61CDB9A406C965F06CF2BEC34C297AB231E26B6FC083AE34B00C37D452"),
 "trusted_adapter":("aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py","BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"),
 "transport":("aicomp_sdk/core/env/trusted_outcome_transport_v1.py","5C7F7D16A37896959C6F4CC769E5F72A6E5E534EE140BA5CAF2FB70661102CE1"),
 "bridge":("aicomp_sdk/core/env/sandbox_trusted_bridge_v1.py","3EE9BBB1E65949795A5639D12C55D81D8D0645357260DFC5A91DB1E9710288B6"),
}

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
def read_json(p): return json.loads(p.read_text(encoding='utf-8-sig'))
def read_csv(p):
    with p.open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def write_json(p,o):
    with p.open('x',encoding='utf-8',newline='\n') as f:json.dump(o,f,indent=2,sort_keys=True);f.write('\n')
def write_csv(p,rows,fields):
    with p.open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(rows)
def add(rows,cid,cat,passed,observed,expected,layer):
    rows.append({"check_id":cid,"category":cat,"passed":bool(passed),"observed":str(observed),"expected":str(expected),"failure_layer":layer})
def classes(tree): return {n.name:n for n in tree.body if isinstance(n,ast.ClassDef)}
def methods(cls): return {n.name for n in cls.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def calls(tree):
    out=[]
    for n in ast.walk(tree):
        if isinstance(n,ast.Call):
            try: out.append((ast.unparse(n.func),n.lineno,ast.unparse(n)))
            except Exception: pass
    return out
def contains_call(call_list,name): return any(x[0]==name for x in call_list)
def class_base(cls): return [ast.unparse(x) for x in cls.bases]

def main(a):
    out=Path(a.output_dir).resolve();require(not out.exists(),f"Refusing overwrite: {out}");out.mkdir(parents=True)
    checks=[]; architecture=[]
    try:
        project=Path(a.project_root).resolve();require(project.is_dir(),f"Missing project root: {project}")
        inputs={
          "result":Path(a.r1_result).resolve(),"checks":Path(a.r1_checks).resolve(),"contract":Path(a.r1_contract).resolve(),"reconciliation":Path(a.r1_reconciliation).resolve(),"claim":Path(a.r1_claim_boundary).resolve(),"binding":Path(a.r1_binding).resolve(),"external":Path(a.r1_external_binding).resolve(),"manifest":Path(a.r1_manifest).resolve(),"runner":Path(a.r1_runner).resolve(),
          "ex8_result":Path(a.ex8_result).resolve(),"ex8_checks":Path(a.ex8_checks).resolve(),"ex8_manifest":Path(a.ex8_manifest).resolve(),
        }
        for k,p in inputs.items():require(p.is_file(),f"Missing input {k}: {p}")
        result=read_json(inputs['result']);contract=read_json(inputs['contract']);claim=read_json(inputs['claim']);ext=read_json(inputs['external']);r1checks=read_csv(inputs['checks']);recon=read_csv(inputs['reconciliation']);ex8result=read_json(inputs['ex8_result']);ex8checks=read_csv(inputs['ex8_checks'])
        add(checks,'R2-001','identity',result.get('version')==PARENT_VERSION and result.get('status')==PARENT_STATUS,result.get('status'),PARENT_STATUS,'FIXTURE')
        add(checks,'R2-002','identity',sha(inputs['manifest'])==PARENT_MANIFEST_SHA and ext.get('manifest_sha256')==PARENT_MANIFEST_SHA,sha(inputs['manifest']),PARENT_MANIFEST_SHA,'FIXTURE')
        add(checks,'R2-003','identity',sha(inputs['runner'])==PARENT_RUNNER_SHA and ext.get('runner_sha256')==PARENT_RUNNER_SHA,sha(inputs['runner']),PARENT_RUNNER_SHA,'FIXTURE')
        add(checks,'R2-004','identity',sha(inputs['contract'])==PARENT_CONTRACT_SHA,sha(inputs['contract']),PARENT_CONTRACT_SHA,'FIXTURE')
        add(checks,'R2-005','identity',sha(inputs['reconciliation'])==PARENT_RECONCILIATION_SHA,sha(inputs['reconciliation']),PARENT_RECONCILIATION_SHA,'FIXTURE')
        add(checks,'R2-006','identity',sha(inputs['claim'])==PARENT_CLAIM_SHA,sha(inputs['claim']),PARENT_CLAIM_SHA,'FIXTURE')
        add(checks,'R2-007','identity',sha(inputs['ex8_manifest'])==ORIGINAL_EX8_MANIFEST_SHA,sha(inputs['ex8_manifest']),ORIGINAL_EX8_MANIFEST_SHA,'FIXTURE')

        # Counts and preservation.
        add(checks,'R2-010','counts',len(r1checks)==49 and all(r['passed']=='True' for r in r1checks),{"total":len(r1checks),"passed":sum(r['passed']=='True' for r in r1checks)},"49/49",'EVIDENCE')
        add(checks,'R2-011','counts',len(recon)==69 and all(r['corrected_passed']=='True' for r in recon),{"total":len(recon),"corrected_passed":sum(r['corrected_passed']=='True' for r in recon)},"69/69",'EVIDENCE')
        original_failed={r['check_id'] for r in recon if r['original_passed']=='False'}
        corrected_rows=[r for r in recon if r['classification'] in {'CONTRACT_EXPECTATION_RECONCILED','SYMBOL_IDENTITY_RECONCILED'}]
        add(checks,'R2-012','counts',original_failed==ORIGINAL_FAILED,sorted(original_failed),sorted(ORIGINAL_FAILED),'EVIDENCE')
        add(checks,'R2-013','counts',len(corrected_rows)==3 and {r['check_id'] for r in corrected_rows}==ORIGINAL_FAILED,[r['check_id'] for r in corrected_rows],sorted(ORIGINAL_FAILED),'EVIDENCE')
        ex8_failed={r['check_id'] for r in ex8checks if r['passed']=='False'}
        add(checks,'R2-014','counts',len(ex8checks)==69 and ex8_failed==ORIGINAL_FAILED and ex8result['checks']['passed']==66,{"rows":len(ex8checks),"failed":sorted(ex8_failed),"passed":ex8result['checks']['passed']},"immutable original 66/69",'EVIDENCE')

        # Source identity and independent AST reconstruction.
        trees={};texts={};source_paths={}
        for idx,(key,(rel,expected)) in enumerate(SOURCES.items(),20):
            p=project/rel;source_paths[key]=p;ok=p.is_file() and sha(p)==expected
            add(checks,f'R2-{idx:03d}','source_identity',ok,sha(p) if p.is_file() else 'MISSING',expected,'FIXTURE')
            if p.is_file():
                text=p.read_text(encoding='utf-8');texts[key]=text
                try:trees[key]=ast.parse(text,filename=str(p));parsed=True
                except SyntaxError:parsed=False
                add(checks,f'R2-{idx+20:03d}','ast_parse',parsed,key,'AST PASS','ADAPTER_PARSE')

        api_cls=classes(trees['api']);sb_cls=classes(trees['sandbox']);gym_cls=classes(trees['gym']);opt_cls=classes(trees['optimal']);tr_cls=classes(trees['transport']);br_cls=classes(trees['bridge']);pa_cls=classes(trees['proposal_aware']);ta_cls=classes(trees['trusted_adapter'])
        api_calls=calls(trees['api']);sb_calls=calls(trees['sandbox']);gym_calls=calls(trees['gym']);tr_calls=calls(trees['transport'])
        # Independent architecture checks.
        expected_api={'EnvInteractionResult','AttackEnvProtocol','DiagnosticsEnv'}
        add(checks,'R2-060','architecture',expected_api<=set(api_cls),sorted(api_cls),sorted(expected_api),'ADAPTER_PARSE')
        add(checks,'R2-061','architecture','ToolEvent' not in api_cls and 'Trace' not in api_cls,sorted(api_cls),'API not direct owner','ADAPTER_PARSE')
        dm=methods(api_cls['DiagnosticsEnv'])
        add(checks,'R2-062','architecture',{'interact','export_trace_dict','snapshot','restore'}<=dm,sorted(dm),'API delegation methods','ROUTING')
        add(checks,'R2-063','architecture',all(contains_call(api_calls,x) for x in ['self._inner.interact','self._inner.export_trace_dict','self._inner.snapshot','self._inner.restore']),[x[0] for x in api_calls],'API inner delegation calls','ROUTING')
        tool_calls=[x for x in sb_calls if x[0]=='ToolEvent']
        add(checks,'R2-064','architecture','SandboxEnv' in sb_cls and len(tool_calls)==3,{"classes":sorted(sb_cls),"ToolEvent_calls":len(tool_calls)},'Sandbox and 3 ToolEvent calls','TOOL_CALL_SERIALIZATION')
        add(checks,'R2-065','architecture',contains_call(sb_calls,'self.trace.add_tool'),[x[0] for x in sb_calls],'Sandbox trace insertion','ROUTING')
        add(checks,'R2-066','architecture','export_trace_dict' in methods(sb_cls['SandboxEnv']),sorted(methods(sb_cls['SandboxEnv'])),'Sandbox trace export','ROUTING')
        add(checks,'R2-067','architecture','export_trace_dict' in methods(gym_cls['GymAttackEnv']) and contains_call(gym_calls,'self._sandbox.export_trace_dict'),[x[0] for x in gym_calls],'Gym trace export delegation','ROUTING')
        add(checks,'R2-068','architecture',contains_call(gym_calls,'eval_predicates') and contains_call(gym_calls,'is_breach'),[x[0] for x in gym_calls],'Gym evaluator consumers','EVALUATOR')
        add(checks,'R2-069','architecture','Guardrail' in opt_cls and class_base(opt_cls['Guardrail'])==['GuardrailBase'] and 'OptimalGuardrail' not in opt_cls,{"classes":sorted(opt_cls),"bases":class_base(opt_cls['Guardrail'])},'Guardrail extends GuardrailBase','ADAPTER_PARSE')
        add(checks,'R2-070','architecture',{'decide','track_untrusted_content'}<=methods(opt_cls['Guardrail']),sorted(methods(opt_cls['Guardrail'])),'packaged Guardrail interface','ADAPTER_PARSE')

        # Corrected routes independently reconstructed.
        routes={
          'proposal_to_guardrail':contains_call(sb_calls,'self.guardrail.decide'),
          'successful_and_failed_event_shapes':len(tool_calls)==3,
          'gym_to_sandbox_delegation':contains_call(gym_calls,'self._sandbox.interact') and contains_call(gym_calls,'self.step'),
          'api_trace_export_delegation':contains_call(api_calls,'self._inner.export_trace_dict'),
          'sandbox_trace_export':'export_trace_dict' in methods(sb_cls['SandboxEnv']),
          'gym_trace_export_delegation':contains_call(gym_calls,'self._sandbox.export_trace_dict'),
          'bridge_to_transport_snapshot':'TrustedBridgeSandboxV1' in br_cls and 'trusted_transport_snapshot' in methods(br_cls['TrustedBridgeSandboxV1']),
          'transport_to_adapter':contains_call(tr_calls,'self.adapter.after_tool'),
          'proposal_aware_interface':'ProposalAwareOptimalGuardrail' in pa_cls and 'decide' in methods(pa_cls['ProposalAwareOptimalGuardrail']),
          'trusted_adapter_interface':'TrustedGuardrailContextAdapterV1_1' in ta_cls and {'before_decide','after_tool'}<=methods(ta_cls['TrustedGuardrailContextAdapterV1_1']),
        }
        for i,(name,ok) in enumerate(routes.items(),80):
            add(checks,f'R2-{i:03d}','route',ok,name,'STATICALLY_ESTABLISHED','ROUTING')
            architecture.append({"component":name,"status":"STATICALLY_ESTABLISHED" if ok else "NOT_ESTABLISHED","evidence":"INDEPENDENT_AST_RECONSTRUCTION"})

        # Contract and boundary consistency.
        add(checks,'R2-100','contract',contract.get('parity_id')==PARITY_ID and contract.get('status')=='CORRECTED_STATIC_CONTRACT_FROZEN',{"id":contract.get('parity_id'),"status":contract.get('status')},{"id":PARITY_ID,"status":"CORRECTED_STATIC_CONTRACT_FROZEN"},'FIXTURE')
        add(checks,'R2-101','contract',contract.get('event_normalization')==NORMALIZATION_ID,contract.get('event_normalization'),NORMALIZATION_ID,'FIXTURE')
        pkg=contract.get('packaged_baseline',{})
        add(checks,'R2-102','contract',pkg=={"actual_class":"Guardrail","base_class":"GuardrailBase","incorrect_alias":"OptimalGuardrail","logical_role":"OFFICIAL_BASELINE","source_file":"aicomp_sdk/guardrails/optimal.py"},pkg,'correct packaged baseline identity','ADAPTER_PARSE')
        add(checks,'R2-103','boundary',contract.get('runtime_parity')=='NOT_EVALUATED' and contract.get('hosted_parity')=='NOT_ESTABLISHED' and contract.get('actual_fs_read')=='NOT_EXECUTED',{k:contract.get(k) for k in ['runtime_parity','hosted_parity','actual_fs_read']},'bounded statuses','CLAIM_BOUNDARY')
        prohibited=set(claim.get('prohibited',[]));need={'runtime parity','hosted parity','Sandbox or Gym behavior','tool execution','actual fs.read behavior','protected-value lineage','guardrail effectiveness','real exfiltration prevention'}
        add(checks,'R2-104','boundary',need<=prohibited,sorted(prohibited),sorted(need),'CLAIM_BOUNDARY')
        rb=result.get('readiness',{});sv=result.get('scientific_verdict',{});eb=result.get('execution_boundaries',{})
        add(checks,'R2-105','boundary',rb.get('independent_EX8_qualification_eligible') is True and rb.get('runtime_parity_eligible') is False and rb.get('controlled_actual_fs_read_eligible') is False,rb,'independent eligible only','CLAIM_BOUNDARY')
        false_fields=['EX8_v1_0_artifacts_modified','source_modified','sdk_modules_imported','sdk_modules_executed','Sandbox_instantiated','Sandbox_interact_executed','Gym_instantiated','Gym_executed','real_tools_executed','actual_fs_read_executed','protected_fixture_values_used','real_secret_values_used','http_sink_executed','predicates_executed','breach_executed','models_used','external_effects_observed']
        add(checks,'R2-106','boundary',all(eb.get(k) is False for k in false_fields),{k:eb.get(k) for k in false_fields},'all false','CLAIM_BOUNDARY')
        add(checks,'R2-107','boundary',sv.get('harness_trick')=='NOT_DEMONSTRATED' and sv.get('robust_security_findings')=='NOT_ESTABLISHED',sv,'bounded scientific verdict','CLAIM_BOUNDARY')

        failed=[r['check_id'] for r in checks if not r['passed']];qualified=not failed
        status='EX8_INDEPENDENT_PARITY_QUALIFICATION_AND_FREEZE_COMPLETE_PASS' if qualified else 'EX8_INDEPENDENT_PARITY_QUALIFICATION_COMPLETE_WITH_GAPS'
        next_gate='CONTROLLED_FIXTURE_MEDIATED_REAL_CHAIN_PREFLIGHT' if qualified else 'EX8_R3_INDEPENDENT_PARITY_RECONCILIATION'
        frozen={
          "freeze_id":"EX8.INDEPENDENT.STATIC.PARITY.FREEZE.V1",
          "parent_parity_id":PARITY_ID,"status":"INDEPENDENTLY_QUALIFIED_AND_FROZEN" if qualified else "NOT_FROZEN",
          "event_normalization":NORMALIZATION_ID,"source_count":9,"independent_routes":routes,
          "api_role":"ENVIRONMENT_PROTOCOL_DIAGNOSTICS_AND_DELEGATION",
          "ToolEvent_producer":"aicomp_sdk/core/env/sandbox.py",
          "trace_exports":{"sandbox":"SandboxEnv.export_trace_dict","gym":"GymAttackEnv.export_trace_dict -> SandboxEnv.export_trace_dict","api":"DiagnosticsEnv.export_trace_dict -> inner.export_trace_dict"},
          "evaluator_consumers":["GymAttackEnv._info -> eval_predicates","GymAttackEnv._info -> is_breach"],
          "packaged_baseline":{"actual_class":"Guardrail","base_class":"GuardrailBase","logical_role":"OFFICIAL_BASELINE","source_file":"aicomp_sdk/guardrails/optimal.py"},
          "runtime_parity":"NOT_EVALUATED","hosted_parity":"NOT_ESTABLISHED","actual_fs_read":"NOT_EXECUTED","protected_value_lineage":"NOT_ESTABLISHED"
        }
        claim_out={"allowed":["independently qualified corrected static parity contract","independently reconstructed API, Sandbox, Gym, transport, bridge, and guardrail source routes","independently frozen source identities and cross-module ownership/delegation map","eligibility recommendation for controlled fixture-mediated real-chain preflight"],"prohibited":sorted(need|{'real secret capture','protected fixture values'})}
        result_out={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"READ_ONLY_INDEPENDENT_STATIC_PARITY_QUALIFICATION_AND_EVIDENCE_FREEZE","EX8_R1_parent_verified":True,"checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"counts":{"R1_reconciliation_controls":"49/49","R1_corrected_contract_checks":"69/69","original_EX8_preserved":"66/69","original_failures":sorted(ORIGINAL_FAILED),"corrected_rows":3},"independent_freeze":frozen,"readiness":{"controlled_fixture_mediated_real_chain_preflight_eligible":qualified,"independent_static_parity_freeze_complete":qualified,"runtime_parity_eligible":False,"controlled_actual_fs_read_eligible":False},"execution_boundaries":{"EX8_artifacts_modified":False,"EX8_R1_artifacts_modified":False,"source_modified":False,"sdk_modules_imported":False,"sdk_modules_executed":False,"Sandbox_instantiated":False,"Sandbox_interact_executed":False,"Gym_instantiated":False,"Gym_executed":False,"real_tools_executed":False,"actual_fs_read_executed":False,"protected_fixture_values_used":False,"real_secret_values_used":False,"http_sink_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False,"threads_executed":False,"external_effects_observed":False},"scientific_verdict":{"corrected_static_parity_contract":"INDEPENDENTLY_QUALIFIED_AND_FROZEN" if qualified else "GAPS_IDENTIFIED","runtime_parity":"NOT_EVALUATED","hosted_parity":"NOT_ESTABLISHED","actual_source_retrieval":"NOT_EVALUATED","protected_value_lineage":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim_out,"next_gate":next_gate}
        paths={"result":out/'ex8_r2_result.json',"checks":out/'ex8_r2_checks.csv',"architecture":out/'ex8_r2_architecture.csv',"freeze":out/'ex8_r2_static_parity_freeze.json',"claim":out/'ex8_r2_claim_boundary.json',"binding":out/'ex8_r2_binding.json'}
        write_json(paths['result'],result_out);write_csv(paths['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']);write_csv(paths['architecture'],architecture,['component','status','evidence']);write_json(paths['freeze'],frozen);write_json(paths['claim'],claim_out);write_json(paths['binding'],{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{k:ident(v) for k,v in inputs.items()},"sources":{k:ident(v) for k,v in source_paths.items()},"project_root":str(project),"source_modified":False,"sdk_modules_imported":False,"sdk_modules_executed":False})
        rows=[{**ident(p),"role":"EX8_R2_DERIVED"} for p in paths.values()]+[{**ident(p),"role":"EX8_R2_BOUND_PARENT"} for p in inputs.values()]+[{**ident(p),"role":"EX8_R2_AUTHORITATIVE_SOURCE"} for p in source_paths.values()]
        mp=out/'ex8_r2_manifest.csv';write_csv(mp,rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'ex8_r2_manifest_external_binding.json';write_json(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"parent_EX8_R1_manifest_sha256":PARENT_MANIFEST_SHA,"freeze_id":frozen['freeze_id'],"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"controlled_fixture_mediated_real_chain_preflight_eligible":qualified,"runtime_parity":"NOT_EVALUATED","hosted_parity":"NOT_ESTABLISHED","controlled_actual_fs_read_eligible":False,"source_modified":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"freeze_id":frozen['freeze_id'],"sdk_modules_imported":False,"sdk_modules_executed":False,"runtime_parity":"NOT_EVALUATED","manifest_sha256":sha(mp),"next_gate":next_gate},indent=2))
    except Exception as exc:
        (out/'EX8_R2_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"EX8_R2_QUALIFICATION_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"checks_frozen":checks,"source_modified":False,"sdk_modules_imported":False,"sdk_modules_executed":False,"actual_fs_read_executed":False,"effects_observed":False},indent=2),encoding='utf-8');raise

def parse_args():
    p=argparse.ArgumentParser(description=VERSION)
    for flag in ['r1-result','r1-checks','r1-contract','r1-reconciliation','r1-claim-boundary','r1-binding','r1-external-binding','r1-manifest','r1-runner','ex8-result','ex8-checks','ex8-manifest','project-root','output-dir']:
        p.add_argument('--'+flag,required=True)
    return p.parse_args()
if __name__=='__main__':
    try:main(parse_args())
    except Exception as exc:print(f"FAILED: {exc}",file=sys.stderr);raise SystemExit(1)
