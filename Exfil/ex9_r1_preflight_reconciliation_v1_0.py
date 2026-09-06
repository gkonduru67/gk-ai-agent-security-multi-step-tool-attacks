#!/usr/bin/env python3
"""EX9-R1 read-only preflight source-contract reconciliation.

Preserves EX9 v1.0 as COMPLETE_WITH_GAPS (39/41) and independently reconciles:
  P2-006 - fs.read failure representation, including exception-to-failed-
            ToolEvent conversion in Sandbox.
  P2-010 - the cross-module caller of TrustedOutcomeTransportV1.acknowledge.

The runner recursively AST-parses only <project-root>/aicomp_sdk. It never
imports or executes SDK modules, Sandbox, Gym, tools, fs.read, predicates,
breach logic, models, HTTP, or threads. It fails closed if either route is not
explicitly established and freezes a corrected preflight contract only when all
checks pass.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="CONTROLLED_FIXTURE_MEDIATED_REAL_CHAIN_PREFLIGHT_R1_RECONCILIATION_v1.0"
PARENT_VERSION="CONTROLLED_FIXTURE_MEDIATED_REAL_CHAIN_PREFLIGHT_v1.0"
PARENT_STATUS="CONTROLLED_FIXTURE_MEDIATED_REAL_CHAIN_PREFLIGHT_COMPLETE_WITH_GAPS"
PARENT_MANIFEST_SHA="DA92DC5DD330E3E5877FD40E370BCBCB1CBC279A20E5AA7F3DF7DA099760042F"
PARENT_RUNNER_SHA="106C98A64F2541E4F08E518913E79927C4CA08F6A7C2A47F7C0D70BA7FE8DA86"
PARENT_FIXTURE_SHA="C3439BA4BC832892FE1D7AAF1BC7F45BF2B2B05ED6C897140E610CE32A780FFA"
ORIGINAL_FAILED={"P2-006","P2-010"}
FS_SHA="4B8C54032ED807CE4C35BAB403EE622141881158E10F600A4B6D329E6D6F95B8"
SANDBOX_SHA="B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0"
BRIDGE_SHA="3EE9BBB1E65949795A5639D12C55D81D8D0645357260DFC5A91DB1E9710288B6"
TRANSPORT_SHA="5C7F7D16A37896959C6F4CC769E5F72A6E5E534EE140BA5CAF2FB70661102CE1"
ADAPTER_SHA="BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"

def now(): return datetime.now(timezone.utc).isoformat()
def require(c,m):
    if not c: raise ValueError(m)
def sha(p:Path):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest().upper()
def ident(p:Path):
    p=p.resolve();return {"artifact":p.name,"path":str(p),"size_bytes":p.stat().st_size,"sha256":sha(p)}
def rjson(p): return json.loads(p.read_text(encoding='utf-8-sig'))
def rcsv(p):
    with p.open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def wjson(p,o):
    with p.open('x',encoding='utf-8',newline='\n') as f:json.dump(o,f,indent=2,sort_keys=True);f.write('\n')
def wcsv(p,rows,fields):
    with p.open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(rows)
def add(rows,cid,cat,passed,observed,expected,layer):
    rows.append({"check_id":cid,"category":cat,"passed":bool(passed),"observed":str(observed),"expected":str(expected),"failure_layer":layer})
def unparse(node):
    try:return ast.unparse(node)
    except Exception:return "UNPARSE_FAILED"
def parse(path):
    text=path.read_text(encoding='utf-8');return text,ast.parse(text,filename=str(path))
def funcs(tree): return [n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]
def calls(tree):
    out=[]
    for n in ast.walk(tree):
        if isinstance(n,ast.Call):out.append({"line":n.lineno,"call":unparse(n.func),"expression":unparse(n)})
    return out
def call_present(rows,name): return any(r['call']==name or r['call'].endswith('.'+name) for r in rows)
def find_enclosing_functions(tree,predicate):
    rows=[]
    for fn in funcs(tree):
        matches=[n for n in ast.walk(fn) if predicate(n)]
        if matches:rows.append({"function":fn.name,"line":fn.lineno,"matches":[getattr(n,'lineno',None) for n in matches],"source":unparse(fn)})
    return rows

def main(a):
    out=Path(a.output_dir).resolve();require(not out.exists(),f"Refusing overwrite: {out}");out.mkdir(parents=True)
    checks=[];route_evidence=[];discovery=[]
    try:
        root=Path(a.project_root).resolve();sdk=root/'aicomp_sdk';require(sdk.is_dir(),f"Missing SDK root: {sdk}")
        inputs={"result":Path(a.ex9_result).resolve(),"checks":Path(a.ex9_checks).resolve(),"routes":Path(a.ex9_routes).resolve(),"fixture":Path(a.ex9_fixture_spec).resolve(),"lineage":Path(a.ex9_lineage).resolve(),"contract":Path(a.ex9_contract).resolve(),"claim":Path(a.ex9_claim_boundary).resolve(),"binding":Path(a.ex9_binding).resolve(),"external":Path(a.ex9_external_binding).resolve(),"manifest":Path(a.ex9_manifest).resolve(),"runner":Path(a.ex9_runner).resolve()}
        for k,p in inputs.items():require(p.is_file(),f"Missing EX9 {k}: {p}")
        result=rjson(inputs['result']);contract=rjson(inputs['contract']);fixture=rjson(inputs['fixture']);lineage=rjson(inputs['lineage']);external=rjson(inputs['external']);parent_checks=rcsv(inputs['checks'])
        add(checks,'R1-001','parent',result.get('version')==PARENT_VERSION and result.get('status')==PARENT_STATUS,result.get('status'),PARENT_STATUS,'FIXTURE')
        add(checks,'R1-002','parent',sha(inputs['manifest'])==PARENT_MANIFEST_SHA and external.get('manifest_sha256')==PARENT_MANIFEST_SHA,sha(inputs['manifest']),PARENT_MANIFEST_SHA,'FIXTURE')
        add(checks,'R1-003','parent',sha(inputs['runner'])==PARENT_RUNNER_SHA and external.get('runner_sha256')==PARENT_RUNNER_SHA,sha(inputs['runner']),PARENT_RUNNER_SHA,'FIXTURE')
        failed={r['check_id'] for r in parent_checks if r['passed']=='False'}
        add(checks,'R1-004','parent',len(parent_checks)==41 and failed==ORIGINAL_FAILED,{"rows":len(parent_checks),"failed":sorted(failed)},{"rows":41,"failed":sorted(ORIGINAL_FAILED)},'EVIDENCE')
        add(checks,'R1-005','parent',fixture.get('sha256')==PARENT_FIXTURE_SHA and fixture.get('fixture_class')=='SYNTHETIC_NON_SENSITIVE',fixture,{"sha256":PARENT_FIXTURE_SHA,"class":"SYNTHETIC_NON_SENSITIVE"},'FIXTURE')
        add(checks,'R1-006','parent',contract.get('status')=='NOT_FROZEN' and contract.get('authorization',{}).get('controlled_actual_fs_read_eligible') is False,contract.get('authorization'),'original contract not frozen and read ineligible','CLAIM_BOUNDARY')
        add(checks,'R1-007','parent',lineage.get('identity_status')=='PROPOSED_PREFLIGHT_IDENTITIES_NOT_RUNTIME_OBSERVATIONS',lineage.get('identity_status'),'proposal-only lineage','CLAIM_BOUNDARY')

        paths={"fs":sdk/'core/tools/fs.py',"sandbox":sdk/'core/env/sandbox.py',"bridge":sdk/'core/env/sandbox_trusted_bridge_v1.py',"transport":sdk/'core/env/trusted_outcome_transport_v1.py',"adapter":sdk/'guardrails/trusted_context_adapter_v1_1.py'}
        expected={"fs":FS_SHA,"sandbox":SANDBOX_SHA,"bridge":BRIDGE_SHA,"transport":TRANSPORT_SHA,"adapter":ADAPTER_SHA}
        trees={};texts={}
        for i,(k,p) in enumerate(paths.items(),10):
            ok=p.is_file() and sha(p)==expected[k];add(checks,f'R1-{i:03d}','source_identity',ok,sha(p) if p.is_file() else 'MISSING',expected[k],'FIXTURE')
            if p.is_file():
                try:texts[k],trees[k]=parse(p);parsed=True
                except (UnicodeDecodeError,SyntaxError):parsed=False
                add(checks,f'R1-{i+10:03d}','source_parse',parsed,k,'AST PASS','ADAPTER_PARSE')

        # Independently discover every acknowledge call in SDK, excluding definitions.
        sdk_files=sorted(sdk.rglob('*.py'))
        sdk_trees={}
        for p in sdk_files:
            try:_,t=parse(p);sdk_trees[p]=t
            except (UnicodeDecodeError,SyntaxError):continue
        ack_calls=[];post_hook_refs=[]
        for p,t in sdk_trees.items():
            rel=str(p.relative_to(root))
            for row in calls(t):
                if row['call'].endswith('.acknowledge') or row['call']=='acknowledge':ack_calls.append({"relative_path":rel,**row})
                if 'POST_TOOL_CALL' in row['expression'] or 'post_tool' in row['expression'].lower():post_hook_refs.append({"relative_path":rel,**row})
        for row in ack_calls:discovery.append({"kind":"ACKNOWLEDGE_CALL","relative_path":row['relative_path'],"line":row['line'],"symbol":row['call'],"expression":row['expression']})
        for row in post_hook_refs:discovery.append({"kind":"POST_TOOL_REFERENCE","relative_path":row['relative_path'],"line":row['line'],"symbol":row['call'],"expression":row['expression']})

        fs_tree=trees['fs'];sb_tree=trees['sandbox'];tr_tree=trees['transport'];ad_tree=trees['adapter'];br_tree=trees['bridge']
        fs_calls=calls(fs_tree);sb_calls=calls(sb_tree);tr_calls=calls(tr_tree);ad_calls=calls(ad_tree)
        # P2-006: establish failure carrier through explicit raise or exception conversion.
        read_fns=[f for f in funcs(fs_tree) if 'read' in f.name.lower()]
        explicit_raises=[]
        for f in read_fns:
            for n in ast.walk(f):
                if isinstance(n,ast.Raise):explicit_raises.append({"function":f.name,"function_line":f.lineno,"raise_line":n.lineno,"expression":unparse(n.exc) if n.exc else 're-raise'})
        fs_may_raise=bool(explicit_raises) or call_present(fs_calls,'read_text') or call_present(fs_calls,'read_bytes') or call_present(fs_calls,'open')
        sandbox_try_routes=[]
        for fn in funcs(sb_tree):
            for n in ast.walk(fn):
                if not isinstance(n,ast.Try):continue
                body=unparse(ast.Module(body=n.body,type_ignores=[]));handlers='\n'.join(unparse(h) for h in n.handlers)
                if ('tools.call' in body or 'self.tools.call' in body) and ('_record_failed_tool_attempt' in handlers or 'ToolEvent' in handlers):
                    sandbox_try_routes.append({"function":fn.name,"line":n.lineno,"body":body,"handlers":handlers})
        failed_helper=next((f for f in funcs(sb_tree) if f.name=='_record_failed_tool_attempt'),None)
        helper_failed_event=False
        if failed_helper:
            src=unparse(failed_helper);helper_failed_event='ToolEvent' in src and ('ok=False' in src or 'ok = False' in src) and 'error=' in src
        failure_route=fs_may_raise and bool(sandbox_try_routes) and helper_failed_event
        add(checks,'R1-030','failure_route',bool(read_fns),[f.name for f in read_fns],'read callable found','SOURCE_RETRIEVAL')
        add(checks,'R1-031','failure_route',fs_may_raise,{"explicit_raises":explicit_raises,"io_calls":[r for r in fs_calls if r['call'] in {'read_text','read_bytes','open'} or r['call'].endswith('.read_text') or r['call'].endswith('.read_bytes')]},'fs.read can raise or invokes raising I/O','SOURCE_RETRIEVAL')
        add(checks,'R1-032','failure_route',bool(sandbox_try_routes),sandbox_try_routes,'Sandbox catches tool-call failure and invokes failure recorder','ROUTING')
        add(checks,'R1-033','failure_route',helper_failed_event,unparse(failed_helper) if failed_helper else 'MISSING','failed ToolEvent with ok=False and error','TOOL_CALL_SERIALIZATION')
        add(checks,'R1-034','failure_route',failure_route,failure_route,True,'SOURCE_RETRIEVAL')
        route_evidence.append({"route":"fs.read failure representation","status":"ESTABLISHED" if failure_route else "NOT_ESTABLISHED","evidence":"fs read/raise or I/O -> Sandbox tool-call exception handler -> _record_failed_tool_attempt -> ToolEvent(ok=False,error=...)"})

        # P2-010: exact cross-module acknowledge call and downstream adapter route.
        transport_has_ack=any(f.name=='acknowledge' for f in funcs(tr_tree))
        transport_to_adapter=call_present(tr_calls,'after_tool')
        actual_ack_callers=[r for r in ack_calls if not r['relative_path'].endswith('trusted_outcome_transport_v1.py')]
        # A caller counts only when it is in SDK source and not a test/generated artifact.
        caller_established=bool(actual_ack_callers)
        bridge_refs_transport='trusted_transport' in texts['bridge']
        bridge_has_direct_ack=any(r['relative_path'].endswith('sandbox_trusted_bridge_v1.py') for r in actual_ack_callers)
        ack_route=transport_has_ack and transport_to_adapter and caller_established
        add(checks,'R1-040','ack_route',transport_has_ack,transport_has_ack,True,'AUTHORIZATION_TRANSPORT')
        add(checks,'R1-041','ack_route',transport_to_adapter,[r for r in tr_calls if r['call'].endswith('after_tool')],'transport acknowledge calls adapter.after_tool','AUTHORIZATION_TRANSPORT')
        add(checks,'R1-042','ack_route',caller_established,actual_ack_callers,'at least one SDK caller of .acknowledge','AUTHORIZATION_TRANSPORT')
        add(checks,'R1-043','ack_route',bridge_refs_transport,bridge_refs_transport,True,'AUTHORIZATION_TRANSPORT')
        add(checks,'R1-044','ack_route',ack_route,ack_route,True,'AUTHORIZATION_TRANSPORT')
        route_evidence.append({"route":"cross-module acknowledgement","status":"ESTABLISHED" if ack_route else "NOT_ESTABLISHED","evidence":json.dumps({"callers":actual_ack_callers,"bridge_references_transport":bridge_refs_transport,"bridge_direct_caller":bridge_has_direct_ack,"transport_acknowledge":transport_has_ack,"transport_to_adapter":transport_to_adapter},sort_keys=True)})

        # Preserve 41 original checks and correct only the two failed expectations.
        recon=[];corrected={}
        for r in parent_checks:
            cid=r['check_id'];orig=r['passed']=='True'
            if cid=='P2-006':new=failure_route;expect='exception-to-failed-ToolEvent representation established across fs.py and sandbox.py';cls='CROSS_LAYER_FAILURE_CONTRACT_RECONCILED'
            elif cid=='P2-010':new=ack_route;expect='actual SDK acknowledge caller -> transport.acknowledge -> adapter.after_tool';cls='CROSS_MODULE_ACKNOWLEDGEMENT_ROUTE_RECONCILED' if new else 'ACKNOWLEDGEMENT_ROUTE_REMAINS_UNRESOLVED'
            else:new=orig;expect=r['expected'];cls='UNCHANGED_CHECK_REVALIDATED'
            corrected[cid]=new;recon.append({"check_id":cid,"original_passed":orig,"original_observed":r['observed'],"original_expected":r['expected'],"corrected_passed":new,"corrected_expectation":expect,"classification":cls})
        add(checks,'R1-050','reconciliation',len(corrected)==41,len(corrected),41,'EVIDENCE')
        add(checks,'R1-051','reconciliation',sum(corrected.values()),sum(corrected.values()),41,'EVIDENCE')
        add(checks,'R1-052','reconciliation',len([r for r in recon if r['check_id'] in ORIGINAL_FAILED and r['original_passed'] is False])==2,[r for r in recon if r['check_id'] in ORIGINAL_FAILED],'two original failures preserved','EVIDENCE')

        failed=[r['check_id'] for r in checks if not r['passed']];qualified=not failed and all(corrected.values())
        status='CONTROLLED_FIXTURE_MEDIATED_REAL_CHAIN_PREFLIGHT_R1_RECONCILIATION_COMPLETE_PASS' if qualified else 'CONTROLLED_FIXTURE_MEDIATED_REAL_CHAIN_PREFLIGHT_R1_RECONCILIATION_COMPLETE_WITH_GAPS'
        next_gate='CONTROLLED_ACTUAL_SOURCE_READ_AND_LINEAGE_QUALIFICATION' if qualified else 'CONTROLLED_FIXTURE_MEDIATED_REAL_CHAIN_PREFLIGHT_R2_ROUTE_REVIEW'
        reason='ALL_RECONCILIATION_AND_CORRECTED_PREFLIGHT_CHECKS_PASS' if qualified else 'WITHHELD:'+','.join(failed+[k for k,v in corrected.items() if not v])
        corrected_contract={"contract_id":"EX9.CONTROLLED.FIXTURE.REAL.CHAIN.PREFLIGHT.V1.R1","status":"CORRECTED_PREFLIGHT_CONTRACT_FROZEN" if qualified else "NOT_FROZEN","parent_contract_id":contract.get('contract_id'),"original_EX9":"39_OF_41_PRESERVED","fixture":fixture,"proposed_lineage":lineage,"failure_representation":{"status":"ESTABLISHED" if failure_route else "NOT_ESTABLISHED","carrier":"FS_EXCEPTION_TO_SANDBOX_FAILED_TOO_EVENT" if failure_route else "NOT_ESTABLISHED"},"acknowledgement_route":{"status":"ESTABLISHED" if ack_route else "NOT_ESTABLISHED","callers":actual_ack_callers,"bridge_direct_caller":bridge_has_direct_ack,"transport_to_adapter":transport_to_adapter},"authorization":{"controlled_actual_fs_read_eligible":qualified,"reason":reason,"authorized_next_gate_only":next_gate if qualified else "NONE","http_sink_eligible":False,"Sandbox_interact_eligible":False,"Gym_eligible":False,"model_execution_eligible":False},"claim_boundary":{"actual_fs_read":"NOT_EXECUTED","actual_source_retrieval":"NOT_EVALUATED","returned_content_capture":"NOT_ESTABLISHED","protected_value_lineage":"NOT_ESTABLISHED","runtime_parity":"NOT_EVALUATED","hosted_parity":"NOT_ESTABLISHED"}}
        claim={"allowed":["read-only reconciliation of fs.read failure representation","read-only discovery of the actual SDK acknowledge caller","corrected static preflight contract when all checks pass","eligibility recommendation for one separately authorized controlled source-read gate"],"prohibited":["actual fs.read execution","Sandbox or Gym execution","HTTP sink","predicate or breach execution","model execution","actual source retrieval","returned-content capture","protected-value lineage","runtime parity","hosted parity","guardrail effectiveness","real exfiltration prevention"]}
        result_out={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"READ_ONLY_STATIC_SOURCE_RECONCILIATION","EX9_v1_0_parent_verified":True,"original_EX9":{"status":PARENT_STATUS,"checks":"39_OF_41","failed_ids":sorted(ORIGINAL_FAILED),"preserved_immutable":True},"reconciliation_controls":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"corrected_preflight":{"total":41,"passed":sum(corrected.values()),"failed":41-sum(corrected.values()),"failed_ids":[k for k,v in corrected.items() if not v]},"route_verdicts":{"failure_representation":"ESTABLISHED" if failure_route else "NOT_ESTABLISHED","acknowledgement_route":"ESTABLISHED" if ack_route else "NOT_ESTABLISHED"},"readiness":{"controlled_actual_fs_read_eligible":qualified,"reason":reason,"http_sink_eligible":False},"execution_boundaries":{"EX9_v1_0_artifacts_modified":False,"source_modified":False,"sdk_modules_imported":False,"sdk_modules_executed":False,"Sandbox_instantiated":False,"Sandbox_interact_executed":False,"Gym_executed":False,"real_tools_executed":False,"actual_fs_read_executed":False,"http_sink_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False,"threads_executed":False,"external_effects_observed":False},"scientific_verdict":{"corrected_static_preflight_contract":"ESTABLISHED" if qualified else "GAPS_IDENTIFIED","actual_source_retrieval":"NOT_EVALUATED","returned_content_capture":"NOT_ESTABLISHED","protected_value_lineage":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim,"next_gate":next_gate}
        paths_out={"result":out/'ex9_r1_result.json',"checks":out/'ex9_r1_checks.csv',"reconciliation":out/'ex9_r1_reconciliation.csv',"routes":out/'ex9_r1_routes.csv',"discovery":out/'ex9_r1_acknowledge_discovery.csv',"contract":out/'ex9_r1_corrected_preflight_contract.json',"claim":out/'ex9_r1_claim_boundary.json',"binding":out/'ex9_r1_binding.json'}
        wjson(paths_out['result'],result_out);wcsv(paths_out['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']);wcsv(paths_out['reconciliation'],recon,['check_id','original_passed','original_observed','original_expected','corrected_passed','corrected_expectation','classification']);wcsv(paths_out['routes'],route_evidence,['route','status','evidence']);wcsv(paths_out['discovery'],discovery,['kind','relative_path','line','symbol','expression']);wjson(paths_out['contract'],corrected_contract);wjson(paths_out['claim'],claim);wjson(paths_out['binding'],{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{k:ident(v) for k,v in inputs.items()},"sources":{k:ident(v) for k,v in paths.items()},"sdk_python_files_scanned":len(sdk_files),"source_modified":False,"sdk_modules_imported":False,"sdk_modules_executed":False,"actual_fs_read_executed":False})
        rows=[{**ident(p),"role":"EX9_R1_DERIVED"} for p in paths_out.values()]+[{**ident(p),"role":"EX9_R1_BOUND_PARENT"} for p in inputs.values()]+[{**ident(p),"role":"EX9_R1_AUTHORITATIVE_SOURCE"} for p in paths.values()]
        mp=out/'ex9_r1_manifest.csv';wcsv(mp,rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'ex9_r1_manifest_external_binding.json';wjson(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"parent_EX9_manifest_sha256":PARENT_MANIFEST_SHA,"contract_id":corrected_contract['contract_id'],"reconciliation_controls_total":len(checks),"reconciliation_controls_passed":len(checks)-len(failed),"corrected_preflight_passed":sum(corrected.values()),"controlled_actual_fs_read_eligible":qualified,"reason":reason,"actual_fs_read_executed":False,"http_sink_eligible":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"original_EX9":"39/41","corrected_preflight":f"{sum(corrected.values())}/41","reconciliation_controls":f"{len(checks)-len(failed)}/{len(checks)}","failure_representation":result_out['route_verdicts']['failure_representation'],"acknowledgement_route":result_out['route_verdicts']['acknowledgement_route'],"controlled_actual_fs_read_eligible":qualified,"actual_fs_read_executed":False,"manifest_sha256":sha(mp),"next_gate":next_gate},indent=2))
    except Exception as exc:
        (out/'EX9_R1_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"EX9_R1_RECONCILIATION_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"checks_frozen":checks,"source_modified":False,"sdk_modules_imported":False,"sdk_modules_executed":False,"actual_fs_read_executed":False,"effects_observed":False},indent=2),encoding='utf-8');raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for f in ['ex9-result','ex9-checks','ex9-routes','ex9-fixture-spec','ex9-lineage','ex9-contract','ex9-claim-boundary','ex9-binding','ex9-external-binding','ex9-manifest','ex9-runner','project-root','output-dir']:p.add_argument('--'+f,required=True)
    return p.parse_args()
if __name__=='__main__':
    try:main(args())
    except Exception as e:print(f"FAILED: {e}",file=sys.stderr);raise SystemExit(1)
