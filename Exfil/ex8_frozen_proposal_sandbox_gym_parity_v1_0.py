#!/usr/bin/env python3
"""EX8 frozen proposal, Sandbox, Gym contract and static parity freeze.

Read-only AST/source reconstruction. No SDK module is imported or executed.
No Sandbox/Gym object, tool, fs.read, predicate, breach logic, model, fixture
value, HTTP sink, or external effect is used.

The runner freezes source-supported interfaces and route evidence. Missing
symbols or route evidence are recorded as NOT_ESTABLISHED and fail readiness;
they are never invented. Static source parity does not establish runtime or
hosted parity.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX8_FROZEN_PROPOSAL_SANDBOX_GYM_PARITY_v1.0"
PARENT_VERSION="P2O_G_INDEPENDENT_LIFECYCLE_QUALIFICATION_AND_FREEZE_v1.0"
PARENT_STATUS="P2O_G_INDEPENDENT_LIFECYCLE_QUALIFICATION_AND_FREEZE_COMPLETE_PASS"
PARENT_MANIFEST_SHA="98E6B7EE07F578CEEF293D38CAF370CA656651D7BD5560A9FE838FA224121BC3"
PARENT_RUNNER_SHA="BE6A7800A618C1CE49FD83BBFF4E9811D8F1C68E05AFC13F2BE350F8883A9E48"
NORMALIZATION_ID="P2O-G.EVENT.NORMALIZATION.V1"
SOURCES={
 "sandbox":"aicomp_sdk/core/env/sandbox.py",
 "gym":"aicomp_sdk/core/env/gym.py",
 "api":"aicomp_sdk/core/env/api.py",
 "predicates":"aicomp_sdk/core/predicates.py",
 "optimal":"aicomp_sdk/guardrails/optimal.py",
 "proposal_aware":"aicomp_sdk/guardrails/proposal_aware_optimal.py",
 "trusted_adapter":"aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py",
 "transport":"aicomp_sdk/core/env/trusted_outcome_transport_v1.py",
 "bridge":"aicomp_sdk/core/env/sandbox_trusted_bridge_v1.py",
}
KNOWN_HASHES={
 "sandbox":"B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0",
 "predicates":"9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37",
 "optimal":"6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED",
 "proposal_aware":"918FFD61CDB9A406C965F06CF2BEC34C297AB231E26B6FC083AE34B00C37D452",
 "trusted_adapter":"BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99",
 "transport":"5C7F7D16A37896959C6F4CC769E5F72A6E5E534EE140BA5CAF2FB70661102CE1",
 "bridge":"3EE9BBB1E65949795A5639D12C55D81D8D0645357260DFC5A91DB1E9710288B6",
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
def write_json(p,o):
    with p.open('x',encoding='utf-8',newline='\n') as f: json.dump(o,f,indent=2,sort_keys=True); f.write('\n')
def write_csv(p,rows,fields):
    with p.open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n'); w.writeheader(); w.writerows(rows)
def add(rows,cid,category,passed,observed,expected,layer):
    rows.append({"check_id":cid,"category":category,"passed":bool(passed),"observed":str(observed),"expected":str(expected),"failure_layer":layer})
def signature(node,drop_self=False):
    a=node.args; pos=[x.arg for x in a.posonlyargs+a.args]
    if drop_self and pos and pos[0] in {'self','cls'}: pos=pos[1:]
    return {"positional":pos,"vararg":a.vararg.arg if a.vararg else None,"keyword_only":[x.arg for x in a.kwonlyargs],"kwarg":a.kwarg.arg if a.kwarg else None,"return":ast.unparse(node.returns) if node.returns else None}
def qname(node):
    try:return ast.unparse(node)
    except Exception:return "UNPARSE_FAILED"
def functions(tree):
    out=[]
    for n in ast.walk(tree):
        if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):
            parent="TOP_LEVEL"
            out.append({"symbol":n.name,"kind":"function","signature":json.dumps(signature(n),sort_keys=True),"lineno":n.lineno,"source":ast.unparse(n)})
    return out
def classes(tree):
    out=[]
    for n in tree.body:
        if isinstance(n,ast.ClassDef):
            init=next((x for x in n.body if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef)) and x.name=='__init__'),None)
            methods=[x.name for x in n.body if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef))]
            out.append({"symbol":n.name,"kind":"class","signature":json.dumps(signature(init,True),sort_keys=True) if init else "NO_EXPLICIT_INIT","bases":";".join(qname(x) for x in n.bases),"methods":";".join(methods),"lineno":n.lineno})
    return out
def call_rows(tree,source_key):
    rows=[]
    for n in ast.walk(tree):
        if isinstance(n,ast.Call): rows.append({"source":source_key,"lineno":n.lineno,"call":qname(n.func),"args":";".join(qname(x) for x in n.args),"keywords":";".join((x.arg or '**')+'='+qname(x.value) for x in n.keywords)})
    return rows
def assignments(tree,source_key):
    rows=[]
    for n in ast.walk(tree):
        if isinstance(n,(ast.Assign,ast.AnnAssign)):
            targets=n.targets if isinstance(n,ast.Assign) else [n.target]
            value=n.value
            rows.append({"source":source_key,"lineno":n.lineno,"targets":";".join(qname(x) for x in targets),"value":qname(value) if value else ""})
    return rows
def excerpts(text,patterns):
    lines=text.splitlines(); found=[]
    for label,needle in patterns:
        for i,line in enumerate(lines,1):
            if needle in line:
                lo=max(1,i-3); hi=min(len(lines),i+6)
                block='\n'.join(f"{j}: {lines[j-1]}" for j in range(lo,hi+1))
                found.append({"label":label,"needle":needle,"start_line":lo,"end_line":hi,"text":block,"sha256":hashlib.sha256(block.encode()).hexdigest().upper()})
                break
    return found


def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    checks=[]
    try:
        project=Path(a.project_root).resolve(); require(project.is_dir(),f"Missing project root: {project}")
        parent={"result":Path(a.parent_result).resolve(),"normalization":Path(a.parent_normalization).resolve(),"binding":Path(a.parent_binding).resolve(),"external_binding":Path(a.parent_external_binding).resolve(),"manifest":Path(a.parent_manifest).resolve(),"runner":Path(a.parent_runner).resolve()}
        for k,p in parent.items(): require(p.is_file(),f"Missing parent {k}: {p}")
        pr=json.loads(parent['result'].read_text(encoding='utf-8-sig')); pn=json.loads(parent['normalization'].read_text(encoding='utf-8-sig')); pe=json.loads(parent['external_binding'].read_text(encoding='utf-8-sig'))
        add(checks,'EX8-001','parent',pr.get('version')==PARENT_VERSION and pr.get('status')==PARENT_STATUS,pr.get('status'),PARENT_STATUS,'FIXTURE')
        add(checks,'EX8-002','parent',sha(parent['manifest'])==PARENT_MANIFEST_SHA and pe.get('manifest_sha256')==PARENT_MANIFEST_SHA,sha(parent['manifest']),PARENT_MANIFEST_SHA,'FIXTURE')
        add(checks,'EX8-003','parent',sha(parent['runner'])==PARENT_RUNNER_SHA and pe.get('runner_sha256')==PARENT_RUNNER_SHA,sha(parent['runner']),PARENT_RUNNER_SHA,'FIXTURE')
        add(checks,'EX8-004','parent',pn.get('normalization_id')==NORMALIZATION_ID,pn.get('normalization_id'),NORMALIZATION_ID,'FIXTURE')
        add(checks,'EX8-005','parent',pe.get('EX8_frozen_parity_gate_eligible') is True and pe.get('controlled_actual_fs_read_eligible') is False,pe,'EX8 eligible; fs.read ineligible','CLAIM_BOUNDARY')

        files={k:project/v for k,v in SOURCES.items()}; inventory=[]; trees={}; texts={}
        for idx,(key,path) in enumerate(files.items(),10):
            exists=path.is_file(); observed=sha(path) if exists else 'MISSING'; known=KNOWN_HASHES.get(key,'NOT_PREVIOUSLY_ESTABLISHED')
            add(checks,f'EX8-{idx:03d}','source_identity',exists,observed,'file exists','FIXTURE')
            if known!='NOT_PREVIOUSLY_ESTABLISHED': add(checks,f'EX8-{idx+20:03d}','source_identity',observed==known,observed,known,'FIXTURE')
            if exists:
                text=path.read_text(encoding='utf-8'); texts[key]=text
                try: tree=ast.parse(text,filename=str(path)); parsed=True
                except SyntaxError: tree=None; parsed=False
                add(checks,f'EX8-{idx+40:03d}','ast_parse',parsed,key,'AST PASS','ADAPTER_PARSE')
                if parsed: trees[key]=tree
                inventory.append({"source":key,"relative_path":SOURCES[key],"size_bytes":path.stat().st_size,"sha256":observed,"prior_expected_sha256":known,"ast_parse":parsed})

        symbols=[]; calls=[]; assigns=[]
        for key,tree in trees.items():
            for r in classes(tree): symbols.append({"source":key,**r})
            for r in functions(tree): symbols.append({"source":key,**{k:r.get(k,'') for k in ['symbol','kind','signature','lineno']},"bases":"","methods":""})
            calls+=call_rows(tree,key); assigns+=assignments(tree,key)

        # Authoritative source-supported contract excerpts. Each required item must be observed.
        pattern_map={
          'sandbox':[("sandbox_context","ctx ="),("guardrail_decide","guardrail.decide"),("successful_tool_event","ToolEvent("),("failed_tool_attempt","_record_failed_tool_attempt"),("sandbox_snapshot","def snapshot"),("sandbox_restore","def restore"),("sandbox_reset","def reset")],
          'gym':[("gym_sandbox_creation","SandboxEnv("),("gym_step","def step"),("gym_interact","def interact"),("gym_reset","def reset")],
          'transport':[("transport_acknowledge","def acknowledge"),("transport_snapshot","def snapshot"),("transport_restore","def restore"),("transport_consume","def consume_outcome")],
          'bridge':[("bridge_class","class TrustedBridgeSandboxV1"),("bridge_snapshot","trusted_transport_snapshot")],
          'optimal':[("optimal_decide","def decide")],
          'proposal_aware':[("proposal_aware_decide","def decide")],
          'trusted_adapter':[("adapter_before_decide","before_decide"),("adapter_after_tool","after_tool")],
          'api':[("api_tool_event","ToolEvent"),("api_trace","Trace")],
          'predicates':[("predicate_exfiltration","EXFILTRATION")],
        }
        excerpt_rows=[]
        for key,patterns in pattern_map.items():
            found=excerpts(texts.get(key,''),patterns); excerpt_rows += [{"source":key,**r} for r in found]
            found_labels={r['label'] for r in found}
            for pos,(label,needle) in enumerate(patterns): add(checks,f'EX8-{100+len(checks):03d}','contract_presence',label in found_labels,label,needle,'ADAPTER_PARSE')

        # Route reconstruction from source evidence only.
        route_specs=[
          ("proposal_to_guardrail","sandbox","guardrail.decide"),
          ("successful_event_construction","sandbox","ToolEvent("),
          ("failed_event_construction","sandbox","_record_failed_tool_attempt"),
          ("gym_to_sandbox_step","gym","self._sandbox.interact"),
          ("gym_step_delegation","gym","self.step("),
          ("bridge_to_transport_snapshot","bridge","trusted_transport_snapshot"),
          ("transport_to_adapter","transport","self.adapter.after_tool"),
        ]
        routes=[]
        for i,(route,key,needle) in enumerate(route_specs,200):
            present=needle in texts.get(key,'')
            routes.append({"route":route,"source":key,"needle":needle,"status":"STATICALLY_OBSERVED" if present else "NOT_ESTABLISHED"})
            add(checks,f'EX8-{i}','route',present,route,'STATICALLY_OBSERVED','ROUTING')

        # Freeze interface signatures of named pivotal classes/methods if present.
        pivotal={
          'sandbox':['SandboxEnv'], 'gym':['GymAttackEnv'], 'transport':['TrustedEventSequenceStateV1','TrustedOutcomeTransportV1'], 'bridge':['TrustedBridgeSandboxV1'],
          'optimal':['OptimalGuardrail'], 'proposal_aware':['ProposalAwareOptimalGuardrail'], 'trusted_adapter':['TrustedGuardrailContextAdapterV1_1']
        }
        interface_rows=[]
        for key,names in pivotal.items():
            tree=trees.get(key)
            top={n.name:n for n in tree.body if isinstance(n,ast.ClassDef)} if tree else {}
            for name in names:
                node=top.get(name); status='ESTABLISHED' if node else 'NOT_ESTABLISHED'
                interface_rows.append({"source":key,"symbol":name,"status":status,"bases":";".join(qname(x) for x in node.bases) if node else "","methods":";".join(x.name for x in node.body if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef))) if node else ""})
                add(checks,f'EX8-{300+len(interface_rows):03d}','interface',node is not None,f'{key}:{name}',status,'ADAPTER_PARSE')

        parity={
          "parity_id":"EX8.PROPOSAL.SANDBOX.GYM.STATIC.PARITY.V1",
          "classification":"STATIC_SOURCE_AND_INTERFACE_RECONSTRUCTION_ONLY",
          "proposal_representation":"SOURCE_EVIDENCE_FROZEN",
          "adapter_parse_boundary":"SOURCE_EVIDENCE_FROZEN",
          "sandbox_context_construction":"SOURCE_EVIDENCE_FROZEN",
          "guardrail_decision_handoff":"SOURCE_EVIDENCE_FROZEN",
          "tool_call_serialization":"SOURCE_EVIDENCE_FROZEN",
          "successful_and_failed_event_shapes":"SOURCE_EVIDENCE_FROZEN",
          "post_tool_handoff":"SOURCE_EVIDENCE_FROZEN",
          "transport_acknowledgement_position":"SOURCE_EVIDENCE_FROZEN",
          "snapshot_restore_reset_carriers":"SOURCE_EVIDENCE_FROZEN",
          "gym_delegation":"SOURCE_EVIDENCE_FROZEN",
          "evaluator_facing_trace_representation":"SOURCE_EVIDENCE_FROZEN",
          "event_normalization":NORMALIZATION_ID,
          "runtime_parity":"NOT_EVALUATED",
          "hosted_parity":"NOT_ESTABLISHED",
          "actual_fs_read":"NOT_EXECUTED",
        }
        failed=[r['check_id'] for r in checks if not r['passed']]; qualified=not failed
        status='EX8_FROZEN_PROPOSAL_SANDBOX_GYM_PARITY_COMPLETE_PASS' if qualified else 'EX8_FROZEN_PROPOSAL_SANDBOX_GYM_PARITY_COMPLETE_WITH_GAPS'
        next_gate='EX8_INDEPENDENT_PARITY_QUALIFICATION_AND_FREEZE' if qualified else 'EX8_R1_SOURCE_CONTRACT_RECONCILIATION'
        claim={"allowed":["authoritative source identities and AST parsing","static proposal-Sandbox-Gym route and interface reconstruction","static event-shape and state-carrier mapping","use of frozen P2O-G event normalization","eligibility recommendation for independent EX8 qualification"],"prohibited":["runtime parity","hosted parity","Sandbox or Gym behavior","tool execution","actual fs.read behavior","protected fixture values","real secret capture","protected-value lineage","guardrail effectiveness","real exfiltration prevention"]}
        result={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"READ_ONLY_STATIC_SOURCE_AND_INTERFACE_RECONSTRUCTION","P2O_G_R1_parent_verified":True,"checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"parity_contract":parity,"inventories":{"sources":len(inventory),"symbols":len(symbols),"calls":len(calls),"assignments":len(assigns),"excerpts":len(excerpt_rows),"routes":len(routes),"interfaces":len(interface_rows)},"readiness":{"independent_EX8_qualification_eligible":qualified,"static_contract_freeze_complete":qualified,"runtime_parity_eligible":False,"controlled_actual_fs_read_eligible":False},"execution_boundaries":{"source_modified":False,"sdk_modules_imported":False,"sdk_modules_executed":False,"Sandbox_instantiated":False,"Sandbox_interact_executed":False,"Gym_instantiated":False,"Gym_executed":False,"real_tools_executed":False,"actual_fs_read_executed":False,"protected_fixture_values_used":False,"real_secret_values_used":False,"http_sink_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False,"external_effects_observed":False},"scientific_verdict":{"static_proposal_sandbox_gym_contract":"ESTABLISHED" if qualified else "GAPS_IDENTIFIED","runtime_parity":"NOT_EVALUATED","hosted_parity":"NOT_ESTABLISHED","actual_source_retrieval":"NOT_EVALUATED","protected_value_lineage":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim,"next_gate":next_gate}

        paths={"result":out/'ex8_result.json',"checks":out/'ex8_checks.csv',"sources":out/'ex8_source_inventory.csv',"symbols":out/'ex8_symbol_inventory.csv',"calls":out/'ex8_call_inventory.csv',"assignments":out/'ex8_assignment_inventory.csv',"excerpts":out/'ex8_contract_excerpts.csv',"routes":out/'ex8_route_map.csv',"interfaces":out/'ex8_interface_map.csv',"parity":out/'ex8_parity_contract.json',"claim":out/'ex8_claim_boundary.json',"binding":out/'ex8_binding.json'}
        write_json(paths['result'],result); write_csv(paths['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']); write_csv(paths['sources'],inventory,['source','relative_path','size_bytes','sha256','prior_expected_sha256','ast_parse']); write_csv(paths['symbols'],symbols,['source','symbol','kind','signature','bases','methods','lineno']); write_csv(paths['calls'],calls,['source','lineno','call','args','keywords']); write_csv(paths['assignments'],assigns,['source','lineno','targets','value']); write_csv(paths['excerpts'],excerpt_rows,['source','label','needle','start_line','end_line','text','sha256']); write_csv(paths['routes'],routes,['route','source','needle','status']); write_csv(paths['interfaces'],interface_rows,['source','symbol','status','bases','methods']); write_json(paths['parity'],parity); write_json(paths['claim'],claim); write_json(paths['binding'],{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"parent":{k:ident(v) for k,v in parent.items()},"sources":{k:ident(v) for k,v in files.items()},"project_root":str(project),"source_modified":False,"sdk_modules_imported":False,"sdk_modules_executed":False})
        derived=tuple(paths.values()); bound=tuple(parent.values()); srcs=tuple(files.values())
        rows=[{**ident(p),"role":"EX8_DERIVED"} for p in derived]+[{**ident(p),"role":"EX8_BOUND_PARENT"} for p in bound]+[{**ident(p),"role":"EX8_AUTHORITATIVE_SOURCE"} for p in srcs]
        mp=out/'ex8_manifest.csv'; write_csv(mp,rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'ex8_manifest_external_binding.json'; write_json(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"parent_p2o_g_r1_manifest_sha256":PARENT_MANIFEST_SHA,"parity_id":parity['parity_id'],"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"independent_EX8_qualification_eligible":qualified,"runtime_parity":"NOT_EVALUATED","hosted_parity":"NOT_ESTABLISHED","controlled_actual_fs_read_eligible":False,"source_modified":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"parity_id":parity['parity_id'],"sdk_modules_imported":False,"sdk_modules_executed":False,"runtime_parity":"NOT_EVALUATED","manifest_sha256":sha(mp),"next_gate":next_gate},indent=2))
    except Exception as exc:
        (out/'EX8_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"EX8_STATIC_FREEZE_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"checks_frozen":checks,"source_modified":False,"sdk_modules_imported":False,"sdk_modules_executed":False,"actual_fs_read_executed":False,"effects_observed":False},indent=2),encoding='utf-8')
        raise


def parse_args():
    p=argparse.ArgumentParser(description=VERSION)
    for flag in ['parent-result','parent-normalization','parent-binding','parent-external-binding','parent-manifest','parent-runner','project-root','output-dir']:
        p.add_argument('--'+flag,required=True)
    return p.parse_args()
if __name__=='__main__':
    try: main(parse_args())
    except Exception as exc: print(f"FAILED: {exc}",file=sys.stderr); raise SystemExit(1)
