#!/usr/bin/env python3
"""EX9-R2 acknowledgement integration requirements and feasibility freeze.

Read-only static review. Binds EX9-R1 and authoritative sources, discovers the
HookRegistry / HookContext / HookStage definitions and registration call sites,
inspects callback ordering, exception, snapshot, restore, reset, and duplicate
registration semantics, evaluates bridge / transport / adapter compatibility,
and freezes the minimum post-tool acknowledgement integration requirements.

This runner creates no implementation and imports or executes no SDK module,
Sandbox, Gym, tool, fs.read, HTTP, predicate, breach logic, model, or thread.
Static feasibility does not establish runtime integration behavior.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX9_R2_ACKNOWLEDGEMENT_INTEGRATION_REQUIREMENTS_AND_FEASIBILITY_FREEZE_v1.0"
PARENT_VERSION="CONTROLLED_FIXTURE_MEDIATED_REAL_CHAIN_PREFLIGHT_R1_RECONCILIATION_v1.0"
PARENT_STATUS="CONTROLLED_FIXTURE_MEDIATED_REAL_CHAIN_PREFLIGHT_R1_RECONCILIATION_COMPLETE_WITH_GAPS"
PARENT_MANIFEST_SHA="08AA82D196B4F30317171CAF59B6E84B6EC81F8E9EED58E997E35CCCB998B3BA"
PARENT_RUNNER_SHA="DD281176A55277B5A2A6ED3D8ACF599C195220371503E6A8689E355C213F67D7"
PARENT_CONTRACT_SHA="3F269B7778697BD30A3F920FFE236705743AF01D4914F191C282E9CF0B3038C9"
PARENT_DISCOVERY_SHA="2CA0B8D6F0A23917B6C6CD66E922ABE536853AADB63719B1EB838D6A985E0D4E"
P2OG_FREEZE_ID="P2O-G.EVENT.NORMALIZATION.V1"
KNOWN={
 "sandbox":("aicomp_sdk/core/env/sandbox.py","B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0"),
 "bridge":("aicomp_sdk/core/env/sandbox_trusted_bridge_v1.py","3EE9BBB1E65949795A5639D12C55D81D8D0645357260DFC5A91DB1E9710288B6"),
 "transport":("aicomp_sdk/core/env/trusted_outcome_transport_v1.py","5C7F7D16A37896959C6F4CC769E5F72A6E5E534EE140BA5CAF2FB70661102CE1"),
 "adapter":("aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py","BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"),
}

def now():return datetime.now(timezone.utc).isoformat()
def req(c,m):
    if not c:raise ValueError(m)
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
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
def add(rows,cid,cat,passed,obs,exp,layer):rows.append({"check_id":cid,"category":cat,"passed":bool(passed),"observed":str(obs),"expected":str(exp),"failure_layer":layer})
def up(n):
    try:return ast.unparse(n)
    except:return "UNPARSE_FAILED"
def parse(p):
    t=Path(p).read_text(encoding='utf-8');return t,ast.parse(t,filename=str(p))
def classes(t):return {n.name:n for n in t.body if isinstance(n,ast.ClassDef)}
def funcs(t):return [n for n in ast.walk(t) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]
def methods(c):return {n.name:n for n in c.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def signature(f):
    if not f:return None
    pos=[a.arg for a in f.args.posonlyargs+f.args.args]
    if pos and pos[0] in {'self','cls'}:pos=pos[1:]
    return {"positional":pos,"keyword_only":[a.arg for a in f.args.kwonlyargs],"vararg":f.args.vararg.arg if f.args.vararg else None,"kwarg":f.args.kwarg.arg if f.args.kwarg else None}
def calls(t):
    out=[]
    for n in ast.walk(t):
        if isinstance(n,ast.Call):out.append({"line":n.lineno,"call":up(n.func),"expression":up(n)})
    return out
def assigns(t):
    out=[]
    for n in ast.walk(t):
        if isinstance(n,(ast.Assign,ast.AnnAssign)):
            tg=n.targets if isinstance(n,ast.Assign) else [n.target];out.append({"line":n.lineno,"target":";".join(up(x) for x in tg),"value":up(n.value) if n.value else ''})
    return out
def has_call(rows,*names):return any(any(r['call']==x or r['call'].endswith('.'+x) for x in names) for r in rows)
def method_has(cls,name,tokens):
    f=methods(cls).get(name)
    if not f:return False
    s=up(f);return all(x in s for x in tokens)

def main(a):
    out=Path(a.output_dir).resolve();req(not out.exists(),f"Refusing overwrite: {out}");out.mkdir(parents=True)
    checks=[];evidence=[];requirements=[]
    try:
        root=Path(a.project_root).resolve();sdk=root/'aicomp_sdk';req(sdk.is_dir(),f"Missing SDK root: {sdk}")
        parent={"result":Path(a.r1_result).resolve(),"checks":Path(a.r1_checks).resolve(),"discovery":Path(a.r1_discovery).resolve(),"contract":Path(a.r1_contract).resolve(),"claim":Path(a.r1_claim_boundary).resolve(),"binding":Path(a.r1_binding).resolve(),"external":Path(a.r1_external_binding).resolve(),"manifest":Path(a.r1_manifest).resolve(),"runner":Path(a.r1_runner).resolve()}
        for k,p in parent.items():req(p.is_file(),f"Missing R1 {k}: {p}")
        pr=rj(parent['result']);pc=rj(parent['contract']);pe=rj(parent['external']);pchecks=rc(parent['checks']);pdisc=rc(parent['discovery'])
        add(checks,'F-001','parent',pr.get('version')==PARENT_VERSION and pr.get('status')==PARENT_STATUS,pr.get('status'),PARENT_STATUS,'FIXTURE')
        add(checks,'F-002','parent',sha(parent['manifest'])==PARENT_MANIFEST_SHA and pe.get('manifest_sha256')==PARENT_MANIFEST_SHA,sha(parent['manifest']),PARENT_MANIFEST_SHA,'FIXTURE')
        add(checks,'F-003','parent',sha(parent['runner'])==PARENT_RUNNER_SHA and pe.get('runner_sha256')==PARENT_RUNNER_SHA,sha(parent['runner']),PARENT_RUNNER_SHA,'FIXTURE')
        add(checks,'F-004','parent',sha(parent['contract'])==PARENT_CONTRACT_SHA,sha(parent['contract']),PARENT_CONTRACT_SHA,'FIXTURE')
        add(checks,'F-005','parent',sha(parent['discovery'])==PARENT_DISCOVERY_SHA,sha(parent['discovery']),PARENT_DISCOVERY_SHA,'FIXTURE')
        add(checks,'F-006','parent',pr.get('corrected_preflight',{}).get('passed')==40 and pr.get('corrected_preflight',{}).get('failed_ids')==['P2-010'],pr.get('corrected_preflight'),'40/41; P2-010 only','EVIDENCE')
        add(checks,'F-007','parent',pr.get('readiness',{}).get('controlled_actual_fs_read_eligible') is False,pr.get('readiness'),'read ineligible','CLAIM_BOUNDARY')
        add(checks,'F-008','parent',not any(r.get('kind')=='ACKNOWLEDGE_CALL' for r in pdisc),pdisc,'no prior acknowledge caller','AUTHORIZATION_TRANSPORT')

        paths={k:root/rel for k,(rel,_) in KNOWN.items()};texts={};trees={}
        for i,(k,p) in enumerate(paths.items(),10):
            expected=KNOWN[k][1];ok=p.is_file() and sha(p)==expected;add(checks,f'F-{i:03d}','source',ok,sha(p) if p.is_file() else 'MISSING',expected,'FIXTURE')
            if p.is_file():
                try:texts[k],trees[k]=parse(p);parsed=True
                except:parsed=False
                add(checks,f'F-{i+10:03d}','source',parsed,k,'AST PASS','ADAPTER_PARSE')

        # Discover hook definitions and registration across SDK.
        pyfiles=sorted(sdk.rglob('*.py'));parsed={}
        for p in pyfiles:
            try:text,tree=parse(p);parsed[p]=(text,tree)
            except:pass
        hook_classes=[];hook_calls=[];ack_calls=[]
        for p,(text,tree) in parsed.items():
            rel=str(p.relative_to(root));cls=classes(tree)
            for name,node in cls.items():
                if name in {'HookRegistry','HookContext','HookStage'} or 'Hook' in name:
                    hook_classes.append({"relative_path":rel,"symbol":name,"line":node.lineno,"bases":";".join(up(x) for x in node.bases),"methods":";".join(methods(node))})
            for r in calls(tree):
                low=r['expression'].lower()
                if 'register' in r['call'].lower() and 'hook' in low:hook_calls.append({"relative_path":rel,**r})
                if r['call'].endswith('.acknowledge') or r['call']=='acknowledge':ack_calls.append({"relative_path":rel,**r})
        # Locate HookRegistry exact owner.
        registry_hits=[];context_hits=[];stage_hits=[]
        for p,(text,tree) in parsed.items():
            cls=classes(tree)
            if 'HookRegistry' in cls:registry_hits.append((p,cls['HookRegistry'],text,tree))
            if 'HookContext' in cls:context_hits.append((p,cls['HookContext'],text,tree))
            if 'HookStage' in cls:stage_hits.append((p,cls['HookStage'],text,tree))
        add(checks,'F-030','hook',len(registry_hits)==1,[str(x[0].relative_to(root)) for x in registry_hits],'one HookRegistry owner','ADAPTER_PARSE')
        add(checks,'F-031','hook',len(context_hits)==1,[str(x[0].relative_to(root)) for x in context_hits],'one HookContext owner','ADAPTER_PARSE')
        add(checks,'F-032','hook',len(stage_hits)==1,[str(x[0].relative_to(root)) for x in stage_hits],'one HookStage owner','ADAPTER_PARSE')
        reg_cls=registry_hits[0][1] if len(registry_hits)==1 else None;reg_methods=methods(reg_cls) if reg_cls else {}
        registration_method=next((n for n in ['register','register_hook','add_hook','add'] if n in reg_methods),None)
        execute_method=next((n for n in ['execute_hooks','execute','run_hooks','run'] if n in reg_methods),None)
        snapshot_method=next((n for n in ['snapshot','snapshot_state'] if n in reg_methods),None)
        restore_method=next((n for n in ['restore','restore_state'] if n in reg_methods),None)
        reset_method='reset' if 'reset' in reg_methods else None
        add(checks,'F-033','hook',registration_method is not None,registration_method,'registration method','ROUTING')
        add(checks,'F-034','hook',execute_method is not None,execute_method,'execution method','ROUTING')
        reg_sig=signature(reg_methods.get(registration_method)) if registration_method else None
        exec_sig=signature(reg_methods.get(execute_method)) if execute_method else None
        ordering=False;failure_behavior='NOT_ESTABLISHED';duplicate='NOT_ESTABLISHED'
        if execute_method:
            src=up(reg_methods[execute_method]);ordering=any(x in src for x in ['for ', 'sorted(', 'enumerate(']);failure_behavior='PROPAGATES' if 'try:' not in src and 'except' not in src else ('HANDLED' if 'except' in src else 'NOT_ESTABLISHED')
        if registration_method:
            src=up(reg_methods[registration_method]);duplicate='ALLOWED_APPEND' if '.append(' in src and not any(x in src for x in [' if ', ' not in ', 'raise']) else ('CHECKED' if any(x in src for x in [' not in ','raise','already']) else 'NOT_ESTABLISHED')
        add(checks,'F-035','hook',ordering,ordering,True,'REPLAY_ORCHESTRATION')
        add(checks,'F-036','hook',failure_behavior!='NOT_ESTABLISHED',failure_behavior,'explicit propagate or handle','REPLAY_ORCHESTRATION')
        add(checks,'F-037','hook',True,{"snapshot":snapshot_method or 'REQUIRES_NEW_CODE',"restore":restore_method or 'REQUIRES_NEW_CODE'},'lifecycle capability explicitly classified','REPLAY_ORCHESTRATION')
        add(checks,'F-038','hook',True,reset_method or 'REQUIRES_NEW_CODE','reset capability explicitly classified','REPLAY_ORCHESTRATION')
        add(checks,'F-039','hook',True,duplicate if duplicate!='NOT_ESTABLISHED' else 'REQUIRES_NEW_CODE','duplicate behavior explicitly classified','REPLAY_ORCHESTRATION')

        # Context fields and stage.
        ctx_cls=context_hits[0][1] if len(context_hits)==1 else None
        ctx_fields=set()
        if ctx_cls:
            for n in ctx_cls.body:
                if isinstance(n,ast.AnnAssign) and isinstance(n.target,ast.Name):ctx_fields.add(n.target.id)
            init=methods(ctx_cls).get('__init__')
            if init:ctx_fields.update(signature(init)['positional']+signature(init)['keyword_only'])
        required_ctx={'tool_name','tool_args','tool_output','trace','context'}
        add(checks,'F-040','mapping',required_ctx<=ctx_fields,sorted(ctx_fields),sorted(required_ctx),'ARGUMENT_FIDELITY')
        post_stage=False
        if len(stage_hits)==1:post_stage='POST_TOOL_CALL' in stage_hits[0][2]
        add(checks,'F-041','mapping',post_stage,post_stage,True,'ROUTING')

        # Bridge current capability.
        bridge_cls=classes(trees['bridge']).get('TrustedBridgeSandboxV1');bm=methods(bridge_cls) if bridge_cls else {}
        bridge_registration=any(n in bm for n in ['register','register_hook','install','attach'])
        bridge_callback=any('hook' in n.lower() or 'post_tool' in n.lower() for n in bm)
        bridge_ack=any('acknowledge' in up(f) for f in bm.values())
        bridge_snapshot=any(n in bm for n in ['snapshot','snapshot_state'])
        bridge_restore=any(n in bm for n in ['restore','restore_state'])
        add(checks,'F-050','bridge',bridge_cls is not None,'TrustedBridgeSandboxV1' if bridge_cls else 'MISSING','class exists','ADAPTER_PARSE')
        # Capability checks are observations, not all required to pass feasibility.
        evidence.extend([
          {"component":"bridge_register_POST_TOOL_CALL","status":"SUPPORTED" if bridge_registration else "REQUIRES_NEW_CODE","evidence":sorted(bm)},
          {"component":"bridge_receive_HookContext","status":"SUPPORTED" if bridge_callback else "REQUIRES_NEW_CODE","evidence":sorted(bm)},
          {"component":"bridge_call_transport_acknowledge","status":"SUPPORTED" if bridge_ack else "REQUIRES_NEW_CODE","evidence":sorted(bm)},
          {"component":"bridge_snapshot_transport_state","status":"SUPPORTED" if bridge_snapshot else "REQUIRES_NEW_CODE","evidence":sorted(bm)},
          {"component":"bridge_restore_transport_state","status":"SUPPORTED" if bridge_restore else "REQUIRES_NEW_CODE","evidence":sorted(bm)},
        ])

        # Transport interface and atomicity.
        tr_cls=classes(trees['transport']).get('TrustedOutcomeTransportV1');tm=methods(tr_cls) if tr_cls else {};ack=tm.get('acknowledge');ack_sig=signature(ack)
        add(checks,'F-060','transport',ack is not None,ack_sig,'acknowledge method','AUTHORIZATION_TRANSPORT')
        ack_src=up(ack) if ack else ''
        requirements_atomic={
          "allocate_outcome":'allocate' in ack_src,
          "compute_raw_digest":'raw_output_sha256' in ack_src,
          "compute_bound_digest":'protected_value_sha256_or_bound_digest' in ack_src,
          "call_adapter":'after_tool' in ack_src,
          "consume_after_adapter":ack_src.find('after_tool')!=-1 and ack_src.find('consume')>ack_src.find('after_tool'),
          "adapter_exception_propagates":'try:' not in ack_src or 'except' not in ack_src,
        }
        for i,(k,v) in enumerate(requirements_atomic.items(),61):add(checks,f'F-{i:03d}','atomicity',v,k,True,'AUTHORIZATION_TRANSPORT')

        # Exact proposed mapping requirements. canonical source / identities are not in HookContext and require trusted enrichment.
        mapping=[
          ("HookContext.tool_name","acknowledge.tool_name","DIRECT" if 'tool_name' in ctx_fields else "NOT_ESTABLISHED"),
          ("HookContext.tool_args","acknowledge.tool_args","DIRECT" if 'tool_args' in ctx_fields else "NOT_ESTABLISHED"),
          ("HookContext.tool_output","acknowledge.raw_output","DIRECT" if 'tool_output' in ctx_fields else "NOT_ESTABLISHED"),
          ("HookContext.context.ok","acknowledge.success","CONTEXT_EXTRACTION" if 'context' in ctx_fields else "NOT_ESTABLISHED"),
          ("HookContext.context.error","failure metadata","CONTEXT_EXTRACTION" if 'context' in ctx_fields else "NOT_ESTABLISHED"),
          ("trusted ToolEvent.source","acknowledge.canonical_source_path","TRUSTED_ENRICHMENT_REQUIRED"),
          ("trusted trace identity","acknowledge.trace_identity","TRUSTED_ENRICHMENT_REQUIRED"),
          ("trusted proposal identity","acknowledge.proposal_identity","TRUSTED_ENRICHMENT_REQUIRED"),
        ]
        for src,dst,status in mapping:requirements.append({"requirement_type":"ARGUMENT_MAPPING","source":src,"target":dst,"status":status,"mandatory":True})
        mapping_complete=all(x[2]!='NOT_ESTABLISHED' for x in mapping)
        add(checks,'F-070','mapping',mapping_complete,mapping,'all mapping requirements classified','ARGUMENT_FIDELITY')

        # Decision: existing bridge cannot call acknowledge => a new trusted hook adapter required if registry/transport interfaces feasible.
        hook_feasible=registration_method is not None and execute_method is not None and post_stage and required_ctx<=ctx_fields
        transport_feasible=ack is not None and all(requirements_atomic.values())
        if hook_feasible and transport_feasible:
            if bridge_registration and bridge_callback and bridge_ack:
                decision='CONFIGURATION_WIRING_ONLY'
            else:
                decision='NEW_TRUSTED_HOOK_ADAPTER_REQUIRED'
        elif hook_feasible and not transport_feasible:
            decision='TRANSPORT_INTERFACE_CHANGE_REQUIRED'
        else:
            decision='NOT_FEASIBLE_WITH_CURRENT_INTERFACES'
        allowed={'CONFIGURATION_WIRING_ONLY','NEW_TRUSTED_HOOK_ADAPTER_REQUIRED','NEW_BRIDGE_SUBCLASS_REQUIRED','TRANSPORT_INTERFACE_CHANGE_REQUIRED','NOT_FEASIBLE_WITH_CURRENT_INTERFACES'}
        add(checks,'F-080','decision',decision in allowed,decision,sorted(allowed),'AUTHORIZATION_TRANSPORT')

        # Freeze minimum requirements regardless of implementation outcome.
        for rid,statement in [
          ('ACK-001','New implementation must use a distinct filename and class; frozen SDK sources remain unmodified.'),
          ('ACK-002','Register exactly one trusted POST_TOOL_CALL callback using the authoritative HookRegistry registration interface.'),
          ('ACK-003','Callback must receive HookContext and fail closed on missing tool_name, tool_args, tool_output, ok, trace, canonical source, or proposal identity.'),
          ('ACK-004','Callback must derive canonical_source_path only from trusted ToolEvent/source state, never model-provided arguments alone.'),
          ('ACK-005','Callback must invoke TrustedOutcomeTransportV1.acknowledge exactly once per unique source event.'),
          ('ACK-006','Outcome allocation and digest computation precede adapter.after_tool; consumption follows successful adapter acknowledgement only.'),
          ('ACK-007','Adapter exceptions propagate and leave the allocated outcome unconsumed.'),
          ('ACK-008','Duplicate and replay handling bind trace, proposal, source-event, outcome, acknowledgement, and consumption identities.'),
          ('ACK-009','Snapshot, restore, and reset include callback registration state and trusted transport state deterministically.'),
          ('ACK-010','Callback ordering relative to other POST_TOOL_CALL hooks must be frozen before runtime qualification.'),
          ('ACK-011','Callback failure must not fabricate a successful tool outcome or lineage.'),
          ('ACK-012','Implementation gate remains synthetic and must not execute fs.read, HTTP, predicates, breach, models, Sandbox, or Gym.'),
        ]:requirements.append({"requirement_type":"NORMATIVE","source":rid,"target":statement,"status":"REQUIRED","mandatory":True})

        failed=[x['check_id'] for x in checks if not x['passed']]
        review_complete=not failed and decision!='NOT_FEASIBLE_WITH_CURRENT_INTERFACES'
        status='EX9_R2_ACKNOWLEDGEMENT_INTEGRATION_REQUIREMENTS_AND_FEASIBILITY_FREEZE_COMPLETE_PASS' if review_complete else 'EX9_R2_ACKNOWLEDGEMENT_INTEGRATION_REQUIREMENTS_AND_FEASIBILITY_FREEZE_COMPLETE_WITH_GAPS'
        next_gate='ACKNOWLEDGEMENT_INTEGRATION_IMPLEMENTATION_AND_IDENTITY_FREEZE' if review_complete else 'EX9_R2_REQUIREMENTS_RECONCILIATION'
        freeze={"freeze_id":"EX9.ACK.INTEGRATION.REQUIREMENTS.FEASIBILITY.V1","status":"FROZEN" if review_complete else "NOT_FROZEN","parent_EX9_R1":"40_OF_41_WITH_ACKNOWLEDGEMENT_GAP","decision":decision,"hook_registry":{"owner":str(registry_hits[0][0].relative_to(root)) if len(registry_hits)==1 else "NOT_ESTABLISHED","registration_method":registration_method,"registration_signature":reg_sig,"execute_method":execute_method,"execute_signature":exec_sig,"ordering":ordering,"callback_failure_behavior":failure_behavior,"snapshot_method":snapshot_method,"restore_method":restore_method,"reset_method":reset_method,"duplicate_registration_behavior":duplicate},"hook_context":{"owner":str(context_hits[0][0].relative_to(root)) if len(context_hits)==1 else "NOT_ESTABLISHED","fields":sorted(ctx_fields),"POST_TOOL_CALL":post_stage},"existing_bridge":{"class":"TrustedBridgeSandboxV1","methods":sorted(bm),"register_callback":bridge_registration,"receive_hook_context":bridge_callback,"call_acknowledge":bridge_ack,"snapshot":bridge_snapshot,"restore":bridge_restore},"transport":{"class":"TrustedOutcomeTransportV1","acknowledge_signature":ack_sig,"atomicity_requirements_observed":requirements_atomic},"argument_mapping":mapping,"normative_requirement_ids":[f'ACK-{i:03d}' for i in range(1,13)],"implementation_creation_performed":False,"runtime_behavior":"NOT_EVALUATED"}
        claim={"allowed":["authoritative hook registration, callback, lifecycle, and transport-interface feasibility findings","minimum trusted acknowledgement integration requirements","implementation outcome classification","eligibility recommendation for a separate implementation and identity-freeze gate"],"prohibited":["implementation creation","SDK source modification","runtime acknowledgement behavior","actual fs.read","Sandbox or Gym execution","HTTP sink","predicate or breach execution","model execution","protected-value lineage","guardrail effectiveness","real exfiltration prevention"]}
        result={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"READ_ONLY_INTERFACE_REQUIREMENTS_AND_FEASIBILITY_REVIEW","EX9_R1_parent_verified":True,"checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"SDK_scan":{"python_files_scanned":len(pyfiles),"parsed_files":len(parsed),"hook_classes_found":len(hook_classes),"hook_registration_calls_found":len(hook_calls),"acknowledge_callers_found":len(ack_calls)},"feasibility":{"hook_interface_feasible":hook_feasible,"transport_interface_feasible":transport_feasible,"existing_bridge_complete":bridge_registration and bridge_callback and bridge_ack,"decision":decision},"freeze":freeze,"readiness":{"acknowledgement_integration_implementation_gate_eligible":review_complete,"controlled_actual_fs_read_eligible":False,"http_sink_eligible":False},"execution_boundaries":{"EX9_artifacts_modified":False,"source_modified":False,"implementation_created":False,"sdk_modules_imported":False,"sdk_modules_executed":False,"Sandbox_instantiated":False,"Sandbox_interact_executed":False,"Gym_executed":False,"real_tools_executed":False,"actual_fs_read_executed":False,"http_sink_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False,"threads_executed":False,"external_effects_observed":False},"scientific_verdict":{"acknowledgement_integration_requirements":"FROZEN" if review_complete else "GAPS_IDENTIFIED","implementation_behavior":"NOT_EVALUATED","actual_source_retrieval":"NOT_EVALUATED","protected_value_lineage":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim,"next_gate":next_gate}

        o={"result":out/'ex9_r2_result.json',"checks":out/'ex9_r2_checks.csv',"requirements":out/'ex9_r2_requirements.csv',"capability":out/'ex9_r2_capability_matrix.csv',"discovery":out/'ex9_r2_hook_discovery.csv',"freeze":out/'ex9_r2_requirements_freeze.json',"claim":out/'ex9_r2_claim_boundary.json',"binding":out/'ex9_r2_binding.json'}
        wj(o['result'],result);wc(o['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']);wc(o['requirements'],requirements,['requirement_type','source','target','status','mandatory']);wc(o['capability'],evidence,['component','status','evidence']);wc(o['discovery'],hook_classes+[{"relative_path":x['relative_path'],"symbol":x['call'],"line":x['line'],"bases":"","methods":x['expression']} for x in hook_calls],['relative_path','symbol','line','bases','methods']);wj(o['freeze'],freeze);wj(o['claim'],claim);wj(o['binding'],{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"parent":{k:ident(v) for k,v in parent.items()},"sources":{k:ident(v) for k,v in paths.items()},"sdk_python_files_scanned":len(pyfiles),"source_modified":False,"implementation_created":False,"sdk_modules_imported":False,"sdk_modules_executed":False})
        rows=[{**ident(p),"role":"EX9_R2_DERIVED"} for p in o.values()]+[{**ident(p),"role":"EX9_R2_BOUND_PARENT"} for p in parent.values()]+[{**ident(p),"role":"EX9_R2_AUTHORITATIVE_SOURCE"} for p in paths.values()]
        mp=out/'ex9_r2_manifest.csv';wc(mp,rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'ex9_r2_manifest_external_binding.json';wj(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"parent_EX9_R1_manifest_sha256":PARENT_MANIFEST_SHA,"freeze_id":freeze['freeze_id'],"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"decision":decision,"acknowledgement_integration_implementation_gate_eligible":review_complete,"controlled_actual_fs_read_eligible":False,"implementation_created":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"decision":decision,"freeze_id":freeze['freeze_id'],"implementation_created":False,"controlled_actual_fs_read_eligible":False,"manifest_sha256":sha(mp),"next_gate":next_gate},indent=2))
    except Exception as e:
        (out/'EX9_R2_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"EX9_R2_FEASIBILITY_BLOCKED","error_type":type(e).__name__,"error":str(e),"checks_frozen":checks,"source_modified":False,"implementation_created":False,"sdk_modules_imported":False,"sdk_modules_executed":False,"actual_fs_read_executed":False},indent=2),encoding='utf-8');raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for f in ['r1-result','r1-checks','r1-discovery','r1-contract','r1-claim-boundary','r1-binding','r1-external-binding','r1-manifest','r1-runner','project-root','output-dir']:p.add_argument('--'+f,required=True)
    return p.parse_args()
if __name__=='__main__':
    try:main(args())
    except Exception as e:print(f"FAILED: {e}",file=sys.stderr);raise SystemExit(1)
