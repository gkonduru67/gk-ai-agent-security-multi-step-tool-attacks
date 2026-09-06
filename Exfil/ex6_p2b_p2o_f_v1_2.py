#!/usr/bin/env python3
"""P2O-F controlled bridge-instance lifecycle qualification.

F0 inspects the exact SandboxEnv constructor and its source before construction.
F1 creates synthetic dependencies and one bridge instance using the explicitly supplied frozen SDK fixture root required by SandboxEnv construction. F2 tests transport identity, bridge-visible state snapshots,
pure state mutation/restore/reset, instance isolation, and fail-closed invalid
transport rejection before SandboxEnv construction.

No interact/step/tool method is called. No fs.read tool, HTTP sink, protected
fixture, real secret, Gym, predicate, breach logic, model, or external network/
process effect is used. Constructor-mediated fixture loading is explicitly recorded as FIXTURE_INITIALIZATION and is not an fs.read tool event or protected-value lineage claim.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, importlib, inspect, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2O_F_CONTROLLED_BRIDGE_INSTANCE_LIFECYCLE_QUALIFICATION_v1.2"
PARENT_VERSION="EX6_P2B_P2O_E_BRIDGE_IMPORT_AND_SYNTHETIC_INTEGRATION_QUALIFICATION_v1.0"
PARENT_STATUS="P2O_E_BRIDGE_IMPORT_AND_SYNTHETIC_INTEGRATION_QUALIFICATION_COMPLETE_PASS"
PARENT_MANIFEST_SHA="442CB588A1AE7B5DEF3D36884FD70D228C4397B54F3297BCE7D97F26DB19F3AF"
PARENT_RUNNER_SHA="3F659B6B73CF6AAE8256E8BAA64A9380BE308AFB02B1CCD63180304A5393EAAC"
TRANSPORT_REL="aicomp_sdk/core/env/trusted_outcome_transport_v1.py"
TRANSPORT_SHA="5C7F7D16A37896959C6F4CC769E5F72A6E5E534EE140BA5CAF2FB70661102CE1"
BRIDGE_REL="aicomp_sdk/core/env/sandbox_trusted_bridge_v1.py"
BRIDGE_SHA="3EE9BBB1E65949795A5639D12C55D81D8D0645357260DFC5A91DB1E9710288B6"
SANDBOX_REL="aicomp_sdk/core/env/sandbox.py"
SANDBOX_SHA="B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0"
PROTECTED={
 SANDBOX_REL:SANDBOX_SHA,
 "aicomp_sdk/core/predicates.py":"9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37",
 "aicomp_sdk/core/tools/fs.py":"4B8C54032ED807CE4C35BAB403EE622141881158E10F600A4B6D329E6D6F95B8",
 "aicomp_sdk/guardrails/optimal.py":"6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED",
 "aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py":"BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99",
}
BRIDGE_MODULE="aicomp_sdk.core.env.sandbox_trusted_bridge_v1"
TRANSPORT_MODULE="aicomp_sdk.core.env.trusted_outcome_transport_v1"
SANDBOX_MODULE="aicomp_sdk.core.env.sandbox"


def now(): return datetime.now(timezone.utc).isoformat()
def require(c,m):
    if not c: raise ValueError(m)
def sha(path:Path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest().upper()
def ident(path:Path):
    path=path.resolve(); return {"artifact":path.name,"path":str(path),"size_bytes":path.stat().st_size,"sha256":sha(path)}
def write_json(path,obj):
    with path.open("x",encoding="utf-8",newline="\n") as f: json.dump(obj,f,indent=2,sort_keys=True); f.write("\n")
def write_csv(path,rows,fields):
    with path.open("x",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore",lineterminator="\n"); w.writeheader(); w.writerows(rows)
def add(rows,cid,layer,passed,observed,expected,failure):
    rows.append({"check_id":cid,"execution_layer":layer,"passed":bool(passed),"observed":str(observed),"expected":str(expected),"failure_layer":failure})


class SyntheticAgent:
    def __init__(self): self.state={"schema":"P2O_F.SYNTHETIC_AGENT.V1"}
    def reset_state(self): self.state={"schema":"P2O_F.SYNTHETIC_AGENT.V1"}
    def snapshot_state(self): return dict(self.state)
    def restore_state(self,state): self.state=dict(state)


class SyntheticGuardrail:
    def __init__(self): self.state={"schema":"P2O_F.SYNTHETIC_GUARDRAIL.V1"}
    def decide(self,tool_name,tool_args,context): raise AssertionError("decide must not execute in P2O-F")
    def snapshot_state(self): return dict(self.state)
    def restore_state(self,state): self.state=dict(state)
    def reset(self): self.state={"schema":"P2O_F.SYNTHETIC_GUARDRAIL.V1"}


class SyntheticAdapter:
    def after_tool(self,outcome): raise AssertionError("after_tool must not execute in P2O-F")


def constructor_ast(source:Path,class_name:str):
    tree=ast.parse(source.read_text(encoding="utf-8"),filename=str(source))
    cls=next((n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==class_name),None)
    require(cls is not None,f"Missing class {class_name}")
    init=next((n for n in cls.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=="__init__"),None)
    require(init is not None,f"Missing explicit {class_name}.__init__")
    calls=[]
    for n in ast.walk(init):
        if isinstance(n,ast.Call):
            try: calls.append(ast.unparse(n.func))
            except Exception: calls.append("UNPARSE_FAILED")
    return init,calls


def build_constructor_kwargs(signature,fixtures_dir,agent,guardrail):
    mappings={"seed":73001,"fixtures_dir":fixtures_dir,"agent":agent,"guardrail":guardrail}
    kwargs={}; unresolved=[]
    for name,p in signature.parameters.items():
        if name in {"self","args","kwargs"}: continue
        if name in mappings: kwargs[name]=mappings[name]
        elif p.default is inspect._empty: unresolved.append(name)
    return kwargs,unresolved


def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    checks=[]; preflight=[]; lifecycle=[]; imported=[]
    bridge_instance=None; sandbox_instance_count=0
    try:
        project=Path(a.project_root).resolve(); require(project.is_dir(),f"Missing project root: {project}")
        inputs={
          "result":Path(a.p2o_e_result).resolve(),"checks":Path(a.p2o_e_checks).resolve(),"e1":Path(a.p2o_e_e1_bridge_import).resolve(),"e2":Path(a.p2o_e_e2_synthetic_integration).resolve(),"claim_boundary":Path(a.p2o_e_claim_boundary).resolve(),"binding":Path(a.p2o_e_binding).resolve(),"external_binding":Path(a.p2o_e_external_binding).resolve(),"manifest":Path(a.p2o_e_manifest).resolve(),"runner":Path(a.p2o_e_runner).resolve()
        }
        for k,p in inputs.items(): require(p.is_file(),f"Missing P2O-E {k}: {p}")
        parent=json.loads(inputs["result"].read_text(encoding="utf-8-sig")); ext=json.loads(inputs["external_binding"].read_text(encoding="utf-8-sig"))
        require(parent.get("version")==PARENT_VERSION and parent.get("status")==PARENT_STATUS,"P2O-E parent differs")
        require(parent.get("checks")=={"failed":0,"failed_ids":[],"passed":17,"total":17},"P2O-E checks differ")
        require(sha(inputs["manifest"])==PARENT_MANIFEST_SHA and ext.get("manifest_sha256")==PARENT_MANIFEST_SHA,"P2O-E manifest differs")
        require(sha(inputs["runner"])==PARENT_RUNNER_SHA and ext.get("runner_sha256")==PARENT_RUNNER_SHA,"P2O-E runner differs")
        require(ext.get("controlled_bridge_instance_lifecycle_gate_eligible") is True and ext.get("controlled_actual_fs_read_eligible") is False,"P2O-E eligibility differs")

        transport_path=project/TRANSPORT_REL; bridge_path=project/BRIDGE_REL; sandbox_path=project/SANDBOX_REL
        for p,e,label in [(transport_path,TRANSPORT_SHA,"transport"),(bridge_path,BRIDGE_SHA,"bridge"),(sandbox_path,SANDBOX_SHA,"sandbox")]: require(p.is_file() and sha(p)==e,f"{label} identity differs")
        for rel,expected in PROTECTED.items():
            p=project/rel; require(p.is_file() and sha(p)==expected,f"Protected source differs: {rel}")

        # F0: import-qualified classes and inspect constructor before instance creation.
        project_text=str(project); inserted=False
        if project_text not in sys.path: sys.path.insert(0,project_text); inserted=True
        try:
            bridge_mod=importlib.import_module(BRIDGE_MODULE); imported.append(BRIDGE_MODULE)
        finally:
            if inserted and sys.path and sys.path[0]==project_text: sys.path.pop(0)
        transport_mod=sys.modules.get(TRANSPORT_MODULE); sandbox_mod=sys.modules.get(SANDBOX_MODULE)
        require(transport_mod is not None and sandbox_mod is not None,"Qualified imports incomplete")
        imported.extend([TRANSPORT_MODULE,SANDBOX_MODULE])
        Bridge=bridge_mod.TrustedBridgeSandboxV1; Sandbox=sandbox_mod.SandboxEnv
        State=transport_mod.TrustedEventSequenceStateV1; Transport=transport_mod.TrustedOutcomeTransportV1
        sandbox_sig=inspect.signature(Sandbox); bridge_sig=inspect.signature(Bridge)
        init_node,calls=constructor_ast(sandbox_path,"SandboxEnv")
        prohibited_constructor_calls=[x for x in calls if x.endswith(".interact") or x.endswith(".step") or x.endswith(".run") or x in {"open","requests.get","requests.post","subprocess.run","subprocess.Popen"}]
        add(checks,"F0-01","F0",not prohibited_constructor_calls,prohibited_constructor_calls,[],"EFFECT")
        add(checks,"F0-02","F0",str(bridge_sig)=="(*args, trusted_transport, **kwargs)",str(bridge_sig),"(*args, trusted_transport, **kwargs)","ADAPTER_PARSE")
        preflight.append({"sandbox_signature":str(sandbox_sig),"bridge_signature":str(bridge_sig),"constructor_calls":";".join(calls),"prohibited_constructor_calls":";".join(prohibited_constructor_calls),"effect_free_route_eligible":not prohibited_constructor_calls})
        if any(not r["passed"] for r in checks if r["execution_layer"]=="F0"): raise ValueError("F0 failed; bridge construction withheld")

        # Invalid transport must reject before Sandbox.__init__ executes.
        original_init=Sandbox.__init__
        counter={"calls":0}
        def counting_init(self,*args,**kwargs):
            counter["calls"]+=1
            return original_init(self,*args,**kwargs)
        Sandbox.__init__=counting_init
        invalid_rejected=False
        try:
            try: Bridge(trusted_transport=object())
            except TypeError: invalid_rejected=True
        finally:
            Sandbox.__init__=original_init
        add(checks,"F1-01","F1",invalid_rejected and counter["calls"]==0,{"rejected":invalid_rejected,"sandbox_init_calls":counter["calls"]},{"rejected":True,"sandbox_init_calls":0},"AUTHORIZATION_TRANSPORT")

        # Controlled constructor fixture dependency. SandboxEnv requires its frozen SDK
        # fixture root (including web_corpus.json). This is constructor initialization,
        # not an fs.read tool event and not protected-value lineage evidence.
        fixture_root=Path(a.fixtures_dir).resolve()
        require(fixture_root.is_dir(),f"Missing fixture root: {fixture_root}")
        required_fixture=fixture_root/"web_corpus.json"
        require(required_fixture.is_file(),f"Missing required constructor fixture: {required_fixture}")
        fixture_inventory_before={x.name:{"size_bytes":x.stat().st_size,"sha256":sha(x)} for x in sorted(fixture_root.iterdir()) if x.is_file()}
        agent=SyntheticAgent(); guardrail=SyntheticGuardrail(); adapter=SyntheticAdapter()
        state1=State(); transport1=Transport(adapter,state1)
        kwargs,unresolved=build_constructor_kwargs(sandbox_sig,fixture_root,agent,guardrail)
        add(checks,"F1-02","F1",not unresolved,unresolved,[],"ADAPTER_PARSE")
        bridge_instance=Bridge(trusted_transport=transport1,**kwargs)
        sandbox_instance_count=1
        add(checks,"F1-03","F1",bridge_instance.trusted_transport is transport1,id(bridge_instance.trusted_transport),id(transport1),"AUTHORIZATION_TRANSPORT")
        empty_snapshot=bridge_instance.trusted_transport_snapshot()
        expected_empty={"schema":"P2N.TRANSPORT.STATE.V1","counter_by_trace":{},"consumed_outcome_identities":[]}
        add(checks,"F1-04","F1",empty_snapshot==expected_empty,empty_snapshot,expected_empty,"REPLAY_ORCHESTRATION")
        no_trace_events=(len(getattr(bridge_instance.trace,"tool_events",[]))==0)
        add(checks,"F1-05","F1",no_trace_events,len(getattr(bridge_instance.trace,"tool_events",[])),0,"TOOL")

        # F2 synthetic state lifecycle through pure state API, observed through bridge helper.
        before=bridge_instance.trusted_transport_snapshot()
        proposal_id=state1.allocate("f-trace-1","proposal")
        outcome_id=state1.allocate("f-trace-1","outcome")
        state1.consume_outcome(outcome_id)
        after=bridge_instance.trusted_transport_snapshot()
        add(checks,"F2-01","F2",before==expected_empty,before,expected_empty,"REPLAY_ORCHESTRATION")
        add(checks,"F2-02","F2",proposal_id=="f-trace-1:proposal:1" and outcome_id=="f-trace-1:outcome:2",(proposal_id,outcome_id),("f-trace-1:proposal:1","f-trace-1:outcome:2"),"REPLAY_ORCHESTRATION")
        add(checks,"F2-03","F2",after["counter_by_trace"]=={"f-trace-1":2} and after["consumed_outcome_identities"]==[outcome_id],after,{"counter_by_trace":{"f-trace-1":2},"consumed_outcome_identities":[outcome_id]},"REPLAY_ORCHESTRATION")
        restored=State(); restored.restore(after)
        add(checks,"F2-04","F2",restored.snapshot()==after,restored.snapshot(),after,"REPLAY_ORCHESTRATION")
        next_after_restore=restored.allocate("f-trace-1","outcome")
        add(checks,"F2-05","F2",next_after_restore=="f-trace-1:outcome:3",next_after_restore,"f-trace-1:outcome:3","REPLAY_ORCHESTRATION")
        duplicate_rejected=False
        try: restored.consume_outcome(outcome_id)
        except ValueError: duplicate_rejected=True
        add(checks,"F2-06","F2",duplicate_rejected,duplicate_rejected,True,"REPLAY_ORCHESTRATION")

        # Second independently constructed bridge instance.
        state2=State(); transport2=Transport(SyntheticAdapter(),state2)
        agent2=SyntheticAgent(); guardrail2=SyntheticGuardrail()
        kwargs2,unresolved2=build_constructor_kwargs(sandbox_sig,fixture_root,agent2,guardrail2)
        require(not unresolved2,f"Second constructor unresolved: {unresolved2}")
        bridge2=Bridge(trusted_transport=transport2,**kwargs2); sandbox_instance_count=2
        isolation=(bridge2 is not bridge_instance and bridge2.trusted_transport is transport2 and state2 is not state1 and bridge2.trusted_transport_snapshot()==expected_empty and bridge_instance.trusted_transport_snapshot()==after)
        add(checks,"F2-07","F2",isolation,isolation,True,"REPLAY_ORCHESTRATION")
        fixture_inventory_after={x.name:{"size_bytes":x.stat().st_size,"sha256":sha(x)} for x in sorted(fixture_root.iterdir()) if x.is_file()}
        fixture_unchanged=fixture_inventory_after==fixture_inventory_before
        add(checks,"F2-08","F2",fixture_unchanged,fixture_inventory_after,fixture_inventory_before,"FIXTURE")
        lifecycle.extend([
          {"control":"invalid_transport_pre_sandbox_rejection","passed":invalid_rejected and counter["calls"]==0,"observed":f"rejected={invalid_rejected};sandbox_init_calls={counter['calls']}"},
          {"control":"trusted_transport_identity","passed":bridge_instance.trusted_transport is transport1,"observed":"identity preserved"},
          {"control":"empty_snapshot","passed":empty_snapshot==expected_empty,"observed":json.dumps(empty_snapshot,sort_keys=True)},
          {"control":"state_mutation_visible","passed":after["counter_by_trace"]=={"f-trace-1":2},"observed":json.dumps(after,sort_keys=True)},
          {"control":"restore_and_replay_resistance","passed":restored.snapshot()!=expected_empty and duplicate_rejected,"observed":f"next={next_after_restore};duplicate_rejected={duplicate_rejected}"},
          {"control":"bridge_instance_isolation","passed":isolation,"observed":str(isolation)},
          {"control":"constructor_fixture_inventory_unchanged","passed":fixture_unchanged,"observed":str(fixture_unchanged)},
        ])

        # Rehash exact source after lifecycle controls.
        source_unchanged=(sha(transport_path)==TRANSPORT_SHA and sha(bridge_path)==BRIDGE_SHA and sha(sandbox_path)==SANDBOX_SHA)
        add(checks,"F2-09","F2",source_unchanged,source_unchanged,True,"FIXTURE")
        failed=[r["check_id"] for r in checks if not r["passed"]]; qualified=not failed
        status="P2O_F_CONTROLLED_BRIDGE_INSTANCE_LIFECYCLE_QUALIFICATION_COMPLETE_PASS" if qualified else "P2O_F_CONTROLLED_BRIDGE_INSTANCE_LIFECYCLE_QUALIFICATION_COMPLETE_WITH_GAPS"
        next_gate="EX6_P2B_P2O_G_SYNTHETIC_POST_TOOL_LIFECYCLE_QUALIFICATION" if qualified else "EX6_P2B_P2O_F_R1_BRIDGE_LIFECYCLE_RECONCILIATION"
        claim={"allowed":["controlled bridge construction with synthetic no-tool dependencies","trusted transport identity and bridge-visible snapshot findings","synthetic transport-state mutation, restore, replay-resistance, and isolation findings","invalid transport rejection before Sandbox construction","eligibility recommendation for separate synthetic post-tool lifecycle qualification"],"prohibited":["Sandbox interact behavior","tool invocation","actual fs.read behavior","protected fixture access","real secret capture","HTTP sink behavior","protected-value lineage","end-to-end authorization transport correctness","guardrail effectiveness","real exfiltration prevention"]}
        result={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"SYNTHETIC_NO_TOOL_BRIDGE_INSTANCE_LIFECYCLE","P2O_E_parent_verified":True,"checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"F0":{"sandbox_constructor_signature":str(sandbox_sig),"bridge_constructor_signature":str(bridge_sig),"prohibited_constructor_calls":prohibited_constructor_calls,"effect_free_constructor_route":"ESTABLISHED_WITHIN_MONITORED_SYNTHETIC_SCOPE" if qualified else "GAPS_IDENTIFIED"},"F1":{"bridge_instances_created":sandbox_instance_count,"invalid_transport_rejected_before_sandbox_init":invalid_rejected and counter["calls"]==0,"trusted_transport_identity_preserved":qualified,"empty_snapshot_passed":qualified,"tool_events_after_construction":0},"F2":{"synthetic_state_lifecycle_passed":qualified,"restore_and_replay_resistance_passed":qualified,"two_bridge_instance_isolation_passed":qualified,"source_identities_unchanged":source_unchanged},"readiness":{"synthetic_post_tool_lifecycle_gate_eligible":qualified,"bridge_instance_lifecycle_qualified":qualified,"Sandbox_interact_qualified":False,"identity_freeze_eligible":False,"controlled_actual_fs_read_eligible":False},"execution_boundaries":{"source_modified":False,"bridge_instantiated":sandbox_instance_count>0,"sandbox_base_constructor_executed":sandbox_instance_count>0,"sandbox_interact_executed":False,"sandbox_tool_event_count":0,"actual_fs_read_executed":False,"tools_executed":False,"http_sink_executed":False,"constructor_fixture_files_loaded":True,"protected_fixture_contents_read":False,"real_secret_values_used":False,"gym_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False,"external_network_or_process_effects_observed":False,"authorized_sdk_fixture_root_used":True,"fixture_root":str(fixture_root),"fixture_inventory_unchanged":fixture_unchanged},"scientific_verdict":{"bridge_instance_lifecycle":"ESTABLISHED_WITHIN_SYNTHETIC_NO_TOOL_SCOPE" if qualified else "GAPS_IDENTIFIED","Sandbox_interact_behavior":"NOT_EVALUATED","synthetic_post_tool_lifecycle":"NOT_EVALUATED","actual_source_retrieval":"NOT_EVALUATED","secret_capture":"NOT_ESTABLISHED","protected_value_lineage":"NOT_ESTABLISHED","authorization_transport_correctness":"NOT_ESTABLISHED_END_TO_END","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim,"next_gate":next_gate}
        rp=out/"ex6_p2b_p2o_f_result.json"; cp=out/"ex6_p2b_p2o_f_checks.csv"; fp=out/"ex6_p2b_p2o_f_f0_preflight.csv"; lp=out/"ex6_p2b_p2o_f_lifecycle.csv"; cl=out/"ex6_p2b_p2o_f_claim_boundary.json"; bp=out/"ex6_p2b_p2o_f_binding.json"
        write_json(rp,result); write_csv(cp,checks,["check_id","execution_layer","passed","observed","expected","failure_layer"]); write_csv(fp,preflight,["sandbox_signature","bridge_signature","constructor_calls","prohibited_constructor_calls","effect_free_route_eligible"]); write_csv(lp,lifecycle,["control","passed","observed"]); write_json(cl,claim); write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{k:ident(v) for k,v in inputs.items()},"sources":{"transport":ident(transport_path),"bridge":ident(bridge_path),"sandbox":ident(sandbox_path)},"project_root":str(project),"fixture_root":str(fixture_root),"fixture_inventory_before":fixture_inventory_before,"fixture_inventory_after":fixture_inventory_after,"imported_modules":imported,"source_modified":False,"sandbox_interact_executed":False,"tools_executed":False})
        derived=(rp,cp,fp,lp,cl,bp); bound=tuple(inputs.values()); sources=(transport_path,bridge_path,sandbox_path)
        rows=[{**ident(p),"role":"P2O_F_DERIVED"} for p in derived]+[{**ident(p),"role":"P2O_F_BOUND"} for p in bound]+[{**ident(p),"role":"P2O_F_INSTANCE_SOURCE"} for p in sources]
        mp=out/"ex6_p2b_p2o_f_manifest.csv"; write_csv(mp,rows,["artifact","role","size_bytes","sha256","path"])
        ep=out/"ex6_p2b_p2o_f_manifest_external_binding.json"; write_json(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"parent_p2o_e_manifest_sha256":PARENT_MANIFEST_SHA,"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"synthetic_post_tool_lifecycle_gate_eligible":qualified,"bridge_instantiated":sandbox_instance_count>0,"sandbox_interact_executed":False,"tools_executed":False,"controlled_actual_fs_read_eligible":False,"source_modified":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"bridge_instances_created":sandbox_instance_count,"sandbox_interact_executed":False,"tools_executed":False,"actual_fs_read_executed":False,"manifest_sha256":sha(mp),"next_gate":next_gate},indent=2))
    except Exception as exc:
        (out/"P2O_F_FAILED.json").write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2O_F_QUALIFICATION_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"checks_frozen":checks,"imported_modules":imported,"bridge_instance_created":bridge_instance is not None,"source_modified":False,"sandbox_interact_executed":False,"actual_fs_read_executed":False,"tools_executed":False,"http_sink_executed":False,"effects_observed":False},indent=2),encoding="utf-8")
        raise


def parse_args():
    p=argparse.ArgumentParser(description=VERSION)
    for flag in ["p2o-e-result","p2o-e-checks","p2o-e-e1-bridge-import","p2o-e-e2-synthetic-integration","p2o-e-claim-boundary","p2o-e-binding","p2o-e-external-binding","p2o-e-manifest","p2o-e-runner","project-root","fixtures-dir","output-dir"]:
        p.add_argument("--"+flag,required=True)
    return p.parse_args()
if __name__=="__main__":
    try: main(parse_args())
    except Exception as exc: print(f"FAILED: {exc}",file=sys.stderr); raise SystemExit(1)
