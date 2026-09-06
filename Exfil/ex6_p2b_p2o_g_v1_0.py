#!/usr/bin/env python3
"""P2O-G synthetic mediated post-tool lifecycle qualification.

Freezes and tests synthetic lifecycle contracts for successful and failed-result
acknowledgements, bounded retry behavior, snapshot/restore transitions, trace
separation, and static concurrency design. Instrumentation wraps the exact pure
transport module functions and state methods to record ordering.

No Sandbox.interact, real tool, fs.read, fixture-value retrieval, HTTP, Gym,
predicate, breach logic, model, thread execution, or external effect occurs.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, importlib, inspect, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2O_G_SYNTHETIC_POST_TOOL_LIFECYCLE_QUALIFICATION_v1.0"
PARENT_VERSION="EX6_P2B_P2O_F_CONTROLLED_BRIDGE_INSTANCE_LIFECYCLE_QUALIFICATION_v1.2"
PARENT_STATUS="P2O_F_CONTROLLED_BRIDGE_INSTANCE_LIFECYCLE_QUALIFICATION_COMPLETE_PASS"
PARENT_MANIFEST_SHA="3AB0B7BD16A6B319EDC3A272931E01A2B6863E54CF68ED8E75AE44D766A2AD77"
PARENT_RUNNER_SHA="A8D0A3E40B22D57568DB44A078D1BDD105F87D91EA08768858F08EA708A76D27"
TRANSPORT_REL="aicomp_sdk/core/env/trusted_outcome_transport_v1.py"
TRANSPORT_SHA="5C7F7D16A37896959C6F4CC769E5F72A6E5E534EE140BA5CAF2FB70661102CE1"
BRIDGE_REL="aicomp_sdk/core/env/sandbox_trusted_bridge_v1.py"
BRIDGE_SHA="3EE9BBB1E65949795A5639D12C55D81D8D0645357260DFC5A91DB1E9710288B6"
TRANSPORT_MODULE="aicomp_sdk.core.env.trusted_outcome_transport_v1"

TRACE_SUCCESS="g-trace-success"
TRACE_FAILURE="g-trace-failure"
TRACE_RETRY="g-trace-retry"
TRACE_A="g-trace-A"
TRACE_B="g-trace-B"
SUCCESS_PROPOSAL="g-proposal-success-001"
FAILURE_PROPOSAL="g-proposal-failure-001"
RETRY_PROPOSAL="g-proposal-retry-001"
SOURCE_PATH="/synthetic/post-tool.txt"
SUCCESS_VALUE={"synthetic_result":"ok","items":[1,"alpha",None]}
FAILURE_VALUE={"synthetic_error":"controlled_failure","code":"SYNTHETIC_ONLY"}
EXPECTED_KEYS={"success","completion_sequence","canonical_source_path","raw_output_sha256","protected_value_sha256_or_bound_digest"}


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
def event(log,kind,**fields):
    row={"order":len(log)+1,"event":kind}; row.update(fields); log.append(row)


class RecordingAdapter:
    def __init__(self,log,label): self.log=log; self.label=label; self.calls=[]
    def after_tool(self,outcome):
        event(self.log,"adapter.after_tool",label=self.label,sequence=outcome.get("completion_sequence"),success=outcome.get("success"))
        self.calls.append(dict(outcome))


class RaisingAdapter:
    def __init__(self,log): self.log=log; self.calls=0
    def after_tool(self,outcome):
        self.calls+=1; event(self.log,"adapter.after_tool.raise",sequence=outcome.get("completion_sequence"))
        raise RuntimeError("g-synthetic-adapter-error")


def ordered(log,names):
    positions=[]
    for name in names:
        pos=next((r["order"] for r in log if r["event"]==name),None)
        if pos is None: return False
        positions.append(pos)
    return positions==sorted(positions) and len(set(positions))==len(positions)


def concurrency_review(source:Path):
    tree=ast.parse(source.read_text(encoding="utf-8"),filename=str(source))
    cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=="TrustedEventSequenceStateV1")
    methods={n.name:n for n in cls.body if isinstance(n,ast.FunctionDef)}
    def with_lock(name):
        node=methods.get(name)
        return bool(node and any(isinstance(x,ast.With) and any("self._lock" in ast.unparse(i.context_expr) for i in x.items) for x in ast.walk(node)))
    transport=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=="TrustedOutcomeTransportV1")
    ack=next(n for n in transport.body if isinstance(n,ast.FunctionDef) and n.name=="acknowledge")
    ack_text=ast.unparse(ack)
    return {
      "lock_field_declared":"_lock" in ast.unparse(cls),
      "allocate_locked":with_lock("allocate"),
      "consume_locked":with_lock("consume_outcome"),
      "snapshot_locked":with_lock("snapshot"),
      "restore_locked":with_lock("restore"),
      "reset_locked":with_lock("reset"),
      "adapter_call_in_acknowledge":"self.adapter.after_tool" in ack_text,
      "transport_acknowledge_has_explicit_lock":"self.sequence_state._lock" in ack_text,
      "threaded_runtime_executed":False,
      "deadlock_behavior":"NOT_EVALUATED",
    }


def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    checks=[]; lifecycle=[]; snapshots=[]; concurrency=[]; imported=[]
    originals={}
    try:
        project=Path(a.project_root).resolve(); require(project.is_dir(),f"Missing project root: {project}")
        inputs={
          "result":Path(a.p2o_f_result).resolve(),"checks":Path(a.p2o_f_checks).resolve(),"preflight":Path(a.p2o_f_preflight).resolve(),"lifecycle":Path(a.p2o_f_lifecycle).resolve(),"claim_boundary":Path(a.p2o_f_claim_boundary).resolve(),"binding":Path(a.p2o_f_binding).resolve(),"external_binding":Path(a.p2o_f_external_binding).resolve(),"manifest":Path(a.p2o_f_manifest).resolve(),"runner":Path(a.p2o_f_runner).resolve()
        }
        for k,p in inputs.items(): require(p.is_file(),f"Missing P2O-F {k}: {p}")
        parent=json.loads(inputs["result"].read_text(encoding="utf-8-sig")); ext=json.loads(inputs["external_binding"].read_text(encoding="utf-8-sig"))
        require(parent.get("version")==PARENT_VERSION and parent.get("status")==PARENT_STATUS,"P2O-F parent differs")
        require(parent.get("checks")=={"failed":0,"failed_ids":[],"passed":16,"total":16},"P2O-F checks differ")
        require(sha(inputs["manifest"])==PARENT_MANIFEST_SHA and ext.get("manifest_sha256")==PARENT_MANIFEST_SHA,"P2O-F manifest differs")
        require(sha(inputs["runner"])==PARENT_RUNNER_SHA and ext.get("runner_sha256")==PARENT_RUNNER_SHA,"P2O-F runner differs")
        require(ext.get("synthetic_post_tool_lifecycle_gate_eligible") is True and ext.get("controlled_actual_fs_read_eligible") is False,"P2O-F eligibility differs")
        transport_path=project/TRANSPORT_REL; bridge_path=project/BRIDGE_REL
        require(transport_path.is_file() and sha(transport_path)==TRANSPORT_SHA,"Transport source differs")
        require(bridge_path.is_file() and sha(bridge_path)==BRIDGE_SHA,"Bridge source differs")

        project_text=str(project); inserted=False
        if project_text not in sys.path: sys.path.insert(0,project_text); inserted=True
        try: mod=importlib.import_module(TRANSPORT_MODULE); imported.append(TRANSPORT_MODULE)
        finally:
            if inserted and sys.path and sys.path[0]==project_text: sys.path.pop(0)
        BaseState=mod.TrustedEventSequenceStateV1; Transport=mod.TrustedOutcomeTransportV1

        # G0 freeze expected digests and policies before mediated scenarios.
        expected_raw=mod.compute_raw_output_sha256_v1(SUCCESS_VALUE)
        expected_outcome="g-trace-success:outcome:2"
        expected_bound=mod.compute_protected_value_bound_digest_v1(TRACE_SUCCESS,SUCCESS_PROPOSAL,expected_outcome,SOURCE_PATH,expected_raw)
        contract={
          "contract_id":"P2O-G.LIFECYCLE.CONTRACT.V1",
          "success":{"trace_identity":TRACE_SUCCESS,"proposal_identity":SUCCESS_PROPOSAL,"source_path":SOURCE_PATH,"post_hook_value":SUCCESS_VALUE,"expected_raw_output_sha256":expected_raw,"expected_bound_digest":expected_bound,"expected_outcome_identity":expected_outcome,"consumption":"CONSUMED_AFTER_ADAPTER_ACK"},
          "failure_result":{"trace_identity":TRACE_FAILURE,"proposal_identity":FAILURE_PROPOSAL,"source_path":SOURCE_PATH,"post_hook_value":FAILURE_VALUE,"success_flag":False,"consumption":"CONSUMED_AFTER_ADAPTER_ACK"},
          "retry":{"successful_ack_retry":"NEW_OUTCOME_EVENT_AND_NEW_ADAPTER_CALL","adapter_exception":"OUTCOME_EVENT_ALLOCATED_NOT_CONSUMED","retry_after_adapter_exception":"NEW_OUTCOME_EVENT; SUCCESSFUL_RETRY_CONSUMED"},
          "ordering":["snapshot.before","proposal.allocate","outcome.allocate","canonicalize","raw_digest","bound_digest","adapter.after_tool","outcome.consume","snapshot.after"],
          "threaded_execution_authorized":False,
        }
        contract_path=out/"ex6_p2b_p2o_g_contract.json"; write_json(contract_path,contract)

        # Instrument state and module functions.
        current_log=[]
        class InstrumentedState(BaseState):
            def allocate(self,trace_identity,event_kind):
                value=super().allocate(trace_identity,event_kind); event(current_log,f"{event_kind}.allocate",identity=value,trace=trace_identity); return value
            def consume_outcome(self,identity):
                result=super().consume_outcome(identity); event(current_log,"outcome.consume",identity=identity); return result
            def snapshot(self):
                value=super().snapshot(); event(current_log,"state.snapshot",state=json.dumps(value,sort_keys=True)); return value
            def restore(self,value):
                result=super().restore(value); event(current_log,"state.restore",state=json.dumps(value,sort_keys=True)); return result
        originals["canonicalize"]=mod.canonicalize_post_hook_output_v1
        originals["raw_digest"]=mod.compute_raw_output_sha256_v1
        originals["bound_digest"]=mod.compute_protected_value_bound_digest_v1
        def wrapped_canonicalize(value):
            result=originals["canonicalize"](value); event(current_log,"canonicalize",canonical_sha256=hashlib.sha256(result).hexdigest().upper()); return result
        def wrapped_raw(value):
            result=originals["raw_digest"](value); event(current_log,"raw_digest",digest=result); return result
        def wrapped_bound(*args,**kwargs):
            result=originals["bound_digest"](*args,**kwargs); event(current_log,"bound_digest",digest=result); return result
        mod.canonicalize_post_hook_output_v1=wrapped_canonicalize
        mod.compute_raw_output_sha256_v1=wrapped_raw
        mod.compute_protected_value_bound_digest_v1=wrapped_bound

        def run_ack(label,trace,proposal,value,success,adapter_cls=RecordingAdapter):
            nonlocal current_log
            current_log=[]; state=InstrumentedState(); adapter=adapter_cls(current_log,label) if adapter_cls is RecordingAdapter else adapter_cls(current_log)
            before=state.snapshot(); current_log[-1]["event"]="snapshot.before"
            proposal_id=state.allocate(trace,"proposal")
            transport=Transport(adapter,state)
            error=None; outcome=None
            try: outcome=transport.acknowledge(trace_identity=trace,proposal_digest=proposal,tool_name="synthetic.tool",success=success,canonical_source_path=SOURCE_PATH,post_hook_output=value)
            except Exception as exc: error=exc
            after=state.snapshot(); current_log[-1]["event"]="snapshot.after"
            return {"label":label,"state":state,"adapter":adapter,"before":before,"after":after,"proposal_id":proposal_id,"outcome":outcome,"error":error,"log":list(current_log)}

        # G1 successful synthetic post-tool lifecycle.
        success=run_ack("success",TRACE_SUCCESS,SUCCESS_PROPOSAL,SUCCESS_VALUE,True)
        expected_order=["snapshot.before","proposal.allocate","outcome.allocate","canonicalize","raw_digest","bound_digest","adapter.after_tool","outcome.consume","snapshot.after"]
        add(checks,"G1-01","G1",success["error"] is None,repr(success["error"]),None,"AUTHORIZATION_TRANSPORT")
        add(checks,"G1-02","G1",ordered(success["log"],expected_order),[r["event"] for r in success["log"]],expected_order,"AUTHORIZATION_TRANSPORT")
        out1=success["outcome"]
        add(checks,"G1-03","G1",out1 and out1["raw_output_sha256"]==expected_raw and out1["protected_value_sha256_or_bound_digest"]==expected_bound,out1,{"raw":expected_raw,"bound":expected_bound},"PROVENANCE")
        add(checks,"G1-04","G1",len(success["adapter"].calls)==1 and set(out1)==EXPECTED_KEYS,len(success["adapter"].calls),1,"AUTHORIZATION_TRANSPORT")
        add(checks,"G1-05","G1",expected_outcome in success["after"]["consumed_outcome_identities"],success["after"],expected_outcome,"REPLAY_ORCHESTRATION")

        # G2 synthetic failed tool-result acknowledgement. Contract says consumed after adapter ack.
        failed_result=run_ack("failed_result",TRACE_FAILURE,FAILURE_PROPOSAL,FAILURE_VALUE,False)
        failure_identity=f"{TRACE_FAILURE}:outcome:2"
        add(checks,"G2-01","G2",failed_result["error"] is None and failed_result["outcome"]["success"] is False,failed_result["outcome"],"success false acknowledged","AUTHORIZATION_TRANSPORT")
        add(checks,"G2-02","G2",len(failed_result["adapter"].calls)==1 and failure_identity in failed_result["after"]["consumed_outcome_identities"],failed_result["after"],failure_identity,"REPLAY_ORCHESTRATION")
        add(checks,"G2-03","G2",ordered(failed_result["log"],expected_order),[r["event"] for r in failed_result["log"]],expected_order,"AUTHORIZATION_TRANSPORT")

        # G3 retry controls on one state and adapter.
        current_log=[]; retry_state=InstrumentedState(); retry_adapter=RecordingAdapter(current_log,"retry"); retry_transport=Transport(retry_adapter,retry_state)
        retry_state.allocate(TRACE_RETRY,"proposal")
        first_retry=retry_transport.acknowledge(trace_identity=TRACE_RETRY,proposal_digest=RETRY_PROPOSAL,tool_name="synthetic.tool",success=True,canonical_source_path=SOURCE_PATH,post_hook_output="retry-value")
        second_retry=retry_transport.acknowledge(trace_identity=TRACE_RETRY,proposal_digest=RETRY_PROPOSAL,tool_name="synthetic.tool",success=True,canonical_source_path=SOURCE_PATH,post_hook_output="retry-value")
        add(checks,"G3-01","G3",len(retry_adapter.calls)==2 and (first_retry["completion_sequence"],second_retry["completion_sequence"])==(2,3),{"calls":len(retry_adapter.calls),"sequences":[first_retry["completion_sequence"],second_retry["completion_sequence"]]},{"calls":2,"sequences":[2,3]},"REPLAY_ORCHESTRATION")
        raising=run_ack("adapter_error",TRACE_RETRY+"-error",RETRY_PROPOSAL,"error-value",True,RaisingAdapter)
        allocated_identity=f"{TRACE_RETRY}-error:outcome:2"
        add(checks,"G3-02","G3",isinstance(raising["error"],RuntimeError) and raising["adapter"].calls==1,repr(raising["error"]),"RuntimeError and one call","AUTHORIZATION_TRANSPORT")
        add(checks,"G3-03","G3",allocated_identity not in raising["after"]["consumed_outcome_identities"] and raising["after"]["counter_by_trace"].get(TRACE_RETRY+"-error")==2,raising["after"],"allocated sequence 2, unconsumed","REPLAY_ORCHESTRATION")
        current_log=[]; error_state=raising["state"]; recovery_adapter=RecordingAdapter(current_log,"recovery"); recovery=Transport(recovery_adapter,error_state)
        recovered=recovery.acknowledge(trace_identity=TRACE_RETRY+"-error",proposal_digest=RETRY_PROPOSAL,tool_name="synthetic.tool",success=True,canonical_source_path=SOURCE_PATH,post_hook_output="recovery-value")
        add(checks,"G3-04","G3",recovered["completion_sequence"]==3 and f"{TRACE_RETRY}-error:outcome:3" in error_state.consumed_outcome_identities,recovered,"new event 3 consumed","REPLAY_ORCHESTRATION")

        # G4 snapshots and restore across explicit transitions.
        for scenario in [success,failed_result,raising]:
            snapshots.append({"scenario":scenario["label"],"stage":"before","snapshot_json":json.dumps(scenario["before"],sort_keys=True)})
            snapshots.append({"scenario":scenario["label"],"stage":"after","snapshot_json":json.dumps(scenario["after"],sort_keys=True)})
        restored=InstrumentedState(); restored.restore(success["after"]); restored_snapshot=restored.snapshot()
        add(checks,"G4-01","G4",restored_snapshot==success["after"],restored_snapshot,success["after"],"REPLAY_ORCHESTRATION")
        duplicate=False
        try: restored.consume_outcome(expected_outcome)
        except ValueError: duplicate=True
        add(checks,"G4-02","G4",duplicate,duplicate,True,"REPLAY_ORCHESTRATION")

        # G5 trace separation.
        current_log=[]; sep_state=InstrumentedState(); sep_adapter=RecordingAdapter(current_log,"separation"); sep_transport=Transport(sep_adapter,sep_state)
        sep_state.allocate(TRACE_A,"proposal"); sep_state.allocate(TRACE_B,"proposal")
        oa=sep_transport.acknowledge(trace_identity=TRACE_A,proposal_digest="proposal-A",tool_name="synthetic.tool",success=True,canonical_source_path="/synthetic/A",post_hook_output="A")
        ob=sep_transport.acknowledge(trace_identity=TRACE_B,proposal_digest="proposal-B",tool_name="synthetic.tool",success=True,canonical_source_path="/synthetic/B",post_hook_output="B")
        sep=sep_state.snapshot()
        sep_ok=(oa["completion_sequence"]==2 and ob["completion_sequence"]==2 and sep["counter_by_trace"]=={TRACE_A:2,TRACE_B:2} and set(sep["consumed_outcome_identities"])=={f"{TRACE_A}:outcome:2",f"{TRACE_B}:outcome:2"})
        add(checks,"G5-01","G5",sep_ok,sep,"independent counters and consumed identities","REPLAY_ORCHESTRATION")

        # G6 static concurrency design review only.
        review=concurrency_review(transport_path); concurrency.append(review)
        static_ok=all(review[k] for k in ["lock_field_declared","allocate_locked","consume_locked","snapshot_locked","restore_locked","reset_locked"])
        add(checks,"G6-01","G6",static_ok,review,"state operations guarded by RLock","AUTHORIZATION_TRANSPORT")
        add(checks,"G6-02","G6",review["adapter_call_in_acknowledge"] and not review["transport_acknowledge_has_explicit_lock"],review,"adapter call present; no explicit state lock around full acknowledge","AUTHORIZATION_TRANSPORT")
        add(checks,"G6-03","G6",review["threaded_runtime_executed"] is False,review["threaded_runtime_executed"],False,"CLAIM_BOUNDARY")

        # Freeze ordered event records without raw post-hook values.
        for scenario in [success,failed_result,raising]:
            for row in scenario["log"]: lifecycle.append({"scenario":scenario["label"],**row})
        failed=[r["check_id"] for r in checks if not r["passed"]]; qualified=not failed
        status="P2O_G_SYNTHETIC_POST_TOOL_LIFECYCLE_QUALIFICATION_COMPLETE_PASS" if qualified else "P2O_G_SYNTHETIC_POST_TOOL_LIFECYCLE_QUALIFICATION_COMPLETE_WITH_GAPS"
        next_gate="P2O_G_INDEPENDENT_LIFECYCLE_QUALIFICATION_AND_FREEZE" if qualified else "EX6_P2B_P2O_G_R1_LIFECYCLE_RECONCILIATION"
        claim={"allowed":["instrumented synthetic post-tool lifecycle ordering","synthetic success and failed-result acknowledgement findings","bounded retry and adapter-exception recovery findings","snapshot, restore, replay-resistance, and trace-separation findings","static concurrency design findings","eligibility recommendation for independent lifecycle qualification"],"prohibited":["real tool-result lifecycle","Sandbox.interact behavior","threaded concurrency behavior","actual fs.read behavior","protected fixture value use","real secret capture","HTTP sink behavior","protected-value lineage","end-to-end authorization transport correctness","guardrail effectiveness","real exfiltration prevention"]}
        result={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"INSTRUMENTED_SYNTHETIC_POST_TOOL_NO_REAL_TOOL","P2O_F_parent_verified":True,"checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"contract_id":contract["contract_id"],"G1":{"successful_lifecycle_ordering":qualified,"expected_outcome_identity":expected_outcome,"expected_raw_digest":expected_raw,"expected_bound_digest":expected_bound},"G2":{"failed_result_acknowledged":qualified,"failure_result_consumption_contract":"CONSUMED_AFTER_ADAPTER_ACK"},"G3":{"successful_retry_contract":"NEW_OUTCOME_EVENT_AND_NEW_ADAPTER_CALL","adapter_exception_contract":"ALLOCATED_NOT_CONSUMED","recovery_contract":"NEW_OUTCOME_EVENT_CONSUMED"},"G4":{"restore_match":qualified,"restored_duplicate_rejected":duplicate},"G5":{"trace_separation":sep_ok},"G6":{"static_concurrency_review":review,"threaded_runtime_executed":False},"readiness":{"independent_lifecycle_qualification_eligible":qualified,"synthetic_post_tool_lifecycle_qualified":qualified,"real_post_tool_lifecycle_qualified":False,"identity_freeze_eligible":False,"controlled_actual_fs_read_eligible":False},"execution_boundaries":{"source_modified":False,"Sandbox_interact_executed":False,"real_tools_executed":False,"actual_fs_read_executed":False,"protected_fixture_values_used":False,"real_secret_values_used":False,"http_sink_executed":False,"gym_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False,"threads_executed":False,"external_effects_observed":False},"scientific_verdict":{"synthetic_post_tool_lifecycle":"ESTABLISHED_WITHIN_INSTRUMENTED_SYNTHETIC_SCOPE" if qualified else "GAPS_IDENTIFIED","real_post_tool_lifecycle":"NOT_EVALUATED","threaded_concurrency":"NOT_EVALUATED","actual_source_retrieval":"NOT_EVALUATED","secret_capture":"NOT_ESTABLISHED","protected_value_lineage":"NOT_ESTABLISHED","authorization_transport_correctness":"NOT_ESTABLISHED_END_TO_END","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim,"next_gate":next_gate}
        rp=out/"ex6_p2b_p2o_g_result.json"; cp=out/"ex6_p2b_p2o_g_checks.csv"; lp=out/"ex6_p2b_p2o_g_ordered_events.csv"; sp=out/"ex6_p2b_p2o_g_snapshots.csv"; gp=out/"ex6_p2b_p2o_g_concurrency_review.csv"; cl=out/"ex6_p2b_p2o_g_claim_boundary.json"; bp=out/"ex6_p2b_p2o_g_binding.json"
        write_json(rp,result); write_csv(cp,checks,["check_id","execution_layer","passed","observed","expected","failure_layer"]); write_csv(lp,lifecycle,["scenario","order","event","label","sequence","success","identity","trace","canonical_sha256","digest","state"]); write_csv(sp,snapshots,["scenario","stage","snapshot_json"]); write_csv(gp,concurrency,list(review.keys())); write_json(cl,claim); write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{k:ident(v) for k,v in inputs.items()},"sources":{"transport":ident(transport_path),"bridge":ident(bridge_path)},"project_root":str(project),"imported_modules":imported,"source_modified":False,"real_tools_executed":False,"threads_executed":False})
        derived=(contract_path,rp,cp,lp,sp,gp,cl,bp); bound=tuple(inputs.values()); sources=(transport_path,bridge_path)
        rows=[{**ident(p),"role":"P2O_G_DERIVED"} for p in derived]+[{**ident(p),"role":"P2O_G_BOUND"} for p in bound]+[{**ident(p),"role":"P2O_G_SOURCE"} for p in sources]
        mp=out/"ex6_p2b_p2o_g_manifest.csv"; write_csv(mp,rows,["artifact","role","size_bytes","sha256","path"])
        ep=out/"ex6_p2b_p2o_g_manifest_external_binding.json"; write_json(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"parent_p2o_f_manifest_sha256":PARENT_MANIFEST_SHA,"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"independent_lifecycle_qualification_eligible":qualified,"real_tools_executed":False,"threads_executed":False,"controlled_actual_fs_read_eligible":False,"source_modified":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"contract_id":contract["contract_id"],"real_tools_executed":False,"threads_executed":False,"actual_fs_read_executed":False,"manifest_sha256":sha(mp),"next_gate":next_gate},indent=2))
    except Exception as exc:
        (out/"P2O_G_FAILED.json").write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2O_G_QUALIFICATION_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"checks_frozen":checks,"source_modified":False,"Sandbox_interact_executed":False,"real_tools_executed":False,"actual_fs_read_executed":False,"threads_executed":False,"effects_observed":False},indent=2),encoding="utf-8")
        raise
    finally:
        if 'mod' in locals() and originals:
            mod.canonicalize_post_hook_output_v1=originals.get("canonicalize",mod.canonicalize_post_hook_output_v1)
            mod.compute_raw_output_sha256_v1=originals.get("raw_digest",mod.compute_raw_output_sha256_v1)
            mod.compute_protected_value_bound_digest_v1=originals.get("bound_digest",mod.compute_protected_value_bound_digest_v1)


def parse_args():
    p=argparse.ArgumentParser(description=VERSION)
    for flag in ["p2o-f-result","p2o-f-checks","p2o-f-preflight","p2o-f-lifecycle","p2o-f-claim-boundary","p2o-f-binding","p2o-f-external-binding","p2o-f-manifest","p2o-f-runner","project-root","output-dir"]:
        p.add_argument("--"+flag,required=True)
    return p.parse_args()
if __name__=="__main__":
    try: main(parse_args())
    except Exception as exc: print(f"FAILED: {exc}",file=sys.stderr); raise SystemExit(1)
