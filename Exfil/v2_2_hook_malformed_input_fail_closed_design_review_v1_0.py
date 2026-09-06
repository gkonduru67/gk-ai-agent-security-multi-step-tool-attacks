#!/usr/bin/env python3
"""V2.2 hook malformed-input fail-closed design review v1.0.

Read-only design qualification. This script does not create V2.2 implementation
files. It binds the targeted HookResult contract evidence, re-inspects the
frozen SDK/V2.1 source via AST, evaluates a fixed two-stage design, and freezes
an approved or rejected design decision with an external manifest binding.

No V2.1/SDK modification, imports, tools, filesystem reads, Sandbox, Gym, HTTP,
guardrail, predicates, breach logic, models, threads, or external effects.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "V2_2_HOOK_MALFORMED_INPUT_FAIL_CLOSED_DESIGN_REVIEW_v1.0"
EXPECTED = {
    "target_manifest": "81774B5EFE121BC0F4486F8BF001CE6BDE8058E2F139E7B7C3E5C5110C1029CB",
    "target_result": "FA46EAC8B3C103E16C2F1585B61743C59496CF271FAB4330EBA38724DED6011A",
    "target_checks": "76289DE07CCABD59E2CAE373B5645853486EFFC5DF9A3B38771CAB2B55E91A26",
    "target_source": "D6FCDF28B72EBCF31D6F41DB99B7939C260BCC83600080DF5B622D8B99EDABAC",
    "target_constructor": "84669FE36767FFADF75C95B5F1B48448687FF6D46457D368CD27440A2AD98007",
    "target_repair": "42FA5A9872EE497045CB6387D03BC1BC311C4DC0B5CC803E63C45BFE14026E5B",
    "target_claim": "041CA9C02D614E3A5A238DECA557BE22D5D3F8C63A583D38882F75F10223450D",
    "target_binding": "911950EFF06AC21695F101372C9C952996DFD94C791CB7F1D42B8C4E23BE7ABC",
    "actual_read_manifest": "FE1350E6779772CDAC9CA4C16D058E53398F1EACA6062F2E0DE2D65B2E4D5AB1",
    "types": "0D3C7B5921749C22CADC5478532C7FE84B86AA90447FEEA8060ACFA9F44D3C7E",
    "registry": "5635B45136517CB5B7FBC6BAB6C9440FE7D6D699E484B6D63651AE296D4BB00B",
    "sandbox": "B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0",
    "v21_hook": "F2DE8D42EE5DBCD3BA4CACD8E98DCCB2EBA63F82EC8683D129C503CCED1CE770",
    "v21_ledger": "18146742E6866C491A032AA96EFC248FFED05706895D32FDE724145D0878009C",
}

def now(): return datetime.now(timezone.utc).isoformat()
def need(v,m):
    if not v: raise ValueError(m)
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest().upper()
def ident(p):
    p=Path(p).resolve(); return {"artifact":p.name,"path":str(p),"size_bytes":p.stat().st_size,"sha256":sha(p)}
def rj(p): return json.loads(Path(p).read_text(encoding="utf-8-sig"))
def rc(p):
    with Path(p).open(encoding="utf-8-sig",newline="") as f:return list(csv.DictReader(f))
def wj(p,v):
    with Path(p).open("x",encoding="utf-8",newline="\n") as f:json.dump(v,f,indent=2,sort_keys=True,ensure_ascii=False);f.write("\n")
def wc(p,rows,fields):
    with Path(p).open("x",encoding="utf-8",newline="") as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore",lineterminator="\n");w.writeheader();w.writerows(rows)
def add(rows,cid,cat,ok,obs,exp,layer):
    rows.append({"check_id":cid,"category":cat,"passed":bool(ok),"observed":json.dumps(obs,sort_keys=True,default=str) if isinstance(obs,(dict,list,tuple)) else str(obs),"expected":json.dumps(exp,sort_keys=True,default=str) if isinstance(exp,(dict,list,tuple)) else str(exp),"failure_layer":layer})
def unparse(n):
    try:return ast.unparse(n)
    except:return "UNPARSE_FAILED"
def cls(tree,name):return next((n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==name),None)
def meth(c,name):return next((n for n in c.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name),None)

def main(a):
    out=Path(a.output_dir).resolve();need(not out.exists(),f"Refusing overwrite: {out}");out.mkdir(parents=True);checks=[]
    try:
        root=Path(a.project_root).resolve()
        paths={
            "target_manifest":Path(a.target_manifest).resolve(),"target_result":Path(a.target_result).resolve(),"target_checks":Path(a.target_checks).resolve(),"target_source":Path(a.target_source).resolve(),"target_constructor":Path(a.target_constructor).resolve(),"target_repair":Path(a.target_repair).resolve(),"target_claim":Path(a.target_claim).resolve(),"target_binding":Path(a.target_binding).resolve(),"actual_read_manifest":Path(a.actual_read_manifest).resolve(),
            "types":root/"aicomp_sdk"/"hooks"/"types.py","registry":root/"aicomp_sdk"/"hooks"/"registry.py","sandbox":root/"aicomp_sdk"/"core"/"env"/"sandbox.py","v21_hook":root/"aicomp_sdk_exfil_v2_1"/"trusted_read_outcome_hook_v2_1.py","v21_ledger":root/"aicomp_sdk_exfil_v2_1"/"successful_read_ledger_v2_1.py"}
        for n,p in paths.items():need(p.is_file(),f"Missing {n}: {p}")
        for i,(n,h) in enumerate(EXPECTED.items(),1):add(checks,f"DR22-{i:03d}","identity",sha(paths[n])==h,sha(paths[n]),h,"FIXTURE")

        target=rj(paths["target_result"]);target_checks=rc(paths["target_checks"]);repair=rj(paths["target_repair"]);source=rj(paths["target_source"])
        parent_ok=target.get("checks")=={"failed":0,"failed_ids":[],"passed":24,"total":24} and target.get("outcome")=="HOOKRESULT_BLOCKING_NOT_SUPPORTED_AT_POST_TOOL_CALL" and len(target_checks)==24 and all(x.get("passed")=="True" for x in target_checks)
        add(checks,"DR22-014","parent",parent_ok,{"checks":target.get("checks"),"outcome":target.get("outcome")},"24/24 and expected outcome","EVIDENCE")
        repair_ok=repair.get("V2_1_modification")=="PROHIBITED" and repair.get("V2_2_required") is True and repair.get("post_tool_blocking")=="NOT_SUPPORTED_BY_SANDBOX_CONTROL_FLOW"
        add(checks,"DR22-015","parent",repair_ok,repair,"V2.1 frozen; V2.2 required; no post-tool block","EVIDENCE")

        texts={n:paths[n].read_text(encoding="utf-8") for n in ["types","registry","sandbox","v21_hook","v21_ledger"]};trees={n:ast.parse(t,filename=str(paths[n])) for n,t in texts.items()}
        hrc=cls(trees["types"],"HookResult");hcc=cls(trees["types"],"HookContext");need(hrc and hcc,"Hook contract classes missing")
        hr_names=[n.target.id for n in hrc.body if isinstance(n,ast.AnnAssign) and isinstance(n.target,ast.Name)];hc_names=[n.target.id for n in hcc.body if isinstance(n,ast.AnnAssign) and isinstance(n.target,ast.Name)]
        add(checks,"DR22-016","contract",hr_names==["continue_execution","modified_context","payload_detected","metadata"],hr_names,"exact HookResult fields","ADAPTER_PARSE")
        add(checks,"DR22-017","contract","should_block" in hc_names and "should_block" not in hr_names,{"HookContext":hc_names,"HookResult":hr_names},"should_block only in HookContext","ADAPTER_PARSE")
        reg=cls(trees["registry"],"HookRegistry");exe=meth(reg,"execute_hooks");rs=unparse(exe);apply=next((n for n in trees["registry"].body if isinstance(n,ast.FunctionDef) and n.name=="_apply_modified_context"),None);aps=unparse(apply)
        reg_ok="if result.modified_context" in rs and "if not result.continue_execution" in rs and "except Exception as err" in rs and "continue_execution=True" in rs and "context.should_block = modified_context.should_block" in aps
        add(checks,"DR22-018","contract",reg_ok,{"execute_hooks":rs,"apply":aps},"modified context transport; exception swallow; chain stop","AUTHORIZATION_TRANSPORT")
        sand=cls(trees["sandbox"],"SandboxEnv");inter=meth(sand,"interact");ss=unparse(inter);pre=ss.find("execute_hooks(HookStage.PRE_TOOL_CALL");precheck=ss.find("if pre_tool_ctx.should_block");tool=ss.find("self.tools.call(tool_name, tool_args)");post=ss.find("execute_hooks(HookStage.POST_TOOL_CALL");postcheck=ss.find("post_tool_ctx.should_block")
        control_order=0<=pre<precheck<tool<post and postcheck==-1
        add(checks,"DR22-019","contract",control_order,{"pre":pre,"precheck":precheck,"tool":tool,"post":post,"postcheck":postcheck},"pre block consumed; post block absent","AUTHORIZATION_TRANSPORT")

        v21c=cls(trees["v21_hook"],"TrustedReadOutcomeHookV21");call=meth(v21c,"__call__");cs=unparse(call)
        v21_gap=cs.count("should_block=True")==2 and "HookStage.POST_TOOL_CALL" in cs
        add(checks,"DR22-020","V2_1",v21_gap,cs,"two unsupported post-tool block calls","AUTHORIZATION_TRANSPORT")

        # Frozen design decision, created only after source-backed checks.
        design={
          "design_id":"EXFIL.V2.2.TWO_STAGE.READ.HOOK.DESIGN.1",
          "classification":"TWO_STAGE_PREVENTION_AND_OBSERVATION",
          "components":{
            "TrustedReadProposalHookV22":{
              "stage":"PRE_TOOL_CALL","purpose":"MALFORMED_READ_PROPOSAL_PREVENTION",
              "ignore_when":["stage is not PRE_TOOL_CALL","tool_name is not fs.read"],
              "validation_order":["tool_args is Mapping","path key exists","path is str","path.strip() is nonempty"],
              "block_result":{
                "continue_execution":False,
                "modified_context":{
                  "copy_from_active_context":["stage","tool_name","tool_args","tool_output","guardrail_decision","trace","context","metadata","hook_state","modified_args","modified_output","injected_content"],
                  "should_block":True},
                "metadata_schema":{"reason":"EXFIL_V22_MALFORMED_READ_ARGS","validation_stage":"PRE_TOOL_CALL"}},
              "original_arguments":"preserve exact received mapping reference/value in diagnostic metadata only if JSON safe; otherwise preserve type name, not repr-derived secret content",
              "normalization":"none for enforcement; validate raw proposal before any normalization"},
            "TrustedReadOutcomeHookV22":{
              "stage":"POST_TOOL_CALL","purpose":"SUCCESSFUL_READ_OBSERVATION_AND_LEDGER_CAPTURE",
              "ignore_when":["stage is not POST_TOOL_CALL","tool_name is not fs.read","context is not Mapping","context.ok is not exactly True","path is not protected"],
              "successful_append_preconditions":["tool_args is Mapping","path is str and nonempty","tool_output is str"],
              "success_result":{"continue_execution":True,"modified_context":None,"metadata":{"successful_protected_read_recorded_v22":True}},
              "malformed_output_policy":{
                "selected_option":"OPTION_A_POST_TOOL_OBSERVATION_CONTRACT_VIOLATION",
                "classification":"POST_TOOL_OBSERVATION_CONTRACT_VIOLATION",
                "behavior":["do not append to successful-read ledger","return metadata-only HookResult","preserve reason EXFIL_V22_MALFORMED_READ_OUTPUT","do not set should_block","do not claim read prevention","do not claim successful content lineage"]}},
            "ExfilIntegrationBundleV22":{"members":["SuccessfulReadLedgerV21","TrustedReadProposalHookV22","TrustedReadOutcomeHookV22","LineageAwareExfilGuardrailV21_or_separately_reviewed_successor"],"ledger_reuse":"V2.1 ledger reused unchanged"},
            "ExfilIntegrationFactoryV22":{"registrations":[{"stage":"PRE_TOOL_CALL","hook":"TrustedReadProposalHookV22","priority":"explicit frozen integer required at implementation freeze"},{"stage":"POST_TOOL_CALL","hook":"TrustedReadOutcomeHookV22","priority":"explicit frozen integer required at implementation freeze"}],"duplicate_registration_policy":"factory must not silently register same hook instance twice; runtime idempotence remains separate qualification"}},
          "ledger_decision":{"reuse":"SuccessfulReadLedgerV21","schema_change_required":False,"reason":"positive v1.4 lineage, snapshot, restore, digests, candidates, and identity already established; new diagnostic violations are metadata-only and must not enter successful-read ledger"},
          "snapshot_restore_responsibility":"unchanged V2.1 ledger contract; hooks add no independent mutable state in approved design",
          "duplicate_delivery_policy":{"outcome_hook":"duplicate valid delivery may append duplicate records, preserving observed V2.1 behavior until a separate deduplication design is justified","proposal_hook":"duplicate malformed proposal callbacks remain blocking results; no ledger mutation"},
          "claim_boundary":{"prevention":"only PRE_TOOL_CALL malformed proposal blocking after registered Sandbox qualification","observation":"POST_TOOL_CALL records successful protected-read content or reports observation contract violation","prohibited":"post-tool prevention, exception-based enforcement, arbitrary authorization, HTTP or breach claims"}}
        invariants={
          "no_HookResult_should_block_keyword":"should_block" not in design["components"]["TrustedReadProposalHookV22"]["block_result"].keys(),
          "pre_block_uses_modified_context":design["components"]["TrustedReadProposalHookV22"]["block_result"]["modified_context"]["should_block"] is True,
          "pre_block_stops_chain":design["components"]["TrustedReadProposalHookV22"]["block_result"]["continue_execution"] is False,
          "post_metadata_only":design["components"]["TrustedReadOutcomeHookV22"]["malformed_output_policy"]["behavior"][1]=="return metadata-only HookResult",
          "no_post_prevention_claim":"do not claim read prevention" in design["components"]["TrustedReadOutcomeHookV22"]["malformed_output_policy"]["behavior"],
          "ledger_unchanged":design["ledger_decision"]["schema_change_required"] is False,
          "raw_before_normalization":design["components"]["TrustedReadProposalHookV22"]["normalization"].startswith("none"),
          "V2_1_unchanged":True,"SDK_unchanged":True}
        add(checks,"DR22-021","design",all(invariants.values()),invariants,"all invariants true","DESIGN")
        pre_decisions=design["components"]["TrustedReadProposalHookV22"]
        add(checks,"DR22-022","design",pre_decisions["validation_order"]==["tool_args is Mapping","path key exists","path is str","path.strip() is nonempty"],pre_decisions["validation_order"],"exact fail-closed validation order","ARGUMENT_FIDELITY")
        postpolicy=design["components"]["TrustedReadOutcomeHookV22"]["malformed_output_policy"]
        add(checks,"DR22-023","design",postpolicy["selected_option"]=="OPTION_A_POST_TOOL_OBSERVATION_CONTRACT_VIOLATION",postpolicy,"Option A selected; metadata only; no ledger append","PROVENANCE")
        add(checks,"DR22-024","design",design["ledger_decision"]["reuse"]=="SuccessfulReadLedgerV21" and design["ledger_decision"]["schema_change_required"] is False,design["ledger_decision"],"reuse V2.1 ledger unchanged","PROVENANCE")
        stage_split=design["components"]["TrustedReadProposalHookV22"]["stage"]=="PRE_TOOL_CALL" and design["components"]["TrustedReadOutcomeHookV22"]["stage"]=="POST_TOOL_CALL"
        add(checks,"DR22-025","design",stage_split,{"proposal":design["components"]["TrustedReadProposalHookV22"]["stage"],"outcome":design["components"]["TrustedReadOutcomeHookV22"]["stage"]},"exact prevention/observation split","AUTHORIZATION_TRANSPORT")
        unchanged=all(sha(paths[n])==h for n,h in EXPECTED.items());add(checks,"DR22-026","immutability",unchanged,"all bound inputs unchanged",True,"FIXTURE")

        failed=[x["check_id"] for x in checks if not x["passed"]]
        if failed: outcome="NOT_ESTABLISHED"
        elif not stage_split: outcome="V2_2_PRE_TOOL_BLOCKING_DESIGN_GAP"
        elif postpolicy["selected_option"]!="OPTION_A_POST_TOOL_OBSERVATION_CONTRACT_VIOLATION": outcome="V2_2_POST_TOOL_DIAGNOSTIC_POLICY_GAP"
        elif design["ledger_decision"]["schema_change_required"]: outcome="V2_2_LEDGER_COMPATIBILITY_GAP"
        else: outcome="V2_2_TWO_STAGE_HOOK_DESIGN_APPROVED"
        status="V2_2_HOOK_MALFORMED_INPUT_FAIL_CLOSED_DESIGN_REVIEW_COMPLETE_PASS" if outcome=="V2_2_TWO_STAGE_HOOK_DESIGN_APPROVED" else "V2_2_HOOK_MALFORMED_INPUT_FAIL_CLOSED_DESIGN_REVIEW_COMPLETE_WITH_GAPS"
        claim={"allowed":["V2.2 two-stage design approved","PRE_TOOL_CALL malformed proposal prevention design frozen","POST_TOOL_CALL successful-read observation design frozen","Option A malformed post-output diagnostic policy selected","V2.1 ledger reuse approved without schema change"],"prohibited":["claim V2.2 implementation exists","claim runtime PRE_TOOL_CALL blocking works","modify V2.1","modify SDK","claim post-tool prevention","HTTP","guardrail effectiveness","predicate or breach","robust end-to-end security findings"]}
        result={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"READ_ONLY_DESIGN_QUALIFICATION","checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"outcome":outcome,"design":design,"invariants":invariants,"execution_boundaries":{"V2_1_modified":False,"SDK_modified":False,"V2_2_implementation_created":False,"Sandbox_instantiated":False,"tools_executed":False,"actual_fs_read_executed":False,"HTTP_executed":False,"guardrail_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False,"threads_executed":False,"external_effects_observed":False},"scientific_verdict":{"design_identity":"ESTABLISHED" if outcome=="V2_2_TWO_STAGE_HOOK_DESIGN_APPROVED" else "NOT_ESTABLISHED","implementation_behavior":"NOT_EVALUATED","positive_v1_4_source_to_ledger_lineage":"PRESERVED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim,"next_gate":"V2_2_HOOK_CONTRACT_REPAIR_AND_IDENTITY_FREEZE" if outcome=="V2_2_TWO_STAGE_HOOK_DESIGN_APPROVED" else "V2_2_HOOK_DESIGN_GAP_REVIEW"}
        outputs={"result":out/"v2_2_hook_design_review_result.json","checks":out/"v2_2_hook_design_review_checks.csv","design":out/"v2_2_two_stage_hook_design.json","matrix":out/"v2_2_hook_design_decision_matrix.csv","claim":out/"v2_2_hook_design_claim_boundary.json","binding":out/"v2_2_hook_design_binding.json"}
        matrix=[{"decision":"prevention_stage","selected":"PRE_TOOL_CALL","rationale":"Sandbox consumes should_block before tool execution"},{"decision":"observation_stage","selected":"POST_TOOL_CALL","rationale":"actual outcome and raw output exist only after execution"},{"decision":"malformed_post_output","selected":"OPTION_A_POST_TOOL_OBSERVATION_CONTRACT_VIOLATION","rationale":"do not append unverifiable content; metadata only; no prevention claim"},{"decision":"ledger","selected":"REUSE_SUCCESSFUL_READ_LEDGER_V21_UNCHANGED","rationale":"successful-read provenance contract already qualified"},{"decision":"exception_enforcement","selected":"PROHIBITED","rationale":"registry swallows exceptions and continues"},{"decision":"duplicate_outcome_delivery","selected":"PRESERVE_OBSERVED_DUPLICATE_APPEND","rationale":"deduplication not yet justified or implemented"}]
        wj(outputs["result"],result);wc(outputs["checks"],checks,["check_id","category","passed","observed","expected","failure_layer"]);wj(outputs["design"],design);wc(outputs["matrix"],matrix,["decision","selected","rationale"]);wj(outputs["claim"],claim);wj(outputs["binding"],{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{n:ident(p) for n,p in paths.items()},"execution_boundaries":result["execution_boundaries"]})
        rows=[{**ident(p),"role":"V22_DESIGN_DERIVED"} for p in outputs.values()]+[{**ident(p),"role":"V22_DESIGN_BOUND_INPUT"} for p in paths.values()];mp=out/"v2_2_hook_design_review_manifest.csv";wc(mp,rows,["artifact","role","size_bytes","sha256","path"]);ep=out/"v2_2_hook_design_review_manifest_external_binding.json";wj(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"targeted_hookresult_manifest_sha256":EXPECTED["target_manifest"],"actual_read_manifest_sha256":EXPECTED["actual_read_manifest"],"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"outcome":outcome,"V2_1_modified":False,"SDK_modified":False,"V2_2_implementation_created":False,"next_gate":result["next_gate"]})
        print(json.dumps({"status":status,"checks":f"{len(checks)-len(failed)}/{len(checks)}","failed_ids":failed,"outcome":outcome,"selected_post_output_policy":"OPTION_A_POST_TOOL_OBSERVATION_CONTRACT_VIOLATION","ledger_reuse":"SuccessfulReadLedgerV21","V2_2_implementation_created":False,"manifest_sha256":sha(mp),"next_gate":result["next_gate"]},indent=2))
    except Exception as e:
        (out/"V2_2_HOOK_DESIGN_REVIEW_FAILED.json").write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"BLOCKED","error_type":type(e).__name__,"error":str(e),"checks_frozen":checks,"V2_1_modified":False,"SDK_modified":False,"V2_2_implementation_created":False},indent=2),encoding="utf-8");raise

def parse():
    p=argparse.ArgumentParser(description=VERSION)
    for n in ["target-manifest","target-result","target-checks","target-source","target-constructor","target-repair","target-claim","target-binding","actual-read-manifest","project-root","output-dir"]:p.add_argument("--"+n,required=True)
    return p.parse_args()
if __name__=="__main__":
    try:main(parse())
    except Exception as e:print(f"FAILED: {e}",file=sys.stderr);raise SystemExit(1)
