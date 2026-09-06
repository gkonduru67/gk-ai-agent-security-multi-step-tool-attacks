#!/usr/bin/env python3
"""Create and freeze the approved V2.2 two-stage hook implementation.

This gate creates source files only. It does not import or execute V2.2, V2.1,
the SDK, Sandbox, Gym, tools, HTTP, guardrails, predicates, breach logic,
models, threads, or external effects.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "V2_2_HOOK_CONTRACT_REPAIR_AND_IDENTITY_FREEZE_v1.0"
ROOT_NAME = "aicomp_sdk_exfil_v2_2"
DESIGN_ID = "EXFIL.V2.2.TWO_STAGE.READ.HOOK.DESIGN.1"
PROPOSAL_PRIORITY = 0
OUTCOME_PRIORITY = 0
EXPECTED = {
    "design_manifest": "FF5E286FBAC1E7250F8A0E235C1F76F43FD43BDBDC66AE650A1FB35564682885",
    "design_result": "487FEB4D9821273CBBA9EF7D5EB4F03C51F1C5EAC0A99B35BBD7E0858D364090",
    "design_checks": "9D180065E8DA6742E4841B826B9E2B46E3725D502A70999601D13E0CB99C6CB1",
    "design": "5A1679FA3FC74E283BBFF4650B3B22F0A92260968741854954C154CB1CDB327F",
    "decision_matrix": "C7F0CC3DE6ADF5189348C9D9C4C689439127CE75DDEF9E21805630EC557A25DA",
    "design_claim": "C9228FF7B5DDE54EA9153D4D3ED18E1977D1CD93737EEB916B46B71888297AC6",
    "design_binding": "DA5AAD092DE6C31A3F7CD32D01CFB12243100F29B6D704E5BEE1DC025554F232",
    "v21_ledger": "18146742E6866C491A032AA96EFC248FFED05706895D32FDE724145D0878009C",
    "v21_guardrail": "2AC1CA55FB0C18460F50B35677F5ECD9EB3477CFB21F9C19F44A48C7AEFD5C26",
    "v21_hook": "F2DE8D42EE5DBCD3BA4CACD8E98DCCB2EBA63F82EC8683D129C503CCED1CE770",
    "sdk_types": "0D3C7B5921749C22CADC5478532C7FE84B86AA90447FEEA8060ACFA9F44D3C7E",
    "sdk_registry": "5635B45136517CB5B7FBC6BAB6C9440FE7D6D699E484B6D63651AE296D4BB00B",
    "sdk_predicates": "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37",
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
def classes(tree): return {n.name:n for n in tree.body if isinstance(n,ast.ClassDef)}
def methods(c): return {n.name:n for n in c.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}

def source_files():
    init = '''"""Approved EXFILTRATION V2.2 two-stage hook integration."""
from .trusted_read_proposal_hook_v2_2 import TrustedReadProposalHookV22
from .trusted_read_outcome_hook_v2_2 import TrustedReadOutcomeHookV22
from .integration_factory_v2_2 import ExfilIntegrationBundleV22, ExfilIntegrationFactoryV22, build_exfil_integration_v22
__all__ = ["TrustedReadProposalHookV22", "TrustedReadOutcomeHookV22", "ExfilIntegrationBundleV22", "ExfilIntegrationFactoryV22", "build_exfil_integration_v22"]
'''
    proposal = '''"""V2.2 PRE_TOOL_CALL malformed fs.read proposal prevention."""
from __future__ import annotations
from collections.abc import Mapping
from typing import Any
from aicomp_sdk.hooks.types import HookContext, HookResult, HookStage

REASON_MALFORMED_READ_ARGS_V22 = "EXFIL_V22_MALFORMED_READ_ARGS"

class TrustedReadProposalHookV22:
    def __call__(self, context: HookContext) -> HookResult:
        if context.stage != HookStage.PRE_TOOL_CALL or context.tool_name != "fs.read":
            return HookResult()
        args = context.tool_args
        reason_detail: str | None = None
        if not isinstance(args, Mapping):
            reason_detail = "TOOL_ARGS_NOT_MAPPING"
        elif "path" not in args:
            reason_detail = "PATH_MISSING"
        elif not isinstance(args.get("path"), str):
            reason_detail = "PATH_NOT_STRING"
        elif not args["path"].strip():
            reason_detail = "PATH_EMPTY"
        if reason_detail is None:
            return HookResult()
        modified = HookContext(
            stage=context.stage,
            tool_name=context.tool_name,
            tool_args=context.tool_args,
            tool_output=context.tool_output,
            guardrail_decision=context.guardrail_decision,
            trace=context.trace,
            context=context.context,
            metadata=context.metadata,
            hook_state=context.hook_state,
            modified_args=context.modified_args,
            modified_output=context.modified_output,
            injected_content=context.injected_content,
            should_block=True,
        )
        return HookResult(
            continue_execution=False,
            modified_context=modified,
            metadata={
                "reason": REASON_MALFORMED_READ_ARGS_V22,
                "validation_stage": "PRE_TOOL_CALL",
                "reason_detail": reason_detail,
                "received_tool_args_type": type(args).__name__,
            },
        )
'''
    outcome = '''"""V2.2 POST_TOOL_CALL successful protected-read observation."""
from __future__ import annotations
from collections.abc import Mapping
from aicomp_sdk.core.predicates import is_protected_secret_path
from aicomp_sdk.hooks.types import HookContext, HookResult, HookStage
from aicomp_sdk_exfil_v2_1.successful_read_ledger_v2_1 import SuccessfulReadLedgerV21

REASON_MALFORMED_READ_OUTPUT_V22 = "EXFIL_V22_MALFORMED_READ_OUTPUT"

class TrustedReadOutcomeHookV22:
    def __init__(self, *, ledger: SuccessfulReadLedgerV21) -> None:
        if not isinstance(ledger, SuccessfulReadLedgerV21):
            raise TypeError("ledger must be SuccessfulReadLedgerV21")
        self._ledger = ledger

    def __call__(self, context: HookContext) -> HookResult:
        if context.stage != HookStage.POST_TOOL_CALL or context.tool_name != "fs.read":
            return HookResult()
        evidence = context.context
        if not isinstance(evidence, Mapping) or evidence.get("ok") is not True:
            return HookResult()
        args = context.tool_args
        if not isinstance(args, Mapping):
            return HookResult(metadata={"reason": REASON_MALFORMED_READ_OUTPUT_V22, "classification": "POST_TOOL_OBSERVATION_CONTRACT_VIOLATION", "reason_detail": "TOOL_ARGS_NOT_MAPPING"})
        path = args.get("path")
        if not isinstance(path, str) or not path.strip():
            return HookResult(metadata={"reason": REASON_MALFORMED_READ_OUTPUT_V22, "classification": "POST_TOOL_OBSERVATION_CONTRACT_VIOLATION", "reason_detail": "PATH_INVALID"})
        if not is_protected_secret_path(path):
            return HookResult()
        output = context.tool_output
        if not isinstance(output, str):
            return HookResult(metadata={"reason": REASON_MALFORMED_READ_OUTPUT_V22, "classification": "POST_TOOL_OBSERVATION_CONTRACT_VIOLATION", "reason_detail": "OUTPUT_NOT_STRING"})
        self._ledger.append_successful_read(
            tool_name="fs.read",
            tool_args=args,
            canonical_path=path,
            explicit_ok=True,
            error_value=evidence.get("error"),
            raw_output=output,
        )
        return HookResult(metadata={"successful_protected_read_recorded_v22": True})
'''
    factory = f'''"""V2.2 construction and registration boundary."""
from __future__ import annotations
from dataclasses import dataclass
from aicomp_sdk.guardrails.base import GuardrailBase
from aicomp_sdk.hooks.registry import HookRegistry
from aicomp_sdk.hooks.types import HookStage
from aicomp_sdk_exfil_v2_1.successful_read_ledger_v2_1 import SuccessfulReadLedgerV21
from aicomp_sdk_exfil_v2_1.lineage_aware_exfil_guardrail_v2_1 import LineageAwareExfilGuardrailV21
from .trusted_read_proposal_hook_v2_2 import TrustedReadProposalHookV22
from .trusted_read_outcome_hook_v2_2 import TrustedReadOutcomeHookV22

DESIGN_ID_V22 = "{DESIGN_ID}"
PROPOSAL_HOOK_PRIORITY_V22 = {PROPOSAL_PRIORITY}
OUTCOME_HOOK_PRIORITY_V22 = {OUTCOME_PRIORITY}

@dataclass(frozen=True, slots=True)
class ExfilIntegrationBundleV22:
    ledger: SuccessfulReadLedgerV21
    proposal_hook: TrustedReadProposalHookV22
    outcome_hook: TrustedReadOutcomeHookV22
    guardrail: LineageAwareExfilGuardrailV21

class ExfilIntegrationFactoryV22:
    @staticmethod
    def build(*, hook_registry: HookRegistry, inner: GuardrailBase | None = None) -> ExfilIntegrationBundleV22:
        if not isinstance(hook_registry, HookRegistry):
            raise TypeError("hook_registry must be HookRegistry")
        ledger = SuccessfulReadLedgerV21()
        proposal_hook = TrustedReadProposalHookV22()
        outcome_hook = TrustedReadOutcomeHookV22(ledger=ledger)
        guardrail = LineageAwareExfilGuardrailV21(ledger=ledger, inner=inner)
        hook_registry.register_hook(HookStage.PRE_TOOL_CALL, proposal_hook, PROPOSAL_HOOK_PRIORITY_V22)
        hook_registry.register_hook(HookStage.POST_TOOL_CALL, outcome_hook, OUTCOME_HOOK_PRIORITY_V22)
        return ExfilIntegrationBundleV22(ledger=ledger, proposal_hook=proposal_hook, outcome_hook=outcome_hook, guardrail=guardrail)

def build_exfil_integration_v22(*, hook_registry: HookRegistry, inner: GuardrailBase | None = None) -> ExfilIntegrationBundleV22:
    return ExfilIntegrationFactoryV22.build(hook_registry=hook_registry, inner=inner)
'''
    return {"__init__.py":init,"trusted_read_proposal_hook_v2_2.py":proposal,"trusted_read_outcome_hook_v2_2.py":outcome,"integration_factory_v2_2.py":factory}

def main(a):
    out=Path(a.output_dir).resolve();need(not out.exists(),f"Refusing overwrite: {out}");out.mkdir(parents=True);checks=[]
    try:
        project=Path(a.project_root).resolve();newroot=project/ROOT_NAME;need(not newroot.exists(),f"V2.2 root already exists: {newroot}")
        paths={
            "design_manifest":Path(a.design_manifest).resolve(),"design_result":Path(a.design_result).resolve(),"design_checks":Path(a.design_checks).resolve(),"design":Path(a.design).resolve(),"decision_matrix":Path(a.decision_matrix).resolve(),"design_claim":Path(a.design_claim).resolve(),"design_binding":Path(a.design_binding).resolve(),
            "v21_ledger":project/"aicomp_sdk_exfil_v2_1"/"successful_read_ledger_v2_1.py","v21_guardrail":project/"aicomp_sdk_exfil_v2_1"/"lineage_aware_exfil_guardrail_v2_1.py","v21_hook":project/"aicomp_sdk_exfil_v2_1"/"trusted_read_outcome_hook_v2_1.py","sdk_types":project/"aicomp_sdk"/"hooks"/"types.py","sdk_registry":project/"aicomp_sdk"/"hooks"/"registry.py","sdk_predicates":project/"aicomp_sdk"/"core"/"predicates.py"}
        for n,p in paths.items():need(p.is_file(),f"Missing {n}: {p}")
        for i,(n,h) in enumerate(EXPECTED.items(),1):add(checks,f"F22-{i:03d}","identity",sha(paths[n])==h,sha(paths[n]),h,"FIXTURE")
        result=rj(paths["design_result"]);dchecks=rc(paths["design_checks"]);design=rj(paths["design"])
        parent_ok=result.get("checks")=={"failed":0,"failed_ids":[],"passed":27,"total":27} and result.get("outcome")=="V2_2_TWO_STAGE_HOOK_DESIGN_APPROVED" and len(dchecks)==27 and all(x.get("passed")=="True" for x in dchecks) and design.get("design_id")==DESIGN_ID
        add(checks,"F22-014","parent",parent_ok,{"checks":result.get("checks"),"outcome":result.get("outcome"),"design_id":design.get("design_id")},"approved 27/27 design","EVIDENCE")

        src=source_files();newroot.mkdir();created=[];trees={}
        for name,text in src.items():
            p=newroot/name;p.write_text(text,encoding="utf-8",newline="\n");created.append(p);trees[name]=ast.parse(text,filename=str(p))
        add(checks,"F22-015","inventory",sorted(p.name for p in created)==sorted(src),[p.name for p in created],sorted(src),"FIXTURE")
        alltext="\n".join(src.values())
        add(checks,"F22-016","compatibility","SuccessfulReadLedgerV22" not in alltext and "SuccessfulReadRecordV22" not in alltext,alltext.count("SuccessfulReadLedgerV21"),"reuse V21 ledger only","PROVENANCE")
        add(checks,"F22-017","immutability","should_block=True" not in alltext.replace("should_block=True,","SHOULD_BLOCK_IN_CONTEXT,"),"HookResult should_block keyword absent","absent","AUTHORIZATION_TRANSPORT")

        pc=classes(trees["trusted_read_proposal_hook_v2_2.py"])["TrustedReadProposalHookV22"];ps=unparse(methods(pc)["__call__"])
        pchecks={"pre_stage":"HookStage.PRE_TOOL_CALL" in ps,"fs_filter":"context.tool_name != 'fs.read'" in ps,"mapping_first":ps.find("not isinstance(args, Mapping)")<ps.find("'path' not in args")<ps.find("not isinstance(args.get('path'), str)")<ps.find("not args['path'].strip()"),"modified_context":"modified_context=modified" in ps,"continue_false":"continue_execution=False" in ps,"context_block":"should_block=True" in ps,"reason":"EXFIL_V22_MALFORMED_READ_ARGS" in alltext}
        add(checks,"F22-018","proposal_hook",all(pchecks.values()),pchecks,"approved pre-tool contract","AUTHORIZATION_TRANSPORT")
        add(checks,"F22-019","proposal_hook","str(args" not in ps and "repr(args" not in ps,ps,"no normalization or unrestricted repr before validation","ARGUMENT_FIDELITY")

        oc=classes(trees["trusted_read_outcome_hook_v2_2.py"])["TrustedReadOutcomeHookV22"];os=unparse(methods(oc)["__call__"])
        ochecks={"post_stage":"HookStage.POST_TOOL_CALL" in os,"ok_exact":"evidence.get('ok') is not True" in os,"protected":"is_protected_secret_path(path)" in os,"string_output":"not isinstance(output, str)" in os,"append":"self._ledger.append_successful_read" in os,"option_a":"POST_TOOL_OBSERVATION_CONTRACT_VIOLATION" in os,"reason":"EXFIL_V22_MALFORMED_READ_OUTPUT" in alltext,"no_block":"should_block" not in os,"metadata_success":"successful_protected_read_recorded_v22" in os}
        add(checks,"F22-020","outcome_hook",all(ochecks.values()),ochecks,"approved post-tool contract","PROVENANCE")
        malformed_before_append=os.find("not isinstance(output, str)")<os.find("self._ledger.append_successful_read")
        add(checks,"F22-021","outcome_hook",malformed_before_append,os,"malformed output returns before append","PROVENANCE")

        fc=classes(trees["integration_factory_v2_2.py"]);bundle=fc["ExfilIntegrationBundleV22"];factory=fc["ExfilIntegrationFactoryV22"];fs=unparse(methods(factory)["build"])
        registrations=fs.count("hook_registry.register_hook")
        fchecks={"two_registrations":registrations==2,"pre":"HookStage.PRE_TOOL_CALL, proposal_hook, PROPOSAL_HOOK_PRIORITY_V22" in fs,"post":"HookStage.POST_TOOL_CALL, outcome_hook, OUTCOME_HOOK_PRIORITY_V22" in fs,"ledger_reuse":"ledger = SuccessfulReadLedgerV21()" in fs,"guardrail_reuse":"LineageAwareExfilGuardrailV21" in fs,"priorities":f"PROPOSAL_HOOK_PRIORITY_V22 = {PROPOSAL_PRIORITY}" in src["integration_factory_v2_2.py"] and f"OUTCOME_HOOK_PRIORITY_V22 = {OUTCOME_PRIORITY}" in src["integration_factory_v2_2.py"]}
        add(checks,"F22-022","factory",all(fchecks.values()),fchecks,"exact two-stage registration and reuse","AUTHORIZATION_TRANSPORT")
        bundle_fields=[n.target.id for n in bundle.body if isinstance(n,ast.AnnAssign) and isinstance(n.target,ast.Name)]
        add(checks,"F22-023","factory",bundle_fields==["ledger","proposal_hook","outcome_hook","guardrail"],bundle_fields,"exact bundle fields","ADAPTER_PARSE")
        no_state=not any("self._" in unparse(n) for tree in [trees["trusted_read_proposal_hook_v2_2.py"]] for n in ast.walk(tree) if isinstance(n,ast.Assign))
        add(checks,"F22-024","state",no_state,"proposal hook has no persistent mutable state",True,"PROVENANCE")
        add(checks,"F22-025","prohibited",all(x not in alltext for x in ["http.post","SandboxEnv","Gym","payload_exfiltrates_secret(","should_block=True, metadata"]),"no prohibited execution or legacy constructor pattern",True,"CLAIM_BOUNDARY")
        unchanged=all(sha(paths[n])==h for n,h in EXPECTED.items());add(checks,"F22-026","immutability",unchanged,"all bound V2.1 SDK and design inputs unchanged",True,"FIXTURE")

        failed=[x["check_id"] for x in checks if not x["passed"]];passed=not failed
        status="V2_2_HOOK_CONTRACT_REPAIR_AND_IDENTITY_FREEZE_COMPLETE_PASS" if passed else "V2_2_HOOK_CONTRACT_REPAIR_AND_IDENTITY_FREEZE_COMPLETE_WITH_GAPS"
        outcome="V2_2_HOOK_IMPLEMENTATION_AND_IDENTITY_FREEZE_PASS" if passed else "V2_2_HOOK_IMPLEMENTATION_FREEZE_GAP"
        inventory=[{**ident(p),"relative_path":str(p.relative_to(project)),"role":"NEW_V2_2_IMPLEMENTATION"} for p in created]
        decisions={"design_id":DESIGN_ID,"proposal_hook_priority":PROPOSAL_PRIORITY,"outcome_hook_priority":OUTCOME_PRIORITY,"priority_rationale":"explicit neutral priority within separate hook stages","registration_order":["PRE_TOOL_CALL proposal hook","POST_TOOL_CALL outcome hook"],"duplicate_registration_prevention":"each factory build creates distinct hook instances and registers each instance exactly once","ledger":"reuse SuccessfulReadLedgerV21 unchanged","guardrail":"reuse LineageAwareExfilGuardrailV21 unchanged","malformed_post_output":"OPTION_A_POST_TOOL_OBSERVATION_CONTRACT_VIOLATION"}
        claim={"allowed":["V2.2 source files created and identity frozen","approved two-stage design present statically","V2.1 ledger and guardrail reused unchanged","explicit hook priorities frozen","V2.1 and SDK identities preserved"],"prohibited":["claim V2.2 imports","claim runtime blocking","claim Sandbox integration","claim HTTP or guardrail effectiveness","claim predicate or breach","claim robust end-to-end security findings"]}
        result={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"STATIC_V2_2_IMPLEMENTATION_CREATION_AND_IDENTITY_FREEZE","checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"outcome":outcome,"implementation":{"source_root":ROOT_NAME,"files":inventory,"classes":["TrustedReadProposalHookV22","TrustedReadOutcomeHookV22","ExfilIntegrationBundleV22","ExfilIntegrationFactoryV22"],"reused_ledger":"SuccessfulReadLedgerV21","reused_guardrail":"LineageAwareExfilGuardrailV21"},"freeze_decisions":decisions,"execution_boundaries":{"V2_2_created":True,"V2_2_imported":False,"V2_2_instantiated":False,"V2_1_modified":False,"SDK_modified":False,"Sandbox_instantiated":False,"tools_executed":False,"actual_fs_read_executed":False,"HTTP_executed":False,"guardrail_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False,"threads_executed":False,"external_effects_observed":False},"scientific_verdict":{"V2_2_identity":"ESTABLISHED" if passed else "NOT_ESTABLISHED","V2_2_static_contract":"ESTABLISHED" if passed else "NOT_ESTABLISHED","V2_2_runtime_behavior":"NOT_EVALUATED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim,"next_gate":"INDEPENDENT_V2_2_HOOK_STATIC_QUALIFICATION" if passed else "V2_2_IMPLEMENTATION_GAP_REVIEW"}
        outs={"result":out/"v2_2_hook_freeze_result.json","checks":out/"v2_2_hook_freeze_checks.csv","inventory":out/"v2_2_hook_freeze_inventory.csv","decisions":out/"v2_2_hook_freeze_decisions.json","claim":out/"v2_2_hook_freeze_claim_boundary.json","binding":out/"v2_2_hook_freeze_binding.json"}
        wj(outs["result"],result);wc(outs["checks"],checks,["check_id","category","passed","observed","expected","failure_layer"]);wc(outs["inventory"],inventory,["artifact","relative_path","role","size_bytes","sha256","path"]);wj(outs["decisions"],decisions);wj(outs["claim"],claim);wj(outs["binding"],{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{n:ident(p) for n,p in paths.items()},"V2_2":{p.name:ident(p) for p in created},"execution_boundaries":result["execution_boundaries"]})
        rows=[{**ident(p),"role":"V22_FREEZE_DERIVED"} for p in outs.values()]+[{**ident(p),"role":"V22_FREEZE_BOUND_INPUT"} for p in paths.values()]+[{**ident(p),"role":"V22_IMPLEMENTATION"} for p in created];mp=out/"v2_2_hook_freeze_manifest.csv";wc(mp,rows,["artifact","role","size_bytes","sha256","path"]);ep=out/"v2_2_hook_freeze_manifest_external_binding.json";wj(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"design_manifest_sha256":EXPECTED["design_manifest"],"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"outcome":outcome,"V2_2_identity_established":passed,"V2_2_imported":False,"V2_1_modified":False,"SDK_modified":False,"next_gate":result["next_gate"]})
        print(json.dumps({"status":status,"checks":f"{len(checks)-len(failed)}/{len(checks)}","failed_ids":failed,"outcome":outcome,"V2_2_files":{p.name:ident(p) for p in created},"priorities":{"proposal":PROPOSAL_PRIORITY,"outcome":OUTCOME_PRIORITY},"V2_2_imported":False,"manifest_sha256":sha(mp),"next_gate":result["next_gate"]},indent=2))
    except Exception as e:
        (out/"V2_2_HOOK_FREEZE_FAILED.json").write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"BLOCKED","error_type":type(e).__name__,"error":str(e),"checks_frozen":checks,"V2_1_modified":False,"SDK_modified":False,"V2_2_imported":False},indent=2),encoding="utf-8");raise

def parse():
    p=argparse.ArgumentParser(description=VERSION)
    for n in ["design-manifest","design-result","design-checks","design","decision-matrix","design-claim","design-binding","project-root","output-dir"]:p.add_argument("--"+n,required=True)
    return p.parse_args()
if __name__=="__main__":
    try:main(parse())
    except Exception as e:print(f"FAILED: {e}",file=sys.stderr);raise SystemExit(1)
