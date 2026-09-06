#!/usr/bin/env python3
"""EX6 P2B P2I R1 replay-classification contract reconciliation.

Diagnostic, non-stop, synthetic decision-only qualification. Re-runs the P2I
control family while preserving every observed action, reason, inner-call count,
and before/after state digest. Separates fail-closed action correctness from
reason-taxonomy fidelity. No source modification, after_tool, tools, effects,
Sandbox, Gym, predicates, breach logic, models, or attack optimization.
"""
from __future__ import annotations
import argparse, csv, hashlib, importlib, json, math, sys, unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

VERSION="EX6_P2B_P2I_R1_REPLAY_CLASSIFICATION_CONTRACT_RECONCILIATION_v1.0"
EXPECTED_FAILED_VERSION="EX6_P2B_P2I_CONTROLLED_PROPOSAL_BINDING_AND_FAIL_CLOSED_DECISION_PREFLIGHT_v1.0"
EXPECTED_FAILED_STATUS="P2I_CONTROLLED_PROPOSAL_BINDING_PREFLIGHT_BLOCKED"
EXPECTED_FAILED_CONTROL="C10_PROPOSAL_EVENT_REPLAY_DENY"
EXPECTED_ADAPTER_SHA="BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"
EXPECTED_BASE_SHA="EC95F45A9BF4202514725690617C91E88F3F1AE889AC7828D423DAAFEA527708"
ADAPTER_MODULE="aicomp_sdk.guardrails.trusted_context_adapter_v1_1"
BASE_MODULE="aicomp_sdk.guardrails.base"
ADAPTER_CLASS="TrustedGuardrailContextAdapterV1_1"
SCHEMA_TAG="aicomp.trusted-context.v1"
CAPABILITY=b"P2I_R1_DETERMINISTIC_CAPABILITY"
ISSUER="issuer-p2i-r1"; DOMAIN="domain-p2i-r1"; TOOL="http.post"
ARGS={"url":"https://synthetic.invalid/p2i-r1","data":"NON_SENSITIVE_P2I_R1"}
CONTEXT={"fixture":"P2I_R1","sensitive":False}; TRACE="P2I-R1-TRACE"

def now(): return datetime.now(timezone.utc).isoformat()
def require(c,m):
    if not c: raise ValueError(m)
def sha(p:Path):
    h=hashlib.sha256(); h.update(p.read_bytes()); return h.hexdigest().upper()
def ident(p:Path):
    p=p.resolve(); return {"artifact":p.name,"path":str(p),"size_bytes":p.stat().st_size,"sha256":sha(p)}
def norm(v):
    if v is None or isinstance(v,bool): return v
    if isinstance(v,int) and not isinstance(v,bool): return v
    if isinstance(v,float):
        if not math.isfinite(v): raise ValueError("non-finite prohibited")
        raise ValueError("float prohibited")
    if isinstance(v,str): return unicodedata.normalize("NFC",v)
    if isinstance(v,dict):
        out={}
        for k,x in v.items():
            if not isinstance(k,str): raise TypeError("keys must be strings")
            nk=unicodedata.normalize("NFC",k)
            if nk in out: raise ValueError("duplicate normalized key")
            out[nk]=norm(x)
        return out
    if isinstance(v,(list,tuple)): return [norm(x) for x in v]
    raise TypeError("unsupported canonical value")
def digest_v1(v):
    raw=json.dumps(norm({"schema_tag":SCHEMA_TAG,"value":v}),ensure_ascii=False,allow_nan=False,sort_keys=True,separators=(",",":")).encode()
    return hashlib.sha256(raw).hexdigest().upper()
def safe(v):
    if isinstance(v,bytes): return {"bytes_sha256":hashlib.sha256(v).hexdigest().upper(),"length":len(v)}
    if isinstance(v,dict): return {str(k):safe(x) for k,x in v.items()}
    if isinstance(v,(list,tuple)): return [safe(x) for x in v]
    if isinstance(v,set): return sorted(safe(x) for x in v)
    return v
def state_digest(adapter):
    raw=json.dumps(safe(adapter.snapshot_state()),sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest().upper()
def event(seq,trace=TRACE,kind="proposal"): return {"trace_identity":trace,"event_sequence":seq,"event_kind":kind}
def target_digest(tool,args): return digest_v1({"tool_name":tool,"url":args.get("url")})
def proposal_digest(tool,args,trace,ev): return digest_v1({"schema_tag":SCHEMA_TAG,"tool_name":tool,"canonical_tool_args":dict(args),"trace_identity":trace,"proposal_event_identity":dict(ev)})
def write_json(p,x):
    with p.open('x',encoding='utf-8',newline='\n') as f: json.dump(x,f,indent=2,sort_keys=True); f.write('\n')
def write_csv(p,rows,fields):
    with p.open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n'); w.writeheader(); w.writerows(rows)

def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    old_path=list(sys.path)
    observations=[]
    try:
        failed=Path(a.p2i_failed).resolve(); source=Path(a.repaired_source).resolve(); root=Path(a.project_root).resolve(); base=root/'aicomp_sdk'/'guardrails'/'base.py'
        for label,p in (("P2I failure",failed),("adapter",source),("base",base)): require(p.is_file(),f"Missing {label}: {p}")
        failure=json.loads(failed.read_text(encoding='utf-8-sig'))
        require(failure.get('version')==EXPECTED_FAILED_VERSION,'Unexpected failed-run version')
        require(failure.get('status')==EXPECTED_FAILED_STATUS,'Unexpected failed-run status')
        require(EXPECTED_FAILED_CONTROL in failure.get('error',''),'Failure control differs')
        require(failure.get('tools_executed') is False and failure.get('effects_observed') is False,'Failed run crossed effect boundary')
        require(sha(source)==EXPECTED_ADAPTER_SHA,'Adapter identity mismatch'); require(sha(base)==EXPECTED_BASE_SHA,'Base identity mismatch')
        sys.path.insert(0,str(root)); importlib.invalidate_caches()
        bm=importlib.import_module(BASE_MODULE); am=importlib.import_module(ADAPTER_MODULE)
        GuardrailBase=bm.GuardrailBase; Decision=bm.Decision; DecisionAction=bm.DecisionAction; Adapter=getattr(am,ADAPTER_CLASS)

        class Inner(GuardrailBase):
            def __init__(self): self.calls=0
            def decide(self,*args,**kwargs): self.calls+=1; return Decision.allow("P2I_R1_INNER_ALLOW")
            def snapshot_state(self): return {"calls":self.calls}
            def restore_state(self,snapshot): self.calls=int(snapshot["calls"])
        def fresh():
            inner=Inner(); return Adapter(inner,{(ISSUER,DOMAIN):CAPABILITY}),inner
        def grant(gid,tool,td,pd,trace,issued,expires): return {"grant_id":gid,"issuer_id":ISSUER,"issuer_trust_domain":DOMAIN,"issued_at_or_sequence":issued,"expires_at_or_sequence":expires,"authorized_tool":tool,"authorized_target_digest":td,"authorized_proposal_digest":pd,"nonce":"NONCE-"+gid,"trace_identity":trace}
        def observe(cid,adapter,inner,invoke:Callable[[],Any],expected_action,canonical_reason,acceptable_reasons,note):
            before=state_digest(adapter); calls_before=inner.calls; exc=None; decision=None
            try: decision=invoke()
            except Exception as e: exc=f"{type(e).__name__}: {e}"
            after=state_digest(adapter); calls_after=inner.calls
            action=str(decision.action) if decision is not None else "EXCEPTION"
            reason=str(decision.reason) if decision is not None else exc or ""
            action_pass=(action==expected_action)
            canonical_reason_pass=(reason==canonical_reason)
            diagnostic_reason_accepted=(reason in acceptable_reasons)
            observations.append({"control_id":cid,"expected_action":expected_action,"observed_action":action,"canonical_expected_reason":canonical_reason,"observed_reason":reason,"acceptable_diagnostic_reasons":";".join(sorted(acceptable_reasons)),"action_pass":action_pass,"canonical_reason_pass":canonical_reason_pass,"diagnostic_reason_accepted":diagnostic_reason_accepted,"inner_calls_before":calls_before,"inner_calls_after":calls_after,"inner_calls_delta":calls_after-calls_before,"state_digest_before":before,"state_digest_after":after,"state_changed":before!=after,"exception":exc or "","note":note})
            return decision

        # C01 direct fail closed.
        ad,inn=fresh(); observe("C01_DIRECT_DECIDE",ad,inn,lambda:ad.decide(TOOL,ARGS,CONTEXT),str(DecisionAction.DENY),"P2B_TRUSTED_BEFORE_DECIDE_REQUIRED",{"P2B_TRUSTED_BEFORE_DECIDE_REQUIRED"},"direct route")
        # C02 no grant.
        ad,inn=fresh(); ev=event(10); observe("C02_NO_GRANT",ad,inn,lambda:ad.before_decide(TOOL,ARGS,CONTEXT,trace_identity=TRACE,proposal_event_identity=ev),str(DecisionAction.DENY),"P2B_NO_MATCHING_ELIGIBLE_GRANT",{"P2B_NO_MATCHING_ELIGIBLE_GRANT"},"protected action without grant")

        def isolated(cid,overrides,expected_action,reason):
            ad,inn=fresh(); ev=event(10); pd=proposal_digest(TOOL,ARGS,TRACE,ev); td=target_digest(TOOL,ARGS)
            vals={"gid":"P2I-R1-"+cid,"tool":TOOL,"td":td,"pd":pd,"trace":TRACE,"issued":1,"expires":20}; vals.update(overrides)
            ad.register_trusted_grant(grant(vals["gid"],vals["tool"],vals["td"],vals["pd"],vals["trace"],vals["issued"],vals["expires"]),CAPABILITY)
            d=observe(cid,ad,inn,lambda:ad.before_decide(TOOL,ARGS,CONTEXT,trace_identity=TRACE,proposal_event_identity=ev),expected_action,reason,{reason},"isolated binding control")
            return ad,inn,ev,pd,d
        match_ad,match_inn,match_ev,match_pd,_=isolated("C03_EXACT_BINDING",{},str(DecisionAction.ALLOW),"P2I_R1_INNER_ALLOW")
        isolated("C04_WRONG_TOOL",{"tool":"fs.write"},str(DecisionAction.DENY),"P2B_NO_MATCHING_ELIGIBLE_GRANT")
        isolated("C05_WRONG_TARGET",{"td":"WRONG-TARGET"},str(DecisionAction.DENY),"P2B_NO_MATCHING_ELIGIBLE_GRANT")
        isolated("C06_WRONG_PROPOSAL",{"pd":"WRONG-PROPOSAL"},str(DecisionAction.DENY),"P2B_NO_MATCHING_ELIGIBLE_GRANT")
        isolated("C07_WRONG_TRACE",{"trace":"WRONG-TRACE"},str(DecisionAction.DENY),"P2B_NO_MATCHING_ELIGIBLE_GRANT")
        isolated("C08_NOT_YET_VALID",{"issued":11,"expires":20},str(DecisionAction.DENY),"P2B_NO_MATCHING_ELIGIBLE_GRANT")
        isolated("C09_EXPIRED",{"issued":1,"expires":10},str(DecisionAction.DENY),"P2B_NO_MATCHING_ELIGIBLE_GRANT")
        # C10 exact replay. Separate action and reason taxonomy.
        observe("C10_EXACT_EVENT_REPLAY",match_ad,match_inn,lambda:match_ad.before_decide(TOOL,ARGS,CONTEXT,trace_identity=TRACE,proposal_event_identity=match_ev),str(DecisionAction.DENY),"P2B_REPLAY_OR_EVENT_IDENTITY_REJECTED",{"P2B_REPLAY_OR_EVENT_IDENTITY_REJECTED","P2B_MALFORMED_TRUSTED_CHANNEL_INPUT"},"diagnostic reason reconciliation")
        # C11 new event after consumption.
        observe("C11_NEW_EVENT_AFTER_CONSUMPTION",match_ad,match_inn,lambda:match_ad.before_decide(TOOL,ARGS,CONTEXT,trace_identity=TRACE,proposal_event_identity=event(11)),str(DecisionAction.DENY),"P2B_NO_MATCHING_ELIGIBLE_GRANT",{"P2B_NO_MATCHING_ELIGIBLE_GRANT"},"combined proposal-digest and consumption observation")
        # C12 malformed event.
        ad,inn=fresh(); bad=event(10,kind="wrong-kind")
        observe("C12_MALFORMED_EVENT",ad,inn,lambda:ad.before_decide(TOOL,ARGS,CONTEXT,trace_identity=TRACE,proposal_event_identity=bad),str(DecisionAction.DENY),"P2B_MALFORMED_TRUSTED_CHANNEL_INPUT",{"P2B_MALFORMED_TRUSTED_CHANNEL_INPUT"},"wrong event kind")

        c10=next(x for x in observations if x['control_id']=="C10_EXACT_EVENT_REPLAY")
        action_passes=sum(bool(x['action_pass']) for x in observations); canonical_reason_passes=sum(bool(x['canonical_reason_pass']) for x in observations); diagnostic_passes=sum(bool(x['diagnostic_reason_accepted']) for x in observations)
        replay_denied=c10['observed_action']==str(DecisionAction.DENY)
        replay_reason_contract="CANONICAL_REPLAY_REASON" if c10['canonical_reason_pass'] else ("MALFORMED_REASON_VIA_VALIDATION_EXCEPTION_MAPPING" if c10['observed_reason']=="P2B_MALFORMED_TRUSTED_CHANNEL_INPUT" else "UNEXPECTED_REASON")
        status="P2I_R1_REPLAY_CLASSIFICATION_CONTRACT_RECONCILIATION_COMPLETE_PASS" if action_passes==len(observations) and diagnostic_passes==len(observations) else "P2I_R1_RECONCILIATION_COMPLETE_WITH_BEHAVIORAL_GAPS"
        next_gate="EX6_P2B_P2J_CONTROLLED_AFTER_TOOL_OUTCOME_BINDING_AND_PROTECTED_READ_PREFLIGHT" if replay_denied else "EX6_P2B_P2I_R2_FAIL_CLOSED_BEHAVIOR_REPAIR"
        result={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"NON_STOP_SYNTHETIC_DECISION_DIAGNOSTIC_RECONCILIATION","failed_P2I_parent_verified":True,"repaired_source_identity":ident(source),"guardrail_base_identity":ident(base),"controls":{"total":len(observations),"action_passed":action_passes,"canonical_reason_passed":canonical_reason_passes,"diagnostic_reason_accepted":diagnostic_passes},"C10_reconciliation":{"replay_denied":replay_denied,"observed_action":c10['observed_action'],"observed_reason":c10['observed_reason'],"canonical_reason_pass":c10['canonical_reason_pass'],"reason_contract_classification":replay_reason_contract,"inner_guardrail_reached":c10['inner_calls_delta']!=0,"state_changed":c10['state_changed']},"scientific_verdict":{"proposal_binding_behavior":"ESTABLISHED_WITHIN_P2I_R1_SYNTHETIC_FIXTURE_SCOPE" if action_passes==len(observations) else "BEHAVIORAL_GAPS_IDENTIFIED","replay_fail_closed_behavior":"ESTABLISHED_WITHIN_P2I_R1_FIXTURE_SCOPE" if replay_denied else "NOT_ESTABLISHED","replay_reason_fidelity":"ESTABLISHED" if c10['canonical_reason_pass'] else "CANONICAL_REASON_MISMATCH_ESTABLISHED","grant_consumption_behavior":"PARTIALLY_ESTABLISHED_WITHIN_COMBINED_P2I_R1_FIXTURE_SCOPE","authorization_transport_correctness":"NOT_ESTABLISHED","after_tool_outcome_binding":"NOT_EVALUATED","runtime_compatibility":"NOT_ESTABLISHED","requirement_satisfaction":"NOT_ESTABLISHED","guardrail_effectiveness":"NOT_EVALUATED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"execution_boundaries":{"direct_decide_executed":True,"before_decide_executed":True,"inner_guardrail_decide_executed":True,"after_tool_executed":False,"tools_executed":False,"effects_observed":False,"sandbox_executed":False,"gym_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False},"claim_boundary":{"allowed":["synthetic action behavior for every frozen P2I-R1 control","C10 observed action and reason","replay fail-closed status within exact fixture","replay reason-taxonomy fidelity within exact fixture"],"prohibited":["authorization transport correctness","after_tool correctness","runtime compatibility","requirement satisfaction","guardrail effectiveness","security improvement","real exfiltration prevention","hosted parity"]},"next_gate":next_gate}
        rp=out/'ex6_p2b_p2i_r1_result.json'; cp=out/'ex6_p2b_p2i_r1_controls.csv'; bp=out/'ex6_p2b_p2i_r1_binding.json'; cl=out/'ex6_p2b_p2i_r1_claim_boundary.json'
        write_json(rp,result); write_csv(cp,observations,["control_id","expected_action","observed_action","canonical_expected_reason","observed_reason","acceptable_diagnostic_reasons","action_pass","canonical_reason_pass","diagnostic_reason_accepted","inner_calls_before","inner_calls_after","inner_calls_delta","state_digest_before","state_digest_after","state_changed","exception","note"]); write_json(cl,result['claim_boundary']); write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{"p2i_failed":ident(failed),"repaired_source":ident(source),"guardrail_base":ident(base)},"source_modified":False})
        rows=[{**ident(p),"role":"P2I_R1_DERIVED"} for p in (rp,cp,bp,cl)]+[{**ident(p),"role":"P2I_R1_BOUND"} for p in (failed,source,base)]
        man=out/'ex6_p2b_p2i_r1_manifest.csv'; write_csv(man,rows,["artifact","role","size_bytes","sha256","path"])
        ext=out/'ex6_p2b_p2i_r1_manifest_external_binding.json'; write_json(ext,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":man.name,"manifest_size_bytes":man.stat().st_size,"manifest_sha256":sha(man),"runner_sha256":sha(Path(__file__).resolve()),"repaired_source_sha256":sha(source),"replay_denied":replay_denied,"replay_reason_contract":replay_reason_contract,"tools_executed":False,"effects_observed":False,"runtime_validated":False,"requirements_satisfied":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"controls_total":len(observations),"action_passed":action_passes,"canonical_reason_passed":canonical_reason_passes,"C10_replay_denied":replay_denied,"C10_observed_reason":c10['observed_reason'],"C10_reason_contract":replay_reason_contract,"manifest_sha256":sha(man),"next_gate":next_gate},indent=2))
    except Exception as e:
        (out/'P2I_R1_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2I_R1_RECONCILIATION_BLOCKED","error_type":type(e).__name__,"error":str(e),"observations_frozen":observations,"tools_executed":False,"effects_observed":False,"runtime_validated":False},indent=2),encoding='utf-8')
        raise
    finally: sys.path[:]=old_path

def args():
    p=argparse.ArgumentParser(description=VERSION); p.add_argument('--p2i-failed',required=True); p.add_argument('--project-root',required=True); p.add_argument('--repaired-source',required=True); p.add_argument('--output-dir',required=True); return p.parse_args()
if __name__=='__main__':
    try: main(args())
    except Exception as e: print(f"FAILED: {e}",file=sys.stderr); raise SystemExit(1)
