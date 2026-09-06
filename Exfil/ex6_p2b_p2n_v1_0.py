#!/usr/bin/env python3
"""EX6 P2B P2N trusted-outcome bridge and digest-producer design.

Read-only design/feasibility gate bound to frozen P2M-R1A evidence.
Generates five producer design contracts, requirement traceability, proposed
insertion points, ordering/failure/snapshot requirements, claim boundary,
manifest, and external binding.

It does NOT modify source, implement the design, import SDK modules, execute
fs.read/tools/Sandbox/Gym/predicates/breach/models, read fixture contents,
preview/export protected values, or observe effects.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2N_TRUSTED_OUTCOME_BRIDGE_AND_DIGEST_PRODUCER_DESIGN_v1.0"
PARENT_VERSION="EX6_P2B_P2M_R1A_EVIDENCE_CLASSIFICATION_RECONCILIATION_v1.0"
PARENT_STATUS="P2M_R1A_EVIDENCE_CLASSIFICATION_RECONCILIATION_COMPLETE_PASS"
PARENT_MANIFEST_SHA="D335FC24BE63FD9F96986A3848BE62A7B488977AF56DDA5D9F14D76F8550DE6B"
PARENT_RUNNER_SHA="31B1132FD46A8BC6337D15571BD14B8CCB0EDAB94B49197D26A0BBCA7352C98D"
EXPECTED_GAPS=["after_tool runtime caller","raw_output_sha256 producer","protected_value_sha256_or_bound_digest producer","runtime event-sequence allocator","canonical_source_path producer"]

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
def write_json(p,x):
    with p.open('x',encoding='utf-8',newline='\n') as f: json.dump(x,f,indent=2,sort_keys=True); f.write('\n')
def write_csv(p,rows,fields):
    with p.open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n'); w.writeheader(); w.writerows(rows)

def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    try:
        pr=Path(a.p2m_r1a_result).resolve(); pe=Path(a.p2m_r1a_evidence).resolve(); pb=Path(a.p2m_r1a_external_binding).resolve(); pm=Path(a.p2m_r1a_manifest).resolve(); runner=Path(a.p2m_r1a_runner).resolve()
        for label,p in (("R1A result",pr),("R1A evidence",pe),("R1A external binding",pb),("R1A manifest",pm),("R1A runner",runner)): require(p.is_file(),f"Missing {label}: {p}")
        result=json.loads(pr.read_text(encoding='utf-8-sig')); binding=json.loads(pb.read_text(encoding='utf-8-sig'))
        require(result.get('version')==PARENT_VERSION and result.get('status')==PARENT_STATUS,'R1A parent differs')
        require(binding.get('status')==PARENT_STATUS,'R1A external binding differs')
        require(binding.get('manifest_sha256')==PARENT_MANIFEST_SHA and sha(pm)==PARENT_MANIFEST_SHA,'R1A manifest differs')
        require(binding.get('runner_sha256')==PARENT_RUNNER_SHA and sha(runner)==PARENT_RUNNER_SHA,'R1A runner differs')
        require(result.get('corrected_unresolved_producer_count')==5,'R1A corrected gap count differs')
        require(result.get('corrected_unresolved_producers')==EXPECTED_GAPS,'R1A gap identity/order differs')
        require(binding.get('controlled_actual_fs_read_eligible') is False and binding.get('fs_read_executed') is False and binding.get('fixture_contents_read') is False and binding.get('source_value_exported') is False,'R1A boundary differs')

        designs=[
          {"design_id":"P2N-01","gap":"after_tool runtime caller","layer":"AUTHORIZATION_TRANSPORT","proposed_host":"aicomp_sdk/core/env/sandbox.py::SandboxEnv.interact","insertion_point":"after POST_TOOL_CALL output is finalized; before serialization, recorded ToolEvent insertion, and runtime-history insertion","inputs":"proposal_digest; outcome_event_identity; trace_identity; tool_name; tool_args_digest; trusted_tool_outcome","outputs":"adapter acknowledgement or fail-closed exception; no source value export","ordering":"PRE_TOOL_CALL -> guardrail/before_decide -> tool call -> POST_TOOL_CALL -> trusted metadata production -> after_tool -> serialization -> trace event -> runtime history","failure_behavior":"if bridge metadata is absent, malformed, replayed, or rejected, do not claim protected-read recording; record an explicit host failure path without silently treating the outcome as trusted","replay_behavior":"one acknowledgement per pending proposal digest and outcome event identity","snapshot_restore":"bridge sequence state and adapter state must snapshot/restore together","feasibility":"FEASIBLE_WITH_HOST_CHANGE_NOT_IMPLEMENTED"},
          {"design_id":"P2N-02","gap":"raw_output_sha256 producer","layer":"SECRET_CAPTURE","proposed_host":"aicomp_sdk/core/env/sandbox.py::SandboxEnv.interact","insertion_point":"after POST_TOOL_CALL output finalization and before serialize_tool_output(output)","inputs":"post-hook-finalized output plus explicit type tag and canonical byte encoding","outputs":"uppercase SHA-256 only","ordering":"hash the authoritative post-hook-finalized value; do not hash serialized output_text unless separately named","failure_behavior":"unsupported/noncanonical output type blocks digest production and protected-read acknowledgement","replay_behavior":"same canonical value and type tag must reproduce the same digest","snapshot_restore":"stateless computation; no mutable digest state","feasibility":"FEASIBLE_WITH_CANONICALIZATION_SPEC_NOT_IMPLEMENTED"},
          {"design_id":"P2N-03","gap":"protected_value_sha256_or_bound_digest producer","layer":"PROVENANCE","proposed_host":"new trusted host helper called only for successful qualifying fs.read outcomes","insertion_point":"after canonical path and successful output are available; before after_tool","inputs":"domain tag; trace identity; proposal digest; outcome event identity; canonical source path; raw_output_sha256","outputs":"bound digest only; never raw protected value","ordering":"requires successful fs.read, protected-path classification, canonical source path, and raw-output digest","failure_behavior":"missing prerequisite prevents protected-value digest and protected-read record","replay_behavior":"bound digest includes event/proposal identity so cross-event reuse differs or is rejected","snapshot_restore":"stateless digest computation; event allocator and pending proposal state remain snapshot-bound","feasibility":"FEASIBLE_AS_VALUE_FREE_BINDING_NOT_IMPLEMENTED"},
          {"design_id":"P2N-04","gap":"runtime event-sequence allocator","layer":"AUTHORIZATION_TRANSPORT","proposed_host":"SandboxEnv trusted host state or dedicated trusted sequence component","insertion_point":"allocate proposal identity before before_decide; allocate outcome identity immediately after finalized tool outcome and before after_tool","inputs":"trace identity; event kind; monotonic counter","outputs":"proposal/outcome event identity and completion_sequence equal to outcome event sequence","ordering":"strictly monotonic per trace; no duplicate or rollback except through authenticated snapshot restore","failure_behavior":"nonmonotonic, duplicate, wrong-kind, or cross-trace identity fails closed before inner guardrail/recording","replay_behavior":"consumed outcome identity cannot be reused","snapshot_restore":"counter and consumed identities included in snapshot/restore/reset","feasibility":"FEASIBLE_WITH_TRUSTED_STATE_CHANGE_NOT_IMPLEMENTED"},
          {"design_id":"P2N-05","gap":"canonical_source_path producer","layer":"ARGUMENT_FIDELITY|PROVENANCE","proposed_host":"aicomp_sdk/core/tools/fs.py trusted result metadata or host-side resolver sharing the exact fs resolver contract","insertion_point":"derive from the resolved sandbox path for a successful fs.read before after_tool","inputs":"filesystem_root; requested path; resolved path","outputs":"normalized workspace-relative POSIX path with a single leading slash","ordering":"derive after path-escape validation and before protected-path classification/after_tool","failure_behavior":"path outside root, non-relative conversion, ambiguity, or normalization mismatch prevents trusted acknowledgement","replay_behavior":"same resolved sandbox object maps deterministically; requested aliases converge to one canonical path","snapshot_restore":"stateless derivation from restored filesystem root and request","feasibility":"FEASIBLE_WITH_SINGLE_AUTHORITATIVE_RESOLVER_NOT_IMPLEMENTED"},
        ]
        trace=[]
        requirement_map={
          "P2N-01":["AZ-001","AZ-002","AZ-003","AZ-004","AZ-005","AZ-006","AZ-007"],
          "P2N-02":["PV-002"],
          "P2N-03":["PV-003","PV-004"],
          "P2N-04":["AZ-003","AZ-004","AZ-005","AZ-007"],
          "P2N-05":["PV-002","PV-003","AZ-002"],
        }
        for d in designs:
            for req_id in requirement_map[d['design_id']]:
                trace.append({"requirement_id":req_id,"design_id":d['design_id'],"gap":d['gap'],"coverage":"DESIGNED_NOT_IMPLEMENTED","evidence_basis":"P2M-R1A corrected five-gap list"})

        schema={
          "schema_version":"P2N_TRUSTED_OUTCOME_V1_PROPOSED",
          "trusted_tool_outcome_required_fields":{
            "success":"bool","completion_sequence":"int","canonical_source_path":"str for fs.read","raw_output_sha256":"64 uppercase hex","protected_value_sha256_or_bound_digest":"64 uppercase hex for qualifying successful protected read"
          },
          "event_identity":{"trace_identity":"nonempty str","event_sequence":"strictly monotonic int","event_kind":"proposal|outcome"},
          "digest_domain_tags":{"raw_output":"P2N.RAW_OUTPUT.V1","protected_binding":"P2N.PROTECTED_BINDING.V1"},
          "value_export_policy":"raw protected value and previews prohibited in evidence artifacts",
        }
        feasibility={
          "overall":"DESIGN_FEASIBLE_BUT_NOT_IMPLEMENTED",
          "implementation_files_proposed":["aicomp_sdk/core/env/sandbox.py","aicomp_sdk/core/tools/fs.py","new trusted helper module name NOT_ESTABLISHED"],
          "immutable_baseline_policy":"packaged OptimalGuardrail remains unmodified",
          "implementation_authorized":False,
          "controlled_actual_fs_read_eligible":False,
          "blocking_reason":"five producer contracts exist only as design specifications",
        }
        claim={"allowed":["five producer design contracts","proposed insertion points and schemas","ordering/failure/replay/snapshot requirements","design feasibility and requirement traceability"],"prohibited":["implementation existence","runtime wiring","actual fs.read behavior","source retrieval success","secret capture","protected-value lineage","authorization transport correctness","guardrail effectiveness","real exfiltration prevention"]}
        result_obj={"version":VERSION,"created_at_utc":now(),"status":"P2N_TRUSTED_OUTCOME_BRIDGE_AND_DIGEST_PRODUCER_DESIGN_COMPLETE_PASS","classification":"READ_ONLY_DESIGN_AND_FEASIBILITY_SPECIFICATION","P2M_R1A_parent_verified":True,"design_contract_count":len(designs),"design_ids":[d['design_id'] for d in designs],"five_gaps_preserved":EXPECTED_GAPS,"mandatory_separations":{"raw_handler_vs_post_hook_output":"PRESERVED","post_hook_output_vs_serialized_output_text":"PRESERVED","raw_output_digest_vs_protected_bound_digest":"PRESERVED","source_category_vs_canonical_source_path":"PRESERVED","proposal_vs_outcome_event_identity":"PRESERVED","digest_presence_vs_derivation_correctness":"PRESERVED"},"proposed_schema":schema,"feasibility":feasibility,"execution_boundaries":{"source_modified":False,"implementation_created":False,"sdk_modules_imported":False,"actual_fs_read_executed":False,"tools_executed":False,"fixture_contents_read":False,"source_value_previewed":False,"source_value_exported":False,"effects_observed":False,"sandbox_executed":False,"gym_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False},"scientific_verdict":{"producer_design_contracts":"ESTABLISHED_AS_DESIGN_ONLY","implementation":"NOT_IMPLEMENTED","runtime_behavior":"NOT_EVALUATED","actual_source_retrieval":"NOT_EVALUATED","secret_capture":"NOT_ESTABLISHED","protected_value_lineage":"NOT_ESTABLISHED","authorization_transport_correctness":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim,"next_gate":"EX6_P2B_P2N_R1_INDEPENDENT_DESIGN_QUALIFICATION"}
        rp=out/'ex6_p2b_p2n_result.json'; dp=out/'ex6_p2b_p2n_designs.csv'; tp=out/'ex6_p2b_p2n_traceability.csv'; sp=out/'ex6_p2b_p2n_schema.json'; fp=out/'ex6_p2b_p2n_feasibility.json'; cp=out/'ex6_p2b_p2n_claim_boundary.json'; bp=out/'ex6_p2b_p2n_binding.json'
        write_json(rp,result_obj); write_csv(dp,designs,["design_id","gap","layer","proposed_host","insertion_point","inputs","outputs","ordering","failure_behavior","replay_behavior","snapshot_restore","feasibility"]); write_csv(tp,trace,["requirement_id","design_id","gap","coverage","evidence_basis"]); write_json(sp,schema); write_json(fp,feasibility); write_json(cp,claim); write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{"p2m_r1a_result":ident(pr),"p2m_r1a_evidence":ident(pe),"p2m_r1a_external_binding":ident(pb),"p2m_r1a_manifest":ident(pm),"p2m_r1a_runner":ident(runner)},"source_modified":False,"implementation_created":False})
        derived=(rp,dp,tp,sp,fp,cp,bp); bound=(pr,pe,pb,pm,runner)
        rows=[{**ident(p),"role":"P2N_DERIVED"} for p in derived]+[{**ident(p),"role":"P2N_BOUND"} for p in bound]
        man=out/'ex6_p2b_p2n_manifest.csv'; write_csv(man,rows,["artifact","role","size_bytes","sha256","path"])
        ext=out/'ex6_p2b_p2n_manifest_external_binding.json'; write_json(ext,{"version":VERSION,"created_at_utc":now(),"status":result_obj['status'],"manifest_filename":man.name,"manifest_size_bytes":man.stat().st_size,"manifest_sha256":sha(man),"runner_sha256":sha(Path(__file__).resolve()),"parent_manifest_sha256":PARENT_MANIFEST_SHA,"design_contract_count":5,"source_modified":False,"implementation_created":False,"actual_fs_read_executed":False,"controlled_actual_fs_read_eligible":False,"next_gate":result_obj['next_gate']})
        print(json.dumps({"status":result_obj['status'],"design_contracts":5,"traceability_rows":len(trace),"implementation":"NOT_IMPLEMENTED","controlled_actual_fs_read_eligible":False,"manifest_sha256":sha(man),"next_gate":result_obj['next_gate']},indent=2))
    except Exception as exc:
        (out/'P2N_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2N_DESIGN_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"source_modified":False,"implementation_created":False,"actual_fs_read_executed":False,"effects_observed":False},indent=2),encoding='utf-8')
        raise

def args():
    p=argparse.ArgumentParser(description=VERSION); p.add_argument('--p2m-r1a-result',required=True); p.add_argument('--p2m-r1a-evidence',required=True); p.add_argument('--p2m-r1a-external-binding',required=True); p.add_argument('--p2m-r1a-manifest',required=True); p.add_argument('--p2m-r1a-runner',required=True); p.add_argument('--output-dir',required=True); return p.parse_args()
if __name__=='__main__':
    try: main(args())
    except Exception as exc: print(f"FAILED: {exc}",file=sys.stderr); raise SystemExit(1)
