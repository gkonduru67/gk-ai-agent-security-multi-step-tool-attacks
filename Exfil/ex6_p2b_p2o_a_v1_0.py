#!/usr/bin/env python3
"""EX6 P2B P2O-A implementation authorization and exact source contract freeze.

Read-only authorization-specification gate. It binds the independently qualified
R2C lineage and freezes exact files, symbols, signatures, imports, requirement
mapping, protected-source identities, and post-generation verification rules.
It authorizes only a later P2O-B generator to create three new files.

This runner creates no SDK implementation, modifies no source, imports no SDK
modules, and executes no tools, fs.read, Sandbox, Gym, predicates, breach logic,
models, fixture reads, source-value previews/exports, or effects.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX6_P2B_P2O_A_IMPLEMENTATION_AUTHORIZATION_AND_EXACT_SOURCE_CONTRACT_FREEZE_v1.0"
PARENT_VERSION = "EX6_P2B_P2N_R2C_INDEPENDENT_RECONCILIATION_QUALIFICATION_v1.0"
PARENT_STATUS = "P2N_R2C_INDEPENDENT_RECONCILIATION_QUALIFICATION_COMPLETE_PASS"
PARENT_MANIFEST_SHA = "3FF5834D2622F51DB1A5C2A2192311B91527421205A45791E9BF04641AEB401D"
PARENT_RUNNER_SHA = "65C6AD0A2458DA2FD49213D5438C85C9B1F661455B471DE9CE1B37D0175CED05"
R2B_SPEC_SHA = "0551D83F26541E691420533FFDCA7606070AEF8FB68924FAFB5D8B4A539980B1"
R2B_VECTORS_SHA = "EAD37C1011A92CDE36A86248C0ED4AB475BFEF3A52CA633DE14E2E0AEF0D4146"
AUTHORIZED_FILES = [
    "aicomp_sdk/core/env/trusted_outcome_transport_v1.py",
    "aicomp_sdk/core/env/sandbox_trusted_bridge_v1.py",
    "aicomp_sdk/core/tools/fs_trusted_result_v1.py",
]
PROTECTED = {
    "aicomp_sdk/core/env/sandbox.py": "B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0",
    "aicomp_sdk/core/predicates.py": "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37",
    "aicomp_sdk/core/tools/fs.py": "4B8C54032ED807CE4C35BAB403EE622141881158E10F600A4B6D329E6D6F95B8",
    "aicomp_sdk/guardrails/optimal.py": "6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED",
    "aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py": "BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99",
}

def now(): return datetime.now(timezone.utc).isoformat()
def require(c,m):
    if not c: raise ValueError(m)
def sha(path:Path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest().upper()
def ident(path:Path):
    path=path.resolve(); return {"artifact":path.name,"path":str(path),"size_bytes":path.stat().st_size,"sha256":sha(path)}
def write_json(path,obj):
    with path.open('x',encoding='utf-8',newline='\n') as f: json.dump(obj,f,indent=2,sort_keys=True); f.write('\n')
def write_csv(path,rows,fields):
    with path.open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n'); w.writeheader(); w.writerows(rows)

def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    try:
        project=Path(a.project_root).resolve(); require(project.is_dir(),f"Missing project root: {project}")
        inputs={
          "result":Path(a.p2n_r2c_result).resolve(),"checks":Path(a.p2n_r2c_checks).resolve(),"vectors":Path(a.p2n_r2c_recomputed_vectors).resolve(),"claim_boundary":Path(a.p2n_r2c_claim_boundary).resolve(),"binding":Path(a.p2n_r2c_binding).resolve(),"external_binding":Path(a.p2n_r2c_external_binding).resolve(),"manifest":Path(a.p2n_r2c_manifest).resolve(),"runner":Path(a.p2n_r2c_runner).resolve(),"canonicalization_spec":Path(a.p2n_r2b_canonicalization_spec).resolve(),"canonicalization_vectors":Path(a.p2n_r2b_canonicalization_vectors).resolve()
        }
        for k,p in inputs.items(): require(p.is_file(),f"Missing {k}: {p}")
        result=json.loads(inputs['result'].read_text(encoding='utf-8-sig')); ext=json.loads(inputs['external_binding'].read_text(encoding='utf-8-sig'))
        require(result.get('version')==PARENT_VERSION and result.get('status')==PARENT_STATUS,'R2C parent differs')
        require(result.get('checks')=={'failed':0,'failed_ids':[],'passed':43,'total':43},'R2C check summary differs')
        require(result.get('qualification')=={'Q60':'INDEPENDENTLY_QUALIFIED','Q73':'INDEPENDENTLY_QUALIFIED'},'R2C qualification differs')
        require(sha(inputs['manifest'])==PARENT_MANIFEST_SHA and ext.get('manifest_sha256')==PARENT_MANIFEST_SHA,'R2C manifest differs')
        require(sha(inputs['runner'])==PARENT_RUNNER_SHA and ext.get('runner_sha256')==PARENT_RUNNER_SHA,'R2C runner differs')
        require(sha(inputs['canonicalization_spec'])==R2B_SPEC_SHA and sha(inputs['canonicalization_vectors'])==R2B_VECTORS_SHA,'Canonicalization parents differ')
        require(ext.get('implementation_authorization_gate_eligible') is True and ext.get('implementation_authorized') is False,'R2C authorization boundary differs')
        for rel in AUTHORIZED_FILES: require(not (project/Path(rel)).exists(),f"Authorized new path already exists: {rel}")
        protected_rows=[]
        for rel,expected in PROTECTED.items():
            p=project/Path(rel); require(p.is_file(),f"Protected source missing: {rel}"); observed=sha(p); require(observed==expected,f"Protected source changed: {rel}")
            protected_rows.append({"relative_path":rel,"size_bytes":p.stat().st_size,"sha256":observed,"modification":"PROHIBITED"})

        files=[
          {"file_id":"AUTH-F01","relative_path":AUTHORIZED_FILES[0],"action":"CREATE_ONLY_IN_P2O_B","overwrite":"PROHIBITED","purpose":"canonicalization, digests, trusted outcome transport, sequence state","status":"AUTHORIZED_CONTRACT_NOT_CREATED"},
          {"file_id":"AUTH-F02","relative_path":AUTHORIZED_FILES[1],"action":"CREATE_ONLY_IN_P2O_B","overwrite":"PROHIBITED","purpose":"opt-in host bridge preserving qualified order","status":"AUTHORIZED_CONTRACT_NOT_CREATED"},
          {"file_id":"AUTH-F03","relative_path":AUTHORIZED_FILES[2],"action":"CREATE_ONLY_IN_P2O_B","overwrite":"PROHIBITED","purpose":"canonical sandbox-relative source path derivation","status":"AUTHORIZED_CONTRACT_NOT_CREATED"},
        ]
        symbols=[
          {"symbol_id":"SYM-001","file_id":"AUTH-F01","kind":"class","name":"TrustedEventSequenceStateV1","signature":"TrustedEventSequenceStateV1()","responsibility":"per-trace monotonic proposal/outcome allocation, consumption, snapshot, restore, reset"},
          {"symbol_id":"SYM-002","file_id":"AUTH-F01","kind":"class","name":"TrustedOutcomeTransportV1","signature":"TrustedOutcomeTransportV1(adapter, sequence_state)","responsibility":"value-free metadata production and exactly-once adapter.after_tool acknowledgement"},
          {"symbol_id":"SYM-003","file_id":"AUTH-F02","kind":"class","name":"TrustedBridgeSandboxV1","signature":"TrustedBridgeSandboxV1(*args, trusted_transport, **kwargs)","responsibility":"opt-in integration; no packaged SandboxEnv modification"},
          {"symbol_id":"SYM-004","file_id":"AUTH-F01","kind":"function","name":"canonicalize_post_hook_output_v1","signature":"canonicalize_post_hook_output_v1(value: object) -> bytes","responsibility":"implement P2N.CANONICAL_OUTPUT.V1 exactly"},
          {"symbol_id":"SYM-005","file_id":"AUTH-F01","kind":"function","name":"compute_raw_output_sha256_v1","signature":"compute_raw_output_sha256_v1(value: object) -> str","responsibility":"domain-separated uppercase SHA-256 over canonical post-hook output"},
          {"symbol_id":"SYM-006","file_id":"AUTH-F01","kind":"function","name":"compute_protected_value_bound_digest_v1","signature":"compute_protected_value_bound_digest_v1(trace_identity: str, proposal_digest: str, outcome_event_identity: str, canonical_source_path: str, raw_output_sha256: str) -> str","responsibility":"value-free protected binding"},
          {"symbol_id":"SYM-007","file_id":"AUTH-F03","kind":"function","name":"canonical_source_path_v1","signature":"canonical_source_path_v1(filesystem_root: Path, requested_path: str, resolved_path: Path) -> str","responsibility":"workspace-relative POSIX path with one leading slash"},
          {"symbol_id":"SYM-008","file_id":"AUTH-F01","kind":"function","name":"snapshot_trusted_transport_state_v1","signature":"snapshot_trusted_transport_state_v1(sequence_state: TrustedEventSequenceStateV1) -> dict[str, object]","responsibility":"deterministic JSON-compatible state snapshot"},
        ]
        imports=[
          {"file_id":"AUTH-F01","allowed_imports":"dataclasses; hashlib; json; threading; unicodedata; typing","prohibited_imports":"aicomp_sdk.core.env.sandbox; aicomp_sdk.core.env.gym; aicomp_sdk.core.predicates; network or process modules"},
          {"file_id":"AUTH-F02","allowed_imports":"typing; aicomp_sdk.core.env.sandbox.SandboxEnv; trusted_outcome_transport_v1 symbols","prohibited_imports":"predicates; gym; model clients; subprocess; network modules"},
          {"file_id":"AUTH-F03","allowed_imports":"pathlib.Path","prohibited_imports":"tool execution; filesystem reads; network or process modules"},
        ]
        trace=[
          {"requirement":"P2N-01","symbols":"SYM-002;SYM-003","coverage":"AUTHORIZED_NOT_IMPLEMENTED"},
          {"requirement":"P2N-02","symbols":"SYM-004;SYM-005","coverage":"AUTHORIZED_NOT_IMPLEMENTED"},
          {"requirement":"P2N-03","symbols":"SYM-006","coverage":"AUTHORIZED_NOT_IMPLEMENTED"},
          {"requirement":"P2N-04","symbols":"SYM-001;SYM-008","coverage":"AUTHORIZED_NOT_IMPLEMENTED"},
          {"requirement":"P2N-05","symbols":"SYM-007","coverage":"AUTHORIZED_NOT_IMPLEMENTED"},
        ]
        post=[
          {"verification_id":"POST-001","requirement":"exactly three authorized paths created and no other SDK path changed","failure_layer":"FIXTURE"},
          {"verification_id":"POST-002","requirement":"all five protected source SHA-256 values unchanged","failure_layer":"FIXTURE"},
          {"verification_id":"POST-003","requirement":"AST symbol names and signatures exactly match authorization","failure_layer":"ADAPTER_PARSE"},
          {"verification_id":"POST-004","requirement":"imports are an allowed subset and prohibited imports absent","failure_layer":"ADAPTER_PARSE"},
          {"verification_id":"POST-005","requirement":"canonicalization implementation reproduces all R2B/R2C vectors without raw-value artifacts","failure_layer":"SECRET_CAPTURE"},
          {"verification_id":"POST-006","requirement":"no module import, tool, Sandbox, Gym, predicate, breach, or runtime execution during generation","failure_layer":"AUTHORIZATION_TRANSPORT"},
          {"verification_id":"POST-007","requirement":"source generation result, raw files, canonical inventories, manifest, and external binding frozen","failure_layer":"FIXTURE"},
        ]
        authorization={
          "authorization_id":"P2O-A-AUTH-v1.0","authorized_next_gate":"EX6_P2B_P2O_B_AUTHORIZED_SOURCE_GENERATION","authorized_action":"create exactly three new source files at authorized paths","authorization_scope":"source generation only; no imports or runtime execution","overwrite_existing_paths":False,"modify_protected_sources":False,"implementation_runtime_qualified":False,"identity_freeze_complete":False,"actual_fs_read_authorized":False,"tools_authorized":False,"sandbox_authorized":False,"gym_authorized":False,"predicates_authorized":False,"breach_authorized":False,"models_authorized":False,"effects_authorized":False,
        }
        claim={"allowed":["authorization of a later generator to create exactly three named source files","exact source-contract symbols, signatures, imports, and traceability","pre-generation protected-source identities","post-generation verification requirements"],"prohibited":["claim that implementation exists","source generation by this gate","runtime wiring","runtime canonicalization","actual fs.read behavior","source retrieval success","secret capture","protected-value lineage","authorization transport correctness","guardrail effectiveness","real exfiltration prevention"]}
        result_out={"version":VERSION,"created_at_utc":now(),"status":"P2O_A_IMPLEMENTATION_AUTHORIZATION_AND_EXACT_SOURCE_CONTRACT_FREEZE_COMPLETE_PASS","classification":"READ_ONLY_AUTHORIZATION_SPECIFICATION","P2N_R2C_parent_verified":True,"authorization":authorization,"inventory":{"authorized_files":len(files),"authorized_symbols":len(symbols),"authorized_import_sets":len(imports),"requirements_mapped":len(trace),"protected_sources":len(protected_rows),"post_generation_verifications":len(post)},"readiness":{"P2O_B_source_generation_authorized":True,"source_generation_performed":False,"implementation_created":False,"implementation_runtime_qualified":False,"identity_freeze_eligible":False,"controlled_actual_fs_read_eligible":False},"execution_boundaries":{"source_modified":False,"implementation_created":False,"sdk_modules_imported":False,"actual_fs_read_executed":False,"tools_executed":False,"fixture_contents_read":False,"source_value_previewed":False,"source_value_exported":False,"effects_observed":False,"sandbox_executed":False,"gym_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False},"scientific_verdict":{"implementation_authorization_contract":"ESTABLISHED","implementation":"NOT_IMPLEMENTED","runtime_behavior":"NOT_EVALUATED","actual_source_retrieval":"NOT_EVALUATED","secret_capture":"NOT_ESTABLISHED","protected_value_lineage":"NOT_ESTABLISHED","authorization_transport_correctness":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim,"next_gate":"EX6_P2B_P2O_B_AUTHORIZED_SOURCE_GENERATION"}
        paths={
          "result":out/'ex6_p2b_p2o_a_result.json',"files":out/'ex6_p2b_p2o_a_files.csv',"symbols":out/'ex6_p2b_p2o_a_symbols.csv',"imports":out/'ex6_p2b_p2o_a_imports.csv',"trace":out/'ex6_p2b_p2o_a_traceability.csv',"protected":out/'ex6_p2b_p2o_a_protected_sources.csv',"post":out/'ex6_p2b_p2o_a_post_generation_verification.csv',"authorization":out/'ex6_p2b_p2o_a_authorization.json',"claim":out/'ex6_p2b_p2o_a_claim_boundary.json',"binding":out/'ex6_p2b_p2o_a_binding.json'
        }
        write_json(paths['result'],result_out); write_csv(paths['files'],files,["file_id","relative_path","action","overwrite","purpose","status"]); write_csv(paths['symbols'],symbols,["symbol_id","file_id","kind","name","signature","responsibility"]); write_csv(paths['imports'],imports,["file_id","allowed_imports","prohibited_imports"]); write_csv(paths['trace'],trace,["requirement","symbols","coverage"]); write_csv(paths['protected'],protected_rows,["relative_path","size_bytes","sha256","modification"]); write_csv(paths['post'],post,["verification_id","requirement","failure_layer"]); write_json(paths['authorization'],authorization); write_json(paths['claim'],claim); write_json(paths['binding'],{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{k:ident(v) for k,v in inputs.items()},"project_root":str(project),"source_modified":False,"implementation_created":False})
        derived=tuple(paths.values()); bound=tuple(inputs.values()); rows=[{**ident(p),"role":"P2O_A_DERIVED"} for p in derived]+[{**ident(p),"role":"P2O_A_BOUND"} for p in bound]
        mp=out/'ex6_p2b_p2o_a_manifest.csv'; write_csv(mp,rows,["artifact","role","size_bytes","sha256","path"])
        ep=out/'ex6_p2b_p2o_a_manifest_external_binding.json'; write_json(ep,{"version":VERSION,"created_at_utc":now(),"status":result_out['status'],"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"parent_r2c_manifest_sha256":PARENT_MANIFEST_SHA,"P2O_B_source_generation_authorized":True,"source_generation_performed":False,"implementation_created":False,"identity_freeze_eligible":False,"controlled_actual_fs_read_eligible":False,"source_modified":False,"actual_fs_read_executed":False,"next_gate":result_out['next_gate']})
        print(json.dumps({"status":result_out['status'],"authorized_files":3,"authorized_symbols":8,"P2O_B_source_generation_authorized":True,"source_generation_performed":False,"implementation_created":False,"controlled_actual_fs_read_eligible":False,"manifest_sha256":sha(mp),"next_gate":result_out['next_gate']},indent=2))
    except Exception as exc:
        (out/'P2O_A_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2O_A_AUTHORIZATION_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"source_modified":False,"implementation_created":False,"actual_fs_read_executed":False,"effects_observed":False},indent=2),encoding='utf-8')
        raise

def parse_args():
    p=argparse.ArgumentParser(description=VERSION)
    for flag in ['p2n-r2c-result','p2n-r2c-checks','p2n-r2c-recomputed-vectors','p2n-r2c-claim-boundary','p2n-r2c-binding','p2n-r2c-external-binding','p2n-r2c-manifest','p2n-r2c-runner','p2n-r2b-canonicalization-spec','p2n-r2b-canonicalization-vectors','project-root','output-dir']:
        p.add_argument('--'+flag,required=True)
    return p.parse_args()
if __name__=='__main__':
    try: main(parse_args())
    except Exception as exc: print(f"FAILED: {exc}",file=sys.stderr); raise SystemExit(1)
