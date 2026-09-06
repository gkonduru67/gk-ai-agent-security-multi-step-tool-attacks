#!/usr/bin/env python3
"""P2O-D controlled import and pure deterministic unit qualification.

D1 imports only the generated pure transport module and path-helper module by
exact file location under isolated synthetic module names. It observes exported
symbols and runtime signatures and constructs TrustedEventSequenceStateV1 with
zero arguments. The bridge module is not imported.

D2 runs only synthetic, deterministic pure-unit controls: canonicalization and
raw-digest vectors, protected-bound-digest determinism, event sequencing,
duplicate-consumption rejection, snapshot/restore/reset, default-factory
isolation, and synthetic Path containment. It performs no fs.read, tool call,
Sandbox/Gym action, predicate, breach logic, model use, protected fixture read,
real-secret handling, network/process action, or external effect.
"""
from __future__ import annotations
import argparse, csv, hashlib, importlib.util, inspect, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2O_D_CONTROLLED_IMPORT_AND_PURE_UNIT_QUALIFICATION_v1.0"
PARENT_VERSION="EX6_P2B_P2O_C_R1_DATACLASS_CONSTRUCTOR_CONTRACT_RECONCILIATION_v1.0"
PARENT_STATUS="P2O_C_R1_DATACLASS_CONSTRUCTOR_CONTRACT_RECONCILIATION_COMPLETE_PASS"
PARENT_MANIFEST_SHA="4EEC4E2982AA7C1F4295A2D6CF824ED7B380F09428F6C8639C8F9B8C581AE4DB"
PARENT_RUNNER_SHA="F9D16D6E69AD05B922D6E406E9EADAFBC045D7CD7CCC25F32C9BA701CE5AD033"
TRANSPORT_REL="aicomp_sdk/core/env/trusted_outcome_transport_v1.py"
TRANSPORT_SHA="5C7F7D16A37896959C6F4CC769E5F72A6E5E534EE140BA5CAF2FB70661102CE1"
PATH_REL="aicomp_sdk/core/tools/fs_trusted_result_v1.py"
PATH_SHA="EF6EC29952194AC83A741CCFAF3FCE41DD64D2D6BEE5501A8273209CD3C21F8F"
BRIDGE_REL="aicomp_sdk/core/env/sandbox_trusted_bridge_v1.py"
BRIDGE_SHA="3EE9BBB1E65949795A5639D12C55D81D8D0645357260DFC5A91DB1E9710288B6"
PROTECTED={
 "aicomp_sdk/core/env/sandbox.py":"B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0",
 "aicomp_sdk/core/predicates.py":"9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37",
 "aicomp_sdk/core/tools/fs.py":"4B8C54032ED807CE4C35BAB403EE622141881158E10F600A4B6D329E6D6F95B8",
 "aicomp_sdk/guardrails/optimal.py":"6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED",
 "aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py":"BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99",
}
POSITIVE_VALUES={
 "null":None,"false":False,"true":True,"zero":0,"negative_int":-12,
 "unicode_nfc":"e\u0301","bytes":b"\x00A","list":[1,"x",None],
 "map_order":{"b":2,"a":1},
}
NEGATIVE_VALUES={
 "float":1.0,"nan":float("nan"),"tuple":(1,2),"set":{1},"nonstring_key":{1:"x"},
}

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
def add(rows,cid,layer,passed,observed,expected):
    rows.append({"check_id":cid,"execution_layer":layer,"passed":bool(passed),"observed":str(observed),"expected":str(expected),"failure_layer":"ADAPTER_PARSE" if layer=="D1" else "AUTHORIZATION_TRANSPORT"})
def load_exact(path:Path,name:str):
    spec=importlib.util.spec_from_file_location(name,path)
    if spec is None or spec.loader is None: raise ImportError(f"cannot create import spec for {path}")
    module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module
    try: spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name,None); raise
    return module

def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    checks=[]; d1=[]; d2=[]; imported=[]
    try:
        project=Path(a.project_root).resolve(); require(project.is_dir(),f"Missing project root: {project}")
        inputs={
          "result":Path(a.p2o_c_r1_result).resolve(),"checks":Path(a.p2o_c_r1_checks).resolve(),"constructor_contract":Path(a.p2o_c_r1_constructor_contract).resolve(),"claim_boundary":Path(a.p2o_c_r1_claim_boundary).resolve(),"binding":Path(a.p2o_c_r1_binding).resolve(),"external_binding":Path(a.p2o_c_r1_external_binding).resolve(),"manifest":Path(a.p2o_c_r1_manifest).resolve(),"runner":Path(a.p2o_c_r1_runner).resolve(),"canonicalization_vectors":Path(a.canonicalization_vectors).resolve()
        }
        for k,p in inputs.items(): require(p.is_file(),f"Missing {k}: {p}")
        result=json.loads(inputs["result"].read_text(encoding="utf-8-sig")); contract=json.loads(inputs["constructor_contract"].read_text(encoding="utf-8-sig")); ext=json.loads(inputs["external_binding"].read_text(encoding="utf-8-sig"))
        vectors=list(csv.DictReader(inputs["canonicalization_vectors"].open(encoding="utf-8-sig",newline="")))
        require(result.get("version")==PARENT_VERSION and result.get("status")==PARENT_STATUS,"P2O-C-R1 parent differs")
        require(result.get("checks")=={"failed":0,"failed_ids":[],"passed":7,"total":7},"P2O-C-R1 checks differ")
        require(contract.get("contract_id")=="P2O-C-R1.DATACLASS.CONSTRUCTOR.V1" and contract.get("runtime_signature_observed") is False,"Constructor contract differs")
        require(sha(inputs["manifest"])==PARENT_MANIFEST_SHA and ext.get("manifest_sha256")==PARENT_MANIFEST_SHA,"P2O-C-R1 manifest differs")
        require(sha(inputs["runner"])==PARENT_RUNNER_SHA and ext.get("runner_sha256")==PARENT_RUNNER_SHA,"P2O-C-R1 runner differs")
        require(ext.get("controlled_import_and_pure_unit_gate_eligible") is True and ext.get("controlled_actual_fs_read_eligible") is False,"P2O-C-R1 eligibility differs")

        transport_path=project/TRANSPORT_REL; path_path=project/PATH_REL; bridge_path=project/BRIDGE_REL
        for path,expected,label in [(transport_path,TRANSPORT_SHA,"transport"),(path_path,PATH_SHA,"path_helper"),(bridge_path,BRIDGE_SHA,"bridge")]:
            require(path.is_file() and sha(path)==expected,f"{label} source identity differs")
        for rel,expected in PROTECTED.items():
            p=project/rel; require(p.is_file() and sha(p)==expected,f"Protected source differs: {rel}")

        # D1: exact local imports. Bridge remains withheld.
        transport=load_exact(transport_path,"_p2o_d_transport_v1"); imported.append("transport")
        pathmod=load_exact(path_path,"_p2o_d_path_v1"); imported.append("path_helper")
        bridge_imported=False
        required_exports=["TrustedEventSequenceStateV1","TrustedOutcomeTransportV1","canonicalize_post_hook_output_v1","compute_raw_output_sha256_v1","compute_protected_value_bound_digest_v1","snapshot_trusted_transport_state_v1"]
        exports_ok=all(hasattr(transport,x) for x in required_exports) and hasattr(pathmod,"canonical_source_path_v1")
        add(checks,"D1-01","D1",exports_ok,[x for x in required_exports if hasattr(transport,x)],required_exports)
        cls=transport.TrustedEventSequenceStateV1
        actual_sig=str(inspect.signature(cls)); params=inspect.signature(cls).parameters
        observed_optional=[name for name,p in params.items() if p.default is not inspect._empty]
        observed_required=[name for name,p in params.items() if p.default is inspect._empty]
        expected_optional=contract["static_basis"]["permitted_optional_generated_parameters"]
        add(checks,"D1-02","D1",observed_required==[],observed_required,[])
        add(checks,"D1-03","D1",observed_optional==expected_optional,observed_optional,expected_optional)
        instance_a=cls(); instance_b=cls()
        add(checks,"D1-04","D1",instance_a is not None,"constructed","zero-argument construction succeeds")
        isolation=(instance_a.counter_by_trace is not instance_b.counter_by_trace and instance_a.consumed_outcome_identities is not instance_b.consumed_outcome_identities and instance_a._lock is not instance_b._lock)
        add(checks,"D1-05","D1",isolation,isolation,"dict/set/lock identities isolated")
        add(checks,"D1-06","D1","_lock" in observed_optional,observed_optional,"_lock observed as optional parameter")
        add(checks,"D1-07","D1",not bridge_imported,bridge_imported,"bridge import withheld")
        d1=[{"module":"transport","imported":True,"source_sha256":TRANSPORT_SHA},{"module":"path_helper","imported":True,"source_sha256":PATH_SHA},{"module":"bridge","imported":False,"source_sha256":BRIDGE_SHA},{"module":"TrustedEventSequenceStateV1","runtime_signature":actual_sig,"required_parameters":";".join(observed_required),"optional_parameters":";".join(observed_optional)}]
        if any(not x["passed"] for x in checks if x["execution_layer"]=="D1"): raise ValueError("D1 failed; D2 withheld")

        # D2: frozen synthetic vectors only.
        by_id={r["vector_id"]:r for r in vectors}
        for vid,value in POSITIVE_VALUES.items():
            row=by_id[vid]; canonical=transport.canonicalize_post_hook_output_v1(value); canon_hash=hashlib.sha256(canonical).hexdigest().upper(); raw=transport.compute_raw_output_sha256_v1(value)
            ok=(str(len(canonical))==row["canonical_length"] and canon_hash==row["canonical_sha256"] and raw==row["raw_digest_sha256"])
            add(checks,f"D2-P-{vid}","D2",ok,f"{len(canonical)}|{canon_hash}|{raw}",f"{row['canonical_length']}|{row['canonical_sha256']}|{row['raw_digest_sha256']}")
            d2.append({"control":vid,"kind":"positive","passed":ok,"canonical_length":len(canonical),"canonical_sha256":canon_hash,"raw_digest_sha256":raw})
        for vid,value in NEGATIVE_VALUES.items():
            rejected=False; error=""
            try: transport.canonicalize_post_hook_output_v1(value)
            except (TypeError,ValueError) as exc: rejected=True; error=type(exc).__name__
            ok=rejected and by_id[vid].get("rejected")=="True"
            add(checks,f"D2-N-{vid}","D2",ok,error,"rejected")
            d2.append({"control":vid,"kind":"negative","passed":ok,"error_type":error})
        bd1=transport.compute_protected_value_bound_digest_v1("trace-1","proposal-1","trace-1:outcome:2","/synthetic.txt","A"*64)
        bd2=transport.compute_protected_value_bound_digest_v1("trace-1","proposal-1","trace-1:outcome:2","/synthetic.txt","A"*64)
        add(checks,"D2-20","D2",bd1==bd2 and len(bd1)==64,bd1,"deterministic uppercase SHA-256")
        state=cls(); e1=state.allocate("trace-1","proposal"); e2=state.allocate("trace-1","outcome")
        add(checks,"D2-21","D2",(e1,e2)==("trace-1:proposal:1","trace-1:outcome:2"),(e1,e2),("trace-1:proposal:1","trace-1:outcome:2"))
        state.consume_outcome(e2); duplicate_rejected=False
        try: state.consume_outcome(e2)
        except ValueError: duplicate_rejected=True
        add(checks,"D2-22","D2",duplicate_rejected,duplicate_rejected,True)
        snap=state.snapshot(); restored=cls(); restored.restore(snap)
        add(checks,"D2-23","D2",restored.snapshot()==snap,restored.snapshot(),snap)
        restored.reset(); reset_ok=(restored.counter_by_trace=={} and restored.consumed_outcome_identities==set())
        add(checks,"D2-24","D2",reset_ok,reset_ok,True)
        synthetic_root=project/"_p2o_d_nonexistent_root"; inside=synthetic_root/"sub"/"file.txt"; outside=project.parent/"outside.txt"
        canonical_path=pathmod.canonical_source_path_v1(synthetic_root,"sub/file.txt",inside)
        add(checks,"D2-25","D2",canonical_path=="/sub/file.txt",canonical_path,"/sub/file.txt")
        outside_rejected=False
        try: pathmod.canonical_source_path_v1(synthetic_root,"../outside.txt",outside)
        except ValueError: outside_rejected=True
        add(checks,"D2-26","D2",outside_rejected,outside_rejected,True)

        failed=[r["check_id"] for r in checks if not r["passed"]]; qualified=not failed
        status="P2O_D_CONTROLLED_IMPORT_AND_PURE_UNIT_QUALIFICATION_COMPLETE_PASS" if qualified else "P2O_D_CONTROLLED_IMPORT_AND_PURE_UNIT_QUALIFICATION_COMPLETE_WITH_GAPS"
        next_gate="EX6_P2B_P2O_E_BRIDGE_IMPORT_AND_SYNTHETIC_INTEGRATION_QUALIFICATION" if qualified else "EX6_P2B_P2O_D_R1_PURE_MODULE_RECONCILIATION"
        claim={"allowed":["controlled importability of the pure transport and path-helper modules","observed runtime constructor signature and zero-argument construction","synthetic pure-unit canonicalization, digest, sequence, snapshot, reset, isolation, and path-control findings","eligibility recommendation for a separate bridge-import synthetic-integration gate"],"prohibited":["bridge importability","Sandbox instantiation or behavior","actual fs.read behavior","tool execution","source retrieval success","real secret capture","protected-value lineage","end-to-end authorization transport correctness","guardrail effectiveness","real exfiltration prevention"]}
        result_out={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"CONTROLLED_LOCAL_IMPORT_AND_SYNTHETIC_PURE_UNIT_CONTROLS","P2O_C_R1_parent_verified":True,"checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"D1":{"transport_imported":True,"path_helper_imported":True,"bridge_imported":False,"runtime_constructor_signature":actual_sig,"required_parameters":observed_required,"optional_parameters":observed_optional,"zero_argument_construction":True,"default_factory_isolation":isolation},"D2":{"positive_vectors":len(POSITIVE_VALUES),"negative_vectors":len(NEGATIVE_VALUES),"pure_unit_controls_passed":qualified},"readiness":{"bridge_import_and_synthetic_integration_gate_eligible":qualified,"pure_modules_importable":qualified,"implementation_pure_unit_qualified":qualified,"implementation_runtime_integrated":False,"identity_freeze_eligible":False,"controlled_actual_fs_read_eligible":False},"execution_boundaries":{"source_modified":False,"transport_module_imported":True,"path_helper_module_imported":True,"bridge_module_imported":False,"sandbox_instantiated":False,"sandbox_executed":False,"actual_fs_read_executed":False,"tools_executed":False,"protected_fixture_contents_read":False,"real_secret_values_used":False,"gym_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False,"external_effects_observed":False},"scientific_verdict":{"pure_module_importability":"ESTABLISHED" if qualified else "GAPS_IDENTIFIED","synthetic_pure_unit_behavior":"ESTABLISHED_WITHIN_FROZEN_SYNTHETIC_SCOPE" if qualified else "GAPS_IDENTIFIED","bridge_importability":"NOT_EVALUATED","actual_source_retrieval":"NOT_EVALUATED","secret_capture":"NOT_ESTABLISHED","protected_value_lineage":"NOT_ESTABLISHED","authorization_transport_correctness":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim,"next_gate":next_gate}
        rp=out/"ex6_p2b_p2o_d_result.json"; cp=out/"ex6_p2b_p2o_d_checks.csv"; d1p=out/"ex6_p2b_p2o_d_d1_imports.csv"; d2p=out/"ex6_p2b_p2o_d_d2_units.csv"; cl=out/"ex6_p2b_p2o_d_claim_boundary.json"; bp=out/"ex6_p2b_p2o_d_binding.json"
        write_json(rp,result_out); write_csv(cp,checks,["check_id","execution_layer","passed","observed","expected","failure_layer"]); write_csv(d1p,d1,["module","imported","source_sha256","runtime_signature","required_parameters","optional_parameters"]); write_csv(d2p,d2,["control","kind","passed","canonical_length","canonical_sha256","raw_digest_sha256","error_type"]); write_json(cl,claim); write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{k:ident(v) for k,v in inputs.items()},"sources":{"transport":ident(transport_path),"path_helper":ident(path_path),"bridge_withheld":ident(bridge_path)},"project_root":str(project),"source_modified":False,"bridge_module_imported":False})
        derived=(rp,cp,d1p,d2p,cl,bp); bound=tuple(inputs.values()); sources=(transport_path,path_path,bridge_path)
        rows=[{**ident(p),"role":"P2O_D_DERIVED"} for p in derived]+[{**ident(p),"role":"P2O_D_BOUND"} for p in bound]+[{**ident(p),"role":"P2O_D_SOURCE" if p!=bridge_path else "P2O_D_WITHHELD_BRIDGE_SOURCE"} for p in sources]
        mp=out/"ex6_p2b_p2o_d_manifest.csv"; write_csv(mp,rows,["artifact","role","size_bytes","sha256","path"])
        ep=out/"ex6_p2b_p2o_d_manifest_external_binding.json"; write_json(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"parent_p2o_c_r1_manifest_sha256":PARENT_MANIFEST_SHA,"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"bridge_import_and_synthetic_integration_gate_eligible":qualified,"bridge_module_imported":False,"controlled_actual_fs_read_eligible":False,"source_modified":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"runtime_constructor_signature":actual_sig,"bridge_module_imported":False,"controlled_actual_fs_read_eligible":False,"manifest_sha256":sha(mp),"next_gate":next_gate},indent=2))
    except Exception as exc:
        (out/"P2O_D_FAILED.json").write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2O_D_QUALIFICATION_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"checks_frozen":checks,"imported_layers":imported,"bridge_module_imported":False,"source_modified":False,"actual_fs_read_executed":False,"tools_executed":False,"sandbox_instantiated":False,"effects_observed":False},indent=2),encoding="utf-8")
        raise

def parse_args():
    p=argparse.ArgumentParser(description=VERSION)
    for flag in ["p2o-c-r1-result","p2o-c-r1-checks","p2o-c-r1-constructor-contract","p2o-c-r1-claim-boundary","p2o-c-r1-binding","p2o-c-r1-external-binding","p2o-c-r1-manifest","p2o-c-r1-runner","canonicalization-vectors","project-root","output-dir"]:
        p.add_argument("--"+flag,required=True)
    return p.parse_args()
if __name__=="__main__":
    try: main(parse_args())
    except Exception as exc: print(f"FAILED: {exc}",file=sys.stderr); raise SystemExit(1)
