#!/usr/bin/env python3
"""EX6 P2B P2G R1 GuardrailBase contract discovery.
Read-only source/import inspection. Does not instantiate the adapter or execute
any guardrail decision, model, tool, Sandbox, Gym, predicate, or breach logic.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, importlib, inspect, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2G_R1_GUARDRAILBASE_CONTRACT_DISCOVERY_v1.0"
EXPECTED_P2F_STATUS="P2F_R1_PACKAGE_DISCOVERY_AND_IMPORT_INTERFACE_PREFLIGHT_COMPLETE_PASS"
EXPECTED_SOURCE_SHA="BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"
EXPECTED_ADAPTER_CLASS="TrustedGuardrailContextAdapterV1_1"

def now(): return datetime.now(timezone.utc).isoformat()
def require(c,m):
    if not c: raise ValueError(m)
def sha(p):
    h=hashlib.sha256(); h.update(Path(p).read_bytes()); return h.hexdigest().upper()
def ident(p):
    p=Path(p).resolve(); return {"artifact":p.name,"path":str(p),"size_bytes":p.stat().st_size,"sha256":sha(p)}
def write_json(p,x):
    with Path(p).open('x',encoding='utf-8',newline='\n') as f: json.dump(x,f,indent=2,sort_keys=True); f.write('\n')
def write_csv(p,rows,fields):
    with Path(p).open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n'); w.writeheader(); w.writerows(rows)

def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    original_path=list(sys.path)
    try:
        p2f=Path(a.p2f_r1_result).resolve(); source=Path(a.repaired_source).resolve(); root=Path(a.project_root).resolve()
        for n,p in (("P2F result",p2f),("repaired source",source)): require(p.is_file(),f"Missing {n}: {p}")
        parent=json.loads(p2f.read_text(encoding='utf-8-sig'))
        require(parent.get('status')==EXPECTED_P2F_STATUS,'P2F R1 parent is not PASS')
        require(sha(source)==EXPECTED_SOURCE_SHA,'Repaired source identity mismatch')
        require((root/'aicomp_sdk').is_dir(),'Project root does not contain aicomp_sdk')
        sys.path.insert(0,str(root)); importlib.invalidate_caches()
        base_mod=importlib.import_module('aicomp_sdk.guardrails.base')
        adapter_mod=importlib.import_module('aicomp_sdk.guardrails.trusted_context_adapter_v1_1')
        GuardrailBase=getattr(base_mod,'GuardrailBase'); Adapter=getattr(adapter_mod,EXPECTED_ADAPTER_CLASS)
        base_file=Path(inspect.getsourcefile(GuardrailBase)).resolve()
        base_text=base_file.read_text(encoding='utf-8-sig'); tree=ast.parse(base_text)
        base_cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='GuardrailBase')
        methods=[]
        for n in base_cls.body:
            if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):
                methods.append({"method":n.name,"signature":str(inspect.signature(getattr(GuardrailBase,n.name))),"is_abstract":bool(getattr(getattr(GuardrailBase,n.name),'__isabstractmethod__',False)),"line_start":n.lineno,"line_end":getattr(n,'end_lineno',n.lineno)})
        contract={
          "guardrail_base_file":ident(base_file),
          "is_abstract_class":inspect.isabstract(GuardrailBase),
          "abstract_methods":sorted(getattr(GuardrailBase,'__abstractmethods__',set())),
          "constructor_signature":str(inspect.signature(GuardrailBase)),
          "adapter_constructor_signature":str(inspect.signature(Adapter)),
          "adapter_requires_isinstance_guardrailbase":'isinstance(inner_guardrail, GuardrailBase)' in source.read_text(encoding='utf-8'),
          "minimum_concrete_test_double_plan":{
            "class_name":"P2GR1GuardrailBaseStub",
            "base_class":"GuardrailBase",
            "override_decide":True,
            "decide_behavior":"raise RuntimeError if called; decision execution prohibited",
            "snapshot_restore":"inherited unless contract requires override"
          }
        }
        eligible=(not inspect.isabstract(GuardrailBase)) or bool(contract['minimum_concrete_test_double_plan'])
        result={
          "version":VERSION,"created_at_utc":now(),"status":"P2G_R1_GUARDRAILBASE_CONTRACT_DISCOVERY_COMPLETE_PASS",
          "classification":"READ_ONLY_GUARDRAILBASE_CONTRACT_DISCOVERY",
          "P2F_R1_parent_verified":True,"repaired_source_identity":ident(source),
          "contract":contract,"constructor_retry_eligibility":"ELIGIBLE_WITH_GUARDRAILBASE_SUBCLASS_STUB" if eligible else "BLOCKED",
          "source_modified":False,
          "execution_boundaries":{"adapter_instantiated":False,"guardrail_decide_executed":False,"sandbox_executed":False,"gym_executed":False,"tools_executed":False,"predicates_executed":False,"breach_executed":False},
          "scientific_verdict":{"constructor_dependency_contract":"ESTABLISHED","constructor_compatibility":"NOT_EVALUATED","state_interface_visibility":"NOT_EVALUATED","runtime_compatibility":"NOT_ESTABLISHED","authorization_transport_correctness":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},
          "claim_boundary":{"allowed":["GuardrailBase source identity","GuardrailBase inheritance contract","constructor dependency contract","minimum controlled subclass-stub plan"],"prohibited":["constructor compatibility","runtime compatibility","authorization transport correctness","requirement satisfaction","guardrail effectiveness","security improvement"]},
          "next_gate":"EX6_P2B_P2G_R2_CONTROLLED_CONSTRUCTOR_AND_STATE_PREFLIGHT_WITH_GUARDRAILBASE_STUB"
        }
        rp=out/'ex6_p2b_p2g_r1_result.json'; mp=out/'ex6_p2b_p2g_r1_methods.csv'; bp=out/'ex6_p2b_p2g_r1_binding.json'; cp=out/'ex6_p2b_p2g_r1_claim_boundary.json'
        write_json(rp,result); write_csv(mp,methods,['method','signature','is_abstract','line_start','line_end']); write_json(cp,result['claim_boundary'])
        write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{"p2f_r1_result":ident(p2f),"repaired_source":ident(source),"guardrail_base":ident(base_file)},"source_modified":False})
        rows=[{**ident(x),"role":"P2G_R1_DERIVED"} for x in (rp,mp,bp,cp)]+[{**ident(x),"role":"P2G_R1_BOUND"} for x in (p2f,source,base_file)]
        man=out/'ex6_p2b_p2g_r1_manifest.csv'; write_csv(man,rows,['artifact','role','size_bytes','sha256','path'])
        ext=out/'ex6_p2b_p2g_r1_manifest_external_binding.json'; write_json(ext,{"version":VERSION,"created_at_utc":now(),"status":result['status'],"manifest_filename":man.name,"manifest_size_bytes":man.stat().st_size,"manifest_sha256":sha(man),"runner_sha256":sha(Path(__file__).resolve()),"adapter_instantiated":False,"runtime_validated":False,"requirements_satisfied":False,"next_gate":result['next_gate']})
        print(json.dumps({"status":result['status'],"guardrail_base_file":str(base_file),"is_abstract_class":contract['is_abstract_class'],"abstract_methods":contract['abstract_methods'],"constructor_retry_eligibility":result['constructor_retry_eligibility'],"manifest_sha256":sha(man),"next_gate":result['next_gate']},indent=2))
    except Exception as e:
        (out/'P2G_R1_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2G_R1_CONTRACT_DISCOVERY_BLOCKED","error_type":type(e).__name__,"error":str(e),"adapter_instantiated":False,"runtime_validated":False},indent=2),encoding='utf-8')
        raise
    finally:
        sys.path[:]=original_path

def args():
    p=argparse.ArgumentParser(description=VERSION)
    p.add_argument('--p2f-r1-result',required=True); p.add_argument('--repaired-source',required=True); p.add_argument('--project-root',required=True); p.add_argument('--output-dir',required=True)
    return p.parse_args()
if __name__=='__main__':
    try: main(args())
    except Exception as e: print(f'FAILED: {e}',file=sys.stderr); raise SystemExit(1)
