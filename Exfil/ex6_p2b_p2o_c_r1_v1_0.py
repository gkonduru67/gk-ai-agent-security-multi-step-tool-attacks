#!/usr/bin/env python3
"""P2O-C-R1 dataclass constructor contract reconciliation.

Read-only contract review. Distinguishes absence of an explicit __init__ from
the runtime constructor synthesized by @dataclass. It does not import modules,
execute decorators or generated symbols, or modify source. It statically derives
whether every init=True dataclass field has a default/default_factory and freezes
the authorized meaning of `TrustedEventSequenceStateV1()` as: zero arguments are
required; optional keyword parameters synthesized from defaulted dataclass fields
are permitted.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2O_C_R1_DATACLASS_CONSTRUCTOR_CONTRACT_RECONCILIATION_v1.0"
PARENT_VERSION="EX6_P2B_P2O_C_INDEPENDENT_SOURCE_AND_AUTHORIZATION_CONFORMANCE_QUALIFICATION_v1.0"
PARENT_STATUS="P2O_C_INDEPENDENT_SOURCE_AND_AUTHORIZATION_CONFORMANCE_QUALIFICATION_COMPLETE_PASS"
PARENT_MANIFEST_SHA="7F592B7762B4F818B7D1212A2918EBB673FC4E96608D272B5CB3B98D684C66DE"
PARENT_RUNNER_SHA="5CE3DDC0AF422E604DA245C04D0A4DDE1E7A1E9C21C4BA6B8AFE9412C7F61594"
SOURCE_REL="aicomp_sdk/core/env/trusted_outcome_transport_v1.py"
SOURCE_SHA="5C7F7D16A37896959C6F4CC769E5F72A6E5E534EE140BA5CAF2FB70661102CE1"
CLASS_NAME="TrustedEventSequenceStateV1"

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
def decorator_name(node):
    target=node.func if isinstance(node,ast.Call) else node
    try: return ast.unparse(target)
    except Exception: return ""
def field_call_info(value):
    info={"uses_field":False,"init":True,"has_default":False,"has_default_factory":False}
    if isinstance(value,ast.Call):
        try: name=ast.unparse(value.func)
        except Exception: name=""
        if name in {"field","dataclasses.field"}:
            info["uses_field"]=True
            for kw in value.keywords:
                if kw.arg=="init" and isinstance(kw.value,ast.Constant): info["init"]=bool(kw.value.value)
                elif kw.arg=="default": info["has_default"]=True
                elif kw.arg=="default_factory": info["has_default_factory"]=True
    return info

def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    checks=[]
    try:
        project=Path(a.project_root).resolve(); require(project.is_dir(),f"Missing project root: {project}")
        inputs={
          "result":Path(a.p2o_c_result).resolve(),"checks":Path(a.p2o_c_checks).resolve(),"signatures":Path(a.p2o_c_signatures).resolve(),"claim_boundary":Path(a.p2o_c_claim_boundary).resolve(),"binding":Path(a.p2o_c_binding).resolve(),"external_binding":Path(a.p2o_c_external_binding).resolve(),"manifest":Path(a.p2o_c_manifest).resolve(),"runner":Path(a.p2o_c_runner).resolve(),"p2o_a_symbols":Path(a.p2o_a_symbols).resolve()
        }
        for k,p in inputs.items(): require(p.is_file(),f"Missing {k}: {p}")
        result=json.loads(inputs['result'].read_text(encoding='utf-8-sig')); ext=json.loads(inputs['external_binding'].read_text(encoding='utf-8-sig')); claim=json.loads(inputs['claim_boundary'].read_text(encoding='utf-8-sig'))
        check_rows=list(csv.DictReader(inputs['checks'].open(encoding='utf-8-sig',newline=''))); sig_rows=list(csv.DictReader(inputs['signatures'].open(encoding='utf-8-sig',newline=''))); auth_symbols=list(csv.DictReader(inputs['p2o_a_symbols'].open(encoding='utf-8-sig',newline='')))
        require(result.get('version')==PARENT_VERSION and result.get('status')==PARENT_STATUS,'P2O-C parent differs')
        require(result.get('checks')=={'failed':0,'failed_ids':[],'passed':45,'total':45},'P2O-C check summary differs')
        require(sha(inputs['manifest'])==PARENT_MANIFEST_SHA and ext.get('manifest_sha256')==PARENT_MANIFEST_SHA,'P2O-C manifest differs')
        require(sha(inputs['runner'])==PARENT_RUNNER_SHA and ext.get('runner_sha256')==PARENT_RUNNER_SHA,'P2O-C runner differs')
        require(any(r.get('check_id')=='Q415' and r.get('passed')=='True' for r in check_rows),'Q415 parent evidence missing')
        require(any(r.get('symbol')==CLASS_NAME and r.get('match')=='True' for r in sig_rows),'P2O-C class signature row missing')
        auth_row=next((r for r in auth_symbols if r.get('name')==CLASS_NAME),None); require(auth_row is not None,'P2O-A symbol authorization missing')
        require(auth_row.get('signature')==f'{CLASS_NAME}()','Authorized textual constructor differs')

        source=project/Path(SOURCE_REL); require(source.is_file(),f"Missing source: {source}"); require(sha(source)==SOURCE_SHA,'Generated source identity differs')
        tree=ast.parse(source.read_text(encoding='utf-8'),filename=str(source))
        cls=next((n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==CLASS_NAME),None); require(cls is not None,'Target class missing')
        decorators=[decorator_name(x) for x in cls.decorator_list]
        explicit_init=next((n for n in cls.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=='__init__'),None)
        dataclass_declared=any(x in {'dataclass','dataclasses.dataclass'} for x in decorators)
        fields=[]
        for node in cls.body:
            if not isinstance(node,ast.AnnAssign) or not isinstance(node.target,ast.Name): continue
            name=node.target.id; info=field_call_info(node.value)
            has_plain_default=node.value is not None and not info['uses_field']
            has_default=has_plain_default or info['has_default'] or info['has_default_factory']
            required=info['init'] and not has_default
            fields.append({"field":name,"annotation":ast.unparse(node.annotation),"init":info['init'],"default_kind":"default_factory" if info['has_default_factory'] else "default" if has_default else "none","required_at_runtime_constructor":required})
        required_fields=[r['field'] for r in fields if r['required_at_runtime_constructor']]
        optional_init_fields=[r['field'] for r in fields if r['init'] and not r['required_at_runtime_constructor']]

        observations=[
          ("R1-01",dataclass_declared,decorators,"@dataclass declared"),
          ("R1-02",explicit_init is None,explicit_init is None,"no explicit __init__"),
          ("R1-03",len(fields)>0,len(fields),">0 annotated dataclass fields"),
          ("R1-04",not required_fields,required_fields,"zero required generated constructor arguments"),
          ("R1-05",len(optional_init_fields)>0,optional_init_fields,"optional generated parameters explicitly acknowledged"),
          ("R1-06",auth_row.get('signature')==f'{CLASS_NAME}()',auth_row.get('signature'),"zero arguments required contract"),
          ("R1-07",set(claim.get('prohibited',[])) >= {'importability','runtime behavior'},claim.get('prohibited'),"importability/runtime behavior prohibited"),
        ]
        for cid,ok,observed,expected in observations: checks.append({"check_id":cid,"passed":bool(ok),"observed":str(observed),"expected":str(expected),"failure_layer":"ADAPTER_PARSE" if cid not in {'R1-07'} else "CLAIM_BOUNDARY"})
        failed=[r['check_id'] for r in checks if not r['passed']]
        reconciled=not failed
        contract={
          "contract_id":"P2O-C-R1.DATACLASS.CONSTRUCTOR.V1",
          "class":CLASS_NAME,
          "authorized_call_form":f"{CLASS_NAME}()",
          "meaning":"zero arguments are required for construction; dataclass-generated optional parameters corresponding to init=True fields with defaults or default_factory are permitted",
          "strictly_no_optional_parameters_required":False,
          "explicit_init_required":False,
          "runtime_signature_observed":False,
          "static_basis":{"dataclass_declared":dataclass_declared,"explicit_init_present":explicit_init is not None,"required_generated_parameters":required_fields,"permitted_optional_generated_parameters":optional_init_fields},
          "source_modification_required":False,
          "future_control":"P2O-D must import in a controlled environment and confirm zero-argument callability plus actual runtime signature before broader runtime claims",
        }
        status='P2O_C_R1_DATACLASS_CONSTRUCTOR_CONTRACT_RECONCILIATION_COMPLETE_PASS' if reconciled else 'P2O_C_R1_DATACLASS_CONSTRUCTOR_CONTRACT_RECONCILIATION_COMPLETE_WITH_GAPS'
        next_gate='EX6_P2B_P2O_D_CONTROLLED_IMPORT_AND_PURE_UNIT_QUALIFICATION' if reconciled else 'EX6_P2B_P2O_C_R2_SOURCE_CONTRACT_REMEDIATION_AUTHORIZATION'
        claim_out={"allowed":["static dataclass declaration and field-default findings","zero-required-argument constructor contract clarification","eligibility recommendation for controlled import and pure-unit qualification"],"prohibited":["runtime constructor signature","importability","runtime behavior","runtime canonicalization correctness","actual fs.read behavior","source retrieval success","secret capture","protected-value lineage","authorization transport correctness","guardrail effectiveness","real exfiltration prevention"]}
        result_out={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"READ_ONLY_CONTRACT_RECONCILIATION","P2O_C_parent_verified":True,"checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"reconciliation":{"constructor_contract":contract,"outcome":"RECONCILED" if reconciled else "GAPS_IDENTIFIED"},"readiness":{"controlled_import_and_pure_unit_gate_eligible":reconciled,"source_modification_required":False if reconciled else None,"generated_modules_imported":False,"generated_symbols_executed":False,"implementation_runtime_qualified":False,"identity_freeze_eligible":False,"controlled_actual_fs_read_eligible":False},"execution_boundaries":{"source_modified":False,"generated_modules_imported":False,"generated_symbols_executed":False,"actual_fs_read_executed":False,"tools_executed":False,"sandbox_instantiated":False,"sandbox_executed":False,"gym_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False,"effects_observed":False},"scientific_verdict":{"constructor_contract":"ESTABLISHED_AS_STATIC_SEMANTIC_CLARIFICATION" if reconciled else "NOT_RECONCILED","runtime_constructor_signature":"NOT_EVALUATED","importability":"NOT_EVALUATED","implementation_runtime_behavior":"NOT_EVALUATED","authorization_transport_correctness":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim_out,"next_gate":next_gate}
        rp=out/'ex6_p2b_p2o_c_r1_result.json'; cp=out/'ex6_p2b_p2o_c_r1_checks.csv'; fp=out/'ex6_p2b_p2o_c_r1_dataclass_fields.csv'; kp=out/'ex6_p2b_p2o_c_r1_constructor_contract.json'; cl=out/'ex6_p2b_p2o_c_r1_claim_boundary.json'; bp=out/'ex6_p2b_p2o_c_r1_binding.json'
        write_json(rp,result_out); write_csv(cp,checks,['check_id','passed','observed','expected','failure_layer']); write_csv(fp,fields,['field','annotation','init','default_kind','required_at_runtime_constructor']); write_json(kp,contract); write_json(cl,claim_out); write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{k:ident(v) for k,v in inputs.items()},"source":ident(source),"project_root":str(project),"source_modified":False,"generated_modules_imported":False})
        derived=(rp,cp,fp,kp,cl,bp); bound=tuple(inputs.values()); rows=[{**ident(p),"role":"P2O_C_R1_DERIVED"} for p in derived]+[{**ident(p),"role":"P2O_C_R1_BOUND"} for p in bound]+[{**ident(source),"role":"P2O_C_R1_REVIEWED_SOURCE"}]
        mp=out/'ex6_p2b_p2o_c_r1_manifest.csv'; write_csv(mp,rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'ex6_p2b_p2o_c_r1_manifest_external_binding.json'; write_json(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"parent_p2o_c_manifest_sha256":PARENT_MANIFEST_SHA,"constructor_contract_id":contract['contract_id'],"controlled_import_and_pure_unit_gate_eligible":reconciled,"source_modified":False,"generated_modules_imported":False,"generated_symbols_executed":False,"controlled_actual_fs_read_eligible":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"required_generated_parameters":required_fields,"permitted_optional_generated_parameters":optional_init_fields,"runtime_signature_observed":False,"source_modified":False,"manifest_sha256":sha(mp),"next_gate":next_gate},indent=2))
    except Exception as exc:
        (out/'P2O_C_R1_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2O_C_R1_RECONCILIATION_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"checks_frozen":checks,"source_modified":False,"generated_modules_imported":False,"generated_symbols_executed":False,"actual_fs_read_executed":False,"effects_observed":False},indent=2),encoding='utf-8')
        raise

def parse_args():
    p=argparse.ArgumentParser(description=VERSION)
    for flag in ['p2o-c-result','p2o-c-checks','p2o-c-signatures','p2o-c-claim-boundary','p2o-c-binding','p2o-c-external-binding','p2o-c-manifest','p2o-c-runner','p2o-a-symbols','project-root','output-dir']:
        p.add_argument('--'+flag,required=True)
    return p.parse_args()
if __name__=='__main__':
    try: main(parse_args())
    except Exception as exc: print(f"FAILED: {exc}",file=sys.stderr); raise SystemExit(1)
