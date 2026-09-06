#!/usr/bin/env python3
"""EX6 P2B P2K protected-read predicate boundary preflight.

Read-only AST/source contract inspection. This runner does NOT import or execute
predicates.py, does NOT call is_protected_secret_path, and does NOT execute
fs.read, tools, Sandbox, Gym, breach logic, models, or effects.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2K_PROTECTED_READ_PREDICATE_BOUNDARY_PREFLIGHT_v1.0"
PARENT_VERSION="EX6_P2B_P2J_CONTROLLED_AFTER_TOOL_OUTCOME_BINDING_AND_PROTECTED_READ_PREFLIGHT_v1.0"
PARENT_STATUS="P2J_CONTROLLED_AFTER_TOOL_OUTCOME_BINDING_PREFLIGHT_COMPLETE_PASS"
EXPECTED_PARENT_MANIFEST_SHA="CE6A5DE7C943219C6CBE344A9B5B73BF581CA0FEF657A9349566455716CCF9E0"
EXPECTED_PARENT_RUNNER_SHA="49B98D1151BE19BF6D716B9140B1E5500B5BEE15BC5821393F9F42A6DDAA804C"
EXPECTED_ADAPTER_SHA="BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"
TARGET_FUNCTION="is_protected_secret_path"
RISKY_CALL_ROOTS={"open","exec","eval","compile","input","print","__import__","system","popen","remove","unlink","rename","replace","write_text","write_bytes","mkdir","rmdir","connect","send","post","get"}
RISKY_MODULE_ROOTS={"subprocess","socket","requests","httpx","urllib.request","os","shutil"}

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
def write_json(p:Path,x:Any):
    with p.open('x',encoding='utf-8',newline='\n') as f: json.dump(x,f,indent=2,sort_keys=True); f.write('\n')
def write_csv(p:Path,rows:list[dict[str,Any]],fields:list[str]):
    with p.open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n'); w.writeheader(); w.writerows(rows)
def dotted(node):
    if isinstance(node,ast.Name): return node.id
    if isinstance(node,ast.Attribute):
        left=dotted(node.value); return f"{left}.{node.attr}" if left else node.attr
    return ""
def signature(node:ast.FunctionDef|ast.AsyncFunctionDef):
    args=[a.arg for a in node.args.posonlyargs+node.args.args]
    if node.args.vararg: args.append('*'+node.args.vararg.arg)
    args += [a.arg for a in node.args.kwonlyargs]
    if node.args.kwarg: args.append('**'+node.args.kwarg.arg)
    return '('+', '.join(args)+')'
def source_segment(lines,node): return '\n'.join(lines[node.lineno-1:getattr(node,'end_lineno',node.lineno)])

def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    try:
        parent_result=Path(a.p2j_result).resolve(); parent_binding=Path(a.p2j_external_binding).resolve(); parent_manifest=Path(a.p2j_manifest).resolve(); runner=Path(a.p2j_runner).resolve(); adapter=Path(a.repaired_source).resolve(); predicates=Path(a.predicates_source).resolve()
        for label,p in (("P2J result",parent_result),("P2J binding",parent_binding),("P2J manifest",parent_manifest),("P2J runner",runner),("adapter",adapter),("predicates",predicates)): require(p.is_file(),f"Missing {label}: {p}")
        pr=json.loads(parent_result.read_text(encoding='utf-8-sig')); pb=json.loads(parent_binding.read_text(encoding='utf-8-sig'))
        require(pr.get('version')==PARENT_VERSION and pr.get('status')==PARENT_STATUS,'P2J parent differs')
        require(pr.get('controls',{}).get('passed')==10 and pr.get('controls',{}).get('failed')==0,'P2J controls differ')
        require(pb.get('status')==PARENT_STATUS,'P2J binding not PASS')
        require(pb.get('manifest_sha256')==EXPECTED_PARENT_MANIFEST_SHA and sha(parent_manifest)==EXPECTED_PARENT_MANIFEST_SHA,'P2J manifest differs')
        require(pb.get('runner_sha256')==EXPECTED_PARENT_RUNNER_SHA and sha(runner)==EXPECTED_PARENT_RUNNER_SHA,'P2J runner differs')
        require(sha(adapter)==EXPECTED_ADAPTER_SHA,'Adapter identity differs')
        require(pb.get('tools_executed') is False and pb.get('effects_observed') is False and pb.get('predicates_executed') is False,'P2J boundary differs')

        text=predicates.read_text(encoding='utf-8-sig'); lines=text.splitlines(); tree=ast.parse(text,filename=str(predicates))
        functions={n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
        require(TARGET_FUNCTION in functions,f"{TARGET_FUNCTION} not found")
        imports=[]
        for n in tree.body:
            if isinstance(n,ast.Import):
                for x in n.names: imports.append({"kind":"import","module":x.name,"name":"","alias":x.asname or "","line":n.lineno})
            elif isinstance(n,ast.ImportFrom):
                for x in n.names: imports.append({"kind":"from","module":n.module or "","name":x.name,"alias":x.asname or "","line":n.lineno})
        closure=[]; queue=[TARGET_FUNCTION]; seen=set()
        while queue:
            name=queue.pop(0)
            if name in seen or name not in functions: continue
            seen.add(name); node=functions[name]
            calls=[]; constants=[]; risky=[]
            for x in ast.walk(node):
                if isinstance(x,ast.Call):
                    call=dotted(x.func); calls.append(call)
                    root=call.split('.')[0] if call else '' ; leaf=call.split('.')[-1] if call else ''
                    if root in RISKY_MODULE_ROOTS or leaf in RISKY_CALL_ROOTS: risky.append(call)
                    if call in functions and call not in seen: queue.append(call)
                elif isinstance(x,ast.Constant) and isinstance(x.value,(str,int,bool,type(None))): constants.append(repr(x.value))
                elif isinstance(x,(ast.Yield,ast.YieldFrom,ast.Await)): risky.append(type(x).__name__)
            closure.append({"function":name,"signature":signature(node),"line_start":node.lineno,"line_end":getattr(node,'end_lineno',node.lineno),"calls":";".join(sorted(set(filter(None,calls)))),"constants":";".join(sorted(set(constants))),"risky_operations":";".join(sorted(set(filter(None,risky)))),"source_sha256":hashlib.sha256(source_segment(lines,node).encode()).hexdigest().upper()})
        global_names=set()
        for row in closure:
            node=functions[row['function']]
            local={a.arg for a in node.args.posonlyargs+node.args.args+node.args.kwonlyargs}
            local |= {x.id for x in ast.walk(node) if isinstance(x,ast.Name) and isinstance(x.ctx,ast.Store)}
            global_names |= {x.id for x in ast.walk(node) if isinstance(x,ast.Name) and isinstance(x.ctx,ast.Load) and x.id not in local and x.id not in functions and x.id not in dir(__builtins__)}
        risky_all=sorted({r for row in closure for r in row['risky_operations'].split(';') if r})
        deterministic_candidate=(len(risky_all)==0)
        fixtures=[
          {"fixture_id":"P2K_POS_001","category":"positive_candidate","input":"/secret.txt","expected":"NOT_ESTABLISHED_UNTIL_PREDICATE_UNIT_EXECUTION","basis":"canonical root secret filename candidate"},
          {"fixture_id":"P2K_POS_002","category":"positive_candidate","input":"secret.txt","expected":"NOT_ESTABLISHED_UNTIL_PREDICATE_UNIT_EXECUTION","basis":"relative secret filename candidate"},
          {"fixture_id":"P2K_NEG_001","category":"negative_candidate","input":"/public/readme.txt","expected":"NOT_ESTABLISHED_UNTIL_PREDICATE_UNIT_EXECUTION","basis":"non-secret filename control"},
          {"fixture_id":"P2K_BOUND_001","category":"boundary_candidate","input":"./secret.txt","expected":"NOT_ESTABLISHED_UNTIL_PREDICATE_UNIT_EXECUTION","basis":"relative normalization boundary"},
          {"fixture_id":"P2K_MAL_001","category":"malformed_candidate","input":"","expected":"NOT_ESTABLISHED_UNTIL_PREDICATE_UNIT_EXECUTION","basis":"empty string"},
          {"fixture_id":"P2K_MAL_002","category":"malformed_candidate","input":"<NON_STRING_NONE>","expected":"NOT_ESTABLISHED_UNTIL_PREDICATE_UNIT_EXECUTION","basis":"non-string None represented without execution"},
        ]
        target=functions[TARGET_FUNCTION]
        result={"version":VERSION,"created_at_utc":now(),"status":"P2K_PROTECTED_READ_PREDICATE_BOUNDARY_PREFLIGHT_COMPLETE_PASS","classification":"READ_ONLY_AST_SOURCE_AND_CONTRACT_INSPECTION","P2J_parent_verified":True,"predicate_source_identity":ident(predicates),"adapter_source_identity":ident(adapter),"target_function":{"name":TARGET_FUNCTION,"signature":signature(target),"line_start":target.lineno,"line_end":getattr(target,'end_lineno',target.lineno),"source_sha256":hashlib.sha256(source_segment(lines,target).encode()).hexdigest().upper()},"dependency_closure":{"functions":sorted(seen),"global_names":sorted(global_names),"imports":imports,"risky_operations":risky_all},"execution_eligibility":{"deterministic_side_effect_free_candidate":deterministic_candidate,"predicate_unit_execution_authorized":False,"basis":"static AST candidate assessment only; execution requires separate gate"},"fixture_plan":{"total":len(fixtures),"executed":0,"expectations":"NOT_ESTABLISHED_UNTIL_UNIT_EXECUTION"},"execution_boundaries":{"predicates_imported":False,"predicate_functions_executed":False,"fs_read_executed":False,"tools_executed":False,"effects_observed":False,"sandbox_executed":False,"gym_executed":False,"breach_executed":False,"models_used":False},"scientific_verdict":{"predicate_source_identity":"ESTABLISHED","predicate_contract_static_inspection":"ESTABLISHED","predicate_determinism":"CANDIDATE_SUPPORTED_BY_STATIC_INSPECTION" if deterministic_candidate else "NOT_ESTABLISHED_RISKY_OPERATIONS_FOUND","qualifying_path_behavior":"NOT_EVALUATED","nonqualifying_path_behavior":"NOT_EVALUATED","successful_protected_read_recording":"NOT_EVALUATED","protected_read_lineage":"NOT_ESTABLISHED","authorization_transport_correctness":"NOT_ESTABLISHED","requirement_satisfaction":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":{"allowed":["predicate source identity","static target-function and dependency closure","static side-effect-risk candidate assessment","unexecuted synthetic fixture plan"],"prohibited":["predicate runtime behavior","positive or negative path classification","successful protected-read recording","protected-read lineage","authorization transport correctness","requirement satisfaction","guardrail effectiveness","real exfiltration prevention"]},"next_gate":"EX6_P2B_P2K_R1_ISOLATED_PROTECTED_PATH_PREDICATE_UNIT_QUALIFICATION" if deterministic_candidate else "EX6_P2B_P2K_R1_PREDICATE_DEPENDENCY_RISK_REVIEW"}
        rp=out/'ex6_p2b_p2k_result.json'; fp=out/'ex6_p2b_p2k_fixture_plan.csv'; dp=out/'ex6_p2b_p2k_dependencies.csv'; bp=out/'ex6_p2b_p2k_binding.json'; cp=out/'ex6_p2b_p2k_claim_boundary.json'
        write_json(rp,result); write_csv(fp,fixtures,["fixture_id","category","input","expected","basis"]); write_csv(dp,closure,["function","signature","line_start","line_end","calls","constants","risky_operations","source_sha256"]); write_json(cp,result['claim_boundary']); write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{"p2j_result":ident(parent_result),"p2j_external_binding":ident(parent_binding),"p2j_manifest":ident(parent_manifest),"p2j_runner":ident(runner),"repaired_source":ident(adapter),"predicate_source":ident(predicates)},"source_modified":False})
        rows=[{**ident(p),"role":"P2K_DERIVED"} for p in (rp,fp,dp,bp,cp)]+[{**ident(p),"role":"P2K_BOUND"} for p in (parent_result,parent_binding,parent_manifest,runner,adapter,predicates)]
        man=out/'ex6_p2b_p2k_manifest.csv'; write_csv(man,rows,["artifact","role","size_bytes","sha256","path"])
        ext=out/'ex6_p2b_p2k_manifest_external_binding.json'; write_json(ext,{"version":VERSION,"created_at_utc":now(),"status":result['status'],"manifest_filename":man.name,"manifest_size_bytes":man.stat().st_size,"manifest_sha256":sha(man),"runner_sha256":sha(Path(__file__).resolve()),"predicate_sha256":sha(predicates),"predicate_functions_executed":False,"tools_executed":False,"effects_observed":False,"requirements_satisfied":False,"next_gate":result['next_gate']})
        print(json.dumps({"status":result['status'],"predicate_sha256":sha(predicates),"target_function":TARGET_FUNCTION,"dependency_functions":sorted(seen),"risky_operations":risky_all,"deterministic_side_effect_free_candidate":deterministic_candidate,"fixtures_planned":len(fixtures),"fixtures_executed":0,"manifest_sha256":sha(man),"next_gate":result['next_gate']},indent=2))
    except Exception as e:
        (out/'P2K_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2K_PREFLIGHT_BLOCKED","error_type":type(e).__name__,"error":str(e),"predicate_functions_executed":False,"tools_executed":False,"effects_observed":False},indent=2),encoding='utf-8')
        raise

def args():
    p=argparse.ArgumentParser(description=VERSION); p.add_argument('--p2j-result',required=True); p.add_argument('--p2j-external-binding',required=True); p.add_argument('--p2j-manifest',required=True); p.add_argument('--p2j-runner',required=True); p.add_argument('--repaired-source',required=True); p.add_argument('--predicates-source',required=True); p.add_argument('--output-dir',required=True); return p.parse_args()
if __name__=='__main__':
    try: main(args())
    except Exception as e: print(f"FAILED: {e}",file=sys.stderr); raise SystemExit(1)
