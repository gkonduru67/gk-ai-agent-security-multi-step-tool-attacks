#!/usr/bin/env python3
"""EX6 P2B P2K R1 predicate dependency-risk review.

Read-only AST/source review that reconciles the P2K conservative `replace`
flag. It does not import or execute predicates.py, call any predicate, read a
fixture, invoke tools, Sandbox, Gym, breach logic, models, or effects.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2K_R1_PREDICATE_DEPENDENCY_RISK_REVIEW_v1.0"
PARENT_VERSION="EX6_P2B_P2K_PROTECTED_READ_PREDICATE_BOUNDARY_PREFLIGHT_v1.0"
PARENT_STATUS="P2K_PROTECTED_READ_PREDICATE_BOUNDARY_PREFLIGHT_COMPLETE_PASS"
EXPECTED_PARENT_MANIFEST_SHA="78BA65887539FEC07D7D15290CFF5AD51794DF793805C6A419E0E2344E811CA3"
EXPECTED_PARENT_RUNNER_SHA="AECBD08B39295D67B57E0FA490CE15E2138CA095A7311E58BAADDAF90E0EDC26"
EXPECTED_PREDICATE_SHA="9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
TARGETS={"is_protected_secret_path","_is_secret_path"}
PURE_STRING_METHODS={"replace","strip","lstrip","rstrip","lower","upper","casefold","startswith","endswith"}
PURE_PATH_CALLS={"posixpath.normpath","posixpath.basename"}
EFFECTFUL_FULL={"os.replace","os.remove","os.unlink","os.rename","shutil.move","shutil.copy","subprocess.run","subprocess.Popen","pathlib.Path.replace","pathlib.Path.write_text","pathlib.Path.write_bytes"}
EFFECTFUL_LEAVES={"write_text","write_bytes","unlink","remove","rename","rmdir","mkdir","open","system","popen","connect","send","post"}

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
def dotted(n):
    if isinstance(n,ast.Name): return n.id
    if isinstance(n,ast.Attribute):
        left=dotted(n.value); return f"{left}.{n.attr}" if left else n.attr
    return ""
def segment(lines,n): return '\n'.join(lines[n.lineno-1:getattr(n,'end_lineno',n.lineno)])
def write_json(p,x):
    with p.open('x',encoding='utf-8',newline='\n') as f: json.dump(x,f,indent=2,sort_keys=True); f.write('\n')
def write_csv(p,rows,fields):
    with p.open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n'); w.writeheader(); w.writerows(rows)

def infer_expr_type(node:ast.AST, assignments:dict[str,str])->str:
    if isinstance(node,ast.Constant) and isinstance(node.value,str): return "str"
    if isinstance(node,ast.Name): return assignments.get(node.id,"unknown")
    if isinstance(node,ast.Call):
        call=dotted(node.func)
        if call in {"str","posixpath.normpath"}: return "str"
        if isinstance(node.func,ast.Attribute) and node.func.attr in PURE_STRING_METHODS: return "str"
    if isinstance(node,ast.Attribute): return "unknown"
    return "unknown"

def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    try:
        prp=Path(a.p2k_result).resolve(); pbp=Path(a.p2k_external_binding).resolve(); pmp=Path(a.p2k_manifest).resolve(); prun=Path(a.p2k_runner).resolve(); pred=Path(a.predicates_source).resolve()
        for label,p in (("P2K result",prp),("P2K external binding",pbp),("P2K manifest",pmp),("P2K runner",prun),("predicates",pred)): require(p.is_file(),f"Missing {label}: {p}")
        pr=json.loads(prp.read_text(encoding='utf-8-sig')); pb=json.loads(pbp.read_text(encoding='utf-8-sig'))
        require(pr.get('version')==PARENT_VERSION and pr.get('status')==PARENT_STATUS,'P2K parent differs')
        require(pb.get('status')==PARENT_STATUS,'P2K external binding not PASS')
        require(pb.get('manifest_sha256')==EXPECTED_PARENT_MANIFEST_SHA and sha(pmp)==EXPECTED_PARENT_MANIFEST_SHA,'P2K manifest differs')
        require(pb.get('runner_sha256')==EXPECTED_PARENT_RUNNER_SHA and sha(prun)==EXPECTED_PARENT_RUNNER_SHA,'P2K runner differs')
        require(pb.get('predicate_sha256')==EXPECTED_PREDICATE_SHA and sha(pred)==EXPECTED_PREDICATE_SHA,'Predicate identity differs')
        require(pb.get('predicate_functions_executed') is False and pb.get('tools_executed') is False and pb.get('effects_observed') is False,'P2K boundary differs')

        text=pred.read_text(encoding='utf-8-sig'); lines=text.splitlines(); tree=ast.parse(text,filename=str(pred))
        functions={n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
        require(TARGETS <= set(functions),'Target closure differs')
        reviews=[]
        for fname in sorted(TARGETS):
            fn=functions[fname]
            assignments={a.arg:"unknown" for a in fn.args.args}
            for n in ast.walk(fn):
                if isinstance(n,ast.Assign):
                    typ=infer_expr_type(n.value,assignments)
                    for t in n.targets:
                        if isinstance(t,ast.Name): assignments[t.id]=typ
                elif isinstance(n,ast.AnnAssign) and isinstance(n.target,ast.Name) and n.value is not None:
                    assignments[n.target.id]=infer_expr_type(n.value,assignments)
            for n in ast.walk(fn):
                if not isinstance(n,ast.Call): continue
                call=dotted(n.func); leaf=call.split('.')[-1] if call else ''
                receiver_type="none"; classification="UNKNOWN_REVIEW_REQUIRED"; rationale="unresolved call target"
                if isinstance(n.func,ast.Attribute): receiver_type=infer_expr_type(n.func.value,assignments)
                if call in PURE_PATH_CALLS:
                    classification="PURE_DETERMINISTIC_LIBRARY_CALL"; rationale="posixpath lexical normalization only"
                elif call=="str":
                    classification="PURE_DETERMINISTIC_BUILTIN"; rationale="in-memory string conversion"
                elif leaf in PURE_STRING_METHODS and receiver_type=="str":
                    classification="PURE_DETERMINISTIC_STRING_METHOD"; rationale="receiver is source-traced as string; no filesystem mutation"
                elif call in EFFECTFUL_FULL or leaf in EFFECTFUL_LEAVES:
                    classification="POTENTIALLY_EFFECTFUL"; rationale="known effect-capable API"
                elif call in TARGETS:
                    classification="INTERNAL_PURE_CANDIDATE_CALL"; rationale="call remains inside reviewed dependency closure"
                reviews.append({"function":fname,"line":n.lineno,"call":call,"receiver_type":receiver_type,"classification":classification,"rationale":rationale,"source":ast.get_source_segment(text,n) or ""})
        effectful=[r for r in reviews if r['classification']=="POTENTIALLY_EFFECTFUL"]
        unresolved=[r for r in reviews if r['classification']=="UNKNOWN_REVIEW_REQUIRED"]
        replace_rows=[r for r in reviews if r['call'].endswith('.replace') or r['call']=='replace']
        replace_resolved=bool(replace_rows) and all(r['classification']=="PURE_DETERMINISTIC_STRING_METHOD" for r in replace_rows)
        eligible=(not effectful and not unresolved and replace_resolved)
        corrected={"prior_flag":"replace","prior_interpretation":"CONSERVATIVE_LEAF_NAME_FLAG","review_result":"PURE_STRING_METHOD_FALSE_POSITIVE" if replace_resolved else "UNRESOLVED","filesystem_replace_detected":any(r['call'] in {"os.replace","pathlib.Path.replace"} for r in reviews),"effectful_calls":effectful,"unresolved_calls":unresolved}
        result={"version":VERSION,"created_at_utc":now(),"status":"P2K_R1_PREDICATE_DEPENDENCY_RISK_REVIEW_COMPLETE_PASS" if eligible else "P2K_R1_RISK_REVIEW_COMPLETE_WITH_UNRESOLVED_CALLS","classification":"READ_ONLY_AST_CALL_RECEIVER_AND_EFFECT_RISK_REVIEW","P2K_parent_verified":True,"predicate_source_identity":ident(pred),"reviewed_functions":sorted(TARGETS),"call_review":{"total":len(reviews),"effectful":len(effectful),"unresolved":len(unresolved)},"replace_flag_reconciliation":corrected,"execution_eligibility":{"isolated_predicate_unit_execution_eligible":eligible,"authorization_scope":"NEXT_GATE_ONLY" if eligible else "WITHHELD","basis":"all closure calls statically resolved as in-memory deterministic operations" if eligible else "effectful or unresolved calls remain"},"execution_boundaries":{"predicates_imported":False,"predicate_functions_executed":False,"fs_read_executed":False,"tools_executed":False,"effects_observed":False,"sandbox_executed":False,"gym_executed":False,"breach_executed":False,"models_used":False},"scientific_verdict":{"replace_risk":"STATIC_FALSE_POSITIVE_ESTABLISHED" if replace_resolved else "NOT_ESTABLISHED","predicate_side_effect_risk":"NO_EFFECTFUL_CALLS_FOUND_IN_REVIEWED_CLOSURE" if not effectful else "EFFECTFUL_CALLS_FOUND","predicate_determinism":"STATIC_ELIGIBILITY_ESTABLISHED_FOR_ISOLATED_UNIT_GATE" if eligible else "NOT_ESTABLISHED","predicate_runtime_behavior":"NOT_EVALUATED","qualifying_path_behavior":"NOT_EVALUATED","nonqualifying_path_behavior":"NOT_EVALUATED","successful_protected_read_recording":"NOT_EVALUATED","protected_read_lineage":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":{"allowed":["call-level receiver classification","replace flag reconciliation","static effect-risk review","eligibility decision for a later isolated predicate unit gate"],"prohibited":["predicate runtime behavior","path classification results","successful protected-read recording","protected-read lineage","authorization transport correctness","guardrail effectiveness","real exfiltration prevention"]},"next_gate":"EX6_P2B_P2K_R2_ISOLATED_PROTECTED_PATH_PREDICATE_UNIT_QUALIFICATION" if eligible else "EX6_P2B_P2K_R2_UNRESOLVED_CALL_REVIEW"}
        rp=out/'ex6_p2b_p2k_r1_result.json'; cp=out/'ex6_p2b_p2k_r1_calls.csv'; bp=out/'ex6_p2b_p2k_r1_binding.json'; cl=out/'ex6_p2b_p2k_r1_claim_boundary.json'
        write_json(rp,result); write_csv(cp,reviews,["function","line","call","receiver_type","classification","rationale","source"]); write_json(cl,result['claim_boundary']); write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{"p2k_result":ident(prp),"p2k_external_binding":ident(pbp),"p2k_manifest":ident(pmp),"p2k_runner":ident(prun),"predicate_source":ident(pred)},"source_modified":False})
        rows=[{**ident(p),"role":"P2K_R1_DERIVED"} for p in (rp,cp,bp,cl)]+[{**ident(p),"role":"P2K_R1_BOUND"} for p in (prp,pbp,pmp,prun,pred)]
        man=out/'ex6_p2b_p2k_r1_manifest.csv'; write_csv(man,rows,["artifact","role","size_bytes","sha256","path"])
        ext=out/'ex6_p2b_p2k_r1_manifest_external_binding.json'; write_json(ext,{"version":VERSION,"created_at_utc":now(),"status":result['status'],"manifest_filename":man.name,"manifest_size_bytes":man.stat().st_size,"manifest_sha256":sha(man),"runner_sha256":sha(Path(__file__).resolve()),"predicate_sha256":sha(pred),"isolated_predicate_unit_execution_eligible":eligible,"predicate_functions_executed":False,"tools_executed":False,"effects_observed":False,"requirements_satisfied":False,"next_gate":result['next_gate']})
        print(json.dumps({"status":result['status'],"replace_flag_review":corrected['review_result'],"effectful_calls":len(effectful),"unresolved_calls":len(unresolved),"isolated_predicate_unit_execution_eligible":eligible,"manifest_sha256":sha(man),"next_gate":result['next_gate']},indent=2))
    except Exception as e:
        (out/'P2K_R1_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2K_R1_RISK_REVIEW_BLOCKED","error_type":type(e).__name__,"error":str(e),"predicate_functions_executed":False,"tools_executed":False,"effects_observed":False},indent=2),encoding='utf-8')
        raise

def args():
    p=argparse.ArgumentParser(description=VERSION); p.add_argument('--p2k-result',required=True); p.add_argument('--p2k-external-binding',required=True); p.add_argument('--p2k-manifest',required=True); p.add_argument('--p2k-runner',required=True); p.add_argument('--predicates-source',required=True); p.add_argument('--output-dir',required=True); return p.parse_args()
if __name__=='__main__':
    try: main(args())
    except Exception as e: print(f"FAILED: {e}",file=sys.stderr); raise SystemExit(1)
