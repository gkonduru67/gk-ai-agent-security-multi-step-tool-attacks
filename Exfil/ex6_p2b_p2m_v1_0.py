#!/usr/bin/env python3
"""EX6 P2B P2M actual-source-retrieval contract preflight.

Read-only AST/source discovery only. Searches SDK Python sources for the fs.read
registration, implementation, invocation, event construction, serialization,
and trusted outcome bridge. It never imports SDK modules, executes fs.read,
reads fixture contents, exports values/previews, invokes tools/Sandbox/Gym,
evaluates breach, or observes effects.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2M_ACTUAL_SOURCE_RETRIEVAL_CONTRACT_PREFLIGHT_v1.0"
P2L_VERSION="EX6_P2B_P2L_SYNTHETIC_SUCCESSFUL_READ_OUTCOME_AND_PROTECTED_READ_RECORD_QUALIFICATION_v1.0"
P2L_STATUS="P2L_SYNTHETIC_PROTECTED_READ_RECORD_QUALIFICATION_COMPLETE_PASS"
P2L_MANIFEST_SHA="5C72AFDE7F2B6DE54350A3A5DB57C22101484A63D4FF1D922A399EEB28063120"
P2L_RUNNER_SHA="70530BF568A957C30DE3B394042E601A3B4B4EF5E0939BF1C2F0D04617DD2C8C"
EXPECTED_ADAPTER_SHA="BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"
EXPECTED_PREDICATE_SHA="9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
SEARCH_TERMS=("fs.read","ToolEvent","serialize_tool_output","last_source","raw_output_sha256","protected_value_sha256_or_bound_digest","canonical_source_path","completion_sequence","after_tool","tool_specs","ToolSpec")
SENSITIVE_NAME_RE=re.compile(r"secret|token|credential|password|api[_-]?key",re.I)

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
def signature(n):
    if not isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)): return ""
    args=[a.arg for a in n.args.posonlyargs+n.args.args]
    if n.args.vararg: args.append('*'+n.args.vararg.arg)
    args += [a.arg for a in n.args.kwonlyargs]
    if n.args.kwarg: args.append('**'+n.args.kwarg.arg)
    return '('+', '.join(args)+')'
def enclosing(tree,lineno):
    candidates=[n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and n.lineno<=lineno<=getattr(n,'end_lineno',n.lineno)]
    if not candidates: return ("module","",1,max(1,lineno))
    n=min(candidates,key=lambda x:getattr(x,'end_lineno',x.lineno)-x.lineno)
    return (type(n).__name__,getattr(n,'name',''),n.lineno,getattr(n,'end_lineno',n.lineno))
def redact_source(text):
    # Static code only; remove suspicious long literals while preserving structure.
    def repl(m):
        body=m.group(0)
        if len(body)>160 or SENSITIVE_NAME_RE.search(body): return '"<REDACTED_LITERAL>"'
        return body
    return re.sub(r"(['\"])(?:\\.|(?!\1).)*\1",repl,text)

def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    try:
        p2l_result=Path(a.p2l_result).resolve(); p2l_binding=Path(a.p2l_external_binding).resolve(); p2l_manifest=Path(a.p2l_manifest).resolve(); p2l_runner=Path(a.p2l_runner).resolve(); project=Path(a.project_root).resolve(); adapter=Path(a.repaired_source).resolve(); predicates=Path(a.predicates_source).resolve()
        for label,p in (("P2L result",p2l_result),("P2L binding",p2l_binding),("P2L manifest",p2l_manifest),("P2L runner",p2l_runner),("project root",project),("adapter",adapter),("predicates",predicates)):
            require(p.exists(),f"Missing {label}: {p}")
        pr=json.loads(p2l_result.read_text(encoding='utf-8-sig')); pb=json.loads(p2l_binding.read_text(encoding='utf-8-sig'))
        require(pr.get('version')==P2L_VERSION and pr.get('status')==P2L_STATUS,'P2L parent differs')
        require(pr.get('controls',{}).get('passed')==6 and pr.get('controls',{}).get('failed')==0,'P2L controls differ')
        require(pb.get('version')==P2L_VERSION and pb.get('status')==P2L_STATUS,'P2L external binding differs')
        require(pb.get('manifest_sha256')==P2L_MANIFEST_SHA and sha(p2l_manifest)==P2L_MANIFEST_SHA,'P2L manifest differs')
        require(pb.get('runner_sha256')==P2L_RUNNER_SHA and sha(p2l_runner)==P2L_RUNNER_SHA,'P2L runner differs')
        require(pb.get('fs_read_executed') is False and pb.get('tools_executed') is False and pb.get('effects_observed') is False,'P2L boundary differs')
        require(sha(adapter)==EXPECTED_ADAPTER_SHA,'Adapter identity differs'); require(sha(predicates)==EXPECTED_PREDICATE_SHA,'Predicate identity differs')
        sdk=project/'aicomp_sdk'; require(sdk.is_dir(),'aicomp_sdk not found under project root')

        files=[]; matches=[]; parse_errors=[]
        for path in sorted(sdk.rglob('*.py')):
            raw=path.read_text(encoding='utf-8-sig'); files.append(ident(path))
            try: tree=ast.parse(raw,filename=str(path))
            except Exception as exc:
                parse_errors.append({"path":str(path),"error":f"{type(exc).__name__}: {exc}"}); continue
            lines=raw.splitlines()
            for idx,line in enumerate(lines,1):
                terms=[t for t in SEARCH_TERMS if t in line]
                if not terms: continue
                kind,name,start,end=enclosing(tree,idx)
                node=next((n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and getattr(n,'name','')==name and n.lineno==start),None)
                excerpt='\n'.join(lines[max(0,idx-2):min(len(lines),idx+1)])
                matches.append({"relative_path":str(path.relative_to(project)),"file_sha256":sha(path),"match_line":idx,"terms":";".join(terms),"enclosing_kind":kind,"enclosing_name":name,"enclosing_signature":signature(node) if node else "","enclosing_start":start,"enclosing_end":end,"excerpt_sha256":hashlib.sha256(excerpt.encode()).hexdigest().upper(),"redacted_excerpt":redact_source(excerpt)})
        require(matches,'No source matches found for retrieval contract terms')

        categories={
          "fs_read_registration": [m for m in matches if 'fs.read' in m['terms']],
          "event_schema": [m for m in matches if 'ToolEvent' in m['terms']],
          "serialization": [m for m in matches if 'serialize_tool_output' in m['terms']],
          "source_identity": [m for m in matches if 'last_source' in m['terms'] or 'canonical_source_path' in m['terms']],
          "digest_contract": [m for m in matches if 'raw_output_sha256' in m['terms'] or 'protected_value_sha256_or_bound_digest' in m['terms']],
          "sequence_contract": [m for m in matches if 'completion_sequence' in m['terms']],
          "trusted_bridge": [m for m in matches if 'after_tool' in m['terms']],
        }
        establish={k:("FOUND_STATIC_EVIDENCE" if v else "NOT_ESTABLISHED") for k,v in categories.items()}
        all_core=all(establish[k]=="FOUND_STATIC_EVIDENCE" for k in ("fs_read_registration","event_schema","serialization"))
        result={"version":VERSION,"created_at_utc":now(),"status":"P2M_ACTUAL_SOURCE_RETRIEVAL_CONTRACT_PREFLIGHT_COMPLETE_PASS","classification":"READ_ONLY_SDK_SOURCE_AND_INTERFACE_DISCOVERY","P2L_parent_verified":True,"source_inventory":{"python_files":len(files),"parse_errors":len(parse_errors),"matches":len(matches)},"discovery_status":establish,"contract_assessment":{"fs_read_invocation_interface":"STATIC_EVIDENCE_COLLECTED" if categories['fs_read_registration'] else "NOT_ESTABLISHED","returned_object_or_event_schema":"STATIC_EVIDENCE_COLLECTED" if categories['event_schema'] else "NOT_ESTABLISHED","success_failure_representation":"STATIC_EVIDENCE_COLLECTED" if categories['event_schema'] else "NOT_ESTABLISHED","raw_output_representation":"STATIC_EVIDENCE_COLLECTED" if categories['event_schema'] else "NOT_ESTABLISHED","canonical_source_path_source":"STATIC_EVIDENCE_COLLECTED" if categories['source_identity'] else "NOT_ESTABLISHED","event_identity_and_completion_sequence":"STATIC_EVIDENCE_COLLECTED" if categories['sequence_contract'] else "NOT_ESTABLISHED","trusted_outcome_bridge":"STATIC_EVIDENCE_COLLECTED" if categories['trusted_bridge'] else "NOT_ESTABLISHED","raw_output_digest_derivation":"STATIC_EVIDENCE_COLLECTED" if categories['digest_contract'] else "NOT_ESTABLISHED","protected_value_digest_binding":"STATIC_EVIDENCE_COLLECTED" if categories['digest_contract'] else "NOT_ESTABLISHED","value_free_evidence_strategy":"SUPPORTED_BY_HASH_AND_REDACTED_SOURCE_ONLY"},"execution_eligibility":{"controlled_actual_fs_read_eligible":False,"reason":"This gate freezes static contract only; runtime authorization requires review of collected evidence and exact fixture/value-handling plan"},"execution_boundaries":{"sdk_modules_imported":False,"fs_read_executed":False,"tools_executed":False,"fixture_contents_read":False,"source_value_exported":False,"source_value_previewed":False,"effects_observed":False,"sandbox_executed":False,"gym_executed":False,"breach_executed":False,"models_used":False},"scientific_verdict":{"source_retrieval_contract_static_discovery":"ESTABLISHED" if all_core else "PARTIAL","actual_source_retrieval":"NOT_EVALUATED","secret_capture":"NOT_ESTABLISHED","protected_value_lineage":"NOT_ESTABLISHED","authorization_transport_correctness":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":{"allowed":["SDK source identities and redacted line-bound contract evidence","static discovery status for fs.read and event/serialization interfaces","value-free evidence feasibility assessment"],"prohibited":["actual fs.read behavior","source retrieval success","secret capture","protected-value lineage","authorization transport correctness","guardrail effectiveness","real exfiltration prevention"]},"next_gate":"EX6_P2B_P2M_R1_SOURCE_RETRIEVAL_CONTRACT_EVIDENCE_REVIEW"}
        rp=out/'ex6_p2b_p2m_result.json'; mpth=out/'ex6_p2b_p2m_matches.csv'; fp=out/'ex6_p2b_p2m_files.csv'; ep=out/'ex6_p2b_p2m_parse_errors.csv'; bp=out/'ex6_p2b_p2m_binding.json'; cp=out/'ex6_p2b_p2m_claim_boundary.json'
        write_json(rp,result); write_csv(mpth,matches,["relative_path","file_sha256","match_line","terms","enclosing_kind","enclosing_name","enclosing_signature","enclosing_start","enclosing_end","excerpt_sha256","redacted_excerpt"]); write_csv(fp,files,["artifact","path","size_bytes","sha256"]); write_csv(ep,parse_errors,["path","error"]); write_json(cp,result['claim_boundary']); write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{"p2l_result":ident(p2l_result),"p2l_external_binding":ident(p2l_binding),"p2l_manifest":ident(p2l_manifest),"p2l_runner":ident(p2l_runner),"adapter":ident(adapter),"predicates":ident(predicates)},"project_root":str(project),"source_modified":False})
        derived=(rp,mpth,fp,ep,bp,cp); bound=(p2l_result,p2l_binding,p2l_manifest,p2l_runner,adapter,predicates)
        rows=[{**ident(p),"role":"P2M_DERIVED"} for p in derived]+[{**ident(p),"role":"P2M_BOUND"} for p in bound]
        man=out/'ex6_p2b_p2m_manifest.csv'; write_csv(man,rows,["artifact","role","size_bytes","sha256","path"])
        ext=out/'ex6_p2b_p2m_manifest_external_binding.json'; write_json(ext,{"version":VERSION,"created_at_utc":now(),"status":result['status'],"manifest_filename":man.name,"manifest_size_bytes":man.stat().st_size,"manifest_sha256":sha(man),"runner_sha256":sha(Path(__file__).resolve()),"fs_read_executed":False,"fixture_contents_read":False,"source_value_exported":False,"effects_observed":False,"next_gate":result['next_gate']})
        print(json.dumps({"status":result['status'],"python_files":len(files),"matches":len(matches),"parse_errors":len(parse_errors),"discovery_status":establish,"controlled_actual_fs_read_eligible":False,"manifest_sha256":sha(man),"next_gate":result['next_gate']},indent=2))
    except Exception as exc:
        (out/'P2M_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2M_PREFLIGHT_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"fs_read_executed":False,"fixture_contents_read":False,"source_value_exported":False,"effects_observed":False},indent=2),encoding='utf-8')
        raise

def args():
    p=argparse.ArgumentParser(description=VERSION); p.add_argument('--p2l-result',required=True); p.add_argument('--p2l-external-binding',required=True); p.add_argument('--p2l-manifest',required=True); p.add_argument('--p2l-runner',required=True); p.add_argument('--project-root',required=True); p.add_argument('--repaired-source',required=True); p.add_argument('--predicates-source',required=True); p.add_argument('--output-dir',required=True); return p.parse_args()
if __name__=='__main__':
    try: main(args())
    except Exception as exc: print(f"FAILED: {exc}",file=__import__('sys').stderr); raise SystemExit(1)
