#!/usr/bin/env python3
"""EX6 P2B P2M R1A evidence-classification reconciliation.

Narrow read-only correction gate. It binds frozen P2M-R1 artifacts and exact
source identities, corrects hook-order classifications, freezes the actual raw
return assignment, initial ToolEvent output, serialization, and every fs_read
return branch, and recomputes the genuine unresolved producer list.

No source modification, SDK imports, fs.read, fixture reads, tools, Sandbox,
Gym, predicates, breach logic, models, source-value preview/export, or effects.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, re, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2M_R1A_EVIDENCE_CLASSIFICATION_RECONCILIATION_v1.0"
PARENT_VERSION="EX6_P2B_P2M_R1_SOURCE_RETRIEVAL_CONTRACT_EVIDENCE_REVIEW_v1.0"
PARENT_STATUS="P2M_R1_SOURCE_RETRIEVAL_CONTRACT_EVIDENCE_REVIEW_COMPLETE_PASS"
PARENT_MANIFEST_SHA="20688BA3D1D3773734255CE04BB1EC0BE38EC45340B28786732C1632C8B5CD27"
PARENT_RUNNER_SHA="57544FE5C4B3E9C5339B5F878C1CDA7A52BEEB55B1047E762802166EADAA79CC"
FS_SHA="4B8C54032ED807CE4C35BAB403EE622141881158E10F600A4B6D329E6D6F95B8"
SANDBOX_SHA="B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0"
EXPECTED_GAPS=["after_tool runtime caller","raw_output_sha256 producer","protected_value_sha256_or_bound_digest producer","runtime event-sequence allocator","canonical_source_path producer"]
SENSITIVE=re.compile(r"secret|token|credential|password|api[_-]?key",re.I)

def now(): return datetime.now(timezone.utc).isoformat()
def req(c,m):
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
def dotted(n):
    if isinstance(n,ast.Name): return n.id
    if isinstance(n,ast.Attribute):
        left=dotted(n.value); return f"{left}.{n.attr}" if left else n.attr
    return ""
def src(text,n): return ast.get_source_segment(text,n) or ""
def redact(s):
    def repl(m):
        v=m.group(0)
        return '"<REDACTED_LITERAL>"' if len(v)>160 or SENSITIVE.search(v) else v
    return re.sub(r"(['\"])(?:\\.|(?!\1).)*\1",repl,s)
def add(rows,control,classification,path,text,node,basis):
    block=src(text,node) if node else ""
    rows.append({"control":control,"classification":classification,"relative_path":path,"line_start":"" if node is None else node.lineno,"line_end":"" if node is None else getattr(node,'end_lineno',node.lineno),"source_block_sha256":"" if node is None else hashlib.sha256(block.encode()).hexdigest().upper(),"basis":basis,"redacted_source":redact(block)})
def funcs(tree): return {n.name:n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}

def main(a):
    out=Path(a.output_dir).resolve(); req(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    rows=[]
    try:
        parent_result=Path(a.p2m_r1_result).resolve(); parent_evidence=Path(a.p2m_r1_evidence).resolve(); parent_binding=Path(a.p2m_r1_external_binding).resolve(); parent_manifest=Path(a.p2m_r1_manifest).resolve(); parent_runner=Path(a.p2m_r1_runner).resolve(); root=Path(a.project_root).resolve()
        for label,p in (("R1 result",parent_result),("R1 evidence",parent_evidence),("R1 external binding",parent_binding),("R1 manifest",parent_manifest),("R1 runner",parent_runner),("project root",root)): req(p.exists(),f"Missing {label}: {p}")
        pr=json.loads(parent_result.read_text(encoding='utf-8-sig')); pb=json.loads(parent_binding.read_text(encoding='utf-8-sig'))
        req(pr.get('version')==PARENT_VERSION and pr.get('status')==PARENT_STATUS,'R1 parent differs')
        req(pb.get('status')==PARENT_STATUS and pb.get('manifest_sha256')==PARENT_MANIFEST_SHA,'R1 external binding differs')
        req(sha(parent_manifest)==PARENT_MANIFEST_SHA and sha(parent_runner)==PARENT_RUNNER_SHA,'R1 identities differ')
        req(pb.get('fs_read_executed') is False and pb.get('fixture_contents_read') is False and pb.get('source_value_exported') is False and pb.get('effects_observed') is False,'R1 boundary differs')
        reported=list(pr.get('not_established',[])); req(len(reported)==7,'R1 reported gap count differs')
        parent_rows=list(csv.DictReader(parent_evidence.open(encoding='utf-8-sig',newline=''))); req(parent_rows,'R1 evidence empty')

        fs=root/'aicomp_sdk/core/tools/fs.py'; sandbox=root/'aicomp_sdk/core/env/sandbox.py'
        req(fs.is_file() and sandbox.is_file(),'Required sources absent'); req(sha(fs)==FS_SHA and sha(sandbox)==SANDBOX_SHA,'Source identity differs')
        ft=fs.read_text(encoding='utf-8-sig'); st=sandbox.read_text(encoding='utf-8-sig'); ftr=ast.parse(ft); str_=ast.parse(st); ff=funcs(ftr); sf=funcs(str_)
        fs_read=ff.get('fs_read'); interact=sf.get('interact'); req(fs_read and interact,'Authoritative functions absent')

        # Hook ordering: locate execute_hooks calls by HookStage argument and verify line ordering.
        calls=[n for n in ast.walk(interact) if isinstance(n,ast.Call)]
        tool_call=next((n for n in calls if dotted(n.func)=='self.tools.call'),None)
        pre=next((n for n in calls if dotted(n.func).endswith('execute_hooks') and any(isinstance(x,ast.Attribute) and x.attr=='PRE_TOOL_CALL' for x in ast.walk(n))),None)
        post=next((n for n in calls if dotted(n.func).endswith('execute_hooks') and any(isinstance(x,ast.Attribute) and x.attr=='POST_TOOL_CALL' for x in ast.walk(n))),None)
        req(tool_call and pre and post,'Required hook/tool calls not found')
        req(pre.lineno < tool_call.lineno < post.lineno,'Hook order not established')
        add(rows,'pre_tool_hook_order','AUTHORITATIVE_PRODUCER_FOUND','aicomp_sdk/core/env/sandbox.py',st,pre,'PRE_TOOL_CALL execute_hooks occurs before self.tools.call.')
        add(rows,'post_tool_hook_order','AUTHORITATIVE_PRODUCER_FOUND','aicomp_sdk/core/env/sandbox.py',st,post,'POST_TOOL_CALL execute_hooks occurs after self.tools.call.')

        # Freeze raw tuple assignment, initial ToolEvent, serialization, and recorded event.
        raw_assign=next((n for n in ast.walk(interact) if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Tuple) and [e.id for e in n.targets[0].elts if isinstance(e,ast.Name)]==['ok','output','err'] and isinstance(n.value,ast.Call) and dotted(n.value.func)=='self.tools.call'),None)
        req(raw_assign,'Raw return assignment not found')
        add(rows,'raw_tool_return_assignment','AUTHORITATIVE_PRODUCER_FOUND','aicomp_sdk/core/env/sandbox.py',st,raw_assign,'Exact ok, output, err assignment from self.tools.call.')
        events=[n for n in ast.walk(interact) if isinstance(n,ast.Call) and dotted(n.func).endswith('ToolEvent')]
        req(len(events)>=2,'Expected ToolEvent constructors absent')
        initial=next((n for n in events if any(k.arg=='output' and isinstance(k.value,ast.Name) and k.value.id=='output' for k in n.keywords)),None)
        recorded=next((n for n in events if any(k.arg=='output' and isinstance(k.value,ast.Name) and k.value.id=='output_text' for k in n.keywords)),None)
        req(initial and recorded,'Initial/recorded ToolEvent output blocks absent')
        add(rows,'initial_ToolEvent_output','AUTHORITATIVE_PRODUCER_FOUND','aicomp_sdk/core/env/sandbox.py',st,initial,'Initial ToolEvent receives current raw or post-hook-modified output.')
        serial=next((n for n in calls if dotted(n.func).endswith('serialize_tool_output') and n.args and isinstance(n.args[0],ast.Name) and n.args[0].id=='output'),None)
        req(serial,'Serialization call absent')
        add(rows,'output_text_serialization','AUTHORITATIVE_PRODUCER_FOUND','aicomp_sdk/core/env/sandbox.py',st,serial,'serialize_tool_output(output) produces output_text path.')
        add(rows,'recorded_ToolEvent_output_text','AUTHORITATIVE_PRODUCER_FOUND','aicomp_sdk/core/env/sandbox.py',st,recorded,'Recorded ToolEvent receives output_text.')

        # Freeze every fs_read return branch and semantics.
        returns=sorted([n for n in ast.walk(fs_read) if isinstance(n,ast.Return)],key=lambda n:n.lineno)
        req(len(returns)==4,f"Expected 4 fs_read returns, found {len(returns)}")
        expected=[('path_escape',False,'','path_escape'),('not_found',False,'','not_found'),('is_directory',False,'','is_directory'),('success',True,'UTF8_TEXT','None')]
        return_summary=[]
        for idx,(label,okv,outv,errv) in enumerate(expected):
            n=returns[idx]; value=n.value; req(isinstance(value,ast.Tuple) and len(value.elts)==3,'Unexpected return shape')
            actual=ast.unparse(value)
            if label!='success':
                req(isinstance(value.elts[0],ast.Constant) and value.elts[0].value is False,'Failure ok differs')
                req(isinstance(value.elts[1],ast.Constant) and value.elts[1].value=='','Failure output differs')
                req(isinstance(value.elts[2],ast.Constant) and value.elts[2].value==errv,'Failure error differs')
            else:
                req(isinstance(value.elts[0],ast.Constant) and value.elts[0].value is True,'Success ok differs')
                req(isinstance(value.elts[1],ast.Call) and dotted(value.elts[1].func).endswith('read_text'),'Success output is not read_text')
                req(isinstance(value.elts[2],ast.Constant) and value.elts[2].value is None,'Success error differs')
            add(rows,'fs_read_return_'+label,'AUTHORITATIVE_PRODUCER_FOUND','aicomp_sdk/core/tools/fs.py',ft,n,'Exact return branch frozen and validated.')
            return_summary.append({"branch":label,"line":n.lineno,"ok":okv,"output":outv,"error":errv,"expression":actual})

        corrected=[x for x in reported if x not in {'pre-hook ordering','post-hook ordering'}]
        req(corrected==EXPECTED_GAPS,f"Corrected gaps differ: {corrected}")
        result_obj={"version":VERSION,"created_at_utc":now(),"status":"P2M_R1A_EVIDENCE_CLASSIFICATION_RECONCILIATION_COMPLETE_PASS","classification":"READ_ONLY_CORRECTION_AND_EXTERNAL_BINDING","P2M_R1_parent_verified":True,"reported_not_established_count":7,"corrected_false_negatives":{"pre-hook ordering":"AUTHORITATIVE_PRODUCER_FOUND","post-hook ordering":"AUTHORITATIVE_PRODUCER_FOUND"},"evidence_label_corrections":{"raw_output_before_serialization":"split into raw_tool_return_assignment, initial_ToolEvent_output, output_text_serialization, and recorded_ToolEvent_output_text","handler_return_contract":"all four branches frozen separately"},"fs_read_return_contract":return_summary,"corrected_unresolved_producer_count":len(corrected),"corrected_unresolved_producers":corrected,"execution_eligibility":{"controlled_actual_fs_read_eligible":False,"reason":"Five required trusted producer contracts remain unestablished."},"execution_boundaries":{"sdk_modules_imported":False,"source_modified":False,"parent_evidence_overwritten":False,"fs_read_executed":False,"tools_executed":False,"fixture_contents_read":False,"source_value_exported":False,"source_value_previewed":False,"effects_observed":False,"sandbox_executed":False,"gym_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False},"scientific_verdict":{"P2M_R1_classification_reconciliation":"ESTABLISHED","hook_ordering":"ESTABLISHED_FROM_EXACT_SOURCE","raw_output_pipeline":"ESTABLISHED_FROM_EXACT_SOURCE","fs_read_return_contract":"ESTABLISHED_FROM_EXACT_SOURCE","genuine_producer_gaps":"FIVE_IDENTIFIED","actual_source_retrieval":"NOT_EVALUATED","secret_capture":"NOT_ESTABLISHED","protected_value_lineage":"NOT_ESTABLISHED","authorization_transport_correctness":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":{"allowed":["corrected P2M-R1 classifications","exact raw-output source blocks","all fs_read return branches","corrected five-gap list"],"prohibited":["actual fs.read behavior","source retrieval success","secret capture","protected-value lineage","authorization transport correctness","guardrail effectiveness","real exfiltration prevention"]},"next_gate":"EX6_P2B_P2N_TRUSTED_OUTCOME_BRIDGE_AND_DIGEST_PRODUCER_DESIGN"}
        rp=out/'ex6_p2b_p2m_r1a_result.json'; ep=out/'ex6_p2b_p2m_r1a_evidence.csv'; bp=out/'ex6_p2b_p2m_r1a_binding.json'; cp=out/'ex6_p2b_p2m_r1a_claim_boundary.json'
        write_json(rp,result_obj); write_csv(ep,rows,["control","classification","relative_path","line_start","line_end","source_block_sha256","basis","redacted_source"]); write_json(cp,result_obj['claim_boundary']); write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{"p2m_r1_result":ident(parent_result),"p2m_r1_evidence":ident(parent_evidence),"p2m_r1_external_binding":ident(parent_binding),"p2m_r1_manifest":ident(parent_manifest),"p2m_r1_runner":ident(parent_runner),"fs_source":ident(fs),"sandbox_source":ident(sandbox)},"source_modified":False,"parent_evidence_overwritten":False})
        manifest_rows=[{**ident(p),"role":"P2M_R1A_DERIVED"} for p in (rp,ep,bp,cp)]+[{**ident(p),"role":"P2M_R1A_BOUND"} for p in (parent_result,parent_evidence,parent_binding,parent_manifest,parent_runner,fs,sandbox)]
        mp=out/'ex6_p2b_p2m_r1a_manifest.csv'; write_csv(mp,manifest_rows,["artifact","role","size_bytes","sha256","path"])
        xp=out/'ex6_p2b_p2m_r1a_manifest_external_binding.json'; write_json(xp,{"version":VERSION,"created_at_utc":now(),"status":result_obj['status'],"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"parent_manifest_sha256":PARENT_MANIFEST_SHA,"corrected_unresolved_producer_count":5,"controlled_actual_fs_read_eligible":False,"fs_read_executed":False,"fixture_contents_read":False,"source_value_exported":False,"effects_observed":False,"next_gate":result_obj['next_gate']})
        print(json.dumps({"status":result_obj['status'],"corrections":2,"fs_read_return_branches":4,"corrected_unresolved_producer_count":5,"controlled_actual_fs_read_eligible":False,"manifest_sha256":sha(mp),"next_gate":result_obj['next_gate']},indent=2))
    except Exception as e:
        (out/'P2M_R1A_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2M_R1A_RECONCILIATION_BLOCKED","error_type":type(e).__name__,"error":str(e),"evidence_frozen":rows,"fs_read_executed":False,"fixture_contents_read":False,"source_value_exported":False,"effects_observed":False},indent=2),encoding='utf-8')
        raise

def args():
    p=argparse.ArgumentParser(description=VERSION); p.add_argument('--p2m-r1-result',required=True); p.add_argument('--p2m-r1-evidence',required=True); p.add_argument('--p2m-r1-external-binding',required=True); p.add_argument('--p2m-r1-manifest',required=True); p.add_argument('--p2m-r1-runner',required=True); p.add_argument('--project-root',required=True); p.add_argument('--output-dir',required=True); return p.parse_args()
if __name__=='__main__':
    try: main(args())
    except Exception as e: print(f"FAILED: {e}",file=sys.stderr); raise SystemExit(1)
