#!/usr/bin/env python3
"""EX6 P2B P2M R1 source-retrieval contract evidence review.

Read-only authoritative producer/consumer review. No SDK imports, fs.read,
fixture reads, source-value preview/export, tools, Sandbox, Gym, breach, model,
or effects. The runner freezes exact AST source blocks and classifies required
contracts as AUTHORITATIVE_PRODUCER_FOUND, AUTHORITATIVE_CONSUMER_FOUND,
STATIC_ONLY, or NOT_ESTABLISHED.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, re, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2M_R1_SOURCE_RETRIEVAL_CONTRACT_EVIDENCE_REVIEW_v1.0"
PARENT_VERSION="EX6_P2B_P2M_ACTUAL_SOURCE_RETRIEVAL_CONTRACT_PREFLIGHT_v1.0"
PARENT_STATUS="P2M_ACTUAL_SOURCE_RETRIEVAL_CONTRACT_PREFLIGHT_COMPLETE_PASS"
PARENT_MANIFEST_SHA="58AD5C1855912B4A800EB730228A711175C84FAC8CDF07BCD2CAA44840789C98"
PARENT_RUNNER_SHA="F709BCA544ACC92ADB41D64E8FC3854042ED84564A2671F2BE7E7D9894279F59"
EXPECTED={
 "aicomp_sdk/core/tools/fs.py":"4B8C54032ED807CE4C35BAB403EE622141881158E10F600A4B6D329E6D6F95B8",
 "aicomp_sdk/core/tools/models.py":"61539F52CDDBD40E86DFC3CC41E3548BFCA78D5DE2B469559B67FED90E1F3ACD",
 "aicomp_sdk/core/tools/schema.py":"A1C9C6CB573656376CE297AF7B28288A7E93D8875D86F05D5575DB409EA3C09D",
 "aicomp_sdk/core/tools/suite.py":"23C3BEE3DE98377E0D93AAC16F5D1091839E5D1420E31B78C7F88C28E06867AA",
 "aicomp_sdk/core/tools/state.py":"2131CFEFB026396CA5BA9E6B7931D3BF42284D4E8923401175589A93D9823F8E",
 "aicomp_sdk/core/env/sandbox.py":"B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0",
 "aicomp_sdk/core/trace.py":"9B51BFCC73DB67610C748D580075003F185C58EA2262B9DE1D8716CB719CF2F0",
 "aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py":"BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99",
}
CLASSES={"AUTHORITATIVE_PRODUCER_FOUND","AUTHORITATIVE_CONSUMER_FOUND","STATIC_ONLY","NOT_ESTABLISHED"}
SENSITIVE=re.compile(r"secret|token|credential|password|api[_-]?key",re.I)

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
def dotted(n):
    if isinstance(n,ast.Name): return n.id
    if isinstance(n,ast.Attribute):
        s=dotted(n.value); return f"{s}.{n.attr}" if s else n.attr
    return ""
def sig(n):
    if not isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)): return ""
    a=[x.arg for x in n.args.posonlyargs+n.args.args]
    if n.args.vararg:a.append('*'+n.args.vararg.arg)
    a += [x.arg for x in n.args.kwonlyargs]
    if n.args.kwarg:a.append('**'+n.args.kwarg.arg)
    ret=ast.unparse(n.returns) if n.returns else "NOT_ANNOTATED"
    return '('+', '.join(a)+')->'+ret
def block(text,n): return ast.get_source_segment(text,n) or ""
def redact(text):
    def repl(m):
        s=m.group(0)
        return '"<REDACTED_LITERAL>"' if len(s)>160 or SENSITIVE.search(s) else s
    return re.sub(r"(['\"])(?:\\.|(?!\1).)*\1",repl,text)
def add(evidence,contract,classification,path,node,text,rationale,role):
    require(classification in CLASSES,'invalid classification')
    src=block(text,node) if node else ""
    evidence.append({"contract":contract,"classification":classification,"role":role,"relative_path":path,"source_sha256":"" if node is None else hashlib.sha256(src.encode()).hexdigest().upper(),"line_start":"" if node is None else node.lineno,"line_end":"" if node is None else getattr(node,'end_lineno',node.lineno),"symbol":"" if node is None else getattr(node,'name',type(node).__name__),"signature":"" if node is None else sig(node),"rationale":rationale,"redacted_source":redact(src)})
def funcs(tree): return {n.name:n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def calls(n): return [dotted(x.func) for x in ast.walk(n) if isinstance(x,ast.Call)]
def literals(n): return [x.value for x in ast.walk(n) if isinstance(x,ast.Constant) and isinstance(x.value,str)]

def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    evidence=[]
    try:
        result=Path(a.p2m_result).resolve(); binding=Path(a.p2m_external_binding).resolve(); manifest=Path(a.p2m_manifest).resolve(); runner=Path(a.p2m_runner).resolve(); root=Path(a.project_root).resolve()
        for label,p in (("P2M result",result),("P2M binding",binding),("P2M manifest",manifest),("P2M runner",runner),("project root",root)): require(p.exists(),f"Missing {label}: {p}")
        pr=json.loads(result.read_text(encoding='utf-8-sig')); pb=json.loads(binding.read_text(encoding='utf-8-sig'))
        require(pr.get('version')==PARENT_VERSION and pr.get('status')==PARENT_STATUS,'P2M parent differs')
        require(pb.get('status')==PARENT_STATUS and pb.get('manifest_sha256')==PARENT_MANIFEST_SHA,'P2M binding differs')
        require(sha(manifest)==PARENT_MANIFEST_SHA and sha(runner)==PARENT_RUNNER_SHA,'P2M identities differ')
        require(pb.get('fs_read_executed') is False and pb.get('fixture_contents_read') is False and pb.get('source_value_exported') is False,'P2M boundary differs')
        sources={}
        for rel,expected in EXPECTED.items():
            p=root/Path(rel); require(p.is_file(),f"Missing source: {rel}"); require(sha(p)==expected,f"Source identity mismatch: {rel}")
            text=p.read_text(encoding='utf-8-sig'); tree=ast.parse(text,filename=str(p)); sources[rel]=(p,text,tree,funcs(tree))

        # fs.read ToolDef and bound handler
        rel="aicomp_sdk/core/tools/fs.py"; _,text,tree,fn=sources[rel]
        fs_tool=None; handler_name=None
        for n in ast.walk(tree):
            if isinstance(n,ast.Call) and dotted(n.func).endswith('ToolDef'):
                kws={k.arg:k.value for k in n.keywords if k.arg}
                name=kws.get('name')
                if isinstance(name,ast.Constant) and name.value=='fs.read':
                    fs_tool=n; h=kws.get('handler'); handler_name=dotted(h).split('.')[-1] if h else None; break
        if fs_tool:
            add(evidence,"fs.read ToolDef","AUTHORITATIVE_PRODUCER_FOUND",rel,fs_tool,text,"Canonical registry object names fs.read and binds its handler.","producer")
        else:add(evidence,"fs.read ToolDef","NOT_ESTABLISHED",rel,None,text,"No canonical fs.read ToolDef located.","producer")
        handler=fn.get(handler_name or '')
        add(evidence,"bound handler argument and return contract","AUTHORITATIVE_PRODUCER_FOUND" if handler else "NOT_ESTABLISHED",rel,handler,text,"Bound handler from fs.read ToolDef with full signature and annotation." if handler else "Bound handler unresolved.","producer")

        # Resolver, mark_source, return
        if handler:
            c=calls(handler); resolver_names=[x.split('.')[-1] for x in c if 'resolve' in x.lower()]
            resolver=next((fn.get(x) for x in resolver_names if fn.get(x)),None)
            add(evidence,"path resolver","AUTHORITATIVE_PRODUCER_FOUND" if resolver else "NOT_ESTABLISHED",rel,resolver,text,"Handler-called resolver found." if resolver else "No handler-called local resolver established.","producer")
            mark=next((x for x in ast.walk(handler) if isinstance(x,ast.Call) and dotted(x.func).endswith('mark_source')),None)
            add(evidence,"mark_source exact value","AUTHORITATIVE_PRODUCER_FOUND" if mark else "NOT_ESTABLISHED",rel,mark,text,"Authoritative handler mark_source call and argument frozen." if mark else "No mark_source call in handler.","producer")
            returns=[x for x in ast.walk(handler) if isinstance(x,ast.Return)]
            ret=returns[-1] if returns else None
            add(evidence,"handler return expression and output type","AUTHORITATIVE_PRODUCER_FOUND" if ret else "NOT_ESTABLISHED",rel,ret,text,"Return expression frozen; annotation retained in handler signature." if ret else "Handler return not found.","producer")

        # ToolSuite invocation
        rel="aicomp_sdk/core/tools/suite.py"; _,text,tree,fn=sources[rel]
        inv=[]
        for n in ast.walk(tree):
            if isinstance(n,ast.Call) and (dotted(n.func).endswith('.handler') or dotted(n.func).endswith('handler')): inv.append(n)
        inv_node=inv[0] if inv else next((n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name in {'call','execute','invoke'}),None)
        add(evidence,"ToolSuite handler invocation","AUTHORITATIVE_PRODUCER_FOUND" if inv_node else "NOT_ESTABLISHED",rel,inv_node,text,"Runtime suite handler invocation path frozen." if inv_node else "No authoritative invocation located.","producer")

        # Sandbox ordered pipeline
        rel="aicomp_sdk/core/env/sandbox.py"; _,text,tree,fn=sources[rel]; interact=fn.get('interact')
        add(evidence,"sandbox success/error handling","AUTHORITATIVE_PRODUCER_FOUND" if interact else "NOT_ESTABLISHED",rel,interact,text,"Complete interact function freezes invocation, success/error and recording order." if interact else "Sandbox interact not found.","producer")
        if interact:
            invoke_calls=[x for x in ast.walk(interact) if isinstance(x,ast.Call) and ('tools' in dotted(x.func) or 'spec.handler' in dotted(x.func))]
            pre=[x for x in ast.walk(interact) if isinstance(x,ast.Call) and 'pre' in dotted(x.func).lower() and 'hook' in dotted(x.func).lower()]
            post=[x for x in ast.walk(interact) if isinstance(x,ast.Call) and 'post' in dotted(x.func).lower() and 'hook' in dotted(x.func).lower()]
            add(evidence,"pre-hook ordering","STATIC_ONLY" if pre else "NOT_ESTABLISHED",rel,pre[0] if pre else None,text,"Pre-hook call located; control-flow order requires reviewed block context." if pre else "No explicit pre-hook call located.","static")
            add(evidence,"post-hook ordering","STATIC_ONLY" if post else "NOT_ESTABLISHED",rel,post[0] if post else None,text,"Post-hook call located; control-flow order requires reviewed block context." if post else "No explicit post-hook call located.","static")
            raw_assign=next((x for x in ast.walk(interact) if isinstance(x,(ast.Assign,ast.AnnAssign)) and 'output' in block(text,x) and any(k in block(text,x) for k in ('tools.','handler','execute'))),None)
            add(evidence,"raw output before serialization","AUTHORITATIVE_PRODUCER_FOUND" if raw_assign else "NOT_ESTABLISHED",rel,raw_assign,text,"Raw handler output assignment located before serialization." if raw_assign else "Raw-output assignment not established.","producer")
            events=[x for x in ast.walk(interact) if isinstance(x,ast.Call) and dotted(x.func).endswith('ToolEvent')]
            add(evidence,"recorded ToolEvent.output","AUTHORITATIVE_PRODUCER_FOUND" if events else "NOT_ESTABLISHED",rel,events[-1] if events else None,text,"Recorded ToolEvent constructor frozen." if events else "ToolEvent producer not found.","producer")
            serial=[x for x in ast.walk(interact) if isinstance(x,ast.Call) and dotted(x.func).endswith('serialize_tool_output')]
            add(evidence,"serialized output_text","AUTHORITATIVE_PRODUCER_FOUND" if serial else "NOT_ESTABLISHED",rel,serial[-1] if serial else None,text,"Authoritative serialization call frozen." if serial else "Serialization call not found.","producer")

        # Runtime after_tool caller across SDK, excluding definitions and adapter self file
        caller=None; caller_rel=None; caller_text=None
        for rel,(p,text,tree,fn) in sources.items():
            if 'trusted_context_adapter' in rel: continue
            for n in ast.walk(tree):
                if isinstance(n,ast.Call) and dotted(n.func).endswith('after_tool'):
                    caller,caller_rel,caller_text=n,rel,text; break
            if caller: break
        add(evidence,"after_tool runtime caller","AUTHORITATIVE_PRODUCER_FOUND" if caller else "NOT_ESTABLISHED",caller_rel or "SDK_SEARCH",caller,caller_text or "","Runtime caller found outside adapter definition." if caller else "No runtime after_tool caller found in authoritative reviewed sources.","producer")

        # Digest producers across reviewed sources
        digest_fields=("raw_output_sha256","protected_value_sha256_or_bound_digest")
        for field in digest_fields:
            producer=None; prod_rel=None; prod_text=None; consumer=None; con_rel=None; con_text=None
            for rel,(p,text,tree,fn) in sources.items():
                for n in ast.walk(tree):
                    if isinstance(n,ast.Call) and dotted(n.func).endswith(('sha256','digest','hexdigest')):
                        parent_src=block(text,n)
                        # local enclosing source window assessed by line
                        lines=text.splitlines(); window='\n'.join(lines[max(0,n.lineno-8):min(len(lines),n.lineno+8)])
                        if field in window: producer,prod_rel,prod_text=n,rel,text; break
                    if isinstance(n,ast.Constant) and n.value==field: consumer,con_rel,con_text=n,rel,text
                if producer: break
            add(evidence,field+" producer","AUTHORITATIVE_PRODUCER_FOUND" if producer else "NOT_ESTABLISHED",prod_rel or "SDK_SEARCH",producer,prod_text or "","Digest computation associated with field found." if producer else "No authoritative digest computation associated with field found.","producer")
            add(evidence,field+" consumer","AUTHORITATIVE_CONSUMER_FOUND" if consumer else "NOT_ESTABLISHED",con_rel or "SDK_SEARCH",consumer,con_text or "","Field consumer located." if consumer else "Field consumer not found.","consumer")

        # Event sequence allocator. Validation alone is consumer, allocation requires increment/counter/enumerate near event creation.
        allocator=None; ar=None; at=None; validator=None; vr=None; vt=None
        for rel,(p,text,tree,fn) in sources.items():
            for n in ast.walk(tree):
                src=block(text,n)
                if allocator is None and isinstance(n,(ast.AugAssign,ast.Assign,ast.Call)) and re.search(r"sequence|event_id|counter",src,re.I) and ('+=' in src or 'next(' in src or 'enumerate(' in src): allocator,ar,at=n,rel,text
                if validator is None and isinstance(n,ast.Constant) and n.value=='completion_sequence': validator,vr,vt=n,rel,text
        add(evidence,"runtime event-sequence allocator","AUTHORITATIVE_PRODUCER_FOUND" if allocator else "NOT_ESTABLISHED",ar or "SDK_SEARCH",allocator,at or "","Sequence allocation mechanism found." if allocator else "No authoritative runtime proposal/outcome sequence allocator found.","producer")
        add(evidence,"completion-sequence consumer","AUTHORITATIVE_CONSUMER_FOUND" if validator else "NOT_ESTABLISHED",vr or "SDK_SEARCH",validator,vt or "","Completion sequence consumer/validator found." if validator else "Completion sequence consumer absent.","consumer")

        # Canonical source path producer/consumer
        prod=None; prrel=None; prtxt=None; cons=None; crel=None; ctxt=None
        for rel,(p,text,tree,fn) in sources.items():
            for n in ast.walk(tree):
                if isinstance(n,ast.Dict):
                    for k,v in zip(n.keys,n.values):
                        if isinstance(k,ast.Constant) and k.value=='canonical_source_path':
                            if 'trusted_context_adapter' in rel: cons,crel,ctxt=k,rel,text
                            else: prod,prrel,prtxt=n,rel,text
                elif isinstance(n,ast.Constant) and n.value=='canonical_source_path' and 'trusted_context_adapter' in rel: cons,crel,ctxt=n,rel,text
        add(evidence,"canonical_source_path producer","AUTHORITATIVE_PRODUCER_FOUND" if prod else "NOT_ESTABLISHED",prrel or "SDK_SEARCH",prod,prtxt or "","Runtime producer mapping found." if prod else "No authoritative runtime producer found.","producer")
        add(evidence,"canonical_source_path consumer","AUTHORITATIVE_CONSUMER_FOUND" if cons else "NOT_ESTABLISHED",crel or "SDK_SEARCH",cons,ctxt or "","Adapter consumer found." if cons else "Consumer not found.","consumer")

        summary={}
        for row in evidence:
            summary.setdefault(row['contract'],row['classification'])
        blockers=[k for k,v in summary.items() if v=='NOT_ESTABLISHED']
        actual_read_eligible=False
        status="P2M_R1_SOURCE_RETRIEVAL_CONTRACT_EVIDENCE_REVIEW_COMPLETE_PASS"
        next_gate="EX6_P2B_P2N_TRUSTED_OUTCOME_BRIDGE_AND_DIGEST_PRODUCER_DESIGN" if blockers else "EX6_P2B_P2M_R2_CONTROLLED_SOURCE_READ_EXECUTION_PREFLIGHT"
        result_obj={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"READ_ONLY_AUTHORITATIVE_PRODUCER_CONSUMER_REVIEW","P2M_parent_verified":True,"contracts":summary,"not_established":blockers,"execution_eligibility":{"controlled_actual_fs_read_eligible":actual_read_eligible,"reason":"Runtime source execution remains prohibited until every producer-side gap has an implemented and qualified contract."},"execution_boundaries":{"sdk_modules_imported":False,"fs_read_executed":False,"tools_executed":False,"fixture_contents_read":False,"source_value_exported":False,"source_value_previewed":False,"effects_observed":False,"sandbox_executed":False,"gym_executed":False,"breach_executed":False,"models_used":False},"scientific_verdict":{"authoritative_source_chain_review":"ESTABLISHED","producer_consumer_gaps":"IDENTIFIED" if blockers else "NONE_IDENTIFIED","actual_source_retrieval":"NOT_EVALUATED","secret_capture":"NOT_ESTABLISHED","protected_value_lineage":"NOT_ESTABLISHED","authorization_transport_correctness":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":{"allowed":["authoritative producer/consumer source-block classifications","exact unresolved producer-side gaps","continued source-execution eligibility decision"],"prohibited":["actual fs.read behavior","source retrieval success","secret capture","protected-value lineage","authorization transport correctness","guardrail effectiveness","real exfiltration prevention"]},"next_gate":next_gate}
        rp=out/'ex6_p2b_p2m_r1_result.json'; ep=out/'ex6_p2b_p2m_r1_evidence.csv'; bp=out/'ex6_p2b_p2m_r1_binding.json'; cp=out/'ex6_p2b_p2m_r1_claim_boundary.json'
        write_json(rp,result_obj); write_csv(ep,evidence,["contract","classification","role","relative_path","source_sha256","line_start","line_end","symbol","signature","rationale","redacted_source"]); write_json(cp,result_obj['claim_boundary']); write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{"p2m_result":ident(result),"p2m_external_binding":ident(binding),"p2m_manifest":ident(manifest),"p2m_runner":ident(runner)},"reviewed_sources":{rel:ident(root/Path(rel)) for rel in EXPECTED},"source_modified":False})
        rows=[{**ident(p),"role":"P2M_R1_DERIVED"} for p in (rp,ep,bp,cp)]+[{**ident(p),"role":"P2M_R1_BOUND"} for p in (result,binding,manifest,runner)]+[{**ident(root/Path(rel)),"role":"P2M_R1_SOURCE"} for rel in EXPECTED]
        man=out/'ex6_p2b_p2m_r1_manifest.csv'; write_csv(man,rows,["artifact","role","size_bytes","sha256","path"])
        ext=out/'ex6_p2b_p2m_r1_manifest_external_binding.json'; write_json(ext,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":man.name,"manifest_size_bytes":man.stat().st_size,"manifest_sha256":sha(man),"runner_sha256":sha(Path(__file__).resolve()),"not_established_count":len(blockers),"controlled_actual_fs_read_eligible":False,"fs_read_executed":False,"fixture_contents_read":False,"source_value_exported":False,"effects_observed":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"contracts_reviewed":len(summary),"not_established":blockers,"controlled_actual_fs_read_eligible":False,"manifest_sha256":sha(man),"next_gate":next_gate},indent=2))
    except Exception as exc:
        (out/'P2M_R1_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2M_R1_REVIEW_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"evidence_frozen":evidence,"fs_read_executed":False,"fixture_contents_read":False,"source_value_exported":False,"effects_observed":False},indent=2),encoding='utf-8')
        raise

def args():
    p=argparse.ArgumentParser(description=VERSION); p.add_argument('--p2m-result',required=True); p.add_argument('--p2m-external-binding',required=True); p.add_argument('--p2m-manifest',required=True); p.add_argument('--p2m-runner',required=True); p.add_argument('--project-root',required=True); p.add_argument('--output-dir',required=True); return p.parse_args()
if __name__=='__main__':
    try: main(args())
    except Exception as exc: print(f"FAILED: {exc}",file=sys.stderr); raise SystemExit(1)
