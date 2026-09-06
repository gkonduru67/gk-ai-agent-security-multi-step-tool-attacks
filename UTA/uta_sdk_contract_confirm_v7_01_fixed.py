#!/usr/bin/env python3
"""Focused UTA SDK contract confirmation v7.01 (JSON-safe fix).

Static inspection only. Does not import or execute aicomp_sdk and does not modify
SDK sources or fixtures.
"""
from __future__ import annotations
import argparse, ast, hashlib, json, os, platform, re, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "UTA_SDK_CONFIRM_v7.01"
CORE = {
    "predicates": "aicomp_sdk/core/predicates.py",
    "sandbox": "aicomp_sdk/core/env/sandbox.py",
    "optimal": "aicomp_sdk/guardrails/optimal.py",
    "guardrail_base": "aicomp_sdk/guardrails/base.py",
}

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""): h.update(b)
    return h.hexdigest().upper()

def text(path: Path) -> str:
    raw = path.read_bytes()
    try: return raw.decode("utf-8")
    except UnicodeDecodeError: return raw.decode("utf-8-sig")

def safe(v: Any) -> Any:
    """Deterministically convert AST values to JSON-safe data."""
    if v is None or isinstance(v, (str, int, float, bool)): return v
    if isinstance(v, dict): return {str(k): safe(x) for k, x in v.items()}
    if isinstance(v, (set, frozenset)):
        vals = [safe(x) for x in v]
        return sorted(vals, key=lambda x: json.dumps(x, sort_keys=True, ensure_ascii=False))
    if isinstance(v, (list, tuple)): return [safe(x) for x in v]
    if isinstance(v, bytes): return {"encoding": "hex", "value": v.hex()}
    if isinstance(v, Path): return str(v)
    return repr(v)

def span(n: ast.AST) -> dict[str, int]:
    return {"start_line": getattr(n,"lineno",0), "end_line": getattr(n,"end_lineno",getattr(n,"lineno",0))}

def excerpt(src: str, n: ast.AST) -> str:
    ls=src.splitlines(); a=max(1,getattr(n,"lineno",1)); b=min(len(ls),getattr(n,"end_lineno",a))
    return "\n".join(f"{i:06d}: {ls[i-1]}" for i in range(a,b+1))

def has_string(n: ast.AST, s: str) -> bool:
    return any(isinstance(x,ast.Constant) and x.value==s for x in ast.walk(n))

def named(tree: ast.AST, name: str, types: tuple[type,...]) -> ast.AST|None:
    return next((n for n in ast.walk(tree) if isinstance(n,types) and getattr(n,"name",None)==name),None)

def literal(n: ast.AST) -> Any:
    try: return safe(ast.literal_eval(n))
    except Exception:
        try: return ast.unparse(n)
        except Exception: return None

def inspect_predicates(p: Path) -> dict[str,Any]:
    s=text(p); t=ast.parse(s,filename=str(p)); ev=named(t,"eval_predicates",(ast.FunctionDef,ast.AsyncFunctionDef)); br=named(t,"is_breach",(ast.FunctionDef,ast.AsyncFunctionDef))
    if ev is None or br is None: raise RuntimeError("eval_predicates or is_breach not found")
    writes=[]
    for n in ast.walk(ev):
        if isinstance(n,ast.If) and has_string(n.test,"WRITE"):
            writes.append({**span(n),"condition":ast.unparse(n.test),"excerpt":excerpt(s,n)})
    uta=[]
    for n in ast.walk(br):
        if isinstance(n,ast.If) and has_string(n.test,"UNTRUSTED_TO_ACTION"):
            uta.append({**span(n),"condition":ast.unparse(n.test),"excerpt":excerpt(s,n)})
    return {"file":str(p),"sha256":sha256(p),"write_condition_candidates":writes,"uta_breach_branches":uta,
            "checks":{"write_condition_found":bool(writes),"uta_breach_branch_found":bool(uta)}}

def inspect_sandbox(p: Path) -> dict[str,Any]:
    s=text(p); t=ast.parse(s,filename=str(p)); contexts=[]; decides=[]; branches=[]; records=[]
    wanted={"side_effect","last_user","recent_sources","user_authorized","user_confirmed_safe","tool_name","tool_args"}
    for n in ast.walk(t):
        if isinstance(n,ast.Dict):
            keys=[k.value for k in n.keys if isinstance(k,ast.Constant) and isinstance(k.value,str)]
            rel=sorted(set(keys)&wanted)
            if rel: contexts.append({**span(n),"keys":keys,"relevant_keys":rel,"excerpt":excerpt(s,n)})
        if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute):
            call=ast.unparse(n)
            if n.func.attr=="decide": decides.append({**span(n),"call":call,"excerpt":excerpt(s,n)})
            if n.func.attr in {"append","record","add","emit"} and re.search(r"decision|denied|guardrail|tool_event|trace",call,re.I):
                records.append({**span(n),"call":call,"excerpt":excerpt(s,n)})
        if isinstance(n,ast.If):
            cond=ast.unparse(n.test); block=excerpt(s,n)
            if re.search(r"decision|allow|deny|confirm|blocked",cond+block,re.I): branches.append({**span(n),"condition":cond,"excerpt":block})
    return {"file":str(p),"sha256":sha256(p),"context_dict_candidates":contexts,"guardrail_decide_calls":decides,
            "decision_and_denial_branches":branches,"recording_call_candidates":records,
            "checks":{"guardrail_context_candidate_found":bool(contexts),"guardrail_decide_call_found":bool(decides),
                      "decision_branch_found":bool(branches),"recording_call_candidate_found":bool(records)}}

def inspect_optimal(p: Path) -> dict[str,Any]:
    s=text(p); t=ast.parse(s,filename=str(p)); cls=named(t,"Guardrail",(ast.ClassDef,))
    if cls is None: raise RuntimeError("Guardrail class not found in optimal.py")
    danger=[]; definition=None; calls=[]
    for n in ast.walk(cls):
        if isinstance(n,(ast.Assign,ast.AnnAssign)):
            targets=n.targets if isinstance(n,ast.Assign) else [n.target]
            if any((isinstance(x,ast.Name) and x.id=="dangerous_operations") or (isinstance(x,ast.Attribute) and x.attr=="dangerous_operations") for x in targets):
                danger.append({**span(n),"value":literal(n.value),"excerpt":excerpt(s,n)})
        if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=="track_untrusted_content":
            definition={**span(n),"arguments":[a.arg for a in n.args.args],"excerpt":excerpt(s,n)}
        if isinstance(n,ast.Call):
            fn=n.func
            hit=(isinstance(fn,ast.Attribute) and fn.attr=="track_untrusted_content") or (isinstance(fn,ast.Name) and fn.id=="track_untrusted_content")
            if hit: calls.append({**span(n),"call":ast.unparse(n),"excerpt":excerpt(s,n)})
    return {"file":str(p),"sha256":sha256(p),"dangerous_operations_assignments":danger,
            "track_untrusted_content_definition":definition,"track_untrusted_content_invocations_within_optimal":calls,
            "checks":{"dangerous_operations_found":bool(danger),"track_method_defined":definition is not None,
                      "track_method_invoked_within_optimal":bool(calls)}}

def inspect_base(p: Path) -> dict[str,Any]:
    s=text(p); t=ast.parse(s,filename=str(p)); d=named(t,"Decision",(ast.ClassDef,)); g=named(t,"GuardrailBase",(ast.ClassDef,))
    return {"file":str(p),"sha256":sha256(p),
            "decision_class":({**span(d),"excerpt":excerpt(s,d)} if d else None),
            "guardrail_base_class":({**span(g),"excerpt":excerpt(s,g)} if g else None)}

def inspect_tools(root: Path) -> dict[str,Any]:
    tr=root/"aicomp_sdk/core/tools"
    if not tr.is_dir(): raise RuntimeError(f"Tools directory not found: {tr}")
    files=sorted(tr.rglob("*.py")); candidates=[]; sources=[]
    for p in files:
        s=text(p)
        try: t=ast.parse(s,filename=str(p))
        except SyntaxError as e:
            candidates.append({"relative_path":p.relative_to(root).as_posix(),"parse_error":str(e)}); continue
        parents={}
        for n in ast.walk(t):
            if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):
                body=excerpt(s,n); low=body.lower()
                if re.search(r"\bweb\b|\bemail\b|web_corpus|mail_seed",low):
                    candidates.append({"relative_path":p.relative_to(root).as_posix(),"function":n.name,
                        "signature":f"{n.name}{ast.unparse(n.args)}",**span(n),"excerpt":body})
            if isinstance(n,ast.Constant) and n.value in {"web","email"}:
                sources.append({"relative_path":p.relative_to(root).as_posix(),"value":n.value,**span(n),"excerpt":excerpt(s,n)})
    high=[x for x in candidates if "signature" in x and any(q in x["excerpt"].lower() for q in ("web_corpus","mail_seed",'source="web"','source="email"','"source": "web"','"source": "email"'))]
    return {"tools_root":str(tr),"python_files_scanned":len(files),"candidate_lookup_methods":candidates,
            "high_relevance_lookup_methods":high,"source_literal_locations":sources,
            "checks":{"tool_files_found":bool(files),"lookup_candidates_found":bool(candidates),"high_relevance_lookup_method_found":bool(high)}}

def write_new(p: Path, data: str) -> None:
    if p.exists(): raise FileExistsError(f"Refusing to overwrite existing artifact: {p}")
    tmp=p.with_name(p.name+".tmp"); tmp.write_text(data,encoding="utf-8",newline="\n"); os.replace(tmp,p)

def markdown(r:dict[str,Any])->str:
    lines=["# Focused UTA SDK Contract Confirmation v7.01","",f"- Generated UTC: `{r['generated_utc']}`",f"- Status: `{r['status']}`",
           "- Method: static AST/source inspection only; SDK not imported or executed.","","## Decision summary",""]
    lines += [f"- **{k}**: `{v}`" for k,v in r["decision_summary"].items()]
    for title,key in [("UTA predicate and breach","predicate_confirmation"),("Sandbox context and denial recording","sandbox_confirmation"),
                      ("Web/email lookup signatures","tool_lookup_confirmation"),("Optimal guardrail","optimal_confirmation"),
                      ("Decision representation","guardrail_base_confirmation")]:
        lines += ["",f"## {title}","","```json",json.dumps(r[key],indent=2,ensure_ascii=False),"```"]
    lines += ["","## Boundaries","","- Static structure is not runtime invocation.",
              "- A deny branch is not evidence that an agent proposed an action.",
              "- A lookup signature is not proof that a fixture record loaded or returned.",""]
    return "\n".join(lines)

def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("--project-root",required=True,type=Path); ap.add_argument("--out-dir",required=True,type=Path); a=ap.parse_args()
    root=a.project_root.expanduser().resolve(); out=a.out_dir.expanduser().resolve()
    if not root.is_dir(): raise SystemExit(f"Project root not found: {root}")
    if out.exists(): raise SystemExit(f"Refusing to use existing output directory: {out}")
    paths={k:root/v for k,v in CORE.items()}; missing=[str(p.relative_to(root)) for p in paths.values() if not p.is_file()]
    if missing: raise SystemExit("Missing required source files:\n  - "+"\n  - ".join(missing))
    out.mkdir(parents=True,exist_ok=False)
    pred=inspect_predicates(paths["predicates"]); sand=inspect_sandbox(paths["sandbox"]); tools=inspect_tools(root); opt=inspect_optimal(paths["optimal"]); base=inspect_base(paths["guardrail_base"])
    summary={"write_predicate_condition_found":pred["checks"]["write_condition_found"],"uta_is_breach_branch_found":pred["checks"]["uta_breach_branch_found"],
      "sandbox_guardrail_context_found":sand["checks"]["guardrail_context_candidate_found"],"sandbox_guardrail_decide_call_found":sand["checks"]["guardrail_decide_call_found"],
      "sandbox_denial_recording_evidence_found":sand["checks"]["decision_branch_found"] and sand["checks"]["recording_call_candidate_found"],
      "web_email_lookup_candidates_found":tools["checks"]["high_relevance_lookup_method_found"],"optimal_dangerous_operations_found":opt["checks"]["dangerous_operations_found"],
      "optimal_track_method_defined":opt["checks"]["track_method_defined"],"optimal_track_method_invoked_within_optimal":opt["checks"]["track_method_invoked_within_optimal"]}
    required=[summary[k] for k in ("write_predicate_condition_found","uta_is_breach_branch_found","sandbox_guardrail_context_found","sandbox_guardrail_decide_call_found","web_email_lookup_candidates_found","optimal_dangerous_operations_found","optimal_track_method_defined")]
    status="CONFIRMATION_COMPLETE" if all(required) else "CONFIRMATION_INCOMPLETE_REVIEW_EVIDENCE"
    report=safe({"schema":"UTA_FOCUSED_SDK_CONFIRMATION_V1","version":VERSION,"generated_utc":datetime.now(timezone.utc).isoformat(),"project_root":str(root),"status":status,
      "method":{"static_only":True,"sdk_imported":False,"sdk_executed":False,"files_modified":False},"decision_summary":summary,
      "predicate_confirmation":pred,"sandbox_confirmation":sand,"tool_lookup_confirmation":tools,"optimal_confirmation":opt,"guardrail_base_confirmation":base,
      "interpretation_boundaries":["Static source confirms structure, not runtime invocation.","Guardrail denial requires a runtime proposed action and captured decision."]})
    jp=out/"uta_sdk_confirmation_v7_01.json"; mp=out/"uta_sdk_confirmation_v7_01.md"; fp=out/"uta_sdk_confirmation_v7_01_freeze_manifest.json"
    write_new(jp,json.dumps(report,indent=2,ensure_ascii=False)+"\n"); write_new(mp,markdown(report)+"\n")
    inp=sorted({p.resolve() for p in list(paths.values())+sorted((root/"aicomp_sdk/core/tools").rglob("*.py"))})
    manifest=safe({"schema":"UTA_FOCUSED_SDK_CONFIRMATION_FREEZE_V1","version":VERSION,"created_utc":datetime.now(timezone.utc).isoformat(),
      "inputs":[{"relative_path":p.relative_to(root).as_posix(),"size_bytes":p.stat().st_size,"sha256":sha256(p)} for p in inp],
      "outputs":[{"file_name":p.name,"size_bytes":p.stat().st_size,"sha256":sha256(p)} for p in (jp,mp)],
      "runtime":{"python":sys.version,"platform":platform.platform(),"script_file":Path(__file__).name,"script_sha256":sha256(Path(__file__).resolve())},
      "limitations":["Static inspection only.","Manifest SHA-256 printed externally to avoid self-reference."]})
    write_new(fp,json.dumps(manifest,indent=2,ensure_ascii=False)+"\n")
    print(f"Status: {status}"); [print(f"{k}: {v}") for k,v in summary.items()]
    print(f"JSON: {jp}\nMarkdown: {mp}\nFreeze manifest: {fp}\nFreeze manifest SHA256: {sha256(fp)}")
    return 0 if status=="CONFIRMATION_COMPLETE" else 3
if __name__=="__main__": raise SystemExit(main())
