#!/usr/bin/env python3
r"""Read-only historical notebook inventory, corrected path layout v1.0.1.

Defaults from --project-root:
  source: <project-root>\backup_versions
  project evidence: <project-root>\ai-agent-security-multi-step-tool-attacks\Exfil
  logs: C:\x_ai_logs\Exfil
No notebook is executed, modified, copied, renamed, or normalized.
"""
from __future__ import annotations
import argparse, ast, csv, datetime as dt, hashlib, json, os, re, shutil, sys
from collections import Counter
from pathlib import Path
from typing import Any

VERSION="EXFIL_HISTORICAL_INVENTORY_v1.0.1"
VERSION_RE=re.compile(r"(?i)(?<![A-Za-z0-9])v?1[._-]1[._-]0*(\d{1,3})(?!\d)")
TERMS=("exfil","fs.read","http.post","secret","protected","predicate","breach","guardrail","source","sink","payload","fixture","encoded","base64","provenance")
CONTROLS=("synthetic_predicate_positive","source_only","sink_only","read_then_post","unrelated_post","encoded_derivation","guardrail_block","failed_source_attribution","wrong_source_value","post_without_successful_effect")
FAIL=("traceback","exception","error","failed","denied","blocked","timeout","invalid argument")
SUCCESS=("success","succeeded","tool_result","tool result","status_code","status code"," 200","effect_observed")
FILE_RE=re.compile(r"(?i)(?P<p>(?:[A-Z]:[/\\]|\.{0,2}[/\\])[^\s\"'`<>|]+?\.(?:py|ipynb|json|ya?ml|csv|tsv|txt|log|md|parquet|pkl|pickle|bin|db|sqlite|xml))")
LITERAL_RE=re.compile(r"(?i)(?P<p>[A-Za-z0-9_.-]+\.(?:py|ipynb|json|ya?ml|csv|tsv|txt|log|md|parquet|pkl|pickle|bin|db|sqlite|xml))")

def sha_file(p:Path)->str:
    h=hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda:f.read(1048576),b""): h.update(b)
    return h.hexdigest().upper()
def sha_bytes(b:bytes)->str:return hashlib.sha256(b).hexdigest().upper()
def text(v:Any)->str:return v if isinstance(v,str) else "".join(map(str,v)) if isinstance(v,list) else "" if v is None else str(v)
def clean(s:str,n=220)->str:
    s=re.sub(r"[\x00-\x1f\x7f]+"," ",s);s=re.sub(r"\s+"," ",s).strip()
    s=re.sub(r"(?i)(secret|token|password|api[_-]?key)\s*[:=]\s*\S+",r"\1=<REDACTED>",s)
    return re.sub(r"\b[A-Za-z0-9+/=_-]{48,}\b","<LONG_TOKEN_REDACTED>",s)[:n]
def write_csv(p:Path,fields:list[str],rows:list[dict[str,Any]]):
    with p.open("x",encoding="utf-8-sig",newline="") as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction="raise");w.writeheader()
        for r in rows:w.writerow({k:r.get(k,"") for k in fields})
def imports(src:str)->set[str]:
    out=set()
    try:t=ast.parse(src)
    except (SyntaxError,ValueError):return out
    for n in ast.walk(t):
        if isinstance(n,ast.Import):out|={a.name for a in n.names}
        elif isinstance(n,ast.ImportFrom) and n.module:out.add(n.module)
    return out
def output_text(o:dict)->str:
    d=o.get("data",{});vals=list(d.values()) if isinstance(d,dict) else []
    return "\n".join(text(x) for x in [o.get("name"),o.get("ename"),o.get("evalue"),o.get("text"),o.get("traceback"),*vals])
def version(name:str):
    m=VERSION_RE.search(name);return (m.group(0),int(m.group(1))) if m else ("",None)
def purpose(src:str,matched:list[str])->str:
    lines=[x.strip().lstrip("#").strip() for x in src.splitlines() if x.strip() and not x.strip().startswith(("```","import ","from "))][:2]
    return clean(("; ".join(lines) or "No concise source description")+" [matched: "+", ".join(matched[:8])+"]")
def resolve(raw:str,nb:Path,root:Path):
    norm=raw.strip().strip(".,;:)]}").replace("\\",os.sep).replace("/",os.sep);p=Path(norm)
    choices=[("ABSOLUTE",p)] if p.is_absolute() else [("NOTEBOOK_PARENT",nb.parent/p),("PROJECT_ROOT",root/p)]
    for base,x in choices:
        x=x.resolve(strict=False)
        if x.is_file():return norm,base,x
    base,x=choices[0];return norm,base,x.resolve(strict=False)
def classify(sig:dict[str,bool],errors:int,relevant:int):
    if sig["control"]:return "CONTROL","Explicit control marker found."
    if all(sig[k] for k in ("read","post","data","read_success","post_success","predicate","breach")):return "CANDIDATE_FINDING","Candidate markers coexist; ordered trace and artifacts still require verification."
    if relevant and (errors or sig["failure"]):return "FAILED_DIAGNOSTIC","Relevant evidence contains failure or error markers."
    return "PARTIAL","Preserved evidence does not establish every mandatory chain gate."

def main()->int:
    ap=argparse.ArgumentParser(description="Read-only EXFILTRATION notebook inventory")
    ap.add_argument("--project-root",required=True,type=Path,help="Outer root containing backup_versions and ai-agent-security-multi-step-tool-attacks")
    ap.add_argument("--notebook-root",type=Path,help="Default: <project-root>/backup_versions")
    ap.add_argument("--project-exfil-root",type=Path,help="Default: <project-root>/ai-agent-security-multi-step-tool-attacks/Exfil")
    ap.add_argument("--logs-root",type=Path,default=Path(r"C:\x_ai_logs\Exfil"))
    ap.add_argument("--start-patch",type=int,default=4);ap.add_argument("--end-patch",type=int,default=16)
    ap.add_argument("--run-id",help="Unique ID; UTC timestamp by default")
    a=ap.parse_args();root=a.project_root.expanduser().resolve();nbroot=(a.notebook_root or root/"backup_versions").expanduser().resolve();projex=(a.project_exfil_root or root/"ai-agent-security-multi-step-tool-attacks"/"Exfil").expanduser().resolve();logs=a.logs_root.expanduser().resolve()
    if not root.is_dir():ap.error(f"Project root not found: {root}")
    if not nbroot.is_dir():ap.error(f"Notebook root not found: {nbroot}")
    if a.start_patch>a.end_patch:ap.error("--start-patch must be <= --end-patch")
    rid=a.run_id or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+",rid):ap.error("Invalid --run-id")
    logpkg=logs/"historical_inventory"/f"inventory_{rid}";projpkg=projex/"historical_inventory"/f"inventory_{rid}"
    if logpkg.exists() or projpkg.exists():ap.error(f"Refusing to overwrite run_id={rid}")
    logpkg.mkdir(parents=True);projpkg.mkdir(parents=True)
    selected=[];excluded=[]
    for p in sorted(nbroot.rglob("*.ipynb"),key=lambda x:str(x).lower()):
        _,patch=version(p.name);(selected if patch is not None and a.start_patch<=patch<=a.end_patch else excluded).append(p)
    debug=logpkg/f"exfil_historical_inventory_debug_{rid}.log"
    with debug.open("x",encoding="utf-8") as f:
        f.write(f"version={VERSION}\nnotebook_root={nbroot}\nproject_exfil_root={projex}\nlogs_root={logs}\nselected={len(selected)}\n")
        for p in excluded:f.write(f"excluded={p.relative_to(nbroot)}\n")
    if not selected:
        with debug.open("a",encoding="utf-8") as f:f.write("ERROR No matching notebooks found\n")
        print(f"ERROR No matching notebooks found under: {nbroot}",file=sys.stderr);return 2
    initial={p:(sha_file(p),p.stat().st_size,p.stat().st_mtime_ns) for p in selected}
    nbrows=[];cellrows=[];refrows=[];hashrows=[];exit_code=0
    for p in selected:
        rel=str(p.relative_to(nbroot));token,patch=version(p.name);before,size,mtime=initial[p];parse_status="OK";parse_error=""
        try:doc=json.loads(p.read_bytes().decode("utf-8-sig"));assert isinstance(doc,dict) and isinstance(doc.get("cells",[]),list)
        except Exception as e:parse_status="ERROR:"+type(e).__name__;parse_error=sha_bytes(str(e).encode());doc={"cells":[],"metadata":{}}
        cs=doc.get("cells",[]);meta=doc.get("metadata",{}) or {};cnt=Counter();execs=[];errors=relevant=refcount=0;sig={k:False for k in ("control","read","post","data","read_success","post_success","predicate","breach","failure")}
        for i,c in enumerate(cs):
            if not isinstance(c,dict):continue
            typ=str(c.get("cell_type","other"));cnt[typ]+=1;src=text(c.get("source"));ec=c.get("execution_count")
            if isinstance(ec,int):execs.append(ec)
            outs=c.get("outputs",[]) if typ=="code" else [];outs=outs if isinstance(outs,list) else []
            otypes=[str(o.get("output_type","unknown")) for o in outs if isinstance(o,dict)];enames=[str(o.get("ename","UnknownError")) for o in outs if isinstance(o,dict) and o.get("output_type")=="error"]
            errors+=bool(enames);cnt["with_outputs"]+=bool(outs);cnt["outputs"]+=len(outs)
            obs=(src+"\n"+"\n".join(output_text(o) for o in outs if isinstance(o,dict))).lower();matched=sorted(t for t in TERMS if t in obs);isrel=bool(matched);relevant+=isrel;norm=obs.replace("-","_").replace(" ","_")
            sig["control"]|=any(x in norm for x in CONTROLS);sig["read"]|="fs.read" in obs or "fs_read" in obs;sig["post"]|="http.post" in obs or "http_post" in obs;sig["data"]|=bool(re.search(r"[\"']?data[\"']?\s*[:=]",obs));sig["read_success"]|=sig["read"] and any(x in obs for x in SUCCESS);sig["post_success"]|=sig["post"] and any(x in obs for x in SUCCESS);sig["predicate"]|="predicate" in obs and any(x in obs for x in SUCCESS);sig["breach"]|=bool(re.search(r"breach\s*[:=]\s*(true|1)",obs));sig["failure"]|=any(x in obs for x in FAIL)
            cellrows.append({"notebook_relative_path":rel,"notebook_sha256":before,"cell_index":i,"cell_type":typ,"execution_count":ec if ec is not None else "","source_sha256":sha_bytes(src.encode()),"source_char_count":len(src),"output_count":len(outs),"output_types":json.dumps(otypes),"outputs_sha256":sha_bytes(json.dumps(outs,sort_keys=True,ensure_ascii=False,separators=(",", ":")).encode()) if outs else "","has_error_output":bool(enames),"error_names":json.dumps(enames),"exfiltration_related":isrel,"matched_terms":json.dumps(matched),"concise_purpose":purpose(src,matched) if isrel else ""})
            found={m.group("p") for rx in (FILE_RE,LITERAL_RE) for m in rx.finditer(src)}
            for mod in imports(src):
                cand=mod.replace(".",os.sep)+".py";_,_,rp=resolve(cand,p,root)
                if rp.is_file():found.add(cand)
            for raw in sorted(found):
                norm,base,rp=resolve(raw,p,root);exists=rp.is_file();rh=rs="";hs="NOT_FOUND"
                if exists:
                    try:rh,rs,hs=sha_file(rp),rp.stat().st_size,"HASHED"
                    except OSError as e:hs="HASH_ERROR:"+type(e).__name__
                refrows.append({"notebook_relative_path":rel,"notebook_sha256":before,"cell_index":i,"reference_text":clean(raw,500),"normalized_reference":clean(norm,500),"resolution_base":base,"resolved_path":str(rp),"exists":exists,"referenced_file_sha256":rh,"referenced_file_size":rs,"hash_status":hs});refcount+=1
        status,rationale=classify(sig,errors,relevant)
        if parse_status!="OK":status,rationale="PARTIAL","Notebook JSON could not be parsed; only file identity is established."
        after=sha_file(p);st=p.stat();stable=before==after and size==st.st_size and mtime==st.st_mtime_ns
        if not stable:exit_code=3
        kernel=meta.get("kernelspec",{}) if isinstance(meta,dict) else {};lang=meta.get("language_info",{}) if isinstance(meta,dict) else {};dup=sorted(k for k,v in Counter(execs).items() if v>1)
        nbrows.append({"relative_path":rel,"filename":p.name,"version_token":token,"version_patch":patch,"sha256_before":before,"sha256_after":after,"hash_stable":stable,"size_bytes":size,"mtime_ns":mtime,"nbformat":doc.get("nbformat", ""),"nbformat_minor":doc.get("nbformat_minor", ""),"kernel_name":kernel.get("name","") if isinstance(kernel,dict) else "","kernel_display_name":kernel.get("display_name","") if isinstance(kernel,dict) else "","language_name":lang.get("name","") if isinstance(lang,dict) else "","language_version":lang.get("version","") if isinstance(lang,dict) else "","cell_count":len(cs),"code_cells":cnt["code"],"markdown_cells":cnt["markdown"],"raw_cells":cnt["raw"],"executed_code_cells":len(execs),"unexecuted_code_cells":cnt["code"]-len(execs),"cells_with_outputs":cnt["with_outputs"],"output_count":cnt["outputs"],"error_cell_count":errors,"execution_count_min":min(execs) if execs else "","execution_count_max":max(execs) if execs else "","duplicate_execution_counts":json.dumps(dup),"out_of_order_execution_counts":any(a>b for a,b in zip(execs,execs[1:])),"exfiltration_related_cells":relevant,"reference_count":refcount,"scientific_status":status,"status_rationale":rationale,"manual_review_required":True,"parse_status":parse_status,"parse_error_sha256":parse_error})
        hashrows.append({"relative_path":rel,"filename":p.name,"size_bytes":size,"mtime_ns":mtime,"sha256_before":before,"sha256_after":after,"hash_stable":stable})
    names={"notebooks":f"exfil_historical_notebooks_{rid}.csv","cells":f"exfil_historical_cells_{rid}.csv","references":f"exfil_historical_references_{rid}.csv","hashes":f"exfil_historical_notebook_sha256_{rid}.csv","preflight":f"exfil_historical_inventory_preflight_{rid}.json","summary":f"exfil_historical_inventory_summary_{rid}.md","manifest":f"exfil_historical_inventory_manifest_{rid}.csv"}
    write_csv(logpkg/names["notebooks"],list(nbrows[0]),nbrows);write_csv(logpkg/names["cells"],list(cellrows[0]) if cellrows else ["notebook_relative_path"],cellrows);write_csv(logpkg/names["references"],list(refrows[0]) if refrows else ["notebook_relative_path"],refrows);write_csv(logpkg/names["hashes"],list(hashrows[0]),hashrows)
    pre={"run_id":rid,"script_version":VERSION,"created_utc":dt.datetime.now(dt.timezone.utc).isoformat(),"project_root":str(root),"notebook_root":str(nbroot),"project_exfil_root":str(projex),"logs_root":str(logs),"selected_notebook_count":len(selected),"excluded_ipynb_count":len(excluded),"read_only_method":"binary read + in-memory JSON parse; no notebook writer or kernel","raw_cell_or_output_content_copied":False,"hash_stability_passed":all(x["hash_stable"] for x in hashrows),"status_counts":dict(Counter(x["scientific_status"] for x in nbrows)),"exit_code":exit_code}
    with (logpkg/names["preflight"]).open("x",encoding="utf-8") as f:json.dump(pre,f,indent=2,sort_keys=True);f.write("\n")
    lines=["# EXFILTRATION Historical Notebook Inventory","",f"- Run ID: `{rid}`",f"- Notebook source: `{nbroot}`",f"- Project evidence root: `{projex}`",f"- Log root: `{logs}`","","Statuses are machine-assisted triage, not confirmed findings.",""]
    for x in nbrows:lines += [f"## {x['filename']}",f"- SHA-256: `{x['sha256_before']}`",f"- Status: `{x['scientific_status']}`",f"- Rationale: {x['status_rationale']}",""]
    with (logpkg/names["summary"]).open("x",encoding="utf-8") as f:f.write("\n".join(lines))
    manifest=[]
    for p in sorted(logpkg.iterdir(),key=lambda x:x.name.lower()):
        if p.is_file() and p.name!=names["manifest"]:manifest.append({"artifact":p.name,"size_bytes":p.stat().st_size,"sha256":sha_file(p)})
    write_csv(logpkg/names["manifest"],["artifact","size_bytes","sha256"],manifest)
    for src in sorted(logpkg.iterdir(),key=lambda x:x.name.lower()):
        if src.is_file():
            dst=projpkg/src.name;shutil.copy2(src,dst)
            if sha_file(src)!=sha_file(dst):raise RuntimeError(f"Mirror hash mismatch: {src.name}")
    print(f"Notebook source: {nbroot}");print(f"Canonical logs: {logpkg}");print(f"Verified project copy: {projpkg}");return exit_code
if __name__=="__main__":raise SystemExit(main())
