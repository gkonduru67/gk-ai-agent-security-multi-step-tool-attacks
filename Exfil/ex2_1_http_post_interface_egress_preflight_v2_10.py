#!/usr/bin/env python3
r"""EX2.1 HTTP POST documented-interface and local-egress preflight v2.10.

Scope: static SDK routing inspection, registry inventory, safe KeyError diagnosis,
benign sink-only invocation, private-network control, and nonempty reset control.
No model, agent, guardrail, notebook, Gym, hosted evaluator, network client, or
packaged-fixture write is performed. Evidence is written only to logs-root.
"""
from __future__ import annotations
import argparse, ast, csv, datetime as dt, hashlib, importlib, inspect, json, re, shutil, sys, tempfile, traceback
from pathlib import Path
from typing import Any

VERSION="EX2_1_HTTP_POST_DOCUMENTED_INTERFACE_AND_EGRESS_PREFLIGHT_v2.10"
FILES=["aicomp_sdk/core/tools/suite.py","aicomp_sdk/core/tools/registry.py","aicomp_sdk/core/tools/schema.py","aicomp_sdk/core/tools/http.py"]

def shab(b:bytes)->str:return hashlib.sha256(b).hexdigest().upper()
def shaf(p:Path)->str:
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest().upper()
def timestamp()->str:return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
def iso()->str:return dt.datetime.now(dt.timezone.utc).isoformat()
def dump(p:Path,x:Any):
 with p.open("x",encoding="utf-8") as f:json.dump(x,f,indent=2,sort_keys=True,ensure_ascii=False);f.write("\n")
def csvout(p:Path,fields:list[str],rows:list[dict[str,Any]]):
 with p.open("x",encoding="utf-8-sig",newline="") as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore");w.writeheader();w.writerows(rows)
def safe(v:Any,n=240)->str:
 s=repr(v);return s[:n]
def exinfo(e:BaseException)->dict[str,Any]:
 tb=traceback.extract_tb(e.__traceback__)
 key=safe(e.args[0]) if isinstance(e,KeyError) and e.args else None
 return {"type":type(e).__name__,"missing_key_repr":key,"missing_key_sha256":shab(key.encode()) if key else None,"message_sha256":shab(f"{type(e).__name__}:{e}".encode()),"traceback_functions":[x.name for x in tb],"traceback_files":[Path(x.filename).name for x in tb],"traceback_lines":[x.lineno for x in tb],"traceback_sha256":shab("\n".join(traceback.format_exception(type(e),e,e.__traceback__)).encode())}
def egress(suite:Any):
 for method in ("get_egress","egress"):
  fn=getattr(suite,method,None)
  if callable(fn):
   try:return list(fn())
   except Exception:pass
 for state_name in ("_state","state"):
  try:return list(getattr(getattr(suite,state_name),"egress_sink"))
  except Exception:pass
 return None

def static_inspect(project:Path)->dict[str,Any]:
 out={"files":[],"functions":[],"string_literals":[],"registrations":[]}
 for rel in FILES:
  p=project/rel;row={"relative_path":rel,"exists":p.is_file()}
  if not p.is_file():out["files"].append(row);continue
  text=p.read_text(encoding="utf-8");row.update(size_bytes=p.stat().st_size,sha256=shaf(p));out["files"].append(row)
  tree=ast.parse(text)
  for n in ast.walk(tree):
   if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
    seg=ast.get_source_segment(text,n) or ""
    if re.search(r"(?i)(http|post|call|register|route|egress|reset|build_state)",getattr(n,"name","")+"\n"+seg):out["functions"].append({"file":rel,"kind":type(n).__name__,"name":getattr(n,"name",""),"start_line":n.lineno,"end_line":getattr(n,"end_lineno",n.lineno),"source_sha256":shab(seg.encode())})
   if isinstance(n,ast.Constant) and isinstance(n.value,str) and re.search(r"(?i)(http|post|egress|private|url|data)",n.value):out["string_literals"].append({"file":rel,"line":getattr(n,"lineno",None),"value":n.value})
   if isinstance(n,(ast.Dict,ast.Call,ast.Assign,ast.AnnAssign)):
    seg=ast.get_source_segment(text,n) or ""
    if "http.post" in seg or "http_post" in seg:out["registrations"].append({"file":rel,"start_line":getattr(n,"lineno",None),"end_line":getattr(n,"end_lineno",getattr(n,"lineno",None)),"source_sha256":shab(seg.encode()),"excerpt":seg[:1200]})
 return out

def public_inventory(suite:Any)->dict[str,Any]:
 result={"suite_type":type(suite).__name__,"suite_signature":str(inspect.signature(type(suite))),"attributes":[],"registered_names":[],"schemas":[]}
 for name in sorted(dir(suite)):
  if name.startswith("__"):continue
  try:v=getattr(suite,name)
  except Exception:continue
  result["attributes"].append({"name":name,"type":type(v).__name__,"callable":callable(v)})
  if any(x in name.lower() for x in ("tool","registry","schema")):
   if isinstance(v,dict):
    result["registered_names"].extend(str(k) for k in v.keys())
    for k,val in v.items():result["schemas"].append({"container":name,"tool":str(k),"value_type":type(val).__name__,"value_repr":safe(val,500)})
   elif isinstance(v,(list,tuple,set)):
    for x in v:
     if isinstance(x,str):result["registered_names"].append(x)
     else:
      xn=getattr(x,"name",None)
      if xn:result["registered_names"].append(str(xn))
 return result

def invoke(suite:Any,name:str,args:dict[str,Any])->dict[str,Any]:
 before=egress(suite)
 try:
  raw=suite.call(name,args);after=egress(suite)
  if isinstance(raw,(tuple,list)) and len(raw)==3:ok,out,error=raw
  else:ok,out,error=None,raw,None
  return {"attempted_name":name,"arguments":args,"returned":True,"return_type":type(raw).__name__,"ok":bool(ok) if ok is not None else None,"error":error,"output_sha256":shab(str(out).encode()),"output_size":len(str(out)),"egress_before_count":len(before) if before is not None else None,"egress_after_count":len(after) if after is not None else None,"egress_delta":len(after)-len(before) if before is not None and after is not None else None,"egress_last_url":after[-1][0] if after and isinstance(after[-1],(tuple,list)) else None,"egress_last_data_sha256":shab(str(after[-1][1]).encode()) if after and isinstance(after[-1],(tuple,list)) and len(after[-1])>1 else None}
 except Exception as e:return {"attempted_name":name,"arguments":args,"returned":False,"exception":exinfo(e),"egress_before_count":len(before) if before is not None else None,"egress_after_count":len(egress(suite)) if egress(suite) is not None else None}

def main()->int:
 ap=argparse.ArgumentParser(description="EX2.1 HTTP POST interface and local-egress preflight")
 ap.add_argument("--project-root",required=True,type=Path);ap.add_argument("--fixtures-root",type=Path);ap.add_argument("--logs-root",type=Path,default=Path(r"C:\x_ai_logs\Exfil"));ap.add_argument("--run-id")
 a=ap.parse_args();project=a.project_root.resolve();fixtures=(a.fixtures_root or project/"aicomp_sdk"/"fixtures").resolve();run=a.run_id or timestamp();out=a.logs_root.resolve()/"EX2_1_http_post_interface_egress_preflight"/f"run_{run}"
 if not (project/"aicomp_sdk").is_dir():ap.error("project-root must contain aicomp_sdk")
 if not fixtures.is_dir():ap.error(f"fixtures root not found: {fixtures}")
 if out.exists():ap.error(f"Refusing to overwrite: {out}")
 out.mkdir(parents=True);sys.path.insert(0,str(project));before={str(p.relative_to(fixtures)):shaf(p) for p in fixtures.rglob("*") if p.is_file()};static=static_inspect(project)
 suite_mod=importlib.import_module("aicomp_sdk.core.tools.suite");ToolSuite=getattr(suite_mod,"ToolSuite")
 with tempfile.TemporaryDirectory(prefix="ex2_1_") as td:
  copied=Path(td)/"fixtures";shutil.copytree(fixtures,copied);suite=ToolSuite(copied,isolate_fs=True);inventory=public_inventory(suite)
  candidates=[]
  for n in inventory["registered_names"]:
   if "http" in n.lower() and "post" in n.lower() and n not in candidates:candidates.append(n)
  for r in static["registrations"]:
   ex=r.get("excerpt","")
   for n in re.findall(r"['\"]([^'\"]*(?:http\.post|http_post)[^'\"]*)['\"]",ex,re.I):
    if n not in candidates:candidates.append(n)
  if "http.post" not in candidates:candidates.insert(0,"http.post")
  marker="EX2_1_BENIGN_EGRESS_MARKER_"+run;allowed_args={"url":"https://example.invalid/ex2-1","data":marker};attempts=[];success=None
  for name in candidates:
   row=invoke(suite,name,allowed_args);attempts.append(row)
   if row.get("ok") is True and row.get("egress_delta")==1:success=row;break
  private=None;reset=None
  if success:
   private=invoke(suite,success["attempted_name"],{"url":"http://127.0.0.1/ex2-1","data":"BENIGN_PRIVATE_CONTROL"})
   before_reset=egress(suite);suite.reset(0);after_reset=egress(suite);reset={"egress_before_reset_count":len(before_reset) if before_reset is not None else None,"egress_after_reset_count":len(after_reset) if after_reset is not None else None,"passed":before_reset is not None and len(before_reset)>0 and after_reset==[]}
 after={str(p.relative_to(fixtures)):shaf(p) for p in fixtures.rglob("*") if p.is_file()};unchanged=before==after
 decision={"sdk_files_present":all(x["exists"] for x in static["files"]),"http_post_registration_evidence_found":bool(static["registrations"] or candidates),"known_good_sink_call_passed":success is not None,"egress_effect_passed":success is not None and success.get("egress_delta")==1,"private_network_control_passed":bool(private and private.get("returned") and private.get("ok") is False and private.get("error")=="private_net_blocked"),"nonempty_reset_control_passed":bool(reset and reset["passed"]),"packaged_fixtures_unchanged":unchanged,"attack_optimization_authorized":False}
 raw={"schema":"EX2_1_PREFLIGHT_V2_10","version":VERSION,"run_id":run,"generated_utc":iso(),"method":{"model_used":False,"agent_used":False,"guardrail_used":False,"network_delivery_claimed":False,"packaged_fixture_write":False},"static_routing":static,"registry_inventory":inventory,"candidate_tool_names":candidates,"attempts":attempts,"successful_call":success,"private_network_control":private,"reset_control":reset,"packaged_fixtures_unchanged":unchanged,"decision":decision}
 names={"raw":f"ex2_1_{run}_raw.json","sdk":f"ex2_1_{run}_sdk.csv","registry":f"ex2_1_{run}_registry.csv","attempts":f"ex2_1_{run}_attempts.csv","summary":f"ex2_1_{run}_summary.md","manifest":f"ex2_1_{run}_manifest.csv"}
 dump(out/names["raw"],raw);csvout(out/names["sdk"],["relative_path","exists","size_bytes","sha256"],static["files"]);csvout(out/names["registry"],["container","tool","value_type","value_repr"],inventory["schemas"])
 flat=[]
 for x in attempts:
  flat.append({"attempted_name":x.get("attempted_name"),"returned":x.get("returned"),"ok":x.get("ok"),"error":x.get("error"),"exception_type":x.get("exception",{}).get("type"),"missing_key_repr":x.get("exception",{}).get("missing_key_repr"),"missing_key_sha256":x.get("exception",{}).get("missing_key_sha256"),"traceback_functions":json.dumps(x.get("exception",{}).get("traceback_functions",[])),"egress_before_count":x.get("egress_before_count"),"egress_after_count":x.get("egress_after_count"),"egress_delta":x.get("egress_delta")})
 csvout(out/names["attempts"],["attempted_name","returned","ok","error","exception_type","missing_key_repr","missing_key_sha256","traceback_functions","egress_before_count","egress_after_count","egress_delta"],flat)
 with (out/names["summary"]).open("x",encoding="utf-8") as f:f.write("# EX2.1 HTTP POST Interface and Egress Preflight\n\n"+"\n".join(f"- {k}: **{v}**" for k,v in decision.items())+"\n\nLocal ToolSuite preflight only. No network-delivery, agent, guardrail, or hosted-parity claim.\n")
 man=[]
 for p in sorted(out.iterdir()):
  if p.is_file() and p.name!=names["manifest"]:man.append({"artifact":p.name,"size_bytes":p.stat().st_size,"sha256":shaf(p)})
 csvout(out/names["manifest"],["artifact","size_bytes","sha256"],man)
 print(f"Evidence package: {out}");print(json.dumps(decision,indent=2));required=["sdk_files_present","http_post_registration_evidence_found","known_good_sink_call_passed","egress_effect_passed","private_network_control_passed","nonempty_reset_control_passed","packaged_fixtures_unchanged"];return 0 if all(decision[k] for k in required) else 2
if __name__=="__main__":raise SystemExit(main())
