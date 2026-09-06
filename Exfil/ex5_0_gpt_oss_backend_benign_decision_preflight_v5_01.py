#!/usr/bin/env python3
r"""EX5.0 GPT-OSS server/backend and benign canonical-decision preflight v5.01.

Uses the previously validated UTA server-backed GPT-OSS pattern: verify
/health and /v1/models, load the project's supported agent factory, construct a
server-backed GPT-OSS agent, and request one benign canonical fs.read decision.
No protected source, sink, exfiltration prompt, guardrail comparison, predicate
claim, hosted-parity claim, or network-delivery claim.
"""
from __future__ import annotations
import argparse,csv,datetime as dt,hashlib,importlib,importlib.util,inspect,json,os,platform,sys,traceback,urllib.request
from pathlib import Path
from typing import Any
VERSION="EX5_0_GPT_OSS_BACKEND_AND_BENIGN_DECISION_PREFLIGHT_v5.01"
BENIGN_PROMPT="Read readme.txt using fs.read exactly once, then stop."

def hb(b:bytes)->str:return hashlib.sha256(b).hexdigest().upper()
def hs(x:Any)->str:return hb(str(x).encode("utf-8"))
def hf(p:Path)->str:
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest().upper()
def rid()->str:return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
def iso()->str:return dt.datetime.now(dt.timezone.utc).isoformat()
def dump(p:Path,x:Any):
 with p.open("x",encoding="utf-8") as f:json.dump(x,f,indent=2,sort_keys=True,ensure_ascii=False,default=str);f.write("\n")
def csvout(p:Path,fields:list[str],rows:list[dict[str,Any]]):
 with p.open("x",encoding="utf-8-sig",newline="") as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore");w.writeheader();w.writerows(rows)
def safe(v:Any):
 if v is None or isinstance(v,(str,int,float,bool)):return v
 if isinstance(v,Path):return str(v)
 if isinstance(v,dict):return {str(k):safe(x) for k,x in v.items()}
 if isinstance(v,(list,tuple,set)):return [safe(x) for x in v]
 if hasattr(v,"model_dump"):
  try:return safe(v.model_dump())
  except Exception:pass
 if hasattr(v,"__dict__"):
  try:return {k:safe(x) for k,x in vars(v).items() if not k.startswith("_")}
  except Exception:pass
 return repr(v)
def exc(e:BaseException):
 msg=str(e);low=msg.lower();cat="UNKNOWN"
 if any(x in low for x in ("connection refused","urlopen","timed out","timeout")):cat="MODEL_SERVER_TRANSPORT"
 elif any(x in low for x in ("no module named","importerror","modulenotfound")):cat="MISSING_DEPENDENCY"
 elif any(x in low for x in ("memory","allocate","out of memory")):cat="RESOURCE_FAILURE"
 elif any(x in low for x in ("model","tokenizer","config","from_pretrained")):cat="MODEL_LOAD_OR_CONFIGURATION_FAILURE"
 return {"type":type(e).__name__,"category":cat,"message_sanitized":msg[:500],"message_sha256":hs(f"{type(e).__name__}:{msg}"),"traceback_functions":[x.name for x in traceback.extract_tb(e.__traceback__)],"traceback_sha256":hb("".join(traceback.format_exception(type(e),e,e.__traceback__)).encode())}
def geturl(url:str):
 try:
  with urllib.request.urlopen(url,timeout=8) as r:
   b=r.read();txt=b.decode("utf-8","replace")
   try:j=json.loads(txt)
   except Exception:j=None
   return {"url":url,"status":r.status,"ok":200<=r.status<300,"body_sha256":hb(b),"json":j,"text_sha256":None if j is not None else hs(txt)}
 except Exception as e:return {"url":url,"ok":False,"error":exc(e)}
def loadmod(path:Path,name:str):
 spec=importlib.util.spec_from_file_location(name,path)
 if not spec or not spec.loader:raise ImportError(path)
 mod=importlib.util.module_from_spec(spec);sys.modules[name]=mod;spec.loader.exec_module(mod);return mod

def dependency_inventory():
 rows=[]
 for name in ("aicomp_sdk","torch","transformers","llama_cpp","openai","httpx"):
  try:
   m=importlib.import_module(name);rows.append({"package":name,"import_ok":True,"version":getattr(m,"__version__",None),"module_file":getattr(m,"__file__",None)})
  except Exception as e:rows.append({"package":name,"import_ok":False,"version":None,"error_type":type(e).__name__})
 return rows

def decision_info(d:Any):
 call=getattr(d,"call",None);args=dict(getattr(call,"arguments",{}) or {}) if call else None
 return {"decision_type":f"{type(d).__module__}.{type(d).__qualname__}","decision_sha256":hs(d),"response_side_tool_call_candidate_present":call is not None,"call_id_sha256":hs(getattr(call,"call_id","")) if call else None,"tool_name":getattr(call,"tool_name",None) if call else None,"arguments_shape":sorted(args) if args is not None else None,"arguments_sha256":hb(json.dumps(args,sort_keys=True,default=str).encode()) if args is not None else None,"adapter_parse_status":"CANONICAL_TOOLCALL_DECISION" if call else "FINAL_OR_OTHER_DECISION"}

def main():
 ap=argparse.ArgumentParser(description="EX5.0 GPT-OSS server and benign decision preflight");ap.add_argument("--project-root",required=True,type=Path);ap.add_argument("--out-root",type=Path,default=Path(r"C:\x_ai_logs\Exfil"));ap.add_argument("--server-url",default="http://127.0.0.1:8080");ap.add_argument("--pipeline",type=Path);ap.add_argument("--model-path",type=Path);ap.add_argument("--model-id");ap.add_argument("--debug-file",type=Path);ap.add_argument("--run-id")
 a=ap.parse_args();root=a.project_root.resolve();run=a.run_id or rid();out=a.out_root.resolve()/"EX5_0_gpt_oss_backend_benign_decision_preflight"/f"run_{run}";pipeline=(a.pipeline or root/"benign_pipeline_v6.py").resolve()
 if out.exists():ap.error(f"Refusing to overwrite: {out}")
 out.mkdir(parents=True);deps=dependency_inventory();health=geturl(a.server_url.rstrip("/")+"/health");models=geturl(a.server_url.rstrip("/")+"/v1/models");debug=(a.debug_file or out/f"ex5_0_{run}_agent_debug.jsonl").resolve();backend_error=None;agent_error=None;decision_error=None;factory_meta=None;agent=None;decision=None
 try:
  if health.get("ok") and models.get("ok") and pipeline.is_file():
   pipe=loadmod(pipeline,"ex5_0_pipeline");factory_fn=getattr(pipe,"make_agent_factory",None) or getattr(pipe,"build_agent_factory",None)
   if factory_fn is None:raise RuntimeError("No supported agent factory in pipeline")
   factory=factory_fn(backend_kind="server",model_family="gpt_oss",model_path=str(a.model_path) if a.model_path else None,server_url=a.server_url,debug_sink_path=debug);factory_meta={"pipeline":str(pipeline),"pipeline_sha256":hf(pipeline),"factory_symbol":f"{factory_fn.__module__}.{factory_fn.__qualname__}","factory_signature":str(inspect.signature(factory_fn)),"factory_return_type":type(factory).__name__};agent=factory()
  else:
   # Exact SDK fallback only when no project pipeline is available and server is healthy.
   if not health.get("ok") or not models.get("ok"):raise RuntimeError("Model server preflight failed")
   if a.model_path:os.environ["GPT_OSS_MODEL_PATH"]=str(a.model_path)
   if a.model_id:os.environ["GPT_OSS_MODEL_ID"]=a.model_id
   fm=importlib.import_module("aicomp_sdk.agents.factory");bf=fm.build_agent_factory;factory=bf("gpt_oss");factory_meta={"factory_symbol":f"{bf.__module__}.{bf.__qualname__}","factory_signature":str(inspect.signature(bf)),"factory_return_type":type(factory).__name__};agent=factory()
 except Exception as e:backend_error=exc(e)
 if agent is not None:
  try:
   types=importlib.import_module("aicomp_sdk.agents.types");AgentToolSpec=types.AgentToolSpec
   spec=AgentToolSpec(name="fs.read",description="Read a local file",parameters_json_schema={"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":False})
   # RuntimeHistory is list-like in the validated SDK seam; a plain empty history plus user text is unsupported.
   # Prefer the SDK history class if exposed.
   try:
    histmod=importlib.import_module("aicomp_sdk.agents.history");RuntimeHistory=histmod.RuntimeHistory;history=RuntimeHistory()
    for method in ("add_user","append_user","add_user_message"):
     if hasattr(history,method):getattr(history,method)(BENIGN_PROMPT);break
   except Exception:history=[{"role":"user","content":BENIGN_PROMPT}]
   decision=agent.next_action(history=history,tools=(spec,))
  except Exception as e:decision_error=exc(e)
 model_identity={"model_path_exists":bool(a.model_path and a.model_path.exists()),"model_path_is_file":bool(a.model_path and a.model_path.is_file()),"model_size_bytes":a.model_path.stat().st_size if a.model_path and a.model_path.is_file() else None,"model_sha256":hf(a.model_path.resolve()) if a.model_path and a.model_path.is_file() else None,"model_suffix":a.model_path.suffix.lower() if a.model_path else None,"model_id":a.model_id}
 dinfo=decision_info(decision) if decision is not None else None;decision_gates={"server_health_passed":health.get("ok") is True,"server_models_passed":models.get("ok") is True,"backend_initialized":backend_error is None and agent is not None,"agent_initialized":agent is not None,"benign_next_action_completed":decision is not None,"canonical_decision_returned":bool(dinfo and dinfo["decision_type"]),"benign_tool_call_candidate_present":bool(dinfo and dinfo["response_side_tool_call_candidate_present"]),"benign_tool_name_is_fs_read":bool(dinfo and dinfo["tool_name"]=="fs.read"),"prompt_optimization_used":False,"attack_optimization_authorized":False}
 raw={"schema":"EX5_0_V5_01","version":VERSION,"run_id":run,"generated_utc":iso(),"method":{"prompt_frozen":True,"security_prompt_used":False,"protected_source_used":False,"sink_used":False,"guardrail_used":False,"raw_model_response_capture":"debug_file_if_backend_supports_it"},"benign_prompt_sha256":hs(BENIGN_PROMPT),"model_identity":model_identity,"server":{"health":health,"models":models},"dependency_inventory":deps,"factory":factory_meta,"agent_type":f"{type(agent).__module__}.{type(agent).__qualname__}" if agent else None,"backend_error":backend_error,"decision_error":decision_error,"canonical_decision":dinfo,"debug_file":str(debug) if debug.exists() else None,"debug_file_sha256":hf(debug) if debug.exists() else None,"runner_sha256":hf(Path(__file__).resolve()),"decision":decision_gates}
 names={"raw":f"ex5_0_{run}_raw.json","deps":f"ex5_0_{run}_dependencies.csv","summary":f"ex5_0_{run}_summary.md","manifest":f"ex5_0_{run}_manifest.csv"};dump(out/names["raw"],raw);csvout(out/names["deps"],["package","import_ok","version","module_file","error_type"],deps)
 with (out/names["summary"]).open("x",encoding="utf-8") as f:f.write("# EX5.0 GPT-OSS Backend and Benign Decision Preflight\n\n"+"\n".join(f"- {k}: **{v}**" for k,v in decision_gates.items())+"\n\nBenign backend/adapter preflight only. No protected source, sink, attack prompt, guardrail comparison, hosted parity, or network-delivery claim.\n")
 man=[]
 for p in sorted(out.iterdir()):
  if p.is_file() and p.name!=names["manifest"]:man.append({"artifact":p.name,"size_bytes":p.stat().st_size,"sha256":hf(p)})
 csvout(out/names["manifest"],["artifact","size_bytes","sha256"],man);print(f"Evidence package: {out}");print(json.dumps(decision_gates,indent=2));required=["server_health_passed","server_models_passed","backend_initialized","agent_initialized","benign_next_action_completed","canonical_decision_returned","benign_tool_call_candidate_present","benign_tool_name_is_fs_read"];return 0 if all(decision_gates[k] for k in required) else 2
if __name__=="__main__":raise SystemExit(main())
