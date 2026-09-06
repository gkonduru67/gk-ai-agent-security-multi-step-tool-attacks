#!/usr/bin/env python3
r"""EX2.2 local egress-record shape and exact effect identity preflight v2.20.

Runs one benign known-good http.post against a temporary fixture copy, inspects
the resulting local egress record generically, and records only structural data
and SHA-256 values. No model, agent, guardrail, notebook, Gym, hosted evaluator,
network-delivery claim, protected value, or packaged-fixture write is involved.
All evidence is written only under logs-root.
"""
from __future__ import annotations
import argparse, csv, dataclasses, datetime as dt, hashlib, json, shutil, sys, tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

VERSION="EX2_2_EGRESS_RECORD_SHAPE_AND_EXACT_EFFECT_IDENTITY_v2.20"

def shab(v:bytes)->str:return hashlib.sha256(v).hexdigest().upper()
def shas(v:Any)->str:return shab(str(v).encode("utf-8"))
def shaf(p:Path)->str:
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest().upper()
def rid()->str:return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
def iso()->str:return dt.datetime.now(dt.timezone.utc).isoformat()
def dump(p:Path,x:Any):
 with p.open("x",encoding="utf-8") as f:json.dump(x,f,indent=2,sort_keys=True,ensure_ascii=False);f.write("\n")
def csvout(p:Path,fields:list[str],rows:list[dict[str,Any]]):
 with p.open("x",encoding="utf-8-sig",newline="") as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore");w.writeheader();w.writerows(rows)
def fixtures_hash(root:Path)->dict[str,str]:return {str(p.relative_to(root)).replace("\\","/"):shaf(p) for p in sorted(root.rglob("*")) if p.is_file()}

def get_egress(suite:Any):
 fn=getattr(suite,"get_egress",None)
 if callable(fn):return list(fn())
 for n in ("_state","state"):
  try:return list(getattr(getattr(suite,n),"egress_sink"))
  except Exception:pass
 raise RuntimeError("No observable egress collection")

def structure(obj:Any)->dict[str,Any]:
 r={"record_type":f"{type(obj).__module__}.{type(obj).__qualname__}","is_mapping":isinstance(obj,Mapping),"is_dataclass":dataclasses.is_dataclass(obj),"is_sequence":isinstance(obj,(list,tuple)),"fields":[],"public_attributes":[],"sequence_length":len(obj) if isinstance(obj,(list,tuple)) else None}
 if isinstance(obj,Mapping):r["fields"]=sorted(str(k) for k in obj.keys())
 elif dataclasses.is_dataclass(obj):r["fields"]=[f.name for f in dataclasses.fields(obj)]
 elif hasattr(obj,"_fields"):r["fields"]=[str(x) for x in getattr(obj,"_fields")]
 if not isinstance(obj,(str,bytes,int,float,bool,type(None),Mapping,list,tuple)):
  for n in sorted(x for x in dir(obj) if not x.startswith("_")):
   try:v=getattr(obj,n)
   except Exception:continue
   if not callable(v):r["public_attributes"].append(n)
 return r

def value_from(obj:Any,names:tuple[str,...],positions:tuple[int,...])->tuple[Any,str|None]:
 if isinstance(obj,Mapping):
  for n in names:
   if n in obj:return obj[n],f"mapping:{n}"
 if dataclasses.is_dataclass(obj) or hasattr(obj,"__dict__") or hasattr(obj,"_fields"):
  for n in names:
   if hasattr(obj,n):return getattr(obj,n),f"attribute:{n}"
 if isinstance(obj,(list,tuple)):
  for i in positions:
   if len(obj)>i:return obj[i],f"sequence:{i}"
 return None,None

def main()->int:
 ap=argparse.ArgumentParser(description="EX2.2 exact local egress-effect identity")
 ap.add_argument("--project-root",required=True,type=Path);ap.add_argument("--fixtures-root",type=Path);ap.add_argument("--logs-root",type=Path,default=Path(r"C:\x_ai_logs\Exfil"));ap.add_argument("--run-id")
 a=ap.parse_args();project=a.project_root.resolve();fixtures=(a.fixtures_root or project/"aicomp_sdk"/"fixtures").resolve();run=a.run_id or rid();out=a.logs_root.resolve()/"EX2_2_egress_record_exact_effect_identity"/f"run_{run}"
 if not (project/"aicomp_sdk").is_dir():ap.error("project-root must contain aicomp_sdk")
 if not fixtures.is_dir():ap.error(f"fixtures root not found: {fixtures}")
 if out.exists():ap.error(f"Refusing to overwrite: {out}")
 out.mkdir(parents=True);before=fixtures_hash(fixtures);sys.path.insert(0,str(project));from aicomp_sdk.core.tools.suite import ToolSuite
 url="https://example.invalid/ex2-2";data="EX2_2_BENIGN_EFFECT_MARKER_"+run
 raw={"schema":"EX2_2_PREFLIGHT_V2_20","version":VERSION,"run_id":run,"generated_utc":iso(),"method":{"model_used":False,"agent_used":False,"guardrail_used":False,"network_delivery_claimed":False,"packaged_fixture_write":False,"raw_payload_serialized":False},"expected":{"url_sha256":shas(url),"data_sha256":shas(data),"url_length":len(url),"data_length":len(data)}}
 with tempfile.TemporaryDirectory(prefix="ex2_2_") as td:
  copied=Path(td)/"fixtures";shutil.copytree(fixtures,copied);suite=ToolSuite(copied,isolate_fs=True);before_e=get_egress(suite);ok,output,error=suite.call("http.post",{"url":url,"data":data});after_e=get_egress(suite)
  rec=after_e[-1] if len(after_e)==len(before_e)+1 else None;shape=structure(rec) if rec is not None else None
  stored_url,url_locator=value_from(rec,("url","uri","endpoint","destination"),(0,)) if rec is not None else (None,None)
  stored_data,data_locator=value_from(rec,("data","payload","body","content"),(1,)) if rec is not None else (None,None)
  obs={"tool_returned":True,"tool_ok":bool(ok),"tool_error":error,"tool_output_sha256":shas(output),"egress_before_count":len(before_e),"egress_after_count":len(after_e),"egress_delta":len(after_e)-len(before_e),"record_shape":shape,"url_locator":url_locator,"data_locator":data_locator,"stored_url_sha256":shas(stored_url) if stored_url is not None else None,"stored_data_sha256":shas(stored_data) if stored_data is not None else None,"stored_url_length":len(str(stored_url)) if stored_url is not None else None,"stored_data_length":len(str(stored_data)) if stored_data is not None else None,"url_match":stored_url==url,"data_match":stored_data==data}
  before_reset=len(after_e);suite.reset(0);after_reset=len(get_egress(suite));obs["reset_before_count"]=before_reset;obs["reset_after_count"]=after_reset;obs["reset_passed"]=before_reset>0 and after_reset==0;raw["observation"]=obs
 after=fixtures_hash(fixtures);unchanged=before==after
 d={"http_post_success":raw["observation"]["tool_ok"] is True,"egress_entry_created":raw["observation"]["egress_delta"]==1,"egress_record_shape_captured":raw["observation"]["record_shape"] is not None,"exact_url_identity_passed":raw["observation"]["url_match"] is True,"exact_data_identity_passed":raw["observation"]["data_match"] is True,"nonempty_reset_passed":raw["observation"]["reset_passed"] is True,"packaged_fixtures_unchanged":unchanged,"attack_optimization_authorized":False};raw["packaged_fixtures_unchanged"]=unchanged;raw["decision"]=d
 names={"raw":f"ex2_2_{run}_raw.json","effect":f"ex2_2_{run}_effect.csv","summary":f"ex2_2_{run}_summary.md","manifest":f"ex2_2_{run}_manifest.csv"};dump(out/names["raw"],raw)
 o=raw["observation"];csvout(out/names["effect"],["record_type","fields","public_attributes","is_mapping","is_dataclass","is_sequence","sequence_length","url_locator","data_locator","stored_url_sha256","expected_url_sha256","url_match","stored_data_sha256","expected_data_sha256","data_match","egress_before_count","egress_after_count","egress_delta"],[{"record_type":o["record_shape"].get("record_type") if o["record_shape"] else None,"fields":json.dumps(o["record_shape"].get("fields",[]) if o["record_shape"] else []),"public_attributes":json.dumps(o["record_shape"].get("public_attributes",[]) if o["record_shape"] else []),"is_mapping":o["record_shape"].get("is_mapping") if o["record_shape"] else None,"is_dataclass":o["record_shape"].get("is_dataclass") if o["record_shape"] else None,"is_sequence":o["record_shape"].get("is_sequence") if o["record_shape"] else None,"sequence_length":o["record_shape"].get("sequence_length") if o["record_shape"] else None,"url_locator":o["url_locator"],"data_locator":o["data_locator"],"stored_url_sha256":o["stored_url_sha256"],"expected_url_sha256":raw["expected"]["url_sha256"],"url_match":o["url_match"],"stored_data_sha256":o["stored_data_sha256"],"expected_data_sha256":raw["expected"]["data_sha256"],"data_match":o["data_match"],"egress_before_count":o["egress_before_count"],"egress_after_count":o["egress_after_count"],"egress_delta":o["egress_delta"]}])
 with (out/names["summary"]).open("x",encoding="utf-8") as f:f.write("# EX2.2 Egress Record Shape and Exact Effect Identity\n\n"+"\n".join(f"- {k}: **{v}**" for k,v in d.items())+"\n\nLocal state identity only. No network-delivery, agent, guardrail, or hosted-parity claim.\n")
 man=[]
 for p in sorted(out.iterdir()):
  if p.is_file() and p.name!=names["manifest"]:man.append({"artifact":p.name,"size_bytes":p.stat().st_size,"sha256":shaf(p)})
 csvout(out/names["manifest"],["artifact","size_bytes","sha256"],man);print(f"Evidence package: {out}");print(json.dumps(d,indent=2));required=["http_post_success","egress_entry_created","egress_record_shape_captured","exact_url_identity_passed","exact_data_identity_passed","nonempty_reset_passed","packaged_fixtures_unchanged"];return 0 if all(d[k] for k in required) else 2
if __name__=="__main__":raise SystemExit(main())
