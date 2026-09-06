#!/usr/bin/env python3
"""Independent predicate and breach qualification over frozen v7.78A traces.

No GPT, guardrail, tool, Sandbox, or Gym execution occurs. The runner verifies the
frozen v7.78A report/manifest, builds a canonical predicate input from each row's
preserved ordered tool events, independently calls packaged eval_predicates() and
is_breach(), compares Sandbox/Gym recomputation, and compares Gym recomputation
with the Gym metadata retained in v7.78A.
"""
from __future__ import annotations
import argparse,csv,hashlib,importlib.util,inspect,json,os,platform,sys,traceback
from datetime import datetime,timezone
from pathlib import Path
from typing import Any

VERSION="UTA_FROZEN_TRACE_PREDICATE_BREACH_QUALIFICATION_v7.79A"
PARENT_VERSION="UTA_SANDBOX_GYM_FROZEN_PROPOSAL_PARITY_v7.78A"
EXPECTED_ROWS=48
EXPECTED_PARENT_MATRIX="51CE3A5C79178147C72A32A04A5C58CD5809A218363A6D43B4C3A61EAABB21FE"
EXPECTED_PREDICATES_SHA256="9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
ENVIRONMENTS=("SANDBOX","GYM")

def safe(v):
 if v is None or isinstance(v,(str,int,float,bool)):return v
 if isinstance(v,Path):return str(v)
 if isinstance(v,dict):return {str(k):safe(x) for k,x in v.items()}
 if isinstance(v,(list,tuple,set)):return [safe(x) for x in v]
 if hasattr(v,"value"):
  try:return safe(v.value)
  except Exception:pass
 for m in ("model_dump","to_dict"):
  if hasattr(v,m):
   try:return safe(getattr(v,m)())
   except Exception:pass
 if hasattr(v,"__dict__"):
  try:return {k:safe(x) for k,x in vars(v).items() if not k.startswith("_")}
  except Exception:pass
 return repr(v)
def canon(v):return json.dumps(safe(v),sort_keys=True,separators=(",",":"),ensure_ascii=True)
def sha_text(s):return hashlib.sha256(s.encode()).hexdigest().upper()
def sha_file(p):
 h=hashlib.sha256()
 with Path(p).open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest().upper()
def atomic_json(p,v):
 if p.exists():raise FileExistsError(f"Refusing overwrite: {p}")
 t=p.with_name(p.name+".tmp");t.write_text(json.dumps(safe(v),indent=2,ensure_ascii=True)+"\n",encoding="ascii");os.replace(t,p)
def loadmod(p,n):
 s=importlib.util.spec_from_file_location(n,p)
 if not s or not s.loader:raise ImportError(p)
 m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
def verify_parent(rp,mp):
 r=json.loads(rp.read_text(encoding="utf-8"));m=json.loads(mp.read_text(encoding="utf-8"));hit=next((x for x in m.get("artifacts",[]) if Path(str(x.get("file") or "")).name.lower()==rp.name.lower()),None)
 ok=bool(hit and str(hit.get("sha256") or "").upper()==sha_file(rp) and r.get("version")==PARENT_VERSION and r.get("status")=="COMPLETED_CLASSIFIABLE_COVERAGE" and r.get("actual_rows")==EXPECTED_ROWS and r.get("failure_count")==0 and r.get("matrix_sha256")==EXPECTED_PARENT_MATRIX and r.get("all_per_candidate_parity") is True)
 if not ok:raise RuntimeError("v7.78A parent report/manifest verification failed")
 return r,{"report":str(rp),"report_sha256":sha_file(rp),"manifest":str(mp),"manifest_sha256":sha_file(mp),"verified":True,"parent_matrix_sha256":r.get("matrix_sha256")}
def predicate_names(v):
 x=safe(v)
 if x is None:return []
 if not isinstance(x,list):x=[x]
 out=[]
 for item in x:
  if isinstance(item,str):name=item
  elif isinstance(item,dict):name=str(item.get("name") or item.get("predicate") or item.get("type") or canon(item))
  else:name=str(item)
  out.append(name)
 return sorted(out)
def canonical_trace(row):
 events=safe(row.get("ordered_tool_events") or [])
 # The preserved Gym trace is retained as a consistency source, while the official
 # recomputation input is canonicalized identically for both environments.
 gi=row.get("gym_info") if isinstance(row.get("gym_info"),dict) else None
 gym_trace=(gi or {}).get("trace") if isinstance((gi or {}).get("trace"),dict) else None
 gym_events=safe((gym_trace or {}).get("tool_events") or []) if gym_trace else None
 if row.get("environment")=="GYM" and gym_events is not None and gym_events!=events:raise RuntimeError(f"Gym metadata trace differs from preserved ordered_tool_events: {row.get('candidate_id')}")
 trace={"messages":safe((gym_trace or {}).get("messages") or []),"tool_events":events,"egress":safe((gym_trace or {}).get("egress") or [])}
 return trace,{"construction":"CANONICAL_FROM_FROZEN_ORDERED_TOOL_EVENTS","gym_metadata_trace_present":gym_trace is not None,"gym_metadata_tool_events_equal":gym_events==events if gym_events is not None else None}
def invoke_is_breach(fn,trace,preds):
 sig=inspect.signature(fn);n=len(sig.parameters)
 if n==2:return fn(trace,preds),{"signature":str(sig),"invocation":"is_breach(trace,predicates)"}
 if n==1:return fn(preds),{"signature":str(sig),"invocation":"is_breach(predicates)"}
 raise RuntimeError(f"Unsupported is_breach signature: {sig}")
def compare_environment_pairs(rows):
 keys=sorted({(r["scenario"],r["treatment"],int(r["seed"])) for r in rows})
 out=[]
 for scenario,treatment,seed in keys:
  s=next((r for r in rows if (r["scenario"],r["treatment"],int(r["seed"]),r["environment"])==(scenario,treatment,seed,"SANDBOX")),None);g=next((r for r in rows if (r["scenario"],r["treatment"],int(r["seed"]),r["environment"])==(scenario,treatment,seed,"GYM")),None)
  pred=bool(s and g and s["independent_predicate_names"]==g["independent_predicate_names"]);breach=bool(s and g and s["independent_breach"]==g["independent_breach"]);trace=bool(s and g and s["trace_sha256"]==g["trace_sha256"])
  out.append({"scenario":scenario,"treatment":treatment,"seed":seed,"sandbox_present":s is not None,"gym_present":g is not None,"trace_sha256_equal":trace,"independent_predicate_parity":pred,"independent_breach_parity":breach,"full_evaluator_parity":trace and pred and breach,"sandbox_predicates":s and s["independent_predicate_names"],"gym_predicates":g and g["independent_predicate_names"],"sandbox_breach":s and s["independent_breach"],"gym_breach":g and g["independent_breach"]})
 return out

def main():
 ap=argparse.ArgumentParser();ap.add_argument("--project-root",required=True,type=Path);ap.add_argument("--parent-report",required=True,type=Path);ap.add_argument("--parent-manifest",required=True,type=Path);ap.add_argument("--out-dir",required=True,type=Path);a=ap.parse_args()
 root=a.project_root.resolve();rp=a.parent_report.resolve();mp=a.parent_manifest.resolve();out=a.out_dir.resolve();pred_path=root/"aicomp_sdk/core/predicates.py";required=[rp,mp,pred_path]
 if out.exists():raise SystemExit(f"Refusing existing output directory: {out}")
 for p in required:
  if not p.is_file():raise SystemExit(f"Missing required file: {p}")
 out.mkdir(parents=True);sys.path.insert(0,str(root));rows=[];failures=[];stage="PREFLIGHT"
 try:
  parent,pv=verify_parent(rp,mp)
  if sha_file(pred_path)!=EXPECTED_PREDICATES_SHA256:raise RuntimeError("predicates.py hash mismatch")
  mod=loadmod(pred_path,"uta_v779_predicates");eval_fn=getattr(mod,"eval_predicates");breach_fn=getattr(mod,"is_breach")
  matrix={"source":"FROZEN_v7.78A_SANDBOX_AND_GYM_TRACES","parent_matrix_sha256":parent["matrix_sha256"],"row_ids":[r.get("candidate_id") for r in parent.get("rows",[])],"independent_functions":{"eval_predicates":str(inspect.signature(eval_fn)),"is_breach":str(inspect.signature(breach_fn))},"no_execution_replay":True,"no_GPT":True,"no_guardrail":True,"no_tool_execution":True};msha=sha_text(canon(matrix))
  if len(parent.get("rows",[]))!=EXPECTED_ROWS:raise RuntimeError("Parent row count changed")
  for src in parent["rows"]:
   stage=f"EVALUATE:{src.get('candidate_id')}"
   try:
    trace,trace_meta=canonical_trace(src);tsha=sha_text(canon(trace));pred_raw=eval_fn(trace);pred_safe=safe(pred_raw);names=predicate_names(pred_raw);breach_raw,breach_meta=invoke_is_breach(breach_fn,trace,pred_raw);breach=bool(breach_raw)
    gi=src.get("gym_info") if isinstance(src.get("gym_info"),dict) else None;stored_pred_raw=(gi or {}).get("predicates") if gi is not None else None;stored_breach=(gi or {}).get("breach") if gi is not None else None;stored_names=predicate_names(stored_pred_raw) if stored_pred_raw is not None else None
    rows.append({"experiment_version":VERSION,"candidate_id":src.get("candidate_id"),"scenario":src.get("scenario"),"treatment":src.get("treatment"),"seed":src.get("seed"),"environment":src.get("environment"),"evaluator_epoch":"LOCAL_NOT_HOSTED","source_parent_row_sha256":sha_text(canon(src)),"trace_sha256":tsha,"trace_construction":trace_meta,"canonical_trace":trace,"predicates_source_sha256":sha_file(pred_path),"eval_predicates_signature":str(inspect.signature(eval_fn)),"independent_predicates":pred_safe,"independent_predicate_names":names,"independent_predicates_sha256":sha_text(canon(pred_safe)),"is_breach_invocation":breach_meta,"independent_breach":breach,"gym_metadata_present":gi is not None,"gym_reported_predicates":safe(stored_pred_raw),"gym_reported_predicate_names":stored_names,"gym_reported_breach":stored_breach,"independent_vs_gym_predicate_match":stored_names==names if stored_names is not None else None,"independent_vs_gym_breach_match":bool(stored_breach)==breach if stored_breach is not None else None,"classification":"INDEPENDENT_RECOMPUTATION_COMPLETE","failure_layer":None})
   except Exception as e:failures.append({"stage":stage,"candidate_id":src.get("candidate_id"),"exception_type":type(e).__name__,"exception":str(e),"traceback":traceback.format_exc(),"scientific_result":None})
  pairs=compare_environment_pairs(rows);gym_rows=[r for r in rows if r["environment"]=="GYM"];gym_pred_comparable=[r for r in gym_rows if r["gym_reported_predicate_names"] is not None];gym_breach_comparable=[r for r in gym_rows if r["gym_reported_breach"] is not None]
  status="COMPLETED_CLASSIFIABLE_COVERAGE" if len(rows)==EXPECTED_ROWS and not failures else "PARTIAL" if rows else "FAIL";all_pairs=status=="COMPLETED_CLASSIFIABLE_COVERAGE" and all(p["full_evaluator_parity"] for p in pairs);gym_pred_all=bool(gym_pred_comparable) and all(r["independent_vs_gym_predicate_match"] for r in gym_pred_comparable);gym_breach_all=bool(gym_breach_comparable) and all(r["independent_vs_gym_breach_match"] for r in gym_breach_comparable)
  stem="uta_frozen_trace_predicate_breach_qualification_v7_79A";pre=out/f"{stem}_preflight.json";rep=out/f"{stem}.json";summ=out/f"{stem}_summary.csv";man=out/f"{stem}_manifest.json"
  atomic_json(pre,{"version":VERSION,"created_utc":datetime.now(timezone.utc).isoformat(),"parent_verification":pv,"predicate_source":{"file":str(pred_path),"sha256":sha_file(pred_path),"size_bytes":pred_path.stat().st_size},"function_signatures":{"eval_predicates":str(inspect.signature(eval_fn)),"is_breach":str(inspect.signature(breach_fn))},"matrix":matrix,"matrix_sha256":msha})
  atomic_json(rep,{"schema":"UTA_FROZEN_TRACE_PREDICATE_BREACH_QUALIFICATION_V1","version":VERSION,"created_utc":datetime.now(timezone.utc).isoformat(),"status":status,"expected_rows":EXPECTED_ROWS,"actual_rows":len(rows),"failure_count":len(failures),"matrix_sha256":msha,"all_environment_evaluator_parity":all_pairs,"environment_pairs":pairs,"gym_metadata_comparison":{"predicate_comparable_rows":len(gym_pred_comparable),"predicate_all_match":gym_pred_all,"breach_comparable_rows":len(gym_breach_comparable),"breach_all_match":gym_breach_all},"rows":rows,"failures":failures,"boundaries":["No GPT, Sandbox, Gym, guardrail, or tool execution occurs in this qualification.","Official packaged eval_predicates and is_breach are independently invoked on canonical traces reconstructed from frozen ordered tool events.","Gym metadata is compared but is not treated as authoritative over independent recomputation.","Local predicate and breach parity does not establish hosted evaluator parity.","A predicate result does not establish authorization correctness."]})
  fields=["candidate_id","scenario","treatment","seed","environment","trace_sha256","independent_predicate_names","independent_predicates_sha256","independent_breach","gym_metadata_present","gym_reported_predicate_names","gym_reported_breach","independent_vs_gym_predicate_match","independent_vs_gym_breach_match","classification"]
  with summ.open("x",encoding="utf-8",newline="") as f:
   w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
   for r in rows:
    rec={k:r.get(k) for k in fields};rec["independent_predicate_names"]=canon(rec["independent_predicate_names"]);rec["gym_reported_predicate_names"]=canon(rec["gym_reported_predicate_names"]) if rec["gym_reported_predicate_names"] is not None else None;w.writerow(rec)
  arts=[pre,rep,summ];atomic_json(man,{"schema":"UTA_FROZEN_TRACE_PREDICATE_BREACH_QUALIFICATION_FREEZE_V1","version":VERSION,"status":status,"created_utc":datetime.now(timezone.utc).isoformat(),"matrix_sha256":msha,"runner":{"file":str(Path(__file__).resolve()),"sha256":sha_file(Path(__file__).resolve()),"size_bytes":Path(__file__).stat().st_size},"inputs":[{"file":str(p),"sha256":sha_file(p),"size_bytes":p.stat().st_size} for p in required],"artifacts":[{"file":p.name,"sha256":sha_file(p),"size_bytes":p.stat().st_size} for p in arts],"runtime":{"python":sys.version,"platform":platform.platform()}})
  print(f"Experiment: {VERSION}\nStatus: {status}\nRows: {len(rows)}/{EXPECTED_ROWS}\nFailures: {len(failures)}\nEnvironment evaluator parity: {sum(p['full_evaluator_parity'] for p in pairs)}/{len(pairs)}\nGym predicate metadata matches: {sum(bool(r['independent_vs_gym_predicate_match']) for r in gym_pred_comparable)}/{len(gym_pred_comparable)}\nGym breach metadata matches: {sum(bool(r['independent_vs_gym_breach_match']) for r in gym_breach_comparable)}/{len(gym_breach_comparable)}\nManifest: {man}\nManifest SHA256: {sha_file(man)}");return 0 if status=="COMPLETED_CLASSIFIABLE_COVERAGE" else 3
 except Exception as e:
  fp=out/"uta_frozen_trace_predicate_breach_qualification_v7_79A_failure.json";atomic_json(fp,{"version":VERSION,"stage":stage,"exception_type":type(e).__name__,"exception":str(e),"traceback":traceback.format_exc(),"rows":rows,"failures":failures,"scientific_result":None});print(f"FAILED: {e}",file=sys.stderr);return 3
if __name__=="__main__":raise SystemExit(main())
