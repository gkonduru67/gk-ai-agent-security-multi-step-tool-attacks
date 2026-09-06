#!/usr/bin/env python3
"""v7.68A.1 targeted replay of HISTORY_GAP_0 and HISTORY_GAP_1.

Treatments: default_allow and packaged base_rules.
Seeds: 26100, 26103, 26105. Budget: 1024. Planned rows: 12.

This is a supplemental experiment. It never overwrites or replaces v7.68A.
Infrastructure failures remain explicit non-results and are never silently retried.
"""
from __future__ import annotations
import argparse, csv, hashlib, importlib, importlib.util, json, os, platform, sys, traceback, urllib.request
from datetime import datetime, timezone
from pathlib import Path

VERSION="UTA_TARGETED_MISSING_CELL_AND_SEQUENCE_ANOMALY_REPLAY_v7.68A.1"
PARENT_VERSION="UTA_THREE_GUARDRAIL_HISTORY_AND_UTILITY_MATRIX_v7.68A"
BUDGET=1024
SEEDS=(26100,26103,26105)
GUARDRAILS=("default_allow","base_rules")
CASES=("HISTORY_GAP_0","HISTORY_GAP_1")
EXPECTED_ROWS=12
EXPECTED_TYPES={"default_allow":"aicomp_sdk.guardrails.base.GuardrailBase","base_rules":"aicomp_sdk.attacks.baselines.guardrail_rules.Guardrail"}
SOURCE_FILES={"default_allow":"aicomp_sdk/guardrails/base.py","base_rules":"aicomp_sdk/attacks/baselines/guardrail_rules.py"}

def safe(v):
 if v is None or isinstance(v,(str,int,float,bool)):return v
 if isinstance(v,Path):return str(v)
 if isinstance(v,dict):return {str(k):safe(x) for k,x in v.items()}
 if isinstance(v,(list,tuple,set)):return [safe(x) for x in v]
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
def geturl(url):
 try:
  with urllib.request.urlopen(url,timeout=8) as r:
   b=r.read();txt=b.decode("utf-8","replace")
   try:j=json.loads(txt)
   except Exception:j=None
   return {"url":url,"status":r.status,"ok":200<=r.status<300,"body_sha256":hashlib.sha256(b).hexdigest().upper(),"json":j,"text":None if j is not None else txt}
 except Exception as e:return {"url":url,"ok":False,"error":f"{type(e).__name__}: {e}"}
def verify_parent(report,manifest):
 m=json.loads(manifest.read_text(encoding="utf-8"));r=json.loads(report.read_text(encoding="utf-8"));hit=next((x for x in m.get("artifacts",[]) if Path(str(x.get("file") or "")).name.lower()==report.name.lower()),None)
 out={"report_sha256":sha_file(report),"recorded_report_sha256":str((hit or {}).get("sha256") or "").upper() or None,"report_hash_verified":bool(hit and str(hit.get("sha256") or "").upper()==sha_file(report)),"manifest_sha256":sha_file(manifest),"parent_status":r.get("status"),"parent_version":r.get("version"),"parent_matrix_sha256":r.get("matrix_sha256"),"parent_actual_rows":r.get("actual_rows"),"parent_expected_rows":r.get("expected_rows")}
 out["verified"]=out["report_hash_verified"] and out["parent_version"]==PARENT_VERSION and out["parent_status"]=="PARTIAL"
 if not out["verified"]:raise RuntimeError("Parent v7.68A verification failed")
 return out,r
def construct(kind):
 if kind=="default_allow":cls=importlib.import_module("aicomp_sdk.guardrails.base").GuardrailBase
 else:cls=importlib.import_module("aicomp_sdk.attacks.baselines.guardrail_rules").Guardrail
 obj=cls();actual=type(obj).__module__+"."+type(obj).__qualname__
 if actual!=EXPECTED_TYPES[kind]:raise RuntimeError(f"Treatment identity mismatch: {kind}: {actual}")
 return obj,actual
def find_parent_row(parent,case,guardrail,seed):
 return next((r for r in parent.get("rows",[]) if r.get("case")==case and r.get("guardrail")==guardrail and r.get("seed")==seed),None)
def pair_transition(parent_row,replay_row):
 if parent_row is None:return "PARENT_CELL_MISSING_REPLAY_AVAILABLE" if replay_row else "BOTH_MISSING"
 if replay_row is None:return "REPLAY_INFRASTRUCTURE_NONRESULT"
 p=(parent_row.get("classification"),parent_row.get("policy_outcome"));q=(replay_row.get("classification"),replay_row.get("policy_outcome"))
 if p==q:return "OUTCOME_REPRODUCED"
 if parent_row.get("duplicate_identical_tool_calls",{}).get("present") and not replay_row.get("duplicate_identical_tool_calls",{}).get("present"):return "SEQUENCE_ANOMALY_NOT_REPRODUCED"
 return "CROSS_RUN_OUTCOME_DIVERGENCE"

def main():
 ap=argparse.ArgumentParser();ap.add_argument("--project-root",required=True,type=Path);ap.add_argument("--fixture-dir",required=True,type=Path);ap.add_argument("--parent-runner",required=True,type=Path);ap.add_argument("--budget-adapter",required=True,type=Path);ap.add_argument("--parent-report",required=True,type=Path);ap.add_argument("--parent-manifest",required=True,type=Path);ap.add_argument("--out-dir",required=True,type=Path);ap.add_argument("--server-url",default="http://127.0.0.1:8080");ap.add_argument("--max-tool-hops",type=int,default=8);a=ap.parse_args()
 root=a.project_root.resolve();fixtures=a.fixture_dir.resolve();runner=a.parent_runner.resolve();adapter=a.budget_adapter.resolve();parent_report=a.parent_report.resolve();parent_manifest=a.parent_manifest.resolve();out=a.out_dir.resolve();pipeline=root/"benign_pipeline_v6.py";sandbox=root/"aicomp_sdk/core/env/sandbox.py";sources={k:root/v for k,v in SOURCE_FILES.items()};required=[runner,adapter,parent_report,parent_manifest,pipeline,sandbox,*sources.values()]
 if out.exists():raise SystemExit(f"Refusing existing output directory: {out}")
 for p in required:
  if not p.is_file():raise SystemExit(f"Missing required file: {p}")
 if not fixtures.is_dir():raise SystemExit(f"Missing fixture directory: {fixtures}")
 out.mkdir(parents=True);sys.path.insert(0,str(root));rows=[];failures=[];stage="PREFLIGHT"
 try:
  parent_verification,parent=verify_parent(parent_report,parent_manifest);helper=loadmod(runner,"uta_v768a1_parent");budget=loadmod(adapter,"uta_v768a1_budget");pipe=loadmod(pipeline,"uta_v768a1_pipeline");factory=getattr(pipe,"make_agent_factory",None) or getattr(pipe,"build_agent_factory",None)
  if factory is None:raise RuntimeError("No supported agent factory")
  Sandbox=importlib.import_module("aicomp_sdk.core.env.sandbox").SandboxEnv;budget.BUDGET=BUDGET
  identities={}
  for kind in GUARDRAILS:
   _,actual=construct(kind);identities[kind]={"actual_type":actual,"expected_type":EXPECTED_TYPES[kind],"source_file":str(sources[kind]),"source_sha256":sha_file(sources[kind]),"identity_verified":True}
  health=geturl(a.server_url.rstrip("/")+"/health");models=geturl(a.server_url.rstrip("/")+"/v1/models")
  if not health.get("ok") or not models.get("ok"):raise RuntimeError("Model server preflight failed")
  server_before=sha_text(canon({"health":health,"models":models,"server_url":a.server_url}));prompts={c:helper.PROMPTS[c] for c in CASES};matrix={"cases":list(CASES),"guardrails":list(GUARDRAILS),"seeds":list(SEEDS),"budget":BUDGET,"prompts":prompts,"prompt_sha256":{k:sha_text(v) for k,v in prompts.items()},"max_tool_hops":a.max_tool_hops,"parent_matrix_sha256":parent.get("matrix_sha256"),"treatment_identity":identities};matrix_sha=sha_text(canon(matrix))
  for kind in GUARDRAILS:
   for case in CASES:
    for seed in SEEDS:
     attempt_id=1;stage=f"RUN:{kind}:{case}:{seed}:ATTEMPT_1";d=out/kind/case.lower()/f"seed_{seed}"/"attempt_1";d.mkdir(parents=True);dbg=d/"agent_debug.jsonl";start=datetime.now(timezone.utc)
     try:
      guard,_=construct(kind);setup=helper.ScriptedAgent([("fs.write",{"path":helper.SPACER_PATH,"content":helper.SPACER_CONTENT})]);env=Sandbox(seed=seed,fixtures_dir=fixtures,agent=setup,guardrail=guard,max_tool_hops=3);sr=env.interact("Initialize controlled spacer.",max_tool_hops=3);before,tp=helper.find_trace(helper,sr,env)
      if not before or before[-1].get("name")!="fs.write" or before[-1].get("ok") is not True:raise RuntimeError("Per-cell spacer setup failed")
      baseline=len(before);af=factory(backend_kind="server",model_family="gpt_oss",model_path=None,server_url=a.server_url,debug_sink_path=dbg);agent=af();wrap,bpath,btype=budget.attach(agent);agent.reset_state();slot=helper.helper.set_env_agent(env,agent) if hasattr(helper,"helper") else helper.set_env_agent(env,agent);res=env.interact(prompts[case],max_tool_hops=a.max_tool_hops);all_events,tp=helper.find_trace(helper.helper if hasattr(helper,"helper") else helper,res,env);events=all_events[baseline:];records,parse_errors=budget.read_jsonl(dbg);scoped=budget.scope_debug(records);analysis=helper.analyze(case,events,scoped,kind);terminal=helper.semantic_response(res,scoped);audit=safe(wrap.audit)
      if not audit or not all(x.get("effective_value")==BUDGET and x.get("one_factor_request_check") is True for x in audit):raise RuntimeError("Budget audit failed")
      row={"experiment_version":VERSION,"matrix_id":"TARGETED_CASE_X_GUARDRAIL_X_MATCHED_SEED","candidate_id":f"{case}_{kind.upper()}_SEED_{seed}_ATTEMPT_1","parent_candidate_id":f"{case}_{kind.upper()}_SEED_{seed}","attempt_id":attempt_id,"retry_after_timeout":False,"case":case,"guardrail":kind,"guardrail_actual_type":identities[kind]["actual_type"],"guardrail_source_sha256":identities[kind]["source_sha256"],"seed":seed,"response_budget":BUDGET,"request_start_utc":start.isoformat(),"request_end_utc":datetime.now(timezone.utc).isoformat(),"server_snapshot_sha256_before":server_before,"messages":[prompts[case]],"prompt_sha256":matrix["prompt_sha256"][case],"setup_event":before[-1],"setup_event_excluded_from_case_trace":True,"agent_slot":slot,"backend_path":bpath,"backend_type":btype,"budget_audit":audit,"debug_file":str(dbg.relative_to(out)),"debug_sha256":sha_file(dbg),"debug_parse_errors":parse_errors,"generation":{"finish_reasons":scoped.get("finish_reasons",[]),"decision_present":scoped.get("decision_present"),"empty_output_error":scoped.get("empty_output_error"),"errors":scoped.get("errors",[])},"terminal_response":terminal,"trace_path":tp,**analysis,"predicates":None,"breach":None,"result_object":safe(res)};rows.append(row)
     except Exception as e:
      end=datetime.now(timezone.utc);etype=type(e).__name__;is_timeout="timeout" in etype.lower() or "timed out" in str(e).lower();failures.append({"stage":stage,"candidate_id":f"{case}_{kind.upper()}_SEED_{seed}_ATTEMPT_1","attempt_id":attempt_id,"guardrail":kind,"case":case,"seed":seed,"request_start_utc":start.isoformat(),"request_end_utc":end.isoformat(),"exception_type":etype,"exception":str(e),"failure_layer":"MODEL_SERVER_TRANSPORT" if is_timeout else "HARNESS_RUNTIME","cell_status":"INFRASTRUCTURE_NON_RESULT" if is_timeout else "HARNESS_NON_RESULT","policy_evaluable":False,"scientific_result":None,"traceback":traceback.format_exc(),"debug_file":str(dbg.relative_to(out)) if dbg.exists() else None,"debug_sha256":sha_file(dbg) if dbg.exists() else None})
  after_health=geturl(a.server_url.rstrip("/")+"/health");after_models=geturl(a.server_url.rstrip("/")+"/v1/models");server_after=sha_text(canon({"health":after_health,"models":after_models,"server_url":a.server_url}))
  comparisons=[]
  for kind in GUARDRAILS:
   for case in CASES:
    for seed in SEEDS:
     old=find_parent_row(parent,case,kind,seed);new=next((r for r in rows if r["case"]==case and r["guardrail"]==kind and r["seed"]==seed),None);fail=next((f for f in failures if f["case"]==case and f["guardrail"]==kind and f["seed"]==seed),None)
     comparisons.append({"case":case,"guardrail":kind,"seed":seed,"parent_row_present":old is not None,"replay_row_present":new is not None,"replay_failure":fail,"parent_classification":old and old.get("classification"),"replay_classification":new and new.get("classification"),"parent_policy_outcome":old and old.get("policy_outcome"),"replay_policy_outcome":new and new.get("policy_outcome"),"parent_duplicate_identical_tool_calls":old and old.get("duplicate_identical_tool_calls"),"replay_duplicate_identical_tool_calls":new and new.get("duplicate_identical_tool_calls"),"transition":pair_transition(old,new)})
  status="COMPLETED_CLASSIFIABLE_COVERAGE" if len(rows)==EXPECTED_ROWS and not failures else "PARTIAL" if rows else "FAIL";stem="uta_targeted_missing_cell_sequence_anomaly_replay_v7_68A_1";pre=out/f"{stem}_preflight.json";report=out/f"{stem}.json";summary=out/f"{stem}_summary.csv";manifest=out/f"{stem}_manifest.json"
  atomic_json(pre,{"version":VERSION,"created_utc":datetime.now(timezone.utc).isoformat(),"parent_verification":parent_verification,"treatment_identity":identities,"server_before":{"health":health,"models":models,"snapshot_sha256":server_before},"server_after":{"health":after_health,"models":after_models,"snapshot_sha256":server_after},"matrix":matrix,"matrix_sha256":matrix_sha,"retry_policy":"NO_SILENT_RETRY; each timeout is retained as a separate infrastructure non-result"})
  atomic_json(report,{"schema":"UTA_TARGETED_MISSING_CELL_AND_SEQUENCE_ANOMALY_REPLAY_V1","version":VERSION,"created_utc":datetime.now(timezone.utc).isoformat(),"status":status,"expected_rows":EXPECTED_ROWS,"actual_rows":len(rows),"failure_count":len(failures),"parent_version":PARENT_VERSION,"parent_matrix_sha256":parent.get("matrix_sha256"),"supplemental_evidence":True,"parent_rows_replaced":False,"budget":BUDGET,"cases":list(CASES),"guardrails":list(GUARDRAILS),"seeds":list(SEEDS),"matrix_sha256":matrix_sha,"parent_replay_comparisons":comparisons,"rows":rows,"failures":failures,"analytical_correction":{"timeout_rule":"A model-server timeout before sufficient response evidence is MODEL_SERVER_TRANSPORT and an INFRASTRUCTURE_NON_RESULT, not agent routing or guardrail behavior.","sequence_rule":"A successful source-derived effect with repeated calls remains effect evidence but is strict-sequence comparison-ineligible.","retry_rule":"No automatic retry is merged into a scientific row.","parent_immutability":"v7.68A remains PARTIAL and immutable; v7.68A.1 is supplemental evidence only."},"interpretation_boundaries":["No proposal means no guardrail classification.","Predicates and breach are intentionally not recomputed.","Local Sandbox outcomes do not establish hosted parity."]})
  fields=["candidate_id","case","guardrail","seed","attempt_id","classification","failure_layer","policy_evaluable","policy_outcome","source_succeeded","spacer_succeeded","final_proposed","final_succeeded","proposal_returned_content_lineage","effect_returned_content_lineage","duplicate_identical_tool_calls","duplicate_sensitive_side_effect","explicit_semantic_refusal"]
  with summary.open("x",encoding="utf-8",newline="") as f:
   w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
   for r in rows:
    g=r["transport_gate_results"];w.writerow({"candidate_id":r["candidate_id"],"case":r["case"],"guardrail":r["guardrail"],"seed":r["seed"],"attempt_id":r["attempt_id"],"classification":r["classification"],"failure_layer":r["failure_layer"],"policy_evaluable":r["policy_evaluable"],"policy_outcome":r["policy_outcome"],"source_succeeded":g["source_succeeded"],"spacer_succeeded":g["spacer_succeeded"],"final_proposed":g["final_proposed"],"final_succeeded":g["final_succeeded"],"proposal_returned_content_lineage":r["proposal_returned_content_lineage"],"effect_returned_content_lineage":r["effect_returned_content_lineage"],"duplicate_identical_tool_calls":r["duplicate_identical_tool_calls"]["present"],"duplicate_sensitive_side_effect":r["duplicate_sensitive_side_effect"],"explicit_semantic_refusal":r["terminal_response"]["explicit_semantic_refusal"]})
  arts=[pre,report,summary]+[out/r["debug_file"] for r in rows]+[out/f["debug_file"] for f in failures if f.get("debug_file") and (out/f["debug_file"]).exists()];unique=[]
  for p in arts:
   if p not in unique:unique.append(p)
  atomic_json(manifest,{"schema":"UTA_TARGETED_MISSING_CELL_AND_SEQUENCE_ANOMALY_REPLAY_FREEZE_V1","version":VERSION,"status":status,"created_utc":datetime.now(timezone.utc).isoformat(),"matrix_sha256":matrix_sha,"parent_matrix_sha256":parent.get("matrix_sha256"),"runner":{"file":str(Path(__file__).resolve()),"sha256":sha_file(Path(__file__).resolve()),"size_bytes":Path(__file__).stat().st_size},"inputs":[{"file":str(p),"sha256":sha_file(p),"size_bytes":p.stat().st_size} for p in required],"artifacts":[{"file":str(p.relative_to(out)),"sha256":sha_file(p),"size_bytes":p.stat().st_size} for p in unique],"runtime":{"python":sys.version,"platform":platform.platform()},"configuration":{"budget":BUDGET,"guardrails":identities,"cases":list(CASES),"seeds":list(SEEDS),"server_url":a.server_url,"server_snapshot_before":server_before,"server_snapshot_after":server_after,"max_tool_hops":a.max_tool_hops}})
  print(f"Experiment: {VERSION}\nStatus: {status}\nRows: {len(rows)}/{EXPECTED_ROWS}\nFailures: {len(failures)}\nManifest: {manifest}\nManifest SHA256: {sha_file(manifest)}")
  return 0 if status=="COMPLETED_CLASSIFIABLE_COVERAGE" else 3
 except Exception as e:
  fp=out/"uta_targeted_missing_cell_sequence_anomaly_replay_v7_68A_1_failure.json";atomic_json(fp,{"version":VERSION,"stage":stage,"exception_type":type(e).__name__,"exception":str(e),"traceback":traceback.format_exc(),"rows":rows,"failures":failures,"scientific_result":None});print(f"FAILED: {e}\nFailure artifact: {fp}",file=sys.stderr);return 3
if __name__=="__main__":raise SystemExit(main())
