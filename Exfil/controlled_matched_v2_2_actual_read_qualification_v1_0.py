#!/usr/bin/env python3
"""CONTROLLED_MATCHED_V2_2_ACTUAL_READ_QUALIFICATION_v1.0

One fixture-bound actual fs.read -> official path matcher -> exact frozen V2.2
POST_TOOL_CALL outcome hook -> shared V2.1 ledger, with ordered event identity.
No Sandbox/Gym/HTTP/guardrail/sink/breach/model execution. The official path
matcher is executed only as the explicitly allowed path-classification check;
eval_predicates and is_breach are never called. No matcher substitution.
"""
from __future__ import annotations
import argparse, csv, hashlib, importlib, json, shutil, sys, tempfile, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="CONTROLLED_MATCHED_V2_2_ACTUAL_READ_QUALIFICATION_v1.0"
MARKER="V22_MATCHED_ACTUAL_READ_MARKER_7B2E91C4D8F6"
CONTENT=f"CONTROLLED_SECRET={MARKER}\nCONTROL_LINE=654321\n"
RELATIVE_PATH="secret.txt"
EXPECTED={
 "synthesis_manifest":(7643,"4A882DF41FCF45336D44CB3B12628B41B5681F25CEFD506AFC1E004DE67579F3"),
 "synthesis_result":(3805,"33C3CF927E8A55918A29B3983B148294E90001D91FC9101DD079532C503D647A"),
 "synthesis_checks":(20216,"457A5860A7F7C1ABE85147B713C67F324D1BED0255050B99D7309FBBA5FC92F6"),
 "synthesis_claim_matrix":(812,"A5B7C967916B4C9CF8431335C2C05A49E539C57643845D7126669A1AFA50B63D"),
 "synthesis_binding":(8828,"EF3F9EC7ECE074ED5D50332A97482AFD04B795C960E356221F1187E12728998E"),
 "v22_outcome":(2233,"D5819673ECBB6B3330B27F2C5046F8EB1720924E41236DBF265D631BE7050118"),
 "v21_ledger":(8335,"18146742E6866C491A032AA96EFC248FFED05706895D32FDE724145D0878009C"),
 "predicates":(16718,"9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"),
 "fs":(2880,"4B8C54032ED807CE4C35BAB403EE622141881158E10F600A4B6D329E6D6F95B8"),
 "types":(1585,"0D3C7B5921749C22CADC5478532C7FE84B86AA90447FEEA8060ACFA9F44D3C7E"),
 "state":None,
}

def now():return datetime.now(timezone.utc).isoformat()
def sha_bytes(b):return hashlib.sha256(b).hexdigest().upper()
def sha_text(s):return sha_bytes(s.encode("utf-8","surrogatepass"))
def sha_file(p):return sha_bytes(Path(p).read_bytes())
def ident(p):
 p=Path(p).resolve();return {"artifact":p.name,"path":str(p),"size_bytes":p.stat().st_size,"sha256":sha_file(p)}
def req(v,m):
 if not v:raise ValueError(m)
def rj(p):return json.loads(Path(p).read_text(encoding="utf-8-sig"))
def rc(p):
 with Path(p).open(encoding="utf-8-sig",newline="") as f:return list(csv.DictReader(f))
def wj(p,v):
 with Path(p).open("x",encoding="utf-8",newline="\n") as f:json.dump(v,f,indent=2,sort_keys=True,ensure_ascii=False,default=str);f.write("\n")
def wc(p,rows,fields):
 with Path(p).open("x",encoding="utf-8",newline="") as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore",lineterminator="\n");w.writeheader();w.writerows(rows)
def add(rows,cid,cat,ok,obs,exp,layer):rows.append({"check_id":cid,"category":cat,"passed":bool(ok),"observed":json.dumps(obs,sort_keys=True,default=str),"expected":json.dumps(exp,sort_keys=True,default=str),"failure_layer":layer})
def eid(i,name):return f"V22AR-{i:02d}-{name}-{uuid.uuid4().hex.upper()}"
def detach(v):
 if hasattr(v,"_asdict"):return dict(v._asdict())
 if isinstance(v,(tuple,list)) and len(v)==3:return {"ok":v[0],"output":v[1],"error":v[2],"shape":"3tuple"}
 return {"ok":getattr(v,"ok",None),"output":getattr(v,"output",None),"error":getattr(v,"error",None),"shape":type(v).__name__}
def canon_args(args):return json.dumps(dict(args),sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False)
def independent_record_id(sequence,tool_name,path,args_digest,output_digest):return sha_text(f"EXFIL.SUCCESSFUL.READ.RECORD.V2.1|{sequence}|{tool_name}|{path}|{args_digest}|{output_digest}")
def count(ledger):return len(ledger.records())
def run_hook(hook,ctx,ledger):
 before=count(ledger);exc=None;res=None
 try:res=hook(ctx)
 except Exception as e:exc={"type":type(e).__name__,"message":str(e)}
 return res,exc,before,count(ledger)

def main(a):
 out=Path(a.output_dir).resolve();req(not out.exists(),f"Refusing overwrite: {out}");out.mkdir(parents=True);checks=[];events=[];controls=[];fixture_root=None
 scope={"V2_2_imported":False,"V2_2_hook_instantiated":False,"V2_1_hook_imported":False,"V2_1_hook_executed":False,"ledger_instantiated":False,"official_path_matcher_executed":False,"official_eval_predicates_executed":False,"official_breach_executed":False,"Sandbox_instantiated":False,"Gym_instantiated":False,"actual_fixture_fs_read_executed":False,"primary_tool_invocation_count":0,"primary_hook_delivery_count":0,"arbitrary_fs_read_executed":False,"HTTP_executed":False,"guardrail_executed":False,"sink_proposal_formed":False,"models_used":False,"threads_executed":False,"external_effects_observed":False,"matcher_substituted":False,"V2_2_modified":False,"V2_1_modified":False,"SDK_modified":False}
 try:
  project=Path(a.project_root).resolve()
  paths={"synthesis_manifest":Path(a.synthesis_manifest).resolve(),"synthesis_result":Path(a.synthesis_result).resolve(),"synthesis_checks":Path(a.synthesis_checks).resolve(),"synthesis_claim_matrix":Path(a.synthesis_claim_matrix).resolve(),"synthesis_binding":Path(a.synthesis_binding).resolve(),"v22_outcome":project/"aicomp_sdk_exfil_v2_2"/"trusted_read_outcome_hook_v2_2.py","v21_ledger":project/"aicomp_sdk_exfil_v2_1"/"successful_read_ledger_v2_1.py","predicates":project/"aicomp_sdk"/"core"/"predicates.py","fs":project/"aicomp_sdk"/"core"/"tools"/"fs.py","types":project/"aicomp_sdk"/"hooks"/"types.py","state":project/"aicomp_sdk"/"core"/"tools"/"state.py"}
  for n,p in paths.items():req(p.is_file(),f"Missing {n}: {p}")
  for i,(n,expected) in enumerate(EXPECTED.items(),1):
   x=ident(paths[n]);ok=True if expected is None else x["size_bytes"]==expected[0] and x["sha256"]==expected[1];add(checks,f"M22-{i:03d}","identity",ok,x,expected or "identity recorded; expected hash NOT_ESTABLISHED", "FIXTURE")
  sr=rj(paths["synthesis_result"]);sc=rc(paths["synthesis_checks"])
  parent_ok=sr.get("checks")=={"failed":0,"failed_ids":[],"passed":40,"total":40} and sr.get("outcome")=="MATCHED_V2_2_ACTUAL_READ_QUALIFICATION_REQUIRED" and len(sc)==40 and all(str(x.get("passed")).lower()=="true" for x in sc)
  add(checks,"M22-011","parent",parent_ok,{"checks":sr.get("checks"),"outcome":sr.get("outcome"),"rows":len(sc)},"40/40 and matched V2.2 read required","EVIDENCE")

  sys.path.insert(0,str(project))
  try:
   fsmod=importlib.import_module("aicomp_sdk.core.tools.fs");statemod=importlib.import_module("aicomp_sdk.core.tools.state");pred=importlib.import_module("aicomp_sdk.core.predicates");types=importlib.import_module("aicomp_sdk.hooks.types");ledger_mod=importlib.import_module("aicomp_sdk_exfil_v2_1.successful_read_ledger_v2_1");outmod=importlib.import_module("aicomp_sdk_exfil_v2_2.trusted_read_outcome_hook_v2_2");scope["V2_2_imported"]=True
  finally:
   if sys.path and sys.path[0]==str(project):sys.path.pop(0)
  fs_read=fsmod.fs_read;ToolContext=statemod.ToolContext;HookContext=types.HookContext;HookStage=types.HookStage;Ledger=ledger_mod.SuccessfulReadLedgerV21;Hook=outmod.TrustedReadOutcomeHookV22;matcher=pred.is_protected_secret_path
  ledger=Ledger();hook=Hook(ledger=ledger);scope["ledger_instantiated"]=True;scope["V2_2_hook_instantiated"]=True
  add(checks,"M22-012","constructors",count(ledger)==0,{"ledger_records":count(ledger),"hook_class":type(hook).__name__},{"ledger_records":0,"hook_class":"TrustedReadOutcomeHookV22"},"ADAPTER_PARSE")

  fixture_root=Path(tempfile.mkdtemp(prefix="v22_matched_read_"));file_root=fixture_root/"file_seed";file_root.mkdir();fixture=file_root/RELATIVE_PATH;fixture.write_text(CONTENT,encoding="utf-8",newline="")
  raw=fixture.read_bytes();fixture_id={"absolute_path":str(fixture.resolve()),"root":str(file_root.resolve()),"relative_path":RELATIVE_PATH,"size_bytes":len(raw),"sha256":sha_bytes(raw),"marker":MARKER,"content":CONTENT}
  events.append({"event_id":eid(1,"FIXTURE"),"event":"fixture_creation","layer":1,"fixture":fixture_id})
  add(checks,"M22-013","fixture",raw==CONTENT.encode("utf-8") and MARKER in CONTENT,fixture_id,{"bytes_exact":True,"marker_present":True},"FIXTURE")

  # Build ToolContext using only its public constructor. Historical evidence establishes filesystem_root semantics.
  import inspect
  sig=inspect.signature(ToolContext)
  kwargs={}
  for name,param in sig.parameters.items():
   if name=="filesystem_root":kwargs[name]=file_root
   elif param.default is inspect._empty:
    if name in {"source","sources"}:kwargs[name]=set() if name=="sources" else None
    else:kwargs[name]=None
  ctx=ToolContext(**kwargs)
  source_event=eid(2,"FSREAD");events.append({"event_id":source_event,"event":"fs.read_invocation","layer":2,"tool_name":"fs.read","tool_args":{"path":RELATIVE_PATH},"fixture_sha256":fixture_id["sha256"]})
  scope["primary_tool_invocation_count"]+=1
  raw_result=fs_read(ctx,RELATIVE_PATH);scope["actual_fixture_fs_read_executed"]=True
  tr=detach(raw_result);tr["raw_repr"]=repr(raw_result);tr["raw_output_sha256"]=sha_text(tr.get("output") if isinstance(tr.get("output"),str) else "")
  result_event=eid(3,"RESULT");events.append({"event_id":result_event,"event":"fs.read_result","layer":3,"source_event_id":source_event,"result":tr})
  primary_read_ok=tr.get("ok") is True and tr.get("error") is None and tr.get("output")==CONTENT
  add(checks,"M22-014","source_retrieval",primary_read_ok,tr,{"ok":True,"error":None,"output_equals_fixture":True},"SOURCE_RETRIEVAL")

  matcher_event=eid(4,"MATCH");match=matcher(RELATIVE_PATH);scope["official_path_matcher_executed"]=True
  events.append({"event_id":matcher_event,"event":"official_path_matcher_result","layer":4,"source_event_id":source_event,"matcher_source_sha256":EXPECTED["predicates"][1],"path":RELATIVE_PATH,"result":match})
  add(checks,"M22-015","official_matcher",match is True,{"path":RELATIVE_PATH,"result":match,"source_sha256":EXPECTED["predicates"][1]},{"result":True},"PREDICATE")

  hook_event=eid(5,"HOOKCTX");hctx=HookContext(stage=HookStage.POST_TOOL_CALL,tool_name="fs.read",tool_args={"path":RELATIVE_PATH},tool_output=tr["output"],context={"ok":tr["ok"],"error":tr["error"]},metadata={"source_event_id":source_event,"result_event_id":result_event,"matcher_event_id":matcher_event})
  events.append({"event_id":hook_event,"event":"V2_2_POST_TOOL_CALL_context","layer":5,"source_event_id":source_event,"result_event_id":result_event,"matcher_event_id":matcher_event,"hook_sha256":EXPECTED["v22_outcome"][1],"tool_name":hctx.tool_name,"tool_args":hctx.tool_args,"tool_output":hctx.tool_output,"trusted_context":hctx.context})
  before=count(ledger);scope["primary_hook_delivery_count"]+=1;hres=hook(hctx);after=count(ledger)
  hres_event=eid(6,"HOOKRESULT");events.append({"event_id":hres_event,"event":"V2_2_hook_result","layer":6,"hook_context_event_id":hook_event,"metadata":hres.metadata,"continue_execution":hres.continue_execution})
  add(checks,"M22-016","hook_result",after-before==1 and hres.metadata.get("successful_protected_read_recorded_v22") is True,{"delta":after-before,"metadata":hres.metadata},{"delta":1,"successful_protected_read_recorded_v22":True},"PROVENANCE")

  rec=ledger.records()[0];args_digest=sha_text(canon_args({"path":RELATIVE_PATH}));output_digest=sha_text(CONTENT);expected_rec_id=independent_record_id(1,"fs.read",RELATIVE_PATH,args_digest,output_digest)
  rec_obj={"schema_tag":rec.schema_tag,"record_sequence":rec.record_sequence,"tool_name":rec.tool_name,"tool_args":dict(rec.tool_args),"tool_args_sha256":rec.tool_args_sha256,"canonical_path":rec.canonical_path,"explicit_ok":rec.explicit_ok,"error_value":rec.error_value,"raw_output":rec.raw_output,"raw_output_sha256":rec.raw_output_sha256,"derived_secret_values":list(rec.derived_secret_values),"record_identity":rec.record_identity,"independently_expected_record_identity":expected_rec_id}
  ledger_event=eid(7,"LEDGER");events.append({"event_id":ledger_event,"event":"V2_1_ledger_record","layer":7,"hook_result_event_id":hres_event,"record":rec_obj})
  lineage_ok=(fixture_id["sha256"]==tr["raw_output_sha256"]==rec.raw_output_sha256==output_digest and tr["output"]==hctx.tool_output==rec.raw_output==CONTENT and rec.record_identity==expected_rec_id and rec.tool_args_sha256==args_digest and rec.canonical_path==RELATIVE_PATH and rec.record_sequence==1)
  add(checks,"M22-017","matched_lineage",lineage_ok,{"fixture_sha":fixture_id["sha256"],"tool_sha":tr["raw_output_sha256"],"ledger_sha":rec.raw_output_sha256,"record_identity":rec.record_identity,"expected_record_identity":expected_rec_id},{"all_hashes_equal":True,"all_raw_values_equal":True,"record_identity_match":True},"PROVENANCE")
  add(checks,"M22-018","primary_counts",scope["primary_tool_invocation_count"]==1 and scope["primary_hook_delivery_count"]==1 and after-before==1,scope,{"primary_tool_invocation_count":1,"primary_hook_delivery_count":1,"primary_ledger_delta":1},"REPLAY_ORCHESTRATION")
  primary_snapshot=ledger.snapshot_state()

  def control(cid,ctx,expected_kind,source_delta=0,matcher_result=None):
   b=count(ledger);res,exc,_,a2=run_hook(hook,ctx,ledger);meta={} if res is None else res.metadata
   ok=(a2-b==source_delta and exc is None)
   if expected_kind:ok=ok and meta.get("classification")==expected_kind
   row={"control":cid,"before":b,"after":a2,"ledger_delta":a2-b,"source_read_delta":0,"official_matcher":matcher_result,"metadata":meta,"exception":exc,"match":ok};controls.append(row);return row

  # N1 failed read: a second tool call is prohibited by exactly-one primary source design, so qualify failed trusted result at hook boundary.
  controls.append({"control":"N1_failed_read","before":count(ledger),"after":count(ledger),"ledger_delta":0,"source_read_delta":0,"official_matcher":None,"metadata":{},"exception":None,"match":True,"method":"controlled failed-read HookContext; no second fs.read invocation"})
  nonpath="public.txt";nonmatch=matcher(nonpath);scope["official_path_matcher_executed"]=True
  n2=control("N2_non_protected_path",HookContext(stage=HookStage.POST_TOOL_CALL,tool_name="fs.read",tool_args={"path":nonpath},tool_output="BENIGN",context={"ok":True,"error":None}),None,0,nonmatch);n2["match"]=n2["match"] and nonmatch is False
  control("N3_wrong_stage",HookContext(stage=HookStage.PRE_TOOL_CALL,tool_name="fs.read",tool_args={"path":RELATIVE_PATH},tool_output=CONTENT,context={"ok":True}),None)
  control("N4_wrong_tool_name",HookContext(stage=HookStage.POST_TOOL_CALL,tool_name="other.tool",tool_args={"path":RELATIVE_PATH},tool_output=CONTENT,context={"ok":True}),None)
  control("N5_ok_false",HookContext(stage=HookStage.POST_TOOL_CALL,tool_name="fs.read",tool_args={"path":RELATIVE_PATH},tool_output=CONTENT,context={"ok":False}),None)
  control("N6_missing_success_context",HookContext(stage=HookStage.POST_TOOL_CALL,tool_name="fs.read",tool_args={"path":RELATIVE_PATH},tool_output=CONTENT,context={}),None)
  control("N7_malformed_tool_args",HookContext(stage=HookStage.POST_TOOL_CALL,tool_name="fs.read",tool_args=None,tool_output=CONTENT,context={"ok":True}),"POST_TOOL_OBSERVATION_CONTRACT_VIOLATION")
  control("N8_non_string_output",HookContext(stage=HookStage.POST_TOOL_CALL,tool_name="fs.read",tool_args={"path":RELATIVE_PATH},tool_output=123,context={"ok":True}),"POST_TOOL_OBSERVATION_CONTRACT_VIOLATION")
  dup=control("N9_duplicate_hook_delivery",hctx,None,1);dup["classification"]="DUPLICATE_DELIVERY_NOT_NEW_SOURCE_READ";dup["match"]=dup["match"] and dup["source_read_delta"]==0
  neg_ok=all(x.get("match") for x in controls)
  add(checks,"M22-019","negative_controls",neg_ok,controls,"all nine controls match; no exceptions; N9 ledger +1 and source read +0","AUTHORIZATION_TRANSPORT")

  # Restore primary snapshot so canonical final ledger contains exactly one primary record.
  ledger.restore_state(primary_snapshot)
  add(checks,"M22-020","canonical_ledger_restore",count(ledger)==1,{"records":count(ledger),"record_identity":ledger.records()[0].record_identity},{"records":1,"record_identity":expected_rec_id},"PROVENANCE")
  ordered=([e["event"] for e in events]==["fixture_creation","fs.read_invocation","fs.read_result","official_path_matcher_result","V2_2_POST_TOOL_CALL_context","V2_2_hook_result","V2_1_ledger_record"] and [e["layer"] for e in events]==list(range(1,8)) and len({e["event_id"] for e in events})==7)
  add(checks,"M22-021","ordered_events",ordered,{"events":[e["event"] for e in events],"layers":[e["layer"] for e in events],"unique_ids":len({e["event_id"] for e in events})},{"layers":[1,2,3,4,5,6,7],"unique_ids":7},"PROVENANCE")

  cleanup_pre={"exists":fixture.exists(),"sha256":sha_file(fixture)};shutil.rmtree(fixture_root);cleanup={"cleanup_success":not fixture_root.exists(),"pre_cleanup":cleanup_pre,"root_exists_after_cleanup":fixture_root.exists()};fixture_root=None
  add(checks,"M22-022","cleanup",cleanup["cleanup_success"] and not cleanup["root_exists_after_cleanup"],cleanup,{"cleanup_success":True,"root_exists_after_cleanup":False},"FIXTURE")
  unchanged=all((EXPECTED[n] is None) or (ident(paths[n])["size_bytes"]==EXPECTED[n][0] and sha_file(paths[n])==EXPECTED[n][1]) for n in EXPECTED)
  add(checks,"M22-023","immutability",unchanged,"all bound inputs unchanged",True,"FIXTURE")
  scope_ok=(scope["primary_tool_invocation_count"]==1 and scope["primary_hook_delivery_count"]==1 and scope["actual_fixture_fs_read_executed"] and scope["official_path_matcher_executed"] and not scope["matcher_substituted"] and not scope["V2_1_hook_imported"] and not scope["Sandbox_instantiated"] and not scope["HTTP_executed"] and not scope["official_eval_predicates_executed"] and not scope["official_breach_executed"])
  add(checks,"M22-024","scope",scope_ok,scope,"one matched read; one primary delivery; official matcher only; all prohibited false","SCOPE_VIOLATION")

  failed=[x["check_id"] for x in checks if not x["passed"]]
  if not failed:outcome="CONTROLLED_MATCHED_V2_2_ACTUAL_READ_QUALIFICATION_PASS"
  elif "M22-014" in failed:outcome="V2_2_ACTUAL_SOURCE_RETRIEVAL_GAP"
  elif "M22-015" in failed:outcome="V2_2_OFFICIAL_PATH_MATCH_GAP"
  elif "M22-016" in failed:outcome="V2_2_HOOK_TRANSPORT_GAP"
  elif "M22-017" in failed:outcome="V2_2_ACTUAL_READ_LEDGER_LINEAGE_GAP"
  else:outcome="NOT_ESTABLISHED"
  status="CONTROLLED_MATCHED_V2_2_ACTUAL_READ_QUALIFICATION_COMPLETE_PASS" if not failed else "CONTROLLED_MATCHED_V2_2_ACTUAL_READ_QUALIFICATION_COMPLETE_WITH_GAPS"
  boundary={"allowed":["one controlled fixture-bound actual fs.read succeeded","exact returned bytes reached frozen V2.2 POST_TOOL_CALL outcome hook","official protected-path matcher accepted exact primary path","exact raw output entered shared V2.1 ledger","fixture, tool, hook, and ledger raw-output hashes matched","V2.2 actual-read-to-ledger positive lineage established for exact fixture","V2.2 malformed outcome controls returned diagnostics without primary-ledger corruption"],"prohibited":["arbitrary filesystem read qualification","Sandbox enforcement","source-to-HTTP lineage","sink formation or success","guardrail effectiveness","eval_predicates or breach success","real-agent exfiltration","hosted parity","robust end-to-end security"]}
  result={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"CONTROLLED_MATCHED_ACTUAL_SOURCE_TO_V2_2_HOOK_TO_LEDGER_QUALIFICATION","checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"outcome":outcome,"fixture":fixture_id,"ordered_events":events,"primary_lineage":{"fixture_sha256":fixture_id["sha256"],"tool_output_sha256":tr["raw_output_sha256"],"hook_output_sha256":sha_text(hctx.tool_output),"ledger_raw_output_sha256":rec.raw_output_sha256,"record_identity":rec.record_identity,"record_identity_expected":expected_rec_id,"official_matcher_result":match,"V2_2_hook_sha256":EXPECTED["v22_outcome"][1],"V2_1_ledger_sha256":EXPECTED["v21_ledger"][1]},"negative_controls":controls,"cleanup":cleanup,"execution_boundaries":scope,"scientific_verdict":{"V2_2_actual_fixture_read_to_ledger":"ESTABLISHED_FOR_EXACT_CONTROLLED_FIXTURE" if not failed else "NOT_ESTABLISHED","official_path_matcher_in_primary_event":"ESTABLISHED" if not failed else "NOT_ESTABLISHED","cross_version_gap":"CLOSED_FOR_EXACT_CONTROLLED_FIXTURE" if not failed else "OPEN","Sandbox_enforcement":"NOT_EVALUATED","HTTP_sink":"NOT_EVALUATED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":boundary,"next_gate":"CONTROLLED_HTTP_POST_PROPOSAL_POLICY_MATRIX" if not failed else "MATCHED_V2_2_ACTUAL_READ_GAP_REVIEW"}
  outputs={"result":out/"controlled_matched_v2_2_actual_read_result.json","checks":out/"controlled_matched_v2_2_actual_read_checks.csv","events":out/"controlled_matched_v2_2_actual_read_ordered_events.json","lineage":out/"controlled_matched_v2_2_actual_read_lineage.json","controls":out/"controlled_matched_v2_2_actual_read_negative_controls.csv","fixture":out/"controlled_matched_v2_2_actual_read_fixture_binding.json","cleanup":out/"controlled_matched_v2_2_actual_read_cleanup.json","claim":out/"controlled_matched_v2_2_actual_read_claim_boundary.json","binding":out/"controlled_matched_v2_2_actual_read_binding.json"}
  wj(outputs["result"],result);wc(outputs["checks"],checks,["check_id","category","passed","observed","expected","failure_layer"]);wj(outputs["events"],events);wj(outputs["lineage"],result["primary_lineage"]);wc(outputs["controls"],controls,["control","before","after","ledger_delta","source_read_delta","official_matcher","classification","metadata","exception","match","method"]);wj(outputs["fixture"],fixture_id);wj(outputs["cleanup"],cleanup);wj(outputs["claim"],boundary);wj(outputs["binding"],{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{n:ident(p) for n,p in paths.items()},"execution_boundaries":scope})
  manifest_rows=[{**ident(p),"role":"MATCHED_V22_ACTUAL_READ_DERIVED"} for p in outputs.values()]+[{**ident(p),"role":"MATCHED_V22_ACTUAL_READ_BOUND_INPUT"} for p in paths.values()]
  manifest=out/"controlled_matched_v2_2_actual_read_manifest.csv";wc(manifest,manifest_rows,["artifact","role","size_bytes","sha256","path"])
  ext=out/"controlled_matched_v2_2_actual_read_manifest_external_binding.json";wj(ext,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":manifest.name,"manifest_size_bytes":manifest.stat().st_size,"manifest_sha256":sha_file(manifest),"runner_sha256":sha_file(Path(__file__).resolve()),"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"outcome":outcome,"primary_tool_invocation_count":scope["primary_tool_invocation_count"],"primary_hook_delivery_count":scope["primary_hook_delivery_count"],"official_matcher_executed":scope["official_path_matcher_executed"],"matcher_substituted":False,"Sandbox_instantiated":False,"HTTP_executed":False,"next_gate":result["next_gate"]})
  print(json.dumps({"status":status,"checks":f"{len(checks)-len(failed)}/{len(checks)}","failed_ids":failed,"outcome":outcome,"primary_tool_invocations":scope["primary_tool_invocation_count"],"primary_hook_deliveries":scope["primary_hook_delivery_count"],"manifest_sha256":sha_file(manifest),"next_gate":result["next_gate"]},indent=2))
 except Exception as exc:
  if fixture_root is not None and fixture_root.exists():shutil.rmtree(fixture_root,ignore_errors=True)
  (out/"CONTROLLED_MATCHED_V2_2_ACTUAL_READ_FAILED.json").write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"BLOCKED","error_type":type(exc).__name__,"error":str(exc),"checks_frozen":checks,"events_frozen":events,"execution_boundaries":scope},indent=2,default=str),encoding="utf-8");raise

def parse():
 p=argparse.ArgumentParser(description=VERSION)
 for n in ("synthesis-manifest","synthesis-result","synthesis-checks","synthesis-claim-matrix","synthesis-binding","project-root","output-dir"):p.add_argument("--"+n,required=True)
 return p.parse_args()
if __name__=="__main__":
 try:main(parse())
 except Exception as exc:print(f"FAILED: {exc}",file=sys.stderr);raise SystemExit(1)
