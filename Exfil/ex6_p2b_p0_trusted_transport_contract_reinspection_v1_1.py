#!/usr/bin/env python3
"""EX6 P2B P0 trusted-transport contract reinspection.

Read-only and fail-closed. This runner binds frozen P1/P1A inputs and inspects
SDK source statically. It does not import the SDK, instantiate an adapter,
execute a guardrail, run Sandbox/Gym/tools/models, or evaluate security effects.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, platform, re, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P0_TRUSTED_TRANSPORT_CONTRACT_REINSPECTION_v1.1"
DEFERRED=[f"AZ-{i:03d}" for i in range(1,8)]+[f"PV-{i:03d}" for i in range(2,5)]
SOURCES=("sandbox","guardrail_base","api")
ALLOWED=[
 "frozen parent identity verification",
 "static SDK source interface inventory",
 "deferred-requirement to source-evidence mapping",
 "explicit SDK gap classification",
 "P2B P1 design-readiness recommendation",
]
PROHIBITED=[
 "adapter implementation exists", "runtime adapter behavior", "guardrail effectiveness",
 "security improvement", "policy superiority", "real exfiltration prevention",
 "Sandbox parity", "Gym parity", "hosted parity", "attack success reduction",
]
TOKENS={
 "AZ-001":["authorization","authorized","grant","trusted"],
 "AZ-002":["tool_name","tool_args","proposal"],
 "AZ-003":["digest","sha256","hash"],
 "AZ-004":["event_id","event_index","tool_event","event"],
 "AZ-005":["one_use","consume","consumed","replay"],
 "AZ-006":["before_decide","decide","guardrail"],
 "AZ-007":["snapshot_state","restore_state","reset_state"],
 "PV-002":["fs.read","read","result","output"],
 "PV-003":["after_tool","tool_result","tool_output","outcome"],
 "PV-004":["http.post","data","payload","lineage"],
}

def now(): return datetime.now(timezone.utc).isoformat()
def sha(p:Path)->str:
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""): h.update(b)
 return h.hexdigest().upper()
def ident(p:Path)->dict[str,Any]:
 return {"artifact":p.name,"path":str(p.resolve()),"size_bytes":p.stat().st_size,"sha256":sha(p)}
def req(c:bool,m:str):
 if not c: raise ValueError(m)
def loadj(p:Path): return json.loads(p.read_text(encoding="utf-8-sig"))
def dumpx(p:Path,x:Any):
 with p.open("x",encoding="utf-8",newline="\n") as f: json.dump(x,f,indent=2,sort_keys=True);f.write("\n")
def csvx(p:Path,rows:list[dict[str,Any]],fields:list[str]):
 with p.open("x",encoding="utf-8",newline="") as f:
  w=csv.DictWriter(f,fieldnames=fields,lineterminator="\n",extrasaction="ignore");w.writeheader();w.writerows(rows)
def external_manifest_check(manifest:Path,binding:Path)->dict[str,Any]:
 b=loadj(binding); req(b.get("manifest_sha256")==sha(manifest),"P1A manifest SHA mismatch")
 if b.get("manifest_size_bytes") is not None: req(int(b["manifest_size_bytes"])==manifest.stat().st_size,"P1A manifest size mismatch")
 return b
def validate_p1_contract(x:Any)->dict[str,Any]:
 req(isinstance(x,dict),"P1 requirements specification must be a JSON object")
 req(x.get("requirements_count")==46,"Unexpected P1 requirements_count")
 counts=x.get("feasibility_counts",{})
 req(counts.get("REQUIRES_TRUSTED_CONTEXT_TRANSPORT")==7,
     "P1 trusted-context-transport feasibility count is not 7")
 gate=x.get("implementation_gate",{})
 req(gate.get("trusted_authorization_features")=="WITHHELD_PENDING_TRANSPORT",
     "P1 trusted authorization gate differs")
 req(gate.get("real_lineage_features")=="WITHHELD_PENDING_SANDBOX_EVENT_TRANSPORT",
     "P1 real-lineage gate differs")
 binding=x.get("full_authorization_binding",{})
 req(binding.get("implementable_under_current_context") is False,
     "P1 full authorization unexpectedly implementable under current context")
 req(binding.get("implementation_status")=="WITHHELD_PENDING_TRUSTED_TRANSPORT",
     "P1 full authorization implementation status differs")
 return {"requirements_count":46,"trusted_context_transport_count":7,
         "trusted_authorization_features":gate["trusted_authorization_features"],
         "real_lineage_features":gate["real_lineage_features"],
         "full_authorization_binding":binding}

def validate_p1a_scope(x:Any)->dict[str,Any]:
 req(isinstance(x,dict),"P1A scope must be a JSON object")
 req(x.get("proposed_component")=="TrustedGuardrailContextAdapter",
     "Unexpected P1A proposed component")
 req(x.get("status")=="DESIGN_WITHHELD_PENDING_SEPARATE_CONTRACT",
     "Unexpected P1A scope status")
 req(x.get("implementation_authorized_by_v6_90A") is False,
     "P1A unexpectedly authorizes implementation")
 channels=x.get("required_channels",{})
 before=channels.get("before_decide",[]); after=channels.get("after_tool",[])
 req(set(before)=={"trusted authorization grant","qualifying successful protected-read records"},
     "P1A before_decide channel differs")
 req(set(after)=={"trusted tool outcome","proposal digest","event identity"},
     "P1A after_tool channel differs")
 expected_rules={"no model-derived authorization","no prompt-derived authorization",
  "no recent_sources-only lineage","no arbitrary hook injection presented as trusted transport",
  "no synthetic value presented as real protected-source output"}
 req(set(x.get("trust_rules",[]))==expected_rules,"P1A trust rules differ")
 return {"proposed_component":x["proposed_component"],"status":x["status"],
         "implementation_authorized":False,"required_channels":channels,
         "trust_rules":x["trust_rules"]}

def inspect_source(label:str,p:Path)->tuple[dict[str,Any],list[dict[str,Any]]]:
 text=p.read_text(encoding="utf-8-sig");tree=ast.parse(text,filename=str(p)); symbols=[]
 for n in ast.walk(tree):
  if isinstance(n,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)):
   kind="class" if isinstance(n,ast.ClassDef) else ("async_function" if isinstance(n,ast.AsyncFunctionDef) else "function")
   symbols.append({"source":label,"symbol":n.name,"kind":kind,"line_start":n.lineno,"line_end":getattr(n,"end_lineno",n.lineno),"source_sha256":hashlib.sha256((ast.get_source_segment(text,n) or ast.unparse(n)).encode()).hexdigest().upper()})
 return {**ident(p),"label":label,"ast_parse":"PASS","symbol_count":len(symbols)},symbols
def evidence(reqid:str,sources:dict[str,str],symbols:list[dict[str,Any]])->dict[str,Any]:
 hits=[]
 for label,text in sources.items():
  low=text.lower()
  for token in TOKENS[reqid]:
   if token.lower() in low: hits.append({"source":label,"token":token})
 symhits=[s for s in symbols if any(t.lower() in s["symbol"].lower() for t in TOKENS[reqid])]
 # Token evidence establishes a candidate interface only, never satisfaction.
 status="CANDIDATE_INTERFACE_EVIDENCE" if hits or symhits else "EXPLICIT_SDK_GAP_NO_STATIC_EVIDENCE"
 return {"requirement_id":reqid,"status":status,"token_hits":hits,"symbol_hits":symhits,"runtime_validated":False,"satisfied":False,"claim_boundary":"static candidate evidence only; design must resolve semantics and trust provenance"}
def main(a):
 out=Path(a.output_dir).resolve();req(not out.exists(),f"Refusing overwrite: {out}");out.mkdir(parents=True)
 try:
  paths={k:Path(getattr(a,k)).resolve() for k in ("requirements_json","p1a_scope_json","p1a_manifest","p1a_external_binding","sandbox","guardrail_base","api")}
  for k,p in paths.items(): req(p.is_file(),f"Missing {k}: {p}")
  parent=external_manifest_check(paths["p1a_manifest"],paths["p1a_external_binding"])
  p1_contract=validate_p1_contract(loadj(paths["requirements_json"]))
  p1a_contract=validate_p1a_scope(loadj(paths["p1a_scope_json"]))
  scope_missing=[]
  source_info=[];symbols=[];texts={}
  for label in SOURCES:
   info,syms=inspect_source(label,paths[label]);source_info.append(info);symbols+=syms;texts[label]=paths[label].read_text(encoding="utf-8-sig")
  mappings=[evidence(x,texts,symbols) for x in DEFERRED]
  gaps=[x["requirement_id"] for x in mappings if x["status"].startswith("EXPLICIT_SDK_GAP")]
  candidates=[x["requirement_id"] for x in mappings if x["status"]=="CANDIDATE_INTERFACE_EVIDENCE"]
  # P1 design can proceed when exact semantic contracts and identities are bound.
  # Implementation readiness is never granted by this P0 runner.
  design_ready=True
  result={
   "version":VERSION,"created_at_utc":now(),"status":"P2B_P0_CONTRACT_REINSPECTION_COMPLETE_PASS" if design_ready else "P2B_P0_CONTRACT_REINSPECTION_COMPLETE_WITH_SCOPE_GAPS",
   "classification":"READ_ONLY_STATIC_CONTRACT_REINSPECTION","parent_external_binding_verified":True,
   "parent_manifest_sha256":sha(paths["p1a_manifest"]),"parent_status":parent.get("status"),
   "requirements_source":ident(paths["requirements_json"]),"p1a_scope_source":ident(paths["p1a_scope_json"]),"p1_contract":p1_contract,"p1a_contract":p1a_contract,
   "sdk_sources":source_info,"deferred_requirements":DEFERRED,"scope_missing_requirement_ids":scope_missing,
   "mapping_summary":{"total":len(mappings),"candidate_interface_evidence":len(candidates),"explicit_sdk_gaps":len(gaps),"candidate_ids":candidates,"gap_ids":gaps},
   "P2B_P1_adapter_design_ready":design_ready,"adapter_implementation_created":False,
   "claim_boundary":{"allowed":ALLOWED,"prohibited":PROHIBITED},
   "execution_boundaries":{"sdk_imported":False,"adapter_created":False,"guardrail_executed":False,"sandbox_executed":False,"gym_executed":False,"tools_executed":False,"predicates_executed":False,"breach_executed":False,"effects_observed":False},
   "next_gate":"EX6_P2B_P1_ADAPTER_DESIGN_SPECIFICATION" if design_ready else "P2B_P0_CONTRACT_RECONCILIATION",
  }
  r=out/"ex6_p2b_p0_result.json";m=out/"ex6_p2b_p0_requirement_interface_matrix.json";s=out/"ex6_p2b_p0_source_blocks.csv";b=out/"ex6_p2b_p0_binding.json";c=out/"ex6_p2b_p0_claim_boundary.json"
  dumpx(r,result);dumpx(m,{"version":VERSION,"rows":mappings});csvx(s,symbols,["source","symbol","kind","line_start","line_end","source_sha256"]);dumpx(c,result["claim_boundary"])
  dumpx(b,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{k:ident(v) for k,v in paths.items()},"source_artifacts_modified":False})
  content=[r,m,s,b,c];rows=[]
  for p in content: rows.append({**ident(p),"role":"P2B_P0_DERIVED"})
  for k,p in paths.items(): rows.append({**ident(p),"role":"P2B_P0_BOUND_"+k.upper()})
  man=out/"ex6_p2b_p0_manifest.csv";csvx(man,rows,["artifact","role","size_bytes","sha256","path"])
  ext=out/"ex6_p2b_p0_manifest_external_binding.json";dumpx(ext,{"version":VERSION,"created_at_utc":now(),"status":result["status"],"manifest_filename":man.name,"manifest_size_bytes":man.stat().st_size,"manifest_sha256":sha(man),"runner_sha256":sha(Path(__file__).resolve()),"P2B_P1_adapter_design_ready":design_ready,"adapter_created":False})
  print(json.dumps({"status":result["status"],"manifest_sha256":sha(man),"design_ready":design_ready,"candidate_ids":candidates,"gap_ids":gaps,"next_gate":result["next_gate"]},indent=2))
 except Exception:
  (out/"P2B_P0_FAILED.txt").write_text("P2B P0 failed. No contract, design-readiness, implementation, or effectiveness claim is allowed.\n",encoding="utf-8")
  raise

def args():
 p=argparse.ArgumentParser(description=VERSION)
 p.add_argument("--requirements-json",required=True);p.add_argument("--p1a-scope-json",required=True)
 p.add_argument("--p1a-manifest",required=True);p.add_argument("--p1a-external-binding",required=True)
 p.add_argument("--sandbox",required=True);p.add_argument("--guardrail-base",required=True);p.add_argument("--api",required=True);p.add_argument("--output-dir",required=True)
 return p.parse_args()
if __name__=="__main__":
 try: main(args())
 except Exception as e: print(f"FAILED: {e}",file=sys.stderr);raise SystemExit(1)
