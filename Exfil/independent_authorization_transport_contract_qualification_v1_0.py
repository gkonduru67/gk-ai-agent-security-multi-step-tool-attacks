#!/usr/bin/env python3
"""Read-only authorization transport contract qualification.

Statically inspects exact required SDK and EXFIL integration sources plus all
Python integration/factory modules and all Python files containing authorization
lexicon terms. Uses AST and source text only. It does not import project modules,
instantiate environments, execute tools/HTTP/models/predicates/guardrails, issue
tokens, or modify inputs.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, re, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="INDEPENDENT_AUTHORIZATION_TRANSPORT_CONTRACT_QUALIFICATION_v1.0"
PARENT_EXPECTED={
 "parent_manifest":(5286,"FBA4A93DDFC045AB878D600BC9FAB5AF9BE7DAB3DE8CFD4CABC00B223CDB32B0"),
 "parent_result":(3992,"EAA8CA2064A56C07FEC71E13D2781B5F15699AA4BB6C46A00FBAF8E13D1A50A3"),
 "parent_checks":(11066,"C7D168DF5C69E2F15AF880BD9E5670366415A0F6FF29923610D6D682CB3FBF2A"),
 "parent_rows":(35148,"C78C01C59B9CF4D3A38977E91403A7123CED4F1A90B9C453D9110FA42494A9D4"),
 "parent_discrepancies":(87,"F0ED30636995AD047FE9A626252BB42B8CD636DD0DCD9AD674FC7835166C81F6"),
 "parent_source_record":(675,"9E1514BE5F777AF5BA0ED1ADE84B942AB4FA905911203598F618D9B05835FD54"),
 "parent_claim":(871,"4961527BC61E2FCA65ACC4C38648BF28A80276DA9D02774220C2082095D6BA8C"),
 "parent_binding":(5463,"7E3168CD1D0B9319565697C24EAE5603134E559B0C6801DED09C37AA36C21765"),
}
REQUIRED_REL=(
 "aicomp_sdk/core/env/api.py","aicomp_sdk/core/env/gym.py","aicomp_sdk/core/env/sandbox.py",
 "aicomp_sdk/guardrails/base.py","aicomp_sdk/guardrails/optimal.py","aicomp_sdk/hooks/registry.py",
 "aicomp_sdk/hooks/types.py","aicomp_sdk/core/tools/http.py",
 "aicomp_sdk_exfil_v2_1/lineage_aware_exfil_guardrail_v2_1.py",
)
TERMS=("authorization","authorized","authorize","user_authorized","token","capability","permit","permission","revoke","revoked","consume","consumed","expiry","expires","expiration","target","payload_digest","payload_sha256","digest","nonce","single_use","single-use")
AUTH_STRONG=("authorization","authorized","authorize","user_authorized","token","capability","permit","revoke","revoked","consume","consumed","expiry","expires","expiration","single_use","single-use")
BIND_TERMS=("tool","tool_name","url","target","data","payload","payload_sha256","payload_digest","digest","expiry","expires","revoked","consumed")

def now():return datetime.now(timezone.utc).isoformat()
def shab(b):return hashlib.sha256(b).hexdigest().upper()
def shaf(p):return shab(Path(p).read_bytes())
def ident(p,root=None):
 p=Path(p).resolve();d={"artifact":p.name,"path":str(p),"size_bytes":p.stat().st_size,"sha256":shaf(p)}
 if root:
  try:d["relative_path"]=p.relative_to(root).as_posix()
  except ValueError:d["relative_path"]="OUTSIDE_PROJECT_ROOT"
 return d
def need(v,m):
 if not v:raise ValueError(m)
def rj(p):return json.loads(Path(p).read_text(encoding="utf-8-sig"))
def rc(p):
 with Path(p).open(encoding="utf-8-sig",newline="") as f:return list(csv.DictReader(f))
def wj(p,v):
 with Path(p).open("x",encoding="utf-8",newline="\n") as f:json.dump(v,f,indent=2,sort_keys=True,ensure_ascii=False,default=str);f.write("\n")
def wc(p,rows,fields):
 with Path(p).open("x",encoding="utf-8",newline="") as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore",lineterminator="\n");w.writeheader();w.writerows(rows)
def add(rows,cid,cat,ok,obs,exp,layer):rows.append({"check_id":cid,"category":cat,"passed":bool(ok),"observed":json.dumps(obs,sort_keys=True,default=str),"expected":json.dumps(exp,sort_keys=True,default=str),"failure_layer":layer})
def manifest_row(rows,name):return next((r for r in rows if r.get("artifact")==name),None)
def line_for(text,pos):return text.count("\n",0,pos)+1
def term_hits(text):
 low=text.lower();out=[]
 for term in TERMS:
  for m in re.finditer(r"(?<![a-z0-9_])"+re.escape(term.lower())+r"(?![a-z0-9_])",low):out.append({"term":term,"line":line_for(text,m.start()),"excerpt":text.splitlines()[line_for(text,m.start())-1].strip()[:500]})
 return sorted(out,key=lambda x:(x["line"],x["term"]))
def dotted(node):
 if isinstance(node,ast.Name):return node.id
 if isinstance(node,ast.Attribute):return dotted(node.value)+"."+node.attr
 return ""
def source_segment(text,node):return ast.get_source_segment(text,node) or ""
def analyze_file(path,root):
 text=path.read_text(encoding="utf-8-sig");tree=ast.parse(text,filename=str(path));hits=term_hits(text);symbols=[];calls=[];flows=[]
 for node in ast.walk(tree):
  if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
   seg=source_segment(text,node);low=seg.lower();matched=sorted({t for t in TERMS if re.search(r"(?<![a-z0-9_])"+re.escape(t)+r"(?![a-z0-9_])",low)})
   if matched:symbols.append({"kind":type(node).__name__,"name":node.name,"line":node.lineno,"matched_terms":matched,"arguments":[a.arg for a in getattr(getattr(node,"args",None),"args",[]) ]})
  if isinstance(node,ast.Call):
   seg=source_segment(text,node);low=seg.lower();matched=sorted({t for t in TERMS if t in low})
   if matched:calls.append({"line":getattr(node,"lineno",None),"callee":dotted(node.func),"matched_terms":matched,"source":seg[:800]})
  if isinstance(node,(ast.Assign,ast.AnnAssign,ast.Return,ast.If)):
   seg=source_segment(text,node);low=seg.lower();matched=sorted({t for t in TERMS if t in low})
   if matched:flows.append({"kind":type(node).__name__,"line":getattr(node,"lineno",None),"matched_terms":matched,"source":seg[:800]})
 d=ident(path,root);d.update({"ast_parse":"PASS","line_count":len(text.splitlines()),"term_hits":hits,"symbols":symbols,"calls":calls,"flows":flows,"strong_auth_terms":sorted({h["term"] for h in hits if h["term"] in AUTH_STRONG}),"binding_terms":sorted({h["term"] for h in hits if h["term"] in BIND_TERMS})});return d

def main(a):
 out=Path(a.output_dir).resolve();need(not out.exists(),f"Refusing overwrite: {out}");out.mkdir(parents=True);checks=[];inventory=[];interface=[];scope={"source_files_read":0,"AST_parsed":0,"project_modules_imported":False,"Sandbox_instantiated":False,"Gym_instantiated":False,"HTTP_executed":False,"guardrail_decisions":0,"authorization_tokens_issued":0,"tools_executed":False,"models_used":False,"predicates_executed":False,"breach_executed":False,"external_effects_observed":False,"attack_optimization":False,"sources_modified":False,"parent_modified":False}
 try:
  root=Path(a.project_root).resolve();need(root.is_dir(),f"Missing project root: {root}")
  parents={k:Path(getattr(a,k)).resolve() for k in PARENT_EXPECTED};parents["parent_external_binding"]=Path(a.parent_external_binding).resolve()
  for n,p in parents.items():need(p.is_file(),f"Missing {n}: {p}")
  input_hashes={str(p):shaf(p) for p in parents.values()}
  for i,(name,expected) in enumerate(PARENT_EXPECTED.items(),1):
   actual=ident(parents[name],root);add(checks,f"AT-{i:03d}","parent_identity",actual["size_bytes"]==expected[0] and actual["sha256"]==expected[1],actual,{"size_bytes":expected[0],"sha256":expected[1]},"FIXTURE")
  pres=rj(parents["parent_result"]);pchecks=rc(parents["parent_checks"]);pman=rc(parents["parent_manifest"]);pext=rj(parents["parent_external_binding"])
  parent_ok=pres.get("outcome")=="INDEPENDENT_SOURCE_TO_PROPOSAL_LINEAGE_QUALIFICATION_PASS" and pres.get("checks")=={"failed":0,"failed_ids":[],"passed":21,"total":21} and len(pchecks)==21 and all(str(r.get("passed")).lower()=="true" for r in pchecks)
  add(checks,"AT-009","parent_pass",parent_ok,{"outcome":pres.get("outcome"),"checks":pres.get("checks"),"rows":pres.get("recomputation_summary",{}).get("rows")},"21/21 independent lineage pass","FIXTURE")
  pmok=True;details=[]
  for name in ("parent_result","parent_checks","parent_rows","parent_discrepancies","parent_source_record","parent_claim","parent_binding"):
   mr=manifest_row(pman,parents[name].name);act=ident(parents[name],root);ok=mr is not None and int(mr["size_bytes"])==act["size_bytes"] and mr["sha256"]==act["sha256"];pmok&=ok;details.append({"artifact":act["artifact"],"match":ok})
  add(checks,"AT-010","parent_manifest",pmok,details,"all required derived parent artifacts match parent manifest","FIXTURE")
  pextok=pext.get("manifest_sha256")==PARENT_EXPECTED["parent_manifest"][1] and pext.get("checks_failed")==0 and pext.get("failed_ids")==[] and pext.get("outcome")=="INDEPENDENT_SOURCE_TO_PROPOSAL_LINEAGE_QUALIFICATION_PASS" and pext.get("next_gate")=="INDEPENDENT_AUTHORIZATION_TRANSPORT_CONTRACT_QUALIFICATION"
  add(checks,"AT-011","parent_external_binding",pextok,{"identity":ident(parents["parent_external_binding"],root),"content":pext},{"manifest_sha256":PARENT_EXPECTED["parent_manifest"][1],"failed_ids":[],"next_gate":"INDEPENDENT_AUTHORIZATION_TRANSPORT_CONTRACT_QUALIFICATION"},"FIXTURE")

  required=[root/r for r in REQUIRED_REL]
  missing=[str(p) for p in required if not p.is_file()];add(checks,"AT-012","required_sources",not missing,{"required":list(REQUIRED_REL),"missing":missing},"all 9 required sources present","AUTHORIZATION_SOURCE_SCOPE_INCOMPLETE");need(not missing,"Required authorization inspection source missing")
  # Integration/factory modules and every Python source containing lexicon terms.
  roots=[p for p in (root/"aicomp_sdk",root/"aicomp_sdk_exfil_v2",root/"aicomp_sdk_exfil_v2_1",root/"aicomp_sdk_exfil_v2_2") if p.is_dir()]
  all_py=sorted({p.resolve() for rr in roots for p in rr.rglob("*.py")})
  integration=[p for p in all_py if any(x in p.name.lower() for x in ("integration","factory","builder","wiring"))]
  lexical=[]
  for p in all_py:
   try:text=p.read_text(encoding="utf-8-sig").lower()
   except UnicodeDecodeError:continue
   if any(re.search(r"(?<![a-z0-9_])"+re.escape(t)+r"(?![a-z0-9_])",text) for t in TERMS):lexical.append(p)
  selected=sorted(set(required+integration+lexical));need(selected,"No source files selected")
  source_hashes={str(p):shaf(p) for p in selected}
  parse_errors=[]
  for p in selected:
   try:d=analyze_file(p,root);inventory.append(d);scope["source_files_read"]+=1;scope["AST_parsed"]+=1
   except Exception as exc:parse_errors.append({"path":str(p),"error":f"{type(exc).__name__}:{exc}"})
  add(checks,"AT-013","AST_parse",not parse_errors,{"selected":len(selected),"parsed":len(inventory),"errors":parse_errors},"all selected sources parse","AUTHORIZATION_SOURCE_SCOPE_INCOMPLETE")
  add(checks,"AT-014","scope_coverage",all(any(x["relative_path"]==r for x in inventory) for r in REQUIRED_REL) and all(any(x["path"]==str(p) for x in inventory) for p in integration),{"required_count":len(required),"integration_factory_count":len(integration),"lexical_count":len(lexical),"selected_unique":len(selected)},"required plus all discovered integration/factory and lexical Python sources","AUTHORIZATION_SOURCE_SCOPE_INCOMPLETE")

  # Explicit interface map from parsed authoritative sources.
  byrel={x["relative_path"]:x for x in inventory}
  sandbox_text=(root/"aicomp_sdk/core/env/sandbox.py").read_text(encoding="utf-8-sig")
  optimal_text=(root/"aicomp_sdk/guardrails/optimal.py").read_text(encoding="utf-8-sig")
  base_text=(root/"aicomp_sdk/guardrails/base.py").read_text(encoding="utf-8-sig")
  http_text=(root/"aicomp_sdk/core/tools/http.py").read_text(encoding="utf-8-sig")
  lineage_text=(root/"aicomp_sdk_exfil_v2_1/lineage_aware_exfil_guardrail_v2_1.py").read_text(encoding="utf-8-sig")
  types_text=(root/"aicomp_sdk/hooks/types.py").read_text(encoding="utf-8-sig")
  explicit={
   "sandbox_context_keys":sorted(set(re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:',re.search(r'ctx\s*=\s*\{(.*?)\n\s*\}',sandbox_text,re.S).group(1) if re.search(r'ctx\s*=\s*\{(.*?)\n\s*\}',sandbox_text,re.S) else ""))),
   "sandbox_guardrail_call":bool(re.search(r'self\.guardrail\.decide\(tool_name,\s*tool_args,\s*ctx\)',sandbox_text)),
   "sandbox_tool_dispatch_after_decision":sandbox_text.find("self.guardrail.decide")<sandbox_text.find("self.tools.call") and sandbox_text.find("self.tools.call")!=-1,
   "base_decide_arguments":bool(re.search(r'def decide\(\s*self,\s*tool_name[^\n]*\n?[^)]*tool_args[^)]*context',base_text,re.S)),
   "hook_context_fields":sorted(set(re.findall(r'^\s{4}([a-zA-Z_][a-zA-Z0-9_]*)\s*:',types_text,re.M))),
   "optimal_user_authorized_read":'context.get("user_authorized", False)' in optimal_text,
   "optimal_user_confirmed_safe_read":'context.get("user_confirmed_safe", False)' in optimal_text,
   "http_handler_arguments":bool(re.search(r'def http_post\(ctx:\s*ToolContext,\s*url:\s*str,\s*data:\s*str\)',http_text)),
   "lineage_guardrail_context_auth_read":any(t in lineage_text.lower() for t in ("authorization","user_authorized","token","capability","revoke","consume","expiry")),
  }
  interface.extend([
   {"component":"SandboxEnv","carrier":"context","observed_fields":explicit["sandbox_context_keys"],"authorization_read":False,"validation":"NOT_PRESENT_IN_CTX_CONSTRUCTION","binding":"NOT_ESTABLISHED","stage":"before guardrail decision context construction"},
   {"component":"GuardrailBase","carrier":"decide(tool_name, tool_args, context)","observed_fields":["tool_name","tool_args","context"],"authorization_read":False,"validation":"NONE_DEFAULT_ALLOW","binding":"NONE","stage":"guardrail"},
   {"component":"optimal.Guardrail","carrier":"context booleans","observed_fields":["user_confirmed_safe","user_authorized"],"authorization_read":explicit["optimal_user_authorized_read"],"validation":"TRUTHINESS_ONLY","binding":"NOT_BOUND_TO_TOOL_TARGET_PAYLOAD_EXPIRY_REVOCATION_OR_CONSUMPTION_IN_SOURCE","stage":"guardrail early allow"},
   {"component":"LineageAwareExfilGuardrailV21","carrier":"tool_args payload plus ledger","observed_fields":["tool_name","tool_args","context"],"authorization_read":explicit["lineage_guardrail_context_auth_read"],"validation":"PAYLOAD_LINEAGE_ONLY","binding":"NO_AUTHORIZATION_CONSUMPTION_IN_SOURCE","stage":"guardrail"},
   {"component":"HookContext","carrier":"context/metadata/hook_state/tool_args","observed_fields":explicit["hook_context_fields"],"authorization_read":False,"validation":"GENERIC_CARRIER_ONLY","binding":"NOT_ESTABLISHED","stage":"multiple hook stages"},
   {"component":"http.post","carrier":"handler arguments","observed_fields":["url","data"],"authorization_read":False,"validation":"PRIVATE_NETWORK_CHECK_ONLY","binding":"NO_AUTHORIZATION_ARGUMENT","stage":"tool execution"},
  ])
  add(checks,"AT-015","sandbox_transport",explicit["sandbox_guardrail_call"] and explicit["sandbox_tool_dispatch_after_decision"] and "user_authorized" not in explicit["sandbox_context_keys"] and "authorization" not in explicit["sandbox_context_keys"],explicit,{"guardrail_before_tool":True,"authorization_not_constructed_in_ctx":True},"AUTHORIZATION_TRANSPORT")
  add(checks,"AT-016","optimal_authorization_semantics",explicit["optimal_user_authorized_read"] and explicit["optimal_user_confirmed_safe_read"],{"user_authorized":explicit["optimal_user_authorized_read"],"user_confirmed_safe":explicit["optimal_user_confirmed_safe_read"]},{"two_context_flags_read":True,"semantics":"truthiness early allow only"},"AUTHORIZATION_TRANSPORT")
  add(checks,"AT-017","tool_contract",explicit["http_handler_arguments"],{"http_post_signature":"ctx,url,data","authorization_argument":False},{"authorization_argument":False},"AUTHORIZATION_TRANSPORT")
  add(checks,"AT-018","lineage_guardrail_contract",not explicit["lineage_guardrail_context_auth_read"],{"authorization_read":explicit["lineage_guardrail_context_auth_read"]},{"authorization_read":False},"AUTHORIZATION_TRANSPORT")

  # Classify candidate consumers. Strong terms in executable symbols/calls are candidates, not automatically authoritative consumers.
  candidates=[]
  for f in inventory:
   if f["strong_auth_terms"]:candidates.append({"relative_path":f["relative_path"],"sha256":f["sha256"],"strong_terms":f["strong_auth_terms"],"binding_terms":f["binding_terms"],"symbols":f["symbols"],"calls":f["calls"],"flows":f["flows"]})
  # Source-specific finding: only optimal context booleans are explicit in required scope; sandbox does not populate them.
  existing_reader=explicit["optimal_user_authorized_read"]
  transport_established=False
  structured_validation=False
  consumer_class="AUTHORIZATION_INTERFACE_PRESENT_BUT_TRANSPORT_NOT_ESTABLISHED" if existing_reader else "AUTHORIZATION_CONSUMER_ABSENT_IN_INSPECTED_SCOPE"
  findings={
   "current_authoritative_component_reads_authorization_evidence":{"value":existing_reader,"component":"aicomp_sdk/guardrails/optimal.py Guardrail.decide","field":"context.user_authorized boolean","semantic_limit":"truthiness-only early allow" if existing_reader else "NOT_ESTABLISHED"},
   "carrier":{"observed":"generic guardrail context Mapping","sandbox_population":"NOT_ESTABLISHED_FOR_user_authorized_or_user_confirmed_safe","tool_args":"NO_STRUCTURED_AUTHORIZATION_FIELD_ESTABLISHED","proposal_object":"NO_AUTHORIZATION_FIELD_ESTABLISHED","runtime_state":"NO_AUTHORIZATION_STATE_ESTABLISHED"},
   "tool_name_binding":"NOT_ESTABLISHED","destination_binding":"NOT_ESTABLISHED","payload_digest_binding":"NOT_ESTABLISHED","expiry_representation":"NOT_ESTABLISHED","revoked_state":"NOT_ESTABLISHED","consumed_state":"NOT_ESTABLISHED","single_use_consumption":"NOT_ESTABLISHED","validation_stage":"EARLY_GUARDRAIL_ALLOW_IF_FLAG_PRESENT_BUT_PRODUCER_AND_TRANSPORT_NOT_ESTABLISHED","router_preserves_authorization_unchanged":"NOT_ESTABLISHED","decision_causally_connected_to_structured_authorization_validation":"NOT_ESTABLISHED","classification":consumer_class,
  }
  add(checks,"AT-019","consumer_classification",consumer_class in {"AUTHORIZATION_INTERFACE_PRESENT_BUT_TRANSPORT_NOT_ESTABLISHED","AUTHORIZATION_CONSUMER_ABSENT_IN_INSPECTED_SCOPE"},{"candidate_files":len(candidates),"finding":findings},"bounded static classification","AUTHORIZATION_TRANSPORT")
  no_structured=(not transport_established and not structured_validation and findings["tool_name_binding"]=="NOT_ESTABLISHED" and findings["destination_binding"]=="NOT_ESTABLISHED" and findings["payload_digest_binding"]=="NOT_ESTABLISHED")
  add(checks,"AT-020","structured_contract",no_structured,findings,"no complete structured authorization transport/validation/binding contract established","AUTHORIZATION_TRANSPORT")
  immutable=all(shaf(p)==h for p,h in [(Path(k),v) for k,v in input_hashes.items()]) and all(shaf(p)==source_hashes[str(p)] for p in selected)
  add(checks,"AT-021","immutability",immutable,{"parent_modified":False,"sources_modified":False},True,"FIXTURE")
  scope["sources_modified"]=not all(shaf(p)==source_hashes[str(p)] for p in selected);scope["parent_modified"]=not all(shaf(Path(k))==v for k,v in input_hashes.items())
  add(checks,"AT-022","execution_boundary",not any((scope["project_modules_imported"],scope["Sandbox_instantiated"],scope["Gym_instantiated"],scope["HTTP_executed"],scope["tools_executed"],scope["models_used"],scope["predicates_executed"],scope["breach_executed"],scope["external_effects_observed"],scope["attack_optimization"])),scope,"static read/AST/hash only","SCOPE_VIOLATION")

  failed=[r["check_id"] for r in checks if not r["passed"]]
  if missing or parse_errors:outcome="AUTHORIZATION_SOURCE_SCOPE_INCOMPLETE"
  elif failed:outcome="NOT_ESTABLISHED"
  else:outcome=consumer_class
  status="INDEPENDENT_AUTHORIZATION_TRANSPORT_CONTRACT_QUALIFICATION_COMPLETE_PASS" if not failed else "INDEPENDENT_AUTHORIZATION_TRANSPORT_CONTRACT_QUALIFICATION_COMPLETE_WITH_GAPS"
  next_gate="REVIEWED_HARDENED_AUTHORIZATION_CONTRACT_DESIGN" if outcome in {"AUTHORIZATION_CONSUMER_ABSENT_IN_INSPECTED_SCOPE","AUTHORIZATION_INTERFACE_PRESENT_BUT_TRANSPORT_NOT_ESTABLISHED"} else "MATCHED_POLICY_COMPARISON" if outcome=="EXISTING_AUTHORIZATION_CONSUMER_ESTABLISHED" else "AUTHORIZATION_SOURCE_SCOPE_GAP_REVIEW"
  boundary={"allowed":["required, integration/factory, and authorization-lexicon Python source identities were frozen","optimal guardrail statically reads user_authorized and user_confirmed_safe context booleans","sandbox guardrail context construction does not include those fields in inspected source","no tool/target/payload-digest/expiry/revocation/consumption/single-use binding was established in inspected source","http.post accepts ctx, url, and data and has no authorization argument","authorization interface is present but transport is not established"],"prohibited":["claim runtime authorization transport","claim structured authorization validation","claim flags are user-authentic or integrity protected","claim authorization enforcement","claim HTTP or Sandbox runtime behavior from static inspection","claim robust security findings"]}
  result={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"READ_ONLY_AUTHORIZATION_CONTRACT_SOURCE_AND_INTERFACE_QUALIFICATION","checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"outcome":outcome,"source_scope":{"required":list(REQUIRED_REL),"selected_files":len(selected),"integration_factory_files":len(integration),"lexical_files":len(lexical),"candidate_consumer_files":len(candidates)},"findings":findings,"execution_boundaries":scope,"scientific_verdict":{"authorization_interface":"PRESENT_AS_UNVALIDATED_CONTEXT_BOOLEANS" if existing_reader else "NOT_ESTABLISHED","authorization_transport":"NOT_ESTABLISHED","structured_validation":"NOT_ESTABLISHED","authorization_enforcement":"NOT_ESTABLISHED","runtime_behavior":"NOT_EVALUATED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":boundary,"next_gate":next_gate}
  outputs={"result":out/"authorization_transport_contract_result.json","checks":out/"authorization_transport_contract_checks.csv","inventory":out/"authorization_source_inventory.json","candidates":out/"authorization_candidate_consumers.json","interface":out/"authorization_interface_map.json","findings":out/"authorization_exact_questions.json","claim":out/"authorization_transport_contract_claim_boundary.json","binding":out/"authorization_transport_contract_binding.json"}
  wj(outputs["result"],result);wc(outputs["checks"],checks,["check_id","category","passed","observed","expected","failure_layer"]);wj(outputs["inventory"],inventory);wj(outputs["candidates"],candidates);wj(outputs["interface"],interface);wj(outputs["findings"],findings);wj(outputs["claim"],boundary);wj(outputs["binding"],{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve(),root),"parents":{n:ident(p,root) for n,p in parents.items()},"inspected_sources":[{k:v for k,v in x.items() if k in {"artifact","relative_path","path","size_bytes","sha256","ast_parse","line_count"}} for x in inventory],"execution_boundaries":scope})
  mrows=[{**ident(p,root),"role":"AUTHORIZATION_CONTRACT_DERIVED"} for p in outputs.values()]+[{**ident(p,root),"role":"AUTHORIZATION_CONTRACT_BOUND_PARENT"} for p in parents.values()]+[{**ident(p,root),"role":"AUTHORIZATION_CONTRACT_BOUND_SOURCE"} for p in selected]
  mp=out/"authorization_transport_contract_manifest.csv";wc(mp,mrows,["artifact","relative_path","role","size_bytes","sha256","path"])
  ep=out/"authorization_transport_contract_manifest_external_binding.json";wj(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":shaf(mp),"runner_sha256":shaf(Path(__file__).resolve()),"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"outcome":outcome,"selected_sources":len(selected),"HTTP_executed":False,"Sandbox_instantiated":False,"next_gate":next_gate})
  print(json.dumps({"status":status,"checks":f"{len(checks)-len(failed)}/{len(checks)}","failed_ids":failed,"selected_sources":len(selected),"candidate_consumer_files":len(candidates),"outcome":outcome,"HTTP_executed":False,"Sandbox_instantiated":False,"manifest_sha256":shaf(mp),"next_gate":next_gate},indent=2))
 except Exception as exc:
  (out/"AUTHORIZATION_TRANSPORT_CONTRACT_FAILED.json").write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"BLOCKED","error_type":type(exc).__name__,"error":str(exc),"checks_frozen":checks,"source_inventory_frozen":inventory,"interface_map_frozen":interface,"execution_boundaries":scope},indent=2,default=str),encoding="utf-8");raise

def parse():
 p=argparse.ArgumentParser(description=VERSION)
 for n in ("parent-manifest","parent-external-binding","parent-result","parent-checks","parent-rows","parent-discrepancies","parent-source-record","parent-claim","parent-binding","project-root","output-dir"):p.add_argument("--"+n,required=True)
 return p.parse_args()
if __name__=="__main__":
 try:main(parse())
 except Exception as exc:print(f"FAILED: {exc}",file=sys.stderr);raise SystemExit(1)
