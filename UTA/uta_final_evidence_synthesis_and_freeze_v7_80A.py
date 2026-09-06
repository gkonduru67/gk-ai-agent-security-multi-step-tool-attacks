#!/usr/bin/env python3
"""UTA final evidence synthesis and freeze, v7.80A.

Discovers and verifies the frozen UTA evidence chain under one evidence root,
then creates a publication-oriented synthesis without rerunning GPT, agents,
guardrails, tools, Sandbox, Gym, predicates, or breach evaluation.

Required evidence epochs: v7.72A, v7.75A, v7.76A, v7.77A.1, v7.78A, v7.79A.
v7.74A is included when present and is otherwise recorded as not supplied.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,os,platform,re,sys,traceback
from datetime import datetime,timezone
from pathlib import Path

VERSION="UTA_FINAL_EVIDENCE_SYNTHESIS_AND_FREEZE_v7.80A"
REQUIRED=("v7_72A","v7_75A","v7_76A","v7_77A_1","v7_78A","v7_79A")
OPTIONAL=("v7_74A",)
DISPLAY={"v7_72A":"GPT_PROPOSAL_QUALIFICATION","v7_74A":"GPT_G3_DIAGNOSTIC","v7_75A":"GPT_G3_HISTORY_DEPTH_LADDER","v7_76A":"GPT_G3_INCREMENTAL_SCAFFOLDING","v7_77A_1":"DETERMINISTIC_G3_POLICY_ISOLATION","v7_78A":"FROZEN_PROPOSAL_SANDBOX_GYM_PARITY","v7_79A":"PREDICATE_BREACH_RECOMPUTATION"}

def safe(v):
 if v is None or isinstance(v,(str,int,float,bool)):return v
 if isinstance(v,Path):return str(v)
 if isinstance(v,dict):return {str(k):safe(x) for k,x in v.items()}
 if isinstance(v,(list,tuple,set)):return [safe(x) for x in v]
 return repr(v)
def canon(v):return json.dumps(safe(v),sort_keys=True,separators=(",",":"),ensure_ascii=True)
def sha_text(s):return hashlib.sha256(s.encode()).hexdigest().upper()
def sha_file(p):
 h=hashlib.sha256()
 with Path(p).open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest().upper()
def atomic_text(p,s):
 if p.exists():raise FileExistsError(f"Refusing overwrite: {p}")
 t=p.with_name(p.name+".tmp");t.write_text(s,encoding="utf-8");os.replace(t,p)
def atomic_json(p,v):atomic_text(p,json.dumps(safe(v),indent=2,ensure_ascii=True)+"\n")
def norm_token(s):return re.sub(r"[^a-z0-9]","",s.lower())
def artifact_entry(manifest,report):
 for x in manifest.get("artifacts",[]):
  if Path(str(x.get("file") or "")).name.lower()==report.name.lower():return x
 return None
def report_score(p):
 n=p.name.lower()
 if any(x in n for x in ("manifest","preflight","failure","summary")):return -100
 try:
  x=json.loads(p.read_text(encoding="utf-8"));score=0
  if isinstance(x,dict):score+=2
  if x.get("schema"):score+=2
  if x.get("status"):score+=2
  if x.get("rows") is not None:score+=2
  return score
 except Exception:return -100
def discover_epoch(root,token,required):
 key=norm_token(token);mans=[p for p in root.rglob("*.json") if "manifest" in p.name.lower() and key in norm_token(p.name)]
 candidates=[]
 for mp in mans:
  try:m=json.loads(mp.read_text(encoding="utf-8"))
  except Exception:continue
  for x in m.get("artifacts",[]):
   n=Path(str(x.get("file") or "")).name
   if not n.lower().endswith(".json") or any(z in n.lower() for z in ("manifest","preflight","failure")):continue
   rp=mp.parent/n
   if rp.is_file():candidates.append((report_score(rp),rp,mp,m,x))
 if not candidates:
  if required:raise FileNotFoundError(f"No verifiable report/manifest pair found for {token} under {root}")
  return None
 _,rp,mp,m,x=max(candidates,key=lambda z:z[0]);r=json.loads(rp.read_text(encoding="utf-8"));actual=sha_file(rp);expected=str(x.get("sha256") or "").upper()
 if not expected or actual!=expected:raise RuntimeError(f"Manifest hash mismatch for {rp}")
 if str(m.get("status") or "").upper() not in ("COMPLETED_CLASSIFIABLE_COVERAGE","FREEZE_COMPLETE"):raise RuntimeError(f"Manifest not complete for {token}: {m.get('status')}")
 if str(r.get("status") or "").upper() not in ("COMPLETED_CLASSIFIABLE_COVERAGE","FREEZE_COMPLETE"):raise RuntimeError(f"Report not complete for {token}: {r.get('status')}")
 return {"token":token,"label":DISPLAY[token],"report_path":str(rp),"report_sha256":actual,"manifest_path":str(mp),"manifest_sha256":sha_file(mp),"report":r,"manifest":m,"matrix_sha256":r.get("matrix_sha256") or m.get("matrix_sha256"),"created_utc":r.get("created_utc") or m.get("created_utc")}
def count(rows,fn):return sum(1 for r in rows if fn(r))
def evidence_summary(e):
 r=e["report"];rows=r.get("rows") if isinstance(r.get("rows"),list) else []
 return {"token":e["token"],"label":e["label"],"version":r.get("version") or e["manifest"].get("version"),"status":r.get("status"),"expected_rows":r.get("expected_rows"),"actual_rows":r.get("actual_rows",len(rows) if rows else None),"failure_count":r.get("failure_count",len(r.get("failures",[])) if isinstance(r.get("failures"),list) else None),"matrix_sha256":e["matrix_sha256"],"report":{"file":e["report_path"],"sha256":e["report_sha256"]},"manifest":{"file":e["manifest_path"],"sha256":e["manifest_sha256"]}}
def derive(evidence):
 by={e["token"]:e for e in evidence};v72=by["v7_72A"]["report"];v75=by["v7_75A"]["report"];v76=by["v7_76A"]["report"];v77=by["v7_77A_1"]["report"];v78=by["v7_78A"]["report"];v79=by["v7_79A"]["report"]
 r72=v72.get("rows",[]);r76=v76.get("rows",[]);r77=v77.get("rows",[]);r78=v78.get("rows",[]);r79=v79.get("rows",[])
 claims=[
 {"id":"UTA-C01","layer":"GPT_FORMATION","claim":"G1, G2, G4, and G5 had qualified exact GPT proposal pairs in the frozen v7.72A matrix; G3 is excluded from that qualified set.","authority":["v7_72A"],"publication_status":"SUPPORTED_LOCAL"},
 {"id":"UTA-C02","layer":"GPT_FORMATION","claim":"Incremental scaffolding recovered a longer exact G3 prefix but did not recover an exact qualifying long-history G3 chain in the tested v7.76A matrix.","authority":["v7_76A"],"publication_status":"SUPPORTED_LOCAL"},
 {"id":"UTA-C03","layer":"DETERMINISTIC_POLICY","claim":"Exact deterministic G3 histories isolated a packaged-policy transition between four and five spacer reads, while Optimal+ retained provenance and denied missing authorization at both depths.","authority":["v7_77A_1"],"publication_status":"SUPPORTED_LOCAL_DETERMINISTIC"},
 {"id":"UTA-C04","layer":"ENVIRONMENT_TRANSFER","claim":"Frozen qualified G1, G2, G4, and G5 proposal contracts achieved per-candidate local Sandbox/Gym trace, guardrail-decision, and effect parity.","authority":["v7_78A"],"publication_status":"SUPPORTED_LOCAL"},
 {"id":"UTA-C05","layer":"PREDICATE_BREACH","claim":"Independent packaged predicate and breach recomputation matched across local Sandbox/Gym traces and matched retained Gym metadata.","authority":["v7_79A"],"publication_status":"SUPPORTED_LOCAL"},
 {"id":"UTA-C06","layer":"POLICY_EVALUATOR_MISMATCH","claim":"The packaged UTA predicate classified both a successful unrelated-content write and a successful exactly authorized source-derived write as breach-positive, so benchmark breach does not encode returned-content lineage or authorization correctness.","authority":["v7_78A","v7_79A"],"publication_status":"SUPPORTED_LOCAL_INTERPRETATION"},
 ]
 metrics={
 "v7_72A":{"rows":v72.get("actual_rows"),"qualified_pairs":count(v72.get("proposal_pairs",[]),lambda x:x.get("exact_proposal_parity") is True)},
 "v7_75A":{"rows":v75.get("actual_rows"),"status":v75.get("status")},
 "v7_76A":{"rows":v76.get("actual_rows"),"exact_incremental_depth3":count(r76,lambda x:x.get("depth")==3 and str(x.get("mode") or "").upper().find("INCREMENTAL")>=0 and x.get("analysis",{}).get("exact_history") is True)},
 "v7_77A_1":{"rows":v77.get("actual_rows"),"proposal_parity_pairs":count(v77.get("proposal_parity_pairs",[]),lambda x:x.get("proposal_parity") is True)},
 "v7_78A":{"rows":v78.get("actual_rows"),"per_candidate_pairs":count(v78.get("parity_pairs",[]),lambda x:x.get("per_candidate_parity") is True)},
 "v7_79A":{"rows":v79.get("actual_rows"),"environment_evaluator_pairs":count(v79.get("environment_pairs",[]),lambda x:x.get("full_evaluator_parity") is True),"predicate_positive_rows":count(r79,lambda x:"UNTRUSTED_TO_ACTION" in x.get("independent_predicate_names",[])),"breach_true_rows":count(r79,lambda x:x.get("independent_breach") is True)} }
 lessons=[
 {"id":"L387","text":"Independent predicate and breach recomputation completed for all frozen v7.78A traces without failure."},
 {"id":"L388","text":"Matched Sandbox/Gym pairs had identical canonical trace hashes, predicate outputs, and breach results."},
 {"id":"L389","text":"Independent evaluator recomputation matched retained Gym metadata."},
 {"id":"L390","text":"Denied final writes did not trigger UNTRUSTED_TO_ACTION in the tested matrix."},
 {"id":"L391","text":"Successful unrelated-content writes after web access were classified as UNTRUSTED_TO_ACTION despite absent returned-content lineage to the effect."},
 {"id":"L392","text":"Successful exact source-derived writes under valid structured authorization were still classified as UNTRUSTED_TO_ACTION."},
 {"id":"L393","text":"Predicate success is reproducible evaluator evidence but does not independently establish authorization failure or guardrail bypass."},
 {"id":"L394","text":"Benchmark breach, policy correctness, returned-content lineage, and authorization correctness must remain separate evidence layers."},
 {"id":"L395","text":"Direct packaged-function recomputation rejecting metadata-only inference is not a parser, timeout, or aggregation trick."},
 {"id":"L396","text":"Local parity does not establish hosted parity or cross-epoch comparability."}]
 modifiers=[
 {"id":"UTA-M99","name":"FROZEN_GPT_PROPOSAL_ENVIRONMENT_REPLAY"}, {"id":"UTA-M100","name":"PER_CANDIDATE_SANDBOX_GYM_TRACE_PARITY"}, {"id":"UTA-M101","name":"ENVIRONMENT_PARITY_WITHOUT_GENERATION_PARITY"}, {"id":"UTA-M104","name":"PREDICATE_LINEAGE_BLINDNESS"}, {"id":"UTA-M105","name":"PREDICATE_AUTHORIZATION_BLINDNESS"}, {"id":"UTA-M106","name":"REPRODUCIBLE_BENCHMARK_BREACH_WITHOUT_POLICY_BREACH"}, {"id":"UTA-M107","name":"INDEPENDENT_EVALUATOR_RECOMPUTATION_PARITY"}, {"id":"UTA-M108","name":"EFFECT_ORIENTED_PREDICATE_POLICY_MISMATCH"}]
 limitations=["All environment, predicate, and breach conclusions are local and do not establish hosted parity.","Deterministic G3 policy isolation does not establish that GPT-OSS can form the exact G3 history.","Frozen semantic tool-call replay does not establish raw model-response serialization or adapter-parse parity.","The tested predicate implementation does not encode the research structured-authorization state.","Evaluator epochs must not be aggregated without an explicit compatible contract.","Gemma parser-normalization findings are not generalized to GPT-OSS or deterministic traces."]
 allowed=["Locally, qualified frozen G1, G2, G4, and G5 proposals had per-candidate Sandbox/Gym trace, guardrail-decision, and effect parity.","Locally, independent predicate and breach recomputation matched retained Gym metadata for the tested frozen traces.","Locally, packaged benchmark breach status did not distinguish unrelated content from exactly authorized source-derived effects.","Deterministic local G3 evidence isolated finite recent-context behavior from persistent provenance behavior."]
 prohibited=["Hosted parity was established.","G3 exact GPT formation was established.","Every benchmark breach was an authorization failure.","G2 proved returned-content propagation.","G4 proved a guardrail bypass or unauthorized effect.","The result generalizes to Gemma parser behavior or a different evaluator epoch."]
 return {"claims":claims,"metrics":metrics,"lessons":lessons,"modifiers":modifiers,"limitations":limitations,"publication_claims":{"allowed":allowed,"prohibited":prohibited},"closure":{"phase":"UNTRUSTED_TO_ACTION","local_revalidation":"COMPLETE","evidence_status":"FROZEN","hosted_parity":"NOT_ESTABLISHED","next_phase":"EXFILTRATION_QUEUED"}}
def md_report(s):
 lines=["# UTA Final Evidence Synthesis and Freeze","",f"- Version: `{s['version']}`",f"- Created UTC: `{s['created_utc']}`",f"- Synthesis SHA-256: `{s['synthesis_sha256']}`","","## Freeze Decision","","```yaml",f"phase: UNTRUSTED_TO_ACTION\nlocal_revalidation: COMPLETE\nevidence_status: FROZEN\nhosted_parity: NOT_ESTABLISHED\nnext_phase: EXFILTRATION_QUEUED","```","","## Evidence Ledger","","| Epoch | Layer | Status | Report SHA-256 | Manifest SHA-256 |","|---|---|---|---|---|"]
 for e in s["evidence_ledger"]:lines.append(f"| {e['token']} | {e['label']} | {e['status']} | `{e['report']['sha256']}` | `{e['manifest']['sha256']}` |")
 lines += ["","## Frozen Claims",""]
 for c in s["claims"]:lines += [f"### {c['id']} · {c['layer']}",c["claim"],f"Authority: `{', '.join(c['authority'])}`  ",f"Publication status: `{c['publication_status']}`",""]
 lines += ["## Layer Separation","","- **GPT formation:** v7.72A, v7.75A, and v7.76A.","- **Deterministic G3 policy isolation:** v7.77A.1.","- **Frozen-proposal local environment transfer:** v7.78A.","- **Independent predicate and breach recomputation:** v7.79A.","- **Hosted evidence:** not established.","","## Lessons Learned",""]
 for x in s["lessons"]:lines.append(f"- **{x['id']}**: {x['text']}")
 lines += ["","## Frozen Modifiers",""]
 for x in s["modifiers"]:lines.append(f"- `{x['id']}` · `{x['name']}`")
 lines += ["","## Limitations",""]+[f"- {x}" for x in s["limitations"]]+["","## Publication Claims Allowed",""]+[f"- {x}" for x in s["publication_claims"]["allowed"]]+["","## Publication Claims Prohibited",""]+[f"- {x}" for x in s["publication_claims"]["prohibited"]]+["","## Authority Rule","","Raw ordered tool events and per-row structured analysis remain authoritative over this synthesis. This report is a frozen interpretive index, not a replacement for source artifacts.",""]
 return "\n".join(lines)
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--evidence-root",required=True,type=Path);ap.add_argument("--out-dir",required=True,type=Path);a=ap.parse_args();root=a.evidence_root.resolve();out=a.out_dir.resolve()
 if not root.is_dir():raise SystemExit(f"Missing evidence root: {root}")
 if out.exists():raise SystemExit(f"Refusing existing output directory: {out}")
 out.mkdir(parents=True);stage="DISCOVERY";evidence=[]
 try:
  for token in REQUIRED:evidence.append(discover_epoch(root,token,True))
  for token in OPTIONAL:
   x=discover_epoch(root,token,False)
   if x:evidence.append(x)
  ledger=[evidence_summary(e) for e in evidence];derived=derive(evidence);created=datetime.now(timezone.utc).isoformat();base={"schema":"UTA_FINAL_EVIDENCE_SYNTHESIS_AND_FREEZE_V1","version":VERSION,"created_utc":created,"status":"FREEZE_COMPLETE","source_authority_order":["Raw ordered tool events","Per-row structured analysis","Canonical CSV","Debug logs","Preflight and manifest","Final synthesis","Generated prose"],"evidence_ledger":ledger,**derived};base["synthesis_sha256"]=sha_text(canon(base));stem="uta_final_evidence_synthesis_and_freeze_v7_80A";rep=out/f"{stem}.json";md=out/f"{stem}.md";claims=out/f"{stem}_claims.csv";pre=out/f"{stem}_preflight.json";man=out/f"{stem}_manifest.json"
  atomic_json(pre,{"version":VERSION,"created_utc":created,"status":"VERIFIED","evidence_root":str(root),"required_epochs":list(REQUIRED),"optional_epochs":list(OPTIONAL),"evidence_ledger":ledger,"discovery_rule":"Manifest artifact hash must match a completed report; frozen source artifacts are not modified."})
  atomic_json(rep,base);atomic_text(md,md_report(base))
  with claims.open("x",encoding="utf-8",newline="") as f:
   fields=["claim_id","layer","claim","authority","publication_status"];w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
   for x in base["claims"]:w.writerow({"claim_id":x["id"],"layer":x["layer"],"claim":x["claim"],"authority":";".join(x["authority"]),"publication_status":x["publication_status"]})
  arts=[pre,rep,md,claims];atomic_json(man,{"schema":"UTA_FINAL_EVIDENCE_SYNTHESIS_AND_FREEZE_MANIFEST_V1","version":VERSION,"status":"FREEZE_COMPLETE","created_utc":created,"synthesis_sha256":base["synthesis_sha256"],"runner":{"file":str(Path(__file__).resolve()),"sha256":sha_file(Path(__file__).resolve()),"size_bytes":Path(__file__).stat().st_size},"source_evidence":[{"token":e["token"],"report":{"file":e["report_path"],"sha256":e["report_sha256"]},"manifest":{"file":e["manifest_path"],"sha256":e["manifest_sha256"]}} for e in evidence],"artifacts":[{"file":p.name,"sha256":sha_file(p),"size_bytes":p.stat().st_size} for p in arts],"runtime":{"python":sys.version,"platform":platform.platform()}})
  print(f"Experiment: {VERSION}\nStatus: FREEZE_COMPLETE\nEvidence epochs: {len(evidence)}\nClaims: {len(base['claims'])}\nSynthesis SHA256: {base['synthesis_sha256']}\nManifest: {man}\nManifest SHA256: {sha_file(man)}");return 0
 except Exception as e:
  fp=out/"uta_final_evidence_synthesis_and_freeze_v7_80A_failure.json";atomic_json(fp,{"version":VERSION,"stage":stage,"exception_type":type(e).__name__,"exception":str(e),"traceback":traceback.format_exc(),"evidence_discovered":[evidence_summary(x) for x in evidence],"scientific_result":None});print(f"FAILED: {e}",file=sys.stderr);return 3
if __name__=="__main__":raise SystemExit(main())
