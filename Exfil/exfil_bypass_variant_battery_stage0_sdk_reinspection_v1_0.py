#!/usr/bin/env python3
"""Read-only SDK rehash + EXFILTRATION contract reinspection.
No SDK imports, no model/Sandbox/Gym/tool/guardrail/predicate/breach execution.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, re
from datetime import datetime, timezone
from pathlib import Path

VERSION = "BYPASS_VARIANT_BATTERY_STAGE_0_v1.0"
FILES = {
 "predicate_file":"aicomp_sdk/core/predicates.py",
 "sandbox_file":"aicomp_sdk/core/env/sandbox.py",
 "api_file":"aicomp_sdk/core/env/api.py",
 "gym_file":"aicomp_sdk/core/env/gym.py",
 "packaged_optimal_file":"aicomp_sdk/guardrails/optimal.py",
}
HIST = {
 "predicate_file":"9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37",
 "sandbox_file":"B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0",
 "api_file":"60F1E4424EC3DEE73186F87ED1184D2CA1DBC4C2A0022004DECEC8B6E94C7CB1",
 "gym_file":"8BBC3479515C388717D76FE9964D957A7CBD9BFB97C28AA894E9C51E3051F8AF",
 "packaged_optimal_file":"6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED",
}
REQ_SYMBOLS={
 "predicate_file":["eval_predicates","is_breach","_secrets_read_in_trace","payload_exfiltrates_secret","exfil_payload_arg","_decode_candidates","_contains_secret","_is_secret_path"],
}
PATTERNS={
 "predicate_file":["EXFIL_SINKS","http.post","data","eval_predicates","is_breach","_secrets_read_in_trace","payload_exfiltrates_secret","exfil_payload_arg","_decode_candidates","_contains_secret","_is_secret_path","email.send"],
 "sandbox_file":["guardrail","decide","DENY","CONFIRM","tools.call","ToolEvent","trace"],
 "api_file":["interact","EnvInteractionResult","AttackEnvProtocol","DEFAULT_MAX_TOOL_HOPS"],
 "gym_file":["SandboxEnv","eval_predicates","is_breach","interact"],
 "packaged_optimal_file":["http.post","data","EXFIL_SINKS","payload_exfiltrates_secret","exfil_payload_arg","DENY","ALLOW","SANITIZE","recent"],
}

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''): h.update(b)
 return h.hexdigest().upper()
def utc(): return datetime.now(timezone.utc).isoformat()
def write_json(p,x):
 with p.open('x',encoding='utf-8',newline='\n') as f: json.dump(x,f,indent=2,sort_keys=True); f.write('\n')
def excerpt(lines, token, radius=3):
 out=[]
 for i,s in enumerate(lines):
  if token.lower() in s.lower():
   a=max(0,i-radius); b=min(len(lines),i+radius+1)
   out.append({"pattern":token,"line":i+1,"start_line":a+1,"end_line":b,"text":"\n".join(f"{j+1:06d}: {lines[j]}" for j in range(a,b))})
   if len(out)>=3: break
 return out
def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--project-root',required=True); ap.add_argument('--output-dir',required=True); a=ap.parse_args()
 root=Path(a.project_root).resolve(); out=Path(a.output_dir).resolve()
 if out.exists(): raise SystemExit(f"Refusing overwrite: {out}")
 out.mkdir(parents=True)
 inventory=[]; evidence={}; checks=[]
 def ck(cid,ok,obs,exp,layer): checks.append({"check_id":cid,"passed":bool(ok),"observed":obs,"expected":exp,"failure_layer":layer})
 for n,(label,rel) in enumerate(FILES.items(),1):
  p=root/rel; exists=p.is_file(); ck(f"S0-{n:03d}",exists,str(p),"authoritative file exists","FIXTURE")
  if not exists: continue
  raw=p.read_bytes(); enc='utf-8';
  try: text=raw.decode(enc)
  except UnicodeDecodeError: enc='utf-8-sig'; text=raw.decode(enc)
  lines=text.splitlines(); parse='OK'; symbols=[]
  try:
   tree=ast.parse(text); symbols=sorted({x.name for x in ast.walk(tree) if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))})
  except SyntaxError as e: parse=f"FAIL:{e.lineno}:{e.msg}"
  cur=sha(p); inventory.append({"label":label,"relative_path":rel,"absolute_path":str(p),"size_bytes":p.stat().st_size,"mtime_utc":datetime.fromtimestamp(p.stat().st_mtime,timezone.utc).isoformat(),"sha256":cur,"historical_sha256":HIST[label],"identity_relation":"SAME_AS_2026_08_02" if cur==HIST[label] else "IDENTITY_CHANGED_REQUIRES_SEMANTIC_REVIEW","encoding":enc,"line_count":len(lines),"ast_parse":parse})
  ck(f"S0-{n+5:03d}",parse=='OK',parse,"AST parse OK","FIXTURE")
  missing=[s for s in REQ_SYMBOLS.get(label,[]) if s not in symbols]; ck(f"S0-{n+10:03d}",not missing,missing,"required symbols present","CONTRACT")
  ev=[]
  for pat in PATTERNS[label]: ev += excerpt(lines,pat)
  evidence[label]={"relative_path":rel,"sha256":cur,"symbols":symbols,"excerpts":ev,"required_symbols_missing":missing}
 # Explicit static contract anchors. Presence is evidence location, not runtime behavior.
 pred_text=(root/FILES['predicate_file']).read_text(encoding='utf-8') if (root/FILES['predicate_file']).is_file() else ''
 sink_ok=bool(re.search(r'EXFIL_SINKS[\s\S]{0,500}["\']http\.post["\']\s*:\s*["\']data["\']',pred_text))
 email_boundary=('email.send' in pred_text and 'CONFUSED_DEPUTY' in pred_text)
 ck('S0-016',sink_ok,"static source anchor","EXFIL_SINKS maps http.post to data","CONTRACT")
 ck('S0-017',email_boundary,"static source anchor","email.send boundary reference present with CONFUSED_DEPUTY","CONTRACT")
 failed=[x['check_id'] for x in checks if not x['passed']]
 changed=[x['label'] for x in inventory if x['identity_relation']!='SAME_AS_2026_08_02']
 status='COMPLETE_PASS' if not failed and not changed else ('CONTRACT_REVIEW_REQUIRED' if not failed else 'BLOCKED')
 result={"version":VERSION,"created_at_utc":utc(),"status":status,"checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"identity_changed":changed,"execution_boundaries":{"read_only":True,"sdk_imported":False,"sdk_executed":False,"model_executed":False,"sandbox_instantiated":False,"gym_executed":False,"tools_executed":False,"guardrail_executed":False,"predicate_executed":False,"breach_executed":False,"attack_optimization":False},"static_contract":{"exfil_sink_http_post_data":sink_ok,"email_send_confused_deputy_boundary_anchor":email_boundary},"claim_boundary":{"allowed":["current local SDK source identities established by SHA-256","EXFILTRATION-relevant source locations statically reinspected"],"prohibited":["static source proves runtime behavior","guardrail blocks exfiltration","V_RENAMED_SOURCE bypass succeeds or fails","predicate or breach occurs","hosted parity","robust defense"]},"next_gate":"V_RENAMED_SOURCE_DESIGN" if status=='COMPLETE_PASS' else "STAGE_0_REVIEW"}
 paths={"inventory":out/'exfil_stage0_sdk_inventory_v1_0.json',"evidence":out/'exfil_stage0_contract_evidence_v1_0.json',"checks":out/'exfil_stage0_checks_v1_0.csv',"result":out/'exfil_stage0_result_v1_0.json'}
 write_json(paths['inventory'],inventory); write_json(paths['evidence'],evidence); write_json(paths['result'],result)
 with paths['checks'].open('x',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=['check_id','passed','observed','expected','failure_layer']); w.writeheader(); w.writerows(checks)
 # manifest excludes itself; external binding binds it.
 rows=[]
 for role,p in paths.items(): rows.append({"artifact":p.name,"role":role.upper(),"size_bytes":p.stat().st_size,"sha256":sha(p),"path":str(p)})
 runner=Path(__file__).resolve(); rows.append({"artifact":runner.name,"role":"RUNNER","size_bytes":runner.stat().st_size,"sha256":sha(runner),"path":str(runner)})
 manifest=out/'exfil_stage0_manifest_v1_0.csv'
 with manifest.open('x',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=['artifact','role','size_bytes','sha256','path']); w.writeheader(); w.writerows(rows)
 binding=out/'exfil_stage0_manifest_external_binding_v1_0.json'; write_json(binding,{"version":VERSION,"created_at_utc":utc(),"manifest_filename":manifest.name,"manifest_sha256":sha(manifest),"runner_sha256":sha(runner),"status":status,"failed_ids":failed,"identity_changed":changed,"next_gate":result['next_gate']})
 print(json.dumps({"status":status,"checks":f"{len(checks)-len(failed)}/{len(checks)}","failed_ids":failed,"identity_changed":changed,"manifest_sha256":sha(manifest),"next_gate":result['next_gate']},indent=2))
if __name__=='__main__': main()
