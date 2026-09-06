#!/usr/bin/env python3
"""Static inspection of Sandbox guardrail-context construction and Gym delegation.

No SDK module is imported and no model/tool execution occurs. Exact AST-derived
line ranges are used to avoid the line-offset defect documented for v7.70A.
"""
from __future__ import annotations
import argparse, ast, hashlib, json, os, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="UTA_SANDBOX_CONTEXT_CONSTRUCTION_INSPECTION_v7.70B"
EXPECTED={
 "sandbox.py":"B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0",
 "gym.py":"8BBC3479515C388717D76FE9964D957A7CBD9BFB97C28AA894E9C51E3051F8AF",
 "optimal.py":"6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED",
}

def sha_file(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def sha_text(s):return hashlib.sha256(s.encode('utf-8')).hexdigest().upper()
def atomic_json(p,v):
 if p.exists():raise FileExistsError(f'Refusing overwrite: {p}')
 t=p.with_name(p.name+'.tmp');t.write_text(json.dumps(v,indent=2,ensure_ascii=True)+'\n',encoding='ascii');os.replace(t,p)
def parse(p):return ast.parse(p.read_text(encoding='utf-8'),filename=str(p))
def method(tree,cls,name):
 for n in tree.body:
  if isinstance(n,ast.ClassDef) and n.name==cls:
   for c in n.body:
    if isinstance(c,(ast.FunctionDef,ast.AsyncFunctionDef)) and c.name==name:return c
 raise RuntimeError(f'Missing {cls}.{name}')
def excerpt(lines,node,label):
 a=node.lineno;b=getattr(node,'end_lineno',a);txt='\n'.join(lines[a-1:b])
 return {'label':label,'start_line':a,'end_line':b,'text':'\n'.join(f'{i}: {lines[i-1]}' for i in range(a,b+1)),'sha256':sha_text(txt)}
def find_assign_to_name(node,name):
 for n in ast.walk(node):
  if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets):return n
 raise RuntimeError(f'Missing assignment {name}')
def find_call_stmt(node,attr):
 for n in ast.walk(node):
  if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr==attr:return n
 raise RuntimeError(f'Missing call {attr}')
def find_if_contains(node,literal):
 for n in ast.walk(node):
  if isinstance(n,ast.If) and literal in ast.unparse(n.test):return n
 raise RuntimeError(f'Missing if {literal}')
def verify_parent(report,manifest):
 r=json.loads(report.read_text(encoding='utf-8'));m=json.loads(manifest.read_text(encoding='utf-8'));act=sha_file(report);hit=next((x for x in m.get('artifacts',[]) if Path(str(x.get('file') or '')).name.lower()==report.name.lower()),None)
 ok=bool(hit and str(hit.get('sha256') or '').upper()==act and r.get('status')=='INSPECTION_COMPLETE')
 if not ok:raise RuntimeError('v7.70A verification failed')
 return {'report':str(report),'report_sha256':act,'manifest':str(manifest),'manifest_sha256':sha_file(manifest),'verified':True}

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--project-root',required=True,type=Path);ap.add_argument('--v770a-report',required=True,type=Path);ap.add_argument('--v770a-manifest',required=True,type=Path);ap.add_argument('--out-dir',required=True,type=Path);a=ap.parse_args()
 root=a.project_root.resolve();out=a.out_dir.resolve();parent=a.v770a_report.resolve();pm=a.v770a_manifest.resolve();files={'sandbox.py':root/'aicomp_sdk/core/env/sandbox.py','gym.py':root/'aicomp_sdk/core/env/gym.py','optimal.py':root/'aicomp_sdk/guardrails/optimal.py'}
 if out.exists():raise SystemExit(f'Refusing existing output directory: {out}')
 for p in [*files.values(),parent,pm]:
  if not p.is_file():raise SystemExit(f'Missing required file: {p}')
 out.mkdir(parents=True)
 try:
  for n,p in files.items():
   if sha_file(p)!=EXPECTED[n]:raise RuntimeError(f'{n} hash mismatch: {sha_file(p)}')
  pv=verify_parent(parent,pm);st=parse(files['sandbox.py']);gt=parse(files['gym.py']);sl=files['sandbox.py'].read_text(encoding='utf-8').splitlines();gl=files['gym.py'].read_text(encoding='utf-8').splitlines();interact=method(st,'SandboxEnv','interact');reset=method(st,'SandboxEnv','reset');snapshot=method(st,'SandboxEnv','snapshot');restore=method(st,'SandboxEnv','restore');record_failed=method(st,'SandboxEnv','_record_failed_tool_attempt');gym_init=method(gt,'GymAttackEnv','__init__');gym_step=method(gt,'GymAttackEnv','step');gym_reset=method(gt,'GymAttackEnv','reset');gym_interact=method(gt,'GymAttackEnv','interact');gym_summary=method(gt,'GymAttackEnv','_trace_summary')
  ctx_assign=find_assign_to_name(interact,'ctx');guard_call=find_call_stmt(interact,'decide');deny_if=find_if_contains(interact,'guardrail_decision.action == \'DENY\'');tool_event_call=None
  for n in ast.walk(interact):
   if isinstance(n,ast.Call) and ((isinstance(n.func,ast.Name) and n.func.id=='ToolEvent') or (isinstance(n.func,ast.Attribute) and n.func.attr=='ToolEvent')) and any(k.arg=='ok' for k in n.keywords):tool_event_call=n;break
  if tool_event_call is None:raise RuntimeError('Missing successful ToolEvent construction')
  gym_sandbox_call=None
  for n in ast.walk(gym_init):
   if isinstance(n,ast.Call) and ((isinstance(n.func,ast.Name) and n.func.id=='SandboxEnv') or (isinstance(n.func,ast.Attribute) and n.func.attr=='SandboxEnv')):gym_sandbox_call=n;break
  if gym_sandbox_call is None:raise RuntimeError('Missing Gym SandboxEnv construction')
  ex={
   'guardrail_context_creation':excerpt(sl,ctx_assign,'ctx assignment'),
   'guardrail_decide_call':excerpt(sl,guard_call,'guardrail.decide call'),
   'denied_event_path':excerpt(sl,deny_if,'DENY recording and break'),
   'failed_event_construction':excerpt(sl,record_failed,'_record_failed_tool_attempt'),
   'successful_event_construction':excerpt(sl,tool_event_call,'successful ToolEvent construction'),
   'sandbox_reset':excerpt(sl,reset,'SandboxEnv.reset'),
   'sandbox_snapshot':excerpt(sl,snapshot,'SandboxEnv.snapshot'),
   'sandbox_restore':excerpt(sl,restore,'SandboxEnv.restore'),
   'gym_wraps_sandbox':excerpt(gl,gym_sandbox_call,'GymAttackEnv creates SandboxEnv'),
   'gym_step_delegation':excerpt(gl,gym_step,'GymAttackEnv.step'),
   'gym_interact_delegation':excerpt(gl,gym_interact,'GymAttackEnv.interact'),
   'gym_reset_delegation':excerpt(gl,gym_reset,'GymAttackEnv.reset'),
   'gym_observation_summary':excerpt(gl,gym_summary,'Gym observation trace summary'),
  }
  questions=[
   {'id':'Q1','question':'Where is guardrail context created?','answer':'Inside SandboxEnv.interact immediately before PRE_GUARDRAIL hooks and guardrail.decide. The local ctx mapping contains seed, recent_sources, recent_tools, last_user, side_effect, and scope. PRE_GUARDRAIL receives this mapping, but guardrail.decide is called with the original ctx variable.','status':'SOURCE_CONFIRMED','evidence':['guardrail_context_creation','guardrail_decide_call']},
   {'id':'Q2','question':'How is recent_sources populated?','answer':'It is rebuilt for each proposed known tool as [event.source for event in self.trace.tool_events[-5:]]. It uses recorded ToolEvent.source values from the last five trace tool events.','status':'SOURCE_CONFIRMED','evidence':['guardrail_context_creation']},
   {'id':'Q3','question':'Do only successful source events qualify?','answer':'No explicit ok filter is applied when recent_sources is constructed. Both successful and failed recorded tool events can contribute their source value if they are within the last five events. The exact source on a failed event is assigned from self.tools.last_source by _record_failed_tool_attempt.','status':'SOURCE_CONFIRMED','evidence':['guardrail_context_creation','failed_event_construction']},
   {'id':'Q4','question':'What is the exact history window?','answer':'The guardrail context window is the last five recorded tool events for both recent_sources and recent_tools. Gym observation summaries use a separate last-eight tool/source window, compacted to four only if the JSON summary exceeds its size limit.','status':'SOURCE_CONFIRMED','evidence':['guardrail_context_creation','gym_observation_summary']},
   {'id':'Q5','question':'How is user_authorized derived?','answer':'SandboxEnv.interact does not place user_authorized in ctx and sandbox.py contains no user_authorized token. The packaged optimal default therefore remains false through context.get unless a different caller or modification supplies the key. PRE_GUARDRAIL hooks receive ctx, but this file then calls decide with the original ctx variable; the source does not show replacement of ctx from the hook object.','status':'SOURCE_CONFIRMED_FOR_SANDBOX_FILE','evidence':['guardrail_context_creation','guardrail_decide_call']},
   {'id':'Q6','question':'How is user_confirmed_safe derived?','answer':'SandboxEnv.interact does not place user_confirmed_safe in ctx and sandbox.py contains no user_confirmed_safe token. The packaged optimal default therefore remains false through context.get unless another caller or mutation supplies the key.','status':'SOURCE_CONFIRMED_FOR_SANDBOX_FILE','evidence':['guardrail_context_creation','guardrail_decide_call']},
   {'id':'Q7','question':'What are reset and persistence behaviors?','answer':'Within an environment, trace tool events persist across interact calls until reset. reset replaces the trace, runtime history, last tool output, tool state, hook state, guardrail state, and agent state with initial/reset values. snapshot captures trace, runtime history, last output, tools, guardrail, agent, hooks, and filesystem; restore reinstates them.','status':'SOURCE_CONFIRMED','evidence':['sandbox_reset','sandbox_snapshot','sandbox_restore']},
   {'id':'Q8','question':'What context is passed on denied events?','answer':'The proposed action is evaluated with ctx before the denial. If the guardrail returns DENY, Sandbox records a failed ToolEvent with ok false, the proposed arguments, side effect, scope, source equal to tools.last_source, and error prefixed denied:, then breaks. That failed event can enter the recent_sources/recent_tools window of a later interact call.','status':'SOURCE_CONFIRMED','evidence':['guardrail_context_creation','guardrail_decide_call','denied_event_path','failed_event_construction']},
   {'id':'Q9','question':'What context is supplied to Gym?','answer':'GymAttackEnv constructs and owns a SandboxEnv with the same agent, guardrail, fixtures, and hook registry. step delegates the user action to self._sandbox.interact. It does not create a separate guardrail context. Gym observation summaries expose their own last-eight recent tool/source view, but that observation window is not the ctx passed to the guardrail.','status':'SOURCE_CONFIRMED','evidence':['gym_wraps_sandbox','gym_step_delegation','gym_observation_summary']},
   {'id':'Q10','question':'Does it preserve provenance across intermediate events?','answer':'Sandbox preserves only coarse source labels for the last five recorded tool events in guardrail ctx. It does not place source event IDs, source success, source output hashes, or final-argument lineage in ctx. A web/email label therefore remains visible across at most four later recorded events and ages out once five newer events occupy the window. This is access-context persistence, not returned-content lineage.','status':'SOURCE_CONFIRMED','evidence':['guardrail_context_creation','successful_event_construction','failed_event_construction']},
  ]
  text=files['sandbox.py'].read_text(encoding='utf-8');tokens={k:(k in text) for k in ['user_authorized','user_confirmed_safe','recent_sources','recent_tools','last_user','side_effect','scope']}
  result={'schema':'UTA_SANDBOX_CONTEXT_CONSTRUCTION_INSPECTION_V1','version':VERSION,'created_utc':datetime.now(timezone.utc).isoformat(),'status':'INSPECTION_COMPLETE','method':'Static AST/source inspection only; SDK modules were not imported or executed.','sources':{n:{'path':str(p),'sha256':sha_file(p),'size_bytes':p.stat().st_size,'line_count':len(p.read_text(encoding="utf-8").splitlines()),'ast_parse':'OK'} for n,p in files.items()},'parent_evidence':pv,'token_presence_in_sandbox':tokens,'evidence_excerpts':ex,'questions':questions,'central_conclusion':'Sandbox constructs packaged-optimal context from the last five recorded ToolEvents without filtering by success and without adding user_authorized or user_confirmed_safe. Gym delegates execution to SandboxEnv and therefore uses Sandbox guardrail-context construction; Gym trace observations have a separate last-eight summary window. The guardrail context preserves coarse access labels, not returned-content lineage.','weakness_updates':[{'id':'W1','name':'COARSE_SOURCE_CONTEXT_TAINT','status':'END_TO_END_SOURCE_CONFIRMED','detail':'Sandbox supplies only recent source labels; no output-to-argument lineage fields.'},{'id':'W2','name':'UNSCOPED_BOOLEAN_AUTHORIZATION_SHORT_CIRCUIT','status':'POLICY_PRESENT_SANDBOX_UNREACHABLE_BY_DEFAULT','detail':'optimal.py reads the booleans, but Sandbox ctx does not create them.'},{'id':'W3','name':'NO_AUTHORIZATION_TOOL_TARGET_CONTENT_BINDING','status':'SOURCE_CONFIRMED_BUT_DEFAULT_SANDBOX_AUTH_CONTEXT_ABSENT','detail':'No structured authorization object is passed.'},{'id':'W4','name':'NO_CARDINALITY_EXPIRY_REVOCATION_ENFORCEMENT','status':'END_TO_END_SOURCE_CONFIRMED','detail':'Neither Sandbox ctx nor optimal.py supplies these controls.'},{'id':'W5','name':'UPSTREAM_HISTORY_WINDOW_DEPENDENCY','status':'RESOLVED_TO_EXACT_WINDOW_5','detail':'recent_sources/recent_tools use trace.tool_events[-5:].'},{'id':'W6','name':'DORMANT_UNTRUSTED_MENTIONS_STATE_IN_DECIDE','status':'SOURCE_CONFIRMED','detail':'Sandbox does not call track_untrusted_content in the guardrail decision path shown.'},{'id':'W7','name':'FAILED_EVENT_SOURCE_CARRYOVER','status':'NEW_SOURCE_CONFIRMED_CANDIDATE','detail':'recent_sources has no ok filter; failed events record source from tools.last_source.'},{'id':'W8','name':'SANDBOX_GYM_OBSERVATION_WINDOW_DIVERGENCE','status':'NEW_SOURCE_CONFIRMED_NON_POLICY_DIFFERENCE','detail':'guardrail ctx window is 5; Gym observation recent tool/source window is 8.'}],'interpretation_boundaries':['Static inspection proves source structure, not dynamic values for a specific run.','A failed event contributing a web/email source requires runtime confirmation of tools.last_source for that sequence.','Gym delegates guardrail decisions to Sandbox, but full parity still requires matched runtime traces and environment configuration.','No attack optimization or Optimal+ implementation is performed in this phase.'],'advancement':{'next_phase':'DETERMINISTIC_SANDBOX_OPTIMAL_CONTEXT_BOUNDARY_MATRIX','eligible':True,'required_focus':['successful versus failed source events','five-event aging boundary','denied-event carryover','absence of Boolean authorization keys','Sandbox versus Gym matched context capture']}}
  stem='uta_sandbox_context_construction_inspection_v7_70B';ro=out/f'{stem}.json';mo=out/f'{stem}.md';mf=out/f'{stem}_manifest.json';atomic_json(ro,result)
  md=[f'# {VERSION}','',f'- Status: INSPECTION_COMPLETE',f'- Sandbox SHA-256: `{EXPECTED["sandbox.py"]}`',f'- Gym SHA-256: `{EXPECTED["gym.py"]}`','','## Answers']
  for q in questions:md += ['',f'### {q["id"]}. {q["question"]}','',q['answer'],'',f'Evidence: {", ".join(q["evidence"])}']
  md += ['','## Central conclusion','',result['central_conclusion'],'','## Next gate','',result['advancement']['next_phase']]
  if mo.exists():raise FileExistsError(mo)
  mo.write_text('\n'.join(md)+'\n',encoding='utf-8');atomic_json(mf,{'schema':'UTA_SANDBOX_CONTEXT_CONSTRUCTION_INSPECTION_FREEZE_V1','version':VERSION,'status':'INSPECTION_COMPLETE','created_utc':datetime.now(timezone.utc).isoformat(),'runner':{'file':str(Path(__file__).resolve()),'sha256':sha_file(Path(__file__).resolve()),'size_bytes':Path(__file__).stat().st_size},'inputs':[{'file':str(p),'sha256':sha_file(p),'size_bytes':p.stat().st_size} for p in [*files.values(),parent,pm]],'artifacts':[{'file':p.name,'sha256':sha_file(p),'size_bytes':p.stat().st_size} for p in [ro,mo]]})
  print(f'Experiment: {VERSION}\nStatus: INSPECTION_COMPLETE\nQuestions answered: 10/10\nReport: {ro}\nManifest: {mf}\nManifest SHA256: {sha_file(mf)}');return 0
 except Exception as e:
  fp=out/'uta_sandbox_context_construction_inspection_v7_70B_failure.json';atomic_json(fp,{'version':VERSION,'status':'FAIL','exception_type':type(e).__name__,'exception':str(e),'scientific_result':None});print(f'FAILED: {e}\nFailure artifact: {fp}',file=sys.stderr);return 3
if __name__=='__main__':raise SystemExit(main())
