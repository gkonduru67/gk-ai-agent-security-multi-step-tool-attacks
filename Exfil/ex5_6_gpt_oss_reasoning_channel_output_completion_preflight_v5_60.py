#!/usr/bin/env python3
"""EX5.6 GPT-OSS reasoning-channel and output-completion preflight v5.60.

Read-only static preflight. It hash-binds the exact llama-server startup command,
version evidence, and supplied local contract/source files; inventories relevant
flags and source passages; and decides whether one matched server-output-channel
intervention is scientifically authorized. It never starts/stops a server,
contacts a model endpoint, reruns a model, modifies a prompt, or executes the
captured startup command.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,re,shlex
from pathlib import Path
from typing import Any
VERSION='EX5_6_GPT_OSS_REASONING_CHANNEL_AND_OUTPUT_COMPLETION_PREFLIGHT_v5.60'
TERMS=(
 'reasoning_content','reasoning_format','reasoning-format','reasoning','analysis',
 'chat_template','chat-template','jinja','tool_calls','tool-call','function_call',
 'finish_reason','max_tokens','n_predict','ctx-size','context-size','version'
)
SENSITIVE_RE=re.compile(r'(?i)(api[_-]?key|token|secret|password|authorization)')
def hb(b:bytes)->str:return hashlib.sha256(b).hexdigest().upper()
def hs(x:Any)->str:return hb(str(x).encode('utf-8'))
def hf(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def dump(p:Path,x:Any):
 with p.open('x',encoding='utf-8') as f:json.dump(x,f,indent=2,sort_keys=True,default=str);f.write('\n')
def csvout(p:Path,fields:list[str],rows:list[dict[str,Any]]):
 with p.open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def safe_tokens(command:str)->list[dict[str,Any]]:
 try:tokens=shlex.split(command,posix=False)
 except Exception:tokens=command.split()
 rows=[];redact_next=False
 for i,t in enumerate(tokens):
  key=t.split('=',1)[0]
  sensitive=redact_next or bool(SENSITIVE_RE.search(key))
  if sensitive:
   rows.append({'index':i,'token':None,'token_sha256':hs(t),'sensitive':True})
  else:
   rows.append({'index':i,'token':t,'token_sha256':hs(t),'sensitive':False})
  redact_next=bool(SENSITIVE_RE.search(t)) and '=' not in t
 return rows
def flags(tokens:list[dict[str,Any]])->list[dict[str,Any]]:
 out=[];i=0
 while i<len(tokens):
  t=tokens[i].get('token')
  if isinstance(t,str) and t.startswith('-'):
   if '=' in t:k,v=t.split('=',1)
   else:
    k=t;v=None
    if i+1<len(tokens):
     n=tokens[i+1].get('token')
     if isinstance(n,str) and not n.startswith('-'):v=n
   out.append({'flag':k,'value':v,'value_sha256':hs(v) if v is not None else None})
  i+=1
 return out
def inspect_file(p:Path)->tuple[dict[str,Any],list[dict[str,Any]]]:
 b=p.read_bytes();text=b.decode('utf-8','replace');matches=[]
 lines=text.splitlines()
 for no,line in enumerate(lines,1):
  low=line.lower();hits=sorted({t for t in TERMS if t.lower() in low})
  if hits:
   matches.append({'file':p.name,'line_number':no,'line_sha256':hs(line),'line_length':len(line),'matched_terms':','.join(hits)})
 return ({'file':p.name,'path_sha256':hs(str(p.resolve())),'size_bytes':len(b),'sha256':hb(b),'line_count':len(lines),'match_count':len(matches)},matches)
def main():
 ap=argparse.ArgumentParser()
 ap.add_argument('--startup-command-file',required=True,type=Path)
 ap.add_argument('--server-version-file',required=True,type=Path)
 ap.add_argument('--contract-file',action='append',default=[],type=Path)
 ap.add_argument('--expected-prompt-sha256',default='3F8BA146E8B3DEDD45EBB4D276A6D55F0BEC8C7C0EFAC2B272B3B21239635176')
 ap.add_argument('--expected-model-sha256',default='C27536640E410032865DC68781D80A08B98F8DB5E93575919AF8CCC0568AEB4F')
 ap.add_argument('--expected-pipeline-sha256',default='88970AC7329F6BB25351DEFF1FB6F3E81F2148EFEA20CEEE43AEC45B1C398DF9')
 ap.add_argument('--out-root',required=True,type=Path)
 a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 for p in [a.startup_command_file,a.server_version_file,*a.contract_file]:
  if not p.is_file():ap.error(f'Not found: {p}')
 out.mkdir(parents=True)
 command=a.startup_command_file.read_text(encoding='utf-8',errors='replace').strip();tok=safe_tokens(command);flg=flags(tok)
 file_rows=[];match_rows=[]
 for p in [a.startup_command_file,a.server_version_file,*a.contract_file]:
  fr,mr=inspect_file(p.resolve());file_rows.append(fr);match_rows.extend(mr)
 flag_names={str(x['flag']).lower() for x in flg}
 contract_terms={t for r in match_rows for t in str(r['matched_terms']).split(',') if t}
 reasoning_contract=any(t in contract_terms for t in ('reasoning_content','reasoning_format','reasoning-format'))
 tool_contract=any(t in contract_terms for t in ('tool_calls','tool-call','function_call'))
 finish_contract='finish_reason' in contract_terms
 startup_reasoning_flag=any(any(k in n for k in ('reason','jinja','chat-template','chat_template')) for n in flag_names)
 sufficient=bool(a.contract_file) and reasoning_contract and tool_contract and finish_contract
 authorization='ONE_MATCHED_SERVER_OUTPUT_CHANNEL_INTERVENTION_AUTHORIZED' if sufficient else 'INTERVENTION_WITHHELD_CONTRACT_INCOMPLETE'
 result={
  'schema':'EX5_6_V5_60','version':VERSION,'model_rerun_performed':False,
  'server_started_or_stopped':False,'startup_command_executed':False,'prompt_modified':False,
  'startup_command_sha256':hs(command),'startup_command_token_count':len(tok),
  'server_version_file_sha256':hf(a.server_version_file),
  'contract_file_count':len(a.contract_file),'reasoning_contract_found':reasoning_contract,
  'tool_call_contract_found':tool_contract,'finish_reason_contract_found':finish_contract,
  'startup_reasoning_or_template_flag_found':startup_reasoning_flag,
  'expected_prompt_sha256':a.expected_prompt_sha256.upper(),
  'expected_model_sha256':a.expected_model_sha256.upper(),
  'expected_pipeline_sha256':a.expected_pipeline_sha256.upper(),
  'preflight_complete':sufficient,'intervention_authorization':authorization,
  'allowed_intervention_count':1 if sufficient else 0,
  'intervention_constraint':'Change exactly one documented server output-channel control; keep frozen prompt, model, tools, GuardrailBase, max_tool_hops, and agent pipeline fixed.',
  'advancement_gate':'visible_message_content_length > 0 OR structured_tool_calls_count > 0',
  'attack_optimization_authorized':False
 }
 dump(out/'ex5_6_preflight.json',result)
 csvout(out/'ex5_6_startup_tokens.csv',['index','token','token_sha256','sensitive'],tok)
 csvout(out/'ex5_6_startup_flags.csv',['flag','value','value_sha256'],flg)
 csvout(out/'ex5_6_source_inventory.csv',['file','path_sha256','size_bytes','sha256','line_count','match_count'],file_rows)
 csvout(out/'ex5_6_contract_matches.csv',['file','line_number','line_sha256','line_length','matched_terms'],match_rows)
 files=[p for p in out.iterdir() if p.is_file()]
 csvout(out/'ex5_6_manifest.csv',['artifact','size_bytes','sha256'],[{'artifact':p.name,'size_bytes':p.stat().st_size,'sha256':hf(p)} for p in files])
 print(json.dumps(result,indent=2));return 0 if sufficient else 2
if __name__=='__main__':raise SystemExit(main())
