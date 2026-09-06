#!/usr/bin/env python3
"""Patch v7.60A.2.1 Preflight 2 to retain actual tool events.

Creates uta_guardrail_boundary_preflight_2_v7_60A_2_2.py beside the input.
The source file is never overwritten.
"""
from pathlib import Path
import argparse

OLD = """def trace_of(result):
 x=getattr(result,'trace',None)
 if x is None:x=result
 x=safe(x)
 if isinstance(x,dict) and isinstance(x.get('trace'),dict):x=x['trace']
 return x if isinstance(x,dict) else {}
"""
NEW = """def _find_tool_event_trace(value,path='root',seen=None,depth=0):
 if seen is None:seen=set()
 if value is None or depth>6:return None
 ident=id(value)
 if ident in seen:return None
 seen.add(ident)
 converted=safe(value)
 if isinstance(converted,dict) and isinstance(converted.get('tool_events'),list):
  return {'path':path,'trace':converted}
 if isinstance(value,dict):items=list(value.items())
 elif hasattr(value,'__dict__'):items=list(vars(value).items())
 else:items=[]
 for key,child in items:
  if str(key).startswith('__'):continue
  found=_find_tool_event_trace(child,f'{path}.{key}',seen,depth+1)
  if found:return found
 if isinstance(value,(list,tuple)):
  for i,child in enumerate(value):
   found=_find_tool_event_trace(child,f'{path}[{i}]',seen,depth+1)
   if found:return found
 return None

def trace_of(result,env):
 candidates=[
  ('result',result),
  ('result.trace',getattr(result,'trace',None)),
  ('result.history',getattr(result,'history',None)),
  ('env._runtime_history',getattr(env,'_runtime_history',None)),
  ('env.runtime_history',getattr(env,'runtime_history',None)),
  ('env.history',getattr(env,'history',None)),
  ('env',env),
 ]
 audit=[]
 for label,obj in candidates:
  audit.append({'candidate':label,'runtime_type':qn(type(obj)) if obj is not None else None})
  found=_find_tool_event_trace(obj,label)
  if found:return found['trace'],{'selected_path':found['path'],'candidates':audit}
 raise RuntimeError('No object containing tool_events was found in result or Sandbox state')
"""

def main():
 ap=argparse.ArgumentParser()
 ap.add_argument('--input',required=True,type=Path)
 ap.add_argument('--output',type=Path)
 a=ap.parse_args();src=a.input.resolve();dst=(a.output.resolve() if a.output else src.with_name('uta_guardrail_boundary_preflight_2_v7_60A_2_2.py'))
 if dst.exists():raise SystemExit(f'Refusing to overwrite: {dst}')
 text=src.read_text(encoding='utf-8')
 if OLD not in text:raise SystemExit('Expected v7.60A.2.1 trace_of block not found; no file written')
 text=text.replace(OLD,NEW)
 text=text.replace('UTA_GUARDRAIL_BOUNDARY_PREFLIGHT_2_v7.60A.2.1','UTA_GUARDRAIL_BOUNDARY_PREFLIGHT_2_v7.60A.2.2')
 text=text.replace("result=env.interact(case['message'],max_tool_hops=a.max_tool_hops);trace=trace_of(result);events=trace.get('tool_events',[]);action=bind_action(case,events);d=decision(action)","result=env.interact(case['message'],max_tool_hops=a.max_tool_hops);trace,trace_adapter=trace_of(result,env);events=trace.get('tool_events',[]);action=bind_action(case,events);d=decision(action)")
 text=text.replace("'trace':trace,'action_event':action,'smoke_pass':all(gates.values())","'trace':trace,'trace_adapter':trace_adapter,'action_event':action,'smoke_pass':all(gates.values())")
 text=text.replace('uta_guardrail_boundary_preflight_2_v7_60A_2_1','uta_guardrail_boundary_preflight_2_v7_60A_2_2')
 dst.write_text(text,encoding='utf-8',newline='\n')
 print(dst)
if __name__=='__main__':main()
