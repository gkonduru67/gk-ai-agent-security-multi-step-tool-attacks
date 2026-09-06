#!/usr/bin/env python3
"""Repair launcher v4 for UTA_DETERMINISTIC_v7.40A.

Confirmed SDK contracts repaired:
- ToolCall derived from ToolCallDecision.call or mapping coercion.
- ScriptedAgent.reset_state().
- ScriptedAgent.next_action accepts the Sandbox keyword contract, including
  history= and tools=, and delegates to the unchanged deterministic state machine.
"""
from __future__ import annotations
import argparse, dataclasses, importlib, importlib.util, inspect, sys, typing
from pathlib import Path

def load_base(p):
 s=importlib.util.spec_from_file_location('uta_v740a_base_v4',p)
 if s is None or s.loader is None:raise RuntimeError(f'Cannot load base: {p}')
 m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def call_type(TC):
 ev=[]
 for label,target in [('class',TC),('init',TC.__init__)]:
  try:
   z=typing.get_type_hints(target);ev.append({'source':label,'keys':sorted(z)})
   if inspect.isclass(z.get('call')):return z['call'],ev
  except Exception as e:ev.append({'source':label,'error':repr(e)})
 try:
  sig=inspect.signature(TC);p=sig.parameters.get('call');ev.append({'source':'signature','signature':str(sig),'annotation':repr(p.annotation) if p else None})
  if p and inspect.isclass(p.annotation):return p.annotation,ev
 except Exception as e:ev.append({'source':'signature','error':repr(e)})
 try:
  if dataclasses.is_dataclass(TC):
   for f in dataclasses.fields(TC):
    if f.name=='call':
     ev.append({'source':'dataclass','annotation':repr(f.type)})
     if inspect.isclass(f.type):return f.type,ev
 except Exception as e:ev.append({'source':'dataclass','error':repr(e)})
 fields=getattr(TC,'model_fields',None) or getattr(TC,'__fields__',None)
 if isinstance(fields,dict) and 'call' in fields:
  f=fields['call'];a=getattr(f,'annotation',None) or getattr(f,'type_',None);ev.append({'source':'model_fields','annotation':repr(a)})
  if inspect.isclass(a):return a,ev
 return None,ev

def imports(root):
 if str(root) not in sys.path:sys.path.insert(0,str(root))
 sm=importlib.import_module('aicomp_sdk.core.env.sandbox');bm=importlib.import_module('aicomp_sdk.guardrails.base')
 vals=[getattr(sm,'SandboxEnv',None),getattr(bm,'GuardrailBase',None),getattr(sm,'ToolCallDecision',None),getattr(sm,'FinalResponseDecision',None)]
 names=['SandboxEnv','GuardrailBase','ToolCallDecision','FinalResponseDecision'];mis=[n for n,v in zip(names,vals) if v is None]
 if mis:raise RuntimeError('Missing exports: '+', '.join(mis))
 C,ev=call_type(vals[2]);imports.discovery={'tool_call_type':repr(C),'evidence':ev};return (*vals,C)

def make_call(C,cid,name,args):
 spec={'call_id':cid,'tool_name':name,'arguments':dict(args)}
 if inspect.isclass(C):
  prior=[]
  for label,fn in [('named',lambda:C(**spec)),('positional',lambda:C(cid,name,dict(args))),('mapping',lambda:C(spec))]:
   try:return fn(),{'form':label,'resolved_type':f'{C.__module__}.{C.__qualname__}','signature':str(inspect.signature(C)),'prior':prior,'discovery':getattr(imports,'discovery',{})}
   except TypeError as e:prior.append({'form':label,'error':str(e)})
 return spec,{'form':'mapping_for_decision_coercion','resolved_type':repr(C),'discovery':getattr(imports,'discovery',{})}

def make_decision(TC,call):
 prior=[]
 for label,fn in [('call_kw',lambda:TC(call=call)),('call_assistant',lambda:TC(call=call,assistant_message=None)),('positional',lambda:TC(call))]:
  try:return fn(),{'form':label,'signature':str(inspect.signature(TC)),'prior':prior,'call_input_type':type(call).__name__}
  except (TypeError,ValueError) as e:prior.append({'form':label,'error':repr(e)})
 C,ev=call_type(TC)
 if isinstance(call,dict) and inspect.isclass(C):
  typed=C(**call)
  for label,fn in [('typed_kw',lambda:TC(call=typed)),('typed_positional',lambda:TC(typed))]:
   try:return fn(),{'form':label,'signature':str(inspect.signature(TC)),'prior':prior,'resolved_call_type':repr(C),'discovery':ev}
   except (TypeError,ValueError) as e:prior.append({'form':label,'error':repr(e)})
 raise RuntimeError('ToolCallDecision construction failed: '+repr(prior))

def patch_agent(base):
 oi=base.ScriptedAgent.__init__
 def init(self,*a,**k):oi(self,*a,**k);self._initial_contract={'source_tool':self.source_tool,'source_id':self.source_id,'marker':self.marker,'target':self.target}
 def reset_state(self):self.step=0;self.audit=[]
 def next_action(self,*args,**kwargs):
  # Confirmed Sandbox contract passes history= as a keyword. Preserve broad
  # compatibility without altering deterministic routing.
  history=kwargs.get('history')
  tools=kwargs.get('tools')
  if history is None and args:history=args[0]
  if tools is None and len(args)>1:tools=args[1]
  before=len(self.audit);result=self.decide(history)
  if len(self.audit)>before:self.audit[-1]['sdk_next_action_contract']={'positional_count':len(args),'keyword_names':sorted(kwargs),'history_type':type(history).__name__,'tools_type':type(tools).__name__,'tools_summary':base.safe(tools)}
  return result
 base.ScriptedAgent.__init__=init;base.ScriptedAgent.reset_state=reset_state;base.ScriptedAgent.next_action=next_action

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--project-root',required=True,type=Path);ap.add_argument('--fixture-dir',required=True,type=Path);ap.add_argument('--fixture-manifest',required=True,type=Path);ap.add_argument('--out-dir',required=True,type=Path);a=ap.parse_args()
 bp=Path(__file__).resolve().with_name('uta_deterministic_transport_v7_40A.py')
 if not bp.is_file():raise SystemExit(f'Base script must be beside launcher: {bp}')
 m=load_base(bp);m.imports=imports;m.make_call=make_call;m.make_decision=make_decision;patch_agent(m);m.__file__=str(Path(__file__).resolve())
 sys.argv=[str(Path(__file__).resolve()),'--project-root',str(a.project_root),'--fixture-dir',str(a.fixture_dir),'--fixture-manifest',str(a.fixture_manifest),'--out-dir',str(a.out_dir)];return m.main()
if __name__=='__main__':raise SystemExit(main())
