#!/usr/bin/env python3
"""Repair launcher v2 for UTA_DETERMINISTIC_v7.40A.

Fixes two confirmed harness/SDK contract mismatches:
1. ToolCall is not publicly exported, so its type is derived from
   ToolCallDecision.call or the decision class is allowed to coerce a mapping.
2. SandboxEnv requires agent.reset_state(), so the scripted agent receives a
   reset_state implementation that restores step and audit state.

The base matrix, frozen fixtures, default-allow guardrail, scoring, and artifact
logic remain in uta_deterministic_transport_v7_40A.py.
"""
from __future__ import annotations
import argparse, dataclasses, importlib, importlib.util, inspect, sys, typing
from pathlib import Path

def load_base(path: Path):
    spec=importlib.util.spec_from_file_location('uta_v740a_base_v2',path)
    if spec is None or spec.loader is None: raise RuntimeError(f'Cannot load base script: {path}')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod

def call_type_from_decision(TC):
    evidence=[]
    try:
        hints=typing.get_type_hints(TC)
        evidence.append({'source':'type_hints_class','keys':sorted(hints)})
        if inspect.isclass(hints.get('call')): return hints['call'],evidence
    except Exception as e:evidence.append({'source':'type_hints_class','error':repr(e)})
    try:
        init_hints=typing.get_type_hints(TC.__init__)
        evidence.append({'source':'type_hints_init','keys':sorted(init_hints)})
        if inspect.isclass(init_hints.get('call')): return init_hints['call'],evidence
    except Exception as e:evidence.append({'source':'type_hints_init','error':repr(e)})
    try:
        sig=inspect.signature(TC);p=sig.parameters.get('call')
        evidence.append({'source':'signature','signature':str(sig),'annotation':repr(p.annotation) if p else None})
        if p and inspect.isclass(p.annotation): return p.annotation,evidence
    except Exception as e:evidence.append({'source':'signature','error':repr(e)})
    try:
        if dataclasses.is_dataclass(TC):
            for f in dataclasses.fields(TC):
                if f.name=='call':
                    evidence.append({'source':'dataclass','annotation':repr(f.type)})
                    if inspect.isclass(f.type): return f.type,evidence
    except Exception as e:evidence.append({'source':'dataclass','error':repr(e)})
    fields=getattr(TC,'model_fields',None) or getattr(TC,'__fields__',None)
    if isinstance(fields,dict) and 'call' in fields:
        f=fields['call'];ann=getattr(f,'annotation',None) or getattr(f,'type_',None)
        evidence.append({'source':'model_fields','annotation':repr(ann)})
        if inspect.isclass(ann): return ann,evidence
    return None,evidence

def repaired_imports(root: Path):
    if str(root) not in sys.path:sys.path.insert(0,str(root))
    sm=importlib.import_module('aicomp_sdk.core.env.sandbox');bm=importlib.import_module('aicomp_sdk.guardrails.base')
    Env=getattr(sm,'SandboxEnv',None);Guard=getattr(bm,'GuardrailBase',None);TC=getattr(sm,'ToolCallDecision',None);FR=getattr(sm,'FinalResponseDecision',None)
    missing=[n for n,v in [('SandboxEnv',Env),('GuardrailBase',Guard),('ToolCallDecision',TC),('FinalResponseDecision',FR)] if v is None]
    if missing:raise RuntimeError('Required runtime exports missing: '+', '.join(missing))
    Call,evidence=call_type_from_decision(TC);repaired_imports.discovery={'tool_call_type':repr(Call),'evidence':evidence}
    return Env,Guard,TC,FR,Call

def repaired_make_call(Call,call_id,name,args):
    spec={'call_id':call_id,'tool_name':name,'arguments':dict(args)}
    if inspect.isclass(Call):
        attempts=[]
        for label,fn in [('named',lambda:Call(**spec)),('positional',lambda:Call(call_id,name,dict(args))),('mapping',lambda:Call(spec))]:
            try:return fn(),{'form':label,'resolved_type':f'{Call.__module__}.{Call.__qualname__}','signature':str(inspect.signature(Call)),'prior':attempts,'discovery':getattr(repaired_imports,'discovery',{})}
            except TypeError as e:attempts.append({'form':label,'error':str(e)})
    return spec,{'form':'untyped_mapping_for_decision_coercion','resolved_type':repr(Call),'discovery':getattr(repaired_imports,'discovery',{})}

def repaired_make_decision(TC,call):
    attempts=[]
    for label,fn in [('call_kw',lambda:TC(call=call)),('call_assistant',lambda:TC(call=call,assistant_message=None)),('positional',lambda:TC(call))]:
        try:return fn(),{'form':label,'signature':str(inspect.signature(TC)),'prior':attempts,'call_input_type':type(call).__name__}
        except (TypeError,ValueError) as e:attempts.append({'form':label,'error':repr(e)})
    Call,evidence=call_type_from_decision(TC)
    if isinstance(call,dict) and inspect.isclass(Call):
        typed=Call(**call)
        for label,fn in [('typed_call_kw',lambda:TC(call=typed)),('typed_positional',lambda:TC(typed))]:
            try:return fn(),{'form':label,'signature':str(inspect.signature(TC)),'prior':attempts,'resolved_call_type':repr(Call),'discovery':evidence}
            except (TypeError,ValueError) as e:attempts.append({'form':label,'error':repr(e)})
    raise RuntimeError('ToolCallDecision construction failed: '+repr(attempts))

def add_agent_contract(base):
    original_init=base.ScriptedAgent.__init__
    def init(self,*args,**kwargs):
        original_init(self,*args,**kwargs)
        self._initial_contract={'source_tool':self.source_tool,'source_id':self.source_id,'marker':self.marker,'target':self.target}
    def reset_state(self):
        self.step=0
        self.audit=[]
    base.ScriptedAgent.__init__=init
    base.ScriptedAgent.reset_state=reset_state

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--project-root',required=True,type=Path);ap.add_argument('--fixture-dir',required=True,type=Path);ap.add_argument('--fixture-manifest',required=True,type=Path);ap.add_argument('--out-dir',required=True,type=Path);a=ap.parse_args()
    base_path=Path(__file__).resolve().with_name('uta_deterministic_transport_v7_40A.py')
    if not base_path.is_file():raise SystemExit(f'Base script must be beside repair launcher: {base_path}')
    mod=load_base(base_path);mod.imports=repaired_imports;mod.make_call=repaired_make_call;mod.make_decision=repaired_make_decision;add_agent_contract(mod)
    mod.__file__=str(Path(__file__).resolve())
    sys.argv=[str(Path(__file__).resolve()),'--project-root',str(a.project_root),'--fixture-dir',str(a.fixture_dir),'--fixture-manifest',str(a.fixture_manifest),'--out-dir',str(a.out_dir)]
    return mod.main()
if __name__=='__main__':raise SystemExit(main())
