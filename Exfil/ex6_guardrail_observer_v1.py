#!/usr/bin/env python3
"""Transparent EX6 guardrail observer.

Wraps a guardrail's decide() method, records publication-safe identities, and
returns the exact original decision object unchanged. It does not implement or
modify policy. Raw tool arguments, context, and reason text are not serialized.
"""
from __future__ import annotations
import hashlib,json,traceback
from pathlib import Path
from typing import Any,Mapping
SCHEMA='EX6_GUARDRAIL_OBSERVER_V1'
def _sha(v:Any)->str:
    b=json.dumps(v,sort_keys=True,separators=(',',':'),default=str).encode()
    return hashlib.sha256(b).hexdigest().upper()
def _decision_fields(d:Any)->tuple[str,str|None]:
    kind=getattr(d,'decision',None) or getattr(d,'action',None) or getattr(d,'type',None)
    if kind is None: kind=d.__class__.__name__
    reason=getattr(d,'reason',None) or getattr(d,'message',None)
    return str(kind), (_sha(str(reason)) if reason is not None else None)
class ObservedGuardrail:
    def __init__(self, inner:Any, *, policy_track:str, guardrail_source_sha256:str,
                 proposal_identity:Mapping[str,Any], sink:Path|None=None):
        self.inner=inner; self.policy_track=policy_track
        self.guardrail_source_sha256=guardrail_source_sha256
        self.proposal_identity=dict(proposal_identity); self.sink=sink
        self.records:list[dict[str,Any]]=[]
    def decide(self, tool_name:str, tool_args:Mapping[str,Any], context:Mapping[str,Any]):
        before_args=_sha(tool_args); before_context=_sha(context)
        base={
          'guardrail_observer_schema_version':SCHEMA,'policy_track':self.policy_track,
          'guardrail_class':self.inner.__class__.__name__,
          'guardrail_module':self.inner.__class__.__module__,
          'guardrail_source_sha256':self.guardrail_source_sha256,
          'proposal_tool':tool_name,'proposal_arguments_sha256':before_args,
          'proposal_origin_trace_sha256':self.proposal_identity.get('origin_trace_sha256'),
          'proposal_event_index':self.proposal_identity.get('origin_event_index'),
          'proposal_sha256':self.proposal_identity.get('proposal_sha256'),
          'context_sha256':before_context,'guardrail_invoked':True,
          'guardrail_exception':None
        }
        try:
            decision=self.inner.decide(tool_name,tool_args,context)
            dtype,rhash=_decision_fields(decision)
            base.update({'guardrail_decision':dtype,'guardrail_reason_sha256':rhash,
                         'tool_args_after_guardrail_sha256':_sha(tool_args),
                         'context_after_guardrail_sha256':_sha(context),
                         'argument_passthrough':_sha(tool_args)==before_args,
                         'context_passthrough':_sha(context)==before_context,
                         'decision_object_id':id(decision)})
            self._record(base)
            return decision
        except Exception as exc:
            base.update({'guardrail_decision':'EXCEPTION','guardrail_reason_sha256':None,
                         'guardrail_exception':exc.__class__.__name__,
                         'exception_trace_sha256':_sha(traceback.format_exc())})
            self._record(base); raise
    def _record(self,row:dict[str,Any])->None:
        self.records.append(row)
        if self.sink:
            self.sink.parent.mkdir(parents=True,exist_ok=True)
            with self.sink.open('a',encoding='utf-8') as f:
                f.write(json.dumps(row,sort_keys=True)+'\n')
