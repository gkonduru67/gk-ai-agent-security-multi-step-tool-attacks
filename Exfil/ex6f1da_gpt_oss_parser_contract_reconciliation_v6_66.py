#!/usr/bin/env python3
"""EX6F.1D-A read-only GPT-OSS parser-contract reconciliation.

Extracts line-bound source evidence for the exact parser/lifecycle symbols needed
to determine whether EX6F.1D called the parser at the wrong abstraction layer.
It preserves and validates the frozen EX6F.1D package. It does not import the
SDK, call the model, contact the server, construct SandboxEnv, or execute tools.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json
from pathlib import Path
from typing import Any

VERSION='EX6F_1D_A_GPT_OSS_PARSER_CONTRACT_RECONCILIATION_v6.66'
EXPECTED={
 'parent_manifest':'7136A255DF9A1F8D5AFCB44B6D9D6FBD235A66BC2B9751B63BBCE79E146B1809',
 'parent_result':'4CC717E358F179DD5647ED71BEE9B588B2344D4D8F37EC50EDD831B96D4E3CD4',
 'gpt_oss_agent':'E3861EF6A69C470B4B47DE7604621C428D0E2DDDB8CC692EF44C466E37C8298D',
 'hf_agent':'6904ACAB523EA5D4DBD9A32A762BC87FD1F0AD4B6DFB5847C3E8BE36BABA62BB',
 'response_parsing':'DDBBE23A03297DD91DC5E27821A881933DDE5BA28B1BB46DC6B14E1B89F7C389',
}

def hf(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def hs(s:str)->str:return hashlib.sha256(s.encode('utf-8')).hexdigest().upper()
def dumpx(p:Path,v:Any):
 with p.open('x',encoding='utf-8') as f:json.dump(v,f,indent=2,sort_keys=True,default=str);f.write('\n')
def csvout(p:Path,fields:list[str],rows:list[dict[str,Any]]):
 with p.open('x',encoding='utf-8-sig',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='raise');w.writeheader();w.writerows(rows)
def dotted(n:ast.AST|None)->str:
 if isinstance(n,ast.Name):return n.id
 if isinstance(n,ast.Attribute):
  p=dotted(n.value);return f'{p}.{n.attr}' if p else n.attr
 return ''
def ann(n:ast.AST|None)->str:
 if n is None:return ''
 try:return ast.unparse(n)
 except Exception:return ''
def collect(path:Path,targets:list[tuple[str|None,str]])->list[dict[str,Any]]:
 text=path.read_text(encoding='utf-8');tree=ast.parse(text);classes={n.name:n for n in tree.body if isinstance(n,ast.ClassDef)};out=[]
 for cls,name in targets:
  scope=classes[cls].body if cls else tree.body
  nodes=[n for n in scope if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name]
  for n in nodes:
   body=ast.get_source_segment(text,n) or '';args=[]
   for a in [*n.args.posonlyargs,*n.args.args,*n.args.kwonlyargs]:args.append({'name':a.arg,'annotation':ann(a.annotation)})
   calls=[];returns=[];constructors=[]
   for x in ast.walk(n):
    if isinstance(x,ast.Call):
     c=dotted(x.func);calls.append(c)
     if c in ('FinalResponseDecision','ToolCallDecision','InvalidModelOutputError','HFGenerationResponse'):constructors.append(c)
    elif isinstance(x,ast.Return):returns.append(ast.get_source_segment(text,x.value) if x.value else 'None')
   out.append({'source_file':path.name,'qualified_symbol':f'{cls}.{name}' if cls else name,'start_line':n.lineno,'end_line':getattr(n,'end_lineno',n.lineno),'source_sha256':hs(body),'signature_arguments':args,'return_annotation':ann(n.returns),'calls':sorted(set(c for c in calls if c)),'return_expressions':returns,'constructors':sorted(set(constructors)),'source_body':body})
 return out
def summary(x:dict[str,Any])->dict[str,Any]:
 b=x['source_body'];lo=b.lower();returns=[str(v) for v in x['return_expressions']]
 return {'source_file':x['source_file'],'qualified_symbol':x['qualified_symbol'],'start_line':x['start_line'],'end_line':x['end_line'],'source_sha256':x['source_sha256'],'argument_contract_sha256':hs(json.dumps(x['signature_arguments'],sort_keys=True)),'return_annotation':x['return_annotation'],'calls_normalize_parsed_response':'normalize_parsed_response' in x['calls'],'calls_low_level_harmony_parser':'_parse_gpt_oss_harmony_response' in x['calls'],'calls_delegate_next_action':'self._delegate.next_action' in x['calls'],'constructs_FinalResponseDecision':'FinalResponseDecision' in x['constructors'],'constructs_ToolCallDecision':'ToolCallDecision' in x['constructors'],'mentions_HFGenerationResponse':'hfgenerationresponse' in lo,'mentions_response_text':'.text' in lo or 'response.text' in lo,'mentions_reasoning_content':'reasoning_content' in lo,'explicit_return_None':any(v=='None' for v in returns),'return_expression_count':len(returns),'call_inventory':' | '.join(x['calls'])}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--parent-manifest',required=True,type=Path);ap.add_argument('--parent-binding',required=True,type=Path);ap.add_argument('--parent-result',required=True,type=Path);ap.add_argument('--gpt-oss-agent-source',required=True,type=Path);ap.add_argument('--hf-agent-source',required=True,type=Path);ap.add_argument('--response-parsing-source',required=True,type=Path);ap.add_argument('--out-root',required=True,type=Path);a=ap.parse_args();out=a.out_root.resolve()
 if out.exists():ap.error(f'Refusing to overwrite: {out}')
 inputs={'parent_manifest':a.parent_manifest,'parent_result':a.parent_result,'gpt_oss_agent':a.gpt_oss_agent_source,'hf_agent':a.hf_agent_source,'response_parsing':a.response_parsing_source}
 for n,p in inputs.items():
  if not p.is_file() or hf(p)!=EXPECTED[n]:ap.error(f'Frozen {n} identity mismatch')
 if not a.parent_binding.is_file() or json.loads(a.parent_binding.read_text(encoding='utf-8')).get('manifest_sha256')!=hf(a.parent_manifest):ap.error('Parent external binding mismatch')
 parent=json.loads(a.parent_result.read_text(encoding='utf-8'))
 evidence=[]
 evidence+=collect(a.gpt_oss_agent_source,[(None,'build_gpt_oss_parser'),('GptOssHarmonyResponseParser','parse'),(None,'_parse_gpt_oss_harmony_response'),('GPTOSSAgent','next_action')])
 evidence+=collect(a.response_parsing_source,[(None,'normalize_parsed_response')])
 evidence+=collect(a.hf_agent_source,[('HFChatTemplateAgent','_parse_response'),('HFChatTemplateAgent','next_action')])
 required={'build_gpt_oss_parser','GptOssHarmonyResponseParser.parse','_parse_gpt_oss_harmony_response','normalize_parsed_response','HFChatTemplateAgent._parse_response','HFChatTemplateAgent.next_action','GPTOSSAgent.next_action'}
 found={x['qualified_symbol'] for x in evidence};missing=sorted(required-found)
 if missing:ap.error('Required symbols missing: '+', '.join(missing))
 sm=[summary(x) for x in evidence];by={x['qualified_symbol']:x for x in sm}
 low=by['_parse_gpt_oss_harmony_response'];wrapper=by['GptOssHarmonyResponseParser.parse'];hfparse=by['HFChatTemplateAgent._parse_response'];hfn=by['HFChatTemplateAgent.next_action'];gptn=by['GPTOSSAgent.next_action'];norm=by['normalize_parsed_response']
 low_may_null=low['explicit_return_None'] or 'None' in low['return_annotation']
 wrapper_normalizes=wrapper['calls_normalize_parsed_response']
 hf_uses_response=hfparse['mentions_HFGenerationResponse'] or hfparse['mentions_response_text']
 lifecycle_wrapper=hfn['calls_normalize_parsed_response'] or hfparse['calls_normalize_parsed_response']
 gpt_delegates=gptn['calls_delegate_next_action']
 wrong_layer=low_may_null and (wrapper_normalizes or lifecycle_wrapper or gpt_delegates)
 if wrong_layer:classification='EX6F_1D_BYPASSED_REQUIRED_PARSER_WRAPPER_LOW_LEVEL_NULL_IS_CONTRACT_POSSIBLE'
 elif low_may_null:classification='LOW_LEVEL_PARSER_NULL_RETURN_IS_CONTRACT_POSSIBLE_WRAPPER_REQUIREMENT_UNRESOLVED'
 else:classification='LOW_LEVEL_PARSER_NULL_NOT_EXPLAINED_BY_INSPECTED_CONTRACT'
 q={'schema':'EX6F_1D_A_V6_66','version':VERSION,'classification':classification,'execution_type':'READ_ONLY_LINE_BOUND_PARSER_CONTRACT_INSPECTION','parent_generation_evidence_preserved':True,'parent_result_classification':parent.get('classification'),'findings':{'low_level_parser':{'expects':low['return_annotation'],'explicit_null_return_possible':low_may_null,'constructs_FinalResponseDecision':low['constructs_FinalResponseDecision'],'constructs_ToolCallDecision':low['constructs_ToolCallDecision']},'GptOssHarmonyResponseParser_parse':{'calls_low_level_helper':wrapper['calls_low_level_harmony_parser'],'calls_normalize_parsed_response':wrapper_normalizes,'expects_HFGenerationResponse':wrapper['mentions_HFGenerationResponse'],'uses_response_text':wrapper['mentions_response_text']},'normalize_parsed_response':{'constructs_FinalResponseDecision':norm['constructs_FinalResponseDecision'],'constructs_ToolCallDecision':norm['constructs_ToolCallDecision']},'HFChatTemplateAgent_parse_response':{'expects_HFGenerationResponse_or_text':hf_uses_response,'calls_normalize_parsed_response':hfparse['calls_normalize_parsed_response']},'HFChatTemplateAgent_next_action':{'calls_normalize_parsed_response':hfn['calls_normalize_parsed_response']},'GPTOSSAgent_next_action':{'delegates_to_HFChatTemplateAgent':gpt_delegates},'reasoning_content_required_in_inspected_bodies':any(x['mentions_reasoning_content'] for x in sm),'EX6F_1D_wrong_abstraction_layer':wrong_layer},'claim_boundaries':{'fresh_model_generation':'NOT_PERFORMED','parent_response_replay':'NOT_PERFORMED','source_contract_only':'INSPECTED','Sandbox':'NOT_CONSTRUCTED','tool_execution':'NONE'},'parser_replay_runner_development_authorized':wrong_layer,'M0_runner_development_authorized':False,'SDK_imported':False,'model_called':False,'server_contacted':False,'Sandbox_constructed':False,'tool_execution':False,'harness_trick':'NOT_DEMONSTRATED','security_finding':'NOT_ESTABLISHED','attack_optimization_authorized':False,'hardened_policy_implementation_authorized':False}
 out.mkdir(parents=True);csvout(out/'ex6f1da_function_contract_summary.csv',list(sm[0]),sm);dumpx(out/'ex6f1da_line_bound_source_evidence.json',{'version':VERSION,'symbols':evidence});dumpx(out/'ex6f1da_reconciliation.json',q)
 src=[a.parent_manifest,a.parent_binding,a.parent_result,a.gpt_oss_agent_source,a.hf_agent_source,a.response_parsing_source,Path(__file__).resolve()];mr=[{'artifact':p.name,'role':'SOURCE_OR_PARENT','size_bytes':p.stat().st_size,'sha256':hf(p)} for p in src]
 for p in out.iterdir():
  if p.is_file():mr.append({'artifact':p.name,'role':'DERIVED','size_bytes':p.stat().st_size,'sha256':hf(p)})
 mp=out/'ex6f1da_manifest.csv';csvout(mp,['artifact','role','size_bytes','sha256'],mr);dumpx(out/'ex6f1da_manifest_external_binding.json',{'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':hf(mp),'binding_scope':'EXTERNAL_SELF_BINDING_RECORD'});print(json.dumps({'version':VERSION,'classification':classification,'parser_replay_runner_development_authorized':q['parser_replay_runner_development_authorized'],'M0_runner_development_authorized':False,'manifest_sha256':hf(mp)},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
