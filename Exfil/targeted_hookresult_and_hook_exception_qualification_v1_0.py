#!/usr/bin/env python3
"""Targeted HookResult and hook-exception contract qualification v1.0.

Read-only source/AST inspection plus isolated constructor and HookRegistry
contract controls. It does not modify V2.1 or the SDK and does not execute
filesystem tools, SandboxEnv, Gym, guardrails, predicates, breach logic, HTTP,
models, threads, or external effects.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, importlib, inspect, json, sys
from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = 'TARGETED_HOOKRESULT_AND_HOOK_EXCEPTION_CONTRACT_QUALIFICATION_v1.0'
EXPECTED = {
    'v14_manifest': 'FE1350E6779772CDAC9CA4C16D058E53398F1EACA6062F2E0DE2D65B2E4D5AB1',
    'v14_result': '20BF135D72E5AF4AC7518E2478A6A4D216642586B608B881262021B84CB4851C',
    'v14_checks': 'AD2E9AEF89CCCDC6744A3B9205A17CD40AD4EB95023737B77D9FDC88A271AD3E',
    'v14_negative': 'B1717B3C27A1F20ED7D22515A8997503A96A9D9C36AE7DEA43135E6135639D77',
    'v14_binding': '5E7186A5B615C36591D50268BDAD4B94FE6427091341CD98179137BA773F4EBF',
    'types': '0D3C7B5921749C22CADC5478532C7FE84B86AA90447FEEA8060ACFA9F44D3C7E',
    'registry': '5635B45136517CB5B7FBC6BAB6C9440FE7D6D699E484B6D63651AE296D4BB00B',
    'sandbox': 'B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0',
    'hook': 'F2DE8D42EE5DBCD3BA4CACD8E98DCCB2EBA63F82EC8683D129C503CCED1CE770',
}

def now(): return datetime.now(timezone.utc).isoformat()
def need(v,m):
    if not v: raise ValueError(m)
def shaf(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest().upper()
def ident(p):
    p=Path(p).resolve(); return {'artifact':p.name,'path':str(p),'size_bytes':p.stat().st_size,'sha256':shaf(p)}
def rj(p): return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def rc(p):
    with Path(p).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def wj(p,v):
    with Path(p).open('x',encoding='utf-8',newline='\n') as f:json.dump(v,f,indent=2,sort_keys=True,ensure_ascii=False,default=str);f.write('\n')
def wc(p,rows,fields_):
    with Path(p).open('x',encoding='utf-8',newline='') as f:w=csv.DictWriter(f,fieldnames=fields_,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(rows)
def add(rows,cid,cat,ok,obs,exp,layer):rows.append({'check_id':cid,'category':cat,'passed':bool(ok),'observed':json.dumps(obs,sort_keys=True,default=str) if isinstance(obs,(dict,list,tuple)) else str(obs),'expected':json.dumps(exp,sort_keys=True,default=str) if isinstance(exp,(dict,list,tuple)) else str(exp),'failure_layer':layer})
def up(n):
    try:return ast.unparse(n)
    except:return 'UNPARSE_FAILED'
def class_node(tree,name):return next((n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==name),None)
def method(cls,name):return next((n for n in cls.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name),None)
def calls_named(node,name):return [n for n in ast.walk(node) if isinstance(n,ast.Call) and (isinstance(n.func,ast.Name) and n.func.id==name or isinstance(n.func,ast.Attribute) and n.func.attr==name)]

def main(a):
    out=Path(a.output_dir).resolve();need(not out.exists(),f'Refusing overwrite: {out}');out.mkdir(parents=True);checks=[]
    try:
        root=Path(a.project_root).resolve()
        paths={
            'v14_manifest':Path(a.v14_manifest).resolve(),'v14_result':Path(a.v14_result).resolve(),'v14_checks':Path(a.v14_checks).resolve(),'v14_negative':Path(a.v14_negative).resolve(),'v14_binding':Path(a.v14_binding).resolve(),
            'types':root/'aicomp_sdk'/'hooks'/'types.py','registry':root/'aicomp_sdk'/'hooks'/'registry.py','sandbox':root/'aicomp_sdk'/'core'/'env'/'sandbox.py','hook':root/'aicomp_sdk_exfil_v2_1'/'trusted_read_outcome_hook_v2_1.py'}
        for n,p in paths.items():need(p.is_file(),f'Missing {n}: {p}')
        for i,(n,h) in enumerate(EXPECTED.items(),1):add(checks,f'HRX-{i:03d}','identity',shaf(paths[n])==h,shaf(paths[n]),h,'FIXTURE')
        v14=rj(paths['v14_result']);vchecks=rc(paths['v14_checks']);neg=rc(paths['v14_negative'])
        parent_ok=v14.get('checks')=={'failed':1,'failed_ids':['AR21-017'],'passed':20,'total':21} and v14.get('outcome')=='CONTROLLED_ACTUAL_FS_READ_HOOK_AND_LEDGER_QUALIFICATION_GAP' and len(vchecks)==21 and [x.get('check_id') for x in vchecks if x.get('passed')!='True']==['AR21-017']
        add(checks,'HRX-010','parent',parent_ok,{'checks':v14.get('checks'),'outcome':v14.get('outcome')},'20/21 only AR21-017 failed','EVIDENCE')
        nmap={x['control']:x for x in neg}; malformed_ok=all(nmap[x].get('match')=='False' and "unexpected keyword argument 'should_block'" in nmap[x].get('exception','') for x in ['malformed_tool_args','non_string_output'])
        add(checks,'HRX-011','parent',malformed_ok,{x:nmap.get(x) for x in ['malformed_tool_args','non_string_output']},'both TypeError on HookResult should_block','EVIDENCE')

        texts={n:paths[n].read_text(encoding='utf-8') for n in ['types','registry','sandbox','hook']};trees={n:ast.parse(t,filename=str(paths[n])) for n,t in texts.items()}
        hookresult=class_node(trees['types'],'HookResult'); hookcontext=class_node(trees['types'],'HookContext'); need(hookresult and hookcontext,'hook classes missing')
        def ann_fields(cls):
            rows=[]
            for n in cls.body:
                if isinstance(n,ast.AnnAssign) and isinstance(n.target,ast.Name):rows.append({'name':n.target.id,'annotation':up(n.annotation),'default':up(n.value) if n.value else 'NO_DEFAULT'})
            return rows
        hr_fields=ann_fields(hookresult);hc_fields=ann_fields(hookcontext)
        expected_hr=['continue_execution','modified_context','payload_detected','metadata']; expected_hc_block=any(x['name']=='should_block' and x['default']=='False' for x in hc_fields)
        add(checks,'HRX-012','HookResult',hookresult.decorator_list and any('dataclass' in up(x) for x in hookresult.decorator_list),[up(x) for x in hookresult.decorator_list],'dataclass','ADAPTER_PARSE')
        add(checks,'HRX-013','HookResult',[x['name'] for x in hr_fields]==expected_hr,hr_fields,expected_hr,'ADAPTER_PARSE')
        add(checks,'HRX-014','HookContext',expected_hc_block,hc_fields,'should_block belongs to HookContext default False','ADAPTER_PARSE')
        add(checks,'HRX-015','HookResult',not any(x['name']=='should_block' for x in hr_fields),hr_fields,'HookResult has no should_block','ADAPTER_PARSE')

        regcls=class_node(trees['registry'],'HookRegistry');exe=method(regcls,'execute_hooks');need(exe,'execute_hooks missing');es=up(exe)
        registry_props={'appends_callback_result':'results.append(result)' in es,'applies_modified_context':'if result.modified_context' in es and '_apply_modified_context' in es,'breaks_on_continue_false':'if not result.continue_execution' in es and 'break' in es,'catches_exception':'except Exception as err' in es,'exception_continues':'continue_execution=True' in es,'exception_metadata':'metadata={\'error\': str(err)}' in es or 'metadata={"error": str(err)}' in es}
        add(checks,'HRX-016','registry',all(registry_props.values()),registry_props,'exact merge and exception behavior','AUTHORIZATION_TRANSPORT')
        apply_fn=next((n for n in trees['registry'].body if isinstance(n,ast.FunctionDef) and n.name=='_apply_modified_context'),None);need(apply_fn,'apply context missing');aps=up(apply_fn)
        add(checks,'HRX-017','registry','context.should_block = modified_context.should_block' in aps,aps,'modified context copies should_block','AUTHORIZATION_TRANSPORT')

        sand=class_node(trees['sandbox'],'SandboxEnv');inter=method(sand,'interact');need(inter,'SandboxEnv.interact missing');ss=up(inter)
        positions={'pre_execute':ss.find('execute_hooks(HookStage.PRE_TOOL_CALL'),'pre_block_check':ss.find('if pre_tool_ctx.should_block'),'tool_call':ss.find('self.tools.call(tool_name, tool_args)'),'post_execute':ss.find('execute_hooks(HookStage.POST_TOOL_CALL'),'post_block_check':ss.find('post_tool_ctx.should_block')}
        pre_supported=0<=positions['pre_execute']<positions['pre_block_check']<positions['tool_call'];post_after=positions['tool_call']<positions['post_execute'];post_not_checked=positions['post_block_check']==-1
        add(checks,'HRX-018','sandbox',pre_supported,positions,'PRE_TOOL_CALL should_block checked before tool call','AUTHORIZATION_TRANSPORT')
        add(checks,'HRX-019','sandbox',post_after and post_not_checked,positions,'POST_TOOL_CALL occurs after effect and should_block is not consumed','AUTHORIZATION_TRANSPORT')
        post_semantics={'modified_output_consumed':'if post_tool_ctx.modified_output is not None' in ss,'injected_content_consumed':'if post_tool_ctx.injected_content is not None' in ss,'tool_event_retains_original_ok':'ok=ok' in ss,'tool_event_retains_error':'error=err' in ss}
        add(checks,'HRX-020','sandbox',all(post_semantics.values()),post_semantics,'post hook can modify output/inject content but not retroactively block effect','AUTHORIZATION_TRANSPORT')

        hookcls=class_node(trees['hook'],'TrustedReadOutcomeHookV21');call=method(hookcls,'__call__');need(call,'hook call missing');hcalls=calls_named(call,'HookResult');incompatible=[]
        for c in hcalls:
            kws={kw.arg:up(kw.value) for kw in c.keywords if kw.arg};
            if 'should_block' in kws:incompatible.append({'line':c.lineno,'keywords':kws})
        add(checks,'HRX-021','V2_1_hook',len(incompatible)==2,incompatible,'two incompatible HookResult should_block calls','AUTHORIZATION_TRANSPORT')

        # Isolated constructor and registry controls. No Sandbox or tools are instantiated.
        sys.path.insert(0,str(root));from aicomp_sdk.hooks.types import HookContext,HookResult,HookStage;from aicomp_sdk.hooks.registry import HookRegistry
        runtime={'HookResult_signature':str(inspect.signature(HookResult)),'HookContext_signature':str(inspect.signature(HookContext)),'HookResult_dataclass_fields':[{'name':f.name,'default':repr(f.default),'default_factory':repr(f.default_factory)} for f in fields(HookResult)]}
        try:HookResult(should_block=True);invalid={'raised':False}
        except Exception as e:invalid={'raised':True,'type':type(e).__name__,'message':str(e)}
        base=HookContext(stage=HookStage.PRE_TOOL_CALL,tool_name='fs.read',tool_args={'path':'secret.txt'});modified=HookContext(stage=HookStage.PRE_TOOL_CALL,tool_name='fs.read',tool_args={'path':'secret.txt'},should_block=True);valid=HookResult(continue_execution=False,modified_context=modified,metadata={'reason':'CONTROL'})
        reg=HookRegistry();reg.register_hook(HookStage.PRE_TOOL_CALL,lambda ctx:valid);results=reg.execute_hooks(HookStage.PRE_TOOL_CALL,base)
        valid_control={'invalid_should_block':invalid,'valid_result':{'continue_execution':valid.continue_execution,'has_modified_context':valid.modified_context is not None,'metadata':valid.metadata},'context_should_block_after_registry':base.should_block,'result_count':len(results)}
        add(checks,'HRX-022','controlled_constructor',invalid.get('raised') and invalid.get('type')=='TypeError' and base.should_block is True and len(results)==1,valid_control,'HookResult modified_context can carry pre-tool should_block','AUTHORIZATION_TRANSPORT')
        def boom(ctx):raise RuntimeError('CONTROLLED_HOOK_EXCEPTION')
        reg2=HookRegistry();reg2.register_hook(HookStage.POST_TOOL_CALL,boom);ctx2=HookContext(stage=HookStage.POST_TOOL_CALL,tool_name='fs.read',tool_args={'path':'secret.txt'},tool_output='x',context={'ok':True});res2=reg2.execute_hooks(HookStage.POST_TOOL_CALL,ctx2)
        exception_control={'raised_to_caller':False,'result_count':len(res2),'continue_execution':res2[0].continue_execution if res2 else None,'metadata':res2[0].metadata if res2 else None,'context_should_block':ctx2.should_block}
        ex_ok=len(res2)==1 and res2[0].continue_execution is True and res2[0].metadata.get('error')=='CONTROLLED_HOOK_EXCEPTION' and ctx2.should_block is False
        add(checks,'HRX-023','controlled_exception',ex_ok,exception_control,'registry swallows exception and continues without blocking','AUTHORIZATION_TRANSPORT')

        unchanged=all(shaf(paths[n])==h for n,h in EXPECTED.items());add(checks,'HRX-024','immutability',unchanged,'all bound inputs unchanged',True,'FIXTURE')
        failed=[x['check_id'] for x in checks if not x['passed']]
        blocking_at_post_supported=not post_not_checked
        if failed:outcome='NOT_ESTABLISHED'
        elif not blocking_at_post_supported:outcome='HOOKRESULT_BLOCKING_NOT_SUPPORTED_AT_POST_TOOL_CALL'
        elif incompatible:outcome='V2_1_HOOKRESULT_CONTRACT_GAP_CONFIRMED_WITH_REPAIR_PATH'
        else:outcome='NOT_ESTABLISHED'
        status='TARGETED_HOOKRESULT_AND_HOOK_EXCEPTION_CONTRACT_QUALIFICATION_COMPLETE_PASS' if not failed else 'TARGETED_HOOKRESULT_AND_HOOK_EXCEPTION_CONTRACT_QUALIFICATION_COMPLETE_WITH_GAPS'
        repair={'V2_1_modification':'PROHIBITED','V2_2_required':True,'supported_pre_tool_blocking':'HookResult(continue_execution=False, modified_context=HookContext(..., should_block=True))','post_tool_blocking':'NOT_SUPPORTED_BY_SANDBOX_CONTROL_FLOW','post_tool_malformed_policy':'must not be mislabeled as preventing the already executed read','recommended_design':'move argument validation to PRE_TOOL_CALL for prevention; keep POST_TOOL_CALL as observation/capture and return a valid HookResult without should_block','exception_policy':'registry swallows callback exceptions into metadata and continues execution'}
        claim={'allowed':['HookResult exact fields and constructor contract established','should_block belongs to HookContext','registry modified_context merge behavior established','registry exception swallowing and continue behavior established','PRE_TOOL_CALL blocking path established','POST_TOOL_CALL blocking not consumed by Sandbox','two incompatible V2.1 hook calls established'],'prohibited':['modify V2.1','claim TypeError is a deny','claim unchanged ledger proves blocking','claim POST_TOOL_CALL can prevent an already executed read','claim hook registry integration was tested in Sandbox','HTTP','guardrail effectiveness','predicate or breach','robust end-to-end security findings']}
        result={'version':VERSION,'created_at_utc':now(),'status':status,'checks':{'total':len(checks),'passed':len(checks)-len(failed),'failed':len(failed),'failed_ids':failed},'outcome':outcome,'HookResult':{'signature':runtime['HookResult_signature'],'fields':hr_fields,'blocking_field_present':False},'HookContext':{'signature':runtime['HookContext_signature'],'should_block_field_present':True},'registry_contract':registry_props,'sandbox_positions':positions,'post_tool_semantics':post_semantics,'V2_1_incompatible_calls':incompatible,'controlled_constructor':valid_control,'controlled_exception':exception_control,'repair_path':repair,'execution_boundaries':{'V2_1_modified':False,'SDK_modified':False,'Sandbox_instantiated':False,'tools_executed':False,'actual_fs_read_executed':False,'HTTP_executed':False,'guardrail_executed':False,'predicates_executed':False,'breach_executed':False,'models_used':False,'threads_executed':False,'external_effects_observed':False},'scientific_verdict':{'hookresult_contract_gap':'ESTABLISHED','post_tool_blocking':'NOT_SUPPORTED','hook_exception_policy':'SWALLOWED_TO_ERROR_METADATA_AND_CONTINUE','positive_v1_4_source_to_ledger_lineage':'PRESERVED','harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'},'claim_boundary':claim,'next_gate':'V2_2_HOOK_MALFORMED_INPUT_FAIL_CLOSED_DESIGN_REVIEW' if outcome=='HOOKRESULT_BLOCKING_NOT_SUPPORTED_AT_POST_TOOL_CALL' else 'V2_2_HOOK_CONTRACT_REPAIR_AND_IDENTITY_FREEZE'}
        outputs={'result':out/'targeted_hookresult_contract_result.json','checks':out/'targeted_hookresult_contract_checks.csv','source':out/'targeted_hookresult_source_contract.json','runtime':out/'targeted_hookresult_constructor_controls.json','repair':out/'targeted_hookresult_repair_path.json','claim':out/'targeted_hookresult_claim_boundary.json','binding':out/'targeted_hookresult_binding.json'}
        wj(outputs['result'],result);wc(outputs['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']);wj(outputs['source'],{'HookResult_fields':hr_fields,'HookContext_fields':hc_fields,'registry_contract':registry_props,'sandbox_positions':positions,'post_tool_semantics':post_semantics,'V2_1_incompatible_calls':incompatible});wj(outputs['runtime'],{'runtime_contract':runtime,'valid_control':valid_control,'exception_control':exception_control});wj(outputs['repair'],repair);wj(outputs['claim'],claim);wj(outputs['binding'],{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'inputs':{n:ident(p) for n,p in paths.items()},'execution_boundaries':result['execution_boundaries']})
        rows=[{**ident(p),'role':'HOOKRESULT_CONTRACT_DERIVED'} for p in outputs.values()]+[{**ident(p),'role':'HOOKRESULT_CONTRACT_BOUND_INPUT'} for p in paths.values()];mp=out/'targeted_hookresult_contract_manifest.csv';wc(mp,rows,['artifact','role','size_bytes','sha256','path']);ep=out/'targeted_hookresult_contract_manifest_external_binding.json';wj(ep,{'version':VERSION,'created_at_utc':now(),'status':status,'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':shaf(mp),'runner_sha256':shaf(Path(__file__).resolve()),'v14_manifest_sha256':EXPECTED['v14_manifest'],'checks_total':len(checks),'checks_passed':len(checks)-len(failed),'checks_failed':len(failed),'failed_ids':failed,'outcome':outcome,'V2_1_modified':False,'SDK_modified':False,'next_gate':result['next_gate']})
        print(json.dumps({'status':status,'checks':f'{len(checks)-len(failed)}/{len(checks)}','failed_ids':failed,'outcome':outcome,'HookResult_should_block_field':False,'HookContext_should_block_field':True,'registry_exception_policy':'SWALLOW_AND_CONTINUE','POST_TOOL_CALL_blocking':'NOT_SUPPORTED','manifest_sha256':shaf(mp),'next_gate':result['next_gate']},indent=2))
    except Exception as e:
        (out/'TARGETED_HOOKRESULT_CONTRACT_FAILED.json').write_text(json.dumps({'version':VERSION,'created_at_utc':now(),'status':'BLOCKED','error_type':type(e).__name__,'error':str(e),'checks_frozen':checks,'V2_1_modified':False,'SDK_modified':False,'Sandbox_instantiated':False,'tools_executed':False},indent=2),encoding='utf-8');raise

def parse():
    p=argparse.ArgumentParser(description=VERSION)
    for n in ['v14-manifest','v14-result','v14-checks','v14-negative','v14-binding','project-root','output-dir']:p.add_argument('--'+n,required=True)
    return p.parse_args()
if __name__=='__main__':
    try:main(parse())
    except Exception as e:print(f'FAILED: {e}',file=sys.stderr);raise SystemExit(1)
