#!/usr/bin/env python3
"""EX9-R4-R1 post-tool success evidence route reconciliation v1.0.

Read-only static construction and ordering inspection. Preserves EX9-R4 v1.1
as 31/32 with F-023 failed. Inventories every HookContext construction tied to
POST_TOOL_CALL, the public metadata/context/trace/hook_state values supplied,
tool execution exception flow, ToolEvent construction/append ordering, and the
ordinary guardrail context schema at later proposals.

The runner compares two public routes:
 A) POST_TOOL_CALL success evidence -> SuccessfulReadLedgerV1
 B) guardrail.decide context -> prior successful fs.read ToolEvents

It never treats non-empty output as success. It does not modify aicomp_sdk,
create aicomp_sdk_exfil, import/execute SDK modules, instantiate Sandbox/Gym,
execute tools/fs.read/http.post, run predicates/breach/models/threads, or cause
external effects.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path

VERSION="EX9_R4_R1_POST_TOOL_SUCCESS_EVIDENCE_ROUTE_RECONCILIATION_v1.0"
PARENT_VERSION="EX9_R4_PUBLIC_HOOK_AND_STATEFUL_GUARDRAIL_FEASIBILITY_FREEZE_v1.1"
PARENT_STATUS="EX9_R4_PUBLIC_HOOK_AND_STATEFUL_GUARDRAIL_FEASIBILITY_FREEZE_COMPLETE_WITH_GAPS"
PARENT_MANIFEST_SHA="232CA29C9758E9BA41B06483BCBB7ACE3D27807173AEA8586B2A282B16B7BDDF"
PARENT_RUNNER_SHA="608FD8ACCF1EC407C19DCDB40E0C73F0A40BEF4963AE08B503CB15BCBD5255C7"
PARENT_RESULT_SHA="FFA124FFA334F2F5B6C060DCDD605F0BA2CBF3B0C9913A355CB62775A939E986"
PARENT_CHECKS_SHA="BAAE1C60D45CF6D0C0780D51B00F17D37BED89BF9594AD89954BB7915525243E"
PARENT_HOOK_SHA="D33B0DA346384B0A1C0ED5423ECD841628BDD774F60E0548230D0D1E510A0D0A"
PARENT_SOURCES_SHA="D4112EEAFC859078B44441BF25DA755CBA58FACFA083AF3468F243C49E2DA6BC"
PARENT_FREEZE_SHA="92A4D401A542F627B0076A003C27F1A36A50E2D4239F3918BD1E878064ACDFE5"
PARENT_ARCH_SHA="03B2A388C0886A62F3D4FEB8FA72FF47AF2D127EA4B959D1946CE8ADD22A1863"
PARENT_MATCHERS_SHA="D780612EDD70EF9E1D6613E8DA47A80270DFAC70384D82BD0B8ABBAB442486FA"

SUCCESS_KEYS={'ok','success','succeeded','is_success','status'}
ERROR_KEYS={'error','exception','exc','failure','failed'}
EVENT_KEYS={'events','tool_events','trace','event_log'}

def now(): return datetime.now(timezone.utc).isoformat()
def require(c,m):
    if not c: raise ValueError(m)
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''): h.update(b)
    return h.hexdigest().upper()
def ident(p):
    p=Path(p).resolve(); return {'artifact':p.name,'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}
def rj(p): return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def rc(p):
    with Path(p).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def wj(p,o):
    with Path(p).open('x',encoding='utf-8',newline='\n') as f:json.dump(o,f,indent=2,sort_keys=True);f.write('\n')
def wc(p,rows,fields):
    with Path(p).open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(rows)
def add(rows,i,c,p,o,e,l):rows.append({'check_id':i,'category':c,'passed':bool(p),'observed':str(o),'expected':str(e),'failure_layer':l})
def parse(p):
    text=Path(p).read_text(encoding='utf-8');return text,ast.parse(text,filename=str(p))
def up(n):
    try:return ast.unparse(n)
    except:return 'UNPARSE_FAILED'
def kwmap(call):return {k.arg:up(k.value) for k in call.keywords if k.arg}
def call_name(n):return up(n.func) if isinstance(n,ast.Call) else ''
def function_ancestors(tree):
    out=[]
    for n in ast.walk(tree):
        if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):out.append(n)
    return out
def containing_function(tree,node):
    candidates=[]
    for f in function_ancestors(tree):
        if any(x is node for x in ast.walk(f)):candidates.append(f)
    return min(candidates,key=lambda x:len(list(ast.walk(x)))) if candidates else None
def dict_literal_keys(expr):
    if isinstance(expr,ast.Dict):
        return [up(k) if k is not None else '**' for k in expr.keys]
    return []
def has_literal_key(expr,keys):
    text=up(expr).lower()
    return any((repr(k) in text or f'"{k}"' in text or f'.{k}' in text or f'[{repr(k)}]' in text) for k in keys)
def class_defs(tree,name):return [n for n in ast.walk(tree) if isinstance(n,ast.ClassDef) and n.name==name]

def main(a):
    out=Path(a.output_dir).resolve();require(not out.exists(),f'Refusing overwrite: {out}');out.mkdir(parents=True)
    checks=[]
    try:
        root=Path(a.project_root).resolve();sdk=root/'aicomp_sdk';require(sdk.is_dir(),f'Missing SDK root: {sdk}')
        parent={'result':Path(a.r4_result).resolve(),'checks':Path(a.r4_checks).resolve(),'hook':Path(a.r4_hook_contract).resolve(),'sources':Path(a.r4_source_identities).resolve(),'freeze':Path(a.r4_feasibility_freeze).resolve(),'architecture':Path(a.r4_architecture).resolve(),'matchers':Path(a.r4_matcher_candidates).resolve(),'claim':Path(a.r4_claim_boundary).resolve(),'binding':Path(a.r4_binding).resolve(),'external':Path(a.r4_external_binding).resolve(),'manifest':Path(a.r4_manifest).resolve(),'runner':Path(a.r4_runner).resolve()}
        for k,p in parent.items():require(p.is_file(),f'Missing parent {k}: {p}')
        pr=rj(parent['result']);pe=rj(parent['external']);pchecks=rc(parent['checks'])
        add(checks,'S-001','parent',pr.get('version')==PARENT_VERSION and pr.get('status')==PARENT_STATUS,pr.get('status'),PARENT_STATUS,'FIXTURE')
        expected=[('manifest',PARENT_MANIFEST_SHA),('runner',PARENT_RUNNER_SHA),('result',PARENT_RESULT_SHA),('checks',PARENT_CHECKS_SHA),('hook',PARENT_HOOK_SHA),('sources',PARENT_SOURCES_SHA),('freeze',PARENT_FREEZE_SHA),('architecture',PARENT_ARCH_SHA),('matchers',PARENT_MATCHERS_SHA)]
        for i,(k,h) in enumerate(expected,2):add(checks,f'S-{i:03d}','parent',sha(parent[k])==h,sha(parent[k]),h,'FIXTURE')
        failed_parent=[x['check_id'] for x in pchecks if x['passed']!='True']
        add(checks,'S-011','parent',len(pchecks)==32 and sum(x['passed']=='True' for x in pchecks)==31 and failed_parent==['F-023'],{'total':len(pchecks),'passed':sum(x['passed']=='True' for x in pchecks),'failed':failed_parent},'31/32 with F-023 failed','EVIDENCE')
        add(checks,'S-012','parent',pr.get('outcome')=='PUBLIC_HOOK_OUTPUT_FIELDS_INSUFFICIENT' and pe.get('frozen_aicomp_sdk_modified') is False,{'outcome':pr.get('outcome'),'modified':pe.get('frozen_aicomp_sdk_modified')},'success gap preserved; SDK unchanged','CLAIM_BOUNDARY')

        parsed=[];parse_errors=[]
        for p in sorted(sdk.rglob('*.py')):
            try:text,tree=parse(p);parsed.append((p,text,tree))
            except Exception as e:parse_errors.append({'path':str(p),'error_type':type(e).__name__,'error':str(e)})
        add(checks,'S-020','inventory',not parse_errors,parse_errors,'all SDK Python sources parse','FIXTURE')

        hook_rows=[];ordering_rows=[];event_rows=[];guardrail_rows=[];source_rows=[]
        for p,text,tree in parsed:
            rel=str(p.relative_to(root));relevant=False
            # HookContext construction and POST_TOOL_CALL execution sites.
            for n in ast.walk(tree):
                if isinstance(n,ast.Call) and call_name(n).endswith('HookContext'):
                    relevant=True;f=containing_function(tree,n);kw=kwmap(n)
                    post_in_fn=bool(f and 'POST_TOOL_CALL' in up(f))
                    row={'relative_path':rel,'file_sha256':sha(p),'function':f.name if f else '<module>','function_line':f.lineno if f else 0,'call_line':n.lineno,'post_tool_context':post_in_fn,'call_expression':up(n),'tool_name_expr':kw.get('tool_name','NOT_SUPPLIED'),'tool_args_expr':kw.get('tool_args','NOT_SUPPLIED'),'tool_output_expr':kw.get('tool_output','NOT_SUPPLIED'),'metadata_expr':kw.get('metadata','NOT_SUPPLIED'),'context_expr':kw.get('context','NOT_SUPPLIED'),'trace_expr':kw.get('trace','NOT_SUPPLIED'),'hook_state_expr':kw.get('hook_state','NOT_SUPPLIED')}
                    row['metadata_success_token']=has_literal_key(next((k.value for k in n.keywords if k.arg=='metadata'),ast.Constant(None)),SUCCESS_KEYS|ERROR_KEYS)
                    row['context_success_token']=has_literal_key(next((k.value for k in n.keywords if k.arg=='context'),ast.Constant(None)),SUCCESS_KEYS|ERROR_KEYS)
                    row['trace_success_token']=has_literal_key(next((k.value for k in n.keywords if k.arg=='trace'),ast.Constant(None)),SUCCESS_KEYS|ERROR_KEYS)
                    hook_rows.append(row)
                if isinstance(n,ast.Call) and ('execute_hooks' in call_name(n) or 'POST_TOOL_CALL' in up(n)):
                    relevant=True;f=containing_function(tree,n)
                    if 'POST_TOOL_CALL' in up(n):ordering_rows.append({'relative_path':rel,'file_sha256':sha(p),'function':f.name if f else '<module>','function_line':f.lineno if f else 0,'line':n.lineno,'kind':'POST_TOOL_CALL_EXECUTION','expression':up(n)})
                # ToolEvent construction and append sites.
                if isinstance(n,ast.Call) and call_name(n).endswith('ToolEvent'):
                    relevant=True;f=containing_function(tree,n);kw=kwmap(n)
                    event_rows.append({'relative_path':rel,'file_sha256':sha(p),'function':f.name if f else '<module>','function_line':f.lineno if f else 0,'line':n.lineno,'kind':'TOOL_EVENT_CONSTRUCTION','expression':up(n),'name_expr':kw.get('name',kw.get('tool_name','NOT_SUPPLIED')),'args_expr':kw.get('args',kw.get('tool_args','NOT_SUPPLIED')),'ok_expr':kw.get('ok',kw.get('success','NOT_SUPPLIED')),'output_expr':kw.get('output',kw.get('tool_output','NOT_SUPPLIED'))})
                if isinstance(n,ast.Call) and call_name(n).endswith('.append') and any(t in up(n).lower() for t in ['event','trace','tool_event']):
                    relevant=True;f=containing_function(tree,n);event_rows.append({'relative_path':rel,'file_sha256':sha(p),'function':f.name if f else '<module>','function_line':f.lineno if f else 0,'line':n.lineno,'kind':'EVENT_APPEND','expression':up(n),'name_expr':'','args_expr':'','ok_expr':'','output_expr':''})
            # Guardrail context construction/calls and exception-flow inventory.
            for f in function_ancestors(tree):
                fs=up(f);low=fs.lower()
                if 'guardrail.decide' in low or '.decide(' in low:
                    for n in ast.walk(f):
                        if isinstance(n,ast.Call) and call_name(n).endswith('.decide'):
                            args=[up(x) for x in n.args];ctx=args[2] if len(args)>=3 else kwmap(n).get('context','NOT_SUPPLIED')
                            guardrail_rows.append({'relative_path':rel,'file_sha256':sha(p),'function':f.name,'function_line':f.lineno,'call_line':n.lineno,'call_expression':up(n),'context_expr':ctx,'context_has_events_token':any(k in ctx.lower() for k in EVENT_KEYS),'context_has_success_token':has_literal_key(ast.Constant(ctx),SUCCESS_KEYS|ERROR_KEYS)})
                if 'post_tool_call' in low or 'execute_hooks' in low:
                    ordering_rows.append({'relative_path':rel,'file_sha256':sha(p),'function':f.name,'function_line':f.lineno,'line':f.lineno,'kind':'ENCLOSING_CONTROL_FLOW','expression':fs})
            if relevant:source_rows.append({**ident(p),'relative_path':rel,'role':'RELEVANT_AUTHORITATIVE_SOURCE'})

        post_hooks=[x for x in hook_rows if x['post_tool_context']]
        add(checks,'S-021','hook',bool(post_hooks),len(post_hooks),'at least one POST_TOOL_CALL HookContext construction','ROUTING')
        add(checks,'S-022','hook',True,len(hook_rows),'all HookContext constructions inventoried','EVIDENCE')
        add(checks,'S-023','event',bool(event_rows),len(event_rows),'ToolEvent construction/append sites inventoried','ROUTING')
        add(checks,'S-024','guardrail',bool(guardrail_rows),len(guardrail_rows),'ordinary guardrail decision contexts inventoried','ROUTING')

        # Resolve explicit success carriers from exact construction expressions.
        metadata_routes=[x for x in post_hooks if x['metadata_success_token']]
        context_routes=[x for x in post_hooks if x['context_success_token']]
        trace_routes=[x for x in post_hooks if x['trace_success_token']]
        event_ok_routes=[x for x in event_rows if x['kind']=='TOOL_EVENT_CONSTRUCTION' and x['ok_expr'] not in {'','NOT_SUPPLIED'}]

        # Static ordering: same function, compare source line numbers.
        ordering=[]
        for h in post_hooks:
            same=[e for e in event_rows if e['relative_path']==h['relative_path'] and e['function']==h['function']]
            before=[e for e in same if e['line']<h['call_line']]
            after=[e for e in same if e['line']>h['call_line']]
            ordering.append({'relative_path':h['relative_path'],'function':h['function'],'hook_line':h['call_line'],'event_before':json.dumps(before,sort_keys=True),'event_after':json.dumps(after,sort_keys=True),'current_event_with_ok_before':any(e['kind']=='TOOL_EVENT_CONSTRUCTION' and e['ok_expr'] not in {'','NOT_SUPPLIED'} for e in before),'event_append_before':any(e['kind']=='EVENT_APPEND' for e in before),'event_append_after':any(e['kind']=='EVENT_APPEND' for e in after)})
        trace_current_possible=any(x['current_event_with_ok_before'] and x['event_append_before'] for x in ordering)

        # Exception control-flow may establish that POST_TOOL_CALL is success-only only
        # if every enclosing function places it in try-body after tool call and not in
        # finally/except. This runner records candidates but does not infer from output.
        exception_candidates=[]
        for p,text,tree in parsed:
            rel=str(p.relative_to(root))
            for f in function_ancestors(tree):
                if 'POST_TOOL_CALL' not in up(f):continue
                tries=[n for n in ast.walk(f) if isinstance(n,ast.Try)]
                for t in tries:
                    post_body=any('POST_TOOL_CALL' in up(n) for n in t.body)
                    post_handler=any('POST_TOOL_CALL' in up(n) for h in t.handlers for n in h.body)
                    post_finally=any('POST_TOOL_CALL' in up(n) for n in t.finalbody)
                    tool_body=any(isinstance(n,ast.Call) and any(k in call_name(n).lower() for k in ['tool','execute','invoke','call']) for n in ast.walk(ast.Module(body=t.body,type_ignores=[])))
                    exception_candidates.append({'relative_path':rel,'file_sha256':sha(p),'function':f.name,'try_line':t.lineno,'tool_call_in_try_body':tool_body,'post_hook_in_try_body':post_body,'post_hook_in_except':post_handler,'post_hook_in_finally':post_finally,'source':up(t)})
        success_only_control=bool(exception_candidates) and all(x['tool_call_in_try_body'] and x['post_hook_in_try_body'] and not x['post_hook_in_except'] and not x['post_hook_in_finally'] for x in exception_candidates)

        # Context-only feasibility requires a concrete context expression carrying
        # event/trace history and the public official event schema using ok/name/args/output.
        context_event_routes=[x for x in guardrail_rows if x['context_has_events_token']]
        predicate_schema_source=[]
        for p,text,tree in parsed:
            if str(p.relative_to(root)).replace('\\','/')=='aicomp_sdk/core/predicates.py':
                for n in tree.body:
                    if isinstance(n,ast.FunctionDef) and n.name in {'_secrets_read_in_trace','secrets_read_in_trace'}:predicate_schema_source.append({'relative_path':str(p.relative_to(root)),'file_sha256':sha(p),'function':n.name,'line':n.lineno,'source':up(n),'uses_ok':"get('ok')" in up(n) or 'get("ok")' in up(n),'uses_name':'fs.read' in up(n),'uses_args':"get('args')" in up(n) or 'get("args")' in up(n),'uses_output':"get('output')" in up(n) or 'get("output")' in up(n)})
        schema_complete=any(x['uses_ok'] and x['uses_name'] and x['uses_args'] and x['uses_output'] for x in predicate_schema_source)
        context_only_feasible=bool(context_event_routes) and schema_complete

        add(checks,'S-030','success',True,{'metadata':len(metadata_routes),'context':len(context_routes),'trace':len(trace_routes),'event_ok':len(event_ok_routes)},'all candidate success carriers classified','ARGUMENT_FIDELITY')
        add(checks,'S-031','ordering',True,ordering,'ToolEvent/hook ordering classified','PROVENANCE')
        add(checks,'S-032','control_flow',True,{'candidates':len(exception_candidates),'success_only':success_only_control},'exception-control success route classified','SOURCE_RETRIEVAL')
        add(checks,'S-033','context_route',True,{'guardrail_event_contexts':len(context_event_routes),'official_event_schema_complete':schema_complete},'context-only route classified','PROVENANCE')
        add(checks,'S-034','discipline',True,'NONEMPTY_OUTPUT_NEVER_USED_AS_SUCCESS','no output-implies-success inference','ARGUMENT_FIDELITY')

        # Select strongest direct public route, preferring explicit carriers.
        if metadata_routes:outcome='PUBLIC_POST_TOOL_SUCCESS_IN_METADATA'
        elif context_routes:outcome='PUBLIC_POST_TOOL_SUCCESS_IN_CONTEXT'
        elif trace_routes and trace_current_possible:outcome='PUBLIC_POST_TOOL_SUCCESS_IN_TRACE_EVENT'
        elif success_only_control:outcome='PUBLIC_POST_TOOL_SUCCESS_COMPUTABLE_FROM_EXCEPTION_CONTROL_FLOW'
        elif context_only_feasible:outcome='CONTEXT_ONLY_PRIOR_SUCCESSFUL_READ_ROUTE_FEASIBLE'
        elif post_hooks and not parse_errors:outcome='NO_PUBLIC_POST_TOOL_SUCCESS_EVIDENCE'
        else:outcome='NOT_ESTABLISHED'

        route={'outcome':outcome,'metadata_routes':metadata_routes,'context_routes':context_routes,'trace_routes':trace_routes,'event_ok_routes':event_ok_routes,'ordering':ordering,'exception_control_candidates':exception_candidates,'context_only_guardrail_routes':context_event_routes,'predicate_event_schema':predicate_schema_source,'nonempty_output_implies_success':False}
        requirements=[
          {'id':'SR-001','statement':'Never infer success from nonempty tool_output, modified_output, absence of error text, or POST_TOOL_CALL stage alone.','status':'REQUIRED'},
          {'id':'SR-002','statement':'Use only an explicit public current-event success value or source-proven success-only control flow.','status':'REQUIRED'},
          {'id':'SR-003','statement':'For a trace route, uniquely bind the current ToolEvent and preserve name, args, ok, output, and order.','status':'REQUIRED'},
          {'id':'SR-004','statement':'For a context-only route, guardrail context must contain prior ordered successful fs.read events with the official event schema.','status':'REQUIRED'},
          {'id':'SR-005','statement':'Preserve source_access, source_success, protected_path, and raw_read_output as separate evidence fields.','status':'REQUIRED'},
          {'id':'SR-006','statement':'Do not modify aicomp_sdk, create aicomp_sdk_exfil, or create implementation in this gate.','status':'REQUIRED'},
          {'id':'SR-007','statement':'Predicate and breach remain independently recomputed and are not executed in this gate.','status':'REQUIRED'},
        ]
        failed=[x['check_id'] for x in checks if not x['passed']]
        pass_gate=not failed and outcome!='NOT_ESTABLISHED'
        status='EX9_R4_R1_POST_TOOL_SUCCESS_EVIDENCE_ROUTE_RECONCILIATION_COMPLETE_PASS' if pass_gate else 'EX9_R4_R1_POST_TOOL_SUCCESS_EVIDENCE_ROUTE_RECONCILIATION_COMPLETE_WITH_GAPS'
        hook_pass=outcome in {'PUBLIC_POST_TOOL_SUCCESS_IN_METADATA','PUBLIC_POST_TOOL_SUCCESS_IN_CONTEXT','PUBLIC_POST_TOOL_SUCCESS_IN_TRACE_EVENT','PUBLIC_POST_TOOL_SUCCESS_COMPUTABLE_FROM_EXCEPTION_CONTROL_FLOW'}
        context_pass=outcome=='CONTEXT_ONLY_PRIOR_SUCCESSFUL_READ_ROUTE_FEASIBLE'
        next_gate='EXFIL_STATEFUL_GUARDRAIL_IMPLEMENTATION_AND_IDENTITY_FREEZE' if hook_pass and pass_gate else ('EXFIL_CONTEXT_LINEAGE_GUARDRAIL_IMPLEMENTATION_AND_IDENTITY_FREEZE' if context_pass and pass_gate else 'EX9_R4_R2_PUBLIC_SUCCESS_ROUTE_DISPOSITION_FREEZE')
        claim={'allowed':['complete static POST_TOOL_CALL HookContext construction inventory','success carrier and ToolEvent ordering classification','exception control-flow classification','ordinary guardrail context event-route classification','selection of one public architecture route'],'prohibited':['infer success from output','claim implementation exists','modify aicomp_sdk','create aicomp_sdk_exfil','runtime fs.read capture','runtime http.post decision','predicate or breach execution','guardrail effectiveness','protected-value lineage','real exfiltration prevention']}
        result={'version':VERSION,'created_at_utc':now(),'status':status,'classification':'READ_ONLY_TARGETED_CONSTRUCTION_AND_ORDERING_INSPECTION','EX9_R4_parent_verified':True,'parent_result':{'checks':'31_OF_32','failed_ids':['F-023'],'outcome':'PUBLIC_HOOK_OUTPUT_FIELDS_INSUFFICIENT','preserved_immutable':True},'checks':{'total':len(checks),'passed':len(checks)-len(failed),'failed':len(failed),'failed_ids':failed},'outcome':outcome,'route':route,'readiness':{'implementation_creation_eligible':(hook_pass or context_pass) and pass_gate,'controlled_actual_fs_read_eligible':False,'http_sink_eligible':False},'execution_boundaries':{'parent_artifacts_modified':False,'frozen_aicomp_sdk_modified':False,'aicomp_sdk_exfil_created':False,'source_modified':False,'implementation_created':False,'sdk_modules_imported':False,'sdk_modules_executed':False,'Sandbox_instantiated':False,'Sandbox_interact_executed':False,'Gym_executed':False,'real_tools_executed':False,'actual_fs_read_executed':False,'http_sink_executed':False,'predicates_executed':False,'breach_executed':False,'models_used':False,'threads_executed':False,'external_effects_observed':False},'scientific_verdict':{'success_evidence_route':outcome,'implementation_behavior':'NOT_EVALUATED','actual_source_retrieval':'NOT_EVALUATED','protected_value_lineage':'NOT_ESTABLISHED','harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'},'claim_boundary':claim,'next_gate':next_gate}
        o={'result':out/'ex9_r4_r1_result.json','checks':out/'ex9_r4_r1_checks.csv','sources':out/'ex9_r4_r1_source_identities.csv','hooks':out/'ex9_r4_r1_hook_constructions.csv','events':out/'ex9_r4_r1_tool_event_sites.csv','ordering':out/'ex9_r4_r1_ordering.csv','control':out/'ex9_r4_r1_exception_control.csv','guardrail':out/'ex9_r4_r1_guardrail_contexts.csv','schema':out/'ex9_r4_r1_event_schema.csv','route':out/'ex9_r4_r1_route_freeze.json','requirements':out/'ex9_r4_r1_requirements.csv','claim':out/'ex9_r4_r1_claim_boundary.json','binding':out/'ex9_r4_r1_binding.json'}
        wj(o['result'],result);wc(o['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']);wc(o['sources'],source_rows,['artifact','relative_path','role','size_bytes','sha256','path']);wc(o['hooks'],hook_rows,['relative_path','file_sha256','function','function_line','call_line','post_tool_context','call_expression','tool_name_expr','tool_args_expr','tool_output_expr','metadata_expr','context_expr','trace_expr','hook_state_expr','metadata_success_token','context_success_token','trace_success_token']);wc(o['events'],event_rows,['relative_path','file_sha256','function','function_line','line','kind','expression','name_expr','args_expr','ok_expr','output_expr']);wc(o['ordering'],ordering,['relative_path','function','hook_line','event_before','event_after','current_event_with_ok_before','event_append_before','event_append_after']);wc(o['control'],exception_candidates,['relative_path','file_sha256','function','try_line','tool_call_in_try_body','post_hook_in_try_body','post_hook_in_except','post_hook_in_finally','source']);wc(o['guardrail'],guardrail_rows,['relative_path','file_sha256','function','function_line','call_line','call_expression','context_expr','context_has_events_token','context_has_success_token']);wc(o['schema'],predicate_schema_source,['relative_path','file_sha256','function','line','uses_ok','uses_name','uses_args','uses_output','source']);wj(o['route'],route);wc(o['requirements'],requirements,['id','statement','status']);wj(o['claim'],claim);wj(o['binding'],{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'parent':{k:ident(v) for k,v in parent.items()},'sources':{x['relative_path']:ident(Path(x['path'])) for x in source_rows},'frozen_aicomp_sdk_modified':False,'aicomp_sdk_exfil_created':False,'implementation_created':False,'sdk_modules_imported':False,'sdk_modules_executed':False})
        rows=[{**ident(p),'role':'EX9_R4_R1_DERIVED'} for p in o.values()]+[{**ident(p),'role':'EX9_R4_R1_BOUND_PARENT'} for p in parent.values()]+[{**ident(Path(x['path'])),'role':'EX9_R4_R1_RELEVANT_SOURCE'} for x in source_rows]
        mp=out/'ex9_r4_r1_manifest.csv';wc(mp,rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'ex9_r4_r1_manifest_external_binding.json';wj(ep,{'version':VERSION,'created_at_utc':now(),'status':status,'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':sha(mp),'runner_sha256':sha(Path(__file__).resolve()),'parent_EX9_R4_manifest_sha256':PARENT_MANIFEST_SHA,'checks_total':len(checks),'checks_passed':len(checks)-len(failed),'checks_failed':len(failed),'outcome':outcome,'frozen_aicomp_sdk_modified':False,'aicomp_sdk_exfil_created':False,'implementation_creation_eligible':result['readiness']['implementation_creation_eligible'],'controlled_actual_fs_read_eligible':False,'implementation_created':False,'next_gate':next_gate})
        print(json.dumps({'status':status,'parent':'31/32 preserved with F-023 failed','checks':f'{len(checks)-len(failed)}/{len(checks)}','outcome':outcome,'hook_constructions':len(hook_rows),'post_tool_constructions':len(post_hooks),'tool_event_sites':len(event_rows),'guardrail_contexts':len(guardrail_rows),'nonempty_output_implies_success':False,'frozen_aicomp_sdk_modified':False,'aicomp_sdk_exfil_created':False,'implementation_created':False,'controlled_actual_fs_read_eligible':False,'manifest_sha256':sha(mp),'next_gate':next_gate},indent=2))
    except Exception as e:
        (out/'EX9_R4_R1_FAILED.json').write_text(json.dumps({'version':VERSION,'created_at_utc':now(),'status':'EX9_R4_R1_RECONCILIATION_BLOCKED','error_type':type(e).__name__,'error':str(e),'checks_frozen':checks,'frozen_aicomp_sdk_modified':False,'aicomp_sdk_exfil_created':False,'source_modified':False,'implementation_created':False,'sdk_modules_imported':False,'sdk_modules_executed':False,'actual_fs_read_executed':False},indent=2),encoding='utf-8');raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for f in ['r4-result','r4-checks','r4-hook-contract','r4-source-identities','r4-feasibility-freeze','r4-architecture','r4-matcher-candidates','r4-claim-boundary','r4-binding','r4-external-binding','r4-manifest','r4-runner','project-root','output-dir']:p.add_argument('--'+f,required=True)
    return p.parse_args()
if __name__=='__main__':
    try:main(args())
    except Exception as e:print(f'FAILED: {e}',file=sys.stderr);raise SystemExit(1)
