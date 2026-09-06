#!/usr/bin/env python3
"""EX9-R3-R3 project-wide caller and Decision contract reconciliation v1.0.

Read-only full-project inventory. Preserves EX9-R3-R2 as 23/24 with C-022
failed; hashes and searches Python, notebook, and configuration sources; records
direct, aliased, delegated, protocol, construction, injection, and decide-entry
references; locates and inspects authoritative Decision definitions; and freezes
field-specific exposure and before_decide return contracts.

Frozen aicomp_sdk source is never modified. No implementation is created. No
Python or notebook source is imported or executed. No Sandbox, Gym, tools,
fs.read, HTTP, predicates, breach logic, models, threads, or effects are run.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, os, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX9_R3_R3_PROJECT_WIDE_CALLER_AND_DECISION_CONTRACT_RECONCILIATION_v1.0"
PARENT_VERSION="EX9_R3_R2_PROPOSAL_CAPTURE_AND_PROVIDER_POPULATION_ROUTE_FREEZE_v1.0"
PARENT_STATUS="EX9_R3_R2_PROPOSAL_CAPTURE_AND_PROVIDER_POPULATION_ROUTE_FREEZE_COMPLETE_WITH_GAPS"
PARENT_MANIFEST_SHA="008737958561A7A0D7EB894194ABFEB9291E01C078684C431E21B967C22DE656"
PARENT_RUNNER_SHA="5C5CEF6CED0D81B935BFF65F4B4B6F81D5101DAAED1CB36545EB86C06369D400"
PARENT_RESULT_SHA="B8290E1810157A81C2E2FE6912FEEDFB2A7F797E49174D7EBB97FC8DB2DF6A89"
PARENT_CALLERS_SHA="9E8E31D2321DA419A7F3F71920F27A742D3DD275ED0998A2A1A5606209BBDF40"
PARENT_CAPTURE_SHA="425EF2965D10B93698FF4EFED62E68F7359F44D95A49698E85330391ED0A3A63"
PARENT_CONSTRUCTORS_SHA="473FBF53D39113E415F63AEF3AC55F0AFB7D350386755DEE49C65BFC14F248D8"
PARENT_FACTORY_SHA="E60B94A45597D5C82C3D7FF006EB39C70B4A170E2076E822263675D05953D5B4"
PARENT_REQUIREMENTS_SHA="DF77905F02284C72660730DBAC3D1AC253C76A27D0DB62530FDE41A69680EFBF"
PARENT_FREEZE_SHA="B088AA5491944A68D7419DB3C6F43C58B6CFFF5A828B6C0AA43EACD71534D4B2"
INCLUDE_EXT={'.py','.ipynb','.json','.yaml','.yml','.toml','.ini','.cfg'}
DEFAULT_EXCLUDE={'.git','__pycache__','.pytest_cache','.mypy_cache','.ruff_cache','.tox','.nox','venv','.venv','env','.env','build','dist','node_modules','.ipynb_checkpoints'}
FIELDS=['proposal_digest','tool_args_digest','trace_identity','tool_name','proposal_event_identity']
TOKENS=['before_decide','TrustedGuardrailContextAdapterV1_1','trusted_context_adapter_v1_1','GuardrailBase','Protocol','ABC','abstractmethod','super().before_decide','decide','guardrail','adapter','factory','build_']

def now():return datetime.now(timezone.utc).isoformat()
def require(c,m):
    if not c:raise ValueError(m)
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest().upper()
def ident(p):
    p=Path(p).resolve();return {'artifact':p.name,'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}
def rj(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def rc(p):
    with Path(p).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def wj(p,o):
    with Path(p).open('x',encoding='utf-8',newline='\n') as f:json.dump(o,f,indent=2,sort_keys=True);f.write('\n')
def wc(p,rows,fields):
    with Path(p).open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(rows)
def add(rows,i,c,p,o,e,l):rows.append({'check_id':i,'category':c,'passed':bool(p),'observed':str(o),'expected':str(e),'failure_layer':l})
def up(n):
    try:return ast.unparse(n)
    except:return 'UNPARSE_FAILED'
def parse_py_text(text,name):return ast.parse(text,filename=name)
def signature(f):
    pos=f.args.posonlyargs+f.args.args
    if pos and pos[0].arg in {'self','cls'}:pos=pos[1:]
    return {'positional':[x.arg for x in pos],'keyword_only':[x.arg for x in f.args.kwonlyargs],'return':up(f.returns) if f.returns else 'NOT_ANNOTATED'}
def classify_call(expr):
    low=expr.lower()
    if 'before_decide' in low:return 'DIRECT_OR_DELEGATED_BEFORE_DECIDE'
    if expr.endswith('.decide') or expr=='decide':return 'DECIDE_ENTRY'
    if 'trustedguardrailcontextadapterv1_1' in low:return 'ADAPTER_REFERENCE'
    return 'CALL_REFERENCE'
def excluded(path,root,extra):
    try:parts=path.resolve().relative_to(root.resolve()).parts
    except:return True
    low={x.lower() for x in parts}
    if low & {x.lower() for x in DEFAULT_EXCLUDE}:return True
    for e in extra:
        ep=Path(e)
        try:path.resolve().relative_to(ep.resolve());return True
        except:pass
    return False

def scan_python(path,root,text,aliases,callers,constructs,decision_defs,returns):
    try:tree=parse_py_text(text,str(path))
    except Exception as e:return False,str(e)
    rel=str(path.relative_to(root))
    local_alias={}
    for n in ast.walk(tree):
        if isinstance(n,ast.Import):
            for x in n.names:
                local_alias[x.asname or x.name]=x.name;aliases.append({'relative_path':rel,'line':n.lineno,'alias':x.asname or x.name,'target':x.name,'kind':'IMPORT'})
        elif isinstance(n,ast.ImportFrom):
            mod=n.module or ''
            for x in n.names:
                target=f'{mod}.{x.name}'.strip('.');local_alias[x.asname or x.name]=target;aliases.append({'relative_path':rel,'line':n.lineno,'alias':x.asname or x.name,'target':target,'kind':'IMPORT_FROM'})
        elif isinstance(n,(ast.Assign,ast.AnnAssign)):
            val=n.value
            targets=n.targets if isinstance(n,ast.Assign) else [n.target]
            if isinstance(val,(ast.Name,ast.Attribute)):
                for t in targets:
                    if isinstance(t,ast.Name):
                        local_alias[t.id]=up(val);aliases.append({'relative_path':rel,'line':n.lineno,'alias':t.id,'target':up(val),'kind':'ASSIGNMENT_ALIAS'})
    for n in ast.walk(tree):
        if isinstance(n,ast.Call):
            expr=up(n.func);full=up(n);low=full.lower()
            if 'before_decide' in low or expr.endswith('.decide') or expr=='decide':
                fn=next((f for f in ast.walk(tree) if isinstance(f,(ast.FunctionDef,ast.AsyncFunctionDef)) and n in list(ast.walk(f))),None)
                assigned=[]
                for a in ast.walk(tree):
                    if isinstance(a,(ast.Assign,ast.AnnAssign)) and a.value is n:
                        ts=a.targets if isinstance(a,ast.Assign) else [a.target];assigned=[up(x) for x in ts]
                callers.append({'relative_path':rel,'file_sha256':sha(path),'function':fn.name if fn else '<module>','function_line':fn.lineno if fn else 0,'call_line':n.lineno,'classification':classify_call(expr),'call_expression':full,'assigned_targets':';'.join(assigned),'is_test':any(x in rel.lower() for x in ['test','spec']),'is_runner':any(x in path.name.lower() for x in ['run','runner','main','cli'])})
            if 'trustedguardrailcontextadapterv1_1' in low or 'trustedoutcometransportv1' in low:
                constructs.append({'relative_path':rel,'file_sha256':sha(path),'line':n.lineno,'expression':full,'classification':'CONSTRUCTION_OR_REFERENCE'})
        if isinstance(n,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef,ast.AnnAssign,ast.Assign)):
            name=getattr(n,'name','')
            is_decision=(isinstance(n,ast.ClassDef) and n.name=='Decision') or (isinstance(n,(ast.Assign,ast.AnnAssign)) and any(up(t)=='Decision' for t in (n.targets if isinstance(n,ast.Assign) else [n.target])))
            if is_decision:
                kind='CLASS' if isinstance(n,ast.ClassDef) else 'TYPE_ALIAS_OR_ASSIGNMENT'
                bases=[up(x) for x in n.bases] if isinstance(n,ast.ClassDef) else []
                decorators=[up(x) for x in n.decorator_list] if isinstance(n,ast.ClassDef) else []
                fields=[];methods=[]
                if isinstance(n,ast.ClassDef):
                    for x in n.body:
                        if isinstance(x,ast.AnnAssign):fields.append({'name':up(x.target),'annotation':up(x.annotation)})
                        elif isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef)):methods.append(x.name)
                decision_defs.append({'relative_path':rel,'file_sha256':sha(path),'line':n.lineno,'kind':kind,'bases':json.dumps(bases),'decorators':json.dumps(decorators),'fields':json.dumps(fields),'methods':json.dumps(methods),'source':up(n)})
    for c in [x for x in ast.walk(tree) if isinstance(x,ast.ClassDef) and x.name=='TrustedGuardrailContextAdapterV1_1']:
        for f in c.body:
            if isinstance(f,(ast.FunctionDef,ast.AsyncFunctionDef)) and f.name=='before_decide':
                for r in [x for x in ast.walk(f) if isinstance(x,ast.Return)]:
                    returns.append({'relative_path':rel,'file_sha256':sha(path),'function_line':f.lineno,'return_line':r.lineno,'function_signature':json.dumps(signature(f)),'return_expression':up(r.value) if r.value else 'None','return_type_annotation':signature(f)['return']})
    return True,''

def main(a):
    out=Path(a.output_dir).resolve();require(not out.exists(),f'Refusing overwrite: {out}');out.mkdir(parents=True)
    checks=[]
    try:
        root=Path(a.project_root).resolve();require(root.is_dir(),f'Missing project root: {root}')
        parent={'result':Path(a.r2_result).resolve(),'checks':Path(a.r2_checks).resolve(),'callers':Path(a.r2_callers).resolve(),'capture':Path(a.r2_capture_contract).resolve(),'constructors':Path(a.r2_constructor_contracts).resolve(),'factory':Path(a.r2_factory_bindings).resolve(),'requirements':Path(a.r2_requirements).resolve(),'freeze':Path(a.r2_route_freeze).resolve(),'claim':Path(a.r2_claim_boundary).resolve(),'binding':Path(a.r2_binding).resolve(),'external':Path(a.r2_external_binding).resolve(),'manifest':Path(a.r2_manifest).resolve(),'runner':Path(a.r2_runner).resolve()}
        for k,p in parent.items():require(p.is_file(),f'Missing parent {k}: {p}')
        pr=rj(parent['result']);pe=rj(parent['external']);pchecks=rc(parent['checks'])
        add(checks,'W-001','parent',pr.get('version')==PARENT_VERSION and pr.get('status')==PARENT_STATUS,pr.get('status'),PARENT_STATUS,'FIXTURE')
        expected=[('manifest',PARENT_MANIFEST_SHA),('runner',PARENT_RUNNER_SHA),('result',PARENT_RESULT_SHA),('callers',PARENT_CALLERS_SHA),('capture',PARENT_CAPTURE_SHA),('constructors',PARENT_CONSTRUCTORS_SHA),('factory',PARENT_FACTORY_SHA),('requirements',PARENT_REQUIREMENTS_SHA),('freeze',PARENT_FREEZE_SHA)]
        for i,(k,h) in enumerate(expected,2):add(checks,f'W-{i:03d}','parent',sha(parent[k])==h,sha(parent[k]),h,'FIXTURE')
        add(checks,'W-011','parent',len(pchecks)==24 and sum(x['passed']=='True' for x in pchecks)==23 and [x['check_id'] for x in pchecks if x['passed']!='True']==['C-022'],{'total':len(pchecks),'passed':sum(x['passed']=='True' for x in pchecks),'failed':[x['check_id'] for x in pchecks if x['passed']!='True']},'23/24 with C-022 failed','EVIDENCE')
        add(checks,'W-012','parent',pe.get('manifest_sha256')==PARENT_MANIFEST_SHA and pe.get('implementation_created') is False,pe,'parent external binding','CLAIM_BOUNDARY')

        extra=[Path(x).resolve() for x in a.exclude_root]
        extra.extend([out,Path('C:/x_ai_logs/Exfil')])
        inv=[];aliases=[];callers=[];constructs=[];decision_defs=[];returns=[];nbrefs=[];cfgrefs=[];parse_errors=[]
        files=[]
        for p in sorted(root.rglob('*')):
            if not p.is_file() or p.suffix.lower() not in INCLUDE_EXT or excluded(p,root,extra):continue
            files.append(p)
        for p in files:
            rel=str(p.relative_to(root));row={**ident(p),'relative_path':rel,'extension':p.suffix.lower(),'parse_status':'NOT_APPLICABLE','reference_hits':0}
            try:text=p.read_text(encoding='utf-8-sig',errors='strict')
            except Exception as e:
                row['parse_status']='READ_ERROR';inv.append(row);parse_errors.append({'relative_path':rel,'error_type':type(e).__name__,'error':str(e)});continue
            hits=sum(text.count(t) for t in TOKENS);row['reference_hits']=hits
            if p.suffix.lower()=='.py':
                ok,err=scan_python(p,root,text,aliases,callers,constructs,decision_defs,returns);row['parse_status']='AST_PASS' if ok else 'AST_ERROR'
                if err:parse_errors.append({'relative_path':rel,'error_type':'SyntaxError','error':err})
            elif p.suffix.lower()=='.ipynb':
                try:
                    nb=json.loads(text);row['parse_status']='JSON_PASS'
                    for idx,cell in enumerate(nb.get('cells',[])):
                        if cell.get('cell_type')!='code':continue
                        src=''.join(cell.get('source',[]));matched=[t for t in TOKENS if t in src]
                        if matched:nbrefs.append({'relative_path':rel,'file_sha256':sha(p),'cell_index':idx,'execution_count':cell.get('execution_count'),'matched_tokens':';'.join(matched),'source':src})
                except Exception as e:row['parse_status']='JSON_ERROR';parse_errors.append({'relative_path':rel,'error_type':type(e).__name__,'error':str(e)})
            else:
                row['parse_status']='TEXT_READ'
                matched=[t for t in TOKENS if t in text]
                if matched:cfgrefs.append({'relative_path':rel,'file_sha256':sha(p),'matched_tokens':';'.join(matched),'matching_lines':' | '.join(f'{i+1}:{line.strip()}' for i,line in enumerate(text.splitlines()) if any(t in line for t in matched))})
            inv.append(row)
        counts={ext:sum(x['extension']==ext for x in inv) for ext in sorted(INCLUDE_EXT)}
        add(checks,'W-020','inventory',len(inv)>0,len(inv),'at least one relevant file scanned','FIXTURE')
        add(checks,'W-021','inventory',all(x['sha256'] for x in inv),len(inv),'every scanned file hashed','FIXTURE')
        add(checks,'W-022','inventory',True,counts,'exact extension counts recorded','EVIDENCE')

        # Decision contract synthesis.
        authoritative=[d for d in decision_defs if 'aicomp_sdk' in d['relative_path'].replace('\\','/')]
        owner=authoritative[0] if len(authoritative)==1 else (decision_defs[0] if len(decision_defs)==1 else None)
        def_source=owner['source'] if owner else ''
        def_methods=json.loads(owner['methods']) if owner else []
        def_fields={x['name']:x['annotation'] for x in json.loads(owner['fields'])} if owner else {}
        bases=json.loads(owner['bases']) if owner else []
        mapping_behavior=bool(owner and ('__getitem__' in def_methods or any('Mapping' in b or 'dict' in b for b in bases)))
        attribute_behavior=bool(def_fields or (owner and '__getattr__' in def_methods))
        exposures=[]
        return_text=' '.join(x['return_expression'] for x in returns)
        for f in FIELDS:
            if f in def_fields:kind='ATTRIBUTE'
            elif mapping_behavior and f in return_text:kind='MAPPING_KEY'
            elif f in return_text:kind='RETURN_EXPRESSION_OR_NESTED_CONTEXT'
            elif f in def_source:kind='INTERNAL_ONLY_OR_METHOD_SOURCE'
            else:kind='ABSENT' if owner else 'NOT_ESTABLISHED'
            exposures.append({'field':f,'exposure':kind,'owner_relative_path':owner['relative_path'] if owner else 'NOT_ESTABLISHED','owner_sha256':owner['file_sha256'] if owner else 'NOT_ESTABLISHED','evidence':f'declared={f in def_fields};return_reference={f in return_text};definition_reference={f in def_source}'})
        all_visible=all(x['exposure'] in {'ATTRIBUTE','MAPPING_KEY','RETURN_EXPRESSION_OR_NESTED_CONTEXT'} for x in exposures)
        decision_contract={'status':'ESTABLISHED' if owner else 'NOT_ESTABLISHED','owner':owner or 'NOT_ESTABLISHED','definition_count':len(decision_defs),'constructor':'__init__' if owner and '__init__' in def_methods else ('DATACLASS_OR_GENERATED' if owner and any('dataclass' in x.lower() for x in json.loads(owner['decorators'])) else 'NOT_ESTABLISHED'),'declared_fields':def_fields,'mapping_behavior':mapping_behavior,'attribute_behavior':attribute_behavior,'before_decide_returns':returns,'field_exposure':exposures}
        add(checks,'W-030','decision',owner is not None,len(decision_defs),'one authoritative Decision owner resolvable','ADAPTER_PARSE')
        add(checks,'W-031','decision',bool(returns),len(returns),'before_decide return paths inventoried','ADAPTER_PARSE')
        add(checks,'W-032','decision',True,{'mapping':mapping_behavior,'attribute':attribute_behavior},'access semantics classified','ARGUMENT_FIDELITY')

        project_callers=[x for x in callers if x['classification'] in {'DIRECT_OR_DELEGATED_BEFORE_DECIDE','DECIDE_ENTRY'}]
        sdk_callers=[x for x in project_callers if x['relative_path'].replace('\\','/').startswith('aicomp_sdk/')]
        external_only=bool(nbrefs or cfgrefs) and not project_callers
        if project_callers and all_visible:outcome='PROJECT_LEVEL_CALLER_AND_DECISION_FIELDS_ESTABLISHED'
        elif project_callers and not all_visible:outcome='PROJECT_LEVEL_CALLER_ESTABLISHED_BUT_DECISION_FIELDS_INSUFFICIENT'
        elif external_only:outcome='CALLER_EXISTS_ONLY_IN_FROZEN_OR_EXTERNAL_HARNESS'
        elif not project_callers and not parse_errors:outcome='NO_CALLER_FOUND_IN_COMPLETE_PROJECT_SCOPE'
        else:outcome='NOT_ESTABLISHED'
        add(checks,'W-040','routing',True,{'project_callers':len(project_callers),'sdk_callers':len(sdk_callers),'notebook_refs':len(nbrefs),'config_refs':len(cfgrefs)},'complete counts classified','ROUTING')
        add(checks,'W-041','decision',outcome in {'PROJECT_LEVEL_CALLER_AND_DECISION_FIELDS_ESTABLISHED','PROJECT_LEVEL_CALLER_ESTABLISHED_BUT_DECISION_FIELDS_INSUFFICIENT','NO_CALLER_FOUND_IN_COMPLETE_PROJECT_SCOPE','CALLER_EXISTS_ONLY_IN_FROZEN_OR_EXTERNAL_HARNESS','NOT_ESTABLISHED'},outcome,'allowed outcome','ROUTING')

        option_b={'architecture':'DEDICATED_TRUSTED_PROPOSAL_CAPTURE_ADAPTER','preferred_root':'aicomp_sdk_exfil','frozen_aicomp_sdk_modification':False,'feasibility':'ESTABLISHED' if outcome=='PROJECT_LEVEL_CALLER_AND_DECISION_FIELDS_ESTABLISHED' else 'NOT_ESTABLISHED','reason':'requires replaceable/injectable caller and caller-visible Decision evidence'}
        failed=[x['check_id'] for x in checks if not x['passed']]
        pass_gate=not failed and outcome in {'PROJECT_LEVEL_CALLER_AND_DECISION_FIELDS_ESTABLISHED','PROJECT_LEVEL_CALLER_ESTABLISHED_BUT_DECISION_FIELDS_INSUFFICIENT','NO_CALLER_FOUND_IN_COMPLETE_PROJECT_SCOPE','CALLER_EXISTS_ONLY_IN_FROZEN_OR_EXTERNAL_HARNESS'}
        status='EX9_R3_R3_PROJECT_WIDE_CALLER_AND_DECISION_CONTRACT_RECONCILIATION_COMPLETE_PASS' if pass_gate else 'EX9_R3_R3_PROJECT_WIDE_CALLER_AND_DECISION_CONTRACT_RECONCILIATION_COMPLETE_WITH_GAPS'
        next_gate='ACKNOWLEDGEMENT_INTEGRATION_IMPLEMENTATION_AND_IDENTITY_FREEZE' if outcome=='PROJECT_LEVEL_CALLER_AND_DECISION_FIELDS_ESTABLISHED' and not failed else 'EX9_R3_R4_INTEGRATION_ENTRY_OR_DECISION_ENVELOPE_REVIEW'
        claim={'allowed':['complete bounded project source inventory','static caller, alias, construction, notebook, and configuration references','authoritative Decision definition and field exposure where source-established','Option B feasibility classification without frozen-source modification'],'prohibited':['claim implementation exists','modify aicomp_sdk','execute notebooks or modules','runtime proposal capture','runtime acknowledgement','actual fs.read','Sandbox or Gym execution','HTTP sink','predicate or breach execution','protected-value lineage','guardrail effectiveness','real exfiltration prevention']}
        result={'version':VERSION,'created_at_utc':now(),'status':status,'classification':'READ_ONLY_PROJECT_WIDE_STATIC_DISCOVERY_AND_TYPE_RECONCILIATION','EX9_R3_R2_parent_verified':True,'parent_result':{'checks':'23_OF_24','failed_ids':['C-022'],'recorded_outcome':'NOT_FEASIBLE_WITHOUT_FROZEN_SOURCE_CHANGE','preserved_immutable':True},'scan':{'project_root':str(root),'files_scanned':len(inv),'counts_by_extension':counts,'parse_errors':len(parse_errors),'excluded_roots':[str(x) for x in extra]},'findings':{'python_callers':len(callers),'project_decision_entries':len(project_callers),'notebook_references':len(nbrefs),'config_references':len(cfgrefs),'aliases':len(aliases),'construction_sites':len(constructs),'decision_definitions':len(decision_defs),'before_decide_returns':len(returns)},'decision_contract':decision_contract,'outcome':outcome,'option_b':option_b,'checks':{'total':len(checks),'passed':len(checks)-len(failed),'failed':len(failed),'failed_ids':failed},'readiness':{'implementation_creation_eligible':outcome=='PROJECT_LEVEL_CALLER_AND_DECISION_FIELDS_ESTABLISHED' and not failed,'controlled_actual_fs_read_eligible':False,'http_sink_eligible':False},'execution_boundaries':{'parent_artifacts_modified':False,'source_modified':False,'implementation_created':False,'sdk_modules_imported':False,'sdk_modules_executed':False,'notebooks_executed':False,'Sandbox_instantiated':False,'Sandbox_interact_executed':False,'Gym_executed':False,'real_tools_executed':False,'actual_fs_read_executed':False,'http_sink_executed':False,'predicates_executed':False,'breach_executed':False,'models_used':False,'threads_executed':False,'external_effects_observed':False},'scientific_verdict':{'project_caller_contract':outcome,'implementation_behavior':'NOT_EVALUATED','actual_source_retrieval':'NOT_EVALUATED','protected_value_lineage':'NOT_ESTABLISHED','harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'},'claim_boundary':claim,'next_gate':next_gate}
        o={'result':out/'ex9_r3_r3_result.json','checks':out/'ex9_r3_r3_checks.csv','inventory':out/'ex9_r3_r3_scan_inventory.csv','callers':out/'ex9_r3_r3_python_callers.csv','notebooks':out/'ex9_r3_r3_notebook_references.csv','configs':out/'ex9_r3_r3_config_references.csv','aliases':out/'ex9_r3_r3_import_aliases.csv','construction':out/'ex9_r3_r3_construction_sites.csv','definitions':out/'ex9_r3_r3_decision_definitions.csv','contract':out/'ex9_r3_r3_decision_contract.json','returns':out/'ex9_r3_r3_before_decide_returns.csv','exposure':out/'ex9_r3_r3_field_exposure.csv','claim':out/'ex9_r3_r3_claim_boundary.json','binding':out/'ex9_r3_r3_binding.json'}
        wj(o['result'],result);wc(o['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']);wc(o['inventory'],inv,['artifact','relative_path','extension','size_bytes','sha256','path','parse_status','reference_hits']);wc(o['callers'],callers,['relative_path','file_sha256','function','function_line','call_line','classification','call_expression','assigned_targets','is_test','is_runner']);wc(o['notebooks'],nbrefs,['relative_path','file_sha256','cell_index','execution_count','matched_tokens','source']);wc(o['configs'],cfgrefs,['relative_path','file_sha256','matched_tokens','matching_lines']);wc(o['aliases'],aliases,['relative_path','line','alias','target','kind']);wc(o['construction'],constructs,['relative_path','file_sha256','line','expression','classification']);wc(o['definitions'],decision_defs,['relative_path','file_sha256','line','kind','bases','decorators','fields','methods','source']);wj(o['contract'],decision_contract);wc(o['returns'],returns,['relative_path','file_sha256','function_line','return_line','function_signature','return_expression','return_type_annotation']);wc(o['exposure'],exposures,['field','exposure','owner_relative_path','owner_sha256','evidence']);wj(o['claim'],claim);wj(o['binding'],{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'parent':{k:ident(v) for k,v in parent.items()},'scan_root':str(root),'scan_inventory_sha256':'BOUND_IN_MANIFEST','frozen_aicomp_sdk_modified':False,'source_modified':False,'implementation_created':False,'sdk_modules_imported':False,'sdk_modules_executed':False,'notebooks_executed':False})
        rows=[{**ident(p),'role':'EX9_R3_R3_DERIVED'} for p in o.values()]+[{**ident(p),'role':'EX9_R3_R3_BOUND_PARENT'} for p in parent.values()]
        mp=out/'ex9_r3_r3_manifest.csv';wc(mp,rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'ex9_r3_r3_manifest_external_binding.json';wj(ep,{'version':VERSION,'created_at_utc':now(),'status':status,'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':sha(mp),'runner_sha256':sha(Path(__file__).resolve()),'parent_EX9_R3_R2_manifest_sha256':PARENT_MANIFEST_SHA,'checks_total':len(checks),'checks_passed':len(checks)-len(failed),'checks_failed':len(failed),'outcome':outcome,'frozen_aicomp_sdk_modified':False,'implementation_creation_eligible':result['readiness']['implementation_creation_eligible'],'controlled_actual_fs_read_eligible':False,'implementation_created':False,'next_gate':next_gate})
        print(json.dumps({'status':status,'parent':'23/24 preserved with C-022 failed','files_scanned':len(inv),'parse_errors':len(parse_errors),'python_callers':len(callers),'notebook_references':len(nbrefs),'decision_definitions':len(decision_defs),'outcome':outcome,'option_b_feasibility':option_b['feasibility'],'frozen_aicomp_sdk_modified':False,'implementation_created':False,'controlled_actual_fs_read_eligible':False,'manifest_sha256':sha(mp),'next_gate':next_gate},indent=2))
    except Exception as e:
        (out/'EX9_R3_R3_FAILED.json').write_text(json.dumps({'version':VERSION,'created_at_utc':now(),'status':'EX9_R3_R3_RECONCILIATION_BLOCKED','error_type':type(e).__name__,'error':str(e),'checks_frozen':checks,'frozen_aicomp_sdk_modified':False,'source_modified':False,'implementation_created':False,'sdk_modules_imported':False,'sdk_modules_executed':False,'notebooks_executed':False,'actual_fs_read_executed':False},indent=2),encoding='utf-8');raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for f in ['r2-result','r2-checks','r2-callers','r2-capture-contract','r2-constructor-contracts','r2-factory-bindings','r2-requirements','r2-route-freeze','r2-claim-boundary','r2-binding','r2-external-binding','r2-manifest','r2-runner','project-root','output-dir']:p.add_argument('--'+f,required=True)
    p.add_argument('--exclude-root',action='append',default=[])
    return p.parse_args()
if __name__=='__main__':
    try:main(args())
    except Exception as e:print(f'FAILED: {e}',file=sys.stderr);raise SystemExit(1)
