#!/usr/bin/env python3
"""Controlled V2.1 successful-read ledger qualification v1.0.

Executes the frozen V2.1 ledger with synthetic in-memory evidence only. The V2
ledger is loaded only for the explicit V2.1-to-V2 schema-rejection control.
Package __init__ files are not executed. No hooks, guardrails, factories, SDK,
Sandbox, Gym, tools, fs.read, HTTP, predicates, breach logic, models, threads,
or external effects are executed.
"""
from __future__ import annotations
import argparse, copy, csv, hashlib, importlib.util, json, math, sys, types
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION='CONTROLLED_V2_1_SUCCESSFUL_READ_LEDGER_QUALIFICATION_v1.0'
V21_PACKAGE='aicomp_sdk_exfil_v2_1'; V21_MODULE=V21_PACKAGE+'.successful_read_ledger_v2_1'
V2_PACKAGE='aicomp_sdk_exfil_v2'; V2_MODULE=V2_PACKAGE+'.successful_read_ledger_v2'
EXPECTED={
'repair_manifest':'1EBCD60880B47D1695383715C044303AB6A58F912CE2C0512FC4E46D0F634959',
'independent_manifest':'3F869927070561486ACDC3C9F9DD5A8BAE28EC44C7431AB02F33B5E69F4DAD32',
'independent_result':'37B4B04748C1AA72B8B49558DFCEE505E4EF79249E67800867ED9222CEBCDEC9',
'independent_checks':'B4CD0A711FC3CF5218AB4984A412F461E1CA24EC1821E83260EB882EAA395985',
'independent_boundaries':'18027C543E70560E8A48E01D86D3AC2CD5548F750DA5022CEEB762587A289E71',
'independent_schema':'08BC979311E0297E0CBE0F8F37E36CFEB969F2DB9430250C116E22F12B033A3B',
'independent_runner':'A417FD4749B7FAA5D4AD26DA5A4E2513605D0CCA4EB85CC5BA83757C484B417B',
'failed_v2_evidence':'AF6C0BEB687AE221E33B37224EA5316ADCEA6AA10BAB004E4F1B4A4E1CF0C054',
'v21_ledger':'18146742E6866C491A032AA96EFC248FFED05706895D32FDE724145D0878009C',
'v2_ledger':'609B22AA7ABD3555B24484E2AF313A5460877BA3C446FBE2978C6136D662857E'}
V21_SIZE=8335; V2_SIZE=6645
TOP_KEYS=['schema_tag','next_sequence','records']
RECORD_KEYS=['schema_tag','record_sequence','tool_name','tool_args','tool_args_sha256','canonical_path','explicit_ok','error_value','raw_output','raw_output_sha256','derived_secret_values','record_identity']
RECORD_TAG='EXFIL.SUCCESSFUL.READ.RECORD.V2.1'; LEDGER_TAG='EXFIL.SUCCESSFUL.READ.LEDGER.V2.1'; MINIMUM=6

class Unsupported: pass

def now():return datetime.now(timezone.utc).isoformat()
def need(v,m):
    if not v:raise ValueError(m)
def sha_file(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b)
    return h.hexdigest().upper()
def sha_text(s):return hashlib.sha256(s.encode('utf-8','surrogatepass')).hexdigest().upper()
def ident(p):
    p=Path(p).resolve();return {'artifact':p.name,'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha_file(p)}
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
def digest_state(v):return sha_text(canonical(v))
def rj(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def rc(p):
    with Path(p).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def wj(p,o):
    with Path(p).open('x',encoding='utf-8',newline='\n') as f:json.dump(o,f,indent=2,sort_keys=True,ensure_ascii=False);f.write('\n')
def wc(p,rows,fields):
    with Path(p).open('x',encoding='utf-8',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(rows)
def add(rows,cid,cat,ok,obs,exp,layer):rows.append({'check_id':cid,'category':cat,'passed':bool(ok),'observed':json.dumps(obs,sort_keys=True,ensure_ascii=False,default=str) if isinstance(obs,(dict,list,tuple)) else str(obs),'expected':json.dumps(exp,sort_keys=True,ensure_ascii=False,default=str) if isinstance(exp,(dict,list,tuple)) else str(exp),'failure_layer':layer})
def expect(fn,types=(Exception,),contains=None):
    try:fn()
    except Exception as e:
        ok=isinstance(e,types) and (contains is None or contains in str(e));return {'raised':True,'type':type(e).__name__,'message':str(e),'match':ok}
    return {'raised':False,'type':None,'message':None,'match':False}
def independent_candidates(raw):
    values=set()
    for raw_line in raw.splitlines():
        line=raw_line.strip()
        if not line or line.startswith('#'):continue
        if '=' in line:
            values.add(line);value=line.partition('=')[2].strip()
            if len(value)>=MINIMUM:values.add(value)
        elif len(line)>=MINIMUM:values.add(line)
    return tuple(sorted(values))
def args_digest(args):return sha_text(canonical(dict(args)))
def identity(sequence,tool,path,adig,odig):return sha_text(f'{RECORD_TAG}|{sequence}|{tool}|{path}|{adig}|{odig}')
def record_dict(r):return {'schema_tag':r.schema_tag,'record_sequence':r.record_sequence,'tool_name':r.tool_name,'tool_args':json.loads(canonical(dict(r.tool_args))),'tool_args_sha256':r.tool_args_sha256,'canonical_path':r.canonical_path,'explicit_ok':r.explicit_ok,'error_value':r.error_value,'raw_output':r.raw_output,'raw_output_sha256':r.raw_output_sha256,'derived_secret_values':list(r.derived_secret_values),'record_identity':r.record_identity}

def isolated_load(package_name,module_name,path):
    before=set(sys.modules);need(package_name not in sys.modules and module_name not in sys.modules,f'{package_name} already loaded')
    package=types.ModuleType(package_name);package.__path__=[str(path.parent)];package.__package__=package_name;package.__spec__=importlib.util.spec_from_loader(package_name,loader=None,is_package=True);sys.modules[package_name]=package
    try:
        spec=importlib.util.spec_from_file_location(module_name,path);need(spec and spec.loader,'module spec unavailable');module=importlib.util.module_from_spec(spec);sys.modules[module_name]=module;spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name,None);sys.modules.pop(package_name,None);raise
    new=sorted(set(sys.modules)-before);forbidden=[n for n in new if any(x in n.lower() for x in ['trusted_read_outcome_hook','lineage_aware_exfil_guardrail','integration_factory','aicomp_sdk.core','aicomp_sdk.hooks','aicomp_sdk.guardrails','sandbox','gym'])]
    return module,{'strategy':'spec_from_file_location_with_synthetic_parent_package','package':package_name,'module':module_name,'source_path':str(path),'package_init_executed':False,'newly_loaded_modules':new,'forbidden_new_modules':forbidden}

def main(a):
    out=Path(a.output_dir).resolve();need(not out.exists(),f'Refusing overwrite: {out}');out.mkdir(parents=True);checks=[];fixtures=[];append_controls=[];json_controls=[];mutability=[];snapshot_controls=[];restore_controls=[];tamper=[]
    actual_fs_read=False;hook=False;guardrail=False;external_effect=False
    try:
        root=Path(a.project_root).resolve();v21_path=root/'aicomp_sdk_exfil_v2_1'/'successful_read_ledger_v2_1.py';v2_path=root/'aicomp_sdk_exfil_v2'/'successful_read_ledger_v2.py'
        inputs={'repair_manifest':Path(a.repair_manifest).resolve(),'independent_manifest':Path(a.independent_manifest).resolve(),'independent_result':Path(a.independent_result).resolve(),'independent_checks':Path(a.independent_checks).resolve(),'independent_boundaries':Path(a.independent_boundaries).resolve(),'independent_schema':Path(a.independent_schema).resolve(),'independent_runner':Path(a.independent_runner).resolve(),'failed_v2_evidence':Path(a.failed_v2_evidence).resolve(),'v21_ledger':v21_path,'v2_ledger':v2_path}
        for k,p in inputs.items():need(p.is_file(),f'Missing {k}: {p}')
        for i,(k,h) in enumerate(EXPECTED.items(),1):add(checks,f'CV21-{i:03d}','identity',sha_file(inputs[k])==h,sha_file(inputs[k]),h,'FIXTURE')
        add(checks,'CV21-011','identity',v21_path.stat().st_size==V21_SIZE and v2_path.stat().st_size==V2_SIZE,{'v21':v21_path.stat().st_size,'v2':v2_path.stat().st_size},{'v21':V21_SIZE,'v2':V2_SIZE},'FIXTURE')
        parent=rj(inputs['independent_result']);parent_checks=rc(inputs['independent_checks']);boundaries=rj(inputs['independent_boundaries']);schema=rj(inputs['independent_schema'])
        parent_ok=parent.get('status')=='INDEPENDENT_V2_1_STATIC_QUALIFICATION_COMPLETE_PASS' and parent.get('outcome')=='INDEPENDENT_V2_1_STATIC_QUALIFICATION_PASS' and parent.get('checks')=={'failed':0,'failed_ids':[],'passed':58,'total':58} and len(parent_checks)==58 and all(x.get('passed')=='True' for x in parent_checks) and boundaries.get('nested_mutability',{}).get('nested_record_graph_immutability')=='NOT_IMPLEMENTED' and schema.get('top_level_keys')==TOP_KEYS and schema.get('record_keys')==RECORD_KEYS
        add(checks,'CV21-012','parent',parent_ok,{'status':parent.get('status'),'outcome':parent.get('outcome'),'checks':parent.get('checks'),'boundaries':boundaries,'schema':schema},'58/58 with frozen boundaries','EVIDENCE')

        v21,import21=isolated_load(V21_PACKAGE,V21_MODULE,v21_path);Ledger=getattr(v21,'SuccessfulReadLedgerV21',None);Record=getattr(v21,'SuccessfulReadRecordV21',None)
        add(checks,'CV21-013','import',not import21['package_init_executed'] and not import21['forbidden_new_modules'],import21,{'package_init_executed':False,'forbidden_new_modules':[]},'ADAPTER_PARSE')
        add(checks,'CV21-014','import',isinstance(Ledger,type) and isinstance(Record,type) and getattr(v21,'OFFICIAL_MIN_SECRET_VALUE_LEN',None)==6,{'Ledger':str(Ledger),'Record':str(Record),'minimum':getattr(v21,'OFFICIAL_MIN_SECRET_VALUE_LEN',None)},'classes and minimum 6','ADAPTER_PARSE');need(isinstance(Ledger,type),'V2.1 ledger unavailable')

        specs=[('CV2-001','RHS length 5','K=12345'),('CV2-002','RHS length 6','K=123456'),('CV2-003','RHS length 7','K=1234567'),('CV2-004','bare length 5','12345'),('CV2-005','bare length 6','123456'),('CV2-006','bare length 7','1234567'),('CV2-007','blank line','   '),('CV2-008','hash comment','# secret'),('CV2-009','empty RHS','K='),('CV2-010','trimmed RHS','K=  123456  '),('CV2-011','duplicate assignments','K=123456\nK=123456'),('CV2-012','multiple equals','K=A=B=C')]
        fixture_ok=True
        for fid,case,raw in specs:
            l=Ledger();p=f'/synthetic/{fid}.txt';r=l.append_successful_read(tool_name='fs.read',tool_args={'path':p},canonical_path=p,explicit_ok=True,error_value=None,raw_output=raw);expected=independent_candidates(raw);observed=tuple(r.derived_secret_values);ok=set(observed)==set(expected) and observed==tuple(sorted(observed));fixtures.append({'fixture_id':fid,'case':case,'raw_input':raw,'raw_input_sha256':sha_text(raw),'expected_membership':json.dumps(sorted(expected)),'observed_ordered_tuple':json.dumps(list(observed)),'membership_match':set(observed)==set(expected),'ordering_status':'SORTED_DETERMINISTIC' if observed==tuple(sorted(observed)) else 'ORDER_MISMATCH'});fixture_ok &= ok
        add(checks,'CV21-015','candidate',fixture_ok,[{'id':x['fixture_id'],'match':x['membership_match'],'order':x['ordering_status']} for x in fixtures],'12 matches','SECRET_CAPTURE')

        caller={'path':'/synthetic/main.txt','nested':{'value':'original'},'items':['a','b']};original=json.loads(canonical(caller));raw='TOKEN=123456\n12345\n123456';l=Ledger();r=l.append_successful_read(tool_name='fs.read',tool_args=caller,canonical_path=caller['path'],explicit_ok=True,error_value={'code':'OK'},raw_output=raw)
        caller['path']='/changed';caller['nested']['value']='changed';caller['items'].append('c');detached=dict(r.tool_args)==original
        ad=args_digest(original);od=sha_text(raw);ident_expected=identity(1,'fs.read',original['path'],ad,od)
        positive={'caller_detached':detached,'args_digest_match':r.tool_args_sha256==ad,'raw_preserved':r.raw_output==raw,'raw_digest_match':r.raw_output_sha256==od,'candidates_match':r.derived_secret_values==independent_candidates(raw),'identity_match':r.record_identity==ident_expected,'sequence':r.record_sequence==1}
        add(checks,'CV21-016','append',all(positive.values()),positive,'all true','PROVENANCE')
        r2=l.append_successful_read(tool_name='fs.read',tool_args={'path':'/synthetic/2'},canonical_path='/synthetic/2',explicit_ok=True,error_value=None,raw_output='SECOND=123456');add(checks,'CV21-017','append',(r.record_sequence,r2.record_sequence)==(1,2),(r.record_sequence,r2.record_sequence),(1,2),'PROVENANCE')
        negatives=[('non_fs_read',lambda:Ledger().append_successful_read(tool_name='http.post',tool_args={},canonical_path='/x',explicit_ok=True,error_value=None,raw_output='x')),('explicit_false',lambda:Ledger().append_successful_read(tool_name='fs.read',tool_args={},canonical_path='/x',explicit_ok=False,error_value=None,raw_output='x')),('args_none',lambda:Ledger().append_successful_read(tool_name='fs.read',tool_args=None,canonical_path='/x',explicit_ok=True,error_value=None,raw_output='x')),('path_none',lambda:Ledger().append_successful_read(tool_name='fs.read',tool_args={},canonical_path=None,explicit_ok=True,error_value=None,raw_output='x')),('raw_none',lambda:Ledger().append_successful_read(tool_name='fs.read',tool_args={},canonical_path='/x',explicit_ok=True,error_value=None,raw_output=None))]
        neg_ok=True
        for name,fn in negatives:o=expect(fn);append_controls.append({'control_id':name,**o});neg_ok &= o['raised']
        add(checks,'CV21-018','append',neg_ok,append_controls,'all rejected','ARGUMENT_FIDELITY')

        outer=expect(lambda:r.tool_args.__setitem__('x',1),(Exception,));outer_ok=outer['raised']
        before_nested=r.tool_args['nested']['value'];r.tool_args['nested']['value']='record-side-change';nested_dict_ok=r.tool_args['nested']['value']=='record-side-change'
        before_len=len(r.tool_args['items']);r.tool_args['items'].append('record-side');nested_list_ok=len(r.tool_args['items'])==before_len+1
        mutability=[{'control':'outer_mapping_assignment','expected':'REJECT','observed':'REJECT' if outer_ok else 'ACCEPT','match':outer_ok},{'control':'nested_record_dictionary_mutation','expected':'PERMIT','observed':'PERMIT' if nested_dict_ok else 'REJECT','match':nested_dict_ok},{'control':'nested_record_list_mutation','expected':'PERMIT','observed':'PERMIT' if nested_list_ok else 'REJECT','match':nested_list_ok}]
        add(checks,'CV21-019','mutability',all(x['match'] for x in mutability),mutability,'outer reject; nested permit','ARGUMENT_FIDELITY')

        bad_values=[('custom_object',Unsupported()),('nan',float('nan')),('positive_infinity',float('inf')),('negative_infinity',float('-inf')),('non_string_key',{1:'value'})]
        json_ok=True
        for name,value in bad_values:
            o=expect(lambda value=value,name=name:Ledger().append_successful_read(tool_name='fs.read',tool_args=({'path':'/x','bad':value} if name!='non_string_key' else dict({'path':'/x'},**{} ) | value),canonical_path='/x',explicit_ok=True,error_value=None,raw_output='X=123456'))
            expected_reject=name!='non_string_key';match=o['raised'] if expected_reject else not o['raised'];json_controls.append({'control_id':'tool_args_'+name,'expected':'REJECT' if expected_reject else 'ACCEPT_JSON_COERCION_OBSERVED','observed':'REJECT' if o['raised'] else 'ACCEPT','exception_type':o['type'],'message':o['message'],'match':match});json_ok &= match
        add(checks,'CV21-020','json_boundary',json_ok,json_controls,'unsupported and nonfinite reject; non-string key behavior recorded','ARGUMENT_FIDELITY')

        safe_error=Ledger();safe_error.append_successful_read(tool_name='fs.read',tool_args={'path':'/safe'},canonical_path='/safe',explicit_ok=True,error_value={'code':'E','details':['x']},raw_output='SAFE=123456');safe_snapshot=safe_error.snapshot_state();safe_restored=Ledger();safe_restored.restore_state(copy.deepcopy(safe_snapshot));safe_error_ok=safe_restored.snapshot_state()==safe_snapshot
        bad_error=Ledger();bad_error.append_successful_read(tool_name='fs.read',tool_args={'path':'/bad'},canonical_path='/bad',explicit_ok=True,error_value=Unsupported(),raw_output='BAD=123456');bad_error_before=[record_dict(x) for x in bad_error.records()];bad_snap=expect(bad_error.snapshot_state,(ValueError,),'not canonically JSON serializable');bad_error_after=[record_dict(x) for x in bad_error.records()];bad_error_ok=bad_snap['match'] and str(bad_error_before)==str(bad_error_after)
        add(checks,'CV21-021','error_value',safe_error_ok and bad_error_ok,{'safe_roundtrip':safe_error_ok,'non_json_snapshot':bad_snap,'ledger_unchanged':str(bad_error_before)==str(bad_error_after)},'safe succeeds; non-JSON snapshot fails closed without mutation','PROVENANCE')

        base=Ledger();base.append_successful_read(tool_name='fs.read',tool_args={'path':'/snapshot','nested':{'v':1},'items':[1,2]},canonical_path='/snapshot',explicit_ok=True,error_value=None,raw_output='SNAP=123456');s1=base.snapshot_state();s2=base.snapshot_state();exact=list(s1.keys())==TOP_KEYS and list(s1['records'][0].keys())==RECORD_KEYS;nonempty=len(s1['records'])==1;types_ok=isinstance(s1['records'][0]['tool_args'],dict) and isinstance(s1['records'][0]['derived_secret_values'],list);raw_ok=s1['records'][0]['raw_output']=='SNAP=123456';deterministic=canonical(s1)==canonical(s2)
        record_before=record_dict(base.records()[0]);s1['records'][0]['tool_args']['nested']['v']=999;s1['records'][0]['tool_args']['items'].append(3);record_after=record_dict(base.records()[0]);snapshot_detached=record_before==record_after
        snapshot_ok=all([exact,nonempty,types_ok,raw_ok,deterministic,snapshot_detached]);snapshot_controls.append({'exact_keys':exact,'nonempty':nonempty,'json_safe_types':types_ok,'raw_exact':raw_ok,'deterministic':deterministic,'snapshot_detached_from_record':snapshot_detached});add(checks,'CV21-022','snapshot',snapshot_ok,snapshot_controls,'all true','PROVENANCE')

        clean=base.snapshot_state();restored=Ledger();restored.restore_state(copy.deepcopy(clean));roundtrip=restored.snapshot_state()==clean and [record_dict(x) for x in restored.records()]==[record_dict(x) for x in base.records()];reset_target=Ledger();reset_target.restore_state(copy.deepcopy(clean));reset_target.reset();reset_ok=reset_target.records()==() and reset_target.snapshot_state()=={'schema_tag':LEDGER_TAG,'next_sequence':1,'records':[]}
        add(checks,'CV21-023','restore',roundtrip and reset_ok,{'roundtrip':roundtrip,'reset':reset_ok},'both true','PROVENANCE')

        v2_to_v21=copy.deepcopy(clean);v2_to_v21['schema_tag']='EXFIL.SUCCESSFUL.READ.LEDGER.V2';o1=expect(lambda:Ledger().restore_state(v2_to_v21),(ValueError,),'invalid ledger snapshot schema')
        v2,import2=isolated_load(V2_PACKAGE,V2_MODULE,v2_path);LedgerV2=getattr(v2,'SuccessfulReadLedgerV2',None);need(isinstance(LedgerV2,type),'V2 ledger unavailable for compatibility rejection');o2=expect(lambda:LedgerV2().restore_state(copy.deepcopy(clean)),(ValueError,),'invalid ledger snapshot schema')
        cross_ok=o1['match'] and o2['match'] and not import2['package_init_executed'] and not import2['forbidden_new_modules'];restore_controls=[{'control':'V2_snapshot_to_V21','result':o1},{'control':'V21_snapshot_to_V2','result':o2},{'control':'V2_import_evidence','result':import2}];add(checks,'CV21-024','compatibility',cross_ok,restore_controls,'both schema rejections','PROVENANCE')

        base_snapshot=base.snapshot_state()
        cases=['ledger_schema_tag','record_schema_tag','record_sequence','tool_name','tool_args','tool_args_sha256','canonical_path','explicit_ok','raw_output','raw_output_sha256','derived_secret_values','record_identity','next_sequence','boolean_next_sequence','missing_top_level','extra_top_level','missing_record_field','extra_record_field','nested_tool_args','json_invalid_tool_args','json_invalid_error_value']
        def mutate(case,s):
            row=s['records'][0]
            if case=='ledger_schema_tag':s['schema_tag']='BAD'
            elif case=='record_schema_tag':row['schema_tag']='BAD'
            elif case=='record_sequence':row['record_sequence']=2
            elif case=='tool_name':row['tool_name']='http.post'
            elif case=='tool_args':row['tool_args']['new']='x'
            elif case=='tool_args_sha256':row['tool_args_sha256']='0'*64
            elif case=='canonical_path':row['canonical_path']='/tampered'
            elif case=='explicit_ok':row['explicit_ok']=False
            elif case=='raw_output':row['raw_output']='TAMPER=123456'
            elif case=='raw_output_sha256':row['raw_output_sha256']='0'*64
            elif case=='derived_secret_values':row['derived_secret_values']=['WRONG']
            elif case=='record_identity':row['record_identity']='0'*64
            elif case=='next_sequence':s['next_sequence']=99
            elif case=='boolean_next_sequence':s['next_sequence']=True
            elif case=='missing_top_level':s.pop('records')
            elif case=='extra_top_level':s['extra']='observed'
            elif case=='missing_record_field':row.pop('error_value')
            elif case=='extra_record_field':row['extra']='observed'
            elif case=='nested_tool_args':row['tool_args']['nested']['v']=99
            elif case=='json_invalid_tool_args':row['tool_args']['bad']=float('nan')
            elif case=='json_invalid_error_value':row['error_value']=Unsupported()
        expected_accept={'extra_top_level','missing_record_field','extra_record_field'}
        tamper_ok=True
        for case in cases:
            s=copy.deepcopy(base_snapshot);mutate(case,s);target=Ledger();target.append_successful_read(tool_name='fs.read',tool_args={'path':'/pre'},canonical_path='/pre',explicit_ok=True,error_value=None,raw_output='PRE=123456');pre=target.snapshot_state();pred=digest_state(pre)
            try:target.restore_state(s);raised=False;typ=None;msg=None
            except Exception as e:raised=True;typ=type(e).__name__;msg=str(e)
            post=target.snapshot_state();postd=digest_state(post);unchanged=pred==postd
            expected='ACCEPT' if case in expected_accept else 'REJECT';match=(not raised) if expected=='ACCEPT' else (raised and unchanged)
            tamper.append({'tamper_id':case,'expected':expected,'observed':'REJECT' if raised else 'ACCEPT','exception_type':typ,'exception_message':msg,'pre_state_sha256':pred,'post_state_sha256':postd,'state_unchanged':unchanged,'match':match});tamper_ok &= match
        add(checks,'CV21-025','tamper_atomicity',tamper_ok,[{'id':x['tamper_id'],'expected':x['expected'],'observed':x['observed'],'unchanged':x['state_unchanged'],'match':x['match']} for x in tamper],'declared behavior and atomic rejection','PROVENANCE')

        unchanged=sha_file(v21_path)==EXPECTED['v21_ledger'] and sha_file(v2_path)==EXPECTED['v2_ledger'];add(checks,'CV21-026','immutability',unchanged,{'v21':sha_file(v21_path),'v2':sha_file(v2_path)},{'v21':EXPECTED['v21_ledger'],'v2':EXPECTED['v2_ledger']},'FIXTURE')
        boundary_ok=not any([actual_fs_read,hook,guardrail,external_effect]);add(checks,'CV21-027','boundary',boundary_ok,{'actual_fs_read':actual_fs_read,'hook':hook,'guardrail':guardrail,'external_effect':external_effect},'all false','CLAIM_BOUNDARY')

        failed=[x['check_id'] for x in checks if not x['passed']]
        if any(x in failed for x in [f'CV21-{i:03d}' for i in range(1,13)]):outcome='NOT_ESTABLISHED'
        elif any(x in failed for x in ['CV21-013','CV21-014']):outcome='V2_1_IMPORT_RUNTIME_GAP'
        elif 'CV21-015' in failed:outcome='V2_1_CANDIDATE_RUNTIME_GAP'
        elif any(x in failed for x in ['CV21-016','CV21-017','CV21-018']):outcome='V2_1_APPEND_OR_DETACHMENT_RUNTIME_GAP'
        elif 'CV21-019' in failed:outcome='V2_1_MUTABILITY_BOUNDARY_GAP'
        elif any(x in failed for x in ['CV21-020','CV21-021']):outcome='V2_1_JSON_BOUNDARY_RUNTIME_GAP'
        elif 'CV21-022' in failed:outcome='V2_1_SNAPSHOT_RUNTIME_GAP'
        elif 'CV21-023' in failed:outcome='V2_1_RESTORE_RUNTIME_GAP'
        elif 'CV21-024' in failed:outcome='V2_1_COMPATIBILITY_RUNTIME_GAP'
        elif 'CV21-025' in failed:outcome='V2_1_TAMPER_OR_ATOMICITY_RUNTIME_GAP'
        elif failed:outcome='NOT_ESTABLISHED'
        else:outcome='CONTROLLED_V2_1_LEDGER_QUALIFICATION_PASS'
        passed=outcome=='CONTROLLED_V2_1_LEDGER_QUALIFICATION_PASS';status='CONTROLLED_V2_1_SUCCESSFUL_READ_LEDGER_QUALIFICATION_COMPLETE_PASS' if passed else 'CONTROLLED_V2_1_SUCCESSFUL_READ_LEDGER_QUALIFICATION_COMPLETE_WITH_GAPS'
        schema_observation={'extra_top_level':'ACCEPTED_AND_IGNORED','missing_record_error_value':'ACCEPTED_AS_NULL','extra_record_field':'ACCEPTED_AND_IGNORED','exact_snapshot_emission':'ESTABLISHED','strict_restore_extra_field_rejection':'NOT_IMPLEMENTED'}
        claim={'allowed':['isolated V2.1 ledger runtime import under declared loader','12 synthetic candidate controls','caller alias isolation runtime behavior','explicit nested-record mutability boundary','JSON fail-closed runtime controls','nonempty snapshot and clean restore runtime behavior','cross-version schema rejection runtime behavior','tamper rejection and failed-restore atomicity for specified cases','extra and missing schema field observations'],'prohibited':['claim actual fs.read','claim protected source retrieval','claim hook transport','claim source provenance','claim guardrail effectiveness','claim strict restore schema when extra fields are accepted','claim deep nested record immutability','claim robust end-to-end security findings']}
        result={'version':VERSION,'created_at_utc':now(),'status':status,'classification':'CONTROLLED_IN_MEMORY_V2_1_LEDGER_RUNTIME_QUALIFICATION','checks':{'total':len(checks),'passed':len(checks)-len(failed),'failed':len(failed),'failed_ids':failed},'outcome':outcome,'candidate_fixtures':{'total':len(fixtures),'passed':sum(bool(x['membership_match']) and x['ordering_status']=='SORTED_DETERMINISTIC' for x in fixtures)},'tamper_matrix':{'total':len(tamper),'matched':sum(bool(x['match']) for x in tamper),'rejections_atomic':sum(bool(x['state_unchanged']) for x in tamper if x['expected']=='REJECT')},'schema_observation':schema_observation,'runtime_boundaries':{'caller_alias_isolation':'ESTABLISHED' if positive['caller_detached'] else 'FAILED','outer_record_mapping_assignment':'REJECTED' if outer_ok else 'ACCEPTED','nested_record_dictionary_mutation':'PERMITTED','nested_record_list_mutation':'PERMITTED','nested_record_graph_immutability':'NOT_IMPLEMENTED','error_value_non_json_snapshot':'FAILS_CLOSED','strict_restore_extra_field_rejection':'NOT_IMPLEMENTED'},'readiness':{'controlled_actual_fs_read_hook_and_ledger_qualification_eligible':passed,'controlled_actual_fs_read_eligible':False,'http_sink_eligible':False},'execution_boundaries':{'V2_1_ledger_imported':True,'V2_ledger_imported_for_schema_rejection_only':True,'V2_1_package_init_executed':False,'V2_package_init_executed':False,'hook_imported':False,'hook_registered':False,'guardrail_imported':False,'guardrail_instantiated':False,'factory_imported':False,'SDK_imported':False,'actual_fs_read_executed':False,'tools_executed':False,'http_sink_executed':False,'predicates_executed':False,'breach_executed':False,'Sandbox_instantiated':False,'Gym_executed':False,'models_used':False,'threads_executed':False,'external_effects_observed':False,'V2_1_modified':False,'V2_modified':False},'scientific_verdict':{'V2_1_ledger_runtime_contract':'ESTABLISHED' if passed else outcome,'actual_source_retrieval':'NOT_EVALUATED','hook_transport':'NOT_EVALUATED','protected_value_lineage':'NOT_ESTABLISHED','guardrail_effectiveness':'NOT_EVALUATED','harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'},'claim_boundary':claim,'next_gate':'CONTROLLED_ACTUAL_FS_READ_HOOK_AND_LEDGER_QUALIFICATION' if passed else 'CONTROLLED_V2_1_LEDGER_GAP_REVIEW'}
        outputs={'result':out/'controlled_v2_1_ledger_result.json','checks':out/'controlled_v2_1_ledger_checks.csv','fixtures':out/'controlled_v2_1_candidate_fixtures.csv','append':out/'controlled_v2_1_append_controls.csv','json':out/'controlled_v2_1_json_controls.csv','mutability':out/'controlled_v2_1_mutability_controls.csv','snapshot':out/'controlled_v2_1_snapshot_controls.json','compat':out/'controlled_v2_1_compatibility_controls.json','tamper':out/'controlled_v2_1_tamper_matrix.csv','import':out/'controlled_v2_1_import_evidence.json','claim':out/'controlled_v2_1_claim_boundary.json','binding':out/'controlled_v2_1_binding.json'}
        wj(outputs['result'],result);wc(outputs['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']);wc(outputs['fixtures'],fixtures,['fixture_id','case','raw_input','raw_input_sha256','expected_membership','observed_ordered_tuple','membership_match','ordering_status']);wc(outputs['append'],append_controls,['control_id','raised','type','message','match']);wc(outputs['json'],json_controls,['control_id','expected','observed','exception_type','message','match']);wc(outputs['mutability'],mutability,['control','expected','observed','match']);wj(outputs['snapshot'],snapshot_controls);wj(outputs['compat'],restore_controls);wc(outputs['tamper'],tamper,['tamper_id','expected','observed','exception_type','exception_message','pre_state_sha256','post_state_sha256','state_unchanged','match']);wj(outputs['import'],{'V21':import21,'V2_schema_rejection_only':import2});wj(outputs['claim'],claim);wj(outputs['binding'],{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'inputs':{k:ident(v) for k,v in inputs.items()},'V2_1_modified':False,'V2_modified':False,'actual_fs_read_executed':False,'hook_registered':False,'guardrail_instantiated':False,'external_effects_observed':False})
        rows=[{**ident(p),'role':'CONTROLLED_V21_DERIVED'} for p in outputs.values()]+[{**ident(p),'role':'CONTROLLED_V21_BOUND_INPUT'} for p in inputs.values()];mp=out/'controlled_v2_1_ledger_manifest.csv';wc(mp,rows,['artifact','role','size_bytes','sha256','path']);ep=out/'controlled_v2_1_ledger_manifest_external_binding.json';wj(ep,{'version':VERSION,'created_at_utc':now(),'status':status,'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':sha_file(mp),'runner_sha256':sha_file(Path(__file__).resolve()),'repair_manifest_sha256':EXPECTED['repair_manifest'],'independent_static_manifest_sha256':EXPECTED['independent_manifest'],'failed_V2_evidence_sha256':EXPECTED['failed_v2_evidence'],'checks_total':len(checks),'checks_passed':len(checks)-len(failed),'checks_failed':len(failed),'failed_ids':failed,'outcome':outcome,'actual_fs_read_executed':False,'http_sink_eligible':False,'next_gate':result['next_gate']})
        print(json.dumps({'status':status,'checks':f'{len(checks)-len(failed)}/{len(checks)}','failed_ids':failed,'outcome':outcome,'candidate_fixtures':f"{result['candidate_fixtures']['passed']}/{result['candidate_fixtures']['total']}",'tamper_controls':f"{result['tamper_matrix']['matched']}/{result['tamper_matrix']['total']}",'nested_record_graph_immutability':'NOT_IMPLEMENTED','strict_restore_extra_field_rejection':'NOT_IMPLEMENTED','actual_fs_read_executed':False,'manifest_sha256':sha_file(mp),'next_gate':result['next_gate']},indent=2))
    except Exception as e:
        (out/'CONTROLLED_V2_1_LEDGER_FAILED.json').write_text(json.dumps({'version':VERSION,'created_at_utc':now(),'status':'CONTROLLED_V2_1_LEDGER_BLOCKED','error_type':type(e).__name__,'error':str(e),'checks_frozen':checks,'actual_fs_read_executed':actual_fs_read,'hook_registered':hook,'guardrail_instantiated':guardrail,'external_effects_observed':external_effect},indent=2),encoding='utf-8');raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for n in ['repair-manifest','independent-manifest','independent-result','independent-checks','independent-boundaries','independent-schema','independent-runner','failed-v2-evidence','project-root','output-dir']:p.add_argument('--'+n,required=True)
    return p.parse_args()
if __name__=='__main__':
    try:main(args())
    except Exception as e:print(f'FAILED: {e}',file=sys.stderr);raise SystemExit(1)
