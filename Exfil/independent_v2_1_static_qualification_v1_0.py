#!/usr/bin/env python3
"""Independent V2.1 static qualification v1.0.
Read-only AST/source qualification. Imports and executes none of V2.1, V2, V1,
SDK, snapshot, restore, candidates, tools, predicates, Sandbox, Gym, HTTP,
breach logic, models, threads, or external effects.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION='INDEPENDENT_V2_1_STATIC_QUALIFICATION_v1.0'
PARENT_VERSION='V2_1_SNAPSHOT_SERIALIZATION_REPAIR_AND_IDENTITY_FREEZE_v1.0'
PARENT_STATUS='V2_1_SNAPSHOT_SERIALIZATION_REPAIR_AND_IDENTITY_FREEZE_COMPLETE_PASS'
PARENT={
'repair_manifest':'1EBCD60880B47D1695383715C044303AB6A58F912CE2C0512FC4E46D0F634959',
'repair_result':'79FD78D9AD7F5F302B3753981F5E8A10109192F21E5AFDD126E6C2C72EF856C7',
'repair_checks':'7416F28774F50B8ED3038AE100B6B3DFC98394E06EC44F81E0CCD640110A13B0',
'repair_inventory':'C38C10308CEFAA969A7C9AE623FC802DA10B61234ABB4DD84718281E426DFF6F',
'repair_binding':'03E2600D69AA63998AFF5724841A5E4F24ABEB52C28D9788621F5F8279CE380D',
'repair_compat':'B9FDADF951DB0B4C3A5FE87529146FABFF067E8E6E5090C77575BA83120F9C2C',
'repair_claim':'5745CD2E13263548AA0F93BE98533384D78160AC018795697230FA4A64B0CCC3',
'failed_evidence':'AF6C0BEB687AE221E33B37224EA5316ADCEA6AA10BAB004E4F1B4A4E1CF0C054',
'repair_runner':'02D77E6840B453E1D42C5CFCBD96DCE62AC072DC638C48CCD9CB9313B7EE88F9'}
V21={'__init__.py':(637,'8EA5CE3B3548A8545677D635F7360652B992FCB36616D55C3EDBF9DC254CFD48'),'successful_read_ledger_v2_1.py':(8335,'18146742E6866C491A032AA96EFC248FFED05706895D32FDE724145D0878009C'),'trusted_read_outcome_hook_v2_1.py':(1532,'F2DE8D42EE5DBCD3BA4CACD8E98DCCB2EBA63F82EC8683D129C503CCED1CE770'),'lineage_aware_exfil_guardrail_v2_1.py':(1394,'2AC1CA55FB0C18460F50B35677F5ECD9EB3477CFB21F9C19F44A48C7AEFD5C26'),'integration_factory_v2_1.py':(1339,'21355E213E0C8AEFCA8851336C64527F49168ACEC7AEFE6EC161441E676AEE1A')}
V2={'__init__.py':'A2FF10622D4323205F04BDAE96B121DF0CF710ABB90F33205A83E94E4812ED06','successful_read_ledger_v2.py':'609B22AA7ABD3555B24484E2AF313A5460877BA3C446FBE2978C6136D662857E','trusted_read_outcome_hook_v2.py':'424D659F677CC6EEFC2E961B350B4A01D41E356849280F3728FB2F5FA5DB9817','lineage_aware_exfil_guardrail_v2.py':'27B938444693B53BF3641CB5E958E5C8946B114D4195E8A6D3C1AB774D42931B','integration_factory_v2.py':'436C9111DD48C069DDF6FB655C5E40D9A471E4B59890592222CBF8C871E39224'}
V1={'__init__.py':'DB60398BBEEAAE411C62FB915F2EAE5C7CDEBA9A2100D278BF2399190ED3094A','successful_read_ledger_v1.py':'3560FD4B7533C5B9B2622B84B1AD9BEC4A5562C1BBFF4FE06279EC7206DB73A6','trusted_read_outcome_hook_v1.py':'2B979C6B652358EAC1E0275A16607AD3A4750CC05C3AC64B6861EFC990B051CD','lineage_aware_exfil_guardrail_v1.py':'0D20934AD62E7191498F795F1D9BFDB008A749CD134A0842582DED1322F5A1DE','integration_factory_v1.py':'8220A3AF5601BA660AAD7EA8A1F6893646A8DB764C88BA8F859A35C12733C431'}
SDK={'aicomp_sdk/core/env/sandbox.py':'B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0','aicomp_sdk/core/predicates.py':'9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37','aicomp_sdk/guardrails/base.py':'EC95F45A9BF4202514725690617C91E88F3F1AE889AC7828D423DAAFEA527708','aicomp_sdk/hooks/types.py':'0D3C7B5921749C22CADC5478532C7FE84B86AA90447FEEA8060ACFA9F44D3C7E','aicomp_sdk/hooks/registry.py':'5635B45136517CB5B7FBC6BAB6C9440FE7D6D699E484B6D63651AE296D4BB00B'}
TOP_KEYS=['schema_tag','next_sequence','records']
RECORD_KEYS=['schema_tag','record_sequence','tool_name','tool_args','tool_args_sha256','canonical_path','explicit_ok','error_value','raw_output','raw_output_sha256','derived_secret_values','record_identity']

def now():return datetime.now(timezone.utc).isoformat()
def need(v,m):
    if not v:raise ValueError(m)
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b)
    return h.hexdigest().upper()
def ident(p):
    p=Path(p).resolve();return {'artifact':p.name,'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}
def rj(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def rc(p):
    with Path(p).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def wj(p,o):
    with Path(p).open('x',encoding='utf-8',newline='\n') as f:json.dump(o,f,indent=2,sort_keys=True,ensure_ascii=False);f.write('\n')
def wc(p,rows,fields):
    with Path(p).open('x',encoding='utf-8',newline='') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(rows)
def add(rows,cid,cat,ok,obs,exp,layer):rows.append({'check_id':cid,'category':cat,'passed':bool(ok),'observed':str(obs),'expected':str(exp),'failure_layer':layer})
def unparse(n):
    try:return ast.unparse(n)
    except:return 'UNPARSE_FAILED'
def defs(t):return {n.name:n for n in t.body if isinstance(n,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef))}
def methods(c):return {n.name:n for n in c.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def dict_keys(node):
    if not isinstance(node,ast.Dict):return []
    out=[]
    for k in node.keys:
        if isinstance(k,ast.Constant) and isinstance(k.value,str):out.append(k.value)
        else:out.append('NON_LITERAL')
    return out
def assignments(node,attr):return [n for n in ast.walk(node) if isinstance(n,(ast.Assign,ast.AnnAssign)) and any(isinstance(t,ast.Attribute) and unparse(t)==attr for t in (n.targets if isinstance(n,ast.Assign) else [n.target]))]
def imported_names(t):
    out=[]
    for n in t.body:
        if isinstance(n,ast.ImportFrom):
            for x in n.names:out.append({'module':n.module or '','level':n.level,'name':x.name})
        elif isinstance(n,ast.Import):
            for x in n.names:out.append({'module':x.name,'level':0,'name':''})
    return out

def main(a):
    out=Path(a.output_dir).resolve();need(not out.exists(),f'Refusing overwrite: {out}');out.mkdir(parents=True);checks=[]
    try:
        root=Path(a.project_root).resolve();v21=root/'aicomp_sdk_exfil_v2_1';v2=root/'aicomp_sdk_exfil_v2';v1=root/'aicomp_sdk_exfil'
        inputs={'repair_manifest':Path(a.repair_manifest).resolve(),'repair_external':Path(a.repair_external).resolve(),'repair_result':Path(a.repair_result).resolve(),'repair_checks':Path(a.repair_checks).resolve(),'repair_inventory':Path(a.repair_inventory).resolve(),'repair_binding':Path(a.repair_binding).resolve(),'repair_compat':Path(a.repair_compat).resolve(),'repair_claim':Path(a.repair_claim).resolve(),'failed_evidence':Path(a.failed_evidence).resolve(),'repair_runner':Path(a.repair_runner).resolve()}
        for k,p in inputs.items():need(p.is_file(),f'Missing {k}: {p}')
        for i,(k,h) in enumerate(PARENT.items(),1):add(checks,f'IV21-{i:03d}','parent_identity',sha(inputs[k])==h,sha(inputs[k]),h,'FIXTURE')
        result=rj(inputs['repair_result']);external=rj(inputs['repair_external']);pr=rc(inputs['repair_checks'])
        parent_ok=result.get('version')==PARENT_VERSION and result.get('status')==PARENT_STATUS and result.get('checks')=={'failed':0,'failed_ids':[],'passed':41,'total':41} and external.get('manifest_sha256')==PARENT['repair_manifest'] and external.get('runner_sha256')==PARENT['repair_runner'] and external.get('failed_evidence_sha256')==PARENT['failed_evidence'] and len(pr)==41 and all(x.get('passed')=='True' for x in pr)
        add(checks,'IV21-010','parent_semantics',parent_ok,{'status':result.get('status'),'checks':result.get('checks'),'external':external},'41/41 complete pass with exact bindings','EVIDENCE')
        actual=sorted(p.name for p in v21.glob('*.py'));add(checks,'IV21-011','inventory',actual==sorted(V21),actual,sorted(V21),'FIXTURE')
        trees={};texts={};inventory=[]
        for i,(n,(size,h)) in enumerate(V21.items(),12):
            p=v21/n;need(p.is_file(),f'Missing V2.1 {n}');text=p.read_text(encoding='utf-8');texts[n]=text;trees[n]=ast.parse(text,filename=str(p));ok=p.stat().st_size==size and sha(p)==h;inventory.append({**ident(p),'relative_path':str(p.relative_to(root)),'expected_size':size,'expected_sha256':h,'match':ok});add(checks,f'IV21-{i:03d}','V21_identity',ok,ident(p),{'size':size,'sha256':h},'FIXTURE')
        for i,(n,h) in enumerate(V2.items(),17):add(checks,f'IV21-{i:03d}','V2_identity',sha(v2/n)==h,sha(v2/n),h,'FIXTURE')
        for i,(n,h) in enumerate(V1.items(),22):add(checks,f'IV21-{i:03d}','V1_identity',sha(v1/n)==h,sha(v1/n),h,'FIXTURE')
        for i,(n,h) in enumerate(SDK.items(),27):add(checks,f'IV21-{i:03d}','SDK_identity',sha(root/n)==h,sha(root/n),h,'FIXTURE')

        imports=[]
        for f,t in trees.items():
            for row in imported_names(t):imports.append({'file':f,**row,'private_sdk':row['level']==0 and row['module'].startswith('aicomp_sdk') and row['name'].startswith('_'),'V1_or_V2_import':row['module'].startswith('aicomp_sdk_exfil') and 'v2_1' not in row['module']})
        add(checks,'IV21-032','imports',not any(x['private_sdk'] or x['V1_or_V2_import'] for x in imports),[x for x in imports if x['private_sdk'] or x['V1_or_V2_import']],'no private SDK or V1/V2 imports','ADAPTER_PARSE')
        relmods={f.rsplit('.',1)[0] for f in trees};relative_ok=True
        for x in imports:
            if x['level']:
                target=(x['module'].split('.')[-1] if x['module'] else '')
                relative_ok &= any(name.startswith(target) for name in relmods)
        add(checks,'IV21-033','imports',relative_ok,imports,'all relative imports resolve statically','ADAPTER_PARSE')

        t=trees['successful_read_ledger_v2_1.py'];d=defs(t);ledger=d['SuccessfulReadLedgerV21'];lm=methods(ledger);snap=lm['snapshot_state'];restore=lm['restore_state'];append=lm['append_successful_read'];snap_s=unparse(snap);rest_s=unparse(restore);app_s=unparse(append);all_s=texts['successful_read_ledger_v2_1.py']
        add(checks,'IV21-034','snapshot','asdict' not in all_s and 'deepcopy' not in all_s and not any(x['name'] in {'asdict','deepcopy'} for x in imports),all_s.count('asdict')+all_s.count('deepcopy'),0,'PROVENANCE')
        add(checks,'IV21-035','snapshot',len([n for n in ledger.body if isinstance(n,ast.FunctionDef) and n.name=='snapshot_state'])==1,'snapshot_state count',1,'PROVENANCE')
        ret=next((n for n in snap.body if isinstance(n,ast.Return)),None);need(ret and isinstance(ret.value,ast.Dict),'snapshot return dict missing');top=dict_keys(ret.value)
        add(checks,'IV21-036','snapshot_schema',top==TOP_KEYS,top,TOP_KEYS,'PROVENANCE')
        records_value=ret.value.values[top.index('records')] if 'records' in top else None;record_dict=None
        if isinstance(records_value,ast.ListComp) and isinstance(records_value.elt,ast.Dict):record_dict=records_value.elt
        rkeys=dict_keys(record_dict) if record_dict else []
        add(checks,'IV21-037','snapshot_schema',rkeys==RECORD_KEYS,rkeys,RECORD_KEYS,'PROVENANCE')
        add(checks,'IV21-038','snapshot','_detach_json_value_v21(dict(record.tool_args))' in snap_s,snap_s,'detached tool_args','ARGUMENT_FIDELITY')
        add(checks,'IV21-039','snapshot','list(record.derived_secret_values)' in snap_s and "'raw_output': record.raw_output" in snap_s,snap_s,'candidate list and raw output direct','PROVENANCE')
        add(checks,'IV21-040','snapshot','for record in self._records' in snap_s and "'next_sequence': self._next_sequence" in snap_s,snap_s,'record order and next sequence preserved','PROVENANCE')
        add(checks,'IV21-041','snapshot','self._records' not in unparse(record_dict) if record_dict else False,unparse(record_dict) if record_dict else None,'no private list reference in record payload','PROVENANCE')

        detach=d['_detach_json_value_v21'];ds=unparse(detach)
        det_checks=['json.dumps(value','json.loads(encoded)','sort_keys=True',"separators=(',', ':')",'ensure_ascii=False','allow_nan=False','except (TypeError, ValueError)','raise ValueError']
        add(checks,'IV21-042','detachment',all(x in ds for x in det_checks),ds,det_checks,'ARGUMENT_FIDELITY')
        add(checks,'IV21-043','detachment',app_s.find('args_copy = _detach_json_value_v21')<app_s.find('args_digest =')<app_s.find('SuccessfulReadRecordV21('),app_s,'detach before digest and record','ARGUMENT_FIDELITY')
        add(checks,'IV21-044','detachment',rest_s.find('args_copy = _detach_json_value_v21')<rest_s.find('args_digest =')<rest_s.find('SuccessfulReadRecordV21('),rest_s,'detach before digest and record','ARGUMENT_FIDELITY')
        add(checks,'IV21-045','detachment','_detach_json_value_v21(dict(record.tool_args))' in snap_s,snap_s,'snapshot separately detaches tool args','ARGUMENT_FIDELITY')
        nested={'caller_alias_isolation':'STRUCTURALLY_INDICATED_BY_JSON_ROUND_TRIP','outer_record_mapping':'MAPPING_PROXY','nested_record_graph_immutability':'NOT_IMPLEMENTED','reason':'nested dict/list values remain mutable through record.tool_args references'}
        add(checks,'IV21-046','mutability_boundary','MappingProxyType(args_copy)' in app_s and 'json.loads(encoded)' in ds,nested,'explicit caller isolation and nested mutability classification','ARGUMENT_FIDELITY')
        error_boundary={'append_error_value':'NOT_DETACHED_BEFORE_RECORD_STORAGE','snapshot_error_value':'JSON_DETACHED','restore_error_value':'JSON_DETACHED','contract':'ERROR_VALUE_JSON_SAFE_FOR_SNAPSHOT_AND_RESTORE; APPEND_MAY_HOLD_NON_JSON_VALUE_UNTIL_SNAPSHOT_FAILS_CLOSED'}
        add(checks,'IV21-047','error_value','_detach_json_value_v21(record.error_value)' in snap_s and "_detach_json_value_v21(row.get('error_value'))" in rest_s,error_boundary,'explicit JSON-safe snapshot/restore restriction','PROVENANCE')

        add(checks,'IV21-048','restore_schema',"snapshot.get('schema_tag') != SCHEMA_TAG_V2_1" in rest_s and "row.get('schema_tag') != RECORD_TAG_V2_1" in rest_s,rest_s,'exact V2.1 tags','PROVENANCE')
        add(checks,'IV21-049','restore_sequence','expected_sequence = 1' in rest_s and 'isinstance(next_sequence, bool)' in rest_s,rest_s,'sequence one and bool rejected','PROVENANCE')
        add(checks,'IV21-050','restore_record',"row.get('tool_name') != 'fs.read'" in rest_s and "row.get('explicit_ok') is not True" in rest_s,rest_s,'fixed fs.read and explicit true','PROVENANCE')
        recompute=['args_digest = _tool_args_digest_v21(args_copy)','output_digest = _sha256_text_v21(raw)','derived = _secret_values_v21(raw)','expected_identity = _record_identity_v21']
        add(checks,'IV21-051','restore_integrity',all(x in rest_s for x in recompute),rest_s,recompute,'PROVENANCE')
        compare=['tool_args_sha256','raw_output_sha256','derived_secret_values','record_identity']
        add(checks,'IV21-052','restore_integrity',all(x in rest_s for x in compare) and 'derived, expected_identity' in rest_s,rest_s,'all derived values compared and recomputed stored','PROVENANCE')
        loop=next((n for n in restore.body if isinstance(n,ast.For)),None);need(loop,'restore loop missing');loop_s=unparse(loop)
        add(checks,'IV21-053','atomicity','self._records' not in loop_s and 'self._next_sequence' not in loop_s,loop_s,'no target mutation inside validation loop','PROVENANCE')
        assigns_records=assignments(restore,'self._records');assigns_next=assignments(restore,'self._next_sequence');commit_line=min([n.lineno for n in assigns_records+assigns_next],default=-1);next_check=max([n.lineno for n in ast.walk(restore) if isinstance(n,ast.If) and 'next_sequence != expected_sequence' in unparse(n.test)],default=-1)
        add(checks,'IV21-054','atomicity',len(assigns_records)==1 and len(assigns_next)==1 and commit_line>next_check>0,{'records_assign':len(assigns_records),'next_assign':len(assigns_next),'next_check':next_check,'commit':commit_line},'single final commits after next check','PROVENANCE')

        v2text=(v2/'successful_read_ledger_v2.py').read_text(encoding='utf-8');tags={'V2_ledger':'EXFIL.SUCCESSFUL.READ.LEDGER.V2','V21_ledger':'EXFIL.SUCCESSFUL.READ.LEDGER.V2.1','V2_record':'EXFIL.SUCCESSFUL.READ.RECORD.V2','V21_record':'EXFIL.SUCCESSFUL.READ.RECORD.V2.1'}
        add(checks,'IV21-055','compatibility',all(x in (v2text+all_s) for x in tags.values()) and tags['V2_ledger']!=tags['V21_ledger'] and tags['V2_record']!=tags['V21_record'],tags,'distinct tags','PROVENANCE')
        migration_terms=['migrate','upgrade_snapshot','from_v2','accept_v2']
        add(checks,'IV21-056','compatibility',not any(x in all_s.lower() for x in migration_terms),[x for x in migration_terms if x in all_s.lower()],[],'PROVENANCE')
        compat=rj(inputs['repair_compat']);compat_ok=compat=={'V21_snapshot_accepted_by_V2':'REJECT_BY_LEDGER_SCHEMA_TAG','V2_snapshot_accepted_by_V21':'REJECT_BY_LEDGER_SCHEMA_TAG','classification':'MUTUALLY_INCOMPATIBLE_BY_DESIGN','same_field_names_imply_compatibility':False}
        add(checks,'IV21-057','compatibility',compat_ok,compat,'mutually incompatible by design','PROVENANCE')
        add(checks,'IV21-058','immutability',all(sha(v21/n)==h for n,(s,h) in V21.items()) and all(sha(v2/n)==h for n,h in V2.items()) and all(sha(v1/n)==h for n,h in V1.items()) and all(sha(root/n)==h for n,h in SDK.items()),'unchanged','V2.1 V2 V1 SDK unchanged','FIXTURE')

        failed=[x['check_id'] for x in checks if not x['passed']]
        if any(x in failed for x in [f'IV21-{i:03d}' for i in range(1,32)]):outcome='NOT_ESTABLISHED'
        elif any(x in failed for x in ['IV21-032','IV21-033']):outcome='V2_1_IMPORT_CONTRACT_GAP'
        elif any(x in failed for x in [f'IV21-{i:03d}' for i in range(34,42)]):outcome='V2_1_SNAPSHOT_SCHEMA_GAP'
        elif any(x in failed for x in ['IV21-042','IV21-043','IV21-044','IV21-045']):outcome='V2_1_DETACHMENT_CONTRACT_GAP'
        elif 'IV21-046' in failed:outcome='V2_1_NESTED_MUTABILITY_BOUNDARY_GAP'
        elif any(x in failed for x in [f'IV21-{i:03d}' for i in range(47,53)]):outcome='V2_1_RESTORE_INTEGRITY_GAP'
        elif any(x in failed for x in ['IV21-053','IV21-054']):outcome='V2_1_ATOMICITY_DESIGN_GAP'
        elif any(x in failed for x in ['IV21-055','IV21-056','IV21-057']):outcome='V2_1_COMPATIBILITY_GAP'
        elif not failed:outcome='INDEPENDENT_V2_1_STATIC_QUALIFICATION_PASS'
        else:outcome='NOT_ESTABLISHED'
        passed=outcome=='INDEPENDENT_V2_1_STATIC_QUALIFICATION_PASS';status='INDEPENDENT_V2_1_STATIC_QUALIFICATION_COMPLETE_PASS' if passed else 'INDEPENDENT_V2_1_STATIC_QUALIFICATION_COMPLETE_WITH_GAPS'
        boundaries={'nested_mutability':nested,'error_value':error_boundary,'snapshot_compatibility':compat}
        claim={'allowed':['independent V2.1 identity and inventory qualification','static import contract qualification','exact snapshot schema frozen','recursive detachment source contract qualified','caller alias isolation structurally indicated','nested record graph mutability explicitly classified','error_value JSON boundary explicitly classified','restore recomputation and atomicity design qualified statically','V2/V2.1 incompatibility qualified statically'],'prohibited':['claim V2.1 importability by execution','claim runtime snapshot success','claim runtime nested-copy isolation','claim runtime tamper rejection','claim actual fs.read','claim protected-value lineage','claim guardrail effectiveness','claim robust security findings']}
        result={'version':VERSION,'created_at_utc':now(),'status':status,'classification':'READ_ONLY_INDEPENDENT_V2_1_STATIC_SOURCE_QUALIFICATION','checks':{'total':len(checks),'passed':len(checks)-len(failed),'failed':len(failed),'failed_ids':failed},'outcome':outcome,'boundaries':boundaries,'readiness':{'controlled_V2_1_successful_read_ledger_qualification_eligible':passed,'controlled_actual_fs_read_eligible':False,'http_sink_eligible':False},'execution_boundaries':{'V2_1_modified':False,'V2_modified':False,'V1_modified':False,'frozen_aicomp_sdk_modified':False,'V2_1_imported':False,'V2_1_instantiated':False,'snapshot_executed':False,'restore_executed':False,'candidate_extraction_executed':False,'actual_fs_read_executed':False,'hook_registered':False,'guardrail_executed':False,'http_sink_executed':False,'predicates_executed':False,'breach_executed':False,'Sandbox_instantiated':False,'Gym_executed':False,'models_used':False,'threads_executed':False,'external_effects_observed':False},'scientific_verdict':{'V2_1_identity':'ESTABLISHED' if passed else 'NOT_ESTABLISHED','V2_1_static_contract':'ESTABLISHED' if passed else outcome,'V2_1_runtime_behavior':'NOT_EVALUATED','nested_record_graph_immutability':'NOT_IMPLEMENTED','actual_source_retrieval':'NOT_EVALUATED','protected_value_lineage':'NOT_ESTABLISHED','guardrail_effectiveness':'NOT_EVALUATED','harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'},'claim_boundary':claim,'next_gate':'CONTROLLED_V2_1_SUCCESSFUL_READ_LEDGER_QUALIFICATION' if passed else 'V2_1_STATIC_GAP_REVIEW'}
        outputs={'result':out/'independent_v2_1_static_result.json','checks':out/'independent_v2_1_static_checks.csv','inventory':out/'independent_v2_1_identities.csv','imports':out/'independent_v2_1_imports.csv','snapshot':out/'independent_v2_1_snapshot_schema.json','boundary':out/'independent_v2_1_boundaries.json','claim':out/'independent_v2_1_claim_boundary.json','binding':out/'independent_v2_1_binding.json'}
        wj(outputs['result'],result);wc(outputs['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']);wc(outputs['inventory'],inventory,['artifact','relative_path','size_bytes','expected_size','sha256','expected_sha256','match','path']);wc(outputs['imports'],imports,['file','module','level','name','private_sdk','V1_or_V2_import']);wj(outputs['snapshot'],{'top_level_keys':top,'record_keys':rkeys,'schema_tag':'EXFIL.SUCCESSFUL.READ.LEDGER.V2.1','record_tag':'EXFIL.SUCCESSFUL.READ.RECORD.V2.1'});wj(outputs['boundary'],boundaries);wj(outputs['claim'],claim);wj(outputs['binding'],{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'inputs':{k:ident(v) for k,v in inputs.items()},'V2_1':{n:ident(v21/n) for n in V21},'V2':{n:ident(v2/n) for n in V2},'V1':{n:ident(v1/n) for n in V1},'SDK':{n:ident(root/n) for n in SDK},'V2_1_imported':False,'V2_1_modified':False})
        rows=[{**ident(p),'role':'INDEPENDENT_V21_DERIVED'} for p in outputs.values()]+[{**ident(p),'role':'INDEPENDENT_V21_BOUND_INPUT'} for p in inputs.values()]+[{**ident(v21/n),'role':'BOUND_V21'} for n in V21]+[{**ident(v2/n),'role':'BOUND_V2'} for n in V2]+[{**ident(v1/n),'role':'BOUND_V1'} for n in V1]+[{**ident(root/n),'role':'BOUND_SDK'} for n in SDK]
        mp=out/'independent_v2_1_static_manifest.csv';wc(mp,rows,['artifact','role','size_bytes','sha256','path']);ep=out/'independent_v2_1_static_manifest_external_binding.json';wj(ep,{'version':VERSION,'created_at_utc':now(),'status':status,'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':sha(mp),'runner_sha256':sha(Path(__file__).resolve()),'parent_repair_manifest_sha256':PARENT['repair_manifest'],'failed_evidence_sha256':PARENT['failed_evidence'],'checks_total':len(checks),'checks_passed':len(checks)-len(failed),'checks_failed':len(failed),'failed_ids':failed,'outcome':outcome,'V2_1_imported':False,'controlled_actual_fs_read_eligible':False,'next_gate':result['next_gate']})
        print(json.dumps({'status':status,'checks':f'{len(checks)-len(failed)}/{len(checks)}','failed_ids':failed,'outcome':outcome,'nested_record_graph_immutability':'NOT_IMPLEMENTED','error_value_boundary':error_boundary['contract'],'V2_1_imported':False,'manifest_sha256':sha(mp),'next_gate':result['next_gate']},indent=2))
    except Exception as exc:
        (out/'INDEPENDENT_V2_1_STATIC_FAILED.json').write_text(json.dumps({'version':VERSION,'created_at_utc':now(),'status':'INDEPENDENT_V2_1_STATIC_BLOCKED','error_type':type(exc).__name__,'error':str(exc),'checks_frozen':checks,'V2_1_modified':False,'V2_1_imported':False,'actual_fs_read_executed':False},indent=2),encoding='utf-8');raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for n in ['repair-manifest','repair-external','repair-result','repair-checks','repair-inventory','repair-binding','repair-compat','repair-claim','failed-evidence','repair-runner','project-root','output-dir']:p.add_argument('--'+n,required=True)
    return p.parse_args()
if __name__=='__main__':
    try:main(args())
    except Exception as exc:print(f'FAILED: {exc}',file=sys.stderr);raise SystemExit(1)
