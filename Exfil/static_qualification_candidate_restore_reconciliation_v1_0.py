#!/usr/bin/env python3
"""Static qualification methodology correction and contract reconciliation v1.0.

Read-only authoritative-source comparison addressing exactly two issues:
A) relationship between V1 _secret_values and the official extraction contract;
B) whether V1 restore_state recomputes and validates record_identity using all
   identity-bound fields.

No source is modified, imported, instantiated, or executed. Generated fixtures
are inert JSON specifications only. No SDK, implementation, predicate, tool,
Sandbox, Gym, fs.read, HTTP, breach, model, thread, or effect is executed.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="STATIC_QUALIFICATION_METHODOLOGY_CORRECTION_AND_CANDIDATE_CONTRACT_RECONCILIATION_v1.0"
PARENT_VERSION="INDEPENDENT_STATEFUL_GUARDRAIL_STATIC_QUALIFICATION_v1.0"
PARENT_STATUS="INDEPENDENT_STATEFUL_GUARDRAIL_STATIC_QUALIFICATION_COMPLETE_WITH_GAPS"
PARENT_MANIFEST_SHA="99E41383F2017E0A9D13887DCE188D6DEA90608A5BB22A62450B2F3FD07045E9"
PARENT_RUNNER_SHA="81F7BF93BB44BA97592B82F696FF1AA347A48833F1FD21C04C942EE4BDC8CFF5"
PARENT_RESULT_SHA="FE3C7A6B8DC2C31C8D1DA8959A33ADFE48B4442D7D556B41B0001633D3703421"
PARENT_CHECKS_SHA="DAC6C9069CD21CA1BCEC1578783D27A47EC37E77C4C59E5E05DF7987E7071923"
PARENT_CANDIDATES_SHA="F0EE7954CE8BF03DB2B5E052FE58F3AE7828C5FC58231C64D4AEAEB99A8F74AC"
PARENT_BINDING_SHA="902C9FA3758DA110A57B91827772B310B33B689ECA9FB78DE0681959317E0A6B"
IMPL_LEDGER_SHA="3560FD4B7533C5B9B2622B84B1AD9BEC4A5562C1BBFF4FE06279EC7206DB73A6"
PREDICATES_SHA="9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"

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
def up(n):
    try:return ast.unparse(n)
    except:return 'UNPARSE_FAILED'
def funcs(tree):return {n.name:n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def source_segment(text,node):return ast.get_source_segment(text,node) or up(node)
def normalize(n):
    c=ast.parse(up(n));
    for x in ast.walk(c):
        for attr in ('lineno','col_offset','end_lineno','end_col_offset','type_comment'):
            if hasattr(x,attr):setattr(x,attr,None)
    return ast.dump(c,include_attributes=False)
def calls(node):return [x for x in ast.walk(node) if isinstance(x,ast.Call)]
def string_literals(node):return sorted({x.value for x in ast.walk(node) if isinstance(x,ast.Constant) and isinstance(x.value,str)})
def has(node,token):return token in up(node)
def feature_signature(fn):
    s=up(fn); lits=string_literals(fn); names={x.id for x in ast.walk(fn) if isinstance(x,ast.Name)}
    return {
      'function':fn.name,'line_start':fn.lineno,'line_end':getattr(fn,'end_lineno',fn.lineno),
      'input_annotation':up(fn.args.args[0].annotation) if fn.args.args and fn.args.args[0].annotation else 'NOT_ANNOTATED',
      'return_annotation':up(fn.returns) if fn.returns else 'NOT_ANNOTATED',
      'splitlines':'.splitlines()' in s,'strip':'.strip()' in s,'lstrip':'.lstrip()' in s,
      'drops_blank':('not line' in s or "== ''" in s),'drops_hash_comments':("startswith('#')" in s or 'startswith("#")' in s),
      'partition_equals':"partition('=')" in s or 'partition("=")' in s,'split_equals':"split('=')" in s or 'split("=")' in s,
      'adds_full_line':'add(line)' in s or 'append(line)' in s,'adds_rhs':('partition' in s or 'split' in s) and ('add(value)' in s or 'append(value)' in s),
      'json_handling':('json' in names or 'json.loads' in s),'mapping_handling':('Mapping' in s or 'dict' in s),
      'sequence_handling':('list' in s or 'tuple' in s or 'set' in s or 'Sequence' in s),
      'bytes_handling':('bytes' in s or 'decode(' in s),'base64_handling':('base64' in s or 'b64' in s),
      'url_handling':('unquote' in s or 'url' in s.lower()),'recursive_call':any(isinstance(c.func,ast.Name) and c.func.id==fn.name for c in calls(fn)),
      'deduplicates':('set()' in s or 'set[' in s),'sorts':('sorted(' in s),'string_literals':lits
    }
def compare_features(custom,official):
    rows=[]
    keys=['input_annotation','return_annotation','splitlines','strip','lstrip','drops_blank','drops_hash_comments','partition_equals','split_equals','adds_full_line','adds_rhs','json_handling','mapping_handling','sequence_handling','bytes_handling','base64_handling','url_handling','recursive_call','deduplicates','sorts']
    for k in keys:
        cv,ov=custom.get(k),official.get(k);rows.append({'dimension':k,'custom_value':json.dumps(cv,sort_keys=True),'official_value':json.dumps(ov,sort_keys=True),'equal':cv==ov,'material':k not in {'input_annotation','return_annotation'}})
    return rows
def relation_from_features(rows,ast_equal):
    if ast_equal:return 'EQUAL_SOURCE_NORMALIZED'
    diffs=[r['dimension'] for r in rows if not r['equal'] and r['material']]
    if not diffs:return 'QUALIFIER_METHOD_ONLY_GAP'
    candidate_expand={'adds_full_line','adds_rhs','mapping_handling','sequence_handling','bytes_handling','base64_handling','url_handling','recursive_call'}
    custom_more=[];official_more=[]
    for r in rows:
        if r['dimension'] not in candidate_expand or r['equal']:continue
        cv=json.loads(r['custom_value']);ov=json.loads(r['official_value'])
        if cv is True and ov is False:custom_more.append(r['dimension'])
        if cv is False and ov is True:official_more.append(r['dimension'])
    if custom_more and official_more:return 'PARTIAL_OVERLAP_STRUCTURALLY_INDICATED'
    if custom_more:return 'CUSTOM_POSSIBLE_SUPERSET_STRUCTURALLY_INDICATED'
    if official_more:return 'CUSTOM_POSSIBLE_SUBSET_STRUCTURALLY_INDICATED'
    return 'DIVERGENT_NOT_SET_ORDERABLE_STATICALLY'
def fixture_specs(rows):
    fixtures=[];i=1
    templates={
      'drops_hash_comments':'# comment\nSECRET=value', 'adds_full_line':'SECRET=value', 'adds_rhs':'SECRET=value',
      'json_handling':'{"secret":"value"}', 'mapping_handling':'{"secret":"value"}',
      'sequence_handling':'["value1","value2"]', 'bytes_handling':'bytes:value',
      'base64_handling':'dmFsdWU=', 'url_handling':'value%20with%20space',
      'splitlines':'A=1\nB=2', 'strip':'  SECRET=value  ', 'lstrip':'  # comment',
      'drops_blank':'\nSECRET=value\n', 'partition_equals':'A=B=C', 'split_equals':'A=B=C',
      'recursive_call':'{"nested":{"secret":"value"}}', 'deduplicates':'X=1\nX=1', 'sorts':'B=2\nA=1'}
    for r in rows:
        if r['equal'] or not r['material']:continue
        fixtures.append({'fixture_id':f'CE-DIV-{i:03d}','dimension':r['dimension'],'input_spec':templates.get(r['dimension'],'NOT_ESTABLISHED'),'execution_status':'NOT_EXECUTED','expected_custom_candidates':'NOT_ESTABLISHED_WITHOUT_EXECUTION','expected_official_candidates':'NOT_ESTABLISHED_WITHOUT_EXECUTION','purpose':'future controlled differential fixture; no result claimed'})
        i+=1
    return fixtures
def identity_formula(fn):
    s=up(fn); return {
      'identity_material_assignment':next((up(n) for n in ast.walk(fn) if isinstance(n,(ast.Assign,ast.AnnAssign)) and 'identity_material' in up(n)), 'NOT_ESTABLISHED'),
      'identity_hash_expression':next((up(c) for c in calls(fn) if '_sha256_text' in up(c) and 'identity_material' in up(c)), 'NOT_ESTABLISHED'),
      'bound_fields':{k:(k in s) for k in ['RECORD_TAG','sequence','tool_name','canonical_path','output_digest']}}
def restore_analysis(fn,formula):
    s=up(fn);recompute=('identity_material' in s and '_sha256_text' in s) or ('record_identity' in s and '_sha256_text' in s and '!=' in s)
    fields={k:(k in s) for k in ['record_sequence','tool_name','canonical_path','raw_output_sha256','raw_output','record_identity']}
    copied="row.get('record_identity')" in s or 'row.get("record_identity")' in s
    return {'recomputes_record_identity':recompute,'snapshot_identity_copied':copied,'restore_fields_present':fields,'all_formula_fields_present':all(fields.get({'sequence':'record_sequence','output_digest':'raw_output_sha256'}.get(k,k),False) for k,v in formula['bound_fields'].items() if v and k!='RECORD_TAG'),'source':s}

def main(a):
    out=Path(a.output_dir).resolve();require(not out.exists(),f'Refusing overwrite: {out}');out.mkdir(parents=True)
    checks=[]
    try:
      root=Path(a.project_root).resolve();ledger=root/'aicomp_sdk_exfil/successful_read_ledger_v1.py';pred=root/'aicomp_sdk/core/predicates.py'
      parent={'result':Path(a.static_result).resolve(),'checks':Path(a.static_checks).resolve(),'candidates':Path(a.static_candidates).resolve(),'claim':Path(a.static_claim_boundary).resolve(),'binding':Path(a.static_binding).resolve(),'external':Path(a.static_external_binding).resolve(),'manifest':Path(a.static_manifest).resolve(),'runner':Path(a.static_runner).resolve()}
      for k,p in parent.items():require(p.is_file(),f'Missing parent {k}: {p}')
      pr=rj(parent['result']);pe=rj(parent['external']);pc=rc(parent['checks'])
      add(checks,'R-001','parent',pr.get('version')==PARENT_VERSION and pr.get('status')==PARENT_STATUS,pr.get('status'),PARENT_STATUS,'FIXTURE')
      for i,(k,h) in enumerate([('manifest',PARENT_MANIFEST_SHA),('runner',PARENT_RUNNER_SHA),('result',PARENT_RESULT_SHA),('checks',PARENT_CHECKS_SHA),('candidates',PARENT_CANDIDATES_SHA),('binding',PARENT_BINDING_SHA)],2):add(checks,f'R-{i:03d}','parent',sha(parent[k])==h,sha(parent[k]),h,'FIXTURE')
      failed=[x['check_id'] for x in pc if x['passed']!='True'];add(checks,'R-008','parent',len(pc)==46 and failed==['Q-064'],{'total':len(pc),'failed':failed},'46 checks and only Q-064 failed','EVIDENCE')
      add(checks,'R-009','parent',pr.get('outcome')=='CANDIDATE_EXTRACTION_SEMANTIC_GAP' and pe.get('implementation_modified') is False,{'outcome':pr.get('outcome'),'modified':pe.get('implementation_modified')},'recorded gap preserved; implementation unchanged','CLAIM_BOUNDARY')
      require(ledger.is_file() and pred.is_file(),'Required sources missing')
      add(checks,'R-010','identity',sha(ledger)==IMPL_LEDGER_SHA,sha(ledger),IMPL_LEDGER_SHA,'FIXTURE');add(checks,'R-011','identity',sha(pred)==PREDICATES_SHA,sha(pred),PREDICATES_SHA,'FIXTURE')
      ltext=ledger.read_text(encoding='utf-8');ptext=pred.read_text(encoding='utf-8');lt=ast.parse(ltext);pt=ast.parse(ptext);lf=funcs(lt);pf=funcs(pt)
      require('_secret_values' in lf,'Custom _secret_values missing')
      # Discover authoritative candidate extraction functions by actual call lineage into secrets-read logic and semantic names.
      official_candidates=[]
      for name,fn in pf.items():
        low=name.lower();s=up(fn)
        score=sum([('secret' in low),('extract' in low),('value' in low),('output' in s),('fs.read' in s),('splitlines' in s),('yield' in s or 'return' in s)])
        if score>=3:official_candidates.append((score,name,fn))
      official_candidates.sort(key=lambda x:(-x[0],x[1]))
      rows_discovery=[{'name':name,'score':score,'line_start':fn.lineno,'line_end':getattr(fn,'end_lineno',fn.lineno),'source':source_segment(ptext,fn)} for score,name,fn in official_candidates]
      add(checks,'R-020','candidate',len(official_candidates)>=1,[x[1] for x in official_candidates],'at least one authoritative extraction candidate discovered','PREDICATE')
      exact=[x for x in official_candidates if x[1] in {'_extract_secret_values','extract_secret_values'}]
      owner=exact[0] if len(exact)==1 else (official_candidates[0] if len(official_candidates)==1 else None)
      add(checks,'R-021','candidate',owner is not None,[(x[0],x[1]) for x in official_candidates],'one authoritative extraction owner resolvable','PREDICATE')
      custom=lf['_secret_values'];official=owner[2] if owner else None
      custom_src=source_segment(ltext,custom);official_src=source_segment(ptext,official) if official else 'NOT_ESTABLISHED'
      custom_sig=feature_signature(custom);official_sig=feature_signature(official) if official else {'function':'NOT_ESTABLISHED'}
      comp=compare_features(custom_sig,official_sig) if official else []
      ast_equal=bool(official and normalize(custom)==normalize(official));relation=relation_from_features(comp,ast_equal) if official else 'NOT_ESTABLISHED'
      fixtures=fixture_specs(comp)
      add(checks,'R-022','candidate',official is not None and relation!='NOT_ESTABLISHED',relation,'candidate relationship classified from authoritative source','PREDICATE')
      add(checks,'R-023','candidate',True,{'ast_equal':ast_equal,'relation':relation,'divergence_count':sum(not r['equal'] for r in comp)},'exact comparison frozen','EVIDENCE')
      add(checks,'R-024','candidate',True,len(fixtures),'non-executed divergence fixtures generated','FIXTURE')

      ledger_cls=next(n for n in lt.body if isinstance(n,ast.ClassDef) and n.name=='SuccessfulReadLedgerV1');lm={n.name:n for n in ledger_cls.body if isinstance(n,ast.FunctionDef)}
      append=lm['append_successful_read'];restore=lm['restore_state'];formula=identity_formula(append);restore_info=restore_analysis(restore,formula)
      add(checks,'R-030','restore',formula['identity_material_assignment']!='NOT_ESTABLISHED' and formula['identity_hash_expression']!='NOT_ESTABLISHED',formula,'append record identity formula established','PROVENANCE')
      add(checks,'R-031','restore',all(formula['bound_fields'].values()),formula['bound_fields'],'all expected identity fields bound at append','PROVENANCE')
      add(checks,'R-032','restore',restore_info['recomputes_record_identity'],restore_info,'restore recomputes and validates record identity','PROVENANCE')
      add(checks,'R-033','restore',restore_info['all_formula_fields_present'],restore_info['restore_fields_present'],'all identity-bound fields present in restore','PROVENANCE')
      tamper=[
        {'tamper_id':'RI-T-001','field':'record_identity','expected_static_disposition':'ACCEPTED_UNVALIDATED' if restore_info['snapshot_identity_copied'] and not restore_info['recomputes_record_identity'] else 'REJECTED_OR_RECOMPUTED','execution_status':'NOT_EXECUTED'},
        {'tamper_id':'RI-T-002','field':'canonical_path','expected_static_disposition':'IDENTITY_MISMATCH_NOT_CHECKED' if not restore_info['recomputes_record_identity'] else 'REJECTED','execution_status':'NOT_EXECUTED'},
        {'tamper_id':'RI-T-003','field':'tool_args','expected_static_disposition':'IDENTITY_MISMATCH_NOT_CHECKED' if not restore_info['recomputes_record_identity'] else 'REJECTED','execution_status':'NOT_EXECUTED'},
        {'tamper_id':'RI-T-004','field':'raw_output','expected_static_disposition':'REJECTED_BY_RAW_DIGEST_CHECK','execution_status':'NOT_EXECUTED'},
        {'tamper_id':'RI-T-005','field':'record_sequence','expected_static_disposition':'REJECTED_BY_SEQUENCE_CHECK','execution_status':'NOT_EXECUTED'}]
      candidate_gap=relation not in {'EQUAL_SOURCE_NORMALIZED','QUALIFIER_METHOD_ONLY_GAP'}
      restore_gap=not restore_info['recomputes_record_identity'] or not restore_info['all_formula_fields_present']
      method_only=(relation=='QUALIFIER_METHOD_ONLY_GAP' and not restore_gap)
      if candidate_gap and restore_gap:outcome='V1_MULTIPLE_STATIC_GAPS_CONFIRMED'
      elif candidate_gap:outcome='V1_CANDIDATE_EXTRACTION_GAP_CONFIRMED'
      elif restore_gap:outcome='V1_RESTORE_IDENTITY_GAP_CONFIRMED'
      elif method_only:outcome='QUALIFIER_METHOD_ONLY_GAP'
      elif relation=='EQUAL_SOURCE_NORMALIZED':outcome='V1_STATIC_CONTRACT_RECONCILED_PASS'
      else:outcome='NOT_ESTABLISHED'
      failed_ids=[x['check_id'] for x in checks if not x['passed']]
      status='STATIC_QUALIFICATION_METHODOLOGY_CORRECTION_AND_CANDIDATE_CONTRACT_RECONCILIATION_COMPLETE_PASS' if outcome in {'V1_STATIC_CONTRACT_RECONCILED_PASS','QUALIFIER_METHOD_ONLY_GAP'} and not failed_ids else 'STATIC_QUALIFICATION_METHODOLOGY_CORRECTION_AND_CANDIDATE_CONTRACT_RECONCILIATION_COMPLETE_WITH_GAPS'
      v2=outcome in {'V1_CANDIDATE_EXTRACTION_GAP_CONFIRMED','V1_RESTORE_IDENTITY_GAP_CONFIRMED','V1_MULTIPLE_STATIC_GAPS_CONFIRMED'}
      claim={'allowed':['authoritative custom-versus-official extraction source comparison','static relationship classification','non-executed divergence fixture specification','append identity-formula reconstruction','restore identity-validation and tamper classification'],'prohibited':['modify V1 or SDK','claim runtime candidate sets','claim official parity unless exact equivalence established','execute extraction or predicates','claim runtime behavior','claim protected-value lineage','claim guardrail effectiveness']}
      result={'version':VERSION,'created_at_utc':now(),'status':status,'classification':'READ_ONLY_AUTHORITATIVE_SOURCE_COMPARISON','parent_verified':True,'checks':{'total':len(checks),'passed':len(checks)-len(failed_ids),'failed':len(failed_ids),'failed_ids':failed_ids},'outcome':outcome,'candidate_reconciliation':{'official_owner':owner[1] if owner else 'NOT_ESTABLISHED','official_source_file':'aicomp_sdk/core/predicates.py','official_source_sha256':sha(pred),'custom_owner':'_secret_values','custom_source_file':'aicomp_sdk_exfil/successful_read_ledger_v1.py','custom_source_sha256':sha(ledger),'normalized_ast_equal':ast_equal,'relationship':relation,'divergence_count':sum(not r['equal'] for r in comp),'fixtures_executed':False},'restore_reconciliation':{'append_identity_formula':formula,'restore':restore_info,'tamper_specs_executed':False,'V2_required':restore_gap},'readiness':{'V2_implementation_freeze_eligible':v2,'corrected_requalification_eligible':outcome in {'V1_STATIC_CONTRACT_RECONCILED_PASS','QUALIFIER_METHOD_ONLY_GAP'},'controlled_actual_fs_read_eligible':False,'http_sink_eligible':False},'execution_boundaries':{'implementation_modified':False,'frozen_aicomp_sdk_modified':False,'implementation_imported':False,'implementation_instantiated':False,'sdk_modules_imported':False,'sdk_modules_executed':False,'candidate_extraction_executed':False,'predicates_executed':False,'Sandbox_instantiated':False,'Gym_executed':False,'real_tools_executed':False,'actual_fs_read_executed':False,'http_sink_executed':False,'breach_executed':False,'models_used':False,'threads_executed':False,'external_effects_observed':False},'scientific_verdict':{'candidate_extraction_relationship':relation,'restore_record_identity_integrity':'GAP_CONFIRMED' if restore_gap else 'ESTABLISHED_STATICALLY','implementation_behavior':'NOT_EVALUATED','protected_value_lineage':'NOT_ESTABLISHED','harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'},'claim_boundary':claim,'next_gate':'EXFIL_STATEFUL_GUARDRAIL_V2_IMPLEMENTATION_AND_IDENTITY_FREEZE' if v2 else ('CORRECTED_INDEPENDENT_STATEFUL_GUARDRAIL_STATIC_QUALIFICATION' if outcome!='NOT_ESTABLISHED' else 'STATIC_RECONCILIATION_GAP_REVIEW')}
      o={'result':out/'reconciliation_result.json','checks':out/'reconciliation_checks.csv','discovery':out/'official_extraction_discovery.csv','sources':out/'extraction_sources.json','features':out/'extraction_features.json','divergences':out/'extraction_divergences.csv','fixtures':out/'extraction_divergence_fixtures.json','identity':out/'restore_identity_contract.json','tamper':out/'restore_tamper_specs.csv','claim':out/'reconciliation_claim_boundary.json','binding':out/'reconciliation_binding.json'}
      wj(o['result'],result);wc(o['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']);wc(o['discovery'],rows_discovery,['name','score','line_start','line_end','source']);wj(o['sources'],{'custom':{'file':str(ledger),'sha256':sha(ledger),'function':'_secret_values','line_start':custom.lineno,'line_end':getattr(custom,'end_lineno',custom.lineno),'source':custom_src},'official':{'file':str(pred),'sha256':sha(pred),'function':owner[1] if owner else 'NOT_ESTABLISHED','line_start':official.lineno if official else None,'line_end':getattr(official,'end_lineno',None) if official else None,'source':official_src}});wj(o['features'],{'custom':custom_sig,'official':official_sig,'normalized_ast_equal':ast_equal,'relationship':relation});wc(o['divergences'],comp,['dimension','custom_value','official_value','equal','material']);wj(o['fixtures'],{'execution_status':'NOT_EXECUTED','fixtures':fixtures});wj(o['identity'],{'append_formula':formula,'restore_analysis':restore_info});wc(o['tamper'],tamper,['tamper_id','field','expected_static_disposition','execution_status']);wj(o['claim'],claim);wj(o['binding'],{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'parent':{k:ident(v) for k,v in parent.items()},'custom_source':ident(ledger),'official_source':ident(pred),'implementation_modified':False,'frozen_aicomp_sdk_modified':False,'implementation_imported':False,'candidate_extraction_executed':False})
      rows=[{**ident(p),'role':'RECONCILIATION_DERIVED'} for p in o.values()]+[{**ident(p),'role':'RECONCILIATION_BOUND_PARENT'} for p in parent.values()]+[{**ident(ledger),'role':'RECONCILIATION_CUSTOM_SOURCE'},{**ident(pred),'role':'RECONCILIATION_OFFICIAL_SOURCE'}]
      mp=out/'reconciliation_manifest.csv';wc(mp,rows,['artifact','role','size_bytes','sha256','path'])
      ep=out/'reconciliation_manifest_external_binding.json';wj(ep,{'version':VERSION,'created_at_utc':now(),'status':status,'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':sha(mp),'runner_sha256':sha(Path(__file__).resolve()),'parent_manifest_sha256':PARENT_MANIFEST_SHA,'checks_total':len(checks),'checks_passed':len(checks)-len(failed_ids),'checks_failed':len(failed_ids),'failed_ids':failed_ids,'outcome':outcome,'V2_required':v2,'implementation_modified':False,'frozen_aicomp_sdk_modified':False,'candidate_extraction_executed':False,'controlled_actual_fs_read_eligible':False,'next_gate':result['next_gate']})
      print(json.dumps({'status':status,'checks':f'{len(checks)-len(failed_ids)}/{len(checks)}','failed_ids':failed_ids,'outcome':outcome,'official_extraction_owner':owner[1] if owner else 'NOT_ESTABLISHED','candidate_relationship':relation,'restore_recomputes_record_identity':restore_info['recomputes_record_identity'],'V2_required':v2,'implementation_modified':False,'candidate_extraction_executed':False,'controlled_actual_fs_read_eligible':False,'manifest_sha256':sha(mp),'next_gate':result['next_gate']},indent=2))
    except Exception as e:
      (out/'RECONCILIATION_FAILED.json').write_text(json.dumps({'version':VERSION,'created_at_utc':now(),'status':'STATIC_RECONCILIATION_BLOCKED','error_type':type(e).__name__,'error':str(e),'checks_frozen':checks,'implementation_modified':False,'frozen_aicomp_sdk_modified':False,'implementation_imported':False,'candidate_extraction_executed':False,'actual_fs_read_executed':False},indent=2),encoding='utf-8');raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for f in ['static-result','static-checks','static-candidates','static-claim-boundary','static-binding','static-external-binding','static-manifest','static-runner','project-root','output-dir']:p.add_argument('--'+f,required=True)
    return p.parse_args()
if __name__=='__main__':
    try:main(args())
    except Exception as e:print(f'FAILED: {e}',file=sys.stderr);raise SystemExit(1)
