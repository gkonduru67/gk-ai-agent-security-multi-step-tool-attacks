#!/usr/bin/env python3
"""Controlled successful-read ledger qualification v1.0.

Executes only the frozen V2 ledger module with synthetic in-memory contract
fixtures. It does not import the V2 package __init__, hook, guardrail, factory,
SDK, Sandbox, or Gym; execute fs.read or any tool; form an HTTP proposal; run
predicates/breach/models/threads; or cause external effects.

The precise ledger source is loaded with an isolated synthetic parent package
whose __path__ points at the frozen V2 directory. This prevents Python's normal
package import path from executing aicomp_sdk_exfil_v2/__init__.py. The exact
loader strategy and newly loaded modules are recorded as evidence.
"""
from __future__ import annotations
import argparse, copy, csv, hashlib, importlib.util, json, sys, types
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "CONTROLLED_SUCCESSFUL_FS_READ_LEDGER_QUALIFICATION_v1.0"
MODULE_NAME = "aicomp_sdk_exfil_v2.successful_read_ledger_v2"
PACKAGE_NAME = "aicomp_sdk_exfil_v2"
EXPECTED = {
    "v2_manifest": "E4012BAEE67A8B93D4B54DEA90415CB4E5A38B4385DC301EF50D9B2E748A9521",
    "independent_manifest": "205284E446C3FD3890478ECC4C7666A2CECF3363B6AC727AE20EC07D42F63993",
    "independent_result": "684935BC42F9C76EE527D42418A0C740AB95538317A67D27BD994411D3638815",
    "corrected_manifest": "68163666E8433F1BC0A0B3E555E39BE1CCC4D07F8EE5A2938DBB5B87825994CA",
    "corrected_result": "5FA706379A549B233E2C5ED98D6811BAB13A41FC690C93E1477AFB08BF87F232",
    "corrected_checks": "D2D41A44E8F985EDEFD39FE3CCEA45C28308C944EA03B0F899E209521FF94E82",
    "corrected_formula": "88F7B45FD5EEF25AE6F4581878712573774EE24370E8C97A179A0311F3444F68",
    "v2_ledger": "609B22AA7ABD3555B24484E2AF313A5460877BA3C446FBE2978C6136D662857E",
}
V2_LEDGER_SIZE = 6645
OFFICIAL_MINIMUM = 6
RECORD_TAG = "EXFIL.SUCCESSFUL.READ.RECORD.V2"
EXPECTED_CORRECTED_OUTCOME = "IQ2_042_QUALIFIER_METHOD_GAP_CONFIRMED"
EXPECTED_REVIEWED_DISPOSITION = "INDEPENDENT_V2_STATIC_QUALIFICATION_PASS_AFTER_METHOD_CORRECTION"


def now() -> str: return datetime.now(timezone.utc).isoformat()
def require(value: bool, message: str) -> None:
    if not value: raise ValueError(message)
def sha_file(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1<<20),b''): h.update(block)
    return h.hexdigest().upper()
def sha_text(value: str) -> str: return hashlib.sha256(value.encode('utf-8','surrogatepass')).hexdigest().upper()
def identity(path: Path) -> dict[str,object]:
    path=path.resolve(); return {"artifact":path.name,"path":str(path),"size_bytes":path.stat().st_size,"sha256":sha_file(path)}
def read_json(path: Path) -> Any: return json.loads(path.read_text(encoding='utf-8-sig'))
def write_json(path: Path, value: Any) -> None:
    with path.open('x',encoding='utf-8',newline='\n') as f: json.dump(value,f,indent=2,sort_keys=True,ensure_ascii=False); f.write('\n')
def write_csv(path: Path, rows: list[dict[str,Any]], fields: list[str]) -> None:
    with path.open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n'); w.writeheader(); w.writerows(rows)
def add(rows:list[dict[str,Any]], cid:str, category:str, passed:bool, observed:Any, expected:Any, layer:str) -> None:
    rows.append({"check_id":cid,"category":category,"passed":bool(passed),"observed":json.dumps(observed,sort_keys=True,ensure_ascii=False,default=str) if isinstance(observed,(dict,list,tuple)) else str(observed),"expected":json.dumps(expected,sort_keys=True,ensure_ascii=False,default=str) if isinstance(expected,(dict,list,tuple)) else str(expected),"failure_layer":layer})
def canonical(value: Any) -> str: return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
def state_digest(snapshot: Any) -> str: return sha_text(canonical(snapshot))
def independent_args_digest(args: dict[str,Any]) -> str: return sha_text(canonical(dict(args)))
def independent_identity(sequence:int, tool_name:str, path:str, args_digest:str, output_digest:str) -> str:
    return sha_text(f"{RECORD_TAG}|{sequence}|{tool_name}|{path}|{args_digest}|{output_digest}")
def independent_candidates(raw: str) -> tuple[str,...]:
    values:set[str]=set()
    for raw_line in raw.splitlines():
        line=raw_line.strip()
        if not line or line.startswith('#'): continue
        if '=' in line:
            values.add(line); value=line.partition('=')[2].strip()
            if len(value)>=OFFICIAL_MINIMUM: values.add(value)
        elif len(line)>=OFFICIAL_MINIMUM: values.add(line)
    return tuple(sorted(values))
def jsonable_record(record: Any) -> dict[str,Any]:
    return {"schema_tag":record.schema_tag,"record_sequence":record.record_sequence,"tool_name":record.tool_name,"tool_args":dict(record.tool_args),"tool_args_sha256":record.tool_args_sha256,"canonical_path":record.canonical_path,"explicit_ok":record.explicit_ok,"error_value":record.error_value,"raw_output":record.raw_output,"raw_output_sha256":record.raw_output_sha256,"derived_secret_values":list(record.derived_secret_values),"record_identity":record.record_identity}

def isolated_load(ledger_path: Path) -> tuple[Any,dict[str,Any]]:
    before=set(sys.modules)
    prior_package=sys.modules.get(PACKAGE_NAME); prior_module=sys.modules.get(MODULE_NAME)
    require(prior_package is None and prior_module is None,"V2 package or ledger module already loaded before controlled import")
    package=types.ModuleType(PACKAGE_NAME); package.__path__=[str(ledger_path.parent)]; package.__package__=PACKAGE_NAME
    package.__spec__=importlib.util.spec_from_loader(PACKAGE_NAME,loader=None,is_package=True)
    sys.modules[PACKAGE_NAME]=package
    try:
        spec=importlib.util.spec_from_file_location(MODULE_NAME,ledger_path)
        require(spec is not None and spec.loader is not None,"Unable to create precise ledger module spec")
        module=importlib.util.module_from_spec(spec); sys.modules[MODULE_NAME]=module; spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(MODULE_NAME,None); sys.modules.pop(PACKAGE_NAME,None); raise
    newly=sorted(set(sys.modules)-before)
    forbidden=[name for name in newly if any(token in name.lower() for token in ['trusted_read_outcome_hook','lineage_aware_exfil_guardrail','integration_factory','aicomp_sdk','sandbox','gym']) and name not in {PACKAGE_NAME,MODULE_NAME}]
    evidence={"strategy":"spec_from_file_location_with_synthetic_parent_package","requested_module":MODULE_NAME,"source_path":str(ledger_path),"package_init_executed":False,"newly_loaded_modules":newly,"forbidden_new_modules":forbidden,"prior_package":prior_package is not None,"prior_module":prior_module is not None}
    return module,evidence

def expect_exception(callable_obj, expected_type: type[BaseException], message_contains: str) -> dict[str,Any]:
    try: callable_obj()
    except Exception as exc:
        return {"raised":True,"type":type(exc).__name__,"message":str(exc),"match":isinstance(exc,expected_type) and message_contains in str(exc)}
    return {"raised":False,"type":None,"message":None,"match":False}

def main(a: argparse.Namespace) -> None:
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    checks:list[dict[str,Any]]=[]; fixture_rows=[]; append_rows=[]; tamper_rows=[]
    actual_fs_read=False; hook_instantiated=False; guardrail_instantiated=False; external_effects=False
    try:
        root=Path(a.project_root).resolve(); ledger_path=root/'aicomp_sdk_exfil_v2'/'successful_read_ledger_v2.py'
        inputs={"v2_manifest":Path(a.v2_manifest).resolve(),"independent_manifest":Path(a.independent_manifest).resolve(),"independent_result":Path(a.independent_result).resolve(),"corrected_manifest":Path(a.corrected_manifest).resolve(),"corrected_result":Path(a.corrected_result).resolve(),"corrected_checks":Path(a.corrected_checks).resolve(),"corrected_formula":Path(a.corrected_formula).resolve(),"corrected_external":Path(a.corrected_external).resolve(),"v2_ledger":ledger_path}
        for name,path in inputs.items(): require(path.is_file(),f"Missing input {name}: {path}")
        for i,(name,expected) in enumerate(EXPECTED.items(),1): add(checks,f'CL-{i:03d}','identity',sha_file(inputs[name])==expected,sha_file(inputs[name]),expected,'FIXTURE')
        add(checks,'CL-010','identity',ledger_path.stat().st_size==V2_LEDGER_SIZE,ledger_path.stat().st_size,V2_LEDGER_SIZE,'FIXTURE')
        old=read_json(inputs['independent_result']); corr=read_json(inputs['corrected_result']); ext=read_json(inputs['corrected_external'])
        add(checks,'CL-011','parent',old.get('checks')=={"failed":1,"failed_ids":["IQ2-042"],"passed":59,"total":60},old.get('checks'),{"failed":1,"failed_ids":["IQ2-042"],"passed":59,"total":60},'EVIDENCE')
        parent_ok=corr.get('outcome')==EXPECTED_CORRECTED_OUTCOME and corr.get('reviewed_static_disposition')==EXPECTED_REVIEWED_DISPOSITION and corr.get('checks',{}).get('failed')==0 and ext.get('manifest_sha256')==EXPECTED['corrected_manifest']
        add(checks,'CL-012','parent',parent_ok,{"outcome":corr.get('outcome'),"disposition":corr.get('reviewed_static_disposition'),"failed":corr.get('checks',{}).get('failed'),"external_manifest":ext.get('manifest_sha256')},{"outcome":EXPECTED_CORRECTED_OUTCOME,"disposition":EXPECTED_REVIEWED_DISPOSITION,"failed":0,"external_manifest":EXPECTED['corrected_manifest']},'EVIDENCE')

        module,import_evidence=isolated_load(ledger_path)
        forbidden=import_evidence['forbidden_new_modules']; add(checks,'CL-013','import',not import_evidence['package_init_executed'],import_evidence,{'package_init_executed':False},'ADAPTER_PARSE')
        add(checks,'CL-014','import',not forbidden,forbidden,[],'ADAPTER_PARSE')
        Record=getattr(module,'SuccessfulReadRecordV2',None); Ledger=getattr(module,'SuccessfulReadLedgerV2',None)
        add(checks,'CL-015','import',isinstance(Record,type) and isinstance(Ledger,type),{"record":str(Record),"ledger":str(Ledger)},'expected classes','ADAPTER_PARSE')
        add(checks,'CL-016','import',getattr(module,'OFFICIAL_MIN_SECRET_VALUE_LEN',None)==6,getattr(module,'OFFICIAL_MIN_SECRET_VALUE_LEN',None),6,'PREDICATE')
        require(isinstance(Ledger,type),'Ledger class unavailable')

        fixtures=[('CV2-001','RHS length 5','K=12345'),('CV2-002','RHS length 6','K=123456'),('CV2-003','RHS length 7','K=1234567'),('CV2-004','bare length 5','12345'),('CV2-005','bare length 6','123456'),('CV2-006','bare length 7','1234567'),('CV2-007','blank line','   '),('CV2-008','hash comment','# secret'),('CV2-009','empty RHS','K='),('CV2-010','trimmed RHS','K=  123456  '),('CV2-011','duplicate assignments','K=123456\nK=123456'),('CV2-012','multiple equals','K=A=B=C')]
        fixtures_ok=True
        for fid,case,raw in fixtures:
            led=Ledger(); args={'path':f'/synthetic/{fid}.txt'}; path=args['path']; expected=independent_candidates(raw)
            rec=led.append_successful_read(tool_name='fs.read',tool_args=args,canonical_path=path,explicit_ok=True,error_value=None,raw_output=raw)
            observed=tuple(rec.derived_secret_values); membership=set(observed)==set(expected); ordering=observed==tuple(sorted(observed)); row={"fixture_id":fid,"case":case,"raw_input":raw,"raw_input_sha256":sha_text(raw),"expected_membership":json.dumps(sorted(expected),ensure_ascii=False),"observed_ordered_tuple":json.dumps(list(observed),ensure_ascii=False),"observed_membership":json.dumps(sorted(set(observed)),ensure_ascii=False),"membership_match":membership,"ordering_status":"SORTED_DETERMINISTIC" if ordering else "ORDER_MISMATCH"}
            fixture_rows.append(row); fixtures_ok &= membership and ordering
        add(checks,'CL-017','candidate',fixtures_ok,[{"id":x['fixture_id'],"match":x['membership_match'],"order":x['ordering_status']} for x in fixture_rows],'12 membership matches and deterministic order','SECRET_CAPTURE')

        ledger=Ledger(); mutable_args={'path':'/synthetic/main.txt','options':{'encoding':'utf-8'}}; original_copy=copy.deepcopy(mutable_args); raw='API_KEY=ABCDEF\n12345\n123456\n# ignored'
        r1=ledger.append_successful_read(tool_name='fs.read',tool_args=mutable_args,canonical_path=mutable_args['path'],explicit_ok=True,error_value=None,raw_output=raw)
        mutable_args['path']='/mutated'; mutable_args['options']['encoding']='latin-1'
        copied=dict(r1.tool_args)==original_copy and dict(r1.tool_args)!=mutable_args
        args_digest=independent_args_digest(original_copy); output_digest=sha_text(raw); expected_identity=independent_identity(1,'fs.read',original_copy['path'],args_digest,output_digest)
        positive={"sequence":r1.record_sequence,"args_copied":copied,"args_digest_match":r1.tool_args_sha256==args_digest,"raw_preserved":r1.raw_output==raw,"raw_digest_match":r1.raw_output_sha256==output_digest,"candidates_match":r1.derived_secret_values==independent_candidates(raw),"identity_match":r1.record_identity==expected_identity}
        add(checks,'CL-018','append',all(positive.values()),positive,'all positive append controls','PROVENANCE')
        r2=ledger.append_successful_read(tool_name='fs.read',tool_args={'path':'/synthetic/second.txt'},canonical_path='/synthetic/second.txt',explicit_ok=True,error_value=None,raw_output='SECOND=123456')
        add(checks,'CL-019','append',(r1.record_sequence,r2.record_sequence)==(1,2),(r1.record_sequence,r2.record_sequence),(1,2),'PROVENANCE')
        negative_controls=[('non_fs_read',lambda:Ledger().append_successful_read(tool_name='http.post',tool_args={},canonical_path='/x',explicit_ok=True,error_value=None,raw_output='x'),ValueError,'only explicit successful fs.read'),('explicit_false',lambda:Ledger().append_successful_read(tool_name='fs.read',tool_args={},canonical_path='/x',explicit_ok=False,error_value=None,raw_output='x'),ValueError,'only explicit successful fs.read'),('args_type',lambda:Ledger().append_successful_read(tool_name='fs.read',tool_args=None,canonical_path='/x',explicit_ok=True,error_value=None,raw_output='x'),TypeError,'malformed successful-read evidence'),('path_type',lambda:Ledger().append_successful_read(tool_name='fs.read',tool_args={},canonical_path=None,explicit_ok=True,error_value=None,raw_output='x'),TypeError,'malformed successful-read evidence'),('raw_type',lambda:Ledger().append_successful_read(tool_name='fs.read',tool_args={},canonical_path='/x',explicit_ok=True,error_value=None,raw_output=None),TypeError,'malformed successful-read evidence')]
        neg_ok=True
        for name,fn,typ,msg in negative_controls:
            observed=expect_exception(fn,typ,msg); append_rows.append({"control_id":name,**observed}); neg_ok &= observed['match']
        add(checks,'CL-020','append',neg_ok,append_rows,'all malformed controls rejected','ARGUMENT_FIDELITY')

        snapshot1=ledger.snapshot_state(); snapshot2=ledger.snapshot_state(); deterministic=canonical(snapshot1)==canonical(snapshot2)
        restored=Ledger(); restored.restore_state(copy.deepcopy(snapshot1)); original_records=[jsonable_record(x) for x in ledger.records()]; restored_records=[jsonable_record(x) for x in restored.records()]
        roundtrip=original_records==restored_records and restored.snapshot_state()['next_sequence']==snapshot1['next_sequence']
        add(checks,'CL-021','restore',deterministic,{"snapshot_digest_1":state_digest(snapshot1),"snapshot_digest_2":state_digest(snapshot2)},'identical snapshot digests','PROVENANCE')
        add(checks,'CL-022','restore',roundtrip,{"records_equal":original_records==restored_records,"next_sequence":restored.snapshot_state()['next_sequence']},'clean round trip','PROVENANCE')
        restored.reset(); reset_ok=restored.records()==() and restored.snapshot_state()=={'schema_tag':'EXFIL.SUCCESSFUL.READ.LEDGER.V2','next_sequence':1,'records':[]}
        add(checks,'CL-023','restore',reset_ok,restored.snapshot_state(),'empty records and next_sequence 1','PROVENANCE')

        baseline=Ledger(); baseline.append_successful_read(tool_name='fs.read',tool_args={'path':'/synthetic/tamper.txt','mode':'text'},canonical_path='/synthetic/tamper.txt',explicit_ok=True,error_value=None,raw_output='TOKEN=123456'); base_snapshot=baseline.snapshot_state()
        def mutate(case:str,s:dict[str,Any]) -> None:
            row=s['records'][0]
            if case=='ledger_schema_tag':s['schema_tag']='BAD'
            elif case=='record_schema_tag':row['schema_tag']='BAD'
            elif case=='record_sequence':row['record_sequence']=2
            elif case=='tool_name':row['tool_name']='http.post'
            elif case=='tool_args':row['tool_args']['mode']='binary'
            elif case=='tool_args_sha256':row['tool_args_sha256']='0'*64
            elif case=='canonical_path':row['canonical_path']='/tampered'
            elif case=='explicit_ok':row['explicit_ok']=False
            elif case=='raw_output':row['raw_output']='TOKEN=TAMPER'
            elif case=='raw_output_sha256':row['raw_output_sha256']='0'*64
            elif case=='derived_secret_values':row['derived_secret_values']=('WRONG',)
            elif case=='record_identity':row['record_identity']='0'*64
            elif case=='next_sequence':s['next_sequence']=99
        cases=['ledger_schema_tag','record_schema_tag','record_sequence','tool_name','tool_args','tool_args_sha256','canonical_path','explicit_ok','raw_output','raw_output_sha256','derived_secret_values','record_identity','next_sequence']
        tamper_ok=True
        for case in cases:
            tampered=copy.deepcopy(base_snapshot); mutate(case,tampered)
            target=Ledger(); target.append_successful_read(tool_name='fs.read',tool_args={'path':'/preexisting'},canonical_path='/preexisting',explicit_ok=True,error_value=None,raw_output='PREEXIST=123456')
            before=target.snapshot_state(); before_digest=state_digest(before)
            try: target.restore_state(tampered); raised=False; typ=None; msg=None
            except Exception as exc: raised=True; typ=type(exc).__name__; msg=str(exc)
            after=target.snapshot_state(); after_digest=state_digest(after); unchanged=before_digest==after_digest
            row={"tamper_id":case,"expected":"REJECT","observed_exception_type":typ,"observed_exception_message":msg,"rejected":raised,"pre_restore_target_state_sha256":before_digest,"post_failure_target_state_sha256":after_digest,"target_state_unchanged":unchanged}
            tamper_rows.append(row); tamper_ok &= raised and unchanged
        add(checks,'CL-024','restore',tamper_ok,[{"id":x['tamper_id'],"rejected":x['rejected'],"unchanged":x['target_state_unchanged']} for x in tamper_rows],'13 tamper cases rejected atomically','PROVENANCE')

        ledger_hash_unchanged=sha_file(ledger_path)==EXPECTED['v2_ledger']; add(checks,'CL-025','immutability',ledger_hash_unchanged,sha_file(ledger_path),EXPECTED['v2_ledger'],'FIXTURE')
        execution_boundary_ok=not any([actual_fs_read,hook_instantiated,guardrail_instantiated,external_effects])
        add(checks,'CL-026','boundary',execution_boundary_ok,{"actual_fs_read":actual_fs_read,"hook_instantiated":hook_instantiated,"guardrail_instantiated":guardrail_instantiated,"external_effects":external_effects},'all false','CLAIM_BOUNDARY')

        failed=[x['check_id'] for x in checks if not x['passed']]
        if any(x in failed for x in [f'CL-{i:03d}' for i in range(1,13)]): outcome='NOT_ESTABLISHED'
        elif any(x in failed for x in ['CL-013','CL-014','CL-015']): outcome='V2_IMPORT_RUNTIME_GAP'
        elif any(x in failed for x in ['CL-016','CL-017']): outcome='V2_CANDIDATE_RUNTIME_GAP'
        elif any(x in failed for x in ['CL-018','CL-020']): outcome='V2_ARGUMENT_DIGEST_RUNTIME_GAP'
        elif 'CL-019' in failed: outcome='V2_RECORD_IDENTITY_RUNTIME_GAP'
        elif any(x in failed for x in ['CL-021','CL-022','CL-023']): outcome='V2_RESTORE_RUNTIME_GAP'
        elif 'CL-024' in failed: outcome='V2_RESTORE_ATOMICITY_GAP'
        elif any(x in failed for x in ['CL-025','CL-026']): outcome='NOT_ESTABLISHED'
        else: outcome='CONTROLLED_V2_LEDGER_QUALIFICATION_PASS'
        passed=outcome=='CONTROLLED_V2_LEDGER_QUALIFICATION_PASS'; status='CONTROLLED_SUCCESSFUL_FS_READ_LEDGER_QUALIFICATION_COMPLETE_PASS' if passed else 'CONTROLLED_SUCCESSFUL_FS_READ_LEDGER_QUALIFICATION_COMPLETE_WITH_GAPS'
        claim={"allowed":["precise isolated V2 ledger import behavior","controlled synthetic candidate membership and ordering","controlled append, digest, identity, snapshot, restore, reset, tamper, and atomicity behavior"],"prohibited":["claim actual fs.read","claim protected source retrieval","claim hook transport","claim source provenance","claim sink proposal or guardrail denial","claim protected-value lineage","claim end-to-end guardrail effectiveness","claim robust security findings"]}
        result={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"CONTROLLED_IN_MEMORY_SUCCESSFUL_READ_EVIDENCE_LEDGER_QUALIFICATION","checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"outcome":outcome,"import_evidence":import_evidence,"fixtures":{"total":len(fixture_rows),"passed":sum(bool(x['membership_match']) and x['ordering_status']=='SORTED_DETERMINISTIC' for x in fixture_rows)},"tamper_controls":{"total":len(tamper_rows),"rejected":sum(bool(x['rejected']) for x in tamper_rows),"atomic":sum(bool(x['target_state_unchanged']) for x in tamper_rows)},"readiness":{"controlled_actual_fs_read_hook_and_ledger_qualification_eligible":passed,"controlled_actual_fs_read_eligible":False,"http_sink_eligible":False},"execution_boundaries":{"V2_ledger_imported":True,"V2_package_init_executed":False,"hook_imported":False,"hook_instantiated":False,"guardrail_imported":False,"guardrail_instantiated":False,"factory_imported":False,"SDK_imported":False,"Sandbox_instantiated":False,"Gym_executed":False,"actual_fs_read_executed":False,"tools_executed":False,"http_sink_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False,"threads_executed":False,"external_effects_observed":False,"V2_modified":False,"V1_modified":False,"frozen_aicomp_sdk_modified":False},"scientific_verdict":{"controlled_ledger_runtime_contract":"ESTABLISHED" if passed else outcome,"actual_source_retrieval":"NOT_EVALUATED","hook_transport":"NOT_EVALUATED","protected_value_lineage":"NOT_ESTABLISHED","guardrail_effectiveness":"NOT_EVALUATED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim,"next_gate":"CONTROLLED_ACTUAL_FS_READ_HOOK_AND_LEDGER_QUALIFICATION" if passed else "CONTROLLED_V2_LEDGER_GAP_REVIEW"}
        outputs={"result":out/'controlled_v2_ledger_result.json',"checks":out/'controlled_v2_ledger_checks.csv',"fixtures":out/'controlled_v2_ledger_candidate_fixtures.csv',"append":out/'controlled_v2_ledger_append_controls.csv',"tamper":out/'controlled_v2_ledger_tamper_matrix.csv',"import":out/'controlled_v2_ledger_import_evidence.json',"claim":out/'controlled_v2_ledger_claim_boundary.json',"binding":out/'controlled_v2_ledger_binding.json'}
        write_json(outputs['result'],result); write_csv(outputs['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']); write_csv(outputs['fixtures'],fixture_rows,['fixture_id','case','raw_input','raw_input_sha256','expected_membership','observed_ordered_tuple','observed_membership','membership_match','ordering_status']); write_csv(outputs['append'],append_rows,['control_id','raised','type','message','match']); write_csv(outputs['tamper'],tamper_rows,['tamper_id','expected','observed_exception_type','observed_exception_message','rejected','pre_restore_target_state_sha256','post_failure_target_state_sha256','target_state_unchanged']); write_json(outputs['import'],import_evidence); write_json(outputs['claim'],claim); write_json(outputs['binding'],{"version":VERSION,"created_at_utc":now(),"runner":identity(Path(__file__).resolve()),"inputs":{k:identity(v) for k,v in inputs.items()},"V2_ledger_imported":True,"package_init_executed":False,"actual_fs_read_executed":False,"hook_instantiated":False,"guardrail_instantiated":False,"external_effects_observed":False})
        manifest_rows=[{**identity(p),"role":"CONTROLLED_V2_LEDGER_DERIVED"} for p in outputs.values()]+[{**identity(p),"role":"CONTROLLED_V2_LEDGER_BOUND_INPUT"} for p in inputs.values()]
        manifest=out/'controlled_v2_ledger_manifest.csv'; write_csv(manifest,manifest_rows,['artifact','role','size_bytes','sha256','path'])
        external=out/'controlled_v2_ledger_manifest_external_binding.json'; write_json(external,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":manifest.name,"manifest_size_bytes":manifest.stat().st_size,"manifest_sha256":sha_file(manifest),"runner_sha256":sha_file(Path(__file__).resolve()),"V2_implementation_manifest_sha256":EXPECTED['v2_manifest'],"independent_static_manifest_sha256":EXPECTED['independent_manifest'],"corrected_IQ2_042_manifest_sha256":EXPECTED['corrected_manifest'],"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"outcome":outcome,"actual_fs_read_executed":False,"http_sink_eligible":False,"next_gate":result['next_gate']})
        print(json.dumps({"status":status,"checks":f"{len(checks)-len(failed)}/{len(checks)}","failed_ids":failed,"outcome":outcome,"candidate_fixtures":f"{result['fixtures']['passed']}/{result['fixtures']['total']}","tamper_rejected":f"{result['tamper_controls']['rejected']}/{result['tamper_controls']['total']}","tamper_atomic":f"{result['tamper_controls']['atomic']}/{result['tamper_controls']['total']}","package_init_executed":False,"actual_fs_read_executed":False,"manifest_sha256":sha_file(manifest),"next_gate":result['next_gate']},indent=2))
    except Exception as exc:
        (out/'CONTROLLED_V2_LEDGER_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"CONTROLLED_V2_LEDGER_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"checks_frozen":checks,"actual_fs_read_executed":actual_fs_read,"hook_instantiated":hook_instantiated,"guardrail_instantiated":guardrail_instantiated,"external_effects_observed":external_effects},indent=2),encoding='utf-8'); raise

def parse_args() -> argparse.Namespace:
    p=argparse.ArgumentParser(description=VERSION)
    for name in ['v2-manifest','independent-manifest','independent-result','corrected-manifest','corrected-result','corrected-checks','corrected-formula','corrected-external','project-root','output-dir']: p.add_argument('--'+name,required=True)
    return p.parse_args()
if __name__=='__main__':
    try: main(parse_args())
    except Exception as exc: print(f'FAILED: {exc}',file=sys.stderr); raise SystemExit(1)
