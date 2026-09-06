#!/usr/bin/env python3
"""EX7 P2 P2R0 full public evaluator event-schema closure, v7.41.

Read-only AST/source inspection. Verifies the immutable v7.40 package and
inspects predicates.py, sandbox.py, trace.py, api.py, cli test.py, and optional
tool-source files. It does not import SDK modules, construct repaired traces,
execute predicates/breach, modify v7.30/v7.40, or select a neutral value unless
that value is explicitly supported by canonical source.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, re, sys, platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "EX7_P2_P2R0_FULL_EVALUATOR_EVENT_SCHEMA_CLOSURE_v7.41"
PARENT_MANIFEST_SHA256 = "CCD74466FA181486C9D130C41FEE8C7F3E820FE86BF069A11E9D48E9D4FB1D36"
PARENT_STATUS = "EX7_P2_P2_DIRECT_OFFICIAL_PREDICATE_AND_BREACH_EXECUTION_COMPLETE"
PREDICATES_SHA256 = "9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
V740_RESULT_SHA256 = "66DFBBBD63C433E2C37A62F550B5F8647826BD5DEBC2A733B486C2BE972CAE49"
V740_CANONICAL_SHA256 = "DAE833800EEA23F95A5E4406B42AEDBCCC86B88E275F0A11D2938F88E0F6A428"
V740_RAW_SHA256 = "46D387ABB92E3EB0B483DC7378E305AEF9AA1050677D57F7F851E975763D550B"
REQUIRED_PARENT = {"ex7_v7_40_parent_verification.csv","ex7_v7_40_execution_preflight.json","ex7_v7_40_raw_results.jsonl","ex7_v7_40_canonical_results.csv","ex7_v7_40_trace_reuse_disclosure.csv","ex7_v7_40_summary.json","ex7_v7_40_claim_boundary.json","ex7_v7_40_result.json","ex7_v7_40_binding.json","ex7_p2_p2_direct_official_predicate_breach_execution_v7_40.py","predicates.py"}


def sha(p: Path) -> str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''): h.update(b)
    return h.hexdigest().upper()
def th(s: str) -> str: return hashlib.sha256(s.encode('utf-8')).hexdigest().upper()
def loadj(p: Path): return json.loads(p.read_text(encoding='utf-8-sig'))
def loadc(p: Path):
    with p.open('r',encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def writej(p: Path,v: Any): p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n',encoding='utf-8',newline='\n')
def writec(p: Path,rows: list[dict[str,Any]],fields: list[str]):
    with p.open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def seg(src: str,n: ast.AST) -> str: return ast.get_source_segment(src,n) or ast.unparse(n)
def index_manifest(p: Path):
    out={}
    for r in loadc(p):
        n=r['artifact'].strip()
        if n in out and any(out[n][k].strip()!=r[k].strip() for k in ('size_bytes','sha256','source_path')): raise ValueError('conflicting duplicate '+n)
        out.setdefault(n,r)
    miss=REQUIRED_PARENT-set(out)
    if miss: raise ValueError(f'missing v7.40 artifacts: {sorted(miss)}')
    return out
def verify(r):
    p=Path(r['source_path']);e=p.is_file();s=p.stat().st_size if e else None;d=sha(p) if e else None;es=int(r['size_bytes']);ed=r['sha256'].upper()
    return {'artifact':r['artifact'],'path':str(p),'exists':e,'expected_size_bytes':es,'observed_size_bytes':s,'size_match':e and s==es,'expected_sha256':ed,'observed_sha256':d,'sha256_match':e and d==ed,'passed':e and s==es and d==ed}
def function(tree,name):
    found=[n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name]
    if len(found)!=1: raise ValueError(f'expected one function {name}, found {len(found)}')
    return found[0]
def root_name(n):
    while isinstance(n,(ast.Attribute,ast.Subscript)): n=n.value
    return n.id if isinstance(n,ast.Name) else None
def literal_key(slice_node):
    return slice_node.value if isinstance(slice_node,ast.Constant) and isinstance(slice_node.value,str) else None
def enclosing_conditions(fn,node):
    parents={}
    for p in ast.walk(fn):
        for c in ast.iter_child_nodes(p): parents[c]=p
    cond=[];cur=node
    while cur in parents:
        cur=parents[cur]
        if isinstance(cur,ast.If): cond.append(seg(SOURCES['predicates'][1],cur.test))
        elif isinstance(cur,(ast.For,ast.comprehension)): cond.append('LOOP:'+seg(SOURCES['predicates'][1],cur.iter))
    return list(reversed(cond))
def direct_access_rows(fn,src):
    rows=[]
    for n in ast.walk(fn):
        if isinstance(n,ast.Subscript):
            key=literal_key(n.slice)
            if key:
                rows.append({'field_name':key,'access_kind':'DIRECT_INDEX','base_expression':seg(src,n.value),'base_root_name':root_name(n.value),'source_function':fn.name,'source_line':n.lineno,'source_end_line':n.end_lineno,'source_expression':seg(src,n),'source_expression_sha256':th(seg(src,n)),'conditions_json':'[]','absence_behavior':'KEYERROR_IF_REACHED','accepted_type':'SOURCE_REVIEW_REQUIRED','canonical_value_domain':'SOURCE_REVIEW_REQUIRED','environment_default':'SOURCE_REVIEW_REQUIRED'})
        elif isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='get' and n.args and isinstance(n.args[0],ast.Constant) and isinstance(n.args[0].value,str):
            default=seg(src,n.args[1]) if len(n.args)>1 else 'None'
            rows.append({'field_name':n.args[0].value,'access_kind':'GET','base_expression':seg(src,n.func.value),'base_root_name':root_name(n.func.value),'source_function':fn.name,'source_line':n.lineno,'source_end_line':n.end_lineno,'source_expression':seg(src,n),'source_expression_sha256':th(seg(src,n)),'conditions_json':'[]','absence_behavior':'DEFAULT:'+default,'accepted_type':'SOURCE_REVIEW_REQUIRED','canonical_value_domain':'SOURCE_REVIEW_REQUIRED','environment_default':default})
    # add enclosing conditions with independent parent traversal
    parents={}
    for p in ast.walk(fn):
        for c in ast.iter_child_nodes(p):parents[c]=p
    for row in rows:
        candidates=[n for n in ast.walk(fn) if getattr(n,'lineno',None)==row['source_line'] and seg(src,n)==row['source_expression']]
        if candidates:
            cond=[];cur=candidates[0]
            while cur in parents:
                cur=parents[cur]
                if isinstance(cur,ast.If):cond.append(seg(src,cur.test))
                elif isinstance(cur,ast.For):cond.append('FOR '+seg(src,cur.target)+' IN '+seg(src,cur.iter))
            row['conditions_json']=json.dumps(list(reversed(cond)),sort_keys=True)
    return rows
def class_fields(tree,src,class_name):
    out=[]
    cls=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==class_name]
    if not cls:return out
    for n in cls[0].body:
        if isinstance(n,ast.AnnAssign) and isinstance(n.target,ast.Name):
            out.append({'field_name':n.target.id,'annotation':seg(src,n.annotation),'default_expression':seg(src,n.value) if n.value else None,'required_constructor_field':n.value is None,'source_line':n.lineno,'source_expression_sha256':th(seg(src,n))})
    return out
def call_keyword_rows(tree,src,call_name):
    out=[]
    for n in ast.walk(tree):
        if isinstance(n,ast.Call):
            called=seg(src,n.func)
            if called.endswith(call_name):
                for kw in n.keywords:
                    if kw.arg:
                        out.append({'constructor':called,'field_name':kw.arg,'value_expression':seg(src,kw.value),'source_line':kw.value.lineno,'source_expression_sha256':th(seg(src,kw.value))})
    return out
def find_string_domains(paths):
    rows=[]
    for p in paths:
        src=p.read_text(encoding='utf-8');tree=ast.parse(src)
        for n in ast.walk(tree):
            if isinstance(n,ast.Constant) and isinstance(n.value,str) and n.value in {'NONE','READ','EXEC','SHARE','WRITE'}:
                rows.append({'source_file':str(p),'source_sha256':sha(p),'value':n.value,'source_line':n.lineno,'context':seg(src,n.parent) if hasattr(n,'parent') else seg(src,n)})
    return rows

def main():
    ap=argparse.ArgumentParser(description=VERSION)
    ap.add_argument('--v7-40-manifest',required=True);ap.add_argument('--v7-40-binding',required=True)
    ap.add_argument('--predicates-source',required=True);ap.add_argument('--sandbox-source',required=True);ap.add_argument('--trace-source',required=True);ap.add_argument('--api-source',required=True);ap.add_argument('--cli-test-source',required=True)
    ap.add_argument('--tools-root');ap.add_argument('--out-root',required=True);a=ap.parse_args()
    runner=Path(__file__).resolve();pm=Path(a.v7_40_manifest);pb=Path(a.v7_40_binding);out=Path(a.out_root)
    source_paths={'predicates':Path(a.predicates_source).resolve(),'sandbox':Path(a.sandbox_source).resolve(),'trace':Path(a.trace_source).resolve(),'api':Path(a.api_source).resolve(),'cli_test':Path(a.cli_test_source).resolve()}
    if out.exists():raise FileExistsError(f'Refusing to overwrite {out}')
    for p in [runner,pm,pb,*source_paths.values()]:
        if not p.is_file():raise FileNotFoundError(p)
    if sha(pm)!=PARENT_MANIFEST_SHA256:raise ValueError('v7.40 manifest mismatch')
    ext=loadj(pb)
    if ext.get('manifest_sha256')!=PARENT_MANIFEST_SHA256 or ext.get('status')!=PARENT_STATUS:raise ValueError('v7.40 binding mismatch')
    idx=index_manifest(pm);checks=[verify(idx[n]) for n in sorted(REQUIRED_PARENT)]
    if any(not r['passed'] for r in checks):raise ValueError('v7.40 parent verification failed')
    if idx['ex7_v7_40_result.json']['sha256'].upper()!=V740_RESULT_SHA256 or idx['ex7_v7_40_canonical_results.csv']['sha256'].upper()!=V740_CANONICAL_SHA256 or idx['ex7_v7_40_raw_results.jsonl']['sha256'].upper()!=V740_RAW_SHA256:raise ValueError('v7.40 result identities mismatch')
    if sha(source_paths['predicates'])!=PREDICATES_SHA256:raise ValueError('predicates.py mismatch')
    global SOURCES;SOURCES={}
    for k,p in source_paths.items():
        src=p.read_text(encoding='utf-8');SOURCES[k]=(ast.parse(src),src,p)
    eval_fn=function(SOURCES['predicates'][0],'eval_predicates');eval_text=seg(SOURCES['predicates'][1],eval_fn)
    access=direct_access_rows(eval_fn,SOURCES['predicates'][1])
    direct=[r for r in access if r['access_kind']=='DIRECT_INDEX']
    # canonical ToolEvent schema and construction/export evidence
    tool_fields=class_fields(SOURCES['trace'][0],SOURCES['trace'][1],'ToolEvent')
    constructors=call_keyword_rows(SOURCES['sandbox'][0],SOURCES['sandbox'][1],'ToolEvent')
    export_fn=function(SOURCES['sandbox'][0],'export_trace_dict');export_text=seg(SOURCES['sandbox'][1],export_fn)
    sandbox_blocks=[]
    for name in ('interact','_record_failed_tool_attempt','export_trace_dict'):
        fn=function(SOURCES['sandbox'][0],name);txt=seg(SOURCES['sandbox'][1],fn);sandbox_blocks.append({'source_file':str(source_paths['sandbox']),'function':name,'line_start':fn.lineno,'line_end':fn.end_lineno,'source_sha256':th(txt),'source':txt})
    blocks=[{'source_file':str(source_paths['predicates']),'function':'eval_predicates','line_start':eval_fn.lineno,'line_end':eval_fn.end_lineno,'source_sha256':th(eval_text),'source':eval_text},{'source_file':str(source_paths['sandbox']),'function':'export_trace_dict','line_start':export_fn.lineno,'line_end':export_fn.end_lineno,'source_sha256':th(export_text),'source':export_text},*sandbox_blocks]
    # infer canonical fields only from ToolEvent dataclass + export mapping + constructors
    export_fields=sorted(set(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*:',export_text)))
    dataclass_names={r['field_name'] for r in tool_fields};constructor_names={r['field_name'] for r in constructors};canonical=sorted(dataclass_names & constructor_names & set(export_fields))
    # side_effect findings strictly evidenced
    se_field=next((r for r in tool_fields if r['field_name']=='side_effect'),None)
    se_direct=[r for r in direct if r['field_name']=='side_effect']
    se_ctor=[r for r in constructors if r['field_name']=='side_effect']
    tools_files=[]
    if a.tools_root:
        tr=Path(a.tools_root).resolve()
        if not tr.is_dir():raise NotADirectoryError(tr)
        tools_files=sorted(tr.rglob('*.py'))
    literal_rows=[]
    inspect_files=[source_paths['predicates'],source_paths['sandbox'],source_paths['trace'],source_paths['api'],source_paths['cli_test'],*tools_files]
    for p in inspect_files:
        src=p.read_text(encoding='utf-8');tree=ast.parse(src)
        parents={}
        for par in ast.walk(tree):
            for ch in ast.iter_child_nodes(par):parents[ch]=par
        for n in ast.walk(tree):
            if isinstance(n,ast.Constant) and isinstance(n.value,str) and n.value in {'NONE','READ','EXEC','SHARE','WRITE'}:
                par=parents.get(n);literal_rows.append({'source_file':str(p),'source_sha256':sha(p),'value':n.value,'source_line':n.lineno,'context':seg(src,par) if par else seg(src,n),'context_sha256':th(seg(src,par) if par else seg(src,n))})
    values=sorted({r['value'] for r in literal_rows})
    side_effect_finding={
      'field_required_in_canonical_ToolEvent_constructor':bool(se_field and se_field['required_constructor_field']),
      'eval_predicates_direct_index_count':len(se_direct),
      'absence_raises_if_reached':bool(se_direct),
      'sandbox_success_value_expression':sorted({r['value_expression'] for r in se_ctor if 'spec.side_effect' in r['value_expression']}),
      'sandbox_unknown_tool_value_expression':sorted({r['value_expression'] for r in se_ctor if r['value_expression'] in {'"NONE"',"'NONE'"}}),
      'observed_literal_domain_in_inspected_sources':values,
      'canonical_neutral_value':'NONE' if any(r['value']=='NONE' and Path(r['source_file'])==source_paths['sandbox'] for r in literal_rows) else None,
      'neutral_value_basis':'Sandbox unknown-tool failed-event construction' if any(r['value']=='NONE' and Path(r['source_file'])==source_paths['sandbox'] for r in literal_rows) else 'NOT_ESTABLISHED',
      'tool_specific_fs_read_value':'READ' if any(r['value']=='READ' for r in literal_rows) else None,
      'tool_specific_http_post_value':'SHARE' if any(r['value']=='SHARE' for r in literal_rows) else None,
      'tool_specific_values_source_complete':bool(tools_files),
    }
    # schema row qualification
    for r in access:
        fld=r['field_name']
        match=next((x for x in tool_fields if x['field_name']==fld),None)
        if match:
            r['accepted_type']=match['annotation'];r['environment_default']=match['default_expression'] if match['default_expression'] is not None else 'NO_DATACLASS_DEFAULT'
        if fld=='side_effect':r['canonical_value_domain']=json.dumps(values);r['environment_default']='spec.side_effect; unknown tool uses NONE'
        elif fld=='source':r['canonical_value_domain']='user|web|email|file|tool per ToolEvent comment; exact runtime values source-dependent'
        elif fld=='name':r['canonical_value_domain']='tool name string'
    now=datetime.now(timezone.utc).isoformat();out.mkdir(parents=True)
    P={'verify':out/'ex7_v7_41_parent_verification.csv','sources':out/'ex7_v7_41_source_inventory.csv','access':out/'ex7_v7_41_eval_event_access_matrix.csv','fields':out/'ex7_v7_41_canonical_tool_event_fields.csv','constructors':out/'ex7_v7_41_sandbox_tool_event_construction.csv','values':out/'ex7_v7_41_side_effect_value_evidence.csv','blocks':out/'ex7_v7_41_exact_source_blocks.csv','finding':out/'ex7_v7_41_schema_findings.json','claims':out/'ex7_v7_41_claim_boundary.json','result':out/'ex7_v7_41_result.json','binding':out/'ex7_v7_41_binding.json','manifest':out/'ex7_v7_41_manifest.csv','external':out/'ex7_v7_41_manifest_external_binding.json'}
    writec(P['verify'],checks,list(checks[0]));source_rows=[{'label':k,'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p),'ast_parse':'PASS'} for k,p in source_paths.items()]+[{'label':'tool_source','path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p),'ast_parse':'PASS'} for p in tools_files];writec(P['sources'],source_rows,['label','path','size_bytes','sha256','ast_parse'])
    writec(P['access'],access,['field_name','access_kind','base_expression','base_root_name','source_function','source_line','source_end_line','source_expression','source_expression_sha256','conditions_json','absence_behavior','accepted_type','canonical_value_domain','environment_default'])
    writec(P['fields'],tool_fields,['field_name','annotation','default_expression','required_constructor_field','source_line','source_expression_sha256']);writec(P['constructors'],constructors,['constructor','field_name','value_expression','source_line','source_expression_sha256']);writec(P['values'],literal_rows,['source_file','source_sha256','value','source_line','context','context_sha256']);writec(P['blocks'],blocks,['source_file','function','line_start','line_end','source_sha256','source'])
    findings={'version':VERSION,'created_at_utc':now,'canonical_tool_event_fields':canonical,'tool_event_dataclass_fields':sorted(dataclass_names),'sandbox_export_fields':export_fields,'eval_predicates_direct_index_fields':sorted(set(r['field_name'] for r in direct)),'eval_predicates_get_fields':sorted(set(r['field_name'] for r in access if r['access_kind']=='GET')),'side_effect':side_effect_finding,'repair_authorization':False,'repaired_fixture_construction':False,'runtime_execution':False,'interpretation':'Full public evaluator schema closure only'};writej(P['finding'],findings)
    writej(P['claims'],{'allowed':['frozen source identities','direct-index versus get access','canonical ToolEvent fields','Sandbox construction and export evidence','source-supported side_effect domain and neutral representation'],'prohibited':['repaired trace validity','predicate result','breach result','real lineage','guardrail effectiveness','policy superiority','hosted parity'],'no_trace_construction':True,'no_runtime_execution':True})
    status='EX7_P2_P2R0_FULL_EVALUATOR_EVENT_SCHEMA_CLOSURE_COMPLETE' if se_field and se_direct and 'side_effect' in canonical else 'EX7_P2_P2R0_SCHEMA_CLOSURE_INCOMPLETE'
    result={'version':VERSION,'created_at_utc':now,'status':status,'classification':'FULL_PUBLIC_EVALUATOR_EVENT_SCHEMA_FROZEN_REPAIR_AND_RUNTIME_WITHHELD','required_parent_artifacts_verified':len(checks),'source_files_verified':len(source_rows),'eval_direct_index_access_count':len(direct),'eval_get_access_count':len(access)-len(direct),'canonical_tool_event_field_count':len(canonical),'side_effect_required':bool(se_field and se_field['required_constructor_field']),'side_effect_absence_raises_if_reached':bool(se_direct),'side_effect_observed_value_domain':values,'canonical_neutral_side_effect':side_effect_finding['canonical_neutral_value'],'neutral_value_basis':side_effect_finding['neutral_value_basis'],'tool_specific_value_evidence_complete':bool(tools_files),'predicates_imported':False,'traces_constructed':False,'eval_predicates_executed':False,'is_breach_executed':False,'v7_40_modified':False,'harness_trick':'NOT_DEMONSTRATED','security_finding':'INTERFACE_SCHEMA_ONLY_NO_RUNTIME_SECURITY_EFFECT','next_gate':'EX7_P2_P1_R1_REPAIRED_TRACE_MATRIX_FREEZE' if status.endswith('COMPLETE') else 'ADDITIONAL_SOURCE_CLOSURE_REQUIRED'};writej(P['result'],result)
    writej(P['binding'],{'version':VERSION,'created_at_utc':now,'parent_manifest':{'path':str(pm),'size_bytes':pm.stat().st_size,'sha256':sha(pm)},'parent_binding':{'path':str(pb),'size_bytes':pb.stat().st_size,'sha256':sha(pb)},'sources':source_rows,'runner':{'path':str(runner),'size_bytes':runner.stat().st_size,'sha256':sha(runner)},'parent_artifacts_modified':False,'v7_40_modified':False,'python':sys.version,'platform':platform.platform()})
    gen=['verify','sources','access','fields','constructors','values','blocks','finding','claims','result','binding'];mr=[{'artifact':P[k].name,'role':'DERIVED_EX7_P2_P2R0_SCHEMA_CLOSURE','size_bytes':P[k].stat().st_size,'sha256':sha(P[k]),'source_path':str(P[k])} for k in gen]
    for p,role in [(runner,'CURRENT_RUNNER'),(pm,'SOURCE_OR_PARENT'),(pb,'SOURCE_OR_PARENT'),*[(p,'AUTHORITATIVE_SOURCE') for p in source_paths.values()],*[(p,'TOOL_SOURCE') for p in tools_files]]:mr.append({'artifact':p.name,'role':role,'size_bytes':p.stat().st_size,'sha256':sha(p),'source_path':str(p)})
    for r in checks:mr.append({'artifact':r['artifact'],'role':'VERIFIED_PARENT_EVIDENCE','size_bytes':r['observed_size_bytes'],'sha256':r['observed_sha256'],'source_path':r['path']})
    writec(P['manifest'],mr,['artifact','role','size_bytes','sha256','source_path']);external={'version':VERSION,'created_at_utc':now,'manifest_filename':P['manifest'].name,'manifest_size_bytes':P['manifest'].stat().st_size,'manifest_sha256':sha(P['manifest']),'status':status,'classification':result['classification'],'parent_v7_40_manifest_sha256':PARENT_MANIFEST_SHA256,'predicates_sha256':PREDICATES_SHA256,'runner_sha256':sha(runner),'canonical_tool_event_field_count':len(canonical),'side_effect_required':result['side_effect_required'],'canonical_neutral_side_effect':result['canonical_neutral_side_effect'],'tool_specific_value_evidence_complete':bool(tools_files)};writej(P['external'],external)
    print(json.dumps({'status':status,'verified_parent_artifacts':len(checks),'source_files_verified':len(source_rows),'direct_index_fields':sorted(set(r['field_name'] for r in direct)),'canonical_tool_event_fields':canonical,'side_effect':side_effect_finding,'runner_sha256':sha(runner),'manifest_sha256':external['manifest_sha256'],'output_directory':str(out)},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
