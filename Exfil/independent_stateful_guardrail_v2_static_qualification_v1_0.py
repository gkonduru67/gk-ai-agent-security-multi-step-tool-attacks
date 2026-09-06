#!/usr/bin/env python3
"""Independent stateful guardrail V2 static qualification v1.0.

Read-only AST qualification of frozen aicomp_sdk_exfil_v2. Recomputes evidence,
V2, V1, and SDK identities; resolves imports; checks candidate control-flow,
canonical argument binding, restore integrity, hook/guardrail/factory structure;
and writes inert boundary fixture specifications. It imports and executes none of
the inspected modules or functions and modifies no inspected source.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "INDEPENDENT_STATEFUL_GUARDRAIL_V2_STATIC_QUALIFICATION_v1.0"
PARENT_VERSION = "EXFIL_STATEFUL_GUARDRAIL_V2_IMPLEMENTATION_AND_IDENTITY_FREEZE_v1.0"
PARENT_STATUS = "EXFIL_STATEFUL_GUARDRAIL_V2_IMPLEMENTATION_AND_IDENTITY_FREEZE_COMPLETE_PASS"
PARENT = {
 "manifest": "E4012BAEE67A8B93D4B54DEA90415CB4E5A38B4385DC301EF50D9B2E748A9521",
 "runner": "57ABA2580E9A0D3759918CDF27117BE506985DB6FE0087C332A8B30F87ED0813",
 "result": "92F6014BBB113B198836139C08659B864583A88A23E73A2CFA295465DF1941A5",
 "checks": "F95CD23ED414D2A3BC47CCB8CC969B3225954006A0EED71E8684F1EF036314C2",
 "inventory": "26017E2EAE00FF001504DB98377217821740623A72E3AA5C5054496795D4AA8A",
 "official": "2E75F6CDE0957715ED8562AC2BC6A9F9D3B256FFA3CEF1F1850E561B3DF4FE22",
 "matrix": "A8ADE57D772CB81EE668D73174AAC95B705C406FE13C502014B567F0E4257BD5",
 "claim": "67202892872A70B8B7863A6560158A60F4209F3304E40E76CD310780830751F9",
 "binding": "93ACEF679CFE03449E376880F5E86D41EAA9111CE00DC19648E2E769E5ABB9A5",
}
V2 = {
 "__init__.py": (613,"A2FF10622D4323205F04BDAE96B121DF0CF710ABB90F33205A83E94E4812ED06"),
 "successful_read_ledger_v2.py": (6645,"609B22AA7ABD3555B24484E2AF313A5460877BA3C446FBE2978C6136D662857E"),
 "trusted_read_outcome_hook_v2.py": (1534,"424D659F677CC6EEFC2E961B350B4A01D41E356849280F3728FB2F5FA5DB9817"),
 "lineage_aware_exfil_guardrail_v2.py": (1392,"27B938444693B53BF3641CB5E958E5C8946B114D4195E8A6D3C1AB774D42931B"),
 "integration_factory_v2.py": (1337,"436C9111DD48C069DDF6FB655C5E40D9A471E4B59890592222CBF8C871E39224"),
}
V1 = {
 "__init__.py":"DB60398BBEEAAE411C62FB915F2EAE5C7CDEBA9A2100D278BF2399190ED3094A",
 "successful_read_ledger_v1.py":"3560FD4B7533C5B9B2622B84B1AD9BEC4A5562C1BBFF4FE06279EC7206DB73A6",
 "trusted_read_outcome_hook_v1.py":"2B979C6B652358EAC1E0275A16607AD3A4750CC05C3AC64B6861EFC990B051CD",
 "lineage_aware_exfil_guardrail_v1.py":"0D20934AD62E7191498F795F1D9BFDB008A749CD134A0842582DED1322F5A1DE",
 "integration_factory_v1.py":"8220A3AF5601BA660AAD7EA8A1F6893646A8DB764C88BA8F859A35C12733C431",
}
SDK = {
 "aicomp_sdk/core/env/sandbox.py":"B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0",
 "aicomp_sdk/core/predicates.py":"9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37",
 "aicomp_sdk/guardrails/base.py":"EC95F45A9BF4202514725690617C91E88F3F1AE889AC7828D423DAAFEA527708",
 "aicomp_sdk/hooks/types.py":"0D3C7B5921749C22CADC5478532C7FE84B86AA90447FEEA8060ACFA9F44D3C7E",
 "aicomp_sdk/hooks/registry.py":"5635B45136517CB5B7FBC6BAB6C9440FE7D6D699E484B6D63651AE296D4BB00B",
}

def now(): return datetime.now(timezone.utc).isoformat()
def need(x,m):
    if not x: raise ValueError(m)
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''): h.update(b)
    return h.hexdigest().upper()
def identity(p):
    p=Path(p).resolve(); return {"artifact":p.name,"path":str(p),"size_bytes":p.stat().st_size,"sha256":sha(p)}
def read_json(p): return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def read_csv(p):
    with Path(p).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def write_json(p,o):
    with Path(p).open('x',encoding='utf-8',newline='\n') as f: json.dump(o,f,indent=2,sort_keys=True); f.write('\n')
def write_csv(p,rows,fields):
    with Path(p).open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n'); w.writeheader(); w.writerows(rows)
def add(rows,i,c,ok,observed,expected,layer): rows.append({"check_id":i,"category":c,"passed":bool(ok),"observed":str(observed),"expected":str(expected),"failure_layer":layer})
def unparse(n):
    try:return ast.unparse(n)
    except:return "UNPARSE_FAILED"
def defs(t): return {n.name:n for n in t.body if isinstance(n,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef))}
def methods(c): return {n.name:n for n in c.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def call_nodes(n,name=None):
    xs=[x for x in ast.walk(n) if isinstance(x,ast.Call)]
    return [x for x in xs if name is None or unparse(x.func).endswith(name)]
def min_line(n,token):
    xs=[x.lineno for x in ast.walk(n) if token in unparse(x)]; return min(xs) if xs else None
def import_rows(file,t,trees,sdk_symbols):
    rows=[]
    module_map={"aicomp_sdk.core.predicates":"aicomp_sdk/core/predicates.py","aicomp_sdk.guardrails.base":"aicomp_sdk/guardrails/base.py","aicomp_sdk.hooks.types":"aicomp_sdk/hooks/types.py","aicomp_sdk.hooks.registry":"aicomp_sdk/hooks/registry.py"}
    for n in t.body:
        if isinstance(n,ast.ImportFrom):
            for a in n.names:
                target=""; exists=True
                if n.level:
                    target=((n.module or '').split('.')[-1]+'.py'); exists=target in trees and a.name in defs(trees[target])
                elif (n.module or '') in module_map:
                    target=module_map[n.module]; exists=a.name in sdk_symbols[target]
                else: target="STDLIB_OR_EXTERNAL"
                rows.append({"file":file,"module":n.module or '',"level":n.level,"name":a.name,"resolved_target":target,"symbol_exists":exists,"public_sdk_symbol":not(a.name.startswith('_') and target.startswith('aicomp_sdk/')),"v1_import":'aicomp_sdk_exfil' in (n.module or '') and 'v2' not in (n.module or '')})
        elif isinstance(n,ast.Import):
            for a in n.names: rows.append({"file":file,"module":a.name,"level":0,"name":"","resolved_target":"STDLIB_OR_EXTERNAL","symbol_exists":True,"public_sdk_symbol":True,"v1_import":a.name=='aicomp_sdk_exfil'})
    return rows

def main(a):
    out=Path(a.output_dir).resolve(); need(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    checks=[]
    try:
        root=Path(a.project_root).resolve(); v2root=root/'aicomp_sdk_exfil_v2'; v1root=root/'aicomp_sdk_exfil'; need(v2root.is_dir(),'V2 root missing'); need(v1root.is_dir(),'V1 root missing')
        parent={"result":Path(a.v2_result).resolve(),"checks":Path(a.v2_checks).resolve(),"inventory":Path(a.v2_inventory).resolve(),"official":Path(a.v2_official_contract).resolve(),"matrix":Path(a.v2_equivalence_matrix).resolve(),"claim":Path(a.v2_claim_boundary).resolve(),"binding":Path(a.v2_binding).resolve(),"external":Path(a.v2_external_binding).resolve(),"manifest":Path(a.v2_manifest).resolve(),"runner":Path(a.v2_runner).resolve()}
        for k,p in parent.items(): need(p.is_file(),f"Missing parent {k}: {p}")
        pr=read_json(parent['result']); pe=read_json(parent['external']); pc=read_csv(parent['checks'])
        add(checks,'IQ2-001','parent',pr.get('version')==PARENT_VERSION and pr.get('status')==PARENT_STATUS,pr.get('status'),PARENT_STATUS,'FIXTURE')
        for i,(k,h) in enumerate(PARENT.items(),2): add(checks,f'IQ2-{i:03d}','parent',sha(parent[k])==h,sha(parent[k]),h,'FIXTURE')
        add(checks,'IQ2-011','parent',len(pc)==44 and all(x['passed']=='True' for x in pc),{"total":len(pc),"passed":sum(x['passed']=='True' for x in pc)},'44/44','EVIDENCE')
        add(checks,'IQ2-012','parent',pe.get('V2_identity_established') is True and pe.get('V2_imported') is False,pe,'identity established; not imported','CLAIM_BOUNDARY')
        actual=sorted(p.name for p in v2root.glob('*.py')); add(checks,'IQ2-013','identity',actual==sorted(V2),actual,sorted(V2),'FIXTURE')
        trees={}; texts={}; idrows=[]
        for j,(name,(size,h)) in enumerate(V2.items(),14):
            p=v2root/name; need(p.is_file(),f'Missing V2 {name}'); text=p.read_text(encoding='utf-8'); texts[name]=text; trees[name]=ast.parse(text,filename=str(p)); ok=p.stat().st_size==size and sha(p)==h; idrows.append({**identity(p),"relative_path":str(p.relative_to(root)),"expected_size":size,"expected_sha256":h,"match":ok}); add(checks,f'IQ2-{j:03d}','identity',ok,identity(p),{"size":size,"sha256":h},'FIXTURE')
        for j,(name,h) in enumerate(V1.items(),19): add(checks,f'IQ2-{j:03d}','V1_identity',sha(v1root/name)==h,sha(v1root/name),h,'FIXTURE')
        sdk_trees={}; sdk_symbols={}
        for j,(rel,h) in enumerate(SDK.items(),24):
            p=root/rel; need(p.is_file(),f'Missing SDK {rel}'); add(checks,f'IQ2-{j:03d}','SDK_identity',sha(p)==h,sha(p),h,'FIXTURE'); t=ast.parse(p.read_text(encoding='utf-8'),filename=str(p)); sdk_trees[rel]=t; sdk_symbols[rel]=set(defs(t))|{x.id for n in t.body if isinstance(n,(ast.Assign,ast.AnnAssign)) for x in (n.targets if isinstance(n,ast.Assign) else [n.target]) if isinstance(x,ast.Name)}
        imports=[]
        for file,t in trees.items(): imports.extend(import_rows(file,t,trees,sdk_symbols))
        add(checks,'IQ2-029','imports',all(x['symbol_exists'] for x in imports),[x for x in imports if not x['symbol_exists']],'all symbols resolve','ADAPTER_PARSE')
        add(checks,'IQ2-030','imports',all(x['public_sdk_symbol'] for x in imports),[x for x in imports if not x['public_sdk_symbol']],'no private SDK import','ADAPTER_PARSE')
        add(checks,'IQ2-031','imports',not any(x['v1_import'] for x in imports),[x for x in imports if x['v1_import']],'no V1 import','ADAPTER_PARSE')
        graph={n:set() for n in trees}
        for x in imports:
            if x['level'] and x['resolved_target'] in trees: graph[x['file']].add(x['resolved_target'])
        def cyclic():
            seen=set(); active=set()
            def visit(n):
                if n in active:return True
                if n in seen:return False
                seen.add(n);active.add(n)
                if any(visit(x) for x in graph[n]):return True
                active.remove(n);return False
            return any(visit(n) for n in graph)
        add(checks,'IQ2-032','imports',not cyclic(),{k:sorted(v) for k,v in graph.items()},'acyclic package graph','ADAPTER_PARSE')

        ledger=defs(trees['successful_read_ledger_v2.py']); ext=ledger['_secret_values_v2']; records=ledger['SuccessfulReadLedgerV2']; lm=methods(records); append=lm['append_successful_read']; restore=lm['restore_state']; es=unparse(ext); aps=unparse(append); rss=unparse(restore)
        pred=sdk_trees['aicomp_sdk/core/predicates.py']; minval=None; official=None
        for n in pred.body:
            if isinstance(n,(ast.Assign,ast.AnnAssign)):
                targets=n.targets if isinstance(n,ast.Assign) else [n.target]
                if any(isinstance(x,ast.Name) and x.id=='_MIN_SECRET_VALUE_LEN' for x in targets): minval=ast.literal_eval(n.value)
            if isinstance(n,ast.FunctionDef) and n.name=='_extract_secret_values': official=n
        add(checks,'IQ2-033','candidate',minval==6,minval,6,'PREDICATE'); add(checks,'IQ2-034','candidate',official is not None,official.name if official else None,'_extract_secret_values','PREDICATE')
        # AST branch dominance: inspect outer loop body in source order.
        loop=next((n for n in ast.walk(ext) if isinstance(n,ast.For)),None); need(loop,'Candidate loop missing')
        guard=next((n for n in loop.body if isinstance(n,ast.If) and ('not line' in unparse(n.test) or 'startswith' in unparse(n.test))),None)
        assign_if=next((n for n in loop.body if isinstance(n,ast.If) and "'=' in line" in unparse(n.test)),None)
        add(checks,'IQ2-035','candidate',guard is not None and any(isinstance(x,ast.Continue) for x in ast.walk(guard)),unparse(guard) if guard else None,'blank/comment continue dominates additions','PREDICATE')
        full_add=next((x for x in ast.walk(assign_if) if isinstance(x,ast.Call) and unparse(x)=='values.add(line)'),None) if assign_if else None
        rhs_if=next((x for x in ast.walk(assign_if) if isinstance(x,ast.If) and 'len(value) >= OFFICIAL_MIN_SECRET_VALUE_LEN' in unparse(x.test)),None) if assign_if else None
        bare_ok=assign_if is not None and assign_if.orelse and any(isinstance(x,ast.If) and 'len(line) >= OFFICIAL_MIN_SECRET_VALUE_LEN' in unparse(x.test) and any(isinstance(c,ast.Call) and unparse(c)=='values.add(line)' for c in ast.walk(x)) for x in assign_if.orelse)
        add(checks,'IQ2-036','candidate',full_add is not None,unparse(assign_if) if assign_if else None,'full assignment unconditional inside assignment branch','PREDICATE')
        add(checks,'IQ2-037','candidate',rhs_if is not None and any(isinstance(c,ast.Call) and unparse(c)=='values.add(value)' for c in ast.walk(rhs_if)),unparse(rhs_if) if rhs_if else None,'RHS addition dominated by >=6','PREDICATE')
        add(checks,'IQ2-038','candidate',bare_ok,unparse(assign_if.orelse) if assign_if else None,'bare addition dominated by >=6','PREDICATE')
        add(checks,'IQ2-039','candidate','tuple(sorted(values))' in es,es,'ordering-only sorted tuple difference','CLAIM_BOUNDARY')
        fixtures=[
          ('CV2-001','RHS length 5','K=12345'),('CV2-002','RHS length 6','K=123456'),('CV2-003','RHS length 7','K=1234567'),('CV2-004','bare length 5','12345'),('CV2-005','bare length 6','123456'),('CV2-006','bare length 7','1234567'),('CV2-007','blank line','   '),('CV2-008','hash comment','# secret'),('CV2-009','empty RHS','K='),('CV2-010','trimmed RHS','K=  123456  '),('CV2-011','duplicate assignments','K=123456\nK=123456'),('CV2-012','multiple equals','K=A=B=C')]
        fixture_rows=[{"fixture_id":i,"case":c,"input_spec":v,"status":"SPECIFICATION_ONLY_NOT_EXECUTED","expected":"DERIVE_FROM_FROZEN_SOURCE_AT_CONTROLLED_RUNTIME_GATE"} for i,c,v in fixtures]

        # Canonical argument contract.
        canon=ledger['_canonical_args_json_v2']; cs=unparse(canon)
        requirements=['sort_keys=True',"separators=(',', ':')",'ensure_ascii=False','allow_nan=False','dict(args)']
        add(checks,'IQ2-040','canonical_args',all(x in cs for x in requirements),cs,requirements,'ARGUMENT_FIDELITY')
        add(checks,'IQ2-041','canonical_args','except (TypeError, ValueError)' in cs and 'raise ValueError' in cs,cs,'noncanonical values fail closed','ARGUMENT_FIDELITY')
        helper=ledger['_record_identity_v2']; hs=unparse(helper); ordered=['RECORD_TAG_V2','sequence','tool_name','canonical_path','tool_args_digest','output_digest']; positions=[hs.find(x) for x in ordered]
        add(checks,'IQ2-042','restore',all(x>=0 for x in positions) and positions==sorted(positions),hs,ordered,'PROVENANCE')
        app_calls=call_nodes(append,'_record_identity_v2'); res_calls=call_nodes(restore,'_record_identity_v2')
        def kws(c):return [x.arg for x in c.keywords]
        add(checks,'IQ2-043','restore',len(app_calls)==1 and len(res_calls)==1,{"append":len(app_calls),"restore":len(res_calls)},'one identity helper call each','PROVENANCE')
        add(checks,'IQ2-044','restore',len(app_calls)==1 and len(res_calls)==1 and kws(app_calls[0])==kws(res_calls[0])==['sequence','tool_name','canonical_path','tool_args_digest','output_digest'],{"append":kws(app_calls[0]) if app_calls else [],"restore":kws(res_calls[0]) if res_calls else []},'same ordered fields','PROVENANCE')
        restore_require=['args_digest = _tool_args_digest_v2(args_copy)','output_digest = _sha256_text_v2(raw)',"row.get('tool_args_sha256') != args_digest","row.get('raw_output_sha256') != output_digest",'derived = _secret_values_v2(raw)',"tuple(row.get('derived_secret_values') or ()) != derived",'expected_identity = _record_identity_v2',"row.get('record_identity') != expected_identity",'record identity mismatch','derived, expected_identity']
        for j,tok in enumerate(restore_require,45): add(checks,f'IQ2-{j:03d}','restore',tok in rss,tok,True,'PROVENANCE')
        add(checks,'IQ2-055','restore',"str(row.get('record_identity'))" not in rss and 'row.get(\'record_identity\'))' not in rss.split('SuccessfulReadRecordV2')[-1],rss,'untrusted identity not propagated','PROVENANCE')

        # Hook.
        hook=defs(trees['trusted_read_outcome_hook_v2.py'])['TrustedReadOutcomeHookV2']; hcall=methods(hook)['__call__']; append_calls=call_nodes(hcall,'append_successful_read'); aline=append_calls[0].lineno if len(append_calls)==1 else None
        guard_tokens=['HookStage.POST_TOOL_CALL',"context.tool_name != 'fs.read'",'isinstance(evidence, Mapping)',"evidence.get('ok') is not True",'isinstance(args, Mapping)','is_protected_secret_path(path)','isinstance(output, str)']
        guard_lines=[min_line(hcall,t) for t in guard_tokens]
        add(checks,'IQ2-056','hook',aline is not None and all(x is not None and x<aline for x in guard_lines),{"append":aline,"guards":dict(zip(guard_tokens,guard_lines))},'all guards dominate append','ROUTING')
        # Guardrail matrix.
        g=defs(trees['lineage_aware_exfil_guardrail_v2.py'])['LineageAwareExfilGuardrailV2']; decide=methods(g)['decide']; gs=unparse(decide)
        matrix=[('non_sink_inner','payload_arg is None' in gs and 'self._inner.decide' in gs),('non_sink_no_inner','Decision.allow()' in gs),('malformed_args','not isinstance(tool_args, Mapping)' in gs and 'Decision.deny' in gs),('missing_payload','payload_arg not in tool_args' in gs),('empty_ledger','if secrets and' in gs),('matching_payload','payload_exfiltrates_secret' in gs and 'Decision.deny' in gs),('nonmatching_payload',gs.count('Decision.allow()')>=2),('inner_delegate',gs.count('self._inner.decide')>=2)]
        add(checks,'IQ2-057','guardrail',all(x[1] for x in matrix),[x for x in matrix if not x[1]],'complete static matrix','GUARDRAIL')
        # Factory.
        fac=defs(trees['integration_factory_v2.py'])['ExfilIntegrationFactoryV2']; build=methods(fac)['build']; fs=unparse(build)
        shared='ledger = SuccessfulReadLedgerV2()' in fs and 'TrustedReadOutcomeHookV2(ledger=ledger)' in fs and 'LineageAwareExfilGuardrailV2(ledger=ledger' in fs
        add(checks,'IQ2-058','factory',shared,fs,'one shared V2 ledger','AUTHORIZATION_TRANSPORT')
        add(checks,'IQ2-059','factory','HookStage.POST_TOOL_CALL' in fs and len(call_nodes(build,'register_hook'))==1,fs,'one POST_TOOL_CALL registration','ROUTING')
        bundle=defs(trees['integration_factory_v2.py'])['ExfilIntegrationBundleV2']; bs=unparse(bundle)
        add(checks,'IQ2-060','factory',all(x in bs for x in ['SuccessfulReadLedgerV2','TrustedReadOutcomeHookV2','LineageAwareExfilGuardrailV2']) and 'V1' not in bs,bs,'V2-only bundle','AUTHORIZATION_TRANSPORT')

        failed=[x['check_id'] for x in checks if not x['passed']]
        if any(x.startswith('IQ2-00') or x in {'IQ2-011','IQ2-012','IQ2-013'} for x in failed): outcome='NOT_ESTABLISHED'
        elif any(x in failed for x in ['IQ2-029','IQ2-030','IQ2-031','IQ2-032']): outcome='V2_IMPORT_CONTRACT_GAP'
        elif any(x in failed for x in ['IQ2-033','IQ2-034','IQ2-035','IQ2-036','IQ2-037','IQ2-038','IQ2-039']): outcome='V2_CANDIDATE_CONTROL_FLOW_GAP'
        elif any(x in failed for x in ['IQ2-040','IQ2-041']): outcome='V2_CANONICAL_ARGUMENT_GAP'
        elif any(x in failed for x in [f'IQ2-{i:03d}' for i in range(42,56)]): outcome='V2_RESTORE_IDENTITY_GAP'
        elif any(x in failed for x in ['IQ2-056','IQ2-057']): outcome='V2_HOOK_OR_GUARDRAIL_GAP'
        elif any(x in failed for x in ['IQ2-058','IQ2-059','IQ2-060']): outcome='V2_FACTORY_BINDING_GAP'
        elif not failed: outcome='INDEPENDENT_V2_STATIC_QUALIFICATION_PASS'
        else: outcome='NOT_ESTABLISHED'
        passed=outcome=='INDEPENDENT_V2_STATIC_QUALIFICATION_PASS'; status='INDEPENDENT_STATEFUL_GUARDRAIL_V2_STATIC_QUALIFICATION_COMPLETE_PASS' if passed else 'INDEPENDENT_STATEFUL_GUARDRAIL_V2_STATIC_QUALIFICATION_COMPLETE_WITH_GAPS'
        claim={"allowed":["independent V2 identity and import-graph qualification","static candidate-control-flow qualification","static canonical-argument and restore-integrity qualification","static hook guardrail factory qualification","non-executed boundary fixture specification"],"prohibited":["claim importability by execution","claim runtime candidate parity","claim runtime restore rejection","claim successful fs.read capture","claim protected-value lineage","claim guardrail effectiveness","claim robust security findings"]}
        result={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"READ_ONLY_INDEPENDENT_V2_STATIC_SOURCE_QUALIFICATION","checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"outcome":outcome,"readiness":{"controlled_successful_fs_read_ledger_qualification_eligible":passed,"controlled_actual_fs_read_eligible":False,"http_sink_eligible":False},"execution_boundaries":{"V2_modified":False,"V1_modified":False,"frozen_aicomp_sdk_modified":False,"V2_imported":False,"V2_instantiated":False,"sdk_modules_imported":False,"sdk_modules_executed":False,"candidate_extraction_executed":False,"restore_executed":False,"predicates_executed":False,"Sandbox_instantiated":False,"Gym_executed":False,"actual_fs_read_executed":False,"http_sink_executed":False,"breach_executed":False,"models_used":False,"threads_executed":False,"external_effects_observed":False},"scientific_verdict":{"V2_identity":"ESTABLISHED" if passed else "NOT_ESTABLISHED","V2_static_contract":"ESTABLISHED" if passed else outcome,"V2_runtime_behavior":"NOT_EVALUATED","protected_value_lineage":"NOT_ESTABLISHED","guardrail_effectiveness":"NOT_EVALUATED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim,"next_gate":"CONTROLLED_SUCCESSFUL_FS_READ_LEDGER_QUALIFICATION" if passed else "V2_STATIC_GAP_REVIEW"}
        outputs={"result":out/'independent_v2_static_result.json',"checks":out/'independent_v2_static_checks.csv',"identities":out/'independent_v2_identities.csv',"imports":out/'independent_v2_imports.csv',"fixtures":out/'independent_v2_boundary_fixture_specs.csv',"guardrail":out/'independent_v2_guardrail_matrix.csv',"claim":out/'independent_v2_claim_boundary.json',"binding":out/'independent_v2_binding.json'}
        write_json(outputs['result'],result); write_csv(outputs['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']); write_csv(outputs['identities'],idrows,['artifact','relative_path','size_bytes','expected_size','sha256','expected_sha256','match','path']); write_csv(outputs['imports'],imports,['file','module','level','name','resolved_target','symbol_exists','public_sdk_symbol','v1_import']); write_csv(outputs['fixtures'],fixture_rows,['fixture_id','case','input_spec','status','expected']); write_csv(outputs['guardrail'],[{"case":x,"established":y} for x,y in matrix],['case','established']); write_json(outputs['claim'],claim); write_json(outputs['binding'],{"version":VERSION,"created_at_utc":now(),"runner":identity(Path(__file__).resolve()),"parent":{k:identity(v) for k,v in parent.items()},"V2":{n:identity(v2root/n) for n in V2},"V1":{n:identity(v1root/n) for n in V1},"SDK":{r:identity(root/r) for r in SDK},"V2_modified":False,"V2_imported":False,"candidate_extraction_executed":False})
        manifest_rows=[{**identity(p),"role":"INDEPENDENT_V2_DERIVED"} for p in outputs.values()]+[{**identity(p),"role":"INDEPENDENT_V2_BOUND_PARENT"} for p in parent.values()]+[{**identity(v2root/n),"role":"INDEPENDENT_V2_BOUND_IMPLEMENTATION"} for n in V2]+[{**identity(v1root/n),"role":"INDEPENDENT_V2_BOUND_V1"} for n in V1]+[{**identity(root/r),"role":"INDEPENDENT_V2_BOUND_SDK"} for r in SDK]
        mp=out/'independent_v2_static_manifest.csv'; write_csv(mp,manifest_rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'independent_v2_static_manifest_external_binding.json'; write_json(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"parent_manifest_sha256":PARENT['manifest'],"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"outcome":outcome,"V2_modified":False,"V2_imported":False,"controlled_actual_fs_read_eligible":False,"next_gate":result['next_gate']})
        print(json.dumps({"status":status,"checks":f"{len(checks)-len(failed)}/{len(checks)}","failed_ids":failed,"outcome":outcome,"manifest_sha256":sha(mp),"controlled_actual_fs_read_eligible":False,"next_gate":result['next_gate']},indent=2))
    except Exception as e:
        (out/'INDEPENDENT_V2_STATIC_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"INDEPENDENT_V2_STATIC_BLOCKED","error_type":type(e).__name__,"error":str(e),"checks_frozen":checks,"V2_modified":False,"V2_imported":False,"candidate_extraction_executed":False,"actual_fs_read_executed":False},indent=2),encoding='utf-8'); raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for x in ['v2-result','v2-checks','v2-inventory','v2-official-contract','v2-equivalence-matrix','v2-claim-boundary','v2-binding','v2-external-binding','v2-manifest','v2-runner','project-root','output-dir']: p.add_argument('--'+x,required=True)
    return p.parse_args()
if __name__=='__main__':
    try: main(args())
    except Exception as e: print(f'FAILED: {e}',file=sys.stderr); raise SystemExit(1)
