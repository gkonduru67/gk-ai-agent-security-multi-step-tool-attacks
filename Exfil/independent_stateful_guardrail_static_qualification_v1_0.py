#!/usr/bin/env python3
"""Independent stateful EXFILTRATION guardrail static qualification v1.0.

Read-only, AST-based independent qualification of the frozen aicomp_sdk_exfil
implementation. Recomputes all evidence/source identities, resolves imports,
checks package cycles, hook fail-closed flow, ledger integrity, candidate
extraction, guardrail decision branches, and factory shared-instance binding.

No source is modified. Nothing is imported, instantiated, or executed. No SDK,
Sandbox, Gym, model, tool, fs.read, http.post, predicate, breach, thread, or
external effect is invoked.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="INDEPENDENT_STATEFUL_GUARDRAIL_STATIC_QUALIFICATION_v1.0"
PARENT_VERSION="EXFIL_STATEFUL_GUARDRAIL_IMPLEMENTATION_AND_IDENTITY_FREEZE_v1.0"
PARENT_STATUS="EXFIL_STATEFUL_GUARDRAIL_IMPLEMENTATION_AND_IDENTITY_FREEZE_COMPLETE_PASS"
PARENT_MANIFEST_SHA="33282BD7F53660C19C8C92BD1120599BD5244FC6076D8335EB6D8DD79D891B5E"
PARENT_RUNNER_SHA="2BD692BA138E25A11067B57BA7901D4C818D60AEEB100368D511FBCE7AFC5640"
PARENT_RESULT_SHA="81901E8344B568B528C6817E9C2DB8C3C098880EE46578114D987B2393AF62C4"
PARENT_CHECKS_SHA="126FEBB1AD7A0DABE7097A75347436BB0824ABB39018B66FD3C924ED84F51198"
PARENT_INVENTORY_SHA="17A637128A0A58F64BD87ADFABD6C5023C8C352FEC2D9A82A10975BB0D53E5F8"
PARENT_CONTRACTS_SHA="2B54018BD6382179448ED1EC5E864364B1ABED2D76DCA7FB97D08BD465CF8DFE"
PARENT_CLAIM_SHA="BD6A1130E8DAC6A88891AF757418563FD1152D8880A5F0C085C378E21B363013"
PARENT_BINDING_SHA="A0AE3BA00B593FDB627F16735BD42AF2FFABA9A29D7C927A0473F5E0EA4AC3D1"
IMPL={
'__init__.py':(557,'DB60398BBEEAAE411C62FB915F2EAE5C7CDEBA9A2100D278BF2399190ED3094A'),
'successful_read_ledger_v1.py':(4793,'3560FD4B7533C5B9B2622B84B1AD9BEC4A5562C1BBFF4FE06279EC7206DB73A6'),
'trusted_read_outcome_hook_v1.py':(1657,'2B979C6B652358EAC1E0275A16607AD3A4750CC05C3AC64B6861EFC990B051CD'),
'lineage_aware_exfil_guardrail_v1.py':(1619,'0D20934AD62E7191498F795F1D9BFDB008A749CD134A0842582DED1322F5A1DE'),
'integration_factory_v1.py':(1440,'8220A3AF5601BA660AAD7EA8A1F6893646A8DB764C88BA8F859A35C12733C431')}
SDK={
'aicomp_sdk/core/env/sandbox.py':'B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0',
'aicomp_sdk/core/predicates.py':'9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37',
'aicomp_sdk/guardrails/base.py':'EC95F45A9BF4202514725690617C91E88F3F1AE889AC7828D423DAAFEA527708',
'aicomp_sdk/hooks/types.py':'0D3C7B5921749C22CADC5478532C7FE84B86AA90447FEEA8060ACFA9F44D3C7E',
'aicomp_sdk/hooks/registry.py':'5635B45136517CB5B7FBC6BAB6C9440FE7D6D699E484B6D63651AE296D4BB00B'}

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
def defs(t):return {n.name:n for n in t.body if isinstance(n,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef))}
def methods(c):return {n.name:n for n in c.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def src(n):return up(n)
def calls(n,name=None):
    xs=[x for x in ast.walk(n) if isinstance(x,ast.Call)]
    return [x for x in xs if name is None or up(x.func).endswith(name)]
def returns(n):return [x for x in ast.walk(n) if isinstance(x,ast.Return)]
def literals(n):return {x.value for x in ast.walk(n) if isinstance(x,ast.Constant) and isinstance(x.value,str)}
def imported_names(tree):
    rows=[]
    for n in tree.body:
        if isinstance(n,ast.ImportFrom):
            rows.extend({'module':n.module or '','level':n.level,'name':x.name,'alias':x.asname or x.name,'line':n.lineno} for x in n.names)
        elif isinstance(n,ast.Import):rows.extend({'module':x.name,'level':0,'name':'','alias':x.asname or x.name,'line':n.lineno} for x in n.names)
    return rows
def top_symbols(tree):return set(defs(tree))|{x.id for n in tree.body if isinstance(n,(ast.Assign,ast.AnnAssign)) for x in ((n.targets if isinstance(n,ast.Assign) else [n.target])) if isinstance(x,ast.Name)}
def order_line(method,needle):
    xs=[x.lineno for x in ast.walk(method) if needle in up(x)]
    return min(xs) if xs else None

def main(a):
    out=Path(a.output_dir).resolve();require(not out.exists(),f'Refusing overwrite: {out}');out.mkdir(parents=True)
    checks=[]
    try:
        root=Path(a.project_root).resolve();pkg=root/'aicomp_sdk_exfil';require(pkg.is_dir(),f'Missing frozen implementation: {pkg}')
        parent={'result':Path(a.freeze_result).resolve(),'checks':Path(a.freeze_checks).resolve(),'inventory':Path(a.freeze_inventory).resolve(),'contracts':Path(a.freeze_contracts).resolve(),'claim':Path(a.freeze_claim_boundary).resolve(),'binding':Path(a.freeze_binding).resolve(),'external':Path(a.freeze_external_binding).resolve(),'manifest':Path(a.freeze_manifest).resolve(),'runner':Path(a.freeze_runner).resolve()}
        for k,p in parent.items():require(p.is_file(),f'Missing parent {k}: {p}')
        pr=rj(parent['result']);pe=rj(parent['external']);pc=rc(parent['checks'])
        add(checks,'Q-001','parent',pr.get('version')==PARENT_VERSION and pr.get('status')==PARENT_STATUS,pr.get('status'),PARENT_STATUS,'FIXTURE')
        expected=[('manifest',PARENT_MANIFEST_SHA),('runner',PARENT_RUNNER_SHA),('result',PARENT_RESULT_SHA),('checks',PARENT_CHECKS_SHA),('inventory',PARENT_INVENTORY_SHA),('contracts',PARENT_CONTRACTS_SHA),('claim',PARENT_CLAIM_SHA),('binding',PARENT_BINDING_SHA)]
        for i,(k,h) in enumerate(expected,2):add(checks,f'Q-{i:03d}','parent',sha(parent[k])==h,sha(parent[k]),h,'FIXTURE')
        add(checks,'Q-010','parent',len(pc)==33 and all(x['passed']=='True' for x in pc),{'total':len(pc),'passed':sum(x['passed']=='True' for x in pc)},'33/33','EVIDENCE')
        add(checks,'Q-011','parent',pe.get('implementation_identity_established') is True and pe.get('implementation_imported') is False,pe,'identity established; not imported','CLAIM_BOUNDARY')

        actual=sorted(p.name for p in pkg.glob('*.py'))
        add(checks,'Q-020','integrity',actual==sorted(IMPL),actual,sorted(IMPL),'FIXTURE')
        trees={};texts={};idrows=[]
        for name,(size,h) in IMPL.items():
            p=pkg/name;require(p.is_file(),f'Missing {p}');idrows.append({**ident(p),'relative_path':str(p.relative_to(root)),'expected_size':size,'expected_sha256':h,'identity_match':p.stat().st_size==size and sha(p)==h});add(checks,f'Q-{21+len(idrows)-1:03d}','integrity',p.stat().st_size==size and sha(p)==h,ident(p),{'size':size,'sha256':h},'FIXTURE');text=p.read_text(encoding='utf-8');texts[name]=text;trees[name]=ast.parse(text,filename=str(p))
        sdk_trees={};sdk_symbols={};sdkrows=[]
        for rel,h in SDK.items():
            p=root/rel;require(p.is_file(),f'Missing SDK source {p}');ok=sha(p)==h;add(checks,f'Q-{26+len(sdkrows):03d}','sdk_integrity',ok,sha(p),h,'FIXTURE');t=ast.parse(p.read_text(encoding='utf-8'),filename=str(p));sdk_trees[rel]=t;sdk_symbols[rel]=top_symbols(t);sdkrows.append({**ident(p),'relative_path':rel,'expected_sha256':h,'identity_match':ok})

        # Import resolution and cycle graph.
        importrows=[];graph={name:set() for name in IMPL}
        sdk_module_to_rel={'aicomp_sdk.core.predicates':'aicomp_sdk/core/predicates.py','aicomp_sdk.guardrails.base':'aicomp_sdk/guardrails/base.py','aicomp_sdk.hooks.types':'aicomp_sdk/hooks/types.py','aicomp_sdk.hooks.registry':'aicomp_sdk/hooks/registry.py'}
        package_symbols={f'aicomp_sdk_exfil.{n[:-3]}':top_symbols(t) for n,t in trees.items() if n!='__init__.py'}
        for file,t in trees.items():
            for r in imported_names(t):
                module=r['module'];resolved='NOT_ESTABLISHED';public=not r['name'].startswith('_');exists=False
                if r['level']:
                    target=(module.split('.')[-1]+'.py') if module else '__init__.py';graph[file].add(target);exists=target in trees and (not r['name'] or r['name'] in top_symbols(trees[target]));resolved=target
                elif module in sdk_module_to_rel:
                    rel=sdk_module_to_rel[module];exists=(not r['name'] or r['name'] in sdk_symbols[rel]);resolved=rel
                elif module.split('.')[0] in {'dataclasses','hashlib','types','typing','collections'}:exists=True;resolved='PYTHON_STDLIB'
                else:exists=True;resolved='EXTERNAL_OR_PACKAGE'
                importrows.append({'file':file,**r,'resolved_target':resolved,'symbol_exists':exists,'public_symbol':public})
        def cycle():
            seen=set();stack=set()
            def visit(n):
                if n in stack:return True
                if n in seen:return False
                seen.add(n);stack.add(n)
                if any(visit(x) for x in graph.get(n,set()) if x in graph):return True
                stack.remove(n);return False
            return any(visit(n) for n in graph)
        add(checks,'Q-040','imports',all(x['symbol_exists'] for x in importrows),[x for x in importrows if not x['symbol_exists']],'all imported symbols resolve','ADAPTER_PARSE')
        add(checks,'Q-041','imports',all(x['public_symbol'] for x in importrows if x['resolved_target'].startswith('aicomp_sdk/')),[x for x in importrows if not x['public_symbol']],'no private SDK imports','ADAPTER_PARSE')
        add(checks,'Q-042','imports',not cycle(),{k:sorted(v) for k,v in graph.items()},'no package cycle','ADAPTER_PARSE')

        # Hook control-flow semantics.
        hook=defs(trees['trusted_read_outcome_hook_v1.py'])['TrustedReadOutcomeHookV1'];call=methods(hook)['__call__'];hs=src(call)
        append_calls=calls(call,'append_successful_read');append_line=append_calls[0].lineno if len(append_calls)==1 else None
        stage_line=order_line(call,'HookStage.POST_TOOL_CALL');tool_line=order_line(call,'context.tool_name != \'fs.read\'');mapping_line=order_line(call,'isinstance(evidence, Mapping)');ok_line=order_line(call,'evidence.get(\'ok\') is not True');path_line=order_line(call,'is_protected_secret_path');output_line=order_line(call,'isinstance(output, str)')
        guard_order=all(x is not None and x<append_line for x in [stage_line,tool_line,mapping_line,ok_line,path_line,output_line]) if append_line else False
        hooksem={'one_append':len(append_calls)==1,'append_line':append_line,'stage_line':stage_line,'tool_line':tool_line,'mapping_line':mapping_line,'ok_line':ok_line,'path_line':path_line,'output_line':output_line,'error_forwarded':'error_value=evidence.get(\'error\')' in hs,'raw_forwarded':'raw_output=output' in hs}
        add(checks,'Q-050','hook',guard_order,hooksem,'all fail-closed guards dominate append','PROVENANCE')
        add(checks,'Q-051','hook',hooksem['error_forwarded'] and hooksem['raw_forwarded'],hooksem,'error and raw output separately forwarded','SECRET_CAPTURE')
        add(checks,'Q-052','hook','should_block=True' in hs and len(append_calls)==1,hs,'malformed evidence fails closed','ARGUMENT_FIDELITY')

        # Ledger integrity.
        ledger=defs(trees['successful_read_ledger_v1.py'])['SuccessfulReadLedgerV1'];lm=methods(ledger);append=lm['append_successful_read'];restore=lm['restore_state'];snap=lm['snapshot_state'];reset=lm['reset'];aps=src(append);rss=src(restore);sns=src(snap);res=src(reset)
        ledgerrows=[
          ('L-SEQ','append sequence deterministic','sequence = self._next_sequence' in aps and 'self._next_sequence += 1' in aps),
          ('L-COPY','caller args copied','args_copy = dict(tool_args)' in aps and 'MappingProxyType(args_copy)' in aps),
          ('L-RAW','raw output retained and hashed','raw_output' in aps and 'output_digest = _sha256_text(raw_output)' in aps),
          ('L-ID','identity deterministic','identity_material' in aps and '_sha256_text(identity_material)' in aps),
          ('L-SNAP','snapshot complete',all(x in sns for x in ['schema_tag','next_sequence','records','asdict'])),
          ('L-DIGEST','restore digest validates','raw_output_sha256' in rss and '_sha256_text(raw)' in rss and 'digest mismatch' in rss),
          ('L-ORDER','restore sequence validates','expected_sequence' in rss and 'record_sequence' in rss),
          ('L-NEXT','restore next sequence validates','next_sequence != expected_sequence' in rss),
          ('L-RESET','reset initial state','self._records = []' in res and 'self._next_sequence = 1' in res)]
        for i,(rid,statement,ok) in enumerate(ledgerrows,53):add(checks,f'Q-{i:03d}','ledger',ok,statement,True,'REPLAY_ORCHESTRATION' if rid.startswith('L-S') or rid in {'L-DIGEST','L-ORDER','L-NEXT','L-RESET'} else 'PROVENANCE')
        # Identity restoration gap: record_identity is accepted, not recomputed.
        recompute_identity_restore='identity_material' in rss or ('record_identity' in rss and '_sha256_text' in rss)
        add(checks,'Q-062','ledger',recompute_identity_restore,{'restore_source':rss},'record identity recomputed and validated on restore','PROVENANCE')

        # Candidate extraction independent classification.
        secret_fn=defs(trees['successful_read_ledger_v1.py'])['_secret_values'];ss=src(secret_fn)
        candidate={'line_based':'.splitlines()' in ss,'strips_whitespace':'.strip()' in ss,'drops_blank':'not line' in ss,'drops_comments':'startswith(\'#\')' in ss,'adds_full_assignment':'values.add(line)' in ss,'adds_rhs':'partition(\'=\')' in ss,'raw_preserved_elsewhere':'raw_output' in texts['successful_read_ledger_v1.py'],'official_source_equivalent':False,'overmatch_risk':'adds full lines and RHS candidates without calling official extraction helper','undermatch_risk':'line parser may differ from official encoded/structured candidate extraction'}
        add(checks,'Q-063','candidates',candidate['raw_preserved_elsewhere'],candidate,'raw output remains separate','SECRET_CAPTURE')
        add(checks,'Q-064','candidates',candidate['official_source_equivalent'],candidate,'source-equivalent official candidate extraction','PREDICATE')

        # Guardrail matrix by static branches.
        guard=defs(trees['lineage_aware_exfil_guardrail_v1.py'])['LineageAwareExfilGuardrailV1'];decide=methods(guard)['decide'];gs=src(decide);rets=[src(x.value) if x.value else 'None' for x in returns(decide)]
        matrix=[
          {'case':'non_sink_with_inner','established':'payload_arg is None' in gs and 'self._inner.decide' in gs,'decision':'DELEGATE'},
          {'case':'non_sink_without_inner','established':'payload_arg is None' in gs and 'Decision.allow()' in gs,'decision':'ALLOW'},
          {'case':'malformed_tool_args','established':'not isinstance(tool_args, Mapping)' in gs and 'Decision.deny(self.REASON_MALFORMED)' in gs,'decision':'DENY'},
          {'case':'sink_missing_payload','established':'payload_arg not in tool_args' in gs and 'Decision.deny(self.REASON_MALFORMED)' in gs,'decision':'DENY'},
          {'case':'sink_empty_ledger','established':'if read_secrets and' in gs,'decision':'DELEGATE_OR_ALLOW'},
          {'case':'sink_matching_value','established':'payload_exfiltrates_secret' in gs and 'Decision.deny(self.REASON_EXFIL)' in gs,'decision':'DENY'},
          {'case':'sink_nonmatching_value','established':gs.count('self._inner.decide')>=2 and gs.count('Decision.allow()')>=2,'decision':'DELEGATE_OR_ALLOW'},
          {'case':'encoded_matching_payload','established':'payload_exfiltrates_secret' in gs,'decision':'OFFICIAL_MATCHER'},
          {'case':'inner_delegation','established':'self._inner is not None' in gs,'decision':'DELEGATE'}]
        add(checks,'Q-065','guardrail',all(x['established'] for x in matrix),[x for x in matrix if not x['established']],'complete decision matrix classified','GUARDRAIL')
        add(checks,'Q-066','guardrail',all('Decision' in r or 'self._inner.decide' in r for r in rets),rets,'ordinary Decision returned on every path','GUARDRAIL')

        # Factory shared binding and public registration signature.
        fac=defs(trees['integration_factory_v1.py'])['ExfilIntegrationFactoryV1'];build=methods(fac)['build'];fs=src(build)
        same='ledger = SuccessfulReadLedgerV1()' in fs and 'TrustedReadOutcomeHookV1(ledger=ledger)' in fs and 'LineageAwareExfilGuardrailV1(ledger=ledger' in fs
        regcalls=calls(build,'register_hook');regexpr=src(regcalls[0]) if len(regcalls)==1 else ''
        hookreg=defs(sdk_trees['aicomp_sdk/hooks/registry.py']).get('HookRegistry');regmethod=methods(hookreg).get('register_hook') if isinstance(hookreg,ast.ClassDef) else None
        add(checks,'Q-067','factory',same,fs,'one shared ledger expression injected into hook and guardrail','AUTHORIZATION_TRANSPORT')
        add(checks,'Q-068','factory',len(regcalls)==1 and 'HookStage.POST_TOOL_CALL' in regexpr and 'hook' in regexpr,regexpr,'one public POST_TOOL_CALL registration','ROUTING')
        add(checks,'Q-069','factory',regmethod is not None,src(regmethod) if regmethod else 'missing','public HookRegistry.register_hook exists','ADAPTER_PARSE')
        add(checks,'Q-070','factory','@dataclass(frozen=True, slots=True)' in texts['integration_factory_v1.py'] and 'ledger=ledger, hook=hook, guardrail=guardrail' in fs,fs,'immutable bundle returns all shared components','AUTHORIZATION_TRANSPORT')

        failed=[x['check_id'] for x in checks if not x['passed']]
        # Precedence: exact gap classification.
        cats={x['failure_layer'] for x in checks if not x['passed']}
        if 'FIXTURE' in cats:outcome='NOT_ESTABLISHED'
        elif 'ADAPTER_PARSE' in cats:outcome='IMPLEMENTATION_IMPORT_CONTRACT_GAP'
        elif any(x in failed for x in ['Q-050','Q-051','Q-052']):outcome='HOOK_FAIL_CLOSED_GAP'
        elif any(x.startswith('Q-06') and x in failed for x in ['Q-062']):outcome='LEDGER_INTEGRITY_GAP'
        elif 'Q-064' in failed:outcome='CANDIDATE_EXTRACTION_SEMANTIC_GAP'
        elif any(x in failed for x in ['Q-065','Q-066']):outcome='GUARDRAIL_DECISION_MATRIX_GAP'
        elif any(x in failed for x in ['Q-067','Q-068','Q-069','Q-070']):outcome='FACTORY_BINDING_GAP'
        elif not failed:outcome='INDEPENDENT_STATIC_QUALIFICATION_PASS'
        else:outcome='NOT_ESTABLISHED'
        pass_gate=outcome=='INDEPENDENT_STATIC_QUALIFICATION_PASS'
        status='INDEPENDENT_STATEFUL_GUARDRAIL_STATIC_QUALIFICATION_COMPLETE_PASS' if pass_gate else 'INDEPENDENT_STATEFUL_GUARDRAIL_STATIC_QUALIFICATION_COMPLETE_WITH_GAPS'
        claim={'allowed':['independent implementation identity validation','static import graph and public symbol qualification','static hook, ledger, candidate, guardrail, and factory semantic classification','exact gap classification'],'prohibited':['modify implementation or SDK','claim importability from static resolution alone','claim runtime behavior','claim successful fs.read capture','claim http.post denial','claim official candidate parity when not established','claim guardrail effectiveness','claim protected-value lineage','claim real exfiltration prevention']}
        result={'version':VERSION,'created_at_utc':now(),'status':status,'classification':'READ_ONLY_INDEPENDENT_STATIC_SOURCE_QUALIFICATION','parent_verified':True,'checks':{'total':len(checks),'passed':len(checks)-len(failed),'failed':len(failed),'failed_ids':failed},'outcome':outcome,'candidate_extraction':candidate,'guardrail_matrix':matrix,'hook_semantics':hooksem,'readiness':{'controlled_successful_read_ledger_qualification_eligible':pass_gate,'implementation_modification_eligible':False,'controlled_actual_fs_read_eligible':False,'http_sink_eligible':False},'execution_boundaries':{'parent_artifacts_modified':False,'implementation_modified':False,'frozen_aicomp_sdk_modified':False,'implementation_imported':False,'implementation_instantiated':False,'sdk_modules_imported':False,'sdk_modules_executed':False,'Sandbox_instantiated':False,'Gym_executed':False,'real_tools_executed':False,'actual_fs_read_executed':False,'http_sink_executed':False,'predicates_executed':False,'breach_executed':False,'models_used':False,'threads_executed':False,'external_effects_observed':False},'scientific_verdict':{'independent_static_qualification':outcome,'implementation_behavior':'NOT_EVALUATED','actual_source_retrieval':'NOT_EVALUATED','protected_value_lineage':'NOT_ESTABLISHED','guardrail_effectiveness':'NOT_EVALUATED','harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'},'claim_boundary':claim,'next_gate':'CONTROLLED_SUCCESSFUL_FS_READ_LEDGER_QUALIFICATION' if pass_gate else 'STATIC_QUALIFICATION_GAP_REVIEW'}
        o={'result':out/'independent_static_result.json','checks':out/'independent_static_checks.csv','identities':out/'independent_static_identities.csv','sdk':out/'independent_static_sdk_identities.csv','imports':out/'independent_static_imports.csv','hook':out/'independent_static_hook.json','ledger':out/'independent_static_ledger.csv','candidates':out/'independent_static_candidates.json','matrix':out/'independent_static_guardrail_matrix.csv','factory':out/'independent_static_factory.json','claim':out/'independent_static_claim_boundary.json','binding':out/'independent_static_binding.json'}
        wj(o['result'],result);wc(o['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']);wc(o['identities'],idrows,['artifact','relative_path','size_bytes','expected_size','sha256','expected_sha256','identity_match','path']);wc(o['sdk'],sdkrows,['artifact','relative_path','size_bytes','sha256','expected_sha256','identity_match','path']);wc(o['imports'],importrows,['file','module','level','name','alias','line','resolved_target','symbol_exists','public_symbol']);wj(o['hook'],hooksem);wc(o['ledger'],[{'id':x[0],'statement':x[1],'passed':x[2]} for x in ledgerrows],['id','statement','passed']);wj(o['candidates'],candidate);wc(o['matrix'],matrix,['case','established','decision']);wj(o['factory'],{'shared_ledger':same,'registration_expression':regexpr,'bundle_frozen': '@dataclass(frozen=True, slots=True)' in texts['integration_factory_v1.py']});wj(o['claim'],claim);wj(o['binding'],{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'parent':{k:ident(v) for k,v in parent.items()},'implementation':{n:ident(pkg/n) for n in IMPL},'sdk':{r:ident(root/r) for r in SDK},'implementation_modified':False,'frozen_aicomp_sdk_modified':False,'implementation_imported':False,'implementation_instantiated':False})
        rows=[{**ident(p),'role':'INDEPENDENT_STATIC_DERIVED'} for p in o.values()]+[{**ident(p),'role':'INDEPENDENT_STATIC_BOUND_PARENT'} for p in parent.values()]+[{**ident(pkg/n),'role':'INDEPENDENT_STATIC_BOUND_IMPLEMENTATION'} for n in IMPL]+[{**ident(root/r),'role':'INDEPENDENT_STATIC_BOUND_SDK'} for r in SDK]
        mp=out/'independent_static_manifest.csv';wc(mp,rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'independent_static_manifest_external_binding.json';wj(ep,{'version':VERSION,'created_at_utc':now(),'status':status,'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':sha(mp),'runner_sha256':sha(Path(__file__).resolve()),'parent_manifest_sha256':PARENT_MANIFEST_SHA,'checks_total':len(checks),'checks_passed':len(checks)-len(failed),'checks_failed':len(failed),'failed_ids':failed,'outcome':outcome,'implementation_modified':False,'frozen_aicomp_sdk_modified':False,'implementation_imported':False,'controlled_actual_fs_read_eligible':False,'next_gate':result['next_gate']})
        print(json.dumps({'status':status,'checks':f'{len(checks)-len(failed)}/{len(checks)}','failed_ids':failed,'outcome':outcome,'candidate_official_source_equivalent':candidate['official_source_equivalent'],'implementation_modified':False,'frozen_aicomp_sdk_modified':False,'implementation_imported':False,'controlled_actual_fs_read_eligible':False,'manifest_sha256':sha(mp),'next_gate':result['next_gate']},indent=2))
    except Exception as e:
        (out/'INDEPENDENT_STATIC_FAILED.json').write_text(json.dumps({'version':VERSION,'created_at_utc':now(),'status':'INDEPENDENT_STATIC_QUALIFICATION_BLOCKED','error_type':type(e).__name__,'error':str(e),'checks_frozen':checks,'implementation_modified':False,'frozen_aicomp_sdk_modified':False,'implementation_imported':False,'sdk_modules_imported':False,'actual_fs_read_executed':False},indent=2),encoding='utf-8');raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for f in ['freeze-result','freeze-checks','freeze-inventory','freeze-contracts','freeze-claim-boundary','freeze-binding','freeze-external-binding','freeze-manifest','freeze-runner','project-root','output-dir']:p.add_argument('--'+f,required=True)
    return p.parse_args()
if __name__=='__main__':
    try:main(args())
    except Exception as e:print(f'FAILED: {e}',file=sys.stderr);raise SystemExit(1)
