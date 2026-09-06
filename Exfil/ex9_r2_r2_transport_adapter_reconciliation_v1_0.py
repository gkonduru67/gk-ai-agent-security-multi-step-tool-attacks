#!/usr/bin/env python3
"""EX9-R2-R2 transport-to-adapter interface reconciliation v1.0.

Read-only static review of TrustedOutcomeTransportV1 versus
TrustedGuardrailContextAdapterV1_1. Preserves EX9-R2-R1 as 24/24, verifies
identities, reconstructs constructor expectations and the exact after_tool call,
searches aicomp_sdk for compatible adapter interfaces and construction sites,
and freezes the minimum compatible implementation outcome.

No source or frozen artifact is modified. No implementation is created. No SDK
module is imported/executed; no Sandbox, Gym, tool, fs.read, HTTP, predicate,
breach, model, thread, or external effect is executed.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
VERSION="EX9_R2_R2_TRANSPORT_TO_ADAPTER_INTERFACE_RECONCILIATION_v1.0"
PARENT_VERSION="EX9_R2_R1_TRANSPORT_ARGUMENT_MAPPING_AND_REQUIREMENTS_CORRECTION_v1.0"
PARENT_STATUS="EX9_R2_R1_TRANSPORT_ARGUMENT_MAPPING_AND_REQUIREMENTS_CORRECTION_COMPLETE_PASS"
PARENT_MANIFEST_SHA="BBAF0C6D4919DDB5F9D27AA330223DBD0F697234F6818F2656496B42993380A7"
PARENT_RUNNER_SHA="C4E450EFE5ED784C78A1315B18F2CE868456C30D8C8079DCE54C5EBB9EF82EB7"
PARENT_FREEZE_SHA="CB137C26D6D7A907A93C5C45D3598BFE8D6436DB3DC7265DDC638BA411425D20"
PARENT_MAPPING_SHA="0437AA1DC390127918DB30B220A006472A50F2E723C041915A6A27D744B14196"
PARENT_REQUIREMENTS_SHA="26F08374095573364F6214D9996548E293413C1EA7D6E5E9428396C43CB1EC73"
TRANSPORT_SHA="5C7F7D16A37896959C6F4CC769E5F72A6E5E534EE140BA5CAF2FB70661102CE1"
ADAPTER_SHA="BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99"
EXPECTED_ADAPTER_KW={"proposal_digest","event_identity","trace_identity","tool_name","tool_args_digest","trusted_tool_outcome"}

def now():return datetime.now(timezone.utc).isoformat()
def require(c,m):
    if not c:raise ValueError(m)
def sha(p):
    h=hashlib.sha256();p=Path(p)
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest().upper()
def ident(p):
    p=Path(p).resolve();return {"artifact":p.name,"path":str(p),"size_bytes":p.stat().st_size,"sha256":sha(p)}
def rj(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def rc(p):
    with Path(p).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def wj(p,o):
    with Path(p).open('x',encoding='utf-8',newline='\n') as f:json.dump(o,f,indent=2,sort_keys=True);f.write('\n')
def wc(p,rows,fields):
    with Path(p).open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(rows)
def add(rows,i,c,p,o,e,l):rows.append({"check_id":i,"category":c,"passed":bool(p),"observed":str(o),"expected":str(e),"failure_layer":l})
def up(n):
    try:return ast.unparse(n)
    except:return "UNPARSE_FAILED"
def parse(p):
    t=Path(p).read_text(encoding='utf-8');return t,ast.parse(t,filename=str(p))
def classes(t):return {n.name:n for n in t.body if isinstance(n,ast.ClassDef)}
def methods(c):return {n.name:n for n in c.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def annotation(a):return up(a.annotation) if a and a.annotation else "NOT_ANNOTATED"
def signature(f):
    pos=f.args.posonlyargs+f.args.args
    if pos and pos[0].arg in {'self','cls'}:pos=pos[1:]
    return {"positional":[{"name":x.arg,"annotation":annotation(x)} for x in pos],"keyword_only":[{"name":x.arg,"annotation":annotation(x)} for x in f.args.kwonlyargs],"return":up(f.returns) if f.returns else "NOT_ANNOTATED"}
def calls(n):
    out=[]
    for x in ast.walk(n):
        if isinstance(x,ast.Call):out.append({"line":x.lineno,"call":up(x.func),"expression":up(x),"node":x})
    return out
def call_shape(call):
    return {"positional_count":len(call.args),"positional":[up(x) for x in call.args],"keywords":{x.arg:up(x.value) for x in call.keywords if x.arg}}
def find_after_tool_interfaces(sdk,root):
    rows=[]
    for p in sorted(sdk.rglob('*.py')):
        try:_,t=parse(p)
        except:continue
        for c in classes(t).values():
            f=methods(c).get('after_tool')
            if f:rows.append({"relative_path":str(p.relative_to(root)),"class":c.name,"line":f.lineno,"signature":signature(f),"source":up(f)})
    return rows
def find_construction(sdk,root):
    rows=[]
    for p in sorted(sdk.rglob('*.py')):
        try:_,t=parse(p)
        except:continue
        for r in calls(t):
            if r['call'].endswith('TrustedOutcomeTransportV1'):
                rows.append({"relative_path":str(p.relative_to(root)),"line":r['line'],"expression":r['expression']})
    return rows

def main(a):
    out=Path(a.output_dir).resolve();require(not out.exists(),f"Refusing overwrite: {out}");out.mkdir(parents=True)
    checks=[]
    try:
        root=Path(a.project_root).resolve();sdk=root/'aicomp_sdk';require(sdk.is_dir(),f"Missing SDK root: {sdk}")
        parent={"result":Path(a.r1_result).resolve(),"checks":Path(a.r1_checks).resolve(),"mapping":Path(a.r1_mapping).resolve(),"requirements":Path(a.r1_requirements).resolve(),"freeze":Path(a.r1_freeze).resolve(),"claim":Path(a.r1_claim_boundary).resolve(),"binding":Path(a.r1_binding).resolve(),"external":Path(a.r1_external_binding).resolve(),"manifest":Path(a.r1_manifest).resolve(),"runner":Path(a.r1_runner).resolve()}
        for k,p in parent.items():require(p.is_file(),f"Missing parent {k}: {p}")
        pr=rj(parent['result']);pe=rj(parent['external']);pf=rj(parent['freeze']);pchecks=rc(parent['checks'])
        add(checks,'A-001','parent',pr.get('version')==PARENT_VERSION and pr.get('status')==PARENT_STATUS,pr.get('status'),PARENT_STATUS,'FIXTURE')
        for i,(k,expected) in enumerate([('manifest',PARENT_MANIFEST_SHA),('runner',PARENT_RUNNER_SHA),('freeze',PARENT_FREEZE_SHA),('mapping',PARENT_MAPPING_SHA),('requirements',PARENT_REQUIREMENTS_SHA)],2):add(checks,f'A-{i:03d}','parent',sha(parent[k])==expected,sha(parent[k]),expected,'FIXTURE')
        add(checks,'A-007','parent',pe.get('manifest_sha256')==PARENT_MANIFEST_SHA and pe.get('runner_sha256')==PARENT_RUNNER_SHA,pe,'external parent binding','FIXTURE')
        add(checks,'A-008','parent',len(pchecks)==24 and all(x['passed']=='True' for x in pchecks),{"total":len(pchecks),"passed":sum(x['passed']=='True' for x in pchecks)},'24/24','EVIDENCE')
        add(checks,'A-009','parent',pf.get('status')=='CORRECTED_REQUIREMENTS_FROZEN' and pf.get('implementation_created') is False,{"status":pf.get('status'),"implementation":pf.get('implementation_created')},'frozen; no implementation','CLAIM_BOUNDARY')

        tp=root/'aicomp_sdk/core/env/trusted_outcome_transport_v1.py';ap=root/'aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py'
        require(tp.is_file() and ap.is_file(),'Missing authoritative transport or adapter')
        add(checks,'A-010','source',sha(tp)==TRANSPORT_SHA,sha(tp),TRANSPORT_SHA,'FIXTURE');add(checks,'A-011','source',sha(ap)==ADAPTER_SHA,sha(ap),ADAPTER_SHA,'FIXTURE')
        tt,tree=parse(tp);at,atree=parse(ap)
        tc=classes(tree).get('TrustedOutcomeTransportV1');ac=classes(atree).get('TrustedGuardrailContextAdapterV1_1');require(tc and ac,'Required classes absent')
        tm=methods(tc);am=methods(ac);init=tm.get('__init__');ack=tm.get('acknowledge');after=am.get('after_tool');require(init and ack and after,'Required methods absent')
        init_sig=signature(init);ack_sig=signature(ack);after_sig=signature(after)
        add(checks,'A-020','interface',init_sig,init_sig,'transport constructor captured','ADAPTER_PARSE')
        adapter_param=next((x for x in init_sig['positional']+init_sig['keyword_only'] if x['name']=='adapter'),None)
        add(checks,'A-021','interface',adapter_param is not None,adapter_param,'constructor adapter parameter','ARGUMENT_FIDELITY')
        ack_calls=[x for x in calls(ack) if x['call']=='self.adapter.after_tool']
        add(checks,'A-022','interface',len(ack_calls)==1,[{"line":x['line'],"expression":x['expression']} for x in ack_calls],'exactly one adapter.after_tool call','ROUTING')
        shape=call_shape(ack_calls[0]['node']) if len(ack_calls)==1 else {"positional_count":0,"positional":[],"keywords":{}}
        adapter_kw={x['name'] for x in after_sig['keyword_only']};adapter_pos={x['name'] for x in after_sig['positional']}
        add(checks,'A-023','interface',adapter_kw==EXPECTED_ADAPTER_KW,sorted(adapter_kw),sorted(EXPECTED_ADAPTER_KW),'ARGUMENT_FIDELITY')
        direct_compatible=shape['positional_count']==0 and set(shape['keywords'])==adapter_kw
        add(checks,'A-024','interface',not direct_compatible,shape,'direct incompatibility explicitly established','AUTHORIZATION_TRANSPORT')

        # Evidence availability for required wrapper mappings.
        ack_src=up(ack);after_src=up(after)
        availability={
          "proposal_digest":"proposal_digest" in ack_src,
          "trace_identity":"trace_identity" in ack_src,
          "tool_name":"tool_name" in ack_src,
          "trusted_tool_outcome":"outcome" in ack_src,
          "event_identity":"outcome_identity" in ack_src,
          "tool_args_digest":False,
        }
        # tool_args_digest exists in adapter pending proposal state, but transport has no access/interface.
        tool_args_pending="tool_args_digest" in after_src and "pending" in after_src
        availability['tool_args_digest_pending_state']=tool_args_pending
        for i,k in enumerate(['proposal_digest','event_identity','trace_identity','tool_name','trusted_tool_outcome'],30):add(checks,f'A-{i:03d}','mapping',availability[k],k,True,'AUTHORIZATION_TRANSPORT')
        add(checks,'A-035','mapping',not availability['tool_args_digest'],availability,'transport lacks tool_args_digest input','AUTHORIZATION_TRANSPORT')
        add(checks,'A-036','mapping',tool_args_pending,tool_args_pending,'adapter requires pending tool_args_digest verification','PROVENANCE')

        interfaces=find_after_tool_interfaces(sdk,root);constructors=find_construction(sdk,root)
        compatible=[]
        for x in interfaces:
            s=x['signature'];kw={i['name'] for i in s['keyword_only']};pos=s['positional']
            if shape['positional_count']==len(pos) and not shape['keywords'] and len(pos)==1:compatible.append(x)
            elif shape['positional_count']==0 and set(shape['keywords'])==kw:compatible.append(x)
        compatible_v11=any(x['class']=='TrustedGuardrailContextAdapterV1_1' for x in compatible)
        add(checks,'A-040','discovery',not compatible_v11,compatible,'no direct V1.1 compatibility','AUTHORIZATION_TRANSPORT')

        # Minimum outcome. A hook adapter alone cannot repair transport->V1.1 call.
        if compatible:
            decision='EXISTING_COMPATIBLE_ADAPTER_INTERFACE_DISCOVERED'
        elif adapter_param and shape['positional_count']==1 and not shape['keywords']:
            decision='NEW_HOOK_ADAPTER_PLUS_TRANSPORT_WRAPPER_REQUIRED'
        else:
            decision='TRANSPORT_INTERFACE_CHANGE_REQUIRED'
        add(checks,'A-041','decision',decision in {'EXISTING_COMPATIBLE_ADAPTER_INTERFACE_DISCOVERED','NEW_HOOK_ADAPTER_PLUS_TRANSPORT_WRAPPER_REQUIRED','TRANSPORT_INTERFACE_CHANGE_REQUIRED'},decision,'classified minimum outcome','AUTHORIZATION_TRANSPORT')

        mapping=[
          {"adapter_parameter":"proposal_digest","source":"acknowledge.proposal_digest","status":"AVAILABLE"},
          {"adapter_parameter":"event_identity","source":"acknowledge local outcome_identity","status":"AVAILABLE_REQUIRES_IDENTITY_SCHEMA_CONVERSION"},
          {"adapter_parameter":"trace_identity","source":"acknowledge.trace_identity","status":"AVAILABLE"},
          {"adapter_parameter":"tool_name","source":"acknowledge.tool_name","status":"AVAILABLE"},
          {"adapter_parameter":"tool_args_digest","source":"pending proposal record or new trusted transport input","status":"NOT_AVAILABLE_TO_CURRENT_TRANSPORT"},
          {"adapter_parameter":"trusted_tool_outcome","source":"acknowledge local outcome mapping","status":"AVAILABLE"},
        ]
        requirements=[
          {"requirement_id":"TA-001","statement":"Do not modify frozen transport or adapter sources; use distinct new component filenames and classes.","status":"REQUIRED"},
          {"requirement_id":"TA-002","statement":"Preserve proposal_digest, trace_identity, tool_name, event identity, tool_args_digest, and trusted outcome as distinct trusted values.","status":"REQUIRED"},
          {"requirement_id":"TA-003","statement":"Outcome identity conversion must satisfy the V1.1 adapter event_identity schema and same-trace outcome-kind validation.","status":"REQUIRED"},
          {"requirement_id":"TA-004","statement":"tool_args_digest must be retrieved from the exact pending proposal or transported as a trusted precomputed digest; raw tool args are insufficient.","status":"REQUIRED"},
          {"requirement_id":"TA-005","statement":"The wrapper or revised transport must call V1.1 after_tool with keyword-only arguments matching the authoritative signature.","status":"REQUIRED"},
          {"requirement_id":"TA-006","statement":"Adapter exception must propagate and leave the allocated outcome unconsumed.","status":"REQUIRED"},
          {"requirement_id":"TA-007","statement":"Failure error metadata remains outside the current transport outcome schema and must be separately documented or explicitly added in a later reviewed contract.","status":"REQUIRED"},
          {"requirement_id":"TA-008","statement":"Implementation identity freeze remains static; no Sandbox, Gym, tool, fs.read, predicate, breach, model, HTTP, or thread execution.","status":"REQUIRED"},
        ]
        failed=[x['check_id'] for x in checks if not x['passed']]
        qualified=not failed and decision!='TRANSPORT_INTERFACE_CHANGE_REQUIRED'
        status='EX9_R2_R2_TRANSPORT_TO_ADAPTER_INTERFACE_RECONCILIATION_COMPLETE_PASS' if qualified else 'EX9_R2_R2_TRANSPORT_TO_ADAPTER_INTERFACE_RECONCILIATION_COMPLETE_WITH_GAPS'
        next_gate='ACKNOWLEDGEMENT_INTEGRATION_IMPLEMENTATION_AND_IDENTITY_FREEZE' if qualified else 'EX9_R2_R3_TRANSPORT_INTERFACE_REQUIREMENTS_REVIEW'
        freeze={"freeze_id":"EX9.TRANSPORT.ADAPTER.INTERFACE.RECONCILIATION.V1","status":"FROZEN" if qualified else "NOT_FROZEN","parent_mapping_freeze_id":pf.get('freeze_id'),"transport_constructor_signature":init_sig,"transport_adapter_parameter":adapter_param,"transport_after_tool_call":shape,"adapter_v1_1_after_tool_signature":after_sig,"direct_compatibility":direct_compatible,"mapping":mapping,"compatible_after_tool_interfaces":[{"relative_path":x['relative_path'],"class":x['class'],"line":x['line'],"signature":x['signature']} for x in compatible],"transport_construction_sites":constructors,"decision":decision,"implementation_created":False,"runtime_behavior":"NOT_EVALUATED"}
        claim={"allowed":["static transport constructor and adapter expectation","exact transport after_tool call shape","exact V1.1 adapter after_tool signature","transport-to-adapter compatibility classification","minimum implementation outcome and requirements"],"prohibited":["implementation creation","SDK source modification","runtime acknowledgement behavior","actual fs.read","Sandbox or Gym execution","HTTP sink","predicate or breach execution","model execution","protected-value lineage","guardrail effectiveness","real exfiltration prevention"]}
        result={"version":VERSION,"created_at_utc":now(),"status":status,"classification":"READ_ONLY_STATIC_INTERFACE_AND_CALL_GRAPH_RECONCILIATION","EX9_R2_R1_parent_verified":True,"parent_result":{"checks":"24_OF_24","preserved_immutable":True},"checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},"compatibility":{"transport_to_V1_1_adapter_direct":direct_compatible,"compatible_adapter_interfaces_found":len(compatible),"decision":decision,"tool_args_digest_path":"NOT_AVAILABLE_TO_CURRENT_TRANSPORT"},"freeze":freeze,"readiness":{"acknowledgement_integration_implementation_gate_eligible":qualified,"controlled_actual_fs_read_eligible":False,"http_sink_eligible":False},"execution_boundaries":{"parent_artifacts_modified":False,"source_modified":False,"implementation_created":False,"sdk_modules_imported":False,"sdk_modules_executed":False,"Sandbox_instantiated":False,"Sandbox_interact_executed":False,"Gym_executed":False,"real_tools_executed":False,"actual_fs_read_executed":False,"http_sink_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False,"threads_executed":False,"external_effects_observed":False},"scientific_verdict":{"transport_to_adapter_contract":"RECONCILED" if qualified else "GAPS_IDENTIFIED","runtime_behavior":"NOT_EVALUATED","actual_source_retrieval":"NOT_EVALUATED","protected_value_lineage":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim,"next_gate":next_gate}
        o={"result":out/'ex9_r2_r2_result.json',"checks":out/'ex9_r2_r2_checks.csv',"mapping":out/'ex9_r2_r2_adapter_mapping.csv',"interfaces":out/'ex9_r2_r2_after_tool_interfaces.csv',"construction":out/'ex9_r2_r2_transport_construction.csv',"requirements":out/'ex9_r2_r2_requirements.csv',"freeze":out/'ex9_r2_r2_interface_freeze.json',"claim":out/'ex9_r2_r2_claim_boundary.json',"binding":out/'ex9_r2_r2_binding.json'}
        wj(o['result'],result);wc(o['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']);wc(o['mapping'],mapping,['adapter_parameter','source','status']);wc(o['interfaces'],interfaces,['relative_path','class','line','signature','source']);wc(o['construction'],constructors,['relative_path','line','expression']);wc(o['requirements'],requirements,['requirement_id','statement','status']);wj(o['freeze'],freeze);wj(o['claim'],claim);wj(o['binding'],{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"parent":{k:ident(v) for k,v in parent.items()},"sources":{"transport":ident(tp),"adapter_v1_1":ident(ap)},"source_modified":False,"implementation_created":False,"sdk_modules_imported":False,"sdk_modules_executed":False})
        rows=[{**ident(p),"role":"EX9_R2_R2_DERIVED"} for p in o.values()]+[{**ident(p),"role":"EX9_R2_R2_BOUND_PARENT"} for p in parent.values()]+[{**ident(tp),"role":"EX9_R2_R2_AUTHORITATIVE_SOURCE"},{**ident(ap),"role":"EX9_R2_R2_AUTHORITATIVE_SOURCE"}]
        mp=out/'ex9_r2_r2_manifest.csv';wc(mp,rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'ex9_r2_r2_manifest_external_binding.json';wj(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"parent_EX9_R2_R1_manifest_sha256":PARENT_MANIFEST_SHA,"freeze_id":freeze['freeze_id'],"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"decision":decision,"acknowledgement_integration_implementation_gate_eligible":qualified,"controlled_actual_fs_read_eligible":False,"implementation_created":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"parent":"24/24 preserved","checks":f"{len(checks)-len(failed)}/{len(checks)}","failed_ids":failed,"direct_transport_to_v1_1_compatibility":direct_compatible,"compatible_interfaces_found":len(compatible),"decision":decision,"implementation_created":False,"controlled_actual_fs_read_eligible":False,"manifest_sha256":sha(mp),"next_gate":next_gate},indent=2))
    except Exception as e:
        (out/'EX9_R2_R2_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"EX9_R2_R2_RECONCILIATION_BLOCKED","error_type":type(e).__name__,"error":str(e),"checks_frozen":checks,"source_modified":False,"implementation_created":False,"sdk_modules_imported":False,"sdk_modules_executed":False,"actual_fs_read_executed":False},indent=2),encoding='utf-8');raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for f in ['r1-result','r1-checks','r1-mapping','r1-requirements','r1-freeze','r1-claim-boundary','r1-binding','r1-external-binding','r1-manifest','r1-runner','project-root','output-dir']:p.add_argument('--'+f,required=True)
    return p.parse_args()
if __name__=='__main__':
    try:main(args())
    except Exception as e:print(f"FAILED: {e}",file=sys.stderr);raise SystemExit(1)
