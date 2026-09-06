#!/usr/bin/env python3
"""EX9-R2-R1 transport mapping and requirements correction v1.0.

Read-only reconciliation of the mechanically passing EX9-R2 requirements freeze
against the authoritative TrustedOutcomeTransportV1.acknowledge signature and
body. The runner preserves EX9-R2 as 38/38, identifies invalid historical
mapping destinations, freezes only destinations present in the actual signature,
and classifies post_hook_output, tool_args, failure metadata, and proposal_digest.

No implementation is created. No SDK module is imported or executed. No
Sandbox, Gym, tool, fs.read, HTTP, predicate, breach logic, model, or thread is
executed. Frozen parent artifacts and SDK sources are never modified.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX9_R2_R1_TRANSPORT_ARGUMENT_MAPPING_AND_REQUIREMENTS_CORRECTION_v1.0"
PARENT_VERSION="EX9_R2_ACKNOWLEDGEMENT_INTEGRATION_REQUIREMENTS_AND_FEASIBILITY_FREEZE_v1.0"
PARENT_STATUS="EX9_R2_ACKNOWLEDGEMENT_INTEGRATION_REQUIREMENTS_AND_FEASIBILITY_FREEZE_COMPLETE_PASS"
PARENT_MANIFEST_SHA="8A4EEC3446A35008C668632B3973803C800AABFCBD82CD0F8F3C422A980D9CB8"
PARENT_RUNNER_SHA="1BE136CC12F00E1D879FBB10D2533D7D53EDC245EA1E5227A4F67E767AD32108"
PARENT_FREEZE_SHA="F57666EC7BE48610EA943DF173C4F01D20DD06C2F1A9F87E93588F0EB1D4CFE3"
PARENT_REQUIREMENTS_SHA="32ECFE00B2FEDC9F3CD029B772895CADF93B99FD1DB2C4CB5459033CE46175FA"
PARENT_CLAIM_SHA="67F98BD5120F2A9F9BDFEC5D99E75BC592CA42E58E9DE535DAAF8A066B03776E"
TRANSPORT_SHA="5C7F7D16A37896959C6F4CC769E5F72A6E5E534EE140BA5CAF2FB70661102CE1"
HOOK_TYPES_REL="aicomp_sdk/hooks/types.py"
TRANSPORT_REL="aicomp_sdk/core/env/trusted_outcome_transport_v1.py"
EXPECTED_PARAMS={"trace_identity","proposal_digest","tool_name","success","canonical_source_path","post_hook_output"}
INVALID_PARENT_DESTINATIONS={"acknowledge.tool_args","acknowledge.raw_output","acknowledge.proposal_identity"}

def now():return datetime.now(timezone.utc).isoformat()
def require(c,m):
    if not c:raise ValueError(m)
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
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
def add(rows,cid,cat,passed,obs,exp,layer):rows.append({"check_id":cid,"category":cat,"passed":bool(passed),"observed":str(obs),"expected":str(exp),"failure_layer":layer})
def up(n):
    try:return ast.unparse(n)
    except:return "UNPARSE_FAILED"
def parse(p):
    text=Path(p).read_text(encoding='utf-8');return text,ast.parse(text,filename=str(p))
def classes(t):return {n.name:n for n in t.body if isinstance(n,ast.ClassDef)}
def methods(c):return {n.name:n for n in c.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def ann(a):return up(a.annotation) if a and a.annotation else "NOT_ANNOTATED"
def sig(f):
    pos=f.args.posonlyargs+f.args.args
    if pos and pos[0].arg in {'self','cls'}:pos=pos[1:]
    return {"positional":[{"name":x.arg,"annotation":ann(x)} for x in pos],"keyword_only":[{"name":x.arg,"annotation":ann(x)} for x in f.args.kwonlyargs],"return_annotation":up(f.returns) if f.returns else "NOT_ANNOTATED"}
def calls(node):
    out=[]
    for n in ast.walk(node):
        if isinstance(n,ast.Call):out.append({"line":n.lineno,"call":up(n.func),"expression":up(n)})
    return out
def subscript_keys(node,name):
    keys=[]
    for n in ast.walk(node):
        if isinstance(n,ast.Subscript) and isinstance(n.value,ast.Name) and n.value.id==name:
            if isinstance(n.slice,ast.Constant) and isinstance(n.slice.value,str):keys.append(n.slice.value)
    return sorted(set(keys))
def attr_uses(node,name):
    return sorted({n.attr for n in ast.walk(node) if isinstance(n,ast.Attribute) and isinstance(n.value,ast.Name) and n.value.id==name})
def name_used(node,name):return any(isinstance(n,ast.Name) and n.id==name for n in ast.walk(node))
def string_values(node):return sorted({n.value for n in ast.walk(node) if isinstance(n,ast.Constant) and isinstance(n.value,str)})
def find_functions_with_token(root,token):
    rows=[]
    for p in sorted(root.rglob('*.py')):
        try:text,tree=parse(p)
        except:continue
        if token not in text:continue
        for f in ast.walk(tree):
            if isinstance(f,(ast.FunctionDef,ast.AsyncFunctionDef)) and token in up(f):
                rows.append({"relative_path":str(p.relative_to(root.parent)),"function":f.name,"line":f.lineno,"source":up(f)})
    return rows

def main(a):
    out=Path(a.output_dir).resolve();require(not out.exists(),f"Refusing overwrite: {out}");out.mkdir(parents=True)
    checks=[];mapping=[];corrections=[]
    try:
        root=Path(a.project_root).resolve();sdk=root/'aicomp_sdk';require(sdk.is_dir(),f"Missing SDK root: {sdk}")
        parent={"result":Path(a.r2_result).resolve(),"checks":Path(a.r2_checks).resolve(),"requirements":Path(a.r2_requirements).resolve(),"freeze":Path(a.r2_freeze).resolve(),"claim":Path(a.r2_claim_boundary).resolve(),"binding":Path(a.r2_binding).resolve(),"external":Path(a.r2_external_binding).resolve(),"manifest":Path(a.r2_manifest).resolve(),"runner":Path(a.r2_runner).resolve()}
        for k,p in parent.items():require(p.is_file(),f"Missing EX9-R2 {k}: {p}")
        pr=rj(parent['result']);pf=rj(parent['freeze']);pe=rj(parent['external']);preqs=rc(parent['requirements']);pchecks=rc(parent['checks'])
        add(checks,'M-001','parent',pr.get('version')==PARENT_VERSION and pr.get('status')==PARENT_STATUS,pr.get('status'),PARENT_STATUS,'FIXTURE')
        add(checks,'M-002','parent',sha(parent['manifest'])==PARENT_MANIFEST_SHA and pe.get('manifest_sha256')==PARENT_MANIFEST_SHA,sha(parent['manifest']),PARENT_MANIFEST_SHA,'FIXTURE')
        add(checks,'M-003','parent',sha(parent['runner'])==PARENT_RUNNER_SHA and pe.get('runner_sha256')==PARENT_RUNNER_SHA,sha(parent['runner']),PARENT_RUNNER_SHA,'FIXTURE')
        add(checks,'M-004','parent',sha(parent['freeze'])==PARENT_FREEZE_SHA,sha(parent['freeze']),PARENT_FREEZE_SHA,'FIXTURE')
        add(checks,'M-005','parent',sha(parent['requirements'])==PARENT_REQUIREMENTS_SHA,sha(parent['requirements']),PARENT_REQUIREMENTS_SHA,'FIXTURE')
        add(checks,'M-006','parent',sha(parent['claim'])==PARENT_CLAIM_SHA,sha(parent['claim']),PARENT_CLAIM_SHA,'FIXTURE')
        add(checks,'M-007','parent',len(pchecks)==38 and all(r['passed']=='True' for r in pchecks),{"rows":len(pchecks),"passed":sum(r['passed']=='True' for r in pchecks)},'38/38 mechanical result','EVIDENCE')
        add(checks,'M-008','parent',pf.get('decision')=='NEW_TRUSTED_HOOK_ADAPTER_REQUIRED' and pf.get('implementation_creation_performed') is False,{"decision":pf.get('decision'),"implementation":pf.get('implementation_creation_performed')},'new adapter; no implementation','CLAIM_BOUNDARY')

        transport=root/TRANSPORT_REL;hook_types=root/HOOK_TYPES_REL
        require(transport.is_file(),f"Missing transport: {transport}");require(hook_types.is_file(),f"Missing hook types: {hook_types}")
        add(checks,'M-010','source',sha(transport)==TRANSPORT_SHA,sha(transport),TRANSPORT_SHA,'FIXTURE')
        ttext,ttree=parse(transport);htext,htree=parse(hook_types)
        add(checks,'M-011','source',True,'transport and hook types parsed','AST PASS','ADAPTER_PARSE')
        tcls=classes(ttree).get('TrustedOutcomeTransportV1');require(tcls is not None,'Missing TrustedOutcomeTransportV1')
        acknowledge=methods(tcls).get('acknowledge');require(acknowledge is not None,'Missing acknowledge')
        signature=sig(acknowledge);kw={x['name'] for x in signature['keyword_only']}
        add(checks,'M-020','signature',kw==EXPECTED_PARAMS,sorted(kw),sorted(EXPECTED_PARAMS),'ARGUMENT_FIDELITY')
        add(checks,'M-021','signature',not signature['positional'],signature['positional'],'no positional params','ARGUMENT_FIDELITY')
        parameter_annotations={x['name']:x['annotation'] for x in signature['keyword_only']}
        body=up(acknowledge);body_calls=calls(acknowledge)

        # Exact post_hook_output contract from annotation and body usage.
        pho_ann=parameter_annotations.get('post_hook_output','NOT_ESTABLISHED')
        pho_keys=subscript_keys(acknowledge,'post_hook_output');pho_attrs=attr_uses(acknowledge,'post_hook_output')
        pho_used=name_used(acknowledge,'post_hook_output')
        pho_forwarded=[r for r in body_calls if 'post_hook_output' in r['expression']]
        if pho_keys or pho_attrs:
            pho_schema='STRUCTURED_ACCESS';pho_content={"subscript_keys":pho_keys,"attributes":pho_attrs}
        elif pho_used:
            pho_schema='OPAQUE_VALUE_PASSTHROUGH';pho_content={"subscript_keys":[],"attributes":[],"forwarded_calls":pho_forwarded}
        else:
            pho_schema='UNUSED_PARAMETER';pho_content={}
        add(checks,'M-022','post_hook_output',pho_ann!='NOT_ESTABLISHED',pho_ann,'explicit annotation','ARGUMENT_FIDELITY')
        add(checks,'M-023','post_hook_output',pho_used,pho_content,'parameter used by acknowledge body','ARGUMENT_FIDELITY')
        add(checks,'M-024','post_hook_output',pho_schema!='UNUSED_PARAMETER',pho_schema,'structured or opaque carrier','ARGUMENT_FIDELITY')

        # Historical invalid destinations must be present in parent and absent from signature.
        historical_dest={r['target'] for r in preqs if r['requirement_type']=='ARGUMENT_MAPPING'}
        invalid_found=INVALID_PARENT_DESTINATIONS & historical_dest
        add(checks,'M-030','correction',invalid_found==INVALID_PARENT_DESTINATIONS,sorted(invalid_found),sorted(INVALID_PARENT_DESTINATIONS),'EVIDENCE')
        add(checks,'M-031','correction',all(x.split('.',1)[1] not in kw for x in INVALID_PARENT_DESTINATIONS),sorted(kw),'invalid destinations absent','ARGUMENT_FIDELITY')
        for x in sorted(INVALID_PARENT_DESTINATIONS):corrections.append({"historical_destination":x,"status":"REMOVED_FROM_CORRECTED_REQUIREMENTS","reason":"ABSENT_FROM_AUTHORITATIVE_ACKNOWLEDGE_SIGNATURE"})

        # Correct destination mapping.
        direct=[
          ('HookContext.tool_name','acknowledge.tool_name','DIRECT'),
          ('HookContext.tool_output','acknowledge.post_hook_output','DIRECT_OPAQUE' if pho_schema=='OPAQUE_VALUE_PASSTHROUGH' else 'DIRECT_STRUCTURED'),
          ('HookContext.context.ok','acknowledge.success','CONTEXT_EXTRACTION'),
          ('trusted ToolEvent.source','acknowledge.canonical_source_path','TRUSTED_ENRICHMENT_REQUIRED'),
          ('trusted trace identity','acknowledge.trace_identity','TRUSTED_ENRICHMENT_REQUIRED'),
          ('trusted proposal digest','acknowledge.proposal_digest','TRUSTED_DERIVATION_REQUIRED'),
        ]
        for src,dst,status in direct:
            exists=dst.split('.',1)[1] in kw
            mapping.append({"source":src,"destination":dst,"status":status if exists else 'NOT_ESTABLISHED',"destination_exists":exists})
        add(checks,'M-040','mapping',all(r['destination_exists'] for r in mapping),mapping,'all corrected destinations exist','ARGUMENT_FIDELITY')

        # tool_args and error are intentionally outside direct transport signature.
        tool_args_used='tool_args' in body or 'tool_args' in string_values(acknowledge)
        error_used='error' in body or 'error' in string_values(acknowledge)
        tool_args_disposition='NOT_REQUIRED_BY_CURRENT_TRANSPORT_INTERFACE_OR_BODY' if not tool_args_used else 'EMBEDDED_OR_REFERENCED_IN_TRANSPORT_BODY'
        error_disposition='NO_SEPARATE_ERROR_PARAMETER;SUCCESS_FALSE_AND_POST_HOOK_OUTPUT_ARE_AVAILABLE' if not error_used else 'ERROR_REFERENCED_IN_TRANSPORT_BODY'
        add(checks,'M-041','mapping',not tool_args_used,tool_args_disposition,'tool_args excluded from current transport','ARGUMENT_FIDELITY')
        add(checks,'M-042','mapping',not error_used,error_disposition,'no separate error destination required','ARGUMENT_FIDELITY')

        # Proposal digest is a caller-provided value; discover existing derivation references.
        proposal_refs=find_functions_with_token(sdk,'proposal_digest')
        digest_ann=parameter_annotations.get('proposal_digest','NOT_ESTABLISHED')
        digest_used=name_used(acknowledge,'proposal_digest')
        digest_disposition='CALLER_PROVIDED_PRECOMPUTED_TRUSTED_DIGEST'
        add(checks,'M-050','proposal_digest',digest_ann!='NOT_ESTABLISHED',digest_ann,'annotated parameter','ARGUMENT_FIDELITY')
        add(checks,'M-051','proposal_digest',digest_used,digest_used,True,'AUTHORIZATION_TRANSPORT')
        add(checks,'M-052','proposal_digest',bool(proposal_refs),[{k:r[k] for k in ['relative_path','function','line']} for r in proposal_refs],'SDK source references establish handling context','PROVENANCE')

        # Compatibility: current transport is sufficient if corrected required destinations exist and opaque/structured output is supported.
        compatible=(kw==EXPECTED_PARAMS and all(r['destination_exists'] for r in mapping) and pho_used and digest_used)
        decision='NEW_TRUSTED_HOOK_ADAPTER_REQUIRED_WITH_CURRENT_TRANSPORT' if compatible else 'TRANSPORT_INTERFACE_CHANGE_REQUIRED'
        add(checks,'M-060','decision',decision in {'NEW_TRUSTED_HOOK_ADAPTER_REQUIRED_WITH_CURRENT_TRANSPORT','TRANSPORT_INTERFACE_CHANGE_REQUIRED'},decision,'classified outcome','AUTHORIZATION_TRANSPORT')

        corrected_requirements=[]
        for src,dst,status in direct:corrected_requirements.append({"requirement_id":"MAP-"+str(len(corrected_requirements)+1).zfill(3),"source":src,"destination":dst,"status":status,"mandatory":True})
        corrected_requirements.extend([
          {"requirement_id":"MAP-007","source":"HookContext.tool_args","destination":"NONE","status":tool_args_disposition,"mandatory":False},
          {"requirement_id":"MAP-008","source":"HookContext.context.error","destination":"NONE","status":error_disposition,"mandatory":False},
          {"requirement_id":"REQ-001","source":"post_hook_output","destination":pho_ann,"status":pho_schema,"mandatory":True},
          {"requirement_id":"REQ-002","source":"proposal_digest","destination":digest_ann,"status":digest_disposition,"mandatory":True},
          {"requirement_id":"REQ-003","source":"implementation","destination":"distinct trusted hook adapter class and filename","status":"REQUIRED","mandatory":True},
          {"requirement_id":"REQ-004","source":"registration","destination":"exactly one POST_TOOL_CALL registration despite append-style registry","status":"REQUIRED","mandatory":True},
          {"requirement_id":"REQ-005","source":"lifecycle","destination":"snapshot, restore, explicit reset ownership, duplicate and replay protection","status":"REQUIRED","mandatory":True},
          {"requirement_id":"REQ-006","source":"atomicity","destination":"allocate/digest/adapter/consume ordering; failed acknowledgement unconsumed","status":"REQUIRED","mandatory":True},
        ])

        failed=[r['check_id'] for r in checks if not r['passed']]
        qualified=not failed and compatible
        status='EX9_R2_R1_TRANSPORT_ARGUMENT_MAPPING_AND_REQUIREMENTS_CORRECTION_COMPLETE_PASS' if qualified else 'EX9_R2_R1_TRANSPORT_ARGUMENT_MAPPING_AND_REQUIREMENTS_CORRECTION_COMPLETE_WITH_GAPS'
        next_gate='ACKNOWLEDGEMENT_INTEGRATION_IMPLEMENTATION_AND_IDENTITY_FREEZE' if qualified else 'EX9_R2_R2_TRANSPORT_INTERFACE_REVIEW'
        freeze={
          "freeze_id":"EX9.ACK.INTEGRATION.CORRECTED.MAPPING.REQUIREMENTS.V1",
          "status":"CORRECTED_REQUIREMENTS_FROZEN" if qualified else "NOT_FROZEN",
          "parent_mechanical_result":"38_OF_38_PRESERVED",
          "parent_freeze_id":pf.get('freeze_id'),
          "authoritative_acknowledge_signature":signature,
          "post_hook_output":{"annotation":pho_ann,"schema_classification":pho_schema,"observed_content_access":pho_content},
          "tool_args_disposition":tool_args_disposition,
          "error_metadata_disposition":error_disposition,
          "proposal_digest":{"annotation":digest_ann,"disposition":digest_disposition,"sdk_reference_count":len(proposal_refs)},
          "removed_historical_destinations":sorted(INVALID_PARENT_DESTINATIONS),
          "corrected_mapping":mapping,
          "decision":decision,
          "implementation_created":False,
          "runtime_behavior":"NOT_EVALUATED",
        }
        claim={"allowed":["corrected argument mapping to the authoritative acknowledge signature","post_hook_output type and source-body usage classification","tool_args and error-metadata disposition under the current transport interface","proposal_digest caller responsibility and handling context","implementation compatibility decision"],"prohibited":["implementation creation","SDK source modification","runtime acknowledgement behavior","actual fs.read","Sandbox or Gym execution","HTTP sink","predicate or breach execution","model execution","protected-value lineage","guardrail effectiveness","real exfiltration prevention"]}
        result={
          "version":VERSION,"created_at_utc":now(),"status":status,
          "classification":"READ_ONLY_SOURCE_AND_REQUIREMENTS_RECONCILIATION",
          "EX9_R2_parent_verified":True,
          "parent_mechanical_result":{"checks":"38_OF_38","preserved_immutable":True,"semantic_mapping_correction_required":True},
          "checks":{"total":len(checks),"passed":len(checks)-len(failed),"failed":len(failed),"failed_ids":failed},
          "correction":{"invalid_historical_destinations":sorted(INVALID_PARENT_DESTINATIONS),"corrected_destination_count":len(mapping),"post_hook_output_schema":pho_schema,"tool_args_disposition":tool_args_disposition,"error_metadata_disposition":error_disposition,"proposal_digest_disposition":digest_disposition},
          "decision":decision,"freeze":freeze,
          "readiness":{"acknowledgement_integration_implementation_gate_eligible":qualified,"controlled_actual_fs_read_eligible":False,"http_sink_eligible":False},
          "execution_boundaries":{"EX9_R2_artifacts_modified":False,"source_modified":False,"implementation_created":False,"sdk_modules_imported":False,"sdk_modules_executed":False,"Sandbox_instantiated":False,"Sandbox_interact_executed":False,"Gym_executed":False,"real_tools_executed":False,"actual_fs_read_executed":False,"http_sink_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False,"threads_executed":False,"external_effects_observed":False},
          "scientific_verdict":{"transport_mapping_requirements":"CORRECTED_AND_FROZEN" if qualified else "GAPS_IDENTIFIED","implementation_behavior":"NOT_EVALUATED","actual_source_retrieval":"NOT_EVALUATED","protected_value_lineage":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},
          "claim_boundary":claim,"next_gate":next_gate,
        }
        outputs={"result":out/'ex9_r2_r1_result.json',"checks":out/'ex9_r2_r1_checks.csv',"mapping":out/'ex9_r2_r1_corrected_mapping.csv',"requirements":out/'ex9_r2_r1_corrected_requirements.csv',"corrections":out/'ex9_r2_r1_removed_destinations.csv',"proposal_refs":out/'ex9_r2_r1_proposal_digest_references.csv',"freeze":out/'ex9_r2_r1_requirements_freeze.json',"claim":out/'ex9_r2_r1_claim_boundary.json',"binding":out/'ex9_r2_r1_binding.json'}
        wj(outputs['result'],result);wc(outputs['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']);wc(outputs['mapping'],mapping,['source','destination','status','destination_exists']);wc(outputs['requirements'],corrected_requirements,['requirement_id','source','destination','status','mandatory']);wc(outputs['corrections'],corrections,['historical_destination','status','reason']);wc(outputs['proposal_refs'],proposal_refs,['relative_path','function','line','source']);wj(outputs['freeze'],freeze);wj(outputs['claim'],claim);wj(outputs['binding'],{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"parent":{k:ident(v) for k,v in parent.items()},"sources":{"transport":ident(transport),"hook_types":ident(hook_types)},"source_modified":False,"implementation_created":False,"sdk_modules_imported":False,"sdk_modules_executed":False})
        rows=[{**ident(p),"role":"EX9_R2_R1_DERIVED"} for p in outputs.values()]+[{**ident(p),"role":"EX9_R2_R1_BOUND_PARENT"} for p in parent.values()]+[{**ident(transport),"role":"EX9_R2_R1_AUTHORITATIVE_SOURCE"},{**ident(hook_types),"role":"EX9_R2_R1_AUTHORITATIVE_SOURCE"}]
        mp=out/'ex9_r2_r1_manifest.csv';wc(mp,rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'ex9_r2_r1_manifest_external_binding.json';wj(ep,{"version":VERSION,"created_at_utc":now(),"status":status,"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"parent_EX9_R2_manifest_sha256":PARENT_MANIFEST_SHA,"freeze_id":freeze['freeze_id'],"checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"decision":decision,"acknowledgement_integration_implementation_gate_eligible":qualified,"controlled_actual_fs_read_eligible":False,"implementation_created":False,"next_gate":next_gate})
        print(json.dumps({"status":status,"parent_mechanical_result":"38/38 preserved","checks_total":len(checks),"checks_passed":len(checks)-len(failed),"checks_failed":len(failed),"failed_ids":failed,"post_hook_output_annotation":pho_ann,"post_hook_output_schema":pho_schema,"tool_args_disposition":tool_args_disposition,"error_metadata_disposition":error_disposition,"decision":decision,"implementation_created":False,"controlled_actual_fs_read_eligible":False,"manifest_sha256":sha(mp),"next_gate":next_gate},indent=2))
    except Exception as e:
        (out/'EX9_R2_R1_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"EX9_R2_R1_MAPPING_CORRECTION_BLOCKED","error_type":type(e).__name__,"error":str(e),"checks_frozen":checks,"source_modified":False,"implementation_created":False,"sdk_modules_imported":False,"sdk_modules_executed":False,"actual_fs_read_executed":False},indent=2),encoding='utf-8');raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for f in ['r2-result','r2-checks','r2-requirements','r2-freeze','r2-claim-boundary','r2-binding','r2-external-binding','r2-manifest','r2-runner','project-root','output-dir']:p.add_argument('--'+f,required=True)
    return p.parse_args()
if __name__=='__main__':
    try:main(args())
    except Exception as e:print(f"FAILED: {e}",file=sys.stderr);raise SystemExit(1)
