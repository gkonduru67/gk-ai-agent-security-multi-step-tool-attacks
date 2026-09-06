#!/usr/bin/env python3
"""EXFIL stateful guardrail implementation and identity freeze v1.0.

Creates a new isolated aicomp_sdk_exfil package, validates it statically with
AST, and freezes exact file identities. It never modifies aicomp_sdk, imports or
executes SDK/new modules, instantiates Sandbox/Gym, executes tools/fs.read/
http.post, calls predicates/breach/models/threads, or causes external effects.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path

VERSION="EXFIL_STATEFUL_GUARDRAIL_IMPLEMENTATION_AND_IDENTITY_FREEZE_v1.0"
PARENT_VERSION="EX9_R4_R1_POST_TOOL_SUCCESS_EVIDENCE_ROUTE_RECONCILIATION_v1.0"
PARENT_STATUS="EX9_R4_R1_POST_TOOL_SUCCESS_EVIDENCE_ROUTE_RECONCILIATION_COMPLETE_PASS"
PARENT_MANIFEST_SHA="4CC3CFB1CA938A5C9CE6B9F0201F71FBBAA042F1F7EBAE35ABC24087ED0D7CB6"
PARENT_RUNNER_SHA="F0C9C37354C28B7E268A126AB0FA4B05830935868EE77AD82684D41A2C76868B"
PARENT_RESULT_SHA="16093603E17327C126BC4D8A601E3C02F5B22FB37D237F2569AE32F56F34E1EB"
PARENT_CHECKS_SHA="FC95496BFBF31461C18BDE156E589A66BCB7F5CED72131E646E80529389D0B00"
PARENT_ROUTE_SHA="A0D3ABD5851812AE86117881C9273126B0A8741B0399535FB4B1C0F621C9028A"
PARENT_REQUIREMENTS_SHA="E0D3A353E217BDA0186D82566E0792FADD1AB18F5EEDCA8D253690B7C06404A4"
PARENT_BINDING_SHA="4BDB87C6D495520D36E00CE854C27066D6A5DD3807B9BD3DA57039EF9C67A726"
SDK_SANDBOX_SHA="B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0"
SDK_PREDICATES_SHA="9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37"
SDK_BASE_SHA="EC95F45A9BF4202514725690617C91E88F3F1AE889AC7828D423DAAFEA527708"
SDK_HOOK_TYPES_SHA="0D3C7B5921749C22CADC5478532C7FE84B86AA90447FEEA8060ACFA9F44D3C7E"
SDK_HOOK_REGISTRY_SHA="5635B45136517CB5B7FBC6BAB6C9440FE7D6D699E484B6D63651AE296D4BB00B"
PACKAGE="aicomp_sdk_exfil"

def now(): return datetime.now(timezone.utc).isoformat()
def require(c,m):
    if not c: raise ValueError(m)
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
def parse_source(src,name):return ast.parse(src,filename=name)
def funcs(tree):return {n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def classes(tree):return {n.name:n for n in tree.body if isinstance(n,ast.ClassDef)}
def methods(cls):return {n.name:n for n in cls.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def signature(f):
    pos=f.args.posonlyargs+f.args.args
    if pos and pos[0].arg in {'self','cls'}:pos=pos[1:]
    return {'positional':[x.arg for x in pos],'keyword_only':[x.arg for x in f.args.kwonlyargs],'return':up(f.returns) if f.returns else 'NOT_ANNOTATED'}
def source_map():
    return {
'__init__.py':'''"""Isolated EXFILTRATION research guardrail package v1."""
from .successful_read_ledger_v1 import SuccessfulReadLedgerV1, SuccessfulReadRecordV1
from .trusted_read_outcome_hook_v1 import TrustedReadOutcomeHookV1
from .lineage_aware_exfil_guardrail_v1 import LineageAwareExfilGuardrailV1
from .integration_factory_v1 import ExfilIntegrationBundleV1, build_exfil_integration_v1
__all__ = ["SuccessfulReadLedgerV1", "SuccessfulReadRecordV1", "TrustedReadOutcomeHookV1", "LineageAwareExfilGuardrailV1", "ExfilIntegrationBundleV1", "build_exfil_integration_v1"]
''',
'successful_read_ledger_v1.py':'''"""Immutable successful protected-read ledger."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Iterable, Mapping
SCHEMA_TAG = "EXFIL.SUCCESSFUL.READ.LEDGER.V1"
RECORD_TAG = "EXFIL.SUCCESSFUL.READ.RECORD.V1"

def _sha256_text(value: str) -> str:
    return sha256(value.encode("utf-8", "surrogatepass")).hexdigest().upper()

def _secret_values(raw: str) -> tuple[str, ...]:
    values: set[str] = set()
    for raw_line in raw.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            values.add(line)
            value = line.partition("=")[2].strip()
            if value:
                values.add(value)
        else:
            values.add(line)
    return tuple(sorted(values))

@dataclass(frozen=True, slots=True)
class SuccessfulReadRecordV1:
    schema_tag: str
    record_sequence: int
    tool_name: str
    tool_args: Mapping[str, Any]
    canonical_path: str
    explicit_ok: bool
    error_value: Any
    raw_output: str
    raw_output_sha256: str
    derived_secret_values: tuple[str, ...]
    record_identity: str

class SuccessfulReadLedgerV1:
    def __init__(self) -> None:
        self._records: list[SuccessfulReadRecordV1] = []
        self._next_sequence = 1

    def append_successful_read(self, *, tool_name: str, tool_args: Mapping[str, Any], canonical_path: str, explicit_ok: bool, error_value: Any, raw_output: str) -> SuccessfulReadRecordV1:
        if tool_name != "fs.read" or explicit_ok is not True:
            raise ValueError("only explicit successful fs.read records are accepted")
        if not isinstance(tool_args, Mapping) or not isinstance(canonical_path, str) or not isinstance(raw_output, str):
            raise TypeError("malformed successful-read evidence")
        args_copy = dict(tool_args)
        output_digest = _sha256_text(raw_output)
        sequence = self._next_sequence
        identity_material = f"{RECORD_TAG}|{sequence}|{tool_name}|{canonical_path}|{output_digest}"
        record = SuccessfulReadRecordV1(RECORD_TAG, sequence, tool_name, MappingProxyType(args_copy), canonical_path, True, error_value, raw_output, output_digest, _secret_values(raw_output), _sha256_text(identity_material))
        self._records.append(record)
        self._next_sequence += 1
        return record

    def qualifying_secret_values(self) -> tuple[str, ...]:
        return tuple(sorted({v for r in self._records for v in r.derived_secret_values}))

    def records(self) -> tuple[SuccessfulReadRecordV1, ...]:
        return tuple(self._records)

    def snapshot_state(self) -> dict[str, object]:
        return {"schema_tag": SCHEMA_TAG, "next_sequence": self._next_sequence, "records": [{**asdict(r), "tool_args": dict(r.tool_args)} for r in self._records]}

    def restore_state(self, snapshot: Mapping[str, Any]) -> None:
        if not isinstance(snapshot, Mapping) or snapshot.get("schema_tag") != SCHEMA_TAG:
            raise ValueError("invalid ledger snapshot schema")
        rows = snapshot.get("records")
        next_sequence = snapshot.get("next_sequence")
        if not isinstance(rows, list) or not isinstance(next_sequence, int) or next_sequence < 1:
            raise ValueError("invalid ledger snapshot structure")
        restored: list[SuccessfulReadRecordV1] = []
        expected_sequence = 1
        for row in rows:
            if not isinstance(row, Mapping) or row.get("schema_tag") != RECORD_TAG or row.get("record_sequence") != expected_sequence:
                raise ValueError("invalid ledger record sequence or schema")
            raw = row.get("raw_output")
            if not isinstance(raw, str) or row.get("raw_output_sha256") != _sha256_text(raw):
                raise ValueError("raw output digest mismatch")
            args = row.get("tool_args")
            if not isinstance(args, Mapping) or row.get("explicit_ok") is not True or row.get("tool_name") != "fs.read":
                raise ValueError("invalid successful-read record")
            record = SuccessfulReadRecordV1(RECORD_TAG, expected_sequence, "fs.read", MappingProxyType(dict(args)), str(row.get("canonical_path")), True, row.get("error_value"), raw, str(row.get("raw_output_sha256")), tuple(row.get("derived_secret_values") or ()), str(row.get("record_identity")))
            restored.append(record)
            expected_sequence += 1
        if next_sequence != expected_sequence:
            raise ValueError("next sequence inconsistent with records")
        self._records = restored
        self._next_sequence = next_sequence

    def reset(self) -> None:
        self._records = []
        self._next_sequence = 1
''',
'trusted_read_outcome_hook_v1.py':'''"""Public POST_TOOL_CALL successful-read capture hook."""
from __future__ import annotations
from collections.abc import Mapping
from typing import Any
from aicomp_sdk.core.predicates import is_protected_secret_path
from aicomp_sdk.hooks.types import HookContext, HookResult, HookStage
from .successful_read_ledger_v1 import SuccessfulReadLedgerV1

class TrustedReadOutcomeHookV1:
    def __init__(self, *, ledger: SuccessfulReadLedgerV1) -> None:
        if not isinstance(ledger, SuccessfulReadLedgerV1):
            raise TypeError("ledger must be SuccessfulReadLedgerV1")
        self._ledger = ledger

    def __call__(self, context: HookContext) -> HookResult:
        if context.stage != HookStage.POST_TOOL_CALL or context.tool_name != "fs.read":
            return HookResult()
        evidence = context.context
        if not isinstance(evidence, Mapping) or evidence.get("ok") is not True:
            return HookResult()
        args = context.tool_args
        if not isinstance(args, Mapping):
            return HookResult(should_block=True, metadata={"reason": "EXFIL_MALFORMED_READ_ARGS"})
        path = args.get("path")
        if not is_protected_secret_path(path):
            return HookResult()
        output = context.tool_output
        if not isinstance(output, str):
            return HookResult(should_block=True, metadata={"reason": "EXFIL_MALFORMED_READ_OUTPUT"})
        self._ledger.append_successful_read(tool_name="fs.read", tool_args=args, canonical_path=str(path), explicit_ok=True, error_value=evidence.get("error"), raw_output=output)
        return HookResult(metadata={"successful_protected_read_recorded": True})
''',
'lineage_aware_exfil_guardrail_v1.py':'''"""Stateful EXFILTRATION proposal guardrail."""
from __future__ import annotations
from collections.abc import Mapping
from typing import Any
from aicomp_sdk.core.predicates import exfil_payload_arg, payload_exfiltrates_secret
from aicomp_sdk.guardrails.base import Decision, GuardrailBase
from .successful_read_ledger_v1 import SuccessfulReadLedgerV1

class LineageAwareExfilGuardrailV1(GuardrailBase):
    REASON_EXFIL = "EXFIL_SUCCESSFUL_READ_VALUE_MATCH"
    REASON_MALFORMED = "EXFIL_MALFORMED_SINK_PROPOSAL"

    def __init__(self, *, ledger: SuccessfulReadLedgerV1, inner: GuardrailBase | None = None) -> None:
        if not isinstance(ledger, SuccessfulReadLedgerV1):
            raise TypeError("ledger must be SuccessfulReadLedgerV1")
        self._ledger = ledger
        self._inner = inner

    def decide(self, tool_name: str, tool_args: Mapping[str, Any], context: Mapping[str, Any]) -> Decision:
        payload_arg = exfil_payload_arg(tool_name)
        if payload_arg is None:
            return self._inner.decide(tool_name, tool_args, context) if self._inner is not None else Decision.allow()
        if not isinstance(tool_args, Mapping) or payload_arg not in tool_args:
            return Decision.deny(self.REASON_MALFORMED)
        raw_payload = tool_args[payload_arg]
        read_secrets = self._ledger.qualifying_secret_values()
        if read_secrets and payload_exfiltrates_secret(raw_payload, read_secrets=read_secrets):
            return Decision.deny(self.REASON_EXFIL)
        return self._inner.decide(tool_name, tool_args, context) if self._inner is not None else Decision.allow()
''',
'integration_factory_v1.py':'''"""Construction boundary for the EXFILTRATION integration."""
from __future__ import annotations
from dataclasses import dataclass
from aicomp_sdk.guardrails.base import GuardrailBase
from aicomp_sdk.hooks.registry import HookRegistry
from aicomp_sdk.hooks.types import HookStage
from .lineage_aware_exfil_guardrail_v1 import LineageAwareExfilGuardrailV1
from .successful_read_ledger_v1 import SuccessfulReadLedgerV1
from .trusted_read_outcome_hook_v1 import TrustedReadOutcomeHookV1

@dataclass(frozen=True, slots=True)
class ExfilIntegrationBundleV1:
    ledger: SuccessfulReadLedgerV1
    hook: TrustedReadOutcomeHookV1
    guardrail: LineageAwareExfilGuardrailV1

class ExfilIntegrationFactoryV1:
    @staticmethod
    def build(*, hook_registry: HookRegistry, inner: GuardrailBase | None = None, priority: int = 0) -> ExfilIntegrationBundleV1:
        ledger = SuccessfulReadLedgerV1()
        hook = TrustedReadOutcomeHookV1(ledger=ledger)
        guardrail = LineageAwareExfilGuardrailV1(ledger=ledger, inner=inner)
        hook_registry.register_hook(HookStage.POST_TOOL_CALL, hook, priority)
        return ExfilIntegrationBundleV1(ledger=ledger, hook=hook, guardrail=guardrail)

def build_exfil_integration_v1(*, hook_registry: HookRegistry, inner: GuardrailBase | None = None, priority: int = 0) -> ExfilIntegrationBundleV1:
    return ExfilIntegrationFactoryV1.build(hook_registry=hook_registry, inner=inner, priority=priority)
'''}

def main(a):
    out=Path(a.output_dir).resolve();require(not out.exists(),f'Refusing overwrite: {out}');out.mkdir(parents=True)
    checks=[]
    try:
        root=Path(a.project_root).resolve();sdk=root/'aicomp_sdk';pkg=root/PACKAGE
        require(sdk.is_dir(),f'Missing SDK: {sdk}');require(not pkg.exists(),f'Refusing existing implementation root: {pkg}')
        parent={'result':Path(a.r1_result).resolve(),'checks':Path(a.r1_checks).resolve(),'route':Path(a.r1_route_freeze).resolve(),'requirements':Path(a.r1_requirements).resolve(),'claim':Path(a.r1_claim_boundary).resolve(),'binding':Path(a.r1_binding).resolve(),'external':Path(a.r1_external_binding).resolve(),'manifest':Path(a.r1_manifest).resolve(),'runner':Path(a.r1_runner).resolve()}
        for k,p in parent.items():require(p.is_file(),f'Missing parent {k}: {p}')
        pr=rj(parent['result']);pe=rj(parent['external']);pc=rc(parent['checks'])
        add(checks,'I-001','parent',pr.get('version')==PARENT_VERSION and pr.get('status')==PARENT_STATUS,pr.get('status'),PARENT_STATUS,'FIXTURE')
        for i,(k,h) in enumerate([('manifest',PARENT_MANIFEST_SHA),('runner',PARENT_RUNNER_SHA),('result',PARENT_RESULT_SHA),('checks',PARENT_CHECKS_SHA),('route',PARENT_ROUTE_SHA),('requirements',PARENT_REQUIREMENTS_SHA),('binding',PARENT_BINDING_SHA)],2):add(checks,f'I-{i:03d}','parent',sha(parent[k])==h,sha(parent[k]),h,'FIXTURE')
        add(checks,'I-009','parent',len(pc)==22 and all(x['passed']=='True' for x in pc) and pr.get('outcome')=='PUBLIC_POST_TOOL_SUCCESS_IN_CONTEXT',{'checks':len(pc),'outcome':pr.get('outcome')},'22/22 and public context success','EVIDENCE')
        add(checks,'I-010','parent',pe.get('implementation_creation_eligible') is True and pe.get('controlled_actual_fs_read_eligible') is False,pe,'static implementation eligible; runtime ineligible','CLAIM_BOUNDARY')
        sdk_files={'sandbox':root/'aicomp_sdk/core/env/sandbox.py','predicates':root/'aicomp_sdk/core/predicates.py','base':root/'aicomp_sdk/guardrails/base.py','types':root/'aicomp_sdk/hooks/types.py','registry':root/'aicomp_sdk/hooks/registry.py'}
        expected_sdk={'sandbox':SDK_SANDBOX_SHA,'predicates':SDK_PREDICATES_SHA,'base':SDK_BASE_SHA,'types':SDK_HOOK_TYPES_SHA,'registry':SDK_HOOK_REGISTRY_SHA}
        for i,k in enumerate(sdk_files,11):require(sdk_files[k].is_file(),f'Missing {sdk_files[k]}');add(checks,f'I-{i:03d}','sdk_identity',sha(sdk_files[k])==expected_sdk[k],sha(sdk_files[k]),expected_sdk[k],'FIXTURE')

        srcs=source_map();pkg.mkdir()
        created=[];contracts=[]
        for name,src in srcs.items():
            p=pkg/name;p.write_text(src,encoding='utf-8',newline='\n');tree=parse_source(src,str(p));created.append(p)
            for cn,c in classes(tree).items():contracts.append({'file':name,'kind':'CLASS','name':cn,'signature':'','methods':json.dumps({mn:signature(m) for mn,m in methods(c).items()},sort_keys=True)})
            for fn,f in funcs(tree).items():contracts.append({'file':name,'kind':'FUNCTION','name':fn,'signature':json.dumps(signature(f),sort_keys=True),'methods':''})
        add(checks,'I-020','creation',len(created)==5,[p.name for p in created],'exactly five planned files','FIXTURE')
        all_text='\n'.join(p.read_text(encoding='utf-8') for p in created)
        required_tokens=['evidence.get("ok") is not True','is_protected_secret_path','payload_exfiltrates_secret','exfil_payload_arg','snapshot_state','restore_state','reset','raw_output','raw_output_sha256','SuccessfulReadLedgerV1','TrustedReadOutcomeHookV1','LineageAwareExfilGuardrailV1','ExfilIntegrationFactoryV1','HookStage.POST_TOOL_CALL']
        for i,t in enumerate(required_tokens,21):add(checks,f'I-{i:03d}','contract',t in all_text,t,'required implementation token','ARGUMENT_FIDELITY')
        prohibited=['importlib','exec(','eval(','subprocess','Sandbox(','Gym(','self.tools.call','http.post(']
        add(checks,'I-040','safety',not any(t in all_text for t in prohibited),[t for t in prohibited if t in all_text],'no execution/private runtime tokens','TOOL')
        add(checks,'I-041','boundary',all('aicomp_sdk_exfil' in str(p) for p in created),[str(p) for p in created],'all implementation files isolated','FIXTURE')
        add(checks,'I-042','boundary',all(sha(sdk_files[k])==expected_sdk[k] for k in sdk_files),'unchanged','all frozen SDK identities preserved','FIXTURE')
        failed=[x['check_id'] for x in checks if not x['passed']]
        pass_gate=not failed
        status='EXFIL_STATEFUL_GUARDRAIL_IMPLEMENTATION_AND_IDENTITY_FREEZE_COMPLETE_PASS' if pass_gate else 'EXFIL_STATEFUL_GUARDRAIL_IMPLEMENTATION_AND_IDENTITY_FREEZE_COMPLETE_WITH_GAPS'
        implementation_rows=[{**ident(p),'relative_path':str(p.relative_to(root)),'role':'NEW_IMPLEMENTATION'} for p in created]
        inventory={'source_root':PACKAGE,'files':implementation_rows,'classes':['SuccessfulReadRecordV1','SuccessfulReadLedgerV1','TrustedReadOutcomeHookV1','LineageAwareExfilGuardrailV1','ExfilIntegrationBundleV1','ExfilIntegrationFactoryV1'],'factory_function':'build_exfil_integration_v1','runtime_behavior':'NOT_EVALUATED'}
        claim={'allowed':['new isolated source implementation exists','AST syntax and required static contracts passed','exact implementation and parent identities frozen','frozen aicomp_sdk identities preserved'],'prohibited':['claim importability','claim runtime behavior','claim successful fs.read capture','claim http.post denial','claim guardrail effectiveness','claim protected-value lineage','claim predicate or breach behavior','claim real exfiltration prevention']}
        result={'version':VERSION,'created_at_utc':now(),'status':status,'classification':'STATIC_IMPLEMENTATION_CREATION_AND_IDENTITY_FREEZE','parent_verified':True,'checks':{'total':len(checks),'passed':len(checks)-len(failed),'failed':len(failed),'failed_ids':failed},'implementation':inventory,'readiness':{'independent_static_qualification_eligible':pass_gate,'controlled_actual_fs_read_eligible':False,'http_sink_eligible':False},'execution_boundaries':{'parent_artifacts_modified':False,'frozen_aicomp_sdk_modified':False,'aicomp_sdk_exfil_created':True,'implementation_created':True,'implementation_imported':False,'implementation_instantiated':False,'sdk_modules_imported':False,'sdk_modules_executed':False,'Sandbox_instantiated':False,'Gym_executed':False,'real_tools_executed':False,'actual_fs_read_executed':False,'http_sink_executed':False,'predicates_executed':False,'breach_executed':False,'models_used':False,'threads_executed':False,'external_effects_observed':False},'scientific_verdict':{'implementation_identity':'ESTABLISHED' if pass_gate else 'NOT_ESTABLISHED','implementation_behavior':'NOT_EVALUATED','actual_source_retrieval':'NOT_EVALUATED','protected_value_lineage':'NOT_ESTABLISHED','guardrail_effectiveness':'NOT_EVALUATED','harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'},'claim_boundary':claim,'next_gate':'INDEPENDENT_STATEFUL_GUARDRAIL_STATIC_QUALIFICATION' if pass_gate else 'IMPLEMENTATION_STATIC_REPAIR'}
        o={'result':out/'exfil_impl_freeze_result.json','checks':out/'exfil_impl_freeze_checks.csv','inventory':out/'exfil_impl_inventory.csv','contracts':out/'exfil_impl_contracts.csv','claim':out/'exfil_impl_claim_boundary.json','binding':out/'exfil_impl_binding.json'}
        wj(o['result'],result);wc(o['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']);wc(o['inventory'],implementation_rows,['artifact','relative_path','role','size_bytes','sha256','path']);wc(o['contracts'],contracts,['file','kind','name','signature','methods']);wj(o['claim'],claim);wj(o['binding'],{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'parent':{k:ident(v) for k,v in parent.items()},'sdk_sources':{k:ident(v) for k,v in sdk_files.items()},'implementation':{p.name:ident(p) for p in created},'frozen_aicomp_sdk_modified':False,'implementation_imported':False,'implementation_instantiated':False,'sdk_modules_imported':False,'sdk_modules_executed':False})
        rows=[{**ident(p),'role':'EXFIL_IMPL_FREEZE_DERIVED'} for p in o.values()]+[{**ident(p),'role':'EXFIL_IMPL_FREEZE_IMPLEMENTATION'} for p in created]+[{**ident(p),'role':'EXFIL_IMPL_FREEZE_BOUND_PARENT'} for p in parent.values()]+[{**ident(p),'role':'EXFIL_IMPL_FREEZE_BOUND_SDK'} for p in sdk_files.values()]
        mp=out/'exfil_impl_freeze_manifest.csv';wc(mp,rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'exfil_impl_freeze_manifest_external_binding.json';wj(ep,{'version':VERSION,'created_at_utc':now(),'status':status,'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':sha(mp),'runner_sha256':sha(Path(__file__).resolve()),'parent_manifest_sha256':PARENT_MANIFEST_SHA,'checks_total':len(checks),'checks_passed':len(checks)-len(failed),'checks_failed':len(failed),'implementation_created':True,'implementation_identity_established':pass_gate,'implementation_imported':False,'implementation_instantiated':False,'frozen_aicomp_sdk_modified':False,'controlled_actual_fs_read_eligible':False,'next_gate':result['next_gate']})
        print(json.dumps({'status':status,'checks':f'{len(checks)-len(failed)}/{len(checks)}','implementation_root':str(pkg),'implementation_files':{p.name:ident(p) for p in created},'frozen_aicomp_sdk_modified':False,'implementation_imported':False,'implementation_instantiated':False,'controlled_actual_fs_read_eligible':False,'manifest_sha256':sha(mp),'next_gate':result['next_gate']},indent=2))
    except Exception as e:
        (out/'EXFIL_IMPL_FREEZE_FAILED.json').write_text(json.dumps({'version':VERSION,'created_at_utc':now(),'status':'EXFIL_IMPLEMENTATION_FREEZE_BLOCKED','error_type':type(e).__name__,'error':str(e),'checks_frozen':checks,'frozen_aicomp_sdk_modified':False,'implementation_imported':False,'implementation_instantiated':False,'sdk_modules_imported':False,'sdk_modules_executed':False,'actual_fs_read_executed':False},indent=2),encoding='utf-8');raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for f in ['r1-result','r1-checks','r1-route-freeze','r1-requirements','r1-claim-boundary','r1-binding','r1-external-binding','r1-manifest','r1-runner','project-root','output-dir']:p.add_argument('--'+f,required=True)
    return p.parse_args()
if __name__=='__main__':
    try:main(args())
    except Exception as e:print(f'FAILED: {e}',file=sys.stderr);raise SystemExit(1)
