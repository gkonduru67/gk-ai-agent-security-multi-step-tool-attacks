#!/usr/bin/env python3
"""Freeze failed V2 ledger run and create isolated V2.1 repair implementation.

This runner:
1. binds and semantically validates the frozen CONTROLLED_V2_LEDGER_FAILED.json;
2. preserves every V2, V1, and bound SDK identity;
3. creates a new aicomp_sdk_exfil_v2_1 package with distinct class names;
4. repairs explicit snapshot serialization and recursive tool_args detachment;
5. changes ledger and record schema identities to V2.1;
6. statically freezes restore atomicity, digest, candidate, and identity contracts;
7. classifies V2/V2.1 snapshot compatibility as intentionally rejected.

It creates source and evidence files only. It does not import or execute V2.1,
V2, V1, SDK, snapshot, restore, candidates, predicates, tools, fs.read, HTTP,
Sandbox, Gym, breach logic, models, threads, or external effects.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path

VERSION="V2_1_SNAPSHOT_SERIALIZATION_REPAIR_AND_IDENTITY_FREEZE_v1.0"
V21_ROOT="aicomp_sdk_exfil_v2_1"
FAILED_RUNNER_SHA="BB2158D3473E813A733CB26C8036FC549D8B83E287ABFF01FD3BBA2C9E857CDE"
FAILED_RUNNER_SIZE=26968
PARENTS={
 "v2_manifest":"E4012BAEE67A8B93D4B54DEA90415CB4E5A38B4385DC301EF50D9B2E748A9521",
 "independent_manifest":"205284E446C3FD3890478ECC4C7666A2CECF3363B6AC727AE20EC07D42F63993",
 "corrected_manifest":"68163666E8433F1BC0A0B3E555E39BE1CCC4D07F8EE5A2938DBB5B87825994CA",
}
V2={
 "__init__.py":(613,"A2FF10622D4323205F04BDAE96B121DF0CF710ABB90F33205A83E94E4812ED06"),
 "successful_read_ledger_v2.py":(6645,"609B22AA7ABD3555B24484E2AF313A5460877BA3C446FBE2978C6136D662857E"),
 "trusted_read_outcome_hook_v2.py":(1534,"424D659F677CC6EEFC2E961B350B4A01D41E356849280F3728FB2F5FA5DB9817"),
 "lineage_aware_exfil_guardrail_v2.py":(1392,"27B938444693B53BF3641CB5E958E5C8946B114D4195E8A6D3C1AB774D42931B"),
 "integration_factory_v2.py":(1337,"436C9111DD48C069DDF6FB655C5E40D9A471E4B59890592222CBF8C871E39224"),
}
V1={
 "__init__.py":"DB60398BBEEAAE411C62FB915F2EAE5C7CDEBA9A2100D278BF2399190ED3094A",
 "successful_read_ledger_v1.py":"3560FD4B7533C5B9B2622B84B1AD9BEC4A5562C1BBFF4FE06279EC7206DB73A6",
 "trusted_read_outcome_hook_v1.py":"2B979C6B652358EAC1E0275A16607AD3A4750CC05C3AC64B6861EFC990B051CD",
 "lineage_aware_exfil_guardrail_v1.py":"0D20934AD62E7191498F795F1D9BFDB008A749CD134A0842582DED1322F5A1DE",
 "integration_factory_v1.py":"8220A3AF5601BA660AAD7EA8A1F6893646A8DB764C88BA8F859A35C12733C431",
}
SDK={
 "aicomp_sdk/core/env/sandbox.py":"B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0",
 "aicomp_sdk/core/predicates.py":"9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37",
 "aicomp_sdk/guardrails/base.py":"EC95F45A9BF4202514725690617C91E88F3F1AE889AC7828D423DAAFEA527708",
 "aicomp_sdk/hooks/types.py":"0D3C7B5921749C22CADC5478532C7FE84B86AA90447FEEA8060ACFA9F44D3C7E",
 "aicomp_sdk/hooks/registry.py":"5635B45136517CB5B7FBC6BAB6C9440FE7D6D699E484B6D63651AE296D4BB00B",
}

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
def wj(p,o):
    with Path(p).open('x',encoding='utf-8',newline='\n') as f:json.dump(o,f,indent=2,sort_keys=True,ensure_ascii=False);f.write('\n')
def wc(p,rows,fields):
    with Path(p).open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(rows)
def add(rows,cid,cat,ok,obs,exp,layer):rows.append({'check_id':cid,'category':cat,'passed':bool(ok),'observed':str(obs),'expected':str(exp),'failure_layer':layer})
def unparse(n):
    try:return ast.unparse(n)
    except:return 'UNPARSE_FAILED'
def defs(t):return {n.name:n for n in t.body if isinstance(n,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef))}
def methods(c):return {n.name:n for n in c.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def sources():
    ledger='''"""V2.1 immutable successful protected-read ledger."""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
import json
from types import MappingProxyType
from typing import Any, Mapping
SCHEMA_TAG_V2_1 = "EXFIL.SUCCESSFUL.READ.LEDGER.V2.1"
RECORD_TAG_V2_1 = "EXFIL.SUCCESSFUL.READ.RECORD.V2.1"
OFFICIAL_MIN_SECRET_VALUE_LEN = 6
SNAPSHOT_COMPATIBILITY = "V2 and V2.1 snapshots are mutually rejected by distinct schema and record tags"

def _sha256_text_v21(value: str) -> str:
    return sha256(value.encode("utf-8", "surrogatepass")).hexdigest().upper()

def _detach_json_value_v21(value: Any) -> Any:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        return json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise ValueError("tool_args are not canonically JSON serializable") from exc

def _canonical_args_json_v21(args: Mapping[str, Any]) -> str:
    detached = _detach_json_value_v21(dict(args))
    if not isinstance(detached, dict):
        raise ValueError("tool_args must serialize as an object")
    return json.dumps(detached, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

def _tool_args_digest_v21(args: Mapping[str, Any]) -> str:
    return _sha256_text_v21(_canonical_args_json_v21(args))

def _secret_values_v21(raw: str) -> tuple[str, ...]:
    values: set[str] = set()
    for raw_line in raw.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            values.add(line)
            value = line.partition("=")[2].strip()
            if len(value) >= OFFICIAL_MIN_SECRET_VALUE_LEN:
                values.add(value)
        elif len(line) >= OFFICIAL_MIN_SECRET_VALUE_LEN:
            values.add(line)
    return tuple(sorted(values))

def _record_identity_v21(*, sequence: int, tool_name: str, canonical_path: str, tool_args_digest: str, output_digest: str) -> str:
    material = f"{RECORD_TAG_V2_1}|{sequence}|{tool_name}|{canonical_path}|{tool_args_digest}|{output_digest}"
    return _sha256_text_v21(material)

@dataclass(frozen=True, slots=True)
class SuccessfulReadRecordV21:
    schema_tag: str
    record_sequence: int
    tool_name: str
    tool_args: Mapping[str, Any]
    tool_args_sha256: str
    canonical_path: str
    explicit_ok: bool
    error_value: Any
    raw_output: str
    raw_output_sha256: str
    derived_secret_values: tuple[str, ...]
    record_identity: str

class SuccessfulReadLedgerV21:
    def __init__(self) -> None:
        self._records: list[SuccessfulReadRecordV21] = []
        self._next_sequence = 1

    def append_successful_read(self, *, tool_name: str, tool_args: Mapping[str, Any], canonical_path: str, explicit_ok: bool, error_value: Any, raw_output: str) -> SuccessfulReadRecordV21:
        if tool_name != "fs.read" or explicit_ok is not True:
            raise ValueError("only explicit successful fs.read records are accepted")
        if not isinstance(tool_args, Mapping) or not isinstance(canonical_path, str) or not isinstance(raw_output, str):
            raise TypeError("malformed successful-read evidence")
        args_copy = _detach_json_value_v21(dict(tool_args))
        if not isinstance(args_copy, dict):
            raise ValueError("tool_args must detach as an object")
        args_digest = _tool_args_digest_v21(args_copy)
        output_digest = _sha256_text_v21(raw_output)
        sequence = self._next_sequence
        identity = _record_identity_v21(sequence=sequence, tool_name=tool_name, canonical_path=canonical_path, tool_args_digest=args_digest, output_digest=output_digest)
        record = SuccessfulReadRecordV21(RECORD_TAG_V2_1, sequence, tool_name, MappingProxyType(args_copy), args_digest, canonical_path, True, error_value, raw_output, output_digest, _secret_values_v21(raw_output), identity)
        self._records.append(record)
        self._next_sequence += 1
        return record

    def qualifying_secret_values(self) -> tuple[str, ...]:
        return tuple(sorted({v for record in self._records for v in record.derived_secret_values}))

    def records(self) -> tuple[SuccessfulReadRecordV21, ...]:
        return tuple(self._records)

    def snapshot_state(self) -> dict[str, object]:
        return {
            "schema_tag": SCHEMA_TAG_V2_1,
            "next_sequence": self._next_sequence,
            "records": [
                {
                    "schema_tag": record.schema_tag,
                    "record_sequence": record.record_sequence,
                    "tool_name": record.tool_name,
                    "tool_args": _detach_json_value_v21(dict(record.tool_args)),
                    "tool_args_sha256": record.tool_args_sha256,
                    "canonical_path": record.canonical_path,
                    "explicit_ok": record.explicit_ok,
                    "error_value": _detach_json_value_v21(record.error_value),
                    "raw_output": record.raw_output,
                    "raw_output_sha256": record.raw_output_sha256,
                    "derived_secret_values": list(record.derived_secret_values),
                    "record_identity": record.record_identity,
                }
                for record in self._records
            ],
        }

    def restore_state(self, snapshot: Mapping[str, Any]) -> None:
        if not isinstance(snapshot, Mapping) or snapshot.get("schema_tag") != SCHEMA_TAG_V2_1:
            raise ValueError("invalid ledger snapshot schema")
        rows = snapshot.get("records")
        next_sequence = snapshot.get("next_sequence")
        if not isinstance(rows, list) or not isinstance(next_sequence, int) or isinstance(next_sequence, bool) or next_sequence < 1:
            raise ValueError("invalid ledger snapshot structure")
        restored: list[SuccessfulReadRecordV21] = []
        expected_sequence = 1
        for row in rows:
            if not isinstance(row, Mapping) or row.get("schema_tag") != RECORD_TAG_V2_1 or row.get("record_sequence") != expected_sequence:
                raise ValueError("invalid ledger record sequence or schema")
            args = row.get("tool_args"); raw = row.get("raw_output"); path = row.get("canonical_path")
            if not isinstance(args, Mapping) or not isinstance(raw, str) or not isinstance(path, str):
                raise ValueError("invalid restored field type")
            if row.get("explicit_ok") is not True or row.get("tool_name") != "fs.read":
                raise ValueError("invalid successful-read record")
            args_copy = _detach_json_value_v21(dict(args))
            if not isinstance(args_copy, dict):
                raise ValueError("restored tool_args must detach as an object")
            args_digest = _tool_args_digest_v21(args_copy)
            output_digest = _sha256_text_v21(raw)
            if row.get("tool_args_sha256") != args_digest:
                raise ValueError("tool args digest mismatch")
            if row.get("raw_output_sha256") != output_digest:
                raise ValueError("raw output digest mismatch")
            derived = _secret_values_v21(raw)
            serialized_derived = row.get("derived_secret_values")
            if not isinstance(serialized_derived, list) or tuple(serialized_derived) != derived:
                raise ValueError("derived secret values mismatch")
            expected_identity = _record_identity_v21(sequence=expected_sequence, tool_name="fs.read", canonical_path=path, tool_args_digest=args_digest, output_digest=output_digest)
            if row.get("record_identity") != expected_identity:
                raise ValueError("record identity mismatch")
            restored.append(SuccessfulReadRecordV21(RECORD_TAG_V2_1, expected_sequence, "fs.read", MappingProxyType(args_copy), args_digest, path, True, _detach_json_value_v21(row.get("error_value")), raw, output_digest, derived, expected_identity))
            expected_sequence += 1
        if next_sequence != expected_sequence:
            raise ValueError("next sequence inconsistent with records")
        self._records = restored
        self._next_sequence = next_sequence

    def reset(self) -> None:
        self._records = []
        self._next_sequence = 1
'''
    return {
'__init__.py':'''"""Isolated EXFILTRATION research guardrail package V2.1."""
from .successful_read_ledger_v2_1 import SuccessfulReadLedgerV21, SuccessfulReadRecordV21
from .trusted_read_outcome_hook_v2_1 import TrustedReadOutcomeHookV21
from .lineage_aware_exfil_guardrail_v2_1 import LineageAwareExfilGuardrailV21
from .integration_factory_v2_1 import ExfilIntegrationBundleV21, ExfilIntegrationFactoryV21, build_exfil_integration_v21
__all__ = ["SuccessfulReadLedgerV21", "SuccessfulReadRecordV21", "TrustedReadOutcomeHookV21", "LineageAwareExfilGuardrailV21", "ExfilIntegrationBundleV21", "ExfilIntegrationFactoryV21", "build_exfil_integration_v21"]
''',
'successful_read_ledger_v2_1.py':ledger,
'trusted_read_outcome_hook_v2_1.py':'''"""V2.1 public POST_TOOL_CALL successful-read capture hook."""
from collections.abc import Mapping
from aicomp_sdk.core.predicates import is_protected_secret_path
from aicomp_sdk.hooks.types import HookContext, HookResult, HookStage
from .successful_read_ledger_v2_1 import SuccessfulReadLedgerV21
class TrustedReadOutcomeHookV21:
    def __init__(self, *, ledger: SuccessfulReadLedgerV21) -> None:
        if not isinstance(ledger, SuccessfulReadLedgerV21): raise TypeError("ledger must be SuccessfulReadLedgerV21")
        self._ledger = ledger
    def __call__(self, context: HookContext) -> HookResult:
        if context.stage != HookStage.POST_TOOL_CALL or context.tool_name != "fs.read": return HookResult()
        evidence=context.context
        if not isinstance(evidence, Mapping) or evidence.get("ok") is not True: return HookResult()
        args=context.tool_args
        if not isinstance(args, Mapping): return HookResult(should_block=True, metadata={"reason":"EXFIL_V21_MALFORMED_READ_ARGS"})
        path=args.get("path")
        if not is_protected_secret_path(path): return HookResult()
        output=context.tool_output
        if not isinstance(output,str): return HookResult(should_block=True, metadata={"reason":"EXFIL_V21_MALFORMED_READ_OUTPUT"})
        self._ledger.append_successful_read(tool_name="fs.read",tool_args=args,canonical_path=str(path),explicit_ok=True,error_value=evidence.get("error"),raw_output=output)
        return HookResult(metadata={"successful_protected_read_recorded_v21":True})
''',
'lineage_aware_exfil_guardrail_v2_1.py':'''"""V2.1 stateful EXFILTRATION proposal guardrail."""
from collections.abc import Mapping
from typing import Any
from aicomp_sdk.core.predicates import exfil_payload_arg, payload_exfiltrates_secret
from aicomp_sdk.guardrails.base import Decision, GuardrailBase
from .successful_read_ledger_v2_1 import SuccessfulReadLedgerV21
class LineageAwareExfilGuardrailV21(GuardrailBase):
    def __init__(self, *, ledger: SuccessfulReadLedgerV21, inner: GuardrailBase | None=None) -> None:
        if not isinstance(ledger, SuccessfulReadLedgerV21): raise TypeError("ledger must be SuccessfulReadLedgerV21")
        self._ledger=ledger; self._inner=inner
    def decide(self, tool_name:str, tool_args:Mapping[str,Any], context:Mapping[str,Any]) -> Decision:
        payload_arg=exfil_payload_arg(tool_name)
        if payload_arg is None: return self._inner.decide(tool_name,tool_args,context) if self._inner is not None else Decision.allow()
        if not isinstance(tool_args,Mapping) or payload_arg not in tool_args: return Decision.deny("EXFIL_V21_MALFORMED_SINK_PROPOSAL")
        secrets=self._ledger.qualifying_secret_values()
        if secrets and payload_exfiltrates_secret(tool_args[payload_arg],read_secrets=secrets): return Decision.deny("EXFIL_V21_SUCCESSFUL_READ_VALUE_MATCH")
        return self._inner.decide(tool_name,tool_args,context) if self._inner is not None else Decision.allow()
''',
'integration_factory_v2_1.py':'''"""V2.1 construction boundary."""
from dataclasses import dataclass
from aicomp_sdk.guardrails.base import GuardrailBase
from aicomp_sdk.hooks.registry import HookRegistry
from aicomp_sdk.hooks.types import HookStage
from .successful_read_ledger_v2_1 import SuccessfulReadLedgerV21
from .trusted_read_outcome_hook_v2_1 import TrustedReadOutcomeHookV21
from .lineage_aware_exfil_guardrail_v2_1 import LineageAwareExfilGuardrailV21
@dataclass(frozen=True, slots=True)
class ExfilIntegrationBundleV21:
    ledger: SuccessfulReadLedgerV21
    hook: TrustedReadOutcomeHookV21
    guardrail: LineageAwareExfilGuardrailV21
class ExfilIntegrationFactoryV21:
    @staticmethod
    def build(*,hook_registry:HookRegistry,inner:GuardrailBase|None=None,priority:int=0)->ExfilIntegrationBundleV21:
        ledger=SuccessfulReadLedgerV21();hook=TrustedReadOutcomeHookV21(ledger=ledger);guardrail=LineageAwareExfilGuardrailV21(ledger=ledger,inner=inner)
        hook_registry.register_hook(HookStage.POST_TOOL_CALL,hook,priority)
        return ExfilIntegrationBundleV21(ledger=ledger,hook=hook,guardrail=guardrail)
def build_exfil_integration_v21(*,hook_registry:HookRegistry,inner:GuardrailBase|None=None,priority:int=0)->ExfilIntegrationBundleV21:
    return ExfilIntegrationFactoryV21.build(hook_registry=hook_registry,inner=inner,priority=priority)
'''}

def main(a):
    out=Path(a.output_dir).resolve();need(not out.exists(),f'Refusing overwrite: {out}');out.mkdir(parents=True);checks=[]
    try:
        root=Path(a.project_root).resolve();v2root=root/'aicomp_sdk_exfil_v2';v1root=root/'aicomp_sdk_exfil';v21root=root/V21_ROOT
        need(v2root.is_dir() and v1root.is_dir(),'Frozen V2 or V1 root missing');need(not v21root.exists(),f'V2.1 root exists: {v21root}')
        inputs={'failed_evidence':Path(a.failed_evidence).resolve(),'failed_runner':Path(a.failed_runner).resolve(),'v2_manifest':Path(a.v2_manifest).resolve(),'independent_manifest':Path(a.independent_manifest).resolve(),'corrected_manifest':Path(a.corrected_manifest).resolve()}
        for k,p in inputs.items():need(p.is_file(),f'Missing {k}: {p}')
        add(checks,'R21-001','identity',inputs['failed_runner'].stat().st_size==FAILED_RUNNER_SIZE and sha(inputs['failed_runner'])==FAILED_RUNNER_SHA,ident(inputs['failed_runner']),{'size':FAILED_RUNNER_SIZE,'sha256':FAILED_RUNNER_SHA},'FIXTURE')
        for i,(k,h) in enumerate(PARENTS.items(),2):add(checks,f'R21-{i:03d}','identity',sha(inputs[k])==h,sha(inputs[k]),h,'FIXTURE')
        failed=rj(inputs['failed_evidence']); frozen=failed.get('checks_frozen',[]); byid={x.get('check_id'):x for x in frozen}
        semantic=failed.get('status')=='CONTROLLED_V2_LEDGER_BLOCKED' and failed.get('error_type')=='TypeError' and failed.get('error')=="cannot pickle 'mappingproxy' object" and byid.get('CL-017',{}).get('passed') is True and byid.get('CL-018',{}).get('passed') is False and '"args_copied": false' in byid.get('CL-018',{}).get('observed','') and failed.get('actual_fs_read_executed') is False and failed.get('external_effects_observed') is False
        add(checks,'R21-005','failure_evidence',semantic,{'status':failed.get('status'),'error':failed.get('error'),'CL-017':byid.get('CL-017',{}).get('passed'),'CL-018':byid.get('CL-018',{}).get('observed')},'snapshot mappingproxy failure plus nested copy failure','PROVENANCE')
        for i,(n,(size,h)) in enumerate(V2.items(),6):p=v2root/n;need(p.is_file(),f'Missing V2 {n}');add(checks,f'R21-{i:03d}','V2_identity',p.stat().st_size==size and sha(p)==h,ident(p),{'size':size,'sha256':h},'FIXTURE')
        for i,(n,h) in enumerate(V1.items(),11):p=v1root/n;need(p.is_file(),f'Missing V1 {n}');add(checks,f'R21-{i:03d}','V1_identity',sha(p)==h,sha(p),h,'FIXTURE')
        for i,(rel,h) in enumerate(SDK.items(),16):p=root/rel;need(p.is_file(),f'Missing SDK {rel}');add(checks,f'R21-{i:03d}','SDK_identity',sha(p)==h,sha(p),h,'FIXTURE')
        src=sources();v21root.mkdir();created=[];trees={}
        for n,text in src.items():p=v21root/n;p.write_text(text,encoding='utf-8',newline='\n');trees[n]=ast.parse(text,filename=str(p));created.append(p)
        add(checks,'R21-021','creation',sorted(p.name for p in created)==sorted(src),[p.name for p in created],sorted(src),'FIXTURE')
        lt=trees['successful_read_ledger_v2_1.py'];d=defs(lt);ledger=d['SuccessfulReadLedgerV21'];lm=methods(ledger);snapshot=unparse(lm['snapshot_state']);restore=unparse(lm['restore_state']);append=unparse(lm['append_successful_read']);alltext=src['successful_read_ledger_v2_1.py']
        snapshot_tests=[('no asdict','asdict' not in alltext),('no deepcopy','deepcopy' not in alltext),('explicit fields',all(x in snapshot for x in ['schema_tag','record_sequence','tool_name','tool_args','tool_args_sha256','canonical_path','explicit_ok','error_value','raw_output','raw_output_sha256','derived_secret_values','record_identity'])),('detached tool args','_detach_json_value_v21(dict(record.tool_args))' in snapshot),('candidate list','list(record.derived_secret_values)' in snapshot),('new ledger tag','EXFIL.SUCCESSFUL.READ.LEDGER.V2.1' in alltext),('new record tag','EXFIL.SUCCESSFUL.READ.RECORD.V2.1' in alltext),('recursive append detach','args_copy = _detach_json_value_v21(dict(tool_args))' in append)]
        for i,(label,ok) in enumerate(snapshot_tests,22):add(checks,f'R21-{i:03d}','snapshot',ok,label,True,'PROVENANCE')
        restore_tests=[('V21 schema required','SCHEMA_TAG_V2_1' in restore),('V21 record required','RECORD_TAG_V2_1' in restore),('args digest recomputed','_tool_args_digest_v21(args_copy)' in restore),('output digest recomputed','_sha256_text_v21(raw)' in restore),('candidates recomputed','_secret_values_v21(raw)' in restore),('identity recomputed','_record_identity_v21(' in restore),('serialized values compared',all(x in restore for x in ['tool_args_sha256','raw_output_sha256','derived_secret_values','record_identity'])),('recomputed identity stored','derived, expected_identity' in restore),('local list','restored: list[SuccessfulReadRecordV21] = []' in restore),('commit after validation',restore.rfind('self._records = restored')>restore.rfind('if next_sequence != expected_sequence'))]
        for i,(label,ok) in enumerate(restore_tests,30):add(checks,f'R21-{i:03d}','restore',ok,label,True,'PROVENANCE')
        compat={'V2_snapshot_accepted_by_V21':'REJECT_BY_LEDGER_SCHEMA_TAG','V21_snapshot_accepted_by_V2':'REJECT_BY_LEDGER_SCHEMA_TAG','same_field_names_imply_compatibility':False,'classification':'MUTUALLY_INCOMPATIBLE_BY_DESIGN'}
        add(checks,'R21-040','compatibility','SCHEMA_TAG_V2_1' in restore and 'EXFIL.SUCCESSFUL.READ.LEDGER.V2.1' in alltext,compat,'mutual schema rejection','PROVENANCE')
        add(checks,'R21-041','immutability',all(sha(v2root/n)==h for n,(s,h) in V2.items()) and all(sha(v1root/n)==h for n,h in V1.items()) and all(sha(root/r)==h for r,h in SDK.items()),'unchanged','V2 V1 SDK unchanged','FIXTURE')
        failed_ids=[x['check_id'] for x in checks if not x['passed']];passed=not failed_ids;status='V2_1_SNAPSHOT_SERIALIZATION_REPAIR_AND_IDENTITY_FREEZE_COMPLETE_PASS' if passed else 'V2_1_SNAPSHOT_SERIALIZATION_REPAIR_AND_IDENTITY_FREEZE_COMPLETE_WITH_GAPS'
        inventory=[{**ident(p),'relative_path':str(p.relative_to(root)),'role':'NEW_V2_1_IMPLEMENTATION'} for p in created]
        claim={'allowed':['failed V2 run identity and semantics frozen','V2.1 source and identities frozen','explicit snapshot serialization present statically','recursive JSON detachment present statically','restore atomicity ordering present statically','V2/V2.1 snapshot incompatibility classified'],'prohibited':['claim V2.1 importability','claim V2.1 runtime snapshot success','claim runtime nested-copy isolation','claim runtime tamper rejection','claim actual fs.read','claim protected-value lineage','claim guardrail effectiveness']}
        result={'version':VERSION,'created_at_utc':now(),'status':status,'classification':'STATIC_V2_1_REPAIR_CREATION_AND_IDENTITY_FREEZE','checks':{'total':len(checks),'passed':len(checks)-len(failed_ids),'failed':len(failed_ids),'failed_ids':failed_ids},'frozen_failure':{'artifact':ident(inputs['failed_evidence']),'error':failed.get('error'),'CL_017_candidate_control':byid.get('CL-017'),'CL_018_append_control':byid.get('CL-018'),'reviewed_defects':['SNAPSHOT_ASDICT_MAPPINGPROXY_RUNTIME_FAILURE','SHALLOW_TOOL_ARGS_COPY_NESTED_ALIASING']},'implementation':{'source_root':V21_ROOT,'files':inventory,'classes':['SuccessfulReadRecordV21','SuccessfulReadLedgerV21','TrustedReadOutcomeHookV21','LineageAwareExfilGuardrailV21','ExfilIntegrationBundleV21','ExfilIntegrationFactoryV21'],'schema_tag':'EXFIL.SUCCESSFUL.READ.LEDGER.V2.1','record_tag':'EXFIL.SUCCESSFUL.READ.RECORD.V2.1','snapshot_compatibility':compat},'readiness':{'independent_V2_1_static_qualification_eligible':passed,'controlled_V2_1_ledger_qualification_eligible':False,'controlled_actual_fs_read_eligible':False,'http_sink_eligible':False},'execution_boundaries':{'V2_1_created':True,'V2_1_imported':False,'V2_1_instantiated':False,'V2_modified':False,'V1_modified':False,'frozen_aicomp_sdk_modified':False,'snapshot_executed':False,'restore_executed':False,'candidate_extraction_executed':False,'actual_fs_read_executed':False,'http_sink_executed':False,'predicates_executed':False,'breach_executed':False,'Sandbox_instantiated':False,'Gym_executed':False,'models_used':False,'threads_executed':False,'external_effects_observed':False},'scientific_verdict':{'V2_1_identity':'ESTABLISHED' if passed else 'NOT_ESTABLISHED','V2_1_runtime_behavior':'NOT_EVALUATED','actual_source_retrieval':'NOT_EVALUATED','protected_value_lineage':'NOT_ESTABLISHED','guardrail_effectiveness':'NOT_EVALUATED','harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'},'claim_boundary':claim,'next_gate':'INDEPENDENT_V2_1_STATIC_QUALIFICATION' if passed else 'V2_1_STATIC_REPAIR_REVIEW'}
        o={'result':out/'v2_1_repair_freeze_result.json','checks':out/'v2_1_repair_freeze_checks.csv','inventory':out/'v2_1_repair_inventory.csv','failure':out/'v2_1_failed_run_freeze.json','compat':out/'v2_1_snapshot_compatibility.json','claim':out/'v2_1_repair_claim_boundary.json','binding':out/'v2_1_repair_binding.json'}
        wj(o['result'],result);wc(o['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']);wc(o['inventory'],inventory,['artifact','relative_path','role','size_bytes','sha256','path']);wj(o['failure'],result['frozen_failure']);wj(o['compat'],compat);wj(o['claim'],claim);wj(o['binding'],{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'inputs':{k:ident(v) for k,v in inputs.items()},'V2':{n:ident(v2root/n) for n in V2},'V1':{n:ident(v1root/n) for n in V1},'SDK':{r:ident(root/r) for r in SDK},'V2_1':{p.name:ident(p) for p in created},'V2_modified':False,'V1_modified':False,'frozen_aicomp_sdk_modified':False,'V2_1_imported':False})
        rows=[{**ident(p),'role':'V2_1_REPAIR_DERIVED'} for p in o.values()]+[{**ident(p),'role':'V2_1_REPAIR_INPUT'} for p in inputs.values()]+[{**ident(p),'role':'V2_1_IMPLEMENTATION'} for p in created]+[{**ident(v2root/n),'role':'BOUND_V2'} for n in V2]+[{**ident(v1root/n),'role':'BOUND_V1'} for n in V1]+[{**ident(root/r),'role':'BOUND_SDK'} for r in SDK]
        mp=out/'v2_1_repair_freeze_manifest.csv';wc(mp,rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'v2_1_repair_freeze_manifest_external_binding.json';wj(ep,{'version':VERSION,'created_at_utc':now(),'status':status,'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':sha(mp),'runner_sha256':sha(Path(__file__).resolve()),'failed_evidence_sha256':sha(inputs['failed_evidence']),'checks_total':len(checks),'checks_passed':len(checks)-len(failed_ids),'checks_failed':len(failed_ids),'failed_ids':failed_ids,'V2_1_identity_established':passed,'V2_modified':False,'V2_1_imported':False,'controlled_actual_fs_read_eligible':False,'next_gate':result['next_gate']})
        print(json.dumps({'status':status,'checks':f'{len(checks)-len(failed_ids)}/{len(checks)}','failed_ids':failed_ids,'failed_evidence_sha256':sha(inputs['failed_evidence']),'V2_1_files':{p.name:ident(p) for p in created},'V2_modified':False,'V2_1_imported':False,'manifest_sha256':sha(mp),'next_gate':result['next_gate']},indent=2))
    except Exception as exc:
        (out/'V2_1_REPAIR_FREEZE_FAILED.json').write_text(json.dumps({'version':VERSION,'created_at_utc':now(),'status':'V2_1_REPAIR_FREEZE_BLOCKED','error_type':type(exc).__name__,'error':str(exc),'checks_frozen':checks,'V2_modified':False,'V1_modified':False,'frozen_aicomp_sdk_modified':False,'V2_1_imported':False,'actual_fs_read_executed':False},indent=2),encoding='utf-8');raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for n in ['failed-evidence','failed-runner','v2-manifest','independent-manifest','corrected-manifest','project-root','output-dir']:p.add_argument('--'+n,required=True)
    return p.parse_args()
if __name__=='__main__':
    try:main(args())
    except Exception as exc:print(f'FAILED: {exc}',file=sys.stderr);raise SystemExit(1)
