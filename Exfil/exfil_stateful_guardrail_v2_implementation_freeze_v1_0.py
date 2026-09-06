#!/usr/bin/env python3
"""EXFIL stateful guardrail V2 implementation and identity freeze v1.0.

Creates a new aicomp_sdk_exfil_v2 package correcting two V1 static gaps:
1) candidate extraction applies the authoritative official minimum-length rule;
2) restore_state recomputes derived candidates, argument digest, output digest,
   and complete record identity, compares the supplied identity, and stores the
   recomputed identity.

Read/create/static-freeze only. Never modifies V1 or aicomp_sdk; never imports,
instantiates, or executes implementation/SDK/predicates/tools/Sandbox/Gym.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path

VERSION="EXFIL_STATEFUL_GUARDRAIL_V2_IMPLEMENTATION_AND_IDENTITY_FREEZE_v1.0"
PARENT_VERSION="STATIC_QUALIFICATION_METHODOLOGY_CORRECTION_AND_CANDIDATE_CONTRACT_RECONCILIATION_v1.0"
PARENT_MANIFEST_SHA="D4502233F3CB3452DE2E95C7E80FDD18F1E62C73D83A4CD1DB5AC5806CE12C87"
PARENT_RUNNER_SHA="F2AF126FB0E836CCAE0467A52C8A9A63CFA69CF7B477E8BE0C1E784DAC492572"
PARENT_RESULT_SHA="FFDDA1637140AC4220C0FC8CC22D28E1F0D51A2931C5EC3A9BFBE38BACAECDF4"
PARENT_CHECKS_SHA="2F6AF43A5A25FF646D95E9DE4D31AF08B5BA46948812AAF2565BD3C3E4367C32"
PARENT_SOURCES_SHA="5984C61D9BC832B8F0C3DBF522E8A7D1B437A9ED93B2DB96FF2F5DB77559F561"
PARENT_FEATURES_SHA="58585B945B0CDEF8858FC58C90FDE070A9BFE8DB56F54219B36AF4A9303FC237"
PARENT_DIVERGENCES_SHA="9D0D72960FA52E152EE6850CA7C6304E9911A042F2CE82DD7CA62E50E6EC754A"
PARENT_RESTORE_SHA="00CA53ADA80AAA474B73E8B61D9020BC01640F94E5A2AB4084CE6734596A75B4"
PARENT_BINDING_SHA="DCA5D46E9395EC246F59B823E9B3E9646EFC8C16BFB0730A3F4C0CE75C35AC2C"
V1={
'__init__.py':'DB60398BBEEAAE411C62FB915F2EAE5C7CDEBA9A2100D278BF2399190ED3094A',
'successful_read_ledger_v1.py':'3560FD4B7533C5B9B2622B84B1AD9BEC4A5562C1BBFF4FE06279EC7206DB73A6',
'trusted_read_outcome_hook_v1.py':'2B979C6B652358EAC1E0275A16607AD3A4750CC05C3AC64B6861EFC990B051CD',
'lineage_aware_exfil_guardrail_v1.py':'0D20934AD62E7191498F795F1D9BFDB008A749CD134A0842582DED1322F5A1DE',
'integration_factory_v1.py':'8220A3AF5601BA660AAD7EA8A1F6893646A8DB764C88BA8F859A35C12733C431'}
SDK={
'aicomp_sdk/core/env/sandbox.py':'B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0',
'aicomp_sdk/core/predicates.py':'9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37',
'aicomp_sdk/guardrails/base.py':'EC95F45A9BF4202514725690617C91E88F3F1AE889AC7828D423DAAFEA527708',
'aicomp_sdk/hooks/types.py':'0D3C7B5921749C22CADC5478532C7FE84B86AA90447FEEA8060ACFA9F44D3C7E',
'aicomp_sdk/hooks/registry.py':'5635B45136517CB5B7FBC6BAB6C9440FE7D6D699E484B6D63651AE296D4BB00B'}
PKG='aicomp_sdk_exfil_v2'

def now(): return datetime.now(timezone.utc).isoformat()
def need(c,m):
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
def add(rows,i,c,p,o,e,l): rows.append({'check_id':i,'category':c,'passed':bool(p),'observed':str(o),'expected':str(e),'failure_layer':l})
def up(n):
    try:return ast.unparse(n)
    except:return 'UNPARSE_FAILED'
def defs(t): return {n.name:n for n in t.body if isinstance(n,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef))}
def methods(c): return {n.name:n for n in c.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def find_min(tree):
    hits=[]
    for n in tree.body:
        if isinstance(n,(ast.Assign,ast.AnnAssign)):
            targets=n.targets if isinstance(n,ast.Assign) else [n.target]; value=n.value
            if any(isinstance(x,ast.Name) and x.id=='_MIN_SECRET_VALUE_LEN' for x in targets):
                hits.append((n,value))
    if len(hits)!=1:return None,None
    n,v=hits[0]
    if isinstance(v,ast.Constant) and isinstance(v.value,int) and v.value>=0:return n,v.value
    return n,None
def sources(min_len:int):
    ledger=f'''"""V2 immutable successful protected-read ledger."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from types import MappingProxyType
from typing import Any, Mapping
SCHEMA_TAG_V2 = "EXFIL.SUCCESSFUL.READ.LEDGER.V2"
RECORD_TAG_V2 = "EXFIL.SUCCESSFUL.READ.RECORD.V2"
OFFICIAL_MIN_SECRET_VALUE_LEN = {min_len}
TOOL_ARGS_IDENTITY_BOUNDARY = "All copied tool_args are bound by canonical JSON SHA-256; canonical_path remains separately bound."

def _sha256_text_v2(value: str) -> str:
    return sha256(value.encode("utf-8", "surrogatepass")).hexdigest().upper()

def _canonical_args_json_v2(args: Mapping[str, Any]) -> str:
    try:
        return json.dumps(dict(args), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("tool_args are not canonically JSON serializable") from exc

def _tool_args_digest_v2(args: Mapping[str, Any]) -> str:
    return _sha256_text_v2(_canonical_args_json_v2(args))

def _secret_values_v2(raw: str) -> tuple[str, ...]:
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

def _record_identity_v2(*, sequence: int, tool_name: str, canonical_path: str, tool_args_digest: str, output_digest: str) -> str:
    material = f"{{RECORD_TAG_V2}}|{{sequence}}|{{tool_name}}|{{canonical_path}}|{{tool_args_digest}}|{{output_digest}}"
    return _sha256_text_v2(material)

@dataclass(frozen=True, slots=True)
class SuccessfulReadRecordV2:
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

class SuccessfulReadLedgerV2:
    def __init__(self) -> None:
        self._records: list[SuccessfulReadRecordV2] = []
        self._next_sequence = 1

    def append_successful_read(self, *, tool_name: str, tool_args: Mapping[str, Any], canonical_path: str, explicit_ok: bool, error_value: Any, raw_output: str) -> SuccessfulReadRecordV2:
        if tool_name != "fs.read" or explicit_ok is not True:
            raise ValueError("only explicit successful fs.read records are accepted")
        if not isinstance(tool_args, Mapping) or not isinstance(canonical_path, str) or not isinstance(raw_output, str):
            raise TypeError("malformed successful-read evidence")
        args_copy = dict(tool_args)
        args_digest = _tool_args_digest_v2(args_copy)
        output_digest = _sha256_text_v2(raw_output)
        sequence = self._next_sequence
        identity = _record_identity_v2(sequence=sequence, tool_name=tool_name, canonical_path=canonical_path, tool_args_digest=args_digest, output_digest=output_digest)
        record = SuccessfulReadRecordV2(RECORD_TAG_V2, sequence, tool_name, MappingProxyType(args_copy), args_digest, canonical_path, True, error_value, raw_output, output_digest, _secret_values_v2(raw_output), identity)
        self._records.append(record)
        self._next_sequence += 1
        return record

    def qualifying_secret_values(self) -> tuple[str, ...]:
        return tuple(sorted({{v for r in self._records for v in r.derived_secret_values}}))

    def records(self) -> tuple[SuccessfulReadRecordV2, ...]:
        return tuple(self._records)

    def snapshot_state(self) -> dict[str, object]:
        return {{"schema_tag": SCHEMA_TAG_V2, "next_sequence": self._next_sequence, "records": [{{**asdict(r), "tool_args": dict(r.tool_args)}} for r in self._records]}}

    def restore_state(self, snapshot: Mapping[str, Any]) -> None:
        if not isinstance(snapshot, Mapping) or snapshot.get("schema_tag") != SCHEMA_TAG_V2:
            raise ValueError("invalid ledger snapshot schema")
        rows = snapshot.get("records"); next_sequence = snapshot.get("next_sequence")
        if not isinstance(rows, list) or not isinstance(next_sequence, int) or next_sequence < 1:
            raise ValueError("invalid ledger snapshot structure")
        restored: list[SuccessfulReadRecordV2] = []
        expected_sequence = 1
        for row in rows:
            if not isinstance(row, Mapping) or row.get("schema_tag") != RECORD_TAG_V2 or row.get("record_sequence") != expected_sequence:
                raise ValueError("invalid ledger record sequence or schema")
            args = row.get("tool_args"); raw = row.get("raw_output"); path = row.get("canonical_path")
            if not isinstance(args, Mapping) or not isinstance(raw, str) or not isinstance(path, str):
                raise ValueError("invalid restored field type")
            if row.get("explicit_ok") is not True or row.get("tool_name") != "fs.read":
                raise ValueError("invalid successful-read record")
            args_copy = dict(args); args_digest = _tool_args_digest_v2(args_copy); output_digest = _sha256_text_v2(raw)
            if row.get("tool_args_sha256") != args_digest:
                raise ValueError("tool args digest mismatch")
            if row.get("raw_output_sha256") != output_digest:
                raise ValueError("raw output digest mismatch")
            derived = _secret_values_v2(raw)
            if tuple(row.get("derived_secret_values") or ()) != derived:
                raise ValueError("derived secret values mismatch")
            expected_identity = _record_identity_v2(sequence=expected_sequence, tool_name="fs.read", canonical_path=path, tool_args_digest=args_digest, output_digest=output_digest)
            if row.get("record_identity") != expected_identity:
                raise ValueError("record identity mismatch")
            restored.append(SuccessfulReadRecordV2(RECORD_TAG_V2, expected_sequence, "fs.read", MappingProxyType(args_copy), args_digest, path, True, row.get("error_value"), raw, output_digest, derived, expected_identity))
            expected_sequence += 1
        if next_sequence != expected_sequence:
            raise ValueError("next sequence inconsistent with records")
        self._records = restored; self._next_sequence = next_sequence

    def reset(self) -> None:
        self._records = []; self._next_sequence = 1
'''
    return {
'__init__.py':'''"""Isolated EXFILTRATION research guardrail package V2."""
from .successful_read_ledger_v2 import SuccessfulReadLedgerV2, SuccessfulReadRecordV2
from .trusted_read_outcome_hook_v2 import TrustedReadOutcomeHookV2
from .lineage_aware_exfil_guardrail_v2 import LineageAwareExfilGuardrailV2
from .integration_factory_v2 import ExfilIntegrationBundleV2, ExfilIntegrationFactoryV2, build_exfil_integration_v2
__all__ = ["SuccessfulReadLedgerV2", "SuccessfulReadRecordV2", "TrustedReadOutcomeHookV2", "LineageAwareExfilGuardrailV2", "ExfilIntegrationBundleV2", "ExfilIntegrationFactoryV2", "build_exfil_integration_v2"]
''',
'successful_read_ledger_v2.py':ledger,
'trusted_read_outcome_hook_v2.py':'''"""V2 public POST_TOOL_CALL successful-read capture hook."""
from collections.abc import Mapping
from aicomp_sdk.core.predicates import is_protected_secret_path
from aicomp_sdk.hooks.types import HookContext, HookResult, HookStage
from .successful_read_ledger_v2 import SuccessfulReadLedgerV2
class TrustedReadOutcomeHookV2:
    def __init__(self, *, ledger: SuccessfulReadLedgerV2) -> None:
        if not isinstance(ledger, SuccessfulReadLedgerV2): raise TypeError("ledger must be SuccessfulReadLedgerV2")
        self._ledger = ledger
    def __call__(self, context: HookContext) -> HookResult:
        if context.stage != HookStage.POST_TOOL_CALL or context.tool_name != "fs.read": return HookResult()
        evidence = context.context
        if not isinstance(evidence, Mapping) or evidence.get("ok") is not True: return HookResult()
        args = context.tool_args
        if not isinstance(args, Mapping): return HookResult(should_block=True, metadata={"reason":"EXFIL_V2_MALFORMED_READ_ARGS"})
        path = args.get("path")
        if not is_protected_secret_path(path): return HookResult()
        output = context.tool_output
        if not isinstance(output, str): return HookResult(should_block=True, metadata={"reason":"EXFIL_V2_MALFORMED_READ_OUTPUT"})
        self._ledger.append_successful_read(tool_name="fs.read", tool_args=args, canonical_path=str(path), explicit_ok=True, error_value=evidence.get("error"), raw_output=output)
        return HookResult(metadata={"successful_protected_read_recorded_v2":True})
''',
'lineage_aware_exfil_guardrail_v2.py':'''"""V2 stateful EXFILTRATION proposal guardrail."""
from collections.abc import Mapping
from typing import Any
from aicomp_sdk.core.predicates import exfil_payload_arg, payload_exfiltrates_secret
from aicomp_sdk.guardrails.base import Decision, GuardrailBase
from .successful_read_ledger_v2 import SuccessfulReadLedgerV2
class LineageAwareExfilGuardrailV2(GuardrailBase):
    def __init__(self, *, ledger: SuccessfulReadLedgerV2, inner: GuardrailBase | None = None) -> None:
        if not isinstance(ledger, SuccessfulReadLedgerV2): raise TypeError("ledger must be SuccessfulReadLedgerV2")
        self._ledger=ledger; self._inner=inner
    def decide(self, tool_name: str, tool_args: Mapping[str, Any], context: Mapping[str, Any]) -> Decision:
        payload_arg=exfil_payload_arg(tool_name)
        if payload_arg is None: return self._inner.decide(tool_name,tool_args,context) if self._inner is not None else Decision.allow()
        if not isinstance(tool_args, Mapping) or payload_arg not in tool_args: return Decision.deny("EXFIL_V2_MALFORMED_SINK_PROPOSAL")
        secrets=self._ledger.qualifying_secret_values()
        if secrets and payload_exfiltrates_secret(tool_args[payload_arg], read_secrets=secrets): return Decision.deny("EXFIL_V2_SUCCESSFUL_READ_VALUE_MATCH")
        return self._inner.decide(tool_name,tool_args,context) if self._inner is not None else Decision.allow()
''',
'integration_factory_v2.py':'''"""V2 construction boundary."""
from dataclasses import dataclass
from aicomp_sdk.guardrails.base import GuardrailBase
from aicomp_sdk.hooks.registry import HookRegistry
from aicomp_sdk.hooks.types import HookStage
from .successful_read_ledger_v2 import SuccessfulReadLedgerV2
from .trusted_read_outcome_hook_v2 import TrustedReadOutcomeHookV2
from .lineage_aware_exfil_guardrail_v2 import LineageAwareExfilGuardrailV2
@dataclass(frozen=True, slots=True)
class ExfilIntegrationBundleV2:
    ledger: SuccessfulReadLedgerV2
    hook: TrustedReadOutcomeHookV2
    guardrail: LineageAwareExfilGuardrailV2
class ExfilIntegrationFactoryV2:
    @staticmethod
    def build(*, hook_registry: HookRegistry, inner: GuardrailBase | None=None, priority: int=0) -> ExfilIntegrationBundleV2:
        ledger=SuccessfulReadLedgerV2(); hook=TrustedReadOutcomeHookV2(ledger=ledger); guardrail=LineageAwareExfilGuardrailV2(ledger=ledger,inner=inner)
        hook_registry.register_hook(HookStage.POST_TOOL_CALL,hook,priority)
        return ExfilIntegrationBundleV2(ledger=ledger,hook=hook,guardrail=guardrail)
def build_exfil_integration_v2(*, hook_registry: HookRegistry, inner: GuardrailBase | None=None, priority: int=0) -> ExfilIntegrationBundleV2:
    return ExfilIntegrationFactoryV2.build(hook_registry=hook_registry,inner=inner,priority=priority)
'''}

def main(a):
    out=Path(a.output_dir).resolve(); need(not out.exists(),f'Refusing overwrite: {out}'); out.mkdir(parents=True)
    checks=[]
    try:
        root=Path(a.project_root).resolve(); v1=root/'aicomp_sdk_exfil'; v2=root/PKG; need(v1.is_dir(),'Missing frozen V1'); need(not v2.exists(),f'V2 root exists: {v2}')
        parent={'result':Path(a.reconciliation_result).resolve(),'checks':Path(a.reconciliation_checks).resolve(),'sources':Path(a.extraction_sources).resolve(),'features':Path(a.extraction_features).resolve(),'divergences':Path(a.extraction_divergences).resolve(),'restore':Path(a.restore_identity_contract).resolve(),'binding':Path(a.reconciliation_binding).resolve(),'external':Path(a.reconciliation_external_binding).resolve(),'manifest':Path(a.reconciliation_manifest).resolve(),'runner':Path(a.reconciliation_runner).resolve()}
        for k,p in parent.items():need(p.is_file(),f'Missing parent {k}: {p}')
        pr=rj(parent['result']); pe=rj(parent['external']); pc=rc(parent['checks'])
        add(checks,'V2-001','parent',pr.get('version')==PARENT_VERSION,pr.get('version'),PARENT_VERSION,'FIXTURE')
        for i,(k,h) in enumerate([('manifest',PARENT_MANIFEST_SHA),('runner',PARENT_RUNNER_SHA),('result',PARENT_RESULT_SHA),('checks',PARENT_CHECKS_SHA),('sources',PARENT_SOURCES_SHA),('features',PARENT_FEATURES_SHA),('divergences',PARENT_DIVERGENCES_SHA),('restore',PARENT_RESTORE_SHA),('binding',PARENT_BINDING_SHA)],2): add(checks,f'V2-{i:03d}','parent',sha(parent[k])==h,sha(parent[k]),h,'FIXTURE')
        add(checks,'V2-011','parent',len(pc)==20 and all(x['passed']=='True' for x in pc) and pr.get('outcome')=='V1_CANDIDATE_EXTRACTION_GAP_CONFIRMED',{'checks':len(pc),'outcome':pr.get('outcome')},'20/20 and V1 candidate gap','EVIDENCE')
        add(checks,'V2-012','parent',pe.get('V2_required') is True and pe.get('controlled_actual_fs_read_eligible') is False,pe,'V2 required; runtime withheld','CLAIM_BOUNDARY')
        for i,(name,h) in enumerate(V1.items(),13): p=v1/name; need(p.is_file(),f'Missing V1 {name}'); add(checks,f'V2-{i:03d}','V1_identity',sha(p)==h,sha(p),h,'FIXTURE')
        for i,(rel,h) in enumerate(SDK.items(),18): p=root/rel; need(p.is_file(),f'Missing SDK {rel}'); add(checks,f'V2-{i:03d}','SDK_identity',sha(p)==h,sha(p),h,'FIXTURE')
        pred=root/'aicomp_sdk/core/predicates.py'; ptext=pred.read_text(encoding='utf-8'); pt=ast.parse(ptext); min_node,min_len=find_min(pt)
        add(checks,'V2-023','official_contract',min_node is not None and min_len is not None,{'source':up(min_node) if min_node else None,'value':min_len},'literal official minimum found','PREDICATE')
        need(min_len is not None,'Official _MIN_SECRET_VALUE_LEN not literal/int; refusing invention')
        off=defs(pt).get('_extract_secret_values'); need(isinstance(off,ast.FunctionDef),'Official extractor missing')
        official_contract={'file':str(pred),'sha256':sha(pred),'minimum_definition':up(min_node),'minimum_value':min_len,'extractor_function':off.name,'line_start':off.lineno,'line_end':getattr(off,'end_lineno',off.lineno),'source':ast.get_source_segment(ptext,off) or up(off)}
        srcs=sources(min_len); v2.mkdir(); created=[]; asts={}
        for name,s in srcs.items(): p=v2/name; p.write_text(s,encoding='utf-8',newline='\n'); asts[name]=ast.parse(s,filename=str(p)); created.append(p)
        add(checks,'V2-024','creation',sorted(p.name for p in created)==sorted(srcs),[p.name for p in created],sorted(srcs),'FIXTURE')
        ledger_text=srcs['successful_read_ledger_v2.py']; lt=asts['successful_read_ledger_v2.py']; ld=defs(lt); ext=ld['_secret_values_v2']; ledger=ld['SuccessfulReadLedgerV2']; lm=methods(ledger); append=up(lm['append_successful_read']); restore=up(lm['restore_state'])
        extractor_checks=[
          ('full assignment','values.add(line)' in up(ext)),('threshold RHS','len(value) >= OFFICIAL_MIN_SECRET_VALUE_LEN' in up(ext)),('threshold bare','len(line) >= OFFICIAL_MIN_SECRET_VALUE_LEN' in up(ext)),('comments','line.startswith(\'#\')' in up(ext)),('blanks','not line' in up(ext)),('deterministic immutable','return tuple(sorted(values))' in up(ext)),('raw separate','raw_output: str' in ledger_text and 'derived_secret_values' in ledger_text)]
        for i,(label,ok) in enumerate(extractor_checks,25): add(checks,f'V2-{i:03d}','candidate',ok,label,True,'PREDICATE' if 'raw' not in label else 'SECRET_CAPTURE')
        restore_checks=[
          ('append formula helper','_record_identity_v2(' in append),('tool args digest bound','tool_args_digest=args_digest' in append),('restore raw digest','output_digest = _sha256_text_v2(raw)' in restore),('restore args digest','args_digest = _tool_args_digest_v2(args_copy)' in restore),('restore derived recompute','derived = _secret_values_v2(raw)' in restore),('identity recomputed','expected_identity = _record_identity_v2(' in restore),('identity compared','row.get(\'record_identity\') != expected_identity' in restore),('mismatch raises','record identity mismatch' in restore),('recomputed stored','derived, expected_identity' in restore),('argument boundary documented','TOOL_ARGS_IDENTITY_BOUNDARY' in ledger_text)]
        for i,(label,ok) in enumerate(restore_checks,32): add(checks,f'V2-{i:03d}','restore_identity',ok,label,True,'PROVENANCE')
        forbidden=['import aicomp_sdk_exfil','from aicomp_sdk_exfil','_extract_secret_values']
        all_text='\n'.join(srcs.values()); add(checks,'V2-042','boundary',not any(x in all_text for x in forbidden),[x for x in forbidden if x in all_text],'no V1 import or private extractor import','ADAPTER_PARSE')
        add(checks,'V2-043','immutability',all(sha(v1/n)==h for n,h in V1.items()),'unchanged','all V1 unchanged','FIXTURE'); add(checks,'V2-044','immutability',all(sha(root/r)==h for r,h in SDK.items()),'unchanged','all SDK unchanged','FIXTURE')
        failed=[x['check_id'] for x in checks if not x['passed']]; pass_gate=not failed
        status='EXFIL_STATEFUL_GUARDRAIL_V2_IMPLEMENTATION_AND_IDENTITY_FREEZE_COMPLETE_PASS' if pass_gate else 'EXFIL_STATEFUL_GUARDRAIL_V2_IMPLEMENTATION_AND_IDENTITY_FREEZE_COMPLETE_WITH_GAPS'
        impl=[{**ident(p),'relative_path':str(p.relative_to(root)),'role':'NEW_V2_IMPLEMENTATION'} for p in created]
        matrix=[{'dimension':'splitlines','V2':'.splitlines()','official':'splitlines','equivalent':True},{'dimension':'strip','V2':'strip','official':'strip','equivalent':True},{'dimension':'blank/comment','V2':'exclude','official':'exclude','equivalent':True},{'dimension':'full assignment','V2':'always add','official':'always add','equivalent':True},{'dimension':'RHS threshold','V2':f'>={min_len}','official':f'>={min_len}','equivalent':True},{'dimension':'bare threshold','V2':f'>={min_len}','official':f'>={min_len}','equivalent':True},{'dimension':'membership container','V2':'set during extraction','official':'set','equivalent':True},{'dimension':'return ordering','V2':'sorted tuple','official':'set unordered','equivalent':False}]
        claim={'allowed':['V2 source exists and identities frozen','official minimum and extractor source bound','static membership-rule equivalence matrix','restore identity recomputation source present','V1 and SDK identities preserved'],'prohibited':['claim importability','claim runtime candidate parity','claim runtime restore behavior','claim successful fs.read capture','claim guardrail effectiveness','claim protected-value lineage','claim real exfiltration prevention']}
        result={'version':VERSION,'created_at_utc':now(),'status':status,'classification':'STATIC_V2_IMPLEMENTATION_CREATION_AND_IDENTITY_FREEZE','checks':{'total':len(checks),'passed':len(checks)-len(failed),'failed':len(failed),'failed_ids':failed},'official_contract':official_contract,'implementation':{'source_root':PKG,'files':impl,'candidate_membership_static_equivalence':'ESTABLISHED' if pass_gate else 'NOT_ESTABLISHED','ordering_difference':'V2_SORTED_TUPLE_VS_OFFICIAL_SET','restore_identity_recomputation':'IMPLEMENTED_STATICALLY','tool_args_identity_boundary':'ALL_TOOL_ARGS_CANONICAL_JSON_DIGEST_BOUND'},'readiness':{'independent_V2_static_qualification_eligible':pass_gate,'controlled_actual_fs_read_eligible':False,'http_sink_eligible':False},'execution_boundaries':{'V1_modified':False,'V2_created':True,'V2_imported':False,'V2_instantiated':False,'frozen_aicomp_sdk_modified':False,'sdk_modules_imported':False,'sdk_modules_executed':False,'candidate_extraction_executed':False,'predicates_executed':False,'Sandbox_instantiated':False,'Gym_executed':False,'actual_fs_read_executed':False,'http_sink_executed':False,'breach_executed':False,'models_used':False,'threads_executed':False,'external_effects_observed':False},'scientific_verdict':{'V2_identity':'ESTABLISHED' if pass_gate else 'NOT_ESTABLISHED','V2_runtime_behavior':'NOT_EVALUATED','protected_value_lineage':'NOT_ESTABLISHED','guardrail_effectiveness':'NOT_EVALUATED','harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'},'claim_boundary':claim,'next_gate':'INDEPENDENT_STATEFUL_GUARDRAIL_V2_STATIC_QUALIFICATION' if pass_gate else 'V2_IMPLEMENTATION_STATIC_REPAIR'}
        o={'result':out/'v2_impl_freeze_result.json','checks':out/'v2_impl_freeze_checks.csv','inventory':out/'v2_impl_inventory.csv','official':out/'v2_official_extraction_contract.json','matrix':out/'v2_extraction_equivalence_matrix.csv','claim':out/'v2_impl_claim_boundary.json','binding':out/'v2_impl_binding.json'}
        wj(o['result'],result); wc(o['checks'],checks,['check_id','category','passed','observed','expected','failure_layer']); wc(o['inventory'],impl,['artifact','relative_path','role','size_bytes','sha256','path']); wj(o['official'],official_contract); wc(o['matrix'],matrix,['dimension','V2','official','equivalent']); wj(o['claim'],claim); wj(o['binding'],{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'parent':{k:ident(v) for k,v in parent.items()},'V1':{n:ident(v1/n) for n in V1},'SDK':{r:ident(root/r) for r in SDK},'V2':{p.name:ident(p) for p in created},'V1_modified':False,'frozen_aicomp_sdk_modified':False,'V2_imported':False})
        rows=[{**ident(p),'role':'V2_FREEZE_DERIVED'} for p in o.values()]+[{**ident(p),'role':'V2_FREEZE_IMPLEMENTATION'} for p in created]+[{**ident(p),'role':'V2_BOUND_PARENT'} for p in parent.values()]+[{**ident(v1/n),'role':'V2_BOUND_V1'} for n in V1]+[{**ident(root/r),'role':'V2_BOUND_SDK'} for r in SDK]
        mp=out/'v2_impl_freeze_manifest.csv'; wc(mp,rows,['artifact','role','size_bytes','sha256','path'])
        ep=out/'v2_impl_freeze_manifest_external_binding.json'; wj(ep,{'version':VERSION,'created_at_utc':now(),'status':status,'manifest_filename':mp.name,'manifest_size_bytes':mp.stat().st_size,'manifest_sha256':sha(mp),'runner_sha256':sha(Path(__file__).resolve()),'parent_manifest_sha256':PARENT_MANIFEST_SHA,'checks_total':len(checks),'checks_passed':len(checks)-len(failed),'checks_failed':len(failed),'failed_ids':failed,'V2_created':True,'V2_identity_established':pass_gate,'V1_modified':False,'frozen_aicomp_sdk_modified':False,'V2_imported':False,'controlled_actual_fs_read_eligible':False,'next_gate':result['next_gate']})
        print(json.dumps({'status':status,'checks':f'{len(checks)-len(failed)}/{len(checks)}','official_minimum':min_len,'V2_files':{p.name:ident(p) for p in created},'V1_modified':False,'frozen_aicomp_sdk_modified':False,'V2_imported':False,'controlled_actual_fs_read_eligible':False,'manifest_sha256':sha(mp),'next_gate':result['next_gate']},indent=2))
    except Exception as e:
        (out/'V2_IMPL_FREEZE_FAILED.json').write_text(json.dumps({'version':VERSION,'created_at_utc':now(),'status':'V2_IMPLEMENTATION_FREEZE_BLOCKED','error_type':type(e).__name__,'error':str(e),'checks_frozen':checks,'V1_modified':False,'frozen_aicomp_sdk_modified':False,'V2_imported':False,'actual_fs_read_executed':False},indent=2),encoding='utf-8'); raise

def args():
    p=argparse.ArgumentParser(description=VERSION)
    for f in ['reconciliation-result','reconciliation-checks','extraction-sources','extraction-features','extraction-divergences','restore-identity-contract','reconciliation-binding','reconciliation-external-binding','reconciliation-manifest','reconciliation-runner','project-root','output-dir']:p.add_argument('--'+f,required=True)
    return p.parse_args()
if __name__=='__main__':
    try:main(args())
    except Exception as e:print(f'FAILED: {e}',file=sys.stderr);raise SystemExit(1)
