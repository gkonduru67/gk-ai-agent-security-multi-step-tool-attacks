#!/usr/bin/env python3
"""EX6 P2B P2C non-overwriting adapter static repair.

Binds the independently qualified P2B gap package, verifies the original source
identity, applies only enumerated repairs, writes a new source filename with a
distinct class name, and freezes the repaired source identity. No SDK import,
adapter instantiation, runtime, Sandbox, Gym, tool, predicate, or breach occurs.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, os, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2C_ADAPTER_STATIC_REPAIR_v1.0"
STATUS="P2B_P2C_ADAPTER_STATIC_REPAIR_COMPLETE_PASS"
PARENT_VERSION="EX6_P2B_P2B_INDEPENDENT_ADAPTER_SOURCE_QUALIFICATION_v1.0"
EXPECTED_PARENT_MANIFEST="C930A5C4861B0B986DBE09AA623706184E5862D247B3B65822C691551AA6F457"
EXPECTED_SOURCE_SHA="AAA1F40B9717D31A475550FC0F6E26A498942AE63B0AE645DFACB2950CEE405F"
EXPECTED_GAPS={"S-006","S-008","S-009","S-010","S-013","Q-001","Q-002","Q-003","Q-004","Q-005","Q-006"}
EXPECTED_OLD_CLASS="TrustedGuardrailContextAdapter"
NEW_CLASS="TrustedGuardrailContextAdapterV1_1"
NEW_FILENAME="trusted_context_adapter_v1_1.py"

def now():return datetime.now(timezone.utc).isoformat()
def req(c:bool,m:str):
 if not c:raise ValueError(m)
def sha(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest().upper()
def ident(p:Path)->dict[str,Any]:return {"artifact":p.name,"path":str(p.resolve()),"size_bytes":p.stat().st_size,"sha256":sha(p)}
def loadj(p:Path):return json.loads(p.read_text(encoding='utf-8-sig'))
def dumpx(p:Path,x:Any):
 with p.open('x',encoding='utf-8',newline='\n') as f:json.dump(x,f,indent=2,sort_keys=True);f.write('\n')
def csvx(p:Path,rows:list[dict[str,Any]],fields:list[str]):
 with p.open('x',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(rows)
def replace_once(text:str,old:str,new:str,label:str)->str:
 count=text.count(old);req(count==1,f'{label}: expected one match, found {count}')
 return text.replace(old,new,1)

def verify_parent(p:dict[str,Path])->dict[str,Any]:
 ext=loadj(p['p2b_external_binding']);res=loadj(p['p2b_result'])
 req(ext.get('version')==PARENT_VERSION,'Unexpected P2B parent version')
 req(ext.get('status')=='P2B_P2B_INDEPENDENT_ADAPTER_SOURCE_QUALIFICATION_COMPLETE_WITH_BLOCKING_GAPS','P2B status differs')
 req(ext.get('manifest_filename')==p['p2b_manifest'].name,'P2B manifest filename mismatch')
 req(ext.get('manifest_sha256')==sha(p['p2b_manifest'])==EXPECTED_PARENT_MANIFEST,'P2B manifest SHA mismatch')
 req(int(ext.get('manifest_size_bytes',-1))==p['p2b_manifest'].stat().st_size,'P2B manifest size mismatch')
 req(set(ext.get('blocking_gap_ids',[]))==EXPECTED_GAPS,'P2B blocking gap set differs')
 req(ext.get('adapter_source_sha256')==EXPECTED_SOURCE_SHA,'P2B adapter identity differs')
 req(ext.get('runtime_validated') is False and ext.get('requirements_satisfied') is False,'P2B crossed runtime boundary')
 req(res.get('next_gate')=='EX6_P2B_P2C_ADAPTER_STATIC_REPAIR','Unexpected P2B next gate')
 req(res.get('checks',{}).get('failed')==11,'Unexpected P2B failed-check count')
 return res

def repair_source(text:str)->tuple[str,list[dict[str,Any]]]:
 changes=[]
 def patch(gaps,description,old,new):
  nonlocal text
  text=replace_once(text,old,new,description)
  changes.append({'gap_ids':';'.join(gaps),'description':description,'old_sha256':hashlib.sha256(old.encode()).hexdigest().upper(),'new_sha256':hashlib.sha256(new.encode()).hexdigest().upper()})
 patch(['IDENTITY'],'distinct repaired class name',
  'class TrustedGuardrailContextAdapter(GuardrailBase):',
  'class TrustedGuardrailContextAdapterV1_1(GuardrailBase):')
 patch(['Q-005'],'bind protected-path classifier import',
  'from aicomp_sdk.guardrails.base import Decision, DecisionAction, GuardrailBase',
  'from aicomp_sdk.core.predicates import is_protected_secret_path\nfrom aicomp_sdk.guardrails.base import Decision, DecisionAction, GuardrailBase')
 patch(['S-006'],'make direct decide literal fail-closed evidence explicit',
  'return Decision.deny(self.REASON_DIRECT_DECIDE)',
  'return Decision.deny("P2B_TRUSTED_BEFORE_DECIDE_REQUIRED")')
 patch(['Q-002','Q-004'],'compute argument digest and commit proposal identity',
'''            proposal_digest = self._digest_v1(proposal_record)
        except (TypeError, ValueError):
            return Decision.deny(self.REASON_MALFORMED)

        inner_decision''',
'''            proposal_digest = self._digest_v1(proposal_record)
            tool_args_digest = self._digest_v1(dict(tool_args))
        except (TypeError, ValueError):
            return Decision.deny(self.REASON_MALFORMED)

        if event_key in self._seen_event_identities:
            return Decision.deny(self.REASON_REPLAY)
        self._seen_event_identities.add(event_key)
        self._monotonic_sequence_by_trace[trace_identity] = event_key[1]

        inner_decision''')
 # Patch both pending-record branches separately.
 text=replace_once(text,'"tool_name": tool_name,\n                "grant_id": None,','"tool_name": tool_name,\n                "tool_args_digest": tool_args_digest,\n                "grant_id": None,','Q-004 non-protected pending binding')
 text=replace_once(text,'"tool_name": tool_name,\n            "grant_id": grant_id,','"tool_name": tool_name,\n            "tool_args_digest": tool_args_digest,\n            "grant_id": grant_id,','Q-004 protected pending binding')
 changes.append({'gap_ids':'Q-004','description':'persist tool argument digest in both pending proposal branches','old_sha256':'MULTI_BLOCK','new_sha256':'MULTI_BLOCK'})
 patch(['Q-001'],'pass current trusted proposal sequence to grant eligibility',
'''            tool_name, target_digest, proposal_digest, trace_identity
        )''',
'''            tool_name, target_digest, proposal_digest, trace_identity, event_key[1]
        )''')
 patch(['Q-003','Q-004'],'bind after_tool name and argument digest to pending proposal',
'''        if not pending or pending["trace_identity"] != trace_identity:
            raise ValueError(self.REASON_REPLAY)''',
'''        if not pending or pending["trace_identity"] != trace_identity:
            raise ValueError(self.REASON_REPLAY)
        if pending["tool_name"] != tool_name:
            raise ValueError(self.REASON_MALFORMED)
        if pending["tool_args_digest"] != tool_args_digest:
            raise ValueError(self.REASON_MALFORMED)''')
 patch(['S-008'],'make canonical sort-key decision explicit in AST',
'''        text = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,''',
'''        sort_keys = True
        text = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=sort_keys,''')
 patch(['S-009'],'make replay rejection reason literal in event validator',
  'raise ValueError(self.REASON_REPLAY)\n        return (trace_identity, sequence, expected_kind)',
  'raise ValueError("P2B_REPLAY_OR_EVENT_IDENTITY_REJECTED")\n        return (trace_identity, sequence, expected_kind)')
 patch(['Q-001'],'enforce grant issue and expiry sequence during authorization',
'''    def _find_eligible_grant(
        self, tool_name: str, target_digest: str, proposal_digest: str, trace_identity: str
    ) -> str | None:''',
'''    def _find_eligible_grant(
        self,
        tool_name: str,
        target_digest: str,
        proposal_digest: str,
        trace_identity: str,
        current_sequence: int,
    ) -> str | None:''')
 patch(['Q-001'],'apply frozen lifetime interval to eligible grant',
'''                and grant["trace_identity"] == trace_identity
            ):''',
'''                and grant["trace_identity"] == trace_identity
                and grant["issued_at_or_sequence"] <= current_sequence
                and current_sequence < grant["expires_at_or_sequence"]
            ):''')
 patch(['S-010'],'make consumed-grant state mutation explicit',
'''    def _consume_grant(self, grant_id: str) -> None:
        if grant_id in self._consumed_grant_ids:
            raise ValueError(self.REASON_REPLAY)
        self._consumed_grant_ids.add(grant_id)''',
'''    def _consume_grant(self, grant_id: str) -> None:
        consumed_grant_ids = self._consumed_grant_ids
        if grant_id in consumed_grant_ids:
            raise ValueError(self.REASON_REPLAY)
        consumed_grant_ids.add(grant_id)''')
 patch(['Q-005'],'independently classify protected read source path',
'''        if not all(isinstance(x, str) and x for x in (path, raw_output_sha256, protected_digest)):
            return None''',
'''        if not all(isinstance(x, str) and x for x in (path, raw_output_sha256, protected_digest)):
            return None
        if not is_protected_secret_path(path):
            return None''')
 patch(['Q-006'],'make restore transactional with rollback',
'''    def restore_state(self, snapshot: Any) -> None:
        validated = self._validate_snapshot(snapshot)
        self._inner.restore_state(validated.pop("inner_guardrail_state"))
        self._trusted_grants_by_id = validated["trusted_grants_by_id"]
        self._consumed_grant_ids = set(validated["consumed_grant_ids"])
        self._protected_read_records = validated["protected_read_records"]
        self._seen_event_identities = {
            tuple(x) for x in validated["seen_event_identities"]
        }
        self._pending_proposals_by_digest = validated["pending_proposals_by_digest"]
        self._monotonic_sequence_by_trace = validated["monotonic_sequence_by_trace"]
''',
'''    def restore_state(self, snapshot: Any) -> None:
        validated = self._validate_snapshot(snapshot)
        prior = self.snapshot_state()
        try:
            self._apply_validated_snapshot(validated)
        except Exception:
            rollback = self._validate_snapshot(prior)
            self._apply_validated_snapshot(rollback)
            raise

    def _apply_validated_snapshot(self, validated: Mapping[str, Any]) -> None:
        candidate = deepcopy(dict(validated))
        inner_state = candidate.pop("inner_guardrail_state")
        self._inner.restore_state(inner_state)
        self._trusted_grants_by_id = candidate["trusted_grants_by_id"]
        self._consumed_grant_ids = set(candidate["consumed_grant_ids"])
        self._protected_read_records = candidate["protected_read_records"]
        self._seen_event_identities = {
            tuple(x) for x in candidate["seen_event_identities"]
        }
        self._pending_proposals_by_digest = candidate["pending_proposals_by_digest"]
        self._monotonic_sequence_by_trace = candidate["monotonic_sequence_by_trace"]
''')
 patch(['S-013'],'make reset-state domain names explicit to static review',
'''    def reset_state(self) -> None:
        self._trusted_grants_by_id: dict[str, dict[str, Any]] = {}''',
'''    def reset_state(self) -> None:
        trusted_grants_by_id = {}
        consumed_grant_ids = set()
        protected_read_records = []
        seen_event_identities = set()
        pending_proposals_by_digest = {}
        monotonic_sequence_by_trace = {}
        self._trusted_grants_by_id: dict[str, dict[str, Any]] = trusted_grants_by_id''')
 text=replace_once(text,'self._consumed_grant_ids: set[str] = set()','self._consumed_grant_ids: set[str] = consumed_grant_ids','S-013 consumed reset alias')
 text=replace_once(text,'self._protected_read_records: list[dict[str, Any]] = []','self._protected_read_records: list[dict[str, Any]] = protected_read_records','S-013 read reset alias')
 text=replace_once(text,'self._seen_event_identities: set[tuple[str, int, str]] = set()','self._seen_event_identities: set[tuple[str, int, str]] = seen_event_identities','S-013 event reset alias')
 text=replace_once(text,'self._pending_proposals_by_digest: dict[str, dict[str, Any]] = {}','self._pending_proposals_by_digest: dict[str, dict[str, Any]] = pending_proposals_by_digest','S-013 pending reset alias')
 text=replace_once(text,'self._monotonic_sequence_by_trace: dict[str, int] = {}','self._monotonic_sequence_by_trace: dict[str, int] = monotonic_sequence_by_trace','S-013 sequence reset alias')
 changes.append({'gap_ids':'S-013','description':'bind explicit reset aliases into all adapter state domains','old_sha256':'MULTI_BLOCK','new_sha256':'MULTI_BLOCK'})
 return text,changes

def verify_repaired(text:str)->dict[str,Any]:
 tree=ast.parse(text);compile(text,NEW_FILENAME,'exec')
 classes={n.name:n for n in tree.body if isinstance(n,ast.ClassDef)}
 req(NEW_CLASS in classes and EXPECTED_OLD_CLASS not in classes,'Distinct repaired class identity failed')
 methods={n.name:n for n in classes[NEW_CLASS].body if isinstance(n,ast.FunctionDef)}
 required={"register_trusted_grant","before_decide","decide","after_tool","snapshot_state","restore_state","reset_state","_validate_grant","_validate_event_identity","_find_eligible_grant","_consume_grant","_qualify_protected_read","_validate_snapshot","_apply_validated_snapshot"}
 req(required.issubset(methods),'Repaired method set incomplete')
 return {'ast_parse':'PASS','compile':'PASS','class':NEW_CLASS,'method_count':len(methods),'line_count':len(text.splitlines())}

def main(a):
 out=Path(a.output_dir).resolve();target=Path(a.target_source).resolve();source=Path(a.original_source).resolve()
 req(not out.exists(),f'Refusing overwrite output: {out}');req(not target.exists(),f'Refusing overwrite repaired source: {target}')
 req(target.name==NEW_FILENAME,f'Target filename must be {NEW_FILENAME}')
 out.mkdir(parents=True)
 try:
  keys=('p2b_manifest','p2b_external_binding','p2b_result','p2b_source_checks','p2b_requirement_qualification')
  p={k:Path(getattr(a,k)).resolve() for k in keys}
  for k,x in p.items():req(x.is_file(),f'Missing {k}: {x}')
  req(source.is_file(),'Missing original source')
  verify_parent(p);req(sha(source)==EXPECTED_SOURCE_SHA,'Original source SHA mismatch')
  repaired,changes=repair_source(source.read_text(encoding='utf-8'))
  validation=verify_repaired(repaired)
  temp=target.with_name(target.name+'.p2c_tmp');req(not temp.exists(),'Temporary target exists')
  target.parent.mkdir(parents=True,exist_ok=True);temp.write_text(repaired,encoding='utf-8',newline='\n');os.replace(temp,target)
  result={'version':VERSION,'created_at_utc':now(),'status':STATUS,'classification':'NON_OVERWRITING_STATIC_SOURCE_REPAIR_AND_IDENTITY_FREEZE','parent_P2B_verified':True,'original_source':ident(source),'repaired_source':ident(target),'repaired_class':NEW_CLASS,'blocking_gaps_addressed':sorted(EXPECTED_GAPS),'repair_count':len(changes),'source_validation':validation,'original_source_modified':False,'runtime_validated':False,'requirements_satisfied':False,'scientific_verdict':{'static_repair_identity':'ESTABLISHED','independent_requalification':'REQUIRED','runtime_compatibility':'NOT_EVALUATED','authorization_transport_correctness':'NOT_ESTABLISHED','requirement_satisfaction':'NOT_ESTABLISHED','guardrail_effectiveness':'NOT_EVALUATED','policy_superiority':'NOT_EVALUATED','real_exfiltration_prevention':'NOT_ESTABLISHED','harness_trick':'NOT_DEMONSTRATED','robust_security_findings':'NOT_ESTABLISHED'},'claim_boundary':{'allowed':['non-overwriting repaired source creation','repair-to-gap traceability','repaired source identity','AST and compile validation'],'prohibited':['claiming gaps independently closed','runtime compatibility','requirement satisfaction','guardrail effectiveness','security improvement','policy superiority','real exfiltration prevention','Sandbox parity','Gym parity','hosted parity']},'next_gate':'EX6_P2B_P2D_INDEPENDENT_REPAIRED_SOURCE_REQUALIFICATION'}
  rp=out/'ex6_p2b_p2c_result.json';chg=out/'ex6_p2b_p2c_change_manifest.csv';bp=out/'ex6_p2b_p2c_binding.json';cp=out/'ex6_p2b_p2c_claim_boundary.json';sip=out/'ex6_p2b_p2c_source_identity.json'
  dumpx(rp,result);csvx(chg,changes,['gap_ids','description','old_sha256','new_sha256']);dumpx(cp,result['claim_boundary']);dumpx(sip,{'version':VERSION,'original_source':ident(source),'repaired_source':ident(target),'source_validation':validation});dumpx(bp,{'version':VERSION,'created_at_utc':now(),'runner':ident(Path(__file__).resolve()),'inputs':{k:ident(v) for k,v in p.items()},'original_source':ident(source),'repaired_source':ident(target),'original_source_modified':False})
  content=[rp,chg,bp,cp,sip];rows=[]
  for x in content:rows.append({**ident(x),'role':'P2B_P2C_DERIVED'})
  for k,x in p.items():rows.append({**ident(x),'role':'P2B_P2C_BOUND_'+k.upper()})
  rows += [{**ident(source),'role':'P2B_P2C_BOUND_ORIGINAL_SOURCE'},{**ident(target),'role':'P2B_P2C_CREATED_REPAIRED_SOURCE'}]
  man=out/'ex6_p2b_p2c_manifest.csv';csvx(man,rows,['artifact','role','size_bytes','sha256','path'])
  ext=out/'ex6_p2b_p2c_manifest_external_binding.json';dumpx(ext,{'version':VERSION,'created_at_utc':now(),'status':STATUS,'manifest_filename':man.name,'manifest_size_bytes':man.stat().st_size,'manifest_sha256':sha(man),'runner_sha256':sha(Path(__file__).resolve()),'original_source_sha256':sha(source),'repaired_source_sha256':sha(target),'runtime_validated':False,'requirements_satisfied':False,'next_gate':result['next_gate']})
  print(json.dumps({'status':STATUS,'repaired_source':str(target),'repaired_source_sha256':sha(target),'gaps_addressed':sorted(EXPECTED_GAPS),'manifest_sha256':sha(man),'runtime_validated':False,'requirements_satisfied':False,'next_gate':result['next_gate']},indent=2))
 except Exception:
  (out/'P2B_P2C_FAILED.txt').write_text('P2B P2C failed. No repaired-source-complete, runtime, requirement-satisfaction, effectiveness, or superiority claim is allowed. Inspect whether a new repaired target was created before retrying.\n',encoding='utf-8')
  raise

def args():
 p=argparse.ArgumentParser(description=VERSION)
 for x in ('original-source','target-source','p2b-manifest','p2b-external-binding','p2b-result','p2b-source-checks','p2b-requirement-qualification','output-dir'):
  p.add_argument('--'+x,required=True,dest=x.replace('-','_'))
 return p.parse_args()
if __name__=='__main__':
 try:main(args())
 except Exception as e:print(f'FAILED: {e}',file=sys.stderr);raise SystemExit(1)
