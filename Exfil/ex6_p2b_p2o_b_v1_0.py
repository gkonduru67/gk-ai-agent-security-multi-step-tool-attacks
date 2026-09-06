#!/usr/bin/env python3
"""P2O-B authorized source generation and static inventory.

Creates exactly three P2O-A-authorized source files using exclusive creation.
Performs AST parsing and static inventories only. It never imports generated or
SDK modules and never executes generated symbols, tools, fs.read, Sandbox, Gym,
predicates, breach logic, models, or effects.
"""
from __future__ import annotations
import argparse, ast, csv, hashlib, json, re, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION="EX6_P2B_P2O_B_AUTHORIZED_SOURCE_GENERATION_v1.0"
PARENT_VERSION="EX6_P2B_P2O_A_IMPLEMENTATION_AUTHORIZATION_AND_EXACT_SOURCE_CONTRACT_FREEZE_v1.0"
PARENT_STATUS="P2O_A_IMPLEMENTATION_AUTHORIZATION_AND_EXACT_SOURCE_CONTRACT_FREEZE_COMPLETE_PASS"
PARENT_MANIFEST_SHA="CB85AAE890FF76583829067242A74ABF0BB9E7B0FD231B34BC39C9917740634A"
PARENT_RUNNER_SHA="67D72F6120483F5C6D20EB474559C78F1E779B588E11CE89FD7167DF744575A5"
AUTHORIZATION_ID="P2O-A-AUTH-v1.0"
CANON_SPEC_SHA="0551D83F26541E691420533FFDCA7606070AEF8FB68924FAFB5D8B4A539980B1"
CANON_VECTORS_SHA="EAD37C1011A92CDE36A86248C0ED4AB475BFEF3A52CA633DE14E2E0AEF0D4146"
AUTHORIZED={
 "AUTH-F01":"aicomp_sdk/core/env/trusted_outcome_transport_v1.py",
 "AUTH-F02":"aicomp_sdk/core/env/sandbox_trusted_bridge_v1.py",
 "AUTH-F03":"aicomp_sdk/core/tools/fs_trusted_result_v1.py",
}
PROTECTED={
 "aicomp_sdk/core/env/sandbox.py":"B781375C5AAE3C2533F6992AAE6D3C65CA56B7077822F1A27955756BEF1168D0",
 "aicomp_sdk/core/predicates.py":"9D9DE5118D8883A0074A5405ED85CF2DEC3F68E8516908CBC48F409E3BA56F37",
 "aicomp_sdk/core/tools/fs.py":"4B8C54032ED807CE4C35BAB403EE622141881158E10F600A4B6D329E6D6F95B8",
 "aicomp_sdk/guardrails/optimal.py":"6724FEDF7BBF3E67DFCDD564BA8A73463E0F783D5C84E0A70DCEFF40C1BC61ED",
 "aicomp_sdk/guardrails/trusted_context_adapter_v1_1.py":"BFDE535B805979FF6D13BA0970A9A13466192F1B1111B02CE8B8BB8C670FFA99",
}

SOURCES={
"AUTH-F01":'''"""Trusted outcome transport v1. Static implementation; runtime not qualified."""
from __future__ import annotations
from dataclasses import dataclass, field
import hashlib
import json
import threading
import unicodedata
from typing import Any

_RAW_DOMAIN = b"P2N.RAW_OUTPUT.V1"
_PROTECTED_DOMAIN = b"P2N.PROTECTED_BINDING.V1"

def _frame(tag: bytes, payload: bytes) -> bytes:
    return tag + str(len(payload)).encode("ascii") + b":" + payload

def canonicalize_post_hook_output_v1(value: object) -> bytes:
    if value is None:
        return _frame(b"N", b"")
    if isinstance(value, bool):
        return _frame(b"B", b"1" if value else b"0")
    if isinstance(value, int) and not isinstance(value, bool):
        return _frame(b"I", str(value).encode("ascii"))
    if isinstance(value, float):
        raise TypeError("float prohibited")
    if isinstance(value, str):
        return _frame(b"S", unicodedata.normalize("NFC", value).encode("utf-8"))
    if isinstance(value, bytes):
        return _frame(b"Y", value)
    if isinstance(value, list):
        return _frame(b"L", b"".join(canonicalize_post_hook_output_v1(x) for x in value))
    if isinstance(value, tuple):
        raise TypeError("tuple prohibited")
    if isinstance(value, dict):
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("map keys must be strings")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise ValueError("duplicate key after NFC normalization")
            normalized[normalized_key] = item
        payload = b""
        for key in sorted(normalized, key=lambda x: x.encode("utf-8")):
            payload += _frame(b"K", key.encode("utf-8"))
            payload += canonicalize_post_hook_output_v1(normalized[key])
        return _frame(b"M", payload)
    raise TypeError(f"unsupported type: {type(value).__name__}")

def compute_raw_output_sha256_v1(value: object) -> str:
    canonical = canonicalize_post_hook_output_v1(value)
    return hashlib.sha256(_RAW_DOMAIN + b"\\x00" + canonical).hexdigest().upper()

def compute_protected_value_bound_digest_v1(trace_identity: str, proposal_digest: str, outcome_event_identity: str, canonical_source_path: str, raw_output_sha256: str) -> str:
    fields = [trace_identity, proposal_digest, outcome_event_identity, canonical_source_path, raw_output_sha256]
    if not all(isinstance(x, str) and x for x in fields):
        raise ValueError("all binding fields must be nonempty strings")
    if len(raw_output_sha256) != 64 or any(c not in "0123456789ABCDEF" for c in raw_output_sha256):
        raise ValueError("raw_output_sha256 must be 64 uppercase hexadecimal characters")
    payload = b"".join(_frame(b"S", unicodedata.normalize("NFC", x).encode("utf-8")) for x in fields)
    return hashlib.sha256(_PROTECTED_DOMAIN + b"\\x00" + payload).hexdigest().upper()

@dataclass
class TrustedEventSequenceStateV1:
    counter_by_trace: dict[str, int] = field(default_factory=dict)
    consumed_outcome_identities: set[str] = field(default_factory=set)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def allocate(self, trace_identity: str, event_kind: str) -> str:
        if not trace_identity or event_kind not in {"proposal", "outcome"}:
            raise ValueError("invalid event identity fields")
        with self._lock:
            sequence = self.counter_by_trace.get(trace_identity, 0) + 1
            self.counter_by_trace[trace_identity] = sequence
            return f"{trace_identity}:{event_kind}:{sequence}"

    def consume_outcome(self, outcome_event_identity: str) -> None:
        with self._lock:
            if outcome_event_identity in self.consumed_outcome_identities:
                raise ValueError("outcome identity already consumed")
            self.consumed_outcome_identities.add(outcome_event_identity)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {"schema": "P2N.TRANSPORT.STATE.V1", "counter_by_trace": dict(sorted(self.counter_by_trace.items())), "consumed_outcome_identities": sorted(self.consumed_outcome_identities)}

    def restore(self, snapshot: dict[str, object]) -> None:
        if snapshot.get("schema") != "P2N.TRANSPORT.STATE.V1":
            raise ValueError("unsupported snapshot schema")
        counters = snapshot.get("counter_by_trace")
        consumed = snapshot.get("consumed_outcome_identities")
        if not isinstance(counters, dict) or not isinstance(consumed, list):
            raise ValueError("malformed snapshot")
        with self._lock:
            self.counter_by_trace = {str(k): int(v) for k, v in counters.items()}
            self.consumed_outcome_identities = {str(x) for x in consumed}

    def reset(self) -> None:
        with self._lock:
            self.counter_by_trace.clear()
            self.consumed_outcome_identities.clear()

class TrustedOutcomeTransportV1:
    def __init__(self, adapter, sequence_state):
        self.adapter = adapter
        self.sequence_state = sequence_state

    def acknowledge(self, *, trace_identity: str, proposal_digest: str, tool_name: str, success: bool, canonical_source_path: str, post_hook_output: object) -> dict[str, object]:
        outcome_identity = self.sequence_state.allocate(trace_identity, "outcome")
        raw_digest = compute_raw_output_sha256_v1(post_hook_output)
        bound_digest = compute_protected_value_bound_digest_v1(trace_identity, proposal_digest, outcome_identity, canonical_source_path, raw_digest)
        outcome = {"success": bool(success), "completion_sequence": int(outcome_identity.rsplit(":", 1)[1]), "canonical_source_path": canonical_source_path, "raw_output_sha256": raw_digest, "protected_value_sha256_or_bound_digest": bound_digest}
        self.adapter.after_tool(outcome)
        self.sequence_state.consume_outcome(outcome_identity)
        return outcome

def snapshot_trusted_transport_state_v1(sequence_state: TrustedEventSequenceStateV1) -> dict[str, object]:
    return sequence_state.snapshot()
''',
"AUTH-F02":'''"""Opt-in trusted bridge v1. Runtime behavior is not qualified."""
from __future__ import annotations
from typing import Any
from aicomp_sdk.core.env.sandbox import SandboxEnv
from aicomp_sdk.core.env.trusted_outcome_transport_v1 import TrustedOutcomeTransportV1

class TrustedBridgeSandboxV1(SandboxEnv):
    def __init__(self, *args, trusted_transport, **kwargs):
        if not isinstance(trusted_transport, TrustedOutcomeTransportV1):
            raise TypeError("trusted_transport must be TrustedOutcomeTransportV1")
        super().__init__(*args, **kwargs)
        self.trusted_transport = trusted_transport

    def trusted_transport_snapshot(self) -> dict[str, object]:
        return self.trusted_transport.sequence_state.snapshot()
''',
"AUTH-F03":'''"""Canonical source-path helper v1. Performs no filesystem reads."""
from __future__ import annotations
from pathlib import Path

def canonical_source_path_v1(filesystem_root: Path, requested_path: str, resolved_path: Path) -> str:
    root = filesystem_root.resolve(strict=False)
    resolved = resolved_path.resolve(strict=False)
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("resolved path is outside filesystem root") from exc
    if not isinstance(requested_path, str) or not requested_path:
        raise ValueError("requested_path must be a nonempty string")
    text = relative.as_posix()
    if text in {"", "."}:
        raise ValueError("canonical source path must identify a file below root")
    return "/" + text
'''
}

def now(): return datetime.now(timezone.utc).isoformat()
def require(c,m):
    if not c: raise ValueError(m)
def sha(path:Path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest().upper()
def ident(path:Path):
    path=path.resolve(); return {"artifact":path.name,"path":str(path),"size_bytes":path.stat().st_size,"sha256":sha(path)}
def write_json(path,obj):
    with path.open('x',encoding='utf-8',newline='\n') as f: json.dump(obj,f,indent=2,sort_keys=True); f.write('\n')
def write_csv(path,rows,fields):
    with path.open('x',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n'); w.writeheader(); w.writerows(rows)
def declared_imports(tree):
    out=[]
    for node in ast.walk(tree):
        if isinstance(node,ast.Import): out.extend(alias.name for alias in node.names)
        elif isinstance(node,ast.ImportFrom): out.append((node.module or '') + ('.'+','.join(a.name for a in node.names) if node.names else ''))
    return sorted(out)
def signature(node):
    args=node.args
    parts=[]
    pos=args.posonlyargs+args.args
    defaults=[None]*(len(pos)-len(args.defaults))+list(args.defaults)
    for a,d in zip(pos,defaults):
        text=a.arg
        if a.annotation: text += ': '+ast.unparse(a.annotation)
        if d is not None: text += '='+ast.unparse(d)
        parts.append(text)
    if args.vararg: parts.append('*'+args.vararg.arg)
    elif args.kwonlyargs: parts.append('*')
    for a,d in zip(args.kwonlyargs,args.kw_defaults):
        text=a.arg
        if a.annotation: text += ': '+ast.unparse(a.annotation)
        if d is not None: text += '='+ast.unparse(d)
        parts.append(text)
    if args.kwarg: parts.append('**'+args.kwarg.arg)
    ret=' -> '+ast.unparse(node.returns) if node.returns else ''
    return f"{node.name}({', '.join(parts)}){ret}"

def main(a):
    out=Path(a.output_dir).resolve(); require(not out.exists(),f"Refusing overwrite: {out}"); out.mkdir(parents=True)
    created=[]
    try:
        project=Path(a.project_root).resolve(); require(project.is_dir(),f"Missing project root: {project}")
        inputs={"result":Path(a.p2o_a_result).resolve(),"authorization":Path(a.p2o_a_authorization).resolve(),"files":Path(a.p2o_a_files).resolve(),"symbols":Path(a.p2o_a_symbols).resolve(),"imports":Path(a.p2o_a_imports).resolve(),"traceability":Path(a.p2o_a_traceability).resolve(),"protected_sources":Path(a.p2o_a_protected_sources).resolve(),"post_verification":Path(a.p2o_a_post_generation_verification).resolve(),"claim_boundary":Path(a.p2o_a_claim_boundary).resolve(),"binding":Path(a.p2o_a_binding).resolve(),"external_binding":Path(a.p2o_a_external_binding).resolve(),"manifest":Path(a.p2o_a_manifest).resolve(),"runner":Path(a.p2o_a_runner).resolve(),"canonicalization_spec":Path(a.canonicalization_spec).resolve(),"canonicalization_vectors":Path(a.canonicalization_vectors).resolve()}
        for k,p in inputs.items(): require(p.is_file(),f"Missing {k}: {p}")
        result=json.loads(inputs['result'].read_text(encoding='utf-8-sig')); auth=json.loads(inputs['authorization'].read_text(encoding='utf-8-sig')); ext=json.loads(inputs['external_binding'].read_text(encoding='utf-8-sig'))
        file_rows=list(csv.DictReader(inputs['files'].open(encoding='utf-8-sig',newline=''))); symbol_rows=list(csv.DictReader(inputs['symbols'].open(encoding='utf-8-sig',newline=''))); import_rows=list(csv.DictReader(inputs['imports'].open(encoding='utf-8-sig',newline='')))
        require(result.get('version')==PARENT_VERSION and result.get('status')==PARENT_STATUS,'P2O-A parent differs')
        require(auth.get('authorization_id')==AUTHORIZATION_ID and auth.get('authorized_action')=='create exactly three new source files at authorized paths','Authorization differs')
        require(auth.get('overwrite_existing_paths') is False and auth.get('modify_protected_sources') is False,'Authorization boundary differs')
        require(sha(inputs['manifest'])==PARENT_MANIFEST_SHA and ext.get('manifest_sha256')==PARENT_MANIFEST_SHA,'P2O-A manifest differs')
        require(sha(inputs['runner'])==PARENT_RUNNER_SHA and ext.get('runner_sha256')==PARENT_RUNNER_SHA,'P2O-A runner differs')
        require(sha(inputs['canonicalization_spec'])==CANON_SPEC_SHA and sha(inputs['canonicalization_vectors'])==CANON_VECTORS_SHA,'Canonicalization binding differs')
        require({r['file_id']:r['relative_path'] for r in file_rows}==AUTHORIZED,'Authorized files differ')
        require(len(symbol_rows)==8 and len(import_rows)==3,'Authorized inventory count differs')
        for rel,expected in PROTECTED.items():
            p=project/Path(rel); require(p.is_file() and sha(p)==expected,f"Protected source differs before generation: {rel}")
        for rel in AUTHORIZED.values(): require(not (project/Path(rel)).exists(),f"Authorized destination exists: {rel}")

        # Exclusive source creation. Parent directories already belong to SDK.
        for file_id,rel in AUTHORIZED.items():
            path=project/Path(rel); require(path.parent.is_dir(),f"Authorized parent missing: {path.parent}")
            with path.open('x',encoding='utf-8',newline='\n') as f: f.write(SOURCES[file_id])
            created.append(path)

        source_inventory=[]; symbols=[]; imports=[]; leakage=[]
        banned_patterns=[r'AKIA[0-9A-Z]{16}',r'-----BEGIN [A-Z ]*PRIVATE KEY-----',r'(?i)password\s*=\s*["\'][^"\']+["\']',r'(?i)api[_-]?key\s*=\s*["\'][^"\']+["\']']
        for file_id,rel in AUTHORIZED.items():
            path=project/Path(rel); text=path.read_text(encoding='utf-8'); tree=ast.parse(text,filename=str(path))
            source_inventory.append({"file_id":file_id,"relative_path":rel,"size_bytes":path.stat().st_size,"sha256":sha(path),"ast_parse":"PASS"})
            for node in tree.body:
                if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                    symbols.append({"file_id":file_id,"kind":"class" if isinstance(node,ast.ClassDef) else "function","name":node.name,"signature":node.name+'()' if isinstance(node,ast.ClassDef) else signature(node),"line":node.lineno})
            for imp in declared_imports(tree): imports.append({"file_id":file_id,"import_decl":imp})
            for pattern in banned_patterns:
                if re.search(pattern,text): leakage.append({"relative_path":rel,"pattern":pattern})

        # Authorized top-level symbol presence. Additional private helpers are allowed.
        observed={(r['file_id'],r['name']) for r in symbols}; expected={(r['file_id'],r['name']) for r in symbol_rows}
        require(expected<=observed,f"Missing authorized symbols: {sorted(expected-observed)}")
        require(not leakage,'Potential raw-value/credential marker found')
        protected_after=[]
        for rel,expected_hash in PROTECTED.items():
            p=project/Path(rel); observed_hash=sha(p); require(observed_hash==expected_hash,f"Protected source changed: {rel}")
            protected_after.append({"relative_path":rel,"size_bytes":p.stat().st_size,"sha256":observed_hash,"expected_sha256":expected_hash,"match":True})

        claim={"allowed":["exactly three authorized source files were exclusively created","generated source identities and static AST/import inventories","protected-source post-generation identity equality","static authorization conformance pending independent qualification"],"prohibited":["runtime behavior","importability","runtime canonicalization correctness","actual fs.read behavior","source retrieval success","secret capture","protected-value lineage","authorization transport correctness","guardrail effectiveness","real exfiltration prevention"]}
        result_out={"version":VERSION,"created_at_utc":now(),"status":"P2O_B_AUTHORIZED_SOURCE_GENERATION_COMPLETE_PASS","classification":"AUTHORIZED_EXCLUSIVE_SOURCE_CREATION_AND_STATIC_INVENTORY","P2O_A_parent_verified":True,"generation":{"authorized_files":3,"created_files":3,"overwrite_performed":False,"additional_sdk_files_created":False,"protected_sources_unchanged":True,"ast_parse_passed":3,"authorized_symbols_present":True,"leakage_scan_findings":0},"readiness":{"implementation_source_created":True,"independent_source_qualification_required":True,"implementation_runtime_qualified":False,"identity_freeze_eligible":False,"controlled_actual_fs_read_eligible":False},"execution_boundaries":{"source_generation_performed":True,"protected_source_modified":False,"sdk_modules_imported":False,"generated_modules_imported":False,"generated_symbols_executed":False,"actual_fs_read_executed":False,"tools_executed":False,"fixture_contents_read":False,"source_value_previewed":False,"source_value_exported":False,"effects_observed":False,"sandbox_instantiated":False,"sandbox_executed":False,"gym_executed":False,"predicates_executed":False,"breach_executed":False,"models_used":False},"scientific_verdict":{"source_generation":"ESTABLISHED","static_authorization_conformance":"PRELIMINARY_PASS_PENDING_INDEPENDENT_QUALIFICATION","implementation_runtime_behavior":"NOT_EVALUATED","actual_source_retrieval":"NOT_EVALUATED","secret_capture":"NOT_ESTABLISHED","protected_value_lineage":"NOT_ESTABLISHED","authorization_transport_correctness":"NOT_ESTABLISHED","harness_trick":"NOT_DEMONSTRATED","robust_security_findings":"NOT_ESTABLISHED"},"claim_boundary":claim,"next_gate":"EX6_P2B_P2O_C_INDEPENDENT_SOURCE_AND_AUTHORIZATION_CONFORMANCE_QUALIFICATION"}
        rp=out/'ex6_p2b_p2o_b_result.json'; fp=out/'ex6_p2b_p2o_b_generated_files.csv'; sp=out/'ex6_p2b_p2o_b_symbols.csv'; ip=out/'ex6_p2b_p2o_b_imports.csv'; pp=out/'ex6_p2b_p2o_b_protected_after.csv'; lp=out/'ex6_p2b_p2o_b_leakage_scan.csv'; cp=out/'ex6_p2b_p2o_b_claim_boundary.json'; bp=out/'ex6_p2b_p2o_b_binding.json'
        write_json(rp,result_out); write_csv(fp,source_inventory,["file_id","relative_path","size_bytes","sha256","ast_parse"]); write_csv(sp,symbols,["file_id","kind","name","signature","line"]); write_csv(ip,imports,["file_id","import_decl"]); write_csv(pp,protected_after,["relative_path","size_bytes","sha256","expected_sha256","match"]); write_csv(lp,leakage,["relative_path","pattern"]); write_json(cp,claim); write_json(bp,{"version":VERSION,"created_at_utc":now(),"runner":ident(Path(__file__).resolve()),"inputs":{k:ident(v) for k,v in inputs.items()},"generated_sources":{rel:ident(project/Path(rel)) for rel in AUTHORIZED.values()},"project_root":str(project),"protected_source_modified":False,"sdk_modules_imported":False})
        derived=(rp,fp,sp,ip,pp,lp,cp,bp); bound=tuple(inputs.values()); generated=tuple(project/Path(x) for x in AUTHORIZED.values())
        rows=[{**ident(p),"role":"P2O_B_DERIVED"} for p in derived]+[{**ident(p),"role":"P2O_B_BOUND"} for p in bound]+[{**ident(p),"role":"P2O_B_GENERATED_SOURCE"} for p in generated]
        mp=out/'ex6_p2b_p2o_b_manifest.csv'; write_csv(mp,rows,["artifact","role","size_bytes","sha256","path"])
        ep=out/'ex6_p2b_p2o_b_manifest_external_binding.json'; write_json(ep,{"version":VERSION,"created_at_utc":now(),"status":result_out['status'],"manifest_filename":mp.name,"manifest_size_bytes":mp.stat().st_size,"manifest_sha256":sha(mp),"runner_sha256":sha(Path(__file__).resolve()),"parent_p2o_a_manifest_sha256":PARENT_MANIFEST_SHA,"generated_source_count":3,"protected_source_modified":False,"generated_modules_imported":False,"runtime_behavior":"NOT_EVALUATED","identity_freeze_eligible":False,"controlled_actual_fs_read_eligible":False,"next_gate":result_out['next_gate']})
        print(json.dumps({"status":result_out['status'],"created_files":3,"protected_sources_unchanged":True,"ast_parse_passed":3,"generated_modules_imported":False,"runtime_behavior":"NOT_EVALUATED","manifest_sha256":sha(mp),"next_gate":result_out['next_gate']},indent=2))
    except Exception as exc:
        # Created files are evidence and are not deleted or overwritten on failure.
        (out/'P2O_B_FAILED.json').write_text(json.dumps({"version":VERSION,"created_at_utc":now(),"status":"P2O_B_GENERATION_BLOCKED","error_type":type(exc).__name__,"error":str(exc),"created_paths":[str(p) for p in created],"created_files_preserved":True,"sdk_modules_imported":False,"generated_symbols_executed":False,"actual_fs_read_executed":False,"effects_observed":False},indent=2),encoding='utf-8')
        raise

def parse_args():
    p=argparse.ArgumentParser(description=VERSION)
    for flag in ['p2o-a-result','p2o-a-authorization','p2o-a-files','p2o-a-symbols','p2o-a-imports','p2o-a-traceability','p2o-a-protected-sources','p2o-a-post-generation-verification','p2o-a-claim-boundary','p2o-a-binding','p2o-a-external-binding','p2o-a-manifest','p2o-a-runner','canonicalization-spec','canonicalization-vectors','project-root','output-dir']:
        p.add_argument('--'+flag,required=True)
    return p.parse_args()
if __name__=='__main__':
    try: main(parse_args())
    except Exception as exc: print(f"FAILED: {exc}",file=sys.stderr); raise SystemExit(1)
